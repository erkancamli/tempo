//! One durable writer for relay and receipt observations. Findings are computed on inspection.

use crate::{
    now_ms,
    source::{FinalizedBlock, ReplayMetadata, TxMetadata},
    state::*,
    store::{Store, bounded_error, decode},
};
use alloy::{consensus::transaction::TxHashRef, eips::eip2718::Encodable2718, primitives::B256};
use anyhow::{Context, Result, ensure};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex},
};

#[cfg(test)]
mod tests;

const RECORDS: &str = "records";
const HASHES: &str = "hashes";
const UNMATCHED: &str = "unmatched_target";
/// `(target height, index)` -> unmatched key, so retention can walk unmatched by target age.
const UNMATCHED_BY_HEIGHT: &str = "unmatched_target_by_height";
const BLOCKS: &str = "source_blocks";
const CLEAN: &str = "clean_inclusions";
const PENDING: &str = "pending";
const RECOVERY: &str = "recovery";
const INCIDENTS: &str = "incidents";
const COLUMNS: &[&str] = &[
    RECORDS,
    HASHES,
    UNMATCHED,
    UNMATCHED_BY_HEIGHT,
    BLOCKS,
    CLEAN,
    PENDING,
    RECOVERY,
    INCIDENTS,
];
// Deliberately incompatible with the separate mirror/audit stores. No silent migration.
const SCHEMA: u32 = 4;
const PROGRESS: &[u8] = b"progress";
pub const RECOVERY_BLOCKS: u64 = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Progress {
    /// The generated shadow chainspec makes this block the epoch-0 boundary.
    pub checkpoint_height: u64,
    /// Advances atomically with all submission outcomes for a source block.
    pub source: BlockCursor,
    pub source_receipts: BlockCursor,
    pub target: BlockCursor,
    pub target_timestamp_ms: u64,
    pub source_transactions: u64,
    pub archived_included: u64,
    /// Target occurrences never matched to a source occurrence and pruned by target age.
    pub archived_unmatched: u64,
    pub system_transactions: u64,
    pub system_failures: u64,
    pub observation_failures: u64,
    pub history_failures: u64,
    pub last_dispatch_ms: u64,
    pub last_dispatch_target: BlockCursor,
    pub last_target_progress_ms: u64,
    pub stall_open: bool,
    incident_sequence: u64,
}

impl Progress {
    fn new(identity: ReplayIdentity) -> Self {
        let source = identity.source_cursor();
        let target = identity.target_cursor();
        Self {
            checkpoint_height: identity.checkpoint_height,
            source,
            source_receipts: source,
            target,
            last_dispatch_target: target,
            last_target_progress_ms: now_ms(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceBlock {
    pub cursor: BlockCursor,
    pub timestamp_ms: u64,
    pub hashes: Vec<B256>,
    pub occurrences: Vec<OccurrenceId>,
}

pub struct Dispatch {
    pub id: OccurrenceId,
    pub transaction: ReplayMetadata,
    pub raw: Vec<u8>,
    pub queued_at_ms: u64,
    pub target_observed: BlockCursor,
    pub uncertain_delivery: bool,
}

pub struct Completed {
    pub id: OccurrenceId,
    pub attempts: Vec<Attempt>,
}

pub struct EvidenceStore {
    store: Store,
    /// Total submission rounds per occurrence, including recovery. Fixed for a process; a
    /// changed value applies to records as they are next written.
    max_rounds: u32,
    pub progress: Progress,
}

/// Both readers and the relay serialize short DB operations, never RPC work, through this handle.
#[derive(Clone)]
pub struct SharedStore(pub Arc<Mutex<EvidenceStore>>);

impl SharedStore {
    pub fn new(store: EvidenceStore) -> Self {
        Self(Arc::new(Mutex::new(store)))
    }

    pub async fn with<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut EvidenceStore) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let store = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("evidence writer panicked"))?;
            operation(&mut store)
        })
        .await?
    }

    pub async fn progress(&self) -> Result<Progress> {
        self.with(|store| Ok(store.progress.clone())).await
    }
}

impl EvidenceStore {
    pub fn open(
        path: &Path,
        identity: ReplayIdentity,
        max_rounds: u32,
        max_bytes: u64,
        min_free_bytes: u64,
    ) -> Result<Self> {
        ensure!(
            identity.checkpoint_height < u64::MAX,
            "checkpoint height overflows shadow epoch length"
        );
        ensure!(max_rounds > 0, "max_rounds must be positive");
        let store = Store::open(path, COLUMNS, SCHEMA, identity, max_bytes, min_free_bytes)?;
        let mut progress: Progress = store
            .get_default(PROGRESS)?
            .unwrap_or_else(|| Progress::new(identity));
        // Liveness, not evidence: downtime before this process started is not a target stall.
        progress.last_target_progress_ms = now_ms();
        let mut this = Self {
            store,
            max_rounds,
            progress: progress.clone(),
        };
        this.commit(WriteBatch::default(), progress)?;
        Ok(this)
    }

    pub fn open_reader(path: &Path) -> Result<Self> {
        let store = Store::open_secondary(path, COLUMNS, SCHEMA)?;
        let progress = store
            .get_default(PROGRESS)?
            .context("missing evidence progress")?;
        Ok(Self {
            store,
            max_rounds: u32::MAX,
            progress,
        })
    }

    fn commit(&mut self, mut batch: WriteBatch, progress: Progress) -> Result<()> {
        Store::put_default(&mut batch, PROGRESS, &progress);
        self.store.commit(batch)?;
        self.progress = progress;
        Ok(())
    }

    pub fn identity(&self) -> Result<ReplayIdentity> {
        self.store.identity()
    }

    pub fn occurrence(&self, id: OccurrenceId) -> Result<Option<Occurrence>> {
        self.store.get(RECORDS, &id.key())
    }

    pub fn by_hash(&self, hash: B256) -> Result<Vec<(OccurrenceId, Occurrence)>> {
        let keys = self.store.raw_prefix_limit(HASHES, hash.as_slice(), 1001)?;
        ensure!(
            keys.len() <= 1000,
            "too many repeated occurrences; inspect by source height/index"
        );
        keys.into_iter()
            .map(|(key, _)| {
                let id = OccurrenceId::decode(&key[32..]).context("invalid hash index")?;
                Ok((
                    id,
                    self.occurrence(id)?.context("missing indexed occurrence")?,
                ))
            })
            .collect()
    }

    fn expired(&self, record: &Occurrence) -> bool {
        record.transaction.valid_before.is_some_and(|expiry| {
            expiry <= (self.progress.target_timestamp_ms / 1000).saturating_add(3)
        })
    }

    /// Whether `recovery_candidates` still has work for this record. Interrupted intents are
    /// always included so their `in_flight` marker is cleared even after the budget is spent.
    fn recoverable(&self, record: &Occurrence) -> bool {
        if record.target.is_some() {
            return false;
        }
        if record.in_flight {
            return true;
        }
        if record.rounds >= self.max_rounds || self.expired(record) {
            return false;
        }
        record.rounds > record.completed_round
            || match record.attempts.last() {
                None => record.rounds > 0,
                Some(attempt) => {
                    attempt.disposition == Disposition::Ambiguous
                        || (attempt.disposition == Disposition::Rejected
                            && attempt
                                .failure
                                .as_ref()
                                .is_some_and(RpcFailure::retry_after_head))
                }
            }
    }

    fn put_record(&self, batch: &mut WriteBatch, record: &Occurrence) -> Result<()> {
        let key = record.id().key();
        self.store.put(batch, RECORDS, &key, record)?;
        let recoverable = self.recoverable(record);
        for (column, present) in [
            (CLEAN, record.clean_inclusion()),
            (PENDING, record.target.is_none()),
            (RECOVERY, recoverable),
        ] {
            if present {
                self.store.put_raw(batch, column, &key, &[])?;
            } else {
                self.store.delete(batch, column, &key)?;
            }
        }
        Ok(())
    }

    /// Keep target occurrences distinct and consume each at most once, including when target
    /// observation precedes source ingestion or the same signed hash occurs repeatedly.
    fn reconcile(
        &self,
        batch: &mut WriteBatch,
        records: &mut BTreeMap<OccurrenceId, Occurrence>,
        incoming: Vec<TargetObservation>,
    ) -> Result<()> {
        let mut hashes: BTreeSet<_> = records.values().map(|r| r.transaction.hash).collect();
        let mut new_targets = BTreeMap::new();
        for target in incoming {
            hashes.insert(target.transaction_hash);
            let key = target_key(&target);
            self.store.put(batch, UNMATCHED, &key, &target)?;
            self.store.put_raw(
                batch,
                UNMATCHED_BY_HEIGHT,
                &target_location_key(&target),
                &key,
            )?;
            ensure!(
                new_targets.insert(key, target).is_none(),
                "duplicate target location"
            );
        }
        for hash in hashes {
            for (id, record) in self.by_hash(hash)? {
                records.entry(id).or_insert(record);
            }
            let mut targets = self
                .store
                .raw_prefix_limit(UNMATCHED, hash.as_slice(), 1000)?
                .into_iter()
                .map(|(key, value)| Ok((key, decode::<TargetObservation>(&value)?)))
                .collect::<Result<BTreeMap<_, _>>>()?;
            targets.extend(
                new_targets
                    .iter()
                    .filter(|(_, t)| t.transaction_hash == hash)
                    .map(|(key, t)| (key.clone(), t.clone())),
            );
            let available = records
                .values_mut()
                .filter(|r| r.transaction.hash == hash && r.target.is_none());
            for (record, (key, target)) in available.zip(targets) {
                self.store.delete(batch, UNMATCHED, &key)?;
                self.store
                    .delete(batch, UNMATCHED_BY_HEIGHT, &target_location_key(&target))?;
                record.target = Some(target);
            }
        }
        for record in records.values() {
            self.put_record(batch, record)?;
        }
        Ok(())
    }

    /// Commit exact bytes and source identity before any request can be submitted. Receipt
    /// observation may independently enrich these records while submission is in flight.
    pub fn prepare_block(&mut self, block: FinalizedBlock) -> Result<Vec<OccurrenceId>> {
        ensure!(
            block.cursor.height == self.progress.source.height + 1,
            "source dispatch is not contiguous"
        );
        self.store.check_disk()?;
        let mut batch = WriteBatch::default();
        let mut progress = self.progress.clone();
        let mut records = BTreeMap::new();
        let mut prepared = SourceBlock {
            cursor: block.cursor,
            timestamp_ms: block.timestamp_ms,
            hashes: block.transactions.iter().map(|tx| *tx.tx_hash()).collect(),
            occurrences: Vec::new(),
        };
        for (index, tx) in block.transactions.into_iter().enumerate() {
            let TxMetadata::Replayable(transaction) = TxMetadata::from_envelope(&tx)? else {
                continue;
            };
            let id = OccurrenceId {
                source_height: block.cursor.height,
                source_index: u32::try_from(index)?,
            };
            let raw = tx.encoded_2718();
            let record = match self.occurrence(id)? {
                Some(record) => {
                    ensure!(
                        record.source.block == block.cursor && record.raw == raw,
                        "source occurrence changed across restart"
                    );
                    record
                }
                None => {
                    progress.source_transactions += 1;
                    self.store.put_raw(
                        &mut batch,
                        HASHES,
                        &tx_index_key(transaction.hash, id),
                        &[],
                    )?;
                    Occurrence {
                        source: TxLocation {
                            block: block.cursor,
                            index: id.source_index,
                            timestamp_ms: block.timestamp_ms,
                        },
                        transaction,
                        raw,
                        source_receipt: None,
                        target: None,
                        queued_at_ms: now_ms(),
                        last_queued_at_ms: 0,
                        target_at_dispatch: progress.target,
                        rounds: 0,
                        completed_round: 0,
                        in_flight: false,
                        interrupted_rounds: 0,
                        attempts: Vec::new(),
                    }
                }
            };
            prepared.occurrences.push(id);
            records.insert(id, record);
        }
        if let Some(previous) = self.source_block(block.cursor.height)? {
            ensure!(
                previous == prepared,
                "prepared source block changed across restart"
            );
        }
        self.store.put(
            &mut batch,
            BLOCKS,
            &block.cursor.height.to_be_bytes(),
            &prepared,
        )?;
        self.reconcile(&mut batch, &mut records, Vec::new())?;
        self.commit(batch, progress)?;
        Ok(prepared.occurrences)
    }

    pub fn source_block(&self, height: u64) -> Result<Option<SourceBlock>> {
        self.store.get(BLOCKS, &height.to_be_bytes())
    }

    /// Starts a submission round. A block round (`recovery == false`) covers every occurrence
    /// of one source block: never-dispatched and interrupted intents are (re)queued, while
    /// occurrences that already have a committed outcome are left to recovery. A recovery round
    /// requeues exactly the ids chosen by `recovery_candidates`.
    pub fn begin_round(&mut self, ids: Vec<OccurrenceId>, recovery: bool) -> Result<Vec<Dispatch>> {
        let mut batch = WriteBatch::default();
        let mut queued = Vec::new();
        for id in ids {
            let mut record = self.occurrence(id)?.context("missing dispatch intent")?;
            let settled =
                !record.in_flight && record.rounds > 0 && record.rounds == record.completed_round;
            if !recovery && settled {
                continue;
            }
            let uncertain = record.rounds > record.completed_round
                || record.attempts.last().is_some_and(|a| {
                    matches!(
                        a.disposition,
                        Disposition::Ambiguous | Disposition::PossiblyIncluded
                    )
                });
            if record.in_flight {
                record.interrupted_rounds += 1;
            }
            record.in_flight = false;
            let expired = record.rounds > 0 && self.expired(&record);
            if record.target.is_none() && record.rounds < self.max_rounds && !expired {
                record.rounds += 1;
                record.in_flight = true;
                record.last_queued_at_ms = now_ms();
                record.target_at_dispatch = self.progress.target;
                queued.push(Dispatch {
                    id,
                    transaction: record.transaction,
                    raw: record.raw.clone(),
                    queued_at_ms: record.last_queued_at_ms,
                    target_observed: self.progress.target,
                    uncertain_delivery: uncertain,
                });
            }
            self.put_record(&mut batch, &record)?;
        }
        self.store.commit(batch)?;
        Ok(queued)
    }

    pub fn complete_round(
        &mut self,
        completed: Vec<Completed>,
        source: Option<BlockCursor>,
    ) -> Result<()> {
        let mut batch = WriteBatch::default();
        let mut progress = self.progress.clone();
        let mut records = BTreeMap::new();
        for completed in completed {
            let mut record = self
                .occurrence(completed.id)?
                .context("missing dispatch record")?;
            ensure!(record.in_flight, "submission completed without an intent");
            ensure!(
                !completed.attempts.is_empty(),
                "submission completed without attempt evidence"
            );
            record.in_flight = false;
            record.completed_round = record.rounds;
            progress.last_dispatch_ms = progress
                .last_dispatch_ms
                .max(completed.attempts.last().unwrap().completed_at_ms);
            progress.last_dispatch_target = record.target_at_dispatch;
            record.attempts.extend(completed.attempts);
            ensure!(
                record.attempts.len() <= 40,
                "attempt evidence exceeded configured bound"
            );
            self.put_record(&mut batch, &record)?;
            ensure!(
                records.insert(completed.id, record).is_none(),
                "duplicate completed submission"
            );
        }
        if let Some(source) = source {
            ensure!(
                source.height == progress.source.height + 1,
                "source cursor advance is not contiguous"
            );
            let block = self
                .source_block(source.height)?
                .context("source block has no durable intent")?;
            ensure!(block.cursor == source, "source completion hash mismatch");
            for id in block.occurrences {
                let record = records
                    .get(&id)
                    .cloned()
                    .or(self.occurrence(id)?)
                    .context("missing source occurrence")?;
                ensure!(
                    !record.in_flight && (record.rounds > 0 || record.target.is_some()),
                    "source block has unfinished submissions"
                );
            }
            progress.source = source;
            if progress.source_receipts.height >= source.height {
                self.store
                    .delete(&mut batch, BLOCKS, &source.height.to_be_bytes())?;
            }
        }
        self.commit(batch, progress)
    }

    pub fn recovery_candidates(&mut self) -> Result<Vec<OccurrenceId>> {
        let floor = self.progress.source.height.saturating_sub(RECOVERY_BLOCKS);
        let end = OccurrenceId {
            source_height: self.progress.source.height,
            source_index: u32::MAX,
        }
        .key();
        let mut batch = WriteBatch::default();
        let mut removed = false;
        let mut candidates = Vec::new();
        // The recovery index excludes accepted-but-pending traffic. Entries that left the
        // window, or that `put_record` wrote under a different budget, are removed here so a
        // large failed prefix cannot permanently starve later recovery.
        for (key, _) in self.store.raw_range(RECOVERY, &[], &end, 10_000)? {
            let id = OccurrenceId::decode(&key).context("invalid recovery index")?;
            let record = self
                .occurrence(id)?
                .context("recovery occurrence missing")?;
            if record.in_flight {
                // An interrupted intent must be closed by `begin_round` even when no further
                // round is available; otherwise it would read as in flight forever.
                candidates.push(id);
                continue;
            }
            if id.source_height < floor || !self.recoverable(&record) {
                self.store.delete(&mut batch, RECOVERY, &key)?;
                removed = true;
                continue;
            }
            // State-dependent rejections wait for observed target finality to move past the
            // head sampled at the rejected submission; ambiguous deliveries retry immediately.
            let awaiting_head = record.rounds == record.completed_round
                && record
                    .attempts
                    .last()
                    .is_some_and(|attempt| attempt.disposition == Disposition::Rejected)
                && self.progress.target.height <= record.target_at_dispatch.height;
            if !awaiting_head {
                candidates.push(id);
            }
        }
        if removed {
            self.store.commit(batch)?;
        }
        Ok(candidates)
    }

    pub fn source_receipts(
        &mut self,
        block: SourceBlock,
        receipts: Vec<ReceiptSummary>,
    ) -> Result<()> {
        ensure!(
            block.cursor.height == self.progress.source_receipts.height + 1,
            "source receipts are not contiguous"
        );
        ensure!(
            receipts.len() == block.hashes.len(),
            "source receipt count mismatch"
        );
        let mut batch = WriteBatch::default();
        let mut progress = self.progress.clone();
        for id in block.occurrences {
            let mut record = self.occurrence(id)?.context("receipt occurrence missing")?;
            record.source_receipt = Some(receipts[id.source_index as usize].clone());
            self.put_record(&mut batch, &record)?;
        }
        progress.source_receipts = block.cursor;
        if progress.source.height >= block.cursor.height {
            self.store
                .delete(&mut batch, BLOCKS, &block.cursor.height.to_be_bytes())?;
        }
        self.commit(batch, progress)
    }

    pub fn observe_target(
        &mut self,
        cursor: BlockCursor,
        timestamp_ms: u64,
        observations: Vec<TargetObservation>,
        system_txs: u64,
        failures: Vec<Incident>,
    ) -> Result<()> {
        ensure!(
            cursor.height == self.progress.target.height + 1,
            "target history is not contiguous"
        );
        self.store.check_disk()?;
        let mut batch = WriteBatch::default();
        let mut progress = self.progress.clone();
        self.reconcile(&mut batch, &mut BTreeMap::new(), observations)?;
        progress.target = cursor;
        progress.target_timestamp_ms = timestamp_ms;
        progress.last_target_progress_ms = now_ms();
        progress.system_transactions += system_txs;
        progress.system_failures += failures.len() as u64;
        for failure in failures {
            self.put_incident(&mut batch, &mut progress, failure)?;
        }
        if progress.stall_open {
            self.put_incident(
                &mut batch,
                &mut progress,
                Incident {
                    observed_at_ms: now_ms(),
                    stage: "target_finality".into(),
                    message: "finality resumed".into(),
                    history_failure: false,
                },
            )?;
            progress.stall_open = false;
        }
        self.commit(batch, progress)
    }

    fn put_incident(
        &self,
        batch: &mut WriteBatch,
        progress: &mut Progress,
        mut incident: Incident,
    ) -> Result<()> {
        incident.message = bounded_error(incident.message);
        progress.incident_sequence += 1;
        let mut key = incident.observed_at_ms.to_be_bytes().to_vec();
        key.extend_from_slice(&progress.incident_sequence.to_be_bytes());
        self.store.put(batch, INCIDENTS, &key, &incident)
    }

    pub fn incident(&mut self, stage: &str, message: String, history_failure: bool) -> Result<()> {
        let mut progress = self.progress.clone();
        if history_failure {
            progress.history_failures += 1;
        } else {
            progress.observation_failures += 1;
        }
        let mut batch = WriteBatch::default();
        self.put_incident(
            &mut batch,
            &mut progress,
            Incident {
                observed_at_ms: now_ms(),
                stage: stage.into(),
                message,
                history_failure,
            },
        )?;
        self.commit(batch, progress)
    }

    pub fn check_stall(&mut self, threshold_ms: u64) -> Result<()> {
        if threshold_ms == 0
            || self.progress.stall_open
            || now_ms().saturating_sub(self.progress.last_target_progress_ms) < threshold_ms
        {
            return Ok(());
        }
        let mut progress = self.progress.clone();
        progress.stall_open = true;
        let mut batch = WriteBatch::default();
        self.put_incident(
            &mut batch,
            &mut progress,
            Incident {
                observed_at_ms: now_ms(),
                stage: "target_finality".into(),
                message: "no finalized target progress within configured horizon".into(),
                history_failure: false,
            },
        )?;
        self.commit(batch, progress)
    }

    pub fn incidents(&self, from_ms: u64, to_ms: u64) -> Result<Vec<Incident>> {
        let mut end = to_ms.to_be_bytes().to_vec();
        end.extend_from_slice(&[0xff; 8]);
        self.store
            .raw_range(INCIDENTS, &from_ms.to_be_bytes(), &end, 1000)?
            .into_iter()
            .map(|(_, value)| decode(&value))
            .collect()
    }

    pub fn has_pending(&self) -> Result<bool> {
        Ok(!self.store.raw_prefix_limit(PENDING, &[], 1)?.is_empty())
    }

    /// Removes clean inclusions older than `retain_blocks` source blocks and target occurrences
    /// that stayed unmatched for `retain_blocks` target blocks. Anomalies are never pruned.
    pub fn prune(&mut self, retain_blocks: u64) -> Result<()> {
        if retain_blocks == 0 {
            return Ok(());
        }
        let mut batch = WriteBatch::default();
        let mut progress = self.progress.clone();
        let unmatched_floor = self.progress.target.height.saturating_sub(retain_blocks);
        for (location, key) in self
            .store
            .raw_prefix_limit(UNMATCHED_BY_HEIGHT, &[], 10_000)?
        {
            let target = OccurrenceId::decode(&location).context("invalid unmatched index")?;
            if target.source_height >= unmatched_floor {
                break;
            }
            self.store.delete(&mut batch, UNMATCHED, &key)?;
            self.store
                .delete(&mut batch, UNMATCHED_BY_HEIGHT, &location)?;
            progress.archived_unmatched += 1;
        }
        let floor = self.progress.source.height.saturating_sub(retain_blocks);
        for (key, _) in self.store.raw_prefix_limit(CLEAN, &[], 10_000)? {
            let id = OccurrenceId::decode(&key).context("invalid clean inclusion index")?;
            if id.source_height >= floor {
                break;
            }
            let record = self.occurrence(id)?.context("clean occurrence missing")?;
            ensure!(
                record.clean_inclusion(),
                "clean inclusion index is inconsistent"
            );
            self.store.delete(&mut batch, RECORDS, &key)?;
            self.store.delete(
                &mut batch,
                HASHES,
                &tx_index_key(record.transaction.hash, id),
            )?;
            self.store.delete(&mut batch, CLEAN, &key)?;
            progress.archived_included += 1;
        }
        if progress.archived_included != self.progress.archived_included
            || progress.archived_unmatched != self.progress.archived_unmatched
        {
            self.commit(batch, progress)?;
        }
        self.store.check_disk()
    }

    pub fn unmatched_count(&self) -> Result<usize> {
        Ok(self
            .store
            .raw_prefix_limit(UNMATCHED_BY_HEIGHT, &[], 10_000)?
            .len())
    }

    pub fn flush(&self) -> Result<()> {
        self.store.flush()
    }
}

fn target_location(target: &TargetObservation) -> OccurrenceId {
    OccurrenceId {
        source_height: target.location.block.height,
        source_index: target.location.index,
    }
}

fn target_key(target: &TargetObservation) -> Vec<u8> {
    tx_index_key(target.transaction_hash, target_location(target)).to_vec()
}

fn target_location_key(target: &TargetObservation) -> [u8; 12] {
    target_location(target).key()
}
