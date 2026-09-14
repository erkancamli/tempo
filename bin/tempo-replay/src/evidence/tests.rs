use super::*;
use alloy::{
    consensus::{SignableTransaction, TxLegacy},
    primitives::Signature,
};
use tempo_primitives::TempoTxEnvelope;

fn identity() -> ReplayIdentity {
    ReplayIdentity {
        chain_id: 4217,
        checkpoint_height: 10,
        source_hash: B256::repeat_byte(1),
        target_hash: B256::repeat_byte(2),
    }
}

fn transaction(nonce: u64) -> TempoTxEnvelope {
    let tx = TxLegacy {
        chain_id: Some(4217),
        nonce,
        ..Default::default()
    };
    let key = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let (signature, recovery) = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap();
    TempoTxEnvelope::Legacy(tx.into_signed(Signature::from_signature_and_parity(
        signature,
        recovery.is_y_odd(),
    )))
}

fn cursor(height: u64, byte: u8) -> BlockCursor {
    BlockCursor {
        height,
        hash: B256::repeat_byte(byte),
    }
}

fn block(height: u64, transactions: Vec<TempoTxEnvelope>) -> FinalizedBlock {
    FinalizedBlock {
        cursor: cursor(height, height as u8),
        timestamp_ms: height * 1000,
        transactions,
    }
}

fn receipt(status: bool) -> ReceiptSummary {
    ReceiptSummary {
        status,
        gas_used: 21_000,
        logs_hash: B256::ZERO,
    }
}

fn attempt(disposition: Disposition) -> Attempt {
    Attempt {
        queued_at_ms: 100,
        target_observed: identity().target_cursor(),
        started_at_ms: 200,
        completed_at_ms: 300,
        disposition,
        failure: None,
    }
}

fn rejection() -> Attempt {
    let mut attempt = attempt(Disposition::Rejected);
    attempt.failure = Some(RpcFailure {
        code: Some(-32003),
        message: "balance too low".into(),
        data: Some(
            r#"{"name":"InsufficientFeeTokenBalanceError","fee":"10","balance":"3"}"#.into(),
        ),
    });
    attempt
}

fn target(hash: B256, height: u64, index: u32, status: bool) -> TargetObservation {
    TargetObservation {
        transaction_hash: hash,
        location: TxLocation {
            block: cursor(height, height as u8 + 100),
            index,
            timestamp_ms: height * 1000,
        },
        receipt: receipt(status),
    }
}

fn observe(store: &mut EvidenceStore, height: u64, transactions: Vec<TargetObservation>) {
    store
        .observe_target(
            cursor(height, height as u8 + 100),
            height * 1000,
            transactions,
            0,
            Vec::new(),
        )
        .unwrap();
}

#[test]
fn checkpoint_identity_schema_and_reader_are_checked() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    assert_eq!(store.progress.source, identity().source_cursor());
    assert_eq!(
        EvidenceStore::open_reader(directory.path())
            .unwrap()
            .progress
            .target,
        identity().target_cursor()
    );
    drop(store);
    let mut other = identity();
    other.target_hash = B256::repeat_byte(99);
    assert!(EvidenceStore::open(directory.path(), other, 3, u64::MAX, 0).is_err());
    let legacy = tempfile::tempdir().unwrap();
    drop(Store::open(legacy.path(), &["occurrences"], 3, identity(), u64::MAX, 0).unwrap());
    assert!(EvidenceStore::open(legacy.path(), identity(), 3, u64::MAX, 0).is_err());
}

#[test]
fn intent_survives_restart_and_cursor_requires_all_outcomes() {
    let directory = tempfile::tempdir().unwrap();
    let source = block(11, vec![transaction(1), transaction(2)]);
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let ids = store.prepare_block(source.clone()).unwrap();
    let first = store.begin_round(ids.clone(), false).unwrap();
    assert_eq!(first[0].raw, source.transactions[0].encoded_2718());
    assert_eq!(store.progress.source.height, 10);
    drop(store);

    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    assert_eq!(store.prepare_block(source.clone()).unwrap(), ids);
    let resumed = store.begin_round(ids.clone(), false).unwrap();
    assert!(resumed.iter().all(|q| q.uncertain_delivery));
    assert_eq!(
        store
            .occurrence(ids[0])
            .unwrap()
            .unwrap()
            .interrupted_rounds,
        1
    );
    assert!(
        store
            .complete_round(
                vec![Completed {
                    id: ids[0],
                    attempts: vec![attempt(Disposition::Accepted)]
                }],
                Some(source.cursor)
            )
            .is_err()
    );
    assert_eq!(store.progress.source.height, 10);
    assert!(store.occurrence(ids[0]).unwrap().unwrap().in_flight);
    store
        .complete_round(
            ids.iter()
                .map(|id| Completed {
                    id: *id,
                    attempts: vec![attempt(Disposition::Accepted)],
                })
                .collect(),
            Some(source.cursor),
        )
        .unwrap();
    assert_eq!(store.progress.source.height, 11);
    assert_eq!(store.progress.source_transactions, 2);
    let reader = EvidenceStore::open_reader(directory.path()).unwrap();
    assert_eq!(
        reader
            .by_hash(*source.transactions[0].tx_hash())
            .unwrap()
            .len(),
        1
    );
    let record = reader.occurrence(ids[0]).unwrap().unwrap();
    let encoded = crate::store::encode(&record).unwrap();
    assert_eq!(
        crate::store::encode(&decode::<Occurrence>(&encoded).unwrap()).unwrap(),
        encoded
    );
}

#[test]
fn concurrent_observation_is_not_overwritten_by_submission_completion() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let source = block(11, vec![transaction(1)]);
    let hash = *source.transactions[0].tx_hash();
    let ids = store.prepare_block(source.clone()).unwrap();
    store.begin_round(ids.clone(), false).unwrap();
    let prepared = store.source_block(11).unwrap().unwrap();
    store
        .source_receipts(prepared, vec![receipt(true)])
        .unwrap();
    observe(&mut store, 11, vec![target(hash, 11, 0, false)]);
    store
        .complete_round(
            vec![Completed {
                id: ids[0],
                attempts: vec![attempt(Disposition::Accepted)],
            }],
            Some(source.cursor),
        )
        .unwrap();
    let record = store.occurrence(ids[0]).unwrap().unwrap();
    assert_eq!(
        record.finding(11, 400, 64, 120_000),
        Finding::ExecutionDrift
    );
    assert!(record.source_receipt.is_some() && record.target.is_some());
    assert!(store.source_block(11).unwrap().is_none());
    assert!(!store.has_pending().unwrap());
    let empty = block(12, vec![]);
    store.prepare_block(empty.clone()).unwrap();
    store
        .complete_round(Vec::new(), Some(empty.cursor))
        .unwrap();
    store.prune(1).unwrap();
    assert!(store.occurrence(ids[0]).unwrap().is_some()); // Drift evidence is retained.
}

#[test]
fn repeated_hashes_match_distinct_target_occurrences_even_when_target_arrives_first() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let tx = transaction(1);
    let hash = *tx.tx_hash();
    observe(&mut store, 11, vec![target(hash, 11, 0, true)]);
    let source = block(11, vec![tx.clone(), tx]);
    let ids = store.prepare_block(source.clone()).unwrap();
    assert!(store.occurrence(ids[0]).unwrap().unwrap().target.is_some());
    assert!(store.occurrence(ids[1]).unwrap().unwrap().target.is_none());
    let queued = store.begin_round(ids.clone(), false).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].id, ids[1]);
    store
        .complete_round(
            vec![Completed {
                id: ids[1],
                attempts: vec![attempt(Disposition::Accepted)],
            }],
            Some(source.cursor),
        )
        .unwrap();
    observe(&mut store, 12, vec![target(hash, 12, 0, true)]);
    let records = store.by_hash(hash).unwrap();
    assert_eq!(records.len(), 2);
    assert_ne!(
        records[0].1.target.as_ref().unwrap().location,
        records[1].1.target.as_ref().unwrap().location
    );
}

#[test]
fn repeated_hashes_in_one_target_batch_do_not_overwrite_or_reuse_a_match() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let tx = transaction(1);
    let hash = *tx.tx_hash();
    let ids = store
        .prepare_block(block(11, vec![tx.clone(), tx]))
        .unwrap();
    observe(
        &mut store,
        11,
        vec![target(hash, 11, 0, true), target(hash, 11, 1, false)],
    );
    assert_eq!(
        store
            .occurrence(ids[0])
            .unwrap()
            .unwrap()
            .target
            .unwrap()
            .location
            .index,
        0
    );
    assert_eq!(
        store
            .occurrence(ids[1])
            .unwrap()
            .unwrap()
            .target
            .unwrap()
            .location
            .index,
        1
    );
}

#[test]
fn state_recovery_waits_for_target_progress_and_keeps_the_original_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 2, u64::MAX, 0).unwrap();
    let source = block(11, vec![transaction(1)]);
    let ids = store.prepare_block(source.clone()).unwrap();
    store.begin_round(ids.clone(), false).unwrap();
    store
        .complete_round(
            vec![Completed {
                id: ids[0],
                attempts: vec![rejection()],
            }],
            Some(source.cursor),
        )
        .unwrap();
    assert!(store.recovery_candidates().unwrap().is_empty());
    // A block round never re-dispatches an occurrence with a committed outcome.
    assert!(store.begin_round(ids.clone(), false).unwrap().is_empty());
    observe(&mut store, 11, Vec::new());
    assert_eq!(store.recovery_candidates().unwrap(), ids);
    let queued = store.begin_round(ids.clone(), true).unwrap();
    assert!(!queued[0].uncertain_delivery); // A reported rejection is not ambiguous delivery.
    store
        .complete_round(
            vec![Completed {
                id: ids[0],
                attempts: vec![attempt(Disposition::Accepted)],
            }],
            None,
        )
        .unwrap();
    let record = store.occurrence(ids[0]).unwrap().unwrap();
    assert_eq!(record.attempts[0], rejection());
    assert_eq!(record.attempts.len(), 2);
    assert!(!record.raw.is_empty());
    assert!(store.recovery_candidates().unwrap().is_empty());
    drop(store);
    let mut store = EvidenceStore::open(directory.path(), identity(), 2, u64::MAX, 0).unwrap();
    assert!(store.begin_round(ids.clone(), false).unwrap().is_empty());
    assert!(store.begin_round(ids, true).unwrap().is_empty()); // Budget spent.
}

#[test]
fn recovery_is_bounded_across_crashes_and_does_not_retry_expired_or_unknown_errors() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 1, u64::MAX, 0).unwrap();
    let source = block(11, vec![transaction(1), transaction(2)]);
    let ids = store.prepare_block(source.clone()).unwrap();
    store.begin_round(ids.clone(), false).unwrap();
    drop(store);
    let mut store = EvidenceStore::open(directory.path(), identity(), 1, u64::MAX, 0).unwrap();
    assert!(store.begin_round(ids.clone(), false).unwrap().is_empty());
    store
        .complete_round(Vec::new(), Some(source.cursor))
        .unwrap();
    assert!(store.recovery_candidates().unwrap().is_empty());
    assert_eq!(
        store
            .occurrence(ids[0])
            .unwrap()
            .unwrap()
            .finding(1000, u64::MAX, 1, 1),
        Finding::DeliveryAmbiguous
    );
    drop(store);

    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let second = block(12, vec![transaction(3), transaction(4)]);
    let ids = store.prepare_block(second.clone()).unwrap();
    store.begin_round(ids.clone(), false).unwrap();
    store
        .complete_round(
            vec![
                Completed {
                    id: ids[0],
                    attempts: vec![rejection()],
                },
                Completed {
                    id: ids[1],
                    attempts: vec![attempt(Disposition::Rejected)],
                },
            ],
            Some(second.cursor),
        )
        .unwrap();
    let mut expired = store.occurrence(ids[0]).unwrap().unwrap();
    expired.transaction.valid_before = Some(12);
    let mut batch = WriteBatch::default();
    store.put_record(&mut batch, &expired).unwrap();
    store.store.commit(batch).unwrap();
    observe(&mut store, 11, Vec::new());
    assert!(store.recovery_candidates().unwrap().is_empty());
}

#[test]
fn interrupted_recovery_does_not_relabel_an_unknown_delivery_as_the_previous_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let source = block(11, vec![transaction(1)]);
    let ids = store.prepare_block(source.clone()).unwrap();
    store.begin_round(ids.clone(), false).unwrap();
    store
        .complete_round(
            vec![Completed {
                id: ids[0],
                attempts: vec![rejection()],
            }],
            Some(source.cursor),
        )
        .unwrap();
    observe(&mut store, 11, Vec::new());
    assert_eq!(store.recovery_candidates().unwrap(), ids);
    store.begin_round(ids.clone(), true).unwrap();
    drop(store); // The second RPC might have reached the node; no outcome was committed.
    let mut store = EvidenceStore::open(directory.path(), identity(), 2, u64::MAX, 0).unwrap();
    // The exhausted, interrupted intent is still handed to `begin_round` so it is closed.
    assert_eq!(store.recovery_candidates().unwrap(), ids);
    assert!(store.begin_round(ids.clone(), true).unwrap().is_empty());
    let record = store.occurrence(ids[0]).unwrap().unwrap();
    assert!(!record.in_flight);
    assert_eq!(record.interrupted_rounds, 1);
    assert_eq!(record.attempts[0].disposition, Disposition::Rejected);
    assert_eq!(
        record.finding(1000, u64::MAX, 1, 1),
        Finding::DeliveryAmbiguous
    );
    assert!(store.recovery_candidates().unwrap().is_empty());
}

#[test]
fn partial_shutdown_outcomes_are_kept_and_settled_occurrences_are_not_redispatched() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let source = block(11, vec![transaction(1), transaction(2)]);
    let ids = store.prepare_block(source.clone()).unwrap();
    assert_eq!(store.begin_round(ids.clone(), false).unwrap().len(), 2);
    // Shutdown: the first lane finished, the second never issued its request.
    store
        .complete_round(
            vec![Completed {
                id: ids[0],
                attempts: vec![attempt(Disposition::Accepted)],
            }],
            None,
        )
        .unwrap();
    assert_eq!(store.progress.source.height, 10);
    drop(store);
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    assert_eq!(store.prepare_block(source.clone()).unwrap(), ids);
    let resumed = store.begin_round(ids.clone(), false).unwrap();
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].id, ids[1]);
    assert!(resumed[0].uncertain_delivery);
    let first = store.occurrence(ids[0]).unwrap().unwrap();
    assert_eq!((first.rounds, first.interrupted_rounds), (1, 0));
    store
        .complete_round(
            vec![Completed {
                id: ids[1],
                attempts: vec![attempt(Disposition::Accepted)],
            }],
            Some(source.cursor),
        )
        .unwrap();
    assert_eq!(store.progress.source.height, 11);
    assert!(!store.occurrence(ids[0]).unwrap().unwrap().clean_inclusion());
    assert_eq!(
        store
            .occurrence(ids[0])
            .unwrap()
            .unwrap()
            .finding(11, 400, 64, 120_000),
        Finding::MissingWithinWindow
    );
}

#[test]
fn expiry_rejections_are_replay_lag_artifacts_not_admission_findings() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let source = block(11, vec![transaction(1)]);
    let ids = store.prepare_block(source.clone()).unwrap();
    store.begin_round(ids.clone(), false).unwrap();
    let mut expired = attempt(Disposition::Rejected);
    expired.failure = Some(RpcFailure {
        code: Some(-32003),
        message: "valid_before too soon".into(),
        data: Some(r#"{"name":"InvalidValidBeforeError","validBefore":10,"minAllowed":14}"#.into()),
    });
    store
        .complete_round(
            vec![Completed {
                id: ids[0],
                attempts: vec![expired],
            }],
            Some(source.cursor),
        )
        .unwrap();
    let record = store.occurrence(ids[0]).unwrap().unwrap();
    assert_eq!(
        record.finding(11, 400, 64, 120_000),
        Finding::ExpiredBeforeDispatch
    );
    observe(&mut store, 11, Vec::new());
    assert!(store.recovery_candidates().unwrap().is_empty());
}

#[test]
fn clean_inclusions_are_pruned_with_their_indexes_but_failures_are_retained() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let source = block(11, vec![transaction(1), transaction(2)]);
    let hash = *source.transactions[0].tx_hash();
    let ids = store.prepare_block(source.clone()).unwrap();
    store.begin_round(ids.clone(), false).unwrap();
    store
        .complete_round(
            vec![
                Completed {
                    id: ids[0],
                    attempts: vec![attempt(Disposition::Accepted)],
                },
                Completed {
                    id: ids[1],
                    attempts: vec![rejection()],
                },
            ],
            Some(source.cursor),
        )
        .unwrap();
    let record = store.occurrence(ids[0]).unwrap().unwrap();
    assert_eq!(
        record.finding(10, 400, 0, 200),
        Finding::MissingWithinWindow
    );
    assert_eq!(record.finding(10, 600, 0, 200), Finding::MissingAfterWindow);
    assert_eq!(record.finding(11, 301, 1, 0), Finding::MissingAfterWindow);
    observe(&mut store, 11, vec![target(hash, 11, 0, true)]);
    assert_eq!(
        store
            .occurrence(ids[0])
            .unwrap()
            .unwrap()
            .finding(11, 600, 1, 1),
        Finding::AwaitingSourceReceipt
    );
    store
        .source_receipts(
            store.source_block(11).unwrap().unwrap(),
            vec![receipt(true), receipt(true)],
        )
        .unwrap();
    for height in 12..=13 {
        let empty = block(height, Vec::new());
        store.prepare_block(empty.clone()).unwrap();
        store
            .complete_round(Vec::new(), Some(empty.cursor))
            .unwrap();
    }
    store.prune(1).unwrap();
    assert_eq!(store.progress.archived_included, 1);
    assert!(store.occurrence(ids[0]).unwrap().is_none());
    assert!(store.by_hash(hash).unwrap().is_empty());
    assert!(store.occurrence(ids[1]).unwrap().is_some());
}

#[test]
fn unmatched_target_occurrences_are_pruned_by_target_age_only() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    let foreign = B256::repeat_byte(0xfe);
    observe(&mut store, 11, vec![target(foreign, 11, 0, true)]);
    assert_eq!(store.unmatched_count().unwrap(), 1);
    store.prune(2).unwrap();
    assert_eq!(store.unmatched_count().unwrap(), 1);
    observe(&mut store, 12, Vec::new());
    observe(&mut store, 13, Vec::new());
    store.prune(2).unwrap();
    assert_eq!(store.unmatched_count().unwrap(), 1); // 13 - 2 = 11 is not yet older than the floor.
    observe(&mut store, 14, Vec::new());
    store.prune(2).unwrap();
    assert_eq!(store.unmatched_count().unwrap(), 0);
    assert_eq!(store.progress.archived_unmatched, 1);
    // A later source occurrence with that hash is simply unmatched, never mis-associated.
    let source = block(11, vec![transaction(1)]);
    let ids = store.prepare_block(source).unwrap();
    assert!(store.occurrence(ids[0]).unwrap().unwrap().target.is_none());
}

#[test]
fn downtime_before_start_is_not_a_target_stall() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    store.progress.last_target_progress_ms = 0;
    store
        .incident("test", "persist progress".into(), false)
        .unwrap();
    drop(store);
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    store.check_stall(60_000).unwrap();
    assert!(!store.progress.stall_open);
}

#[test]
fn stalls_and_observation_errors_are_not_execution_or_consensus_findings() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    store.progress.last_target_progress_ms = 0;
    store.check_stall(1).unwrap();
    store.check_stall(1).unwrap();
    assert_eq!(store.incidents(0, u64::MAX).unwrap().len(), 1);
    assert!(store.progress.stall_open);
    drop(store);
    let mut store = EvidenceStore::open(directory.path(), identity(), 3, u64::MAX, 0).unwrap();
    assert!(store.progress.stall_open);
    observe(&mut store, 11, Vec::new());
    assert!(!store.progress.stall_open);
    store
        .incident("source_receipts", "HTTP 503".into(), false)
        .unwrap();
    assert_eq!(store.progress.observation_failures, 1);
    assert_eq!(store.progress.history_failures, 0);
    store
        .incident("source_reader", "skipped authenticated block".into(), true)
        .unwrap();
    assert_eq!(store.progress.history_failures, 1);
}
