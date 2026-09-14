//! Durable observations and derived diagnostics. A source occurrence is not just a tx hash.

use crate::source::ReplayMetadata;
use alloy::primitives::B256;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayIdentity {
    pub chain_id: u64,
    pub checkpoint_height: u64,
    pub source_hash: B256,
    pub target_hash: B256,
}

impl ReplayIdentity {
    pub fn source_cursor(self) -> BlockCursor {
        BlockCursor {
            height: self.checkpoint_height,
            hash: self.source_hash,
        }
    }

    pub fn target_cursor(self) -> BlockCursor {
        BlockCursor {
            height: self.checkpoint_height,
            hash: self.target_hash,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockCursor {
    pub height: u64,
    pub hash: B256,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct OccurrenceId {
    pub source_height: u64,
    pub source_index: u32,
}

impl OccurrenceId {
    pub fn key(self) -> [u8; 12] {
        let mut key = [0; 12];
        key[..8].copy_from_slice(&self.source_height.to_be_bytes());
        key[8..].copy_from_slice(&self.source_index.to_be_bytes());
        key
    }

    pub fn decode(key: &[u8]) -> Option<Self> {
        Some(Self {
            source_height: u64::from_be_bytes(key.get(..8)?.try_into().ok()?),
            source_index: u32::from_be_bytes(key.get(8..)?.try_into().ok()?),
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxLocation {
    pub block: BlockCursor,
    pub index: u32,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptSummary {
    pub status: bool,
    pub gas_used: u64,
    pub logs_hash: B256,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetObservation {
    pub transaction_hash: B256,
    pub location: TxLocation,
    pub receipt: ReceiptSummary,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Accepted,
    AlreadyKnown,
    Rejected,
    PossiblyIncluded,
    Ambiguous,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcFailure {
    pub code: Option<i64>,
    pub message: String,
    /// Bounded original JSON text, not serde_json::Value (our binary codec is not self-describing).
    pub data: Option<String>,
}

impl RpcFailure {
    /// The node's structured rejection name, only for `TransactionRejected` responses.
    fn structured_name(&self) -> Option<String> {
        if self.code != Some(-32003) {
            return None;
        } // TransactionRejected, not an arbitrary RPC error.
        let data = serde_json::from_str::<serde_json::Value>(self.data.as_deref()?).ok()?;
        Some(data.get("name")?.as_str()?.to_owned())
    }

    /// Only explicitly structured, state-dependent node errors are eligible. Unknown errors,
    /// expiry, signature failures and nonce-too-low are deliberately not inferred as retryable.
    pub fn retry_after_head(&self) -> bool {
        matches!(
            self.structured_name().as_deref(),
            Some(
                "InsufficientFeeTokenBalanceError"
                    | "InsufficientAmmLiquidityError"
                    | "FeeTokenPausedError"
            )
        )
    }

    /// The signed validity window had already closed at the target when it was submitted. This
    /// is a replay-lag artifact, not evidence about the transaction, and is never retried.
    pub fn expired_at_admission(&self) -> bool {
        self.structured_name().as_deref() == Some("InvalidValidBeforeError")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attempt {
    pub queued_at_ms: u64,
    pub target_observed: BlockCursor,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub disposition: Disposition,
    pub failure: Option<RpcFailure>,
}

/// One record is enriched independently by the relay and receipt observers. No persisted finding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Occurrence {
    pub source: TxLocation,
    pub transaction: ReplayMetadata,
    pub raw: Vec<u8>,
    pub source_receipt: Option<ReceiptSummary>,
    pub target: Option<TargetObservation>,
    pub queued_at_ms: u64,
    pub last_queued_at_ms: u64,
    pub target_at_dispatch: BlockCursor,
    /// Committed before each submission round, including recovery, to bound restart retries.
    pub rounds: u32,
    pub completed_round: u32,
    pub in_flight: bool,
    pub interrupted_rounds: u32,
    pub attempts: Vec<Attempt>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    NotDispatched,
    SubmissionInFlight,
    DeliveryAmbiguous,
    AdmissionRejected,
    ExpiredBeforeDispatch,
    MissingWithinWindow,
    MissingAfterWindow,
    AwaitingSourceReceipt,
    Included,
    ExecutionDrift,
}

impl Occurrence {
    pub fn id(&self) -> OccurrenceId {
        OccurrenceId {
            source_height: self.source.block.height,
            source_index: self.source.index,
        }
    }

    pub fn finding(
        &self,
        target_height: u64,
        now: u64,
        missing_blocks: u64,
        missing_ms: u64,
    ) -> Finding {
        if let Some(target) = &self.target {
            return match &self.source_receipt {
                None => Finding::AwaitingSourceReceipt,
                Some(source) if source == &target.receipt => Finding::Included,
                Some(_) => Finding::ExecutionDrift,
            };
        }
        if self.in_flight {
            return Finding::SubmissionInFlight;
        }
        if self.rounds > self.completed_round {
            return Finding::DeliveryAmbiguous;
        }
        let Some(last) = self.attempts.last() else {
            return if self.rounds == 0 {
                Finding::NotDispatched
            } else {
                Finding::DeliveryAmbiguous
            };
        };
        match last.disposition {
            Disposition::Rejected
                if last
                    .failure
                    .as_ref()
                    .is_some_and(RpcFailure::expired_at_admission) =>
            {
                Finding::ExpiredBeforeDispatch
            }
            Disposition::Rejected => Finding::AdmissionRejected,
            Disposition::Ambiguous | Disposition::PossiblyIncluded => Finding::DeliveryAmbiguous,
            _ if (missing_ms > 0 && now.saturating_sub(last.completed_at_ms) >= missing_ms)
                || (missing_blocks > 0
                    && target_height.saturating_sub(self.target_at_dispatch.height)
                        >= missing_blocks) =>
            {
                Finding::MissingAfterWindow
            }
            _ => Finding::MissingWithinWindow,
        }
    }

    pub fn clean_inclusion(&self) -> bool {
        !self.in_flight
            && self.interrupted_rounds == 0
            && self.attempts.iter().all(|a| {
                matches!(
                    a.disposition,
                    Disposition::Accepted | Disposition::AlreadyKnown
                )
            })
            && self
                .target
                .as_ref()
                .is_some_and(|target| self.source_receipt.as_ref() == Some(&target.receipt))
    }
}

/// Facts about an observation failure, not a diagnosis of transaction validity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Incident {
    pub observed_at_ms: u64,
    pub stage: String,
    pub message: String,
    pub history_failure: bool,
}

pub fn tx_index_key(hash: B256, occurrence: OccurrenceId) -> [u8; 44] {
    let mut key = [0u8; 44];
    key[..32].copy_from_slice(hash.as_slice());
    key[32..].copy_from_slice(&occurrence.key());
    key
}

/// Writes an immutable JSON report atomically.
pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let temporary = temporary_path(path);
    std::fs::write(&temporary, bytes)?;
    std::fs::File::open(&temporary)?.sync_all()?;
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = parent {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("report");
    path.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occurrence_keys_are_ordered_and_exact() {
        let first = OccurrenceId {
            source_height: 9,
            source_index: 4,
        };
        let second = OccurrenceId {
            source_height: 10,
            source_index: 0,
        };
        assert!(first.key() < second.key());
        assert_eq!(OccurrenceId::decode(&first.key()), Some(first));
        assert!(OccurrenceId::decode(&first.key()[..11]).is_none());
        assert!(OccurrenceId::decode(&[0; 13]).is_none());
    }

    #[test]
    fn recovery_requires_a_known_structured_reason() {
        let mut error = RpcFailure {
            code: Some(-32003),
            message: "insufficient balance".into(),
            data: None,
        };
        assert!(!error.retry_after_head());
        error.data = Some(r#"{"name":"InsufficientFeeTokenBalanceError"}"#.into());
        assert!(error.retry_after_head());
        error.data = Some(r#"{"name":"ExpiredError"}"#.into());
        assert!(!error.retry_after_head());
        error.data = Some("truncated".into());
        assert!(!error.retry_after_head());
        error.data = Some(r#"{"name":"InvalidValidBeforeError","validBefore":10}"#.into());
        assert!(!error.retry_after_head());
        assert!(error.expired_at_admission());
        error.code = Some(-32000);
        assert!(!error.expired_at_admission());
    }
}
