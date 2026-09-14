//! Independent receipt workers. RPC/observation outages are recorded and retried, not relay gates.

use crate::{
    evidence::SharedStore,
    now_ms,
    source::{
        HistoryError, TempoProvider, fetch_finalized_block, history_failure, replayable,
        shadow_finalized_stream, shadow_network_identity,
    },
    state::{BlockCursor, Incident, ReceiptSummary, TargetObservation, TxLocation},
};
use alloy::{
    consensus::{BlockHeader, Transaction, transaction::TxHashRef},
    network::ReceiptResponse,
    primitives::{B256, keccak256},
    providers::Provider,
};
use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use std::time::Duration;
use tempo_chainspec::{
    TempoHardforks,
    spec::{SYSTEM_TX_ADDRESSES, SYSTEM_TX_COUNT, chainspec_from_chain_id},
};
use tempo_primitives::TempoTxEnvelope;
use tokio_util::sync::CancellationToken;

pub async fn source_receipts(
    provider: TempoProvider,
    store: SharedStore,
    stop: CancellationToken,
) -> Result<()> {
    let mut failed = false;
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let block = store
            .with(|store| store.source_block(store.progress.source_receipts.height + 1))
            .await?;
        let Some(block) = block else {
            tokio::select! { _ = stop.cancelled() => return Ok(()), _ = tokio::time::sleep(Duration::from_millis(250)) => {} }
            continue;
        };
        let result = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            result = fetch_receipts(&provider, block.cursor, &block.hashes) => result,
        };
        match result {
            Ok(receipts) => {
                store
                    .with(move |store| store.source_receipts(block, receipts))
                    .await?;
                failed = false;
            }
            Err(error) => {
                report_failure(&store, "source_receipts", &error, &mut failed).await?;
                tokio::select! { _ = stop.cancelled() => return Ok(()), _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
            }
        }
    }
}

pub async fn target(
    provider: TempoProvider,
    store: SharedStore,
    chain_id: u64,
    stop: CancellationToken,
) -> Result<()> {
    let mut failed = false;
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let (progress, identity) = store
            .with(|store| Ok((store.progress.clone(), store.identity()?)))
            .await?;
        let cursor = progress.target;
        // Restart at the last atomically committed target cursor after any observation failure.
        let result = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            result = async {
                // One header read; without the identity every re-initialization would walk the
                // whole checkpoint..cursor range to derive it.
                let network = shadow_network_identity(&provider, identity.target_cursor()).await?;
                let mut finalized = shadow_finalized_stream(provider.clone(), cursor.hash, progress.checkpoint_height, network).await?;
                let mut previous = cursor;
                loop {
                    let header = finalized.next().await.context("target finalized stream ended")??;
                    ensure!(header.number() == previous.height + 1 && header.parent_hash() == previous.hash, HistoryError("target history is not contiguous"));
                    let block = fetch_finalized_block(&provider, &header).await?;
                    let hashes: Vec<_> = block.transactions.iter().map(|tx| *tx.tx_hash()).collect();
                    let receipts = fetch_receipts(&provider, block.cursor, &hashes).await?;
                    let mut failures = system_invariant_failures(&block.transactions, block.timestamp_ms / 1000, chain_id)?;
                    let mut observations = Vec::new();
                    let mut system_txs = 0;
                    for (index, (tx, receipt)) in block.transactions.into_iter().zip(receipts).enumerate() {
                        let location = TxLocation { block: block.cursor, index: u32::try_from(index)?, timestamp_ms: block.timestamp_ms };
                        if replayable(&tx) {
                            observations.push(TargetObservation { transaction_hash: *tx.tx_hash(), location, receipt });
                        } else {
                            system_txs += 1;
                            if !receipt.status { failures.push(system_failure(format!("system/subblock transaction {} reverted at {}:{}", tx.tx_hash(), location.block.height, index))); }
                        }
                    }
                    previous = block.cursor;
                    store.with(move |store| store.observe_target(block.cursor, block.timestamp_ms, observations, system_txs, failures)).await?;
                    failed = false;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            } => result,
        };
        if let Err(error) = result {
            report_failure(&store, "target_observation", &error, &mut failed).await?;
            if history_failure(&error) {
                return Err(error);
            }
            tokio::select! { _ = stop.cancelled() => return Ok(()), _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
        }
    }
}

async fn report_failure(
    store: &SharedStore,
    stage: &'static str,
    error: &anyhow::Error,
    failed: &mut bool,
) -> Result<()> {
    // One durable incident per outage episode, not one write per retry during an outage.
    if !*failed || history_failure(error) {
        let message = format!("{error:#}");
        let history = history_failure(error);
        tracing::warn!(stage, error = %message, "receipt observation failed; dispatch remains independent");
        store
            .with(move |store| store.incident(stage, message, history))
            .await?;
        *failed = true;
    }
    Ok(())
}

async fn fetch_receipts(
    provider: &TempoProvider,
    cursor: BlockCursor,
    hashes: &[B256],
) -> Result<Vec<ReceiptSummary>> {
    let receipts = provider
        .get_block_receipts(cursor.hash.into())
        .await
        .context("fetch finalized block receipts")?
        .with_context(|| format!("finalized block {} has no receipts", cursor.height))?;
    ensure!(
        receipts.len() == hashes.len(),
        "receipt count disagrees with authenticated block"
    );
    for (index, (receipt, hash)) in receipts.iter().zip(hashes).enumerate() {
        ensure!(
            receipt.transaction_hash() == *hash
                && receipt.block_hash() == Some(cursor.hash)
                && receipt.block_number() == Some(cursor.height)
                && receipt.transaction_index() == Some(index as u64),
            "receipt identity disagrees with authenticated block at {}:{index}",
            cursor.height
        );
    }
    Ok(receipts.iter().map(receipt_summary).collect())
}

fn receipt_summary(receipt: &tempo_alloy::rpc::TempoTransactionReceipt) -> ReceiptSummary {
    ReceiptSummary {
        status: receipt.status(),
        gas_used: receipt.gas_used(),
        logs_hash: consensus_logs_hash(receipt.logs()),
    }
}

fn consensus_logs_hash(logs: &[alloy::rpc::types::Log]) -> B256 {
    let mut encoded = Vec::new();
    alloy::rlp::encode_iter::<_, _, alloy::primitives::Log>(
        logs.iter().map(|log| &log.inner),
        &mut encoded,
    );
    keccak256(encoded)
}

fn system_invariant_failures(
    transactions: &[TempoTxEnvelope],
    timestamp: u64,
    chain_id: u64,
) -> Result<Vec<Incident>> {
    let chainspec = chainspec_from_chain_id(chain_id)
        .with_context(|| format!("unsupported Tempo chain id {chain_id}"))?;
    let expected = if chainspec.is_t4_active_at_timestamp(timestamp) {
        0
    } else {
        SYSTEM_TX_COUNT
    };
    let mut failures = Vec::new();
    let count = transactions.iter().filter(|tx| tx.is_system_tx()).count();
    if count != expected {
        failures.push(system_failure(format!(
            "expected {expected} system transactions, observed {count}"
        )));
    }
    for tx in transactions.iter().filter(|tx| tx.is_system_tx()) {
        if !tx.is_valid_system_tx(chain_id) {
            failures.push(system_failure(format!(
                "invalid system transaction {}",
                tx.tx_hash()
            )));
        }
    }
    let tail = &transactions[transactions.len().saturating_sub(expected)..];
    for (tx, expected_to) in tail.iter().zip(SYSTEM_TX_ADDRESSES) {
        if !tx.is_system_tx() || tx.to() != Some(expected_to) {
            failures.push(system_failure(format!(
                "end-of-block system transaction has target {:?}, expected {expected_to}",
                tx.to()
            )));
        }
    }
    Ok(failures)
}

fn system_failure(message: String) -> Incident {
    Incident {
        observed_at_ms: now_ms(),
        stage: "system_execution".into(),
        message,
        history_failure: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn receipt_outage_does_not_gate_dispatch_or_lose_the_receipt_cursor() {
        use crate::{evidence::EvidenceStore, source::FinalizedBlock, state::ReplayIdentity};
        use alloy::providers::{ProviderBuilder, mock::Asserter};
        let directory = tempfile::tempdir().unwrap();
        let identity = ReplayIdentity {
            chain_id: 4217,
            checkpoint_height: 10,
            source_hash: B256::repeat_byte(1),
            target_hash: B256::repeat_byte(2),
        };
        let store = SharedStore::new(
            EvidenceStore::open(directory.path(), identity, 3, u64::MAX, 0).unwrap(),
        );
        let cursor = BlockCursor {
            height: 11,
            hash: B256::repeat_byte(3),
        };
        store
            .with(move |store| {
                store.prepare_block(FinalizedBlock {
                    cursor,
                    timestamp_ms: 11_000,
                    transactions: Vec::new(),
                })
            })
            .await
            .unwrap();
        let asserter = Asserter::new();
        let provider = ProviderBuilder::<_, _, tempo_alloy::TempoNetwork>::default()
            .connect_mocked_client(asserter.clone());
        asserter.push_failure_msg("receipt RPC temporarily unavailable");
        let stop = CancellationToken::new();
        let worker = tokio::spawn(source_receipts(provider, store.clone(), stop.clone()));
        tokio::time::timeout(Duration::from_secs(3), async {
            while store.progress().await.unwrap().observation_failures == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Source dispatch can commit while the independent receipt worker is retrying.
            store
                .with(move |store| store.complete_round(Vec::new(), Some(cursor)))
                .await
                .unwrap();
            assert_eq!(store.progress().await.unwrap().source, cursor);
            assert_eq!(store.progress().await.unwrap().source_receipts.height, 10);
            asserter.push_success(&Some(
                Vec::<tempo_alloy::rpc::TempoTransactionReceipt>::new(),
            ));
            while store.progress().await.unwrap().source_receipts != cursor {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        stop.cancel();
        worker.await.unwrap().unwrap();
        assert_eq!(store.progress().await.unwrap().observation_failures, 1);
    }

    #[test]
    fn system_invariants_follow_the_hardfork_schedule() {
        assert!(!system_invariant_failures(&[], 0, 4217).unwrap().is_empty());
        assert!(
            system_invariant_failures(&[], u64::MAX, 4217)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn receipt_log_hash_ignores_rpc_location_metadata() {
        let receipt = |block_byte: u8, block_number: u64| {
            let block_hash = B256::repeat_byte(block_byte);
            serde_json::from_value::<tempo_alloy::rpc::TempoTransactionReceipt>(serde_json::json!({
                "type": "0x2", "status": "0x1", "cumulativeGasUsed": "0x5208", "logsBloom": format!("0x{}", "00".repeat(256)),
                "logs": [{
                    "address": "0x1111111111111111111111111111111111111111", "topics": [format!("{:#x}", B256::repeat_byte(0x22))],
                    "data": "0x010203", "blockHash": format!("{block_hash:#x}"), "blockNumber": format!("0x{block_number:x}"),
                    "blockTimestamp": "0x1234", "transactionHash": format!("{:#x}", B256::repeat_byte(0x33)),
                    "transactionIndex": "0x1", "logIndex": "0x2", "removed": false
                }],
                "transactionHash": format!("{:#x}", B256::repeat_byte(0x33)), "transactionIndex": "0x1",
                "blockHash": format!("{block_hash:#x}"), "blockNumber": format!("0x{block_number:x}"),
                "gasUsed": "0x5208", "effectiveGasPrice": "0x1", "from": "0x4444444444444444444444444444444444444444",
                "to": "0x5555555555555555555555555555555555555555", "contractAddress": null,
                "feePayer": "0x4444444444444444444444444444444444444444"
            })).unwrap()
        };
        let source = receipt(0xaa, 10);
        let target = receipt(0xbb, 11);
        assert_ne!(
            serde_json::to_vec(source.logs()).unwrap(),
            serde_json::to_vec(target.logs()).unwrap()
        );
        assert_eq!(receipt_summary(&source), receipt_summary(&target));
    }
}
