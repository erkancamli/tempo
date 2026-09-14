//! Exact-byte relay with bounded nonce-lane concurrency and conservative recovery.

use crate::{
    config::Run,
    evidence::{Completed, Dispatch, SharedStore},
    now_ms,
    source::{
        FinalizedBlock, HistoryError, TempoProvider, fetch_finalized_block, finalized_stream,
        history_failure,
    },
    state::{Attempt, BlockCursor, Disposition, RpcFailure},
    store::bounded_error,
};
use alloy::{consensus::BlockHeader, providers::Provider};
use anyhow::{Result, ensure};
use futures_util::{StreamExt, stream};
use metrics::{counter, gauge, histogram};
use std::{collections::BTreeMap, future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

pub async fn run(
    source: TempoProvider,
    target: TempoProvider,
    store: SharedStore,
    settings: Run,
    chain_id: u64,
    to_block: Option<u64>,
    stop: CancellationToken,
) -> Result<()> {
    let cursor = store.progress().await?.source;
    if to_block.is_some_and(|end| cursor.height >= end) {
        return recovery_until_stopped(&target, &store, &settings, &stop).await;
    }
    // Bounded read-ahead overlaps source RPC with submission without moving a durable cursor.
    let (send, mut receive) = tokio::sync::mpsc::channel(2);
    let reader = tokio::spawn(read_source(
        source,
        store.clone(),
        chain_id,
        cursor,
        to_block,
        send,
        stop.clone(),
    ));
    let result = async {
        recover(&target, &store, &settings, &stop).await?;
        let mut recovery = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                block = receive.recv() => {
                    let Some(block) = block else { break; };
                    let cursor = block.cursor;
                    gauge!("tempo_replay_source_lag_ms").set(now_ms().saturating_sub(block.timestamp_ms) as f64);
                    let ids = store.with(move |store| store.prepare_block(block)).await?;
                    let queued = store.with(move |store| store.begin_round(ids, false)).await?;
                    let expected = queued.len();
                    // On shutdown, lanes stop issuing requests but in-flight ones finish and
                    // their outcomes are committed. The cursor advances only when every queued
                    // occurrence has an outcome; anything else stays a durable ambiguous intent.
                    let completed = submit_all(target.clone(), queued, &settings, &stop).await;
                    let source = (completed.len() == expected).then_some(cursor);
                    store.with(move |store| store.complete_round(completed, source)).await?;
                    if source.is_none() { break; }
                }
                _ = recovery.tick() => recover(&target, &store, &settings, &stop).await?,
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    if stop.is_cancelled() || result.is_err() {
        reader.abort();
    }
    let read_result = reader.await;
    result?;
    if stop.is_cancelled() {
        return Ok(());
    }
    if let Err(error) = read_result? {
        let history = history_failure(&error);
        let message = format!("source reader failed: {error:#}");
        store
            .with(move |store| store.incident("source_reader", message, history))
            .await?;
        return Err(error);
    }
    recovery_until_stopped(&target, &store, &settings, &stop).await
}

/// Streams authenticated source blocks after `cursor`. RPC outages are recorded once per
/// episode and the stream is re-initialized from the last delivered block; history
/// inconsistencies are fatal.
async fn read_source(
    source: TempoProvider,
    store: SharedStore,
    chain_id: u64,
    cursor: BlockCursor,
    to_block: Option<u64>,
    send: tokio::sync::mpsc::Sender<FinalizedBlock>,
    stop: CancellationToken,
) -> Result<()> {
    let mut previous = cursor;
    let mut failed = false;
    loop {
        if stop.is_cancelled() || to_block == Some(previous.height) {
            return Ok(());
        }
        let result = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            result = async {
                let mut finalized = finalized_stream(source.clone(), chain_id, previous.hash).await?;
                loop {
                    let header = finalized.next().await.ok_or_else(|| anyhow::anyhow!("authenticated source stream ended"))??;
                    if to_block.is_some_and(|end| header.number() > end) { return Ok(()); }
                    ensure!(header.number() == previous.height + 1 && header.parent_hash() == previous.hash, HistoryError("source history is not contiguous"));
                    let block = fetch_finalized_block(&source, &header).await?;
                    let cursor = block.cursor;
                    if send.send(block).await.is_err() { return Ok(()); }
                    previous = cursor;
                    failed = false;
                    if to_block == Some(previous.height) { return Ok(()); }
                }
            } => result,
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if history_failure(&error) => return Err(error),
            Err(error) => {
                if !failed {
                    let message = format!("{error:#}");
                    tracing::warn!(stage = "source_reader", error = %message, "source stream failed; retrying from the last delivered block");
                    store
                        .with(move |store| store.incident("source_reader", message, false))
                        .await?;
                    failed = true;
                }
                tokio::select! {
                    _ = stop.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    }
}

async fn recovery_until_stopped(
    target: &TempoProvider,
    store: &SharedStore,
    settings: &Run,
    stop: &CancellationToken,
) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = tick.tick() => recover(target, store, settings, stop).await?,
        }
    }
}

async fn recover(
    target: &TempoProvider,
    store: &SharedStore,
    settings: &Run,
    stop: &CancellationToken,
) -> Result<()> {
    let queued = store
        .with(move |store| {
            let ids = store.recovery_candidates()?;
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            store.begin_round(ids, true)
        })
        .await?;
    if queued.is_empty() {
        return Ok(());
    }
    counter!("tempo_replay_recovery_submissions_total").increment(queued.len() as u64);
    let completed = submit_all(target.clone(), queued, settings, stop).await;
    if completed.is_empty() {
        return Ok(());
    }
    store
        .with(move |store| store.complete_round(completed, None))
        .await
}

async fn submit_all(
    target: TempoProvider,
    queued: Vec<Dispatch>,
    settings: &Run,
    stop: &CancellationToken,
) -> Vec<Completed> {
    let retries = settings.retries();
    let delay = Duration::from_millis(settings.retry_delay_ms());
    gauge!("tempo_replay_dispatch_queue").set(queued.len() as f64);
    let completed = submit_lanes(queued, settings.concurrency(), stop, move |queued| {
        let target = target.clone();
        let stop = stop.clone();
        async move { submit(&target, queued, retries, delay, &stop).await }
    })
    .await;
    gauge!("tempo_replay_dispatch_queue").set(0.0);
    completed
}

/// One outstanding request per sequential lane. Expiring nonces are independent occurrences.
/// Completion order never holds up unrelated lanes; source order within a lane is unchanged.
/// After `stop`, lanes issue no further requests; occurrences never submitted are omitted.
async fn submit_lanes<F, Fut>(
    queued: Vec<Dispatch>,
    concurrency: usize,
    stop: &CancellationToken,
    submit: F,
) -> Vec<Completed>
where
    F: Fn(Dispatch) -> Fut + Clone,
    Fut: Future<Output = Completed>,
{
    let mut lanes = BTreeMap::new();
    for queued in queued {
        let key = (
            queued.transaction.sender,
            queued.transaction.nonce_key,
            queued.transaction.expiring.then_some(queued.id),
        );
        lanes.entry(key).or_insert_with(Vec::new).push(queued);
    }
    stream::iter(lanes.into_values().map(|lane| {
        let submit = submit.clone();
        async move {
            let mut completed = Vec::with_capacity(lane.len());
            for queued in lane {
                if stop.is_cancelled() {
                    break;
                }
                completed.push(submit(queued).await);
            }
            completed
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .flatten()
    .collect()
}

async fn submit(
    target: &TempoProvider,
    queued: Dispatch,
    retries: u32,
    delay: Duration,
    stop: &CancellationToken,
) -> Completed {
    let mut attempts = Vec::new();
    let mut uncertain = queued.uncertain_delivery;
    for retry in 0..=retries {
        let started_at_ms = now_ms();
        histogram!("tempo_replay_queue_wait_ms")
            .record(started_at_ms.saturating_sub(queued.queued_at_ms) as f64);
        let (disposition, failure) = match target.send_raw_transaction(&queued.raw).await {
            Ok(pending) if *pending.tx_hash() == queued.transaction.hash => {
                (Disposition::Accepted, None)
            }
            Ok(pending) => (
                Disposition::Ambiguous,
                Some(RpcFailure {
                    code: None,
                    message: format!("target returned unexpected hash {}", pending.tx_hash()),
                    data: None,
                }),
            ),
            Err(error) => {
                let response = error.as_error_resp();
                let message = response.map_or_else(
                    || error.to_string(),
                    |response| response.message.to_string(),
                );
                let disposition = classify_response(response.is_some(), &message, uncertain);
                let failure = RpcFailure {
                    code: response.map(|response| response.code),
                    message: bounded_error(message),
                    data: response
                        .and_then(|response| response.data.as_ref())
                        .map(|data| bounded_error(data.get())),
                };
                (disposition, Some(failure))
            }
        };
        let completed_at_ms = now_ms();
        counter!("tempo_replay_submissions_total", "outcome" => disposition_name(disposition))
            .increment(1);
        histogram!("tempo_replay_rpc_ms")
            .record(completed_at_ms.saturating_sub(started_at_ms) as f64);
        tracing::debug!(target: "tempo_replay", tx_hash = %queued.transaction.hash,
            source_height = queued.id.source_height, source_index = queued.id.source_index,
            stage = "rpc_submission", queued_at_ms = queued.queued_at_ms, started_at_ms, completed_at_ms,
            outcome = disposition_name(disposition), error = ?failure, "shadow submission outcome");
        attempts.push(Attempt {
            queued_at_ms: queued.queued_at_ms,
            target_observed: queued.target_observed,
            started_at_ms,
            completed_at_ms,
            disposition,
            failure,
        });
        if disposition != Disposition::Ambiguous || stop.is_cancelled() {
            break;
        }
        uncertain = true;
        if retry < retries {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = tokio::time::sleep(delay.saturating_mul(1 << retry.min(8))) => {}
            }
        }
    }
    Completed {
        id: queued.id,
        attempts,
    }
}

fn classify_response(rpc_response: bool, message: &str, uncertain: bool) -> Disposition {
    if !rpc_response {
        return Disposition::Ambiguous;
    }
    let message = message.to_ascii_lowercase();
    if message.contains("already known") || message.contains("already imported") {
        Disposition::AlreadyKnown
    } else if uncertain
        && (message.contains("nonce too low") || message.contains("nonce is too low"))
    {
        Disposition::PossiblyIncluded
    } else {
        Disposition::Rejected
    }
}

fn disposition_name(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Accepted => "accepted",
        Disposition::AlreadyKnown => "already_known",
        Disposition::Rejected => "rejected",
        Disposition::PossiblyIncluded => "possibly_included",
        Disposition::Ambiguous => "ambiguous",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{BlockCursor, OccurrenceId};
    use alloy::primitives::{Address, B256, U256};
    use std::sync::{Arc, Mutex};

    fn queued(index: u32, sender: u8, expiring: bool) -> Dispatch {
        Dispatch {
            id: OccurrenceId {
                source_height: 1,
                source_index: index,
            },
            transaction: crate::source::ReplayMetadata {
                hash: B256::repeat_byte(index as u8),
                transaction_type: 2,
                sender: Address::repeat_byte(sender),
                nonce: u64::from(index),
                nonce_key: if expiring { U256::MAX } else { U256::ZERO },
                expiring,
                encoded_length: 1,
                gas_limit: 21_000,
                valid_before: None,
                valid_after: None,
            },
            raw: vec![index as u8],
            queued_at_ms: 0,
            target_observed: BlockCursor::default(),
            uncertain_delivery: false,
        }
    }

    #[tokio::test]
    async fn lanes_preserve_order_without_serializing_other_senders_or_expiring_nonces() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let result = submit_lanes(
            vec![
                queued(0, 1, false),
                queued(1, 1, false),
                queued(2, 2, false),
                queued(3, 1, true),
                queued(4, 1, true),
            ],
            4,
            &CancellationToken::new(),
            move |tx| {
                let events = events.clone();
                async move {
                    let index = tx.id.source_index;
                    events.lock().unwrap().push((index, "start"));
                    if index == 0 || index == 3 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    events.lock().unwrap().push((index, "finish"));
                    Completed {
                        id: tx.id,
                        attempts: Vec::new(),
                    }
                }
            },
        )
        .await;
        assert_eq!(result.len(), 5);
        let events = observed.lock().unwrap();
        let position = |event| events.iter().position(|e| *e == event).unwrap();
        assert!(position((0, "finish")) < position((1, "start")));
        assert!(position((2, "start")) < position((0, "finish")));
        assert!(position((4, "start")) < position((3, "finish")));
    }

    #[tokio::test]
    async fn shutdown_finishes_issued_requests_but_starts_no_new_ones() {
        let stop = CancellationToken::new();
        let signal = stop.clone();
        let result = submit_lanes(
            vec![
                queued(0, 1, false),
                queued(1, 1, false),
                queued(2, 2, false),
            ],
            4,
            &stop,
            move |tx| {
                let signal = signal.clone();
                async move {
                    if tx.id.source_index == 0 {
                        signal.cancel();
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Completed {
                        id: tx.id,
                        attempts: Vec::new(),
                    }
                }
            },
        )
        .await;
        let mut ids: Vec<_> = result.into_iter().map(|c| c.id.source_index).collect();
        ids.sort_unstable();
        // Lane (1) had already issued index 0, which completes; index 1 was never issued.
        // Lane (2) either started before the cancel or not; it is never left half-done.
        assert!(ids.contains(&0) && !ids.contains(&1));
    }

    #[tokio::test]
    async fn rpc_attempts_preserve_timing_and_structured_rejections_without_blind_retries() {
        use alloy::providers::{ProviderBuilder, mock::Asserter};
        let asserter = Asserter::new();
        let provider = ProviderBuilder::<_, _, tempo_alloy::TempoNetwork>::default()
            .connect_mocked_client(asserter.clone());
        let stop = CancellationToken::new();
        let request = queued(1, 1, false);
        asserter.push_success(&request.transaction.hash);
        let completed = submit(&provider, request, 2, Duration::ZERO, &stop).await;
        assert_eq!(completed.attempts.len(), 1);
        let attempt = &completed.attempts[0];
        assert_eq!(attempt.disposition, Disposition::Accepted);
        assert!(
            attempt.started_at_ms >= attempt.queued_at_ms
                && attempt.completed_at_ms >= attempt.started_at_ms
        );
        asserter.push_failure(serde_json::from_value(serde_json::json!({
            "code": -32003, "message": "balance too low", "data": {"name": "InsufficientFeeTokenBalanceError", "fee": "10", "balance": "3"}
        })).unwrap());
        let completed = submit(&provider, queued(2, 1, false), 2, Duration::ZERO, &stop).await;
        assert_eq!(completed.attempts.len(), 1);
        assert_eq!(completed.attempts[0].disposition, Disposition::Rejected);
        let error = completed.attempts[0].failure.as_ref().unwrap();
        assert!(error.retry_after_head());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(error.data.as_ref().unwrap()).unwrap()["balance"],
            "3"
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn ambiguous_attempt_followed_by_nonce_too_low_is_not_a_fresh_rejection() {
        use alloy::providers::{ProviderBuilder, mock::Asserter};
        let asserter = Asserter::new();
        let provider = ProviderBuilder::<_, _, tempo_alloy::TempoNetwork>::default()
            .connect_mocked_client(asserter.clone());
        asserter.push_success(&B256::repeat_byte(99));
        asserter.push_failure_msg("nonce too low");
        let completed = submit(
            &provider,
            queued(1, 1, false),
            2,
            Duration::ZERO,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(completed.attempts.len(), 2);
        assert_eq!(completed.attempts[0].disposition, Disposition::Ambiguous);
        assert_eq!(
            completed.attempts[1].disposition,
            Disposition::PossiblyIncluded
        );
        assert!(asserter.read_q().is_empty());
    }

    #[test]
    fn rpc_classification_does_not_confuse_transport_or_nonce_ambiguity_with_rejection() {
        assert_eq!(
            classify_response(false, "nonce too low", false),
            Disposition::Ambiguous
        );
        assert_eq!(
            classify_response(true, "nonce too low", false),
            Disposition::Rejected
        );
        assert_eq!(
            classify_response(true, "nonce too low", true),
            Disposition::PossiblyIncluded
        );
        assert_eq!(
            classify_response(true, "already known", true),
            Disposition::AlreadyKnown
        );
        assert_eq!(
            classify_response(true, "expired", true),
            Disposition::Rejected
        );
    }
}
