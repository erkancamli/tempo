//! One process, independent relay/receipt workers, and a shared durable writer.

use crate::{
    config::Run,
    evidence::{Progress, SharedStore},
    now_ms, observe, relay,
    source::TempoProvider,
};
use anyhow::{Context, Result};
use metrics::gauge;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub async fn run(
    source: TempoProvider,
    target: TempoProvider,
    store: SharedStore,
    settings: Run,
    chain_id: u64,
    to_block: Option<u64>,
    stop: CancellationToken,
) -> Result<Progress> {
    let mut tasks = JoinSet::new();
    let (s, t, db, cfg, token) = (
        source.clone(),
        target.clone(),
        store.clone(),
        settings.clone(),
        stop.clone(),
    );
    tasks.spawn(async move {
        relay::run(s, t, db, cfg, chain_id, to_block, token)
            .await
            .map(|()| true)
    });
    let (s, db, token) = (source, store.clone(), stop.clone());
    tasks.spawn(async move { observe::source_receipts(s, db, token).await.map(|()| false) });
    let (db, token) = (store.clone(), stop.clone());
    tasks.spawn(async move {
        observe::target(target, db, chain_id, token)
            .await
            .map(|()| false)
    });
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let result = async {
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                task = tasks.join_next() => {
                    task.context("all replay workers exited")???;
                }
                _ = tick.tick() => {
                    let retain = settings.retain_included_blocks();
                    let stall = settings.finality_stall().as_millis() as u64;
                    let (progress, pending) = store.with(move |store| {
                        store.check_stall(stall)?;
                        store.prune(retain)?;
                        Ok((store.progress.clone(), store.has_pending()?))
                    }).await?;
                    gauge!("tempo_replay_source_height").set(progress.source.height as f64);
                    gauge!("tempo_replay_source_receipt_height").set(progress.source_receipts.height as f64);
                    gauge!("tempo_replay_target_height").set(progress.target.height as f64);
                    gauge!("tempo_replay_target_finality_stalled").set(f64::from(u32::from(progress.stall_open)));
                    let time_elapsed = !settings.missing_after().is_zero()
                        && now_ms().saturating_sub(progress.last_dispatch_ms) >= settings.missing_after().as_millis() as u64;
                    let blocks_elapsed = settings.missing_after_blocks() > 0
                        && progress.target.height.saturating_sub(progress.last_dispatch_target.height) >= settings.missing_after_blocks();
                    if to_block.is_some_and(|end| progress.source.height >= end && progress.source_receipts.height >= end)
                        && (!pending || time_elapsed || blocks_elapsed) { break; }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    stop.cancel();
    // Let workers leave short DB operations before flushing; unfinished RPC rounds retain intents.
    let mut worker_error = None;
    while let Some(task) = tasks.join_next().await {
        if let Err(error) = task.map_err(anyhow::Error::from).and_then(|result| result) {
            worker_error.get_or_insert(error);
        }
    }
    store.with(|store| store.flush()).await?;
    result?;
    if let Some(error) = worker_error {
        return Err(error);
    }
    store.progress().await
}
