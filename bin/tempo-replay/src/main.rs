//! Single-service replay, independent historical profiling, and read-only evidence inspection.

use alloy::primitives::B256;
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::Serialize;
use std::path::PathBuf;
use tempo_replay::{
    config::{Checkpoint, Config, Endpoint},
    evidence::{EvidenceStore, Progress, SharedStore},
    now_ms, profile, service,
    source::{TempoProvider, block_hash, chain_id, finalized_stream},
    state::{Finding, Incident, Occurrence, OccurrenceId, ReplayIdentity, atomic_json},
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "Mirror and observe finalized Tempo traffic")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Relay exact signed transactions and independently observe receipts in one service.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        to_block: Option<u64>,
    },
    /// Produce a workload profile over an exact finalized source range.
    Profile {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        from_block: u64,
        #[arg(long)]
        to_block: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect one consistent shared-store snapshot; no RPC requests are made.
    Inspect {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, conflicts_with = "source_block")]
        tx: Option<B256>,
        #[arg(long, requires = "index", conflicts_with = "tx")]
        source_block: Option<u64>,
        #[arg(long, requires = "source_block")]
        index: Option<u32>,
    },
}

#[derive(Serialize)]
struct Inspection {
    identity: ReplayIdentity,
    observed_at_ms: u64,
    progress: Progress,
    records: Vec<InspectionRecord>,
}

#[derive(Serialize)]
struct InspectionRecord {
    occurrence: OccurrenceId,
    finding: Finding,
    evidence: Occurrence,
    incidents: Vec<Incident>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tempo_replay=info".into()),
        )
        .json()
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().command {
        Command::Run { config, to_block } => {
            let config = Config::load(&config)?;
            let (target_config, checkpoint, run) = config.run()?;
            ensure_end(to_block, checkpoint.height)?;
            if let Some(address) = run.metrics {
                PrometheusBuilder::new()
                    .with_http_listener(address)
                    .install()
                    .context("install Prometheus exporter")?;
            }
            let (source, target) = connect_checked(&config, target_config, checkpoint).await?;
            let settings = run.clone();
            let identity = checkpoint.identity(config.chain_id);
            let store = tokio::task::spawn_blocking(move || {
                EvidenceStore::open(
                    &settings.store.state,
                    identity,
                    settings.max_rounds(),
                    settings.store.max_bytes(),
                    settings.store.min_free_bytes(),
                )
            })
            .await??;
            ensure!(
                to_block.is_none_or(|end| store.progress.source.height <= end),
                "end block precedes the durable source cursor"
            );
            let progress = service::run(
                source,
                target,
                SharedStore::new(store),
                run.clone(),
                config.chain_id,
                to_block,
                shutdown_token(),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&progress)?);
        }
        Command::Profile {
            config,
            from_block,
            to_block,
            output,
        } => {
            ensure!(
                from_block > 0 && from_block <= to_block,
                "invalid profile range; start after a checkpoint block"
            );
            let config = Config::load(&config)?;
            let source = config.source.connect()?;
            ensure!(
                chain_id(&source).await? == config.chain_id,
                "source chain id mismatch"
            );
            let start_after = block_hash(&source, from_block - 1).await?;
            let finalized = finalized_stream(source.clone(), config.chain_id, start_after).await?;
            let report = profile::WorkloadProfile::profile(
                config.chain_id,
                source,
                finalized,
                from_block,
                to_block,
            )
            .await?;
            atomic_json(&output, &report)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Inspect {
            config,
            tx,
            source_block,
            index,
        } => {
            ensure!(
                tx.is_some() || source_block.is_some(),
                "provide --tx or --source-block/--index"
            );
            let config = Config::load(&config)?;
            let settings = config.run()?.2.clone();
            let identity = config.run()?.1.identity(config.chain_id);
            let inspection = tokio::task::spawn_blocking(move || {
                let store = EvidenceStore::open_reader(&settings.store.state)?;
                ensure!(
                    store.identity()? == identity,
                    "config does not match the stored replay identity"
                );
                let observed_at_ms = now_ms();
                let evidence = if let Some(hash) = tx {
                    store.by_hash(hash)?
                } else if let Some((source_height, source_index)) = source_block.zip(index) {
                    let id = OccurrenceId {
                        source_height,
                        source_index,
                    };
                    store
                        .occurrence(id)?
                        .map(|record| (id, record))
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                };
                let records = evidence
                    .into_iter()
                    .map(|(occurrence, evidence)| {
                        let center = evidence
                            .attempts
                            .first()
                            .map_or(evidence.queued_at_ms, |attempt| attempt.started_at_ms);
                        Ok(InspectionRecord {
                            occurrence,
                            finding: evidence.finding(
                                store.progress.target.height,
                                observed_at_ms,
                                settings.missing_after_blocks(),
                                settings.missing_after().as_millis() as u64,
                            ),
                            incidents: store.incidents(
                                center.saturating_sub(300_000),
                                center.saturating_add(300_000),
                            )?,
                            evidence,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok::<_, anyhow::Error>(Inspection {
                    identity,
                    observed_at_ms,
                    progress: store.progress,
                    records,
                })
            })
            .await??;
            println!("{}", serde_json::to_string_pretty(&inspection)?);
        }
    }
    Ok(())
}

async fn connect_checked(
    config: &Config,
    target: &Endpoint,
    checkpoint: &Checkpoint,
) -> Result<(TempoProvider, TempoProvider)> {
    let source = config.source.connect()?;
    let target = target.connect()?;
    check_endpoint(
        &source,
        config.chain_id,
        checkpoint.height,
        checkpoint.source_hash,
        "source",
    )
    .await?;
    check_endpoint(
        &target,
        config.chain_id,
        checkpoint.height,
        checkpoint.target_hash,
        "target",
    )
    .await?;
    Ok((source, target))
}

fn ensure_end(to_block: Option<u64>, checkpoint_height: u64) -> Result<()> {
    ensure!(
        to_block.is_none_or(|height| height > checkpoint_height),
        "end block must follow the checkpoint"
    );
    Ok(())
}

async fn check_endpoint(
    provider: &TempoProvider,
    expected_chain_id: u64,
    height: u64,
    expected: B256,
    name: &str,
) -> Result<()> {
    ensure!(
        chain_id(provider).await? == expected_chain_id,
        "{name} chain id mismatch"
    );
    ensure!(
        block_hash(provider, height).await? == expected,
        "{name} checkpoint hash mismatch"
    );
    Ok(())
}

fn shutdown_token() -> CancellationToken {
    let stop = CancellationToken::new();
    let signal = stop.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            signal.cancel();
            return;
        }
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    stop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_service_cli_rejects_legacy_split_state_flags() {
        assert!(Cli::try_parse_from(["tempo-replay", "run", "--config", "replay.toml"]).is_ok());
        assert!(Cli::try_parse_from(["tempo-replay", "audit", "--config", "replay.toml"]).is_err());
        assert!(
            Cli::try_parse_from([
                "tempo-replay",
                "inspect",
                "--config",
                "replay.toml",
                "--source-block",
                "1",
                "--index",
                "0"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "tempo-replay",
                "inspect",
                "--config",
                "replay.toml",
                "--source-block",
                "1"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "tempo-replay",
                "inspect",
                "--mirror-state",
                "mirror",
                "--audit-state",
                "audit"
            ])
            .is_err()
        );
    }
}
