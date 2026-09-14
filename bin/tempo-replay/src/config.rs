//! Shared endpoint/checkpoint configuration and bounded single-service settings.

use crate::{
    source::{TempoProvider, connect},
    state::ReplayIdentity,
};
use alloy::primitives::B256;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub chain_id: u64,
    pub source: Endpoint,
    pub target: Option<Endpoint>,
    pub checkpoint: Option<Checkpoint>,
    pub run: Option<Run>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(
            &std::fs::read_to_string(path)
                .with_context(|| format!("read config {}", path.display()))?,
        )
        .with_context(|| {
            format!(
                "parse config {} (legacy [audit] settings now belong in [run])",
                path.display()
            )
        })?;
        ensure!(config.chain_id > 0, "chain id must be positive");
        Ok(config)
    }

    pub fn run(&self) -> Result<(&Endpoint, &Checkpoint, &Run)> {
        let target = self.target.as_ref().context("run requires [target]")?;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .context("run requires [checkpoint]")?;
        let run = self.run.as_ref().context("run requires [run]")?;
        ensure!(run.concurrency() > 0, "concurrency must be positive");
        ensure!(
            run.retries() <= 4 && (1..=8).contains(&run.max_rounds()),
            "retries must be <= 4 and max_rounds in 1..=8"
        );
        ensure!(
            run.retry_delay_ms() <= 60_000,
            "retry_delay_ms must be <= 60000"
        );
        ensure!(run.store.max_bytes() > 0, "database limit must be positive");
        ensure!(
            run.missing_after_blocks() > 0 || !run.missing_after().is_zero(),
            "missing horizon must be positive"
        );
        ensure!(
            checkpoint.source_hash != checkpoint.target_hash,
            "source and patched target checkpoint hashes must differ"
        );
        Ok((target, checkpoint, run))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub url: String,
    pub credential_env: Option<String>,
    pub ca_file: Option<PathBuf>,
}

impl Endpoint {
    pub fn connect(&self) -> Result<TempoProvider> {
        let url = reqwest::Url::parse(&self.url).context("invalid RPC URL")?;
        ensure!(url.scheme() == "https", "RPC endpoints must use HTTPS");
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "RPC URL cannot embed credentials, query parameters, or fragments"
        );
        let credential = self
            .credential_env
            .as_ref()
            .map(|name| std::env::var(name).with_context(|| format!("read credential from {name}")))
            .transpose()?;
        let ca = self
            .ca_file
            .as_ref()
            .map(|path| std::fs::read(path).with_context(|| format!("read CA {}", path.display())))
            .transpose()?;
        connect(&self.url, credential.as_deref(), ca.as_deref())
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub height: u64,
    pub source_hash: B256,
    pub target_hash: B256,
}

impl Checkpoint {
    pub fn identity(&self, chain_id: u64) -> ReplayIdentity {
        ReplayIdentity {
            chain_id,
            checkpoint_height: self.height,
            source_hash: self.source_hash,
            target_hash: self.target_hash,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    #[serde(flatten)]
    pub store: StoreConfig,
    pub metrics: Option<SocketAddr>,
    concurrency: Option<usize>,
    retries: Option<u32>,
    retry_delay_ms: Option<u64>,
    max_rounds: Option<u32>,
    retain_included_blocks: Option<u64>,
    missing_after_blocks: Option<u64>,
    missing_after_seconds: Option<u64>,
    finality_stall_seconds: Option<u64>,
}

impl Run {
    pub fn concurrency(&self) -> usize {
        self.concurrency.unwrap_or(64)
    }
    pub fn retries(&self) -> u32 {
        self.retries.unwrap_or(2)
    }
    pub fn retry_delay_ms(&self) -> u64 {
        self.retry_delay_ms.unwrap_or(250)
    }
    pub fn max_rounds(&self) -> u32 {
        self.max_rounds.unwrap_or(3)
    }
    pub fn retain_included_blocks(&self) -> u64 {
        self.retain_included_blocks.unwrap_or(10_000)
    }
    pub fn missing_after_blocks(&self) -> u64 {
        self.missing_after_blocks.unwrap_or(64)
    }
    pub fn missing_after(&self) -> Duration {
        Duration::from_secs(self.missing_after_seconds.unwrap_or(120))
    }
    pub fn finality_stall(&self) -> Duration {
        Duration::from_secs(self.finality_stall_seconds.unwrap_or(30))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct StoreConfig {
    pub state: PathBuf,
    max_bytes: Option<u64>,
    min_free_bytes: Option<u64>,
}

impl StoreConfig {
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes.unwrap_or(50 * 1024 * 1024 * 1024)
    }
    pub fn min_free_bytes(&self) -> u64 {
        self.min_free_bytes.unwrap_or(5 * 1024 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_uses_one_store_and_bounded_settings() {
        let config: Config = toml::from_str(include_str!("../tempo-replay.example.toml")).unwrap();
        let (_, _, run) = config.run().unwrap();
        assert_eq!(run.concurrency(), 64);
        assert_eq!(run.max_rounds(), 3);
        assert_eq!(run.missing_after_blocks(), 64);
    }

    #[test]
    fn omitted_tuning_has_bounded_defaults() {
        let run: Run = toml::from_str("state = 'replay'").unwrap();
        assert_eq!(run.concurrency(), 64);
        assert_eq!(run.retries(), 2);
        assert_eq!(run.retry_delay_ms(), 250);
        assert_eq!(run.missing_after(), Duration::from_secs(120));
        assert_eq!(run.retain_included_blocks(), 10_000);
    }

    #[test]
    fn rejects_unbounded_retry_configuration_and_legacy_audit_section() {
        let mut config: Config =
            toml::from_str(include_str!("../tempo-replay.example.toml")).unwrap();
        config.run.as_mut().unwrap().max_rounds = Some(9);
        assert!(config.run().is_err());
        assert!(
            toml::from_str::<Config>(&format!(
                "{}\n[audit]\nstate = 'old'",
                include_str!("../tempo-replay.example.toml")
            ))
            .is_err()
        );
    }

    #[test]
    fn endpoint_rejects_insecure_or_embedded_credentials() {
        let endpoint = |url: &str| Endpoint {
            url: url.into(),
            credential_env: None,
            ca_file: None,
        };
        assert!(endpoint("http://source.example").connect().is_err());
        assert!(endpoint("https://user@source.example").connect().is_err());
        assert!(
            endpoint("https://source.example?token=secret")
                .connect()
                .is_err()
        );
    }

    #[test]
    fn profile_only_config_does_not_require_a_target() {
        let config: Config =
            toml::from_str("chain_id = 4217\n[source]\nurl = 'https://source.example'").unwrap();
        assert!(config.run().is_err());
    }
}
