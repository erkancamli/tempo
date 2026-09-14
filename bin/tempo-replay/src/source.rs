//! Typed Tempo RPC access and certificate-authenticated finalized block retrieval.

use crate::state::BlockCursor;
use alloy::{
    consensus::{
        BlockHeader, Transaction,
        transaction::{SignerRecoverable, TxHashRef},
    },
    eips::eip2718::Encodable2718,
    primitives::{Address, B256, U256},
    providers::{Provider, RootProvider, builder},
};
use anyhow::{Context, Result, ensure};
use commonware_codec::ReadExt as _;
use reth_primitives_traits::SealedHeader;
use serde::{Deserialize, Serialize};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::{NetworkIdentity, spec::chainspec_from_chain_id};
use tempo_consensus::finalized_header_stream::{Config, FinalizedHeaderStream};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::{TempoHeader, TempoTxEnvelope};

/// Typed Alloy provider for Tempo RPC responses.
pub type TempoProvider = RootProvider<TempoNetwork>;

/// Typed full block matched to a certificate-authenticated finalized header.
#[derive(Clone, Debug)]
pub struct FinalizedBlock {
    pub cursor: BlockCursor,
    pub timestamp_ms: u64,
    pub transactions: Vec<TempoTxEnvelope>,
}

/// Shared classification and fields used by mirror, audit, and profile.
#[derive(Clone, Copy, Debug)]
pub enum TxMetadata {
    System,
    Subblock(ReplayMetadata),
    Replayable(ReplayMetadata),
}

impl TxMetadata {
    pub fn from_envelope(transaction: &TempoTxEnvelope) -> Result<Self> {
        if transaction.is_system_tx() {
            return Ok(Self::System);
        }
        let metadata = ReplayMetadata::from_envelope(transaction)?;
        if transaction.has_sub_block_nonce_key_prefix() {
            Ok(Self::Subblock(metadata))
        } else {
            Ok(Self::Replayable(metadata))
        }
    }
}

/// Shared fields for a non-system transaction.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayMetadata {
    pub hash: B256,
    pub transaction_type: u8,
    pub sender: Address,
    pub nonce: u64,
    pub nonce_key: U256,
    pub expiring: bool,
    pub encoded_length: u64,
    pub gas_limit: u64,
    pub valid_before: Option<u64>,
    pub valid_after: Option<u64>,
}

impl ReplayMetadata {
    fn from_envelope(transaction: &TempoTxEnvelope) -> Result<Self> {
        Ok(Self {
            hash: *transaction.tx_hash(),
            transaction_type: transaction.tx_type() as u8,
            sender: transaction
                .recover_signer()
                .context("recover source transaction signer")?,
            nonce: transaction.nonce(),
            nonce_key: transaction.nonce_key().unwrap_or_default(),
            expiring: transaction.is_expiring_nonce(),
            encoded_length: transaction.encode_2718_len() as u64,
            gas_limit: transaction.gas_limit(),
            valid_before: transaction.valid_before(),
            valid_after: transaction
                .as_aa()
                .and_then(|tx| tx.tx().valid_after.map(core::num::NonZeroU64::get)),
        })
    }
}

pub fn connect(
    url: &str,
    bearer_token: Option<&str>,
    ca_pem: Option<&[u8]>,
) -> Result<TempoProvider> {
    let url = url.parse().context("invalid RPC URL")?;
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = bearer_token {
        ensure!(!token.is_empty(), "RPC bearer token is empty");
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid RPC bearer token")?;
        value.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    let mut client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .default_headers(headers);
    if let Some(pem) = ca_pem {
        client = client.add_root_certificate(
            reqwest::Certificate::from_pem(pem).context("invalid RPC CA certificate")?,
        );
    }
    Ok(builder::<TempoNetwork>().connect_reqwest(client.build()?, url))
}

pub async fn chain_id(provider: &TempoProvider) -> Result<u64> {
    provider.get_chain_id().await.context("fetch chain id")
}

pub async fn block_hash(provider: &TempoProvider, number: u64) -> Result<B256> {
    Ok(provider
        .get_block_by_number(number.into())
        .await
        .context("fetch checkpoint block")?
        .with_context(|| format!("block {number} is unavailable"))?
        .header
        .hash)
}

pub async fn finalized_stream(
    provider: TempoProvider,
    chain_id: u64,
    start_after: B256,
) -> Result<FinalizedHeaderStream> {
    let chainspec = chainspec_from_chain_id(chain_id)
        .with_context(|| format!("unsupported Tempo chain id {chain_id}"))?;
    let epoch_length = chainspec
        .info
        .epoch_length()
        .context("Tempo chainspec has no consensus epoch length")?;
    FinalizedHeaderStream::init(
        provider,
        Config::new(
            start_after,
            chainspec.network_identity.clone(),
            epoch_length,
        ),
    )
    .await
    .context("initialize authenticated finalized stream")
}

/// bootstrap-shadowfork sets epochLength = boundary height + 1 and installs a private DKG
/// outcome. Authenticate from that pinned history, not mainnet's epoch schedule or committee.
///
/// The identity is passed explicitly: without it the stream derives one by fetching every
/// header from the checkpoint boundary to `start_after` on each (re)initialization.
pub async fn shadow_finalized_stream(
    provider: TempoProvider,
    start_after: B256,
    checkpoint_height: u64,
    identity: NetworkIdentity,
) -> Result<FinalizedHeaderStream> {
    FinalizedHeaderStream::init(
        provider,
        shadow_config(start_after, checkpoint_height, identity)?,
    )
    .await
    .context("initialize authenticated shadow finalized stream")
}

/// Reads the private shadow DKG outcome from the verified checkpoint boundary header once.
pub async fn shadow_network_identity(
    provider: &TempoProvider,
    checkpoint: BlockCursor,
) -> Result<NetworkIdentity> {
    let header = provider
        .get_header_by_hash(checkpoint.hash)
        .await
        .context("fetch shadow checkpoint header")?
        .with_context(|| format!("shadow checkpoint {} is unavailable", checkpoint.height))?;
    let sealed = SealedHeader::seal_slow(header.inner.inner);
    ensure!(
        sealed.hash() == checkpoint.hash && sealed.number() == checkpoint.height,
        HistoryError("shadow checkpoint header disagrees with the configured checkpoint")
    );
    shadow_identity_from_boundary(&sealed)
}

fn shadow_identity_from_boundary(boundary: &SealedHeader<TempoHeader>) -> Result<NetworkIdentity> {
    let outcome = OnchainDkgOutcome::read(&mut boundary.extra_data().as_ref())
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context(HistoryError(
            "shadow checkpoint header does not contain a valid DKG outcome",
        ))?;
    Ok(NetworkIdentity {
        from_epoch: outcome.epoch.get(),
        identity: *outcome.network_identity(),
    })
}

fn shadow_config(
    start_after: B256,
    checkpoint_height: u64,
    identity: NetworkIdentity,
) -> Result<Config> {
    let epoch_length = checkpoint_height
        .checked_add(1)
        .and_then(core::num::NonZeroU64::new)
        .context("checkpoint overflows shadow epoch length")?;
    Ok(Config::new(start_after, Some(identity), epoch_length))
}

pub async fn fetch_finalized_block(
    provider: &TempoProvider,
    header: &SealedHeader<TempoHeader>,
) -> Result<FinalizedBlock> {
    let number = header.number();
    // Fetch by authenticated hash: a lagging or forked RPC can only report the block as
    // missing (retryable), never hand back a different block at the same height.
    let block = provider
        .get_block_by_hash(header.hash())
        .full()
        .await
        .context("fetch full finalized block")?
        .with_context(|| format!("finalized block {number} is unavailable"))?;
    ensure!(
        block.header.hash == header.hash(),
        HistoryError("RPC block hash disagrees with authenticated finalized header")
    );
    ensure!(
        block.header.inner.inner == **header,
        HistoryError("RPC block header disagrees with authenticated finalized header")
    );
    let transactions: Vec<_> = block
        .transactions
        .into_transactions()
        .map(|tx| tx.into_inner())
        .collect();
    ensure!(
        alloy::consensus::proofs::calculate_transaction_root(&transactions)
            == header.transactions_root(),
        HistoryError("RPC transaction body disagrees with authenticated finalized header")
    );
    Ok(FinalizedBlock {
        cursor: BlockCursor {
            height: number,
            hash: header.hash(),
        },
        timestamp_ms: header.timestamp_millis(),
        transactions,
    })
}

pub fn replayable(transaction: &TempoTxEnvelope) -> bool {
    !transaction.is_system_tx() && !transaction.has_sub_block_nonce_key_prefix()
}

/// A fetched block must agree with the authenticated chain, not just an RPC height.
#[derive(Debug)]
pub struct HistoryError(pub &'static str);

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for HistoryError {}

pub fn history_failure(error: &anyhow::Error) -> bool {
    use tempo_consensus::finalized_header_stream::Error;
    error.is::<HistoryError>()
        || error.downcast_ref::<Error>().is_some_and(|error| {
            !matches!(
                error,
                Error::Rpc(_)
                    | Error::MissingHeader(_)
                    | Error::MissingTransitionCertificate { .. }
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        consensus::{SignableTransaction, TxLegacy},
        eips::eip2718::Encodable2718,
        primitives::{Signature, U256},
    };
    use tempo_primitives::{TempoSignature, TempoTransaction, transaction::PrimitiveSignature};

    #[test]
    fn shadow_finality_uses_the_patched_epoch_schedule_and_pinned_private_history() {
        let start = B256::repeat_byte(1);
        let identity = chainspec_from_chain_id(4217)
            .unwrap()
            .network_identity
            .clone()
            .expect("mainnet has a compiled network identity");
        let config = shadow_config(start, 120_000, identity.clone()).unwrap();
        assert_eq!(config.start_after, start);
        assert_eq!(config.epoch_length.get(), 120_001);
        assert_eq!(config.network_identity, Some(identity.clone()));
        assert!(shadow_config(start, u64::MAX, identity).is_err());
        let garbage = SealedHeader::seal_slow(TempoHeader::default());
        let error = shadow_identity_from_boundary(&garbage).unwrap_err();
        assert!(history_failure(&error));
        assert!(history_failure(
            &anyhow::Error::new(HistoryError("bad body")).context("RPC block")
        ));
        assert!(!history_failure(&anyhow::anyhow!("RPC unavailable")));
    }

    #[test]
    fn replay_filter_uses_native_system_and_subblock_classification() {
        let system = TempoTxEnvelope::Legacy(TxLegacy::default().into_signed(Signature::new(
            U256::ZERO,
            U256::ZERO,
            false,
        )));
        assert!(!replayable(&system));

        let regular = TempoTxEnvelope::Legacy(TxLegacy::default().into_signed(Signature::new(
            U256::from(1),
            U256::from(2),
            false,
        )));
        let encoded = regular.encoded_2718();
        assert!(replayable(&regular));
        assert_eq!(regular.encoded_2718(), encoded);

        let nonce_key = U256::from_be_bytes::<32>({
            let mut key = [0; 32];
            key[0] = 0x5b;
            key
        });
        let subblock = TempoTxEnvelope::AA(
            TempoTransaction {
                nonce_key,
                ..Default::default()
            }
            .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                Signature::new(U256::from(1), U256::from(2), false),
            ))),
        );
        assert!(!replayable(&subblock));
    }
}
