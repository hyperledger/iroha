//! Explicit account custody and trust for the supervised native AMX relayer.

use std::{path::PathBuf, time::Duration};

use iroha_crypto::PublicKey;
use iroha_data_model::{
    NetworkId, account::AccountId, block::consensus::SumeragiRootScope,
    transaction::FeePaymentIntent,
};
use iroha_model_base::chain::ChainId;

/// Node-local scheduling and durable storage for authenticated AMX obligations.
#[derive(Debug, Clone)]
pub struct AmxRelay {
    /// Existing workflow storage root; contains no signing keys.
    pub journal_dir: PathBuf,
    /// Local observation cadence, never a consensus deadline or escrow-release authority.
    pub poll_interval: Duration,
    /// Maximum source heights inspected in one service pass.
    pub max_source_heights_per_pass: usize,
    /// Maximum authenticated proof reads per destination observation.
    pub max_finality_proof_reads: usize,
    /// Explicitly provisioned destinations; an empty list performs no relay signing.
    pub routes: Vec<AmxRelayRoute>,
}

/// One funded account and independently pinned destination root.
#[derive(Debug, Clone)]
pub struct AmxRelayRoute {
    /// Exact genesis-lineage identity selected by the operator.
    pub network_id: NetworkId,
    /// Exact consensus chain label.
    pub chain_id: ChainId,
    /// Global or private-root binding selected independently of any status response.
    pub scope: SumeragiRootScope,
    /// Account authorized to pay for relaying; never the validator-key fallback.
    pub authority: AccountId,
    /// Explicit file-only SDK account configuration and its separate key custody.
    pub account_config: PathBuf,
    /// Canonical signed genesis bytes, checked against the independent pins below.
    pub signed_genesis: PathBuf,
    /// SHA-256 of the exact signed genesis file.
    pub signed_genesis_sha256: [u8; 32],
    /// Independently selected genesis signing authority.
    pub genesis_public_key: PublicKey,
    /// Exact signature-bound fee authorization for relay carriers.
    pub fee_payment: FeePaymentIntent,
}

impl Default for AmxRelay {
    fn default() -> Self {
        use crate::parameters::defaults::amx_relay as defaults;
        Self {
            journal_dir: PathBuf::from(defaults::JOURNAL_DIR),
            poll_interval: Duration::from_millis(defaults::POLL_INTERVAL_MS),
            max_source_heights_per_pass: defaults::MAX_SOURCE_HEIGHTS_PER_PASS,
            max_finality_proof_reads: defaults::MAX_FINALITY_PROOF_READS,
            routes: Vec::new(),
        }
    }
}
