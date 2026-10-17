//! Strongly typed public `SoraFS` `PoP` runtime policy.
use std::{path::PathBuf, time::Duration};
/// One governed `PoP` dual-control approver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPopApprovalSigner {
    /// Stable payload-free signer identifier.
    pub signer_id: String,
    /// Raw Ed25519 public key bytes.
    pub public_key: [u8; 32],
    /// Finalized epoch at which the signer is revoked.
    pub revoked_at_epoch: Option<u64>,
}
/// Non-secret production policy for the Torii `PoP` credential service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPopCredentialService {
    /// Durable issuer checkpoint directory.
    pub issuer_state_dir: PathBuf,
    /// Encrypted wallet-vault directory.
    pub wallet_state_dir: PathBuf,
    /// Exact active finalized issuer-policy digest.
    pub issuer_policy_digest: [u8; 32],
    /// Governed issuer identifier.
    pub issuer_id: String,
    /// Non-secret authenticated external signer handle.
    pub issuer_signer_handle: String,
    /// Governed raw Ed25519 issuer public key.
    pub issuer_public_key: [u8; 32],
    /// Non-secret runtime hybrid recipient-key handle.
    pub enrollment_recipient_key_id: String,
    /// Digest of the exact hybrid enrollment-recipient public key.
    pub enrollment_recipient_public_key_digest: [u8; 32],
    /// Non-secret runtime hybrid wallet-recipient key handle.
    pub wallet_recipient_key_id: String,
    /// Digest of the exact hybrid wallet-recipient public key.
    pub wallet_recipient_public_key_digest: [u8; 32],
    /// Non-secret runtime wallet wrapping-key handle.
    pub wallet_wrapping_key_id: String,
    /// Non-secret deployment runtime-provider registry handle.
    pub runtime_provider_registry_handle: String,
    /// Exact non-zero deployment registry policy revision.
    pub runtime_provider_registry_revision: u64,
    /// Exact deployment registry policy digest.
    pub runtime_provider_registry_policy_digest: [u8; 32],
    /// Required distinct active approval count.
    pub approval_quorum: u8,
    /// Canonically signer-id-ordered approval authority.
    pub approval_signers: Vec<SorafsPopApprovalSigner>,
    /// Maximum pending encrypted enrollments.
    pub max_pending_enrollments: u32,
    /// Maximum durable registry outbox entries.
    pub max_outbox_entries: u32,
    /// Maximum durable dead letters.
    pub max_dead_letters: u32,
    /// Maximum consumed proof nullifiers.
    pub max_seen_nullifiers: u32,
    /// Submission attempts before terminal dead-lettering.
    pub max_submission_attempts: u16,
    /// Registry worker cadence.
    pub worker_interval: Duration,
    /// Maximum absolute skew between finalized and runtime clock time.
    pub max_finalized_time_skew: Duration,
}
