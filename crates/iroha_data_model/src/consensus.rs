//! Consensus-related data model DTOs for on-chain persistence.
use crate::prelude::*;

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_crypto::{Hash, PublicKey, Signature};
use iroha_primitives::numeric::Quantity;
use iroha_schema::{Ident, IntoSchema};

use norito::codec::{Decode, Encode};
use norito::json::JsonKeyCodec;
use std::str::FromStr;
mod parent_service;
pub use parent_service::{
    NposParentServiceCommitQc, ParentServiceCustodyError, PreparedParentServiceCommitQc,
};
mod penalty_actions;
pub use penalty_actions::{
    NposPenaltyActions, NposPenaltyActionsCustodyError, PreparedNposPenaltyActions,
};
/// Version of the validator-set hashing scheme (`HashOf` over the ordered peer identities)
/// that lane committee records and queue-plan admission contexts name.
pub const VALIDATOR_SET_HASH_VERSION_V1: u16 = 1;
/// Protocol version for the first-release global threshold beacon.
pub const GLOBAL_THRESHOLD_BEACON_VERSION_V1: u16 = 1;
/// Hard upper bound for one autonomous lane consensus committee.
///
/// This bounds proposal, vote, quorum-certificate, drain, and persisted proof
/// envelopes across configuration, runtime admission, and restart recovery.
pub const MAX_LANE_CONSENSUS_VALIDATORS: usize = 128;
/// Finite protocol ceiling for one canonical parent service `CommitQC` original.
/// The complete verifier still checks the actual bitmap, signature, attestation
/// geometry and independently authenticated epoch; byte size grants no authority.
pub const PARENT_SERVICE_COMMIT_QC_MAX_BYTES: usize = 512 * 1024;

/// Deterministic native service and `NPoS` state effects embedded in a signed block.
///
/// These effects are applied as part of the committed block transition so every
/// peer replays the same native evidence and penalty state. Beacon authority is
/// carried by the exact native execution-result commitment.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields, decode_fields)]
pub struct NposConsensusEffects {
    /// Original parent `CommitQC` selected by this proposal. It is consensus input,
    /// never the replica's local certificate. None is valid only before H3.
    #[norito(required)]
    pub parent_service_commit_qc: Option<NposParentServiceCommitQc>,
    /// Original native evidence admitted in canonical evidence-key order.
    pub evidence_admissions: Vec<crate::block::consensus::Evidence>,
    /// Penalty and marker actions applied by this block.
    pub penalty_actions: NposPenaltyActions,
}
impl NposConsensusEffects {
    /// Returns true when the bundle carries no committed state changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parent_service_commit_qc.is_none()
            && self.evidence_admissions.is_empty()
            && self.penalty_actions.is_empty()
    }
}
impl Ord for NposConsensusEffects {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.encode().cmp(&other.encode())
    }
}
impl PartialOrd for NposConsensusEffects {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
/// A deterministic consensus-evidence slash action.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct NposConsensusSlashAction {
    /// Domain-separated consensus evidence digest.
    pub evidence_key: Hash,
    /// Signer index in the evidence roster.
    pub signer: u32,
    /// Peer identity resolved from the evidence roster.
    pub peer_id: iroha_model_base::peer::PeerId,
    /// Public lane containing the validator registration.
    pub lane_id: iroha_model_base::topology::LaneId,
    /// Validator account to slash.
    pub validator: crate::account::AccountId,
    /// Slash identifier recorded in validator status.
    pub slash_id: Hash,
    /// Amount to slash.
    pub amount: Quantity,
}
/// Marker that a consensus evidence record's penalty was applied.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct NposMarkConsensusEvidenceAppliedAction {
    /// Domain-separated consensus evidence digest.
    pub evidence_key: Hash,
    /// Block height that applied the marker.
    pub height: u64,
}
/// Penalty or marker action applied by a committed `NPoS` effects bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "kind", content = "value", rename_all = "snake_case")]
#[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
pub enum NposPenaltyAction {
    /// Slash a validator from consensus evidence.
    ConsensusSlash(NposConsensusSlashAction),
    /// Mark a consensus evidence record's penalty as applied.
    MarkConsensusEvidenceApplied(NposMarkConsensusEvidenceAppliedAction),
}
/// Snapshot of the election parameters used when selecting validators for an epoch.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct ValidatorElectionParameters {
    /// Maximum number of validators allowed in the elected set (0 = unlimited).
    pub max_validators: u32,
    /// Minimum self-bond required for eligibility (stake units).
    pub min_self_bond: Quantity,
    /// Minimum nomination bond required for delegators (stake units).
    pub min_nomination_bond: Quantity,
    /// Finality margin (blocks) required when activating a newly elected set.
    pub finality_margin_blocks: u64,
}
/// Deterministic tie-break record used when ordering candidates.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct ValidatorTieBreak {
    /// Candidate peer identifier.
    pub peer_id: iroha_model_base::peer::PeerId,
    /// Blake2b-derived score used to order candidates (lower is preferred).
    pub score: [u8; 32],
}
/// Election outcome for an epoch along with audit metadata.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct ValidatorElectionOutcome {
    /// Epoch index the elected set will service.
    pub epoch: u64,
    /// Height at which the election ran.
    pub snapshot_height: u64,
    /// Seed used to derive deterministic ordering/tie-breaks.
    pub seed: [u8; 32],
    /// Total candidates considered.
    pub candidates_total: u32,
    /// Ordered elected validator set.
    pub validator_set: Vec<iroha_model_base::peer::PeerId>,
    /// Stable hash of the elected validator set.
    pub validator_set_hash: HashOf<Vec<iroha_model_base::peer::PeerId>>,
    /// Parameters in effect for the election.
    pub params: ValidatorElectionParameters,
    /// Optional rejection or misconfiguration reason.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    /// Tie-break scores for auditability.
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub tie_break: Vec<ValidatorTieBreak>,
}
impl ValidatorElectionOutcome {
    /// Construct an empty election outcome for failed or skipped elections.
    #[must_use]
    pub fn empty(epoch: u64, snapshot_height: u64, seed: [u8; 32]) -> Self {
        let validator_set = Vec::new();
        let validator_set_hash = HashOf::new(&validator_set);
        Self {
            epoch,
            snapshot_height,
            seed,
            candidates_total: 0,
            validator_set,
            validator_set_hash,
            params: ValidatorElectionParameters {
                max_validators: 0,
                min_self_bond: Quantity::zero(),
                min_nomination_bond: Quantity::zero(),
                finality_margin_blocks: 0,
            },
            rejection_reason: Some("validator election failed".to_owned()),
            tie_break: Vec::new(),
        }
    }
}
/// Logical role for a consensus or committee key.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    derive_more::Display,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "role", content = "value")]
pub enum ConsensusKeyRole {
    /// Validator signing key used for blocks/commit certificates.
    Validator,
    /// JDG/committee attestation key.
    Committee,
    /// Domain/endorsement committee key.
    Endorsement,
}
/// Identifier for a consensus/committee key (role + stable name).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    derive_more::Display,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[display("{role}:{name}")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::consensus::ConsensusKeyId")]
pub struct ConsensusKeyId {
    /// Logical role served by this key.
    pub role: ConsensusKeyRole,
    /// Human-friendly name (stable across rotations).
    pub name: Ident,
}
impl ConsensusKeyId {
    /// Construct a new key identifier.
    #[must_use]
    pub fn new(role: ConsensusKeyRole, name: impl Into<Ident>) -> Self {
        Self {
            role,
            name: name.into(),
        }
    }
}
/// Lifecycle state of a consensus key.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    derive_more::Display,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "value")]
pub enum ConsensusKeyStatus {
    /// Scheduled but not yet active for signing.
    Pending,
    /// Active and allowed for signing/verification.
    Active,
    /// Overlap/retirement window; still accepted until grace elapses.
    Retiring,
    /// Disabled or superseded; signatures should be rejected.
    Disabled,
}
/// Recorded consensus/committee key with lifecycle metadata.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::consensus::ConsensusKeyRecord")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ConsensusKeyRecord {
    /// Identifier of the key (role + name).
    pub id: ConsensusKeyId,
    /// Public key material used for signatures.
    pub public_key: PublicKey,
    /// Optional Proof-of-Possession for BLS keys (required for BLS algorithms).
    #[norito(skip_serializing_if = "Option::is_none")]
    pub pop: Option<Vec<u8>>,
    /// First block height (inclusive) at which this key becomes valid.
    pub activation_height: u64,
    /// Optional block height (exclusive) at which this key expires.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub expiry_height: Option<u64>,
    /// Optional link to the key this record supersedes.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<ConsensusKeyId>,
    /// Declared lifecycle status.
    pub status: ConsensusKeyStatus,
}

impl JsonKeyCodec for ConsensusKeyId {
    fn encode_json_key(&self, out: &mut String) {
        norito::json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, norito::json::Error> {
        let (role_str, name_str) = encoded.split_once(':').ok_or_else(|| {
            norito::json::Error::Message("invalid consensus key id; expected role:name".into())
        })?;
        let role = match role_str {
            "Validator" => ConsensusKeyRole::Validator,
            "Committee" => ConsensusKeyRole::Committee,
            "Endorsement" => ConsensusKeyRole::Endorsement,
            other => return Err(norito::json::Error::unknown_field(other)),
        };
        let name = Ident::from_str(name_str).map_err(|err| {
            norito::json::Error::Message(format!("invalid consensus key name: {err}"))
        })?;
        Ok(ConsensusKeyId { role, name })
    }
}
impl ConsensusKeyRecord {
    /// Determine whether the key should be accepted at `height`, honoring overlap/expiry grace.
    #[must_use]
    pub fn is_live_at(
        &self,
        height: u64,
        overlap_grace_blocks: u64,
        expiry_grace_blocks: u64,
    ) -> bool {
        if matches!(self.status, ConsensusKeyStatus::Disabled) {
            return false;
        }
        if height < self.activation_height {
            return false;
        }
        if let Some(expiry) = self.expiry_height {
            let last_allowed = expiry.saturating_add(expiry_grace_blocks.max(overlap_grace_blocks));
            if height >= last_allowed {
                return false;
            }
        }
        true
    }
}

/// One canonically indexed public verification share in a global beacon DKG transcript.
///
/// Participant indices are one-based and the enclosing session must contain the
/// exact sequence `1..=committee_size`. `participant_seat_binding` commits to
/// the typed session, frozen ordered-roster commitment, and one-based seat.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconPublicShareV1 {
    /// Canonical one-based participant index.
    pub index: u16,
    /// Deterministic binding of this one-based seat to the frozen ordered roster.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub participant_seat_binding: [u8; 32],
    /// Canonical compressed BLS12-381 G2 public verification share.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub public_key_share: [u8; 96],
}

/// Immutable bindings and height windows for one all-edge beacon DKG run.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgSessionV1 {
    /// Fixed first-release beacon protocol version.
    pub version: u16,
    /// Exact deployment identity derived from genesis.
    pub network_id: NetworkId,
    /// Unique threshold-beacon session identifier.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub session_id: [u8; 32],
    /// Unique genesis or frozen committee attempt; never reused after cancellation.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub attempt_id: [u8; 32],
    /// Target signing generation, independent of the scheduled epoch.
    pub authority_generation: u64,
    /// Hash of the frozen ordered DKG participant roster.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub roster_hash: [u8; 32],
    /// Exact `3f + 1` participant count.
    pub committee_size: u16,
    /// Exact `f + 1` reconstruction threshold (and coefficient count).
    pub threshold: u16,
    /// First height at which dealer commitments are accepted.
    pub start_height: u64,
    /// Exclusive end of the dealer-commitment window.
    pub commitments_end_height: u64,
    /// Exclusive end of encrypted private delivery.
    pub deliveries_end_height: u64,
    /// Exclusive end of signed recipient acceptance.
    pub acceptances_end_height: u64,
}

/// Schnorr proof that a dealer knows the constant-term exponent.
///
/// Since the constant coefficient commitment is exactly `g^s`, this proof is
/// what enforces `r(0) = u(0) = 0` in the augmented JF/Pedersen DKG.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgConstantProofV1 {
    /// Canonical compressed G2 Schnorr nonce commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub commitment: [u8; 96],
    /// Canonical big-endian scalar response.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub response: [u8; 32],
}

/// One dealer's Figure-5 augmented JF/Pedersen coefficient commitments.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgDealerCommitmentV1 {
    /// Dealer's canonical one-based participant index.
    pub dealer_index: u16,
    /// `C_k = g^s_k h^r_k v^u_k` in ascending coefficient order.
    ///
    /// The list length must equal the reconstruction threshold. `C_0` is
    /// exactly `g^s_0` because both zero-polynomials have zero constant term.
    #[norito(json = "crate::json_helpers::fixed_bytes::vec")]
    pub coefficient_commitments: Vec<[u8; 96]>,
    /// Fiat-Shamir Schnorr proof of knowledge for the constant coefficient.
    pub constant_term_proof: GlobalThresholdBeaconDkgConstantProofV1,
    /// Dealer-seat BLS signature over the complete session and public broadcast.
    pub signature: Signature,
}

/// One attempt-bound recipient encryption key authenticated by its BLS seat.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgRecipientKeyV1 {
    /// One-based index in the exact frozen roster.
    pub recipient_index: u16,
    /// Exact BLS validator which owns this recipient slot.
    pub validator: iroha_model_base::peer::PeerId,
    /// X25519 component of the canonical hybrid recipient key.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub x25519_public_key: [u8; 32],
    /// ML-KEM-768 component of the canonical hybrid recipient key.
    pub mlkem768_public_key: Vec<u8>,
    /// Seat BLS signature over the complete session and unsigned key fields.
    pub signature: Signature,
}

/// Public authenticated ciphertext for a private dealer-to-recipient share.
///
/// The plaintext scalar triple is never included in public DKG state.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgEncryptedShareV1 {
    /// One-based dealer index in the frozen roster.
    pub dealer_index: u16,
    /// One-based recipient index in the frozen roster.
    pub recipient_index: u16,
    /// Hash of the exact dealer coefficient commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub dealer_commitment_hash: [u8; 32],
    /// Hash of the recipient's signed attempt-bound encryption key.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub recipient_key_hash: [u8; 32],
    /// Authenticated height within the delivery window.
    pub delivery_height: u64,
    /// Ephemeral X25519 KEM public component.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub ephemeral_x25519_public_key: [u8; 32],
    /// ML-KEM-768 encapsulation ciphertext.
    pub mlkem768_ciphertext: Vec<u8>,
    /// Nonce-prefixed authenticated ciphertext for one 96-byte share triple.
    pub encrypted_share: Vec<u8>,
    /// Dealer BLS signature over the complete session and unsigned envelope.
    pub signature: Signature,
}

/// Public proof that a recipient accepted one authenticated private DKG edge.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgShareAcceptanceV1 {
    /// One-based dealer index in the frozen roster.
    pub dealer_index: u16,
    /// One-based recipient index in the frozen roster.
    pub recipient_index: u16,
    /// Hash of the exact dealer coefficient commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub dealer_commitment_hash: [u8; 32],
    /// Hash of the signed encrypted private edge acknowledged by the recipient.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub encrypted_share_hash: [u8; 32],
    /// Authenticated finalized height at which the recipient accepted the edge.
    pub accepted_height: u64,
    /// Recipient BLS signature over the complete session and unsigned acceptance.
    pub signature: Signature,
}

/// Canonical public audit transcript for a completed all-edge beacon DKG.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgTranscriptV1 {
    /// Immutable session and height-window bindings.
    pub session: GlobalThresholdBeaconDkgSessionV1,
    /// Independently domain-derived compressed G2 generator `h`.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub generator_h: [u8; 96],
    /// Independently domain-derived compressed G2 generator `v`.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub generator_v: [u8; 96],
    /// Valid dealer broadcasts in strictly ascending dealer order.
    pub dealer_commitments: Vec<GlobalThresholdBeaconDkgDealerCommitmentV1>,
    /// Exact signed recipient encryption keys in one-based seat order.
    pub recipient_keys: Vec<GlobalThresholdBeaconDkgRecipientKeyV1>,
    /// Signed encrypted private edges; ciphertext never reveals a scalar.
    pub encrypted_shares: Vec<GlobalThresholdBeaconDkgEncryptedShareV1>,
    /// Exact signed acknowledgments in canonical `(dealer, recipient)` order.
    pub share_acceptances: Vec<GlobalThresholdBeaconDkgShareAcceptanceV1>,
    /// Every dealer index in strictly ascending order; no roster reroll.
    pub qualified_dealers: Vec<u16>,
    /// Hash of the complete canonical DKG event transcript above.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub event_hash: [u8; 32],
    /// Height at which qualification and the public key were finalized.
    pub finalized_at_height: u64,
}

/// Figure-3 proof attached to one adaptive threshold-BLS partial signature.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct GlobalThresholdBeaconPartialSignatureProofV1 {
    /// Composite-key Schnorr commitment `x` in compressed G2.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub x: [u8; 96],
    /// Partial-signature Schnorr commitment `y` in compressed G1.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub y: [u8; 48],
    /// Response for the `s` witness.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub z_s: [u8; 32],
    /// Response for the `r` witness.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub z_r: [u8; 32],
    /// Response for the `u` witness.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub z_u: [u8; 32],
}

/// One internal adaptive threshold-BLS signature share and its Figure-3 proof.
///
/// This object is used only while reconstructing the unique final signature;
/// it is never embedded in a finalized public pulse.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct GlobalThresholdBeaconPartialSignatureV1 {
    /// Typed beacon session identifier.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub session_id: [u8; 32],
    /// Canonical one-based signer index.
    pub signer_index: u16,
    /// `H0(m)^s(i) H1(m)^r(i)` in compressed G1.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub signature_share: [u8; 48],
    /// Three-witness non-interactive proof of correct share construction.
    pub proof: GlobalThresholdBeaconPartialSignatureProofV1,
}

impl norito::NoritoSchema for GlobalThresholdBeaconPartialSignatureV1 {
    fn nominal_name() -> String {
        "iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1".to_owned()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1")
    }
}

/// Complete public commitment for one global threshold-beacon key session.
///
/// This DTO deliberately contains the complete ordered public-share transcript.
/// A consumer must recompute `transcript_hash`; accepting the supplied hash by
/// itself would permit a session to claim a roster or DKG transcript it did not
/// actually use. Beacon sessions are a separate typed cryptographic domain from
/// Parliament timelock-release sessions.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconKeySessionV1 {
    /// Fixed protocol version; must equal [`GLOBAL_THRESHOLD_BEACON_VERSION_V1`].
    pub version: u16,
    /// Exact deployment identity derived from the genesis header.
    pub network_id: NetworkId,
    /// Unique non-zero identifier for this beacon key session.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub session_id: [u8; 32],
    /// Hash of the frozen ordered validator roster.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub roster_hash: [u8; 32],
    /// Exact `3f + 1` committee size.
    pub committee_size: u16,
    /// Exact `f + 1` reconstruction threshold.
    pub threshold: u16,
    /// Canonical compressed BLS12-381 G2 group public key.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub group_public_key: [u8; 96],
    /// Complete verification-share list in exact one-based index order.
    pub public_shares: Vec<GlobalThresholdBeaconPublicShareV1>,
    /// Complete augmented JF/Pedersen DKG audit transcript.
    pub adaptive_dkg: GlobalThresholdBeaconDkgTranscriptV1,
    /// Non-zero commitment to all qualified DKG contributions.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub dkg_contribution_hash: [u8; 32],
    /// Recomputed commitment to the complete typed public transcript.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub transcript_hash: [u8; 32],
}

/// Finalized-chain point bound into a global threshold-beacon pulse.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconChainAnchorV1 {
    /// Finalized block height authenticated by the pulse.
    pub height: u64,
    /// Exact finalized block-header hash at `height`.
    pub block_hash: HashOf<crate::block::BlockHeader>,
}

/// Complete native signing context for a threshold pulse, independent of proposal views.
/// Its context ID commits the complete authenticated authority generation and scheduling epoch.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1")]
#[norito(deny_unknown_fields)]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconPulseContextV1 {
    /// Exact native consensus instance derived from signed genesis and the configured chain.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub instance: [u8; 32],
    /// Scheduling epoch number, including the signed genesis epoch zero.
    pub epoch: u64,
    /// Complete authenticated native epoch context digest.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub epoch_context_id: [u8; 32],
    /// Exact consensus hash of the immediately applied native parent.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub parent_consensus_hash: [u8; 32],
    /// Original execution result of that same applied parent.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub parent_result: [u8; 32],
}
impl GlobalThresholdBeaconPulseContextV1 {
    /// Reject inert identities; authority equality is checked against the independent native source.
    ///
    /// # Errors
    /// Returns an error when an instance, epoch context or parent identity is zero.
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            &self.instance,
            &self.epoch_context_id,
            &self.parent_consensus_hash,
            &self.parent_result,
        ]
        .into_iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err("global beacon pulse has an inert native context identity");
        }
        Ok(())
    }
}

/// One finalized pulse from the canonical global threshold beacon.
///
/// There is intentionally no signer bitmap, share list, or reconstruction
/// subset. A threshold-BLS final signature is unique for its message and group
/// key, so the public result cannot vary with the subset used internally to
/// reconstruct it. `seed` and `pulse_id` are redundant audit fields which must
/// be recomputed from the verified final signature.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(decode_fields)]
pub struct FinalizedGlobalThresholdBeaconPulseV1 {
    /// Fixed protocol version; must equal [`GLOBAL_THRESHOLD_BEACON_VERSION_V1`].
    pub version: u16,
    /// Exact deployment identity derived from the genesis header.
    pub network_id: NetworkId,
    /// Beacon key session which produced this pulse.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub session_id: [u8; 32],
    /// Frozen roster hash inherited from the key session.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub roster_hash: [u8; 32],
    /// Recomputed public-transcript commitment inherited from the key session.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub transcript_hash: [u8; 32],
    /// Complete native context covered by every proof-carrying threshold share.
    pub context: GlobalThresholdBeaconPulseContextV1,
    /// Consensus height at which this pulse is finalized.
    pub height: u64,
    /// Canonical fixed protocol round (zero in V1), independent of consensus view.
    pub round: u64,
    /// Exact finalized-chain point authenticated by this pulse.
    pub finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1,
    /// Canonical compressed BLS12-381 G1 final group signature.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub signature: [u8; 48],
    /// Unique 32-byte seed derived from the verified final signature.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub seed: [u8; 32],
    /// Canonical identifier recomputed from the signed pulse and final signature.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub pulse_id: [u8; 32],
}

impl norito::NoritoSchema for FinalizedGlobalThresholdBeaconPulseV1 {
    fn nominal_name() -> String {
        "iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1".to_owned()
    }
    fn static_frame_name() -> Option<&'static str> {
        // Fixed-capacity header production does not allocate a schema-name String.
        Some("iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1")
    }
}

mod pulse_inline;

#[cfg(test)]
mod tests {
    #[test]
    fn canonical_registry_schema_identity_roundtrips() {
        let value = ConsensusKeyId::new(ConsensusKeyRole::Validator, "state-key");
        assert_eq!(
            <ConsensusKeyId as norito::NoritoSchema>::nominal_name(),
            "iroha_data_model::consensus::ConsensusKeyId"
        );
        let encoded = norito::encode_canonical(&value).expect("canonical owner frame");
        assert_eq!(
            encoded[6..22],
            norito::schema::identity::frame_hash::<ConsensusKeyId>()
        );
        assert_eq!(
            norito::decode_canonical::<ConsensusKeyId>(&encoded)
                .expect("canonical owner roundtrip"),
            value
        );
        let mut wrong_owner = encoded;
        wrong_owner[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<ConsensusKeyId>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
    }

    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_primitives::numeric::Numeric;
    #[derive(Encode)]
    struct ForgedNposConsensusSlashAction {
        evidence_key: Hash,
        signer: u32,
        peer_id: iroha_model_base::peer::PeerId,
        lane_id: iroha_model_base::topology::LaneId,
        validator: crate::account::AccountId,
        slash_id: Hash,
        amount: Numeric,
    }
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked consensus DTO fixture keypair")
    }
    fn threshold_beacon_network(marker: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([marker; Hash::LENGTH]),
        ))
    }
    fn threshold_beacon_session_fixture() -> GlobalThresholdBeaconKeySessionV1 {
        let network_id = threshold_beacon_network(0x81);
        let session_id = [0x22; 32];
        let roster_hash = [0x33; 32];
        let dkg_session = GlobalThresholdBeaconDkgSessionV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id,
            session_id,
            attempt_id: session_id,
            authority_generation: 0,
            roster_hash,
            committee_size: 4,
            threshold: 2,
            start_height: 1,
            commitments_end_height: 10,
            deliveries_end_height: 20,
            acceptances_end_height: 30,
        };
        let dealer_commitments = (1_u16..=4)
            .map(|dealer_index| GlobalThresholdBeaconDkgDealerCommitmentV1 {
                dealer_index,
                coefficient_commitments: vec![
                    [u8::try_from(dealer_index).expect("fixture value fits u8") + 0x20;
                        96];
                    2
                ],
                constant_term_proof: GlobalThresholdBeaconDkgConstantProofV1 {
                    commitment: [u8::try_from(dealer_index).expect("fixture value fits u8") + 0x30;
                        96],
                    response: [u8::try_from(dealer_index).expect("fixture value fits u8") + 0x40;
                        32],
                },
                signature: Signature::new(
                    KeyPair::from_seed(
                        vec![u8::try_from(dealer_index).expect("fixture value fits u8"); 32],
                        Algorithm::Ed25519,
                    )
                    .private_key(),
                    &session_id,
                ),
            })
            .collect();
        GlobalThresholdBeaconKeySessionV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id,
            session_id,
            roster_hash,
            committee_size: 4,
            threshold: 2,
            group_public_key: [0x44; 96],
            public_shares: (1_u16..=4)
                .map(|index| GlobalThresholdBeaconPublicShareV1 {
                    index,
                    participant_seat_binding: [u8::try_from(index).expect("fixture value fits u8");
                        32],
                    public_key_share: [u8::try_from(index).expect("fixture value fits u8") + 0x50;
                        96],
                })
                .collect(),
            adaptive_dkg: GlobalThresholdBeaconDkgTranscriptV1 {
                session: dkg_session,
                generator_h: [0x61; 96],
                generator_v: [0x62; 96],
                dealer_commitments,
                recipient_keys: Vec::new(),
                encrypted_shares: Vec::new(),
                share_acceptances: Vec::new(),
                qualified_dealers: vec![1, 2, 3, 4],
                event_hash: [0x66; 32],
                finalized_at_height: 30,
            },
            dkg_contribution_hash: [0x66; 32],
            transcript_hash: [0x77; 32],
        }
    }
    fn threshold_beacon_pulse_fixture() -> FinalizedGlobalThresholdBeaconPulseV1 {
        let session = threshold_beacon_session_fixture();
        FinalizedGlobalThresholdBeaconPulseV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id: session.network_id,
            session_id: session.session_id,
            roster_hash: session.roster_hash,
            transcript_hash: session.transcript_hash,
            context: GlobalThresholdBeaconPulseContextV1 {
                instance: [0x91; 32],
                epoch: 0,
                epoch_context_id: [0x92; 32],
                parent_consensus_hash: [0x93; 32],
                parent_result: [0x94; 32],
            },
            height: 42,
            round: 0,
            finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
                height: 41,
                block_hash: HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
                    Hash::prehashed([0xAA; Hash::LENGTH]),
                ),
            },
            signature: [0xBB; 48],
            seed: [0xCC; 32],
            pulse_id: [0xDD; 32],
        }
    }
    #[test]
    fn native_pulse_context_requires_every_native_identity() {
        let original = threshold_beacon_pulse_fixture().context;
        original.validate().unwrap();
        assert_eq!(original.epoch, 0, "signed genesis epoch zero is valid");
        for index in 0..4 {
            let mut malformed = original;
            match index {
                0 => malformed.instance = [0; 32],
                1 => malformed.epoch_context_id = [0; 32],
                2 => malformed.parent_consensus_hash = [0; 32],
                _ => malformed.parent_result = [0; 32],
            }
            assert!(malformed.validate().is_err());
        }
        let encoded = norito::encode_canonical(&original).unwrap();
        assert_eq!(
            norito::decode_canonical::<GlobalThresholdBeaconPulseContextV1>(&encoded).unwrap(),
            original
        );
    }

    #[test]
    fn threshold_beacon_session_and_pulse_norito_roundtrip() {
        let session = threshold_beacon_session_fixture();
        let encoded_session = session.encode();
        let decoded_session =
            GlobalThresholdBeaconKeySessionV1::decode(&mut encoded_session.as_slice())
                .expect("decode threshold beacon session");
        assert_eq!(decoded_session, session);

        let pulse = threshold_beacon_pulse_fixture();
        let encoded_pulse = pulse.encode();
        let decoded_pulse =
            FinalizedGlobalThresholdBeaconPulseV1::decode(&mut encoded_pulse.as_slice())
                .expect("decode finalized threshold beacon pulse");
        assert_eq!(decoded_pulse, pulse);

        let partial = GlobalThresholdBeaconPartialSignatureV1 {
            session_id: session.session_id,
            signer_index: 2,
            signature_share: [0xE1; 48],
            proof: GlobalThresholdBeaconPartialSignatureProofV1 {
                x: [0xE2; 96],
                y: [0xE3; 48],
                z_s: [0xE4; 32],
                z_r: [0xE5; 32],
                z_u: [0xE6; 32],
            },
        };
        let encoded_partial = partial.encode();
        let decoded_partial =
            GlobalThresholdBeaconPartialSignatureV1::decode(&mut encoded_partial.as_slice())
                .expect("decode adaptive partial signature");
        assert_eq!(decoded_partial, partial);
        // Schema-only codec fixtures: cryptographic acceptance is covered by the Core tests.
        for (nominal, declared) in [
            (<GlobalThresholdBeaconPartialSignatureV1 as norito::NoritoSchema>::nominal_name(),
             <GlobalThresholdBeaconPartialSignatureV1 as norito::NoritoSchema>::static_frame_name()),
            (<FinalizedGlobalThresholdBeaconPulseV1 as norito::NoritoSchema>::nominal_name(),
             <FinalizedGlobalThresholdBeaconPulseV1 as norito::NoritoSchema>::static_frame_name()),
        ] {
            assert_eq!(declared, Some(nominal.as_str()));
        }
        let pulse_frame = norito::encode_canonical(&pulse).unwrap();
        let partial_frame = norito::encode_canonical(&partial).unwrap();
        assert_eq!(
            norito::decode_canonical::<FinalizedGlobalThresholdBeaconPulseV1>(&pulse_frame)
                .unwrap(),
            pulse
        );
        assert_eq!(
            norito::decode_canonical::<GlobalThresholdBeaconPartialSignatureV1>(&partial_frame)
                .unwrap(),
            partial
        );
        assert!(
            norito::decode_canonical::<FinalizedGlobalThresholdBeaconPulseV1>(&partial_frame)
                .is_err()
        );
        assert!(
            norito::decode_canonical::<GlobalThresholdBeaconPartialSignatureV1>(&pulse_frame)
                .is_err()
        );
    }

    #[test]
    fn threshold_beacon_session_and_pulse_json_roundtrip_without_subset_metadata() {
        let session = threshold_beacon_session_fixture();
        let session_json = norito::json::to_json(&session).expect("encode beacon session JSON");
        let decoded_session: GlobalThresholdBeaconKeySessionV1 =
            norito::json::from_str(&session_json).expect("decode beacon session JSON");
        assert_eq!(decoded_session, session);

        let pulse = threshold_beacon_pulse_fixture();
        let pulse_json = norito::json::to_json(&pulse).expect("encode beacon pulse JSON");
        let decoded_pulse: FinalizedGlobalThresholdBeaconPulseV1 =
            norito::json::from_str(&pulse_json).expect("decode beacon pulse JSON");
        assert_eq!(decoded_pulse, pulse);
        assert!(!pulse_json.contains("signer"));
        assert!(!pulse_json.contains("subset"));
        assert!(!pulse_json.contains("share"));
    }
    #[test]
    fn negative_numeric_payload_cannot_decode_as_consensus_slash_amount() {
        let key_pair = checked_random_keypair();
        let peer_id = iroha_model_base::peer::PeerId::new(key_pair.public_key().clone());
        let slash = ForgedNposConsensusSlashAction {
            evidence_key: Hash::new(b"forged-negative-consensus-slash"),
            signer: 0,
            peer_id,
            lane_id: iroha_model_base::topology::LaneId::SINGLE,
            validator: crate::account::AccountId::new(key_pair.public_key().clone()),
            slash_id: Hash::new(b"negative-consensus-slash"),
            amount: Numeric::new(-1_i32, 0),
        };
        let encoded = slash.encode();
        assert!(
            NposConsensusSlashAction::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as a consensus slash amount"
        );
    }
    #[test]
    fn consensus_key_record_and_list_use_distinct_canonical_frames() {
        let record = ConsensusKeyRecord {
            id: ConsensusKeyId::new(ConsensusKeyRole::Validator, "v1"),
            public_key: checked_random_keypair().public_key().clone(),
            pop: None,
            activation_height: 10,
            expiry_height: Some(20),
            replaces: Some(ConsensusKeyId::new(ConsensusKeyRole::Validator, "v0")),
            status: ConsensusKeyStatus::Active,
        };
        let encoded = norito::encode_canonical(&record).expect("encode consensus key record");
        let header = norito::core::Header::read(&encoded[..]).expect("record frame header");
        assert_eq!(
            header.schema,
            norito::core::schema_hash_for_name("iroha_data_model::consensus::ConsensusKeyRecord"),
        );
        assert_eq!(
            norito::decode_from_bytes::<ConsensusKeyRecord>(&encoded).unwrap(),
            record,
        );
        assert!(matches!(
            norito::decode_from_bytes::<Vec<ConsensusKeyRecord>>(&encoded),
            Err(norito::core::Error::SchemaMismatch),
        ));
        let records = vec![record];
        let encoded = norito::encode_canonical(&records).expect("encode consensus key list");
        assert_eq!(
            norito::decode_from_bytes::<Vec<ConsensusKeyRecord>>(&encoded).unwrap(),
            records,
        );
    }
    #[test]
    fn consensus_key_record_liveness_respects_activation_and_expiry() {
        let id = ConsensusKeyId::new(ConsensusKeyRole::Validator, "v1");
        let pk = checked_random_keypair().public_key().clone();
        let record = ConsensusKeyRecord {
            id,
            public_key: pk,
            pop: None,
            activation_height: 10,
            expiry_height: Some(20),
            replaces: None,
            status: ConsensusKeyStatus::Active,
        };

        assert_eq!(
            <ConsensusKeyRecord as norito::NoritoSchema>::nominal_name(),
            "iroha_data_model::consensus::ConsensusKeyRecord"
        );
        let response = vec![record.clone()];
        let bytes = norito::encode_canonical(&response).expect("consensus key list frame");
        let decoded: Vec<ConsensusKeyRecord> =
            norito::decode_canonical(&bytes).expect("key list roundtrip");
        assert_eq!(decoded, response);
        let mut wrong_owner = bytes.clone();
        wrong_owner[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<Vec<ConsensusKeyRecord>>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(
            norito::decode_canonical::<Vec<ConsensusKeyRecord>>(&bytes[..bytes.len() - 1]).is_err()
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(norito::decode_canonical::<Vec<ConsensusKeyRecord>>(&trailing).is_err());
        assert!(!record.is_live_at(9, 0, 0));
        assert!(record.is_live_at(10, 0, 0));
        assert!(record.is_live_at(19, 0, 0));
        assert!(!record.is_live_at(20, 0, 0));
        // overlap/expiry grace extends acceptance
        assert!(record.is_live_at(20, 2, 0));
        assert!(!record.is_live_at(23, 2, 0));
    }
    #[test]
    fn consensus_key_record_disabled_is_never_live() {
        let id = ConsensusKeyId::new(ConsensusKeyRole::Validator, "v1");
        let pk = checked_random_keypair().public_key().clone();
        let record = ConsensusKeyRecord {
            id,
            public_key: pk,
            pop: None,
            activation_height: 0,
            expiry_height: None,
            replaces: None,
            status: ConsensusKeyStatus::Disabled,
        };
        assert!(!record.is_live_at(0, 5, 5));
        assert!(!record.is_live_at(100, 5, 5));
    }

    #[test]
    fn consensus_key_record_json_rejects_unknown_fields() {
        let record = ConsensusKeyRecord {
            id: ConsensusKeyId::new(ConsensusKeyRole::Validator, "v1"),
            public_key: checked_random_keypair().public_key().clone(),
            pop: None,
            activation_height: 10,
            expiry_height: None,
            replaces: None,
            status: ConsensusKeyStatus::Pending,
        };
        let mut value = norito::json::to_value(&record).expect("serialize consensus key record");
        value
            .as_object_mut()
            .expect("consensus key record JSON object")
            .insert(
                "unsupported_key_metadata".to_owned(),
                norito::json::Value::Null,
            );
        assert!(
            norito::json::from_value::<ConsensusKeyRecord>(value).is_err(),
            "the first-release consensus key schema must reject unknown fields"
        );
    }
    #[test]
    fn validator_election_outcome_empty_has_expected_defaults() {
        let seed = [0x44; 32];
        let outcome = ValidatorElectionOutcome::empty(7, 42, seed);
        assert_eq!(outcome.epoch, 7);
        assert_eq!(outcome.snapshot_height, 42);
        assert_eq!(outcome.seed, seed);
        assert_eq!(outcome.candidates_total, 0);
        assert!(outcome.validator_set.is_empty());
        assert_eq!(
            outcome.validator_set_hash,
            HashOf::new(&outcome.validator_set)
        );
        assert_eq!(outcome.params.max_validators, 0);
        assert_eq!(outcome.params.finality_margin_blocks, 0);
        assert_eq!(
            outcome.rejection_reason.as_deref(),
            Some("validator election failed")
        );
        assert!(outcome.tie_break.is_empty());
    }
}
