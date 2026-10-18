//! Atomic private cross-dataspace settlement wire types.
//!
//! This module defines the public manifest, restricted proof sidecar, local
//! auditor policy and approval, and compact Native AMX receipt carried by the
//! first atomic private-settlement protocol. Business contents exist only in
//! [`PrivateSettlementAuditPlaintextV1`] and its nested restricted types. The
//! literal pool-to-asset mapping and its random opening additionally exist in
//! [`PrivateSettlementPoolGovernanceV1`]. These restricted objects have
//! redacted debug output and must never be embedded in blocks, public receipts,
//! logs, events, metrics, or errors.

mod confidential_encoding;
mod context;
pub use context::*;
mod error;
mod proof_intent;
mod settlement_validation;
pub use proof_intent::PrivateSettlementProofIntentV1;

pub use error::PrivateSettlementValidationError;

#[cfg(test)]
use confidential_encoding::CONFIDENTIAL_NONZERO_BUFFER_ZEROIZED_DROPS;
use confidential_encoding::{
    canonical_hash, encode_confidential_canonical, private_settlement_signature_preimage,
    zeroize_confidential_vec_spare_capacity,
};

use crate::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    privacy::{
        PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PrivacyCommitmentV1,
        PrivacyEncryptedOutputV1, PrivacyNullifierV1, PrivacyPoolIdV1, PrivacyRootV1,
    },
    transaction::FeePaymentIntent,
};
use iroha_crypto::{
    Hash, HashOf, HybridPublicKey, PublicKey, SignatureOf, zeroize_value_for_confidential_discard,
};
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Atomic private-settlement wire version.
pub const ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1: u8 = 1;
/// Minimum number of dataspaces in one atomic private settlement.
pub const ATOMIC_PRIVATE_SETTLEMENT_MIN_LEGS_V1: usize = 2;
/// Maximum number of dataspaces in one atomic private settlement.
pub const ATOMIC_PRIVATE_SETTLEMENT_MAX_LEGS_V1: usize = u8::MAX as usize;
/// Exact number of nullifier slots in the fixed-shape settlement proof.
pub const PRIVATE_SETTLEMENT_INPUT_SLOTS_V1: usize = 2;
/// Exact number of output slots in the fixed-shape settlement proof.
pub const PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1: usize = 3;
/// Exact validator count in one private-settlement participant committee.
pub const PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1: usize = 4;
/// Minimum signatures required from a four-validator participant committee.
pub const PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1: u8 = 3;
/// Maximum number of auditors governed by one dataspace policy.
pub const PRIVATE_SETTLEMENT_MAX_AUDITORS_V1: usize = 32;
/// Maximum cleartext memo bytes admitted to an auditor capsule.
pub const PRIVATE_SETTLEMENT_MAX_AUDIT_MEMO_BYTES_V1: usize = 2 * 1024;
/// Maximum governed policy-reference digests admitted to an auditor capsule.
pub const PRIVATE_SETTLEMENT_MAX_AUDIT_POLICY_REFERENCES_V1: usize = 32;
/// Maximum proof bytes in one restricted private-settlement sidecar.
///
/// This is the closed IVM proof ceiling.  Sidecar framing, capsule bytes, and
/// availability metadata are budgeted separately and must never be smuggled
/// into this field.
pub const PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1: usize = 8 * 1024 * 1024;
/// ML-KEM-768 public key width.
pub const PRIVATE_SETTLEMENT_ML_KEM_768_PUBLIC_KEY_BYTES_V1: usize = 1_184;
/// ML-KEM-768 encapsulation ciphertext width.
pub const PRIVATE_SETTLEMENT_ML_KEM_768_CIPHERTEXT_BYTES_V1: usize = 1_088;
/// XChaCha20-Poly1305 nonce width.
pub const PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1: usize = 24;
/// A wrapped 32-byte DEK plus its Poly1305 authentication tag.
pub const PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1: usize = 48;
/// Conservative canonical framing budget for the capsule header, AAD, nonce, and vectors.
pub const PRIVATE_SETTLEMENT_CAPSULE_ENVELOPE_BOUND_BYTES_V1: u64 = 8 * 1024;
/// Conservative canonical framing budget for one governed auditor's complete wrapped-DEK row.
///
/// The budget includes the account identifier, algorithm-tagged public key,
/// ML-KEM ciphertext, X25519 component, nonce, wrapped key, and Norito framing.
pub const PRIVATE_SETTLEMENT_WRAPPED_DEK_ROW_BOUND_BYTES_V1: u64 = 8 * 1024;
/// Upper bound for the canonical public carrier receipt.
pub const PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1: usize = 4 * 1024 * 1024;
/// Compressed BLS-normal proof/signature width used by Native AMX.
pub const PRIVATE_SETTLEMENT_BLS_BYTES_V1: usize = 96;
/// Attested lifecycle code for a sidecar collecting auditor approvals.
pub const PRIVATE_SETTLEMENT_LIFECYCLE_COLLECTING_V1: u8 = 0;
/// Attested lifecycle code for a sidecar with its auditor threshold satisfied.
pub const PRIVATE_SETTLEMENT_LIFECYCLE_AUDITED_V1: u8 = 1;
/// Attested lifecycle code for a durably prepared sidecar.
pub const PRIVATE_SETTLEMENT_LIFECYCLE_PREPARED_V1: u8 = 2;
/// Attested lifecycle code for a sidecar carrying a durable Commit QC.
pub const PRIVATE_SETTLEMENT_LIFECYCLE_COMMIT_CERTIFIED_V1: u8 = 3;
/// Attested lifecycle code for an atomically finalized sidecar.
pub const PRIVATE_SETTLEMENT_LIFECYCLE_FINALIZED_V1: u8 = 4;
/// Attested lifecycle code for an authoritatively aborted sidecar.
pub const PRIVATE_SETTLEMENT_LIFECYCLE_ABORTED_V1: u8 = 5;
/// Attested lifecycle code for an expired sidecar.
pub const PRIVATE_SETTLEMENT_LIFECYCLE_EXPIRED_V1: u8 = 6;
/// Exact number of ordinary fee-bearing carriers in a successful V1 settlement.
///
/// Prepare registration is the first carrier and atomic financial finalization
/// is the second. The designated private reimbursement terms bind this count so
/// they cannot be interpreted as covering only the final carrier.
pub const PRIVATE_SETTLEMENT_SUCCESS_FEE_BEARING_CARRIERS_V1: u8 = 2;
/// Exact audited settlement-local proof profile descriptor.
pub const PRIVATE_SETTLEMENT_PROOF_PROFILE_DESCRIPTOR_V1: &[u8] = b"iroha-atomic-private-settlement-stark-v1:native-rust:first-release:inputs=2-fixed:payer-authorization=purpose-separated-controller-signatures:outputs=3-fixed:roles=recipient+change+sponsor-reimbursement:activity=positive-value-membership-or-zero-virtual-domain-dummy:input-openings=air-sha256-raw256-exact-ordered-values-authorities-rhos-blindings-memos:values=u128-checked-balanced:asset=salted-hidden-binding:tree=sha256-depth32:successor=proof-statement-bound-root+epoch:successor-correctness=validator-derived-frontier:public-intent=canonical-proof-binding-excluding-post-proof-artifacts:reimbursement-success-fee-carriers=2:business-plaintext=auditor-capsule-sha256-commitment:wallet=x25519+xchacha20poly1305:proof=stark-fri-sha3-384-goldilocks";

/// Return a deterministic safe upper bound for one canonical V1 audit capsule.
///
/// `padded_plaintext_bytes` excludes the 16-byte payload authentication tag.
/// The bound is intentionally conservative so configuration validation can
/// prove that at least the governed minimum auditor roster is usable without
/// constructing identities or cryptographic material.
#[must_use]
pub const fn private_settlement_capsule_canonical_upper_bound_v1(
    padded_plaintext_bytes: u64,
    auditor_count: u64,
) -> u64 {
    padded_plaintext_bytes
        .saturating_add(16)
        .saturating_add(PRIVATE_SETTLEMENT_CAPSULE_ENVELOPE_BOUND_BYTES_V1)
        .saturating_add(
            auditor_count.saturating_mul(PRIVATE_SETTLEMENT_WRAPPED_DEK_ROW_BOUND_BYTES_V1),
        )
}

const BUNDLE_ID_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:bundle-id:v1\0";
const PROOF_BINDING_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:proof-binding:v1\0";
const MANIFEST_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:manifest:v1\0";
const STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:statement:v1\0";
const PROOF_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:proof:v1\0";
const DELTA_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:delta:v1\0";
const CAPSULE_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:audit-capsule:v1\0";
const SIDECAR_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:sidecar:v1\0";
const SIDECAR_AVAILABILITY_SIGNATURE_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:availability-signature:v1\0";
const AUDITOR_VIEW_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:auditor-view:v1\0";
const AUDITOR_VIEW_ATTESTATION_SIGNATURE_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:auditor-view-attestation:v1\0";
const AUDIT_APPROVAL_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:audit-approval:v1\0";
const AUDIT_APPROVAL_ACKNOWLEDGEMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:audit-approval-acknowledgement:v1\0";
const AUDIT_APPROVAL_ACKNOWLEDGEMENT_ATTESTATION_SIGNATURE_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:audit-approval-acknowledgement-attestation:v1\0";
const PHASE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:participant-phase-signature:v1\0";
const PREPARED_BUNDLE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:prepared-bundle:v1\0";
const AUDIT_POLICY_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:audit-policy:v1\0";
const POOL_GOVERNANCE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:pool-governance:v1\0";
const AUDITOR_KEY_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:auditor-key:v1\0";
const AUTHORITY_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:authority:v1\0";
const OUTPUT_VIEW_KEY_AUTHORIZATION_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:output-view-key-authorization:v1\0";
const PAYER_INPUT_AUTHORIZATION_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:payer-input-authorization:v1\0";
const AUDIT_PLAINTEXT_COMMITMENT_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:audit-plaintext:v1\0";
const ASSET_BINDING_COMMITMENT_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:asset-binding:v1\0";
const FEE_INTENT_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:fee-intent:v1\0";
const REIMBURSEMENT_TERMS_COMMITMENT_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:reimbursement-terms:v1\0";

fn hash_is_zero(hash: &Hash) -> bool {
    *hash == Hash::prehashed([0; Hash::LENGTH])
}

/// Compute the SHA-256 commitment to one canonical typed auditor plaintext.
///
/// The decoder rejects arbitrary bytes and non-canonical aliases before the
/// non-circular audit projection is committed.  Output commitments and output
/// memo digests are verifier-derived from that projection and are deliberately
/// not hashed back into it; an auditor must recompute and compare both fields.
///
/// # Errors
///
/// Returns a Norito error on a platform where the slice length does not fit
/// the canonical `u64` frame.
pub fn private_settlement_audit_plaintext_commitment_v1(
    canonical_plaintext: &[u8],
) -> Result<Hash, norito::Error> {
    let plaintext =
        norito::decode_canonical::<PrivateSettlementAuditPlaintextV1>(canonical_plaintext)?;
    plaintext.validate().map_err(|_| {
        norito::Error::Io(std::io::Error::other(
            "invalid atomic private settlement audit plaintext",
        ))
    })?;
    plaintext.commitment()
}

/// Canonical route and incarnation of one private settlement leg.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementRouteV1")]
pub struct PrivateSettlementRouteV1 {
    /// Participant dataspace visible on the global plane.
    pub dataspace_id: DataSpaceId,
    /// Participant lane visible on the global plane.
    pub lane_id: LaneId,
    /// Exact active lane incarnation at the authority context.
    pub lane_incarnation: Hash,
}

#[derive(Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAssetBindingMaterialV1"
)]
struct PrivateSettlementAssetBindingMaterialV1 {
    route: PrivateSettlementRouteV1,
    pool_id: PrivacyPoolIdV1,
    asset_definition_id: AssetDefinitionId,
    asset_binding_salt: [u8; 32],
}

impl PrivateSettlementAssetBindingMaterialV1 {
    fn zeroize_for_confidential_discard(&mut self) {
        zeroize_value_for_confidential_discard(&mut self.asset_definition_id.aid_bytes);
        zeroize_value_for_confidential_discard(&mut self.asset_binding_salt);
    }
}

impl Drop for PrivateSettlementAssetBindingMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Recompute the salted commitment opening one restricted pool-to-asset mapping.
///
/// The complete route, including the lane incarnation, is committed so a valid
/// opening cannot be replayed after a route is re-incarnated. The exact asset
/// and random salt are restricted governance material and must not be copied
/// into a public manifest, receipt, event, log, or metric.
///
/// # Errors
///
/// Returns a Norito error when the canonical binding material cannot be encoded.
pub fn private_settlement_asset_binding_commitment_v1(
    route: PrivateSettlementRouteV1,
    pool_id: PrivacyPoolIdV1,
    asset_definition_id: &AssetDefinitionId,
    asset_binding_salt: [u8; 32],
) -> Result<Hash, norito::Error> {
    let material = PrivateSettlementAssetBindingMaterialV1 {
        route,
        pool_id,
        asset_definition_id: asset_definition_id.clone(),
        asset_binding_salt,
    };
    let encoded = encode_confidential_canonical(&material)?;
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| norito::Error::Io(std::io::Error::other("asset binding is too large")))?;
    let mut hasher = Sha256::new();
    hasher.update(ASSET_BINDING_COMMITMENT_DOMAIN_V1);
    hasher.update(encoded_len.to_le_bytes());
    hasher.update(encoded.as_slice());
    Ok(Hash::prehashed(hasher.finalize().into()))
}

/// Public commitment to one restricted private settlement leg.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementLegCommitmentV1"
)]
pub struct PrivateSettlementLegCommitmentV1 {
    /// Zero-based ordinal in canonical route order.
    pub ordinal: u8,
    /// Exact participant route.
    pub route: PrivateSettlementRouteV1,
    /// Opaque private-note pool identifier; it never embeds a literal asset identifier.
    pub pool_id: PrivacyPoolIdV1,
    /// Salted commitment to the restricted pool-to-asset binding.
    pub asset_binding_commitment: Hash,
    /// Digest of the governed local auditor policy.
    pub audit_policy_digest: Hash,
    /// Digest of the complete restricted sidecar.
    pub payload_digest: Hash,
    /// Digest of the exact signed restricted-DA availability certificate.
    pub availability_certificate_digest: Hash,
    /// Digest of the fixed-shape public state delta.
    pub delta_digest: Hash,
}

/// Canonical public intent projection shared by construction and final manifests.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementBundleIdMaterialV1"
)]
pub struct PrivateSettlementBundleIdMaterialV1 {
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Independently selected authenticated Global context height.
    pub authority_context_height: u64,
    /// Last admissible settlement height.
    pub expiry_height: u64,
    /// Exact public fee sponsor.
    pub sponsor: AccountId,
    /// Canonical public fee intent digest.
    pub fee_intent_digest: Hash,
    /// Commitment to independently authorized restricted reimbursement terms.
    pub reimbursement_terms_commitment: Hash,
    /// Ordered leg carrying the sole reimbursement.
    pub reimbursement_leg_ordinal: u8,
    /// Canonical ordered public participant intents.
    pub legs: Vec<PrivateSettlementBundleLegMaterialV1>,
}

/// Canonical public intent projection shared by construction and final manifests.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementBundleLegMaterialV1"
)]
pub struct PrivateSettlementBundleLegMaterialV1 {
    /// Canonical zero-based leg ordinal.
    pub ordinal: u8,
    /// Exact route and incarnation.
    pub route: PrivateSettlementRouteV1,
    /// Opaque native pool identifier.
    pub pool_id: PrivacyPoolIdV1,
    /// Salted binding to the restricted asset.
    pub asset_binding_commitment: Hash,
    /// Exact governed auditor-policy digest.
    pub audit_policy_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementProofBindingMaterialV1"
)]
struct PrivateSettlementProofBindingMaterialV1 {
    version: u8,
    bundle_id: Hash,
    intent: PrivateSettlementBundleIdMaterialV1,
}

/// Public manifest for one atomic private cross-dataspace settlement.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::AtomicPrivateSettlementV1")]
pub struct AtomicPrivateSettlementV1 {
    /// Wire version; must be [`ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1`].
    pub version: u8,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable domain-separated identifier derived from public intent material.
    pub bundle_id: Hash,
    /// Global/catalog height used to resolve routes, policies, and keys.
    pub authority_context_height: u64,
    /// Final global block height at which unfinished work expires.
    pub expiry_height: u64,
    /// Neutral public relayer that submits and funds the global carrier.
    pub sponsor: AccountId,
    /// Exact signature-bound public fee payer, assets, and charge maxima.
    pub public_fee_intent: FeePaymentIntent,
    /// Digest of the signature-bound public fee intent and quote.
    pub fee_intent_digest: Hash,
    /// Commitment to the privately agreed sponsor reimbursement terms.
    pub reimbursement_terms_commitment: Hash,
    /// Leg whose fixed third output reimburses the sponsor.
    pub reimbursement_leg_ordinal: u8,
    /// Canonically ordered public leg commitments.
    pub legs: Vec<PrivateSettlementLegCommitmentV1>,
}

/// Proof relation selected for a restricted private settlement leg.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "profile",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementProofProfileV1"
)]
pub enum PrivateSettlementProofProfileV1 {
    /// IVM private-note STARK with two fixed inputs and three fixed outputs.
    IvmPrivateNoteFixed2In3Out,
}

/// Exact fixed-shape public statement verified by a participant committee.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementProofStatementV1"
)]
pub struct PrivateSettlementProofStatementV1 {
    /// Statement wire version.
    pub version: u8,
    /// Closed proof profile.
    pub profile: PrivateSettlementProofProfileV1,
    /// Pinned digest of the exact relation/profile descriptor.
    pub proof_profile_digest: Hash,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact participant route.
    pub route: PrivateSettlementRouteV1,
    /// Global/catalog height used to resolve the route, keys, and policy.
    pub authority_context_height: u64,
    /// Opaque private-note pool identifier.
    pub pool_id: PrivacyPoolIdV1,
    /// Salted commitment to the restricted pool-to-asset binding.
    pub asset_binding_commitment: Hash,
    /// Current private state root.
    pub old_root: PrivacyRootV1,
    /// Successor root bound into the proof statement and independently derived by validators.
    pub new_root: PrivacyRootV1,
    /// Epoch of `old_root`.
    pub old_epoch: u64,
    /// Epoch of `new_root`; exactly one greater than `old_epoch`.
    pub new_epoch: u64,
    /// Two fixed nullifier slots, including any domain-separated dummy slot.
    pub nullifiers: Vec<PrivacyNullifierV1>,
    /// Three fixed commitment slots: recipient, change/dummy, and sponsor reimbursement.
    pub output_commitments: Vec<PrivacyCommitmentV1>,
    /// Three fixed encrypted outputs aligned with `output_commitments`.
    pub encrypted_outputs: Vec<PrivacyEncryptedOutputV1>,
    /// SHA-256 commitment to the exact auditor-only business plaintext.
    pub audit_plaintext_commitment: Hash,
    /// Exact raw SHA-256 commitment to the two private input openings proved by the AIR.
    ///
    /// Includes each value, authority, nonce, blinding and memo. Activity is
    /// canonical: a positive value is live and zero is a virtual dummy. All
    /// 256 digest bits are retained; Iroha entity-hash marker semantics do not apply.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub audit_input_commitment: [u8; 32],
    /// Digest of the encrypted audit capsule.
    pub audit_capsule_digest: Hash,
    /// Digest of the governed auditor policy.
    pub audit_policy_digest: Hash,
    /// Exact auditor encryption/signing key epoch.
    pub audit_key_epoch: u64,
    /// Digest of the public fee quote and fee intent.
    pub fee_intent_digest: Hash,
    /// Commitment to private reimbursement terms.
    pub reimbursement_terms_commitment: Hash,
    /// Manifest leg whose third output must reimburse the sponsor.
    pub reimbursement_leg_ordinal: u8,
    /// Final global height at which the statement remains admissible.
    pub expiry_height: u64,
}

/// Fixed-shape state delta committed by a participant committee.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementDeltaV1")]
pub struct PrivateSettlementDeltaV1 {
    /// Delta wire version.
    pub version: u8,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact participant route.
    pub route: PrivateSettlementRouteV1,
    /// Opaque pool identifier.
    pub pool_id: PrivacyPoolIdV1,
    /// Salted commitment to the restricted asset binding.
    pub asset_binding_commitment: Hash,
    /// Current root and epoch.
    pub old_root: PrivacyRootV1,
    /// Successor root deterministically derived from the old frontier and fixed outputs.
    pub new_root: PrivacyRootV1,
    /// Epoch of `old_root`.
    pub old_epoch: u64,
    /// Epoch of `new_root`; exactly one greater than `old_epoch`.
    pub new_epoch: u64,
    /// Fixed nullifier slots.
    pub nullifiers: Vec<PrivacyNullifierV1>,
    /// Fixed output commitments.
    pub output_commitments: Vec<PrivacyCommitmentV1>,
    /// Fixed encrypted outputs aligned with `output_commitments`.
    pub encrypted_outputs: Vec<PrivacyEncryptedOutputV1>,
    /// Digest of the proof statement.
    pub statement_digest: Hash,
    /// Digest of the proof bytes.
    pub proof_digest: Hash,
    /// Digest of the encrypted audit capsule.
    pub capsule_digest: Hash,
    /// Digest of the governed audit policy.
    pub audit_policy_digest: Hash,
    /// Auditor policy key epoch.
    pub audit_key_epoch: u64,
}

/// Padding class used for encrypted auditor capsules.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "padding",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementCapsulePaddingV1"
)]
pub enum PrivateSettlementCapsulePaddingV1 {
    /// 4 KiB padded plaintext.
    KiB4,
    /// 16 KiB padded plaintext.
    KiB16,
    /// 64 KiB padded plaintext.
    KiB64,
    /// 256 KiB padded plaintext.
    KiB256,
}

impl PrivateSettlementCapsulePaddingV1 {
    /// Exact padded plaintext width.
    #[must_use]
    pub const fn plaintext_bytes(self) -> usize {
        match self {
            Self::KiB4 => 4 * 1024,
            Self::KiB16 => 16 * 1024,
            Self::KiB64 => 64 * 1024,
            Self::KiB256 => 256 * 1024,
        }
    }

    /// Exact ciphertext width including the Poly1305 tag.
    #[must_use]
    pub const fn ciphertext_bytes(self) -> usize {
        self.plaintext_bytes() + 16
    }
}

/// Fixed semantic role of one private-settlement output slot.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "role",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditOutputRoleV1"
)]
pub enum PrivateSettlementAuditOutputRoleV1 {
    /// CBDC note created for the settlement recipient.
    SettlementRecipient,
    /// Optional change note returned to the payer.
    PayerChange,
    /// Optional note reimbursing the public carrier sponsor.
    SponsorReimbursement,
}

/// One fixed input slot authorized by the private-settlement payer.
///
/// The slot carries only public note identifiers and a digest of the note
/// spending authority. It never contains the corresponding spending secret.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditPayerInputV1"
)]
pub struct PrivateSettlementAuditPayerInputV1 {
    /// Fixed input ordinal in the two-input relation.
    pub input_ordinal: u8,
    /// Whether this slot contains a spendable input rather than a cover note.
    pub active: bool,
    /// Exact input note commitment consumed by the proof witness.
    pub commitment: PrivacyCommitmentV1,
    /// Exact fixed-slot nullifier published by the proof statement.
    pub nullifier: PrivacyNullifierV1,
    /// Digest of the note spending authority, never its spending secret.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub note_spending_authority: [u8; 32],
    /// Non-zero bundle-bound dummy domain exactly when `active` is false.
    #[norito(required)]
    pub dummy_domain: Option<Hash>,
}

impl fmt::Debug for PrivateSettlementAuditPayerInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditPayerInputV1(<redacted>)")
    }
}

impl PrivateSettlementAuditPayerInputV1 {
    /// Wipe the restricted input-authority metadata before discard.
    ///
    /// Public commitment and nullifier bindings remain intact. The value
    /// intentionally becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        zeroize_value_for_confidential_discard(&mut self.active);
        zeroize_value_for_confidential_discard(&mut self.note_spending_authority);
        zeroize_value_for_confidential_discard(&mut self.dummy_domain);
    }
}

impl Drop for PrivateSettlementAuditPayerInputV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Purpose-separated authorization body for both fixed payer input slots.
///
/// The payer controller signs this restricted body before proof construction,
/// binding the exact public nullifiers and private input-authority digests to
/// one bundle, leg, route, and expiry without disclosing spending secrets.
#[derive(
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditPayerAuthorizationBodyV1"
)]
pub struct PrivateSettlementAuditPayerAuthorizationBodyV1 {
    /// Wire version.
    pub version: u8,
    /// Hash of the fixed payer-authorization purpose domain.
    pub purpose: Hash,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact participant route.
    pub route: PrivateSettlementRouteV1,
    /// Exact payer whose controller authorizes both input slots.
    pub payer: AccountId,
    /// Global settlement expiry preventing authorization replay after expiry.
    pub expiry_height: u64,
    /// Exactly two ordinal-ordered active-or-dummy input bindings.
    pub inputs: Vec<PrivateSettlementAuditPayerInputV1>,
}

impl fmt::Debug for PrivateSettlementAuditPayerAuthorizationBodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditPayerAuthorizationBodyV1(<redacted>)")
    }
}

impl PrivateSettlementAuditPayerAuthorizationBodyV1 {
    /// Construct the existing payer-signing body before a complete audit plaintext exists.
    /// The input openings and real public nullifiers must already be derived by the wallet.
    /// This supplies no signature or proof authority.
    /// # Errors
    /// Invalid fixed input shape, zero/duplicate nullifiers or invalid replay binding.
    #[allow(clippy::too_many_arguments)]
    pub fn from_openings(
        network_id: NetworkId,
        bundle_id: Hash,
        leg_ordinal: u8,
        route: PrivateSettlementRouteV1,
        payer: &AccountId,
        expiry_height: u64,
        openings: &[PrivateSettlementAuditNoteOpeningV1],
        nullifiers: &[PrivacyNullifierV1],
    ) -> Result<Self, PrivateSettlementValidationError> {
        if nullifiers.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
            || nullifiers.iter().any(PrivacyNullifierV1::is_zero)
            || nullifiers[0] == nullifiers[1]
            || openings.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        let inputs = openings
            .iter()
            .zip(nullifiers)
            .enumerate()
            .map(|(index, (opening, nullifier))| {
                Ok(PrivateSettlementAuditPayerInputV1 {
                    input_ordinal: u8::try_from(index)
                        .map_err(|_| PrivateSettlementValidationError::InvalidAuditPlaintext)?,
                    active: opening.active,
                    commitment: opening.commitment,
                    nullifier: *nullifier,
                    note_spending_authority: opening.spending_authority,
                    dummy_domain: opening.dummy_domain,
                })
            })
            .collect::<Result<Vec<_>, PrivateSettlementValidationError>>()?;
        let body = PrivateSettlementAuditPayerAuthorizationBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            purpose: Hash::new(PAYER_INPUT_AUTHORIZATION_DOMAIN_V1),
            network_id,
            bundle_id,
            leg_ordinal,
            route,
            payer: payer.clone(),
            expiry_height,
            inputs,
        };
        body.validate_shape()?;
        Ok(body)
    }

    /// Wipe restricted payer identity and input-authority metadata before discard.
    ///
    /// Public replay and proof bindings remain intact. The body intentionally
    /// becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.payer.zeroize_for_confidential_discard();
        for input in &mut self.inputs {
            input.zeroize_for_confidential_discard();
        }
        zeroize_confidential_vec_spare_capacity(&mut self.inputs);
    }

    fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
            || self.purpose != Hash::new(PAYER_INPUT_AUTHORIZATION_DOMAIN_V1)
            || hash_is_zero(&self.bundle_id)
            || hash_is_zero(&self.route.lane_incarnation)
            || self.expiry_height == 0
            || self.inputs.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        for (index, input) in self.inputs.iter().enumerate() {
            if usize::from(input.input_ordinal) != index
                || input.commitment.is_zero()
                || input.nullifier.is_zero()
                || input.note_spending_authority.iter().all(|byte| *byte == 0)
                || input.active == input.dummy_domain.is_some()
                || input
                    .dummy_domain
                    .is_some_and(|dummy_domain| hash_is_zero(&dummy_domain))
            {
                return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
            }
        }
        if self.inputs[0].nullifier == self.inputs[1].nullifier {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        Ok(())
    }
}

impl Drop for PrivateSettlementAuditPayerAuthorizationBodyV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// One controller-member signature authorizing both fixed payer inputs.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditPayerSignatureV1"
)]
pub struct PrivateSettlementAuditPayerSignatureV1 {
    /// Controller member that produced the signature.
    pub signer: PublicKey,
    /// Purpose-specific signature over the exact payer authorization body.
    pub signature: SignatureOf<PrivateSettlementAuditPayerAuthorizationBodyV1>,
}

impl fmt::Debug for PrivateSettlementAuditPayerSignatureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditPayerSignatureV1(<redacted>)")
    }
}

impl PrivateSettlementAuditPayerSignatureV1 {
    /// Wipe confidential signer and signature metadata before discard.
    ///
    /// The entry intentionally becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.signer.zeroize_for_confidential_discard();
        self.signature.zeroize_for_confidential_discard();
    }

    /// Construct one typed controller signature entry.
    #[must_use]
    pub fn new(
        signer: PublicKey,
        signature: SignatureOf<PrivateSettlementAuditPayerAuthorizationBodyV1>,
    ) -> Self {
        Self { signer, signature }
    }
}

impl Drop for PrivateSettlementAuditPayerSignatureV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Canonical single- or multisignature payer authorization for both inputs.
#[derive(
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditPayerAuthorizationV1"
)]
pub struct PrivateSettlementAuditPayerAuthorizationV1 {
    /// Exact purpose-separated payer authorization body.
    pub body: PrivateSettlementAuditPayerAuthorizationBodyV1,
    /// Unique controller signatures in strict public-key order.
    pub signatures: Vec<PrivateSettlementAuditPayerSignatureV1>,
}

impl fmt::Debug for PrivateSettlementAuditPayerAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditPayerAuthorizationV1(<redacted>)")
    }
}

impl PrivateSettlementAuditPayerAuthorizationV1 {
    /// Wipe every restricted field in this payer authorization before discard.
    ///
    /// Public binding context remains intact. The authorization intentionally
    /// becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.body.zeroize_for_confidential_discard();
        for signature in &mut self.signatures {
            signature.zeroize_for_confidential_discard();
        }
        zeroize_confidential_vec_spare_capacity(&mut self.signatures);
    }

    /// Construct an authorization with canonical signer ordering.
    #[must_use]
    pub fn new(
        body: PrivateSettlementAuditPayerAuthorizationBodyV1,
        mut signatures: Vec<PrivateSettlementAuditPayerSignatureV1>,
    ) -> Self {
        signatures.sort_unstable_by(|left, right| left.signer.cmp(&right.signer));
        Self { body, signatures }
    }

    fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        self.body.validate_shape()?;
        if self.signatures.is_empty()
            || self
                .signatures
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        Ok(())
    }
}

impl Drop for PrivateSettlementAuditPayerAuthorizationV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Purpose-separated account authorization of one one-time output view key.
///
/// This body is restricted audit-capsule material. It binds a one-time X25519
/// view key to the exact account occupying one fixed settlement role without
/// publishing either the account controller or its authorization signatures.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditViewKeyAuthorizationBodyV1"
)]
pub struct PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
    /// Wire version.
    pub version: u8,
    /// Hash of the fixed authorization-purpose domain.
    pub purpose: Hash,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact participant route.
    pub route: PrivateSettlementRouteV1,
    /// Fixed output ordinal within the three-output relation.
    pub output_ordinal: u8,
    /// Exact semantic output role.
    pub role: PrivateSettlementAuditOutputRoleV1,
    /// Exact account whose controller authorizes the view key.
    pub authorized_account: AccountId,
    /// One-time X25519 public view key being authorized.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub recipient_view_key: [u8; 32],
    /// Whether the authorized output is an active note or a fixed cover slot.
    pub output_active: bool,
    /// Digest of the authorized output note's spending authority.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub note_spending_authority: [u8; 32],
    /// Global settlement expiry preventing authorization replay after expiry.
    pub expiry_height: u64,
}

impl fmt::Debug for PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditViewKeyAuthorizationBodyV1(<redacted>)")
    }
}

impl PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
    /// Construct the existing output-view signing body from an actual note opening.
    /// The ordinal selects recipient, payer change or sponsor; no placeholder signature
    /// or completed plaintext is needed. This supplies no signature or proof authority.
    /// # Errors
    /// An ordinal outside the fixed three-output relation.
    #[allow(clippy::too_many_arguments)]
    pub fn from_output(
        network_id: NetworkId,
        bundle_id: Hash,
        leg_ordinal: u8,
        route: PrivateSettlementRouteV1,
        expiry_height: u64,
        recipient: &AccountId,
        payer: &AccountId,
        sponsor: &AccountId,
        output_index: usize,
        recipient_view_key: [u8; 32],
        note: &PrivateSettlementAuditNoteOpeningV1,
    ) -> Result<Self, PrivateSettlementValidationError> {
        let (role, authorized_account) = match output_index {
            0 => (
                PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
                recipient.clone(),
            ),
            1 => (
                PrivateSettlementAuditOutputRoleV1::PayerChange,
                payer.clone(),
            ),
            2 => (
                PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
                sponsor.clone(),
            ),
            _ => return Err(PrivateSettlementValidationError::InvalidAuditPlaintext),
        };
        Ok(Self {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            purpose: Hash::new(OUTPUT_VIEW_KEY_AUTHORIZATION_DOMAIN_V1),
            network_id,
            bundle_id,
            leg_ordinal,
            route,
            output_ordinal: u8::try_from(output_index)
                .map_err(|_| PrivateSettlementValidationError::InvalidAuditPlaintext)?,
            role,
            authorized_account,
            recipient_view_key,
            output_active: note.active,
            note_spending_authority: note.spending_authority,
            expiry_height,
        })
    }

    /// Wipe restricted account and one-time output-key metadata before discard.
    ///
    /// Public replay and route bindings remain intact. The body intentionally
    /// becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.authorized_account.zeroize_for_confidential_discard();
        zeroize_value_for_confidential_discard(&mut self.recipient_view_key);
        zeroize_value_for_confidential_discard(&mut self.output_active);
        zeroize_value_for_confidential_discard(&mut self.note_spending_authority);
    }
}

impl Drop for PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// One controller-member signature authorizing an output view key.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditViewKeySignatureV1"
)]
pub struct PrivateSettlementAuditViewKeySignatureV1 {
    /// Controller member that produced the signature.
    pub signer: PublicKey,
    /// Purpose-specific signature over the exact authorization body.
    pub signature: SignatureOf<PrivateSettlementAuditViewKeyAuthorizationBodyV1>,
}

impl fmt::Debug for PrivateSettlementAuditViewKeySignatureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditViewKeySignatureV1(<redacted>)")
    }
}

impl PrivateSettlementAuditViewKeySignatureV1 {
    /// Wipe confidential signer and signature metadata before discard.
    ///
    /// The entry intentionally becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.signer.zeroize_for_confidential_discard();
        self.signature.zeroize_for_confidential_discard();
    }

    /// Construct one typed controller signature entry.
    #[must_use]
    pub fn new(
        signer: PublicKey,
        signature: SignatureOf<PrivateSettlementAuditViewKeyAuthorizationBodyV1>,
    ) -> Self {
        Self { signer, signature }
    }
}

impl Drop for PrivateSettlementAuditViewKeySignatureV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Canonical single- or multisignature authorization for one output view key.
#[derive(
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditViewKeyAuthorizationV1"
)]
pub struct PrivateSettlementAuditViewKeyAuthorizationV1 {
    /// Exact purpose-separated authorization body.
    pub body: PrivateSettlementAuditViewKeyAuthorizationBodyV1,
    /// Unique controller signatures in strict public-key order.
    pub signatures: Vec<PrivateSettlementAuditViewKeySignatureV1>,
}

impl fmt::Debug for PrivateSettlementAuditViewKeyAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditViewKeyAuthorizationV1(<redacted>)")
    }
}

impl PrivateSettlementAuditViewKeyAuthorizationV1 {
    /// Wipe every restricted field in this view-key authorization before discard.
    ///
    /// Public binding context remains intact. The authorization intentionally
    /// becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.body.zeroize_for_confidential_discard();
        for signature in &mut self.signatures {
            signature.zeroize_for_confidential_discard();
        }
        zeroize_confidential_vec_spare_capacity(&mut self.signatures);
    }

    /// Construct an authorization with canonical signer ordering.
    #[must_use]
    pub fn new(
        body: PrivateSettlementAuditViewKeyAuthorizationBodyV1,
        mut signatures: Vec<PrivateSettlementAuditViewKeySignatureV1>,
    ) -> Self {
        signatures.sort_unstable_by(|left, right| left.signer.cmp(&right.signer));
        Self { body, signatures }
    }

    fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.body.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
            || self.body.purpose != Hash::new(OUTPUT_VIEW_KEY_AUTHORIZATION_DOMAIN_V1)
            || self.body.expiry_height == 0
            || self.body.recipient_view_key.iter().all(|byte| *byte == 0)
            || self.signatures.is_empty()
            || self
                .signatures
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        Ok(())
    }
}

impl Drop for PrivateSettlementAuditViewKeyAuthorizationV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Capsule-only opening of the ephemeral X25519 output-encryption public key.
///
/// This is encryption randomness, not a note spending secret. An auditor uses
/// it with the public one-time view key to authenticate and open the published
/// ciphertext deterministically; it must never leave the restricted capsule.
#[derive(
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditEncryptionOpeningV1"
)]
pub struct PrivateSettlementAuditEncryptionOpeningV1 {
    /// Ephemeral X25519 secret whose public key appears in the output envelope.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub ephemeral_secret: [u8; 32],
}

impl fmt::Debug for PrivateSettlementAuditEncryptionOpeningV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditEncryptionOpeningV1(<redacted>)")
    }
}

impl PrivateSettlementAuditEncryptionOpeningV1 {
    /// Wipe the ephemeral encryption secret before discard.
    ///
    /// The opening intentionally becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        zeroize_value_for_confidential_discard(&mut self.ephemeral_secret);
    }
}

impl Drop for PrivateSettlementAuditEncryptionOpeningV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Auditor-visible opening of one fixed private-note slot.
///
/// The opening deliberately excludes every spending secret.  Active slots
/// carry the values needed to recompute their commitments; inactive slots
/// carry only a domain-separated dummy identifier.
#[derive(
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditNoteOpeningV1"
)]
pub struct PrivateSettlementAuditNoteOpeningV1 {
    /// Whether this slot represents a spendable note.
    pub active: bool,
    /// Public commitment aligned with the private proof witness.
    pub commitment: PrivacyCommitmentV1,
    /// Atomic CBDC value; zero exactly for a dummy slot.
    pub value: u128,
    /// Digest of the spending authority, never the spending secret itself.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub spending_authority: [u8; 32],
    /// Unique active-note nonce.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub rho: [u8; 32],
    /// Active-note commitment blinding.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub blinding: [u8; 32],
    /// Digest of the note-local memo.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub memo_digest: [u8; 32],
    /// Non-zero, bundle-bound dummy domain exactly when `active` is false.
    #[norito(required)]
    pub dummy_domain: Option<Hash>,
}

impl fmt::Debug for PrivateSettlementAuditNoteOpeningV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditNoteOpeningV1(<redacted>)")
    }
}

impl PrivateSettlementAuditNoteOpeningV1 {
    /// Wipe every private note-opening field before discard.
    ///
    /// The public commitment remains intact. The opening intentionally becomes
    /// invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        zeroize_value_for_confidential_discard(&mut self.active);
        zeroize_value_for_confidential_discard(&mut self.value);
        zeroize_value_for_confidential_discard(&mut self.spending_authority);
        zeroize_value_for_confidential_discard(&mut self.rho);
        zeroize_value_for_confidential_discard(&mut self.blinding);
        zeroize_value_for_confidential_discard(&mut self.memo_digest);
        zeroize_value_for_confidential_discard(&mut self.dummy_domain);
    }

    fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.commitment.is_zero() {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        let has_zero_private_field = self.spending_authority.iter().all(|byte| *byte == 0)
            || self.rho.iter().all(|byte| *byte == 0)
            || self.blinding.iter().all(|byte| *byte == 0)
            || self.memo_digest.iter().all(|byte| *byte == 0);
        if self.active {
            if self.value == 0 || has_zero_private_field || self.dummy_domain.is_some() {
                return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
            }
        } else if self.value != 0
            || has_zero_private_field
            || self.dummy_domain.as_ref().is_none_or(hash_is_zero)
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        Ok(())
    }
}

impl Drop for PrivateSettlementAuditNoteOpeningV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Auditor-visible opening and one-time view key for one fixed output slot.
#[derive(
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditOutputV1"
)]
pub struct PrivateSettlementAuditOutputV1 {
    /// Fixed position-dependent role.
    pub role: PrivateSettlementAuditOutputRoleV1,
    /// One-time recipient/view key, including a unique cover key for dummies.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub recipient_view_key: [u8; 32],
    /// Exact role-account authorization of `recipient_view_key`.
    pub view_key_authorization: PrivateSettlementAuditViewKeyAuthorizationV1,
    /// Capsule-only opening used to authenticate the published ciphertext.
    pub encryption_opening: PrivateSettlementAuditEncryptionOpeningV1,
    /// Note or domain-separated dummy opening.
    pub note: PrivateSettlementAuditNoteOpeningV1,
}

impl fmt::Debug for PrivateSettlementAuditOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditOutputV1(<redacted>)")
    }
}

impl PrivateSettlementAuditOutputV1 {
    /// Wipe every restricted key, authorization, and opening before discard.
    ///
    /// Public role context remains intact. The output intentionally becomes
    /// invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        zeroize_value_for_confidential_discard(&mut self.recipient_view_key);
        self.view_key_authorization
            .zeroize_for_confidential_discard();
        self.encryption_opening.zeroize_for_confidential_discard();
        self.note.zeroize_for_confidential_discard();
    }
}

impl Drop for PrivateSettlementAuditOutputV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Exact business and note-opening material encrypted for local auditors.
///
/// This type is never public protocol state.  Its commitment is public and is
/// checked by the settlement proof; its bytes are available only after an
/// authorized auditor unwraps the capsule DEK.
#[derive(
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditPlaintextV1"
)]
pub struct PrivateSettlementAuditPlaintextV1 {
    /// Plaintext wire version.
    pub version: u8,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact participant route.
    pub route: PrivateSettlementRouteV1,
    /// Opaque pool identifier aligned with the public statement.
    pub pool_id: PrivacyPoolIdV1,
    /// Exact payer visible only to authorized local auditors.
    pub payer: AccountId,
    /// Purpose-separated payer-controller authorization of both input slots.
    pub payer_authorization: PrivateSettlementAuditPayerAuthorizationV1,
    /// Exact settlement recipient visible only to authorized local auditors.
    pub recipient: AccountId,
    /// Exact public carrier sponsor.
    pub sponsor: AccountId,
    /// Exact governed CBDC asset definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Random salt opening the public asset-binding commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub asset_binding_salt: [u8; 32],
    /// Atomic value delivered to the settlement recipient.
    pub amount: u128,
    /// Atomic sponsor reimbursement; zero on every non-designated leg.
    pub sponsor_reimbursement_amount: u128,
    /// Exact public fee-intent digest bound into reimbursement terms.
    pub fee_intent_digest: Hash,
    /// Global settlement expiry bound into reimbursement terms.
    pub settlement_expiry_height: u64,
    /// Random opening salt for the private reimbursement-terms commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub reimbursement_terms_salt: [u8; 32],
    /// Exact business memo, bounded before encryption.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub memo: Vec<u8>,
    /// Strictly ordered exact governance/policy references.
    pub policy_references: Vec<Hash>,
    /// Exactly two active-or-dummy input note openings.
    pub inputs: Vec<PrivateSettlementAuditNoteOpeningV1>,
    /// Exactly three role-ordered active-or-dummy outputs.
    pub outputs: Vec<PrivateSettlementAuditOutputV1>,
}

#[derive(Encode)]
struct PrivateSettlementAuditOutputCommitmentMaterialV1 {
    role: PrivateSettlementAuditOutputRoleV1,
    recipient_view_key: [u8; 32],
    view_key_authorization: PrivateSettlementAuditViewKeyAuthorizationV1,
    encryption_opening: PrivateSettlementAuditEncryptionOpeningV1,
    active: bool,
    value: u128,
    spending_authority: [u8; 32],
    rho: [u8; 32],
    blinding: [u8; 32],
    dummy_domain: Option<Hash>,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditCommitmentMaterialV1"
)]
struct PrivateSettlementAuditCommitmentMaterialV1 {
    version: u8,
    network_id: NetworkId,
    bundle_id: Hash,
    leg_ordinal: u8,
    route: PrivateSettlementRouteV1,
    pool_id: PrivacyPoolIdV1,
    payer: AccountId,
    payer_authorization: PrivateSettlementAuditPayerAuthorizationV1,
    recipient: AccountId,
    sponsor: AccountId,
    asset_definition_id: AssetDefinitionId,
    asset_binding_salt: [u8; 32],
    amount: u128,
    sponsor_reimbursement_amount: u128,
    fee_intent_digest: Hash,
    settlement_expiry_height: u64,
    reimbursement_terms_salt: [u8; 32],
    memo: Vec<u8>,
    policy_references: Vec<Hash>,
    inputs: Vec<PrivateSettlementAuditNoteOpeningV1>,
    outputs: Vec<PrivateSettlementAuditOutputCommitmentMaterialV1>,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementReimbursementTermsMaterialV1"
)]
struct PrivateSettlementReimbursementTermsMaterialV1 {
    network_id: NetworkId,
    leg_ordinal: u8,
    route: PrivateSettlementRouteV1,
    sponsor: AccountId,
    asset_definition_id: AssetDefinitionId,
    sponsor_reimbursement_amount: u128,
    fee_intent_digest: Hash,
    success_fee_bearing_carriers: u8,
    settlement_expiry_height: u64,
    reimbursement_terms_salt: [u8; 32],
}

/// Derive the exact private reimbursement commitment before a bundle or audit witness exists.
///
/// This reuses the sole canonical reimbursement projection. The successful carrier count is
/// the protocol constant, and the bundle identifier is excluded to avoid circular commitments.
/// No authorization, proof or plaintext placeholder is required or constructed.
/// # Errors
/// Canonical encoding failure; this computation alone grants no payment authority.
#[allow(clippy::too_many_arguments)]
pub fn private_settlement_reimbursement_terms_commitment_v1(
    network_id: NetworkId,
    leg_ordinal: u8,
    route: PrivateSettlementRouteV1,
    sponsor: &AccountId,
    asset_definition_id: &AssetDefinitionId,
    sponsor_reimbursement_amount: u128,
    fee_intent_digest: Hash,
    settlement_expiry_height: u64,
    reimbursement_terms_salt: [u8; 32],
) -> Result<Hash, norito::Error> {
    canonical_hash(
        REIMBURSEMENT_TERMS_COMMITMENT_DOMAIN_V1,
        &PrivateSettlementReimbursementTermsMaterialV1 {
            network_id,
            leg_ordinal,
            route,
            sponsor: sponsor.clone(),
            asset_definition_id: asset_definition_id.clone(),
            sponsor_reimbursement_amount,
            fee_intent_digest,
            success_fee_bearing_carriers: PRIVATE_SETTLEMENT_SUCCESS_FEE_BEARING_CARRIERS_V1,
            settlement_expiry_height,
            reimbursement_terms_salt,
        },
    )
}

impl PrivateSettlementAuditOutputCommitmentMaterialV1 {
    fn zeroize_for_confidential_discard(&mut self) {
        zeroize_value_for_confidential_discard(&mut self.recipient_view_key);
        self.view_key_authorization
            .zeroize_for_confidential_discard();
        self.encryption_opening.zeroize_for_confidential_discard();
        zeroize_value_for_confidential_discard(&mut self.active);
        zeroize_value_for_confidential_discard(&mut self.value);
        zeroize_value_for_confidential_discard(&mut self.spending_authority);
        zeroize_value_for_confidential_discard(&mut self.rho);
        zeroize_value_for_confidential_discard(&mut self.blinding);
        zeroize_value_for_confidential_discard(&mut self.dummy_domain);
    }
}

impl Drop for PrivateSettlementAuditOutputCommitmentMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

impl PrivateSettlementAuditCommitmentMaterialV1 {
    fn zeroize_for_confidential_discard(&mut self) {
        self.payer.zeroize_for_confidential_discard();
        self.payer_authorization.zeroize_for_confidential_discard();
        self.recipient.zeroize_for_confidential_discard();
        self.sponsor.zeroize_for_confidential_discard();
        zeroize_value_for_confidential_discard(&mut self.asset_definition_id.aid_bytes);
        zeroize_value_for_confidential_discard(&mut self.asset_binding_salt);
        zeroize_value_for_confidential_discard(&mut self.amount);
        zeroize_value_for_confidential_discard(&mut self.sponsor_reimbursement_amount);
        zeroize_value_for_confidential_discard(&mut self.reimbursement_terms_salt);
        zeroize_value_for_confidential_discard(&mut self.memo);
        zeroize_value_for_confidential_discard(&mut self.policy_references);
        for input in &mut self.inputs {
            input.zeroize_for_confidential_discard();
        }
        zeroize_confidential_vec_spare_capacity(&mut self.inputs);
        for output in &mut self.outputs {
            output.zeroize_for_confidential_discard();
        }
        zeroize_confidential_vec_spare_capacity(&mut self.outputs);
    }
}

impl Drop for PrivateSettlementAuditCommitmentMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

impl PrivateSettlementReimbursementTermsMaterialV1 {
    fn zeroize_for_confidential_discard(&mut self) {
        self.sponsor.zeroize_for_confidential_discard();
        zeroize_value_for_confidential_discard(&mut self.asset_definition_id.aid_bytes);
        zeroize_value_for_confidential_discard(&mut self.sponsor_reimbursement_amount);
        zeroize_value_for_confidential_discard(&mut self.reimbursement_terms_salt);
    }
}

impl Drop for PrivateSettlementReimbursementTermsMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

impl fmt::Debug for PrivateSettlementAuditPlaintextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditPlaintextV1(<redacted>)")
    }
}

impl Drop for PrivateSettlementAuditPlaintextV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

impl PrivateSettlementAuditPlaintextV1 {
    /// Wipe every secret-bearing field before discarding this plaintext.
    ///
    /// Public binding context remains intact, but the plaintext intentionally
    /// becomes invalid and must not be used after this call. Calling this
    /// method more than once is safe.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.payer.zeroize_for_confidential_discard();
        self.recipient.zeroize_for_confidential_discard();
        self.sponsor.zeroize_for_confidential_discard();
        zeroize_value_for_confidential_discard(&mut self.asset_definition_id.aid_bytes);
        zeroize_value_for_confidential_discard(&mut self.asset_binding_salt);
        zeroize_value_for_confidential_discard(&mut self.amount);
        zeroize_value_for_confidential_discard(&mut self.sponsor_reimbursement_amount);
        zeroize_value_for_confidential_discard(&mut self.reimbursement_terms_salt);
        zeroize_value_for_confidential_discard(&mut self.memo);
        zeroize_value_for_confidential_discard(&mut self.policy_references);

        self.payer_authorization.zeroize_for_confidential_discard();
        for input in &mut self.inputs {
            input.zeroize_for_confidential_discard();
        }
        zeroize_confidential_vec_spare_capacity(&mut self.inputs);
        for output in &mut self.outputs {
            output.zeroize_for_confidential_discard();
        }
        zeroize_confidential_vec_spare_capacity(&mut self.outputs);
    }

    /// Derive the exact purpose-separated authorization body for both inputs.
    ///
    /// Public nullifiers are supplied by the proof statement; every remaining
    /// field is derived from this restricted plaintext. The fixed slot shape is
    /// enforced before a body is returned.
    ///
    /// # Errors
    ///
    /// Returns a redacted shape error unless exactly two non-zero, distinct
    /// statement nullifiers are supplied.
    pub fn payer_authorization_body(
        &self,
        nullifiers: &[PrivacyNullifierV1],
    ) -> Result<PrivateSettlementAuditPayerAuthorizationBodyV1, PrivateSettlementValidationError>
    {
        PrivateSettlementAuditPayerAuthorizationBodyV1::from_openings(
            self.network_id,
            self.bundle_id,
            self.leg_ordinal,
            self.route,
            &self.payer,
            self.settlement_expiry_height,
            &self.inputs,
            nullifiers,
        )
    }

    /// Derive the exact purpose-separated authorization body for one output.
    ///
    /// The account is selected by fixed ordinal rather than by the untrusted
    /// role field: recipient, payer change, then sponsor.
    ///
    /// # Errors
    ///
    /// Returns a redacted shape error when `output_index` is outside the fixed
    /// three-output relation.
    pub fn output_view_key_authorization_body(
        &self,
        output_index: usize,
    ) -> Result<PrivateSettlementAuditViewKeyAuthorizationBodyV1, PrivateSettlementValidationError>
    {
        let output = self
            .outputs
            .get(output_index)
            .ok_or(PrivateSettlementValidationError::InvalidAuditPlaintext)?;
        PrivateSettlementAuditViewKeyAuthorizationBodyV1::from_output(
            self.network_id,
            self.bundle_id,
            self.leg_ordinal,
            self.route,
            self.settlement_expiry_height,
            &self.recipient,
            &self.payer,
            &self.sponsor,
            output_index,
            output.recipient_view_key,
            &output.note,
        )
    }

    fn commitment_material(&self) -> PrivateSettlementAuditCommitmentMaterialV1 {
        PrivateSettlementAuditCommitmentMaterialV1 {
            version: self.version,
            network_id: self.network_id,
            bundle_id: self.bundle_id,
            leg_ordinal: self.leg_ordinal,
            route: self.route,
            pool_id: self.pool_id,
            payer: self.payer.clone(),
            payer_authorization: self.payer_authorization.clone(),
            recipient: self.recipient.clone(),
            sponsor: self.sponsor.clone(),
            asset_definition_id: self.asset_definition_id.clone(),
            asset_binding_salt: self.asset_binding_salt,
            amount: self.amount,
            sponsor_reimbursement_amount: self.sponsor_reimbursement_amount,
            fee_intent_digest: self.fee_intent_digest,
            settlement_expiry_height: self.settlement_expiry_height,
            reimbursement_terms_salt: self.reimbursement_terms_salt,
            memo: self.memo.clone(),
            policy_references: self.policy_references.clone(),
            inputs: self.inputs.clone(),
            outputs: self
                .outputs
                .iter()
                .map(|output| PrivateSettlementAuditOutputCommitmentMaterialV1 {
                    role: output.role,
                    recipient_view_key: output.recipient_view_key,
                    view_key_authorization: output.view_key_authorization.clone(),
                    encryption_opening: output.encryption_opening.clone(),
                    active: output.note.active,
                    value: output.note.value,
                    spending_authority: output.note.spending_authority,
                    rho: output.note.rho,
                    blinding: output.note.blinding,
                    dummy_domain: output.note.dummy_domain,
                })
                .collect(),
        }
    }

    /// Compute the non-circular SHA-256 commitment proved by the settlement relation.
    ///
    /// Every business field, input opening, output secret opening, role, role
    /// authorization, one-time view key, and ephemeral encryption opening is
    /// committed. Output memo digests and commitments are excluded because the
    /// verifier derives them from this commitment; the auditor separately
    /// recomputes and compares those public fields.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when canonical encoding fails.
    pub fn commitment(&self) -> Result<Hash, norito::Error> {
        let material = self.commitment_material();
        let encoded = encode_confidential_canonical(&material)?;
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| {
            norito::Error::Io(std::io::Error::other(
                "audit commitment material is too large",
            ))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(AUDIT_PLAINTEXT_COMMITMENT_DOMAIN_V1);
        hasher.update(encoded_len.to_le_bytes());
        hasher.update(encoded.as_slice());
        Ok(Hash::prehashed(hasher.finalize().into()))
    }

    /// Compute the salted public binding of the exact restricted asset.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when canonical asset material cannot be encoded.
    pub fn asset_binding_commitment(&self) -> Result<Hash, norito::Error> {
        private_settlement_asset_binding_commitment_v1(
            self.route,
            self.pool_id,
            &self.asset_definition_id,
            self.asset_binding_salt,
        )
    }

    /// Compute the private sponsor-reimbursement terms commitment.
    ///
    /// The commitment deliberately excludes `bundle_id` because the bundle ID
    /// already commits to this value. Including both would create a circular
    /// fixed-point construction.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when canonical reimbursement material cannot be encoded.
    pub fn reimbursement_terms_commitment(&self) -> Result<Hash, norito::Error> {
        private_settlement_reimbursement_terms_commitment_v1(
            self.network_id,
            self.leg_ordinal,
            self.route,
            &self.sponsor,
            &self.asset_definition_id,
            self.sponsor_reimbursement_amount,
            self.fee_intent_digest,
            self.settlement_expiry_height,
            self.reimbursement_terms_salt,
        )
    }

    fn reimbursement_terms_material(
        &self,
        success_fee_bearing_carriers: u8,
    ) -> PrivateSettlementReimbursementTermsMaterialV1 {
        PrivateSettlementReimbursementTermsMaterialV1 {
            network_id: self.network_id,
            leg_ordinal: self.leg_ordinal,
            route: self.route,
            sponsor: self.sponsor.clone(),
            asset_definition_id: self.asset_definition_id.clone(),
            sponsor_reimbursement_amount: self.sponsor_reimbursement_amount,
            fee_intent_digest: self.fee_intent_digest,
            success_fee_bearing_carriers,
            settlement_expiry_height: self.settlement_expiry_height,
            reimbursement_terms_salt: self.reimbursement_terms_salt,
        }
    }

    /// Validate the restricted plaintext's fixed slot shape and value balance.
    ///
    /// # Errors
    ///
    /// Returns a typed error without exposing any sensitive field value.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if hash_is_zero(&self.bundle_id)
            || hash_is_zero(&self.route.lane_incarnation)
            || self.pool_id.is_zero()
            || self.asset_binding_salt.iter().all(|byte| *byte == 0)
            || hash_is_zero(&self.fee_intent_digest)
            || self.settlement_expiry_height == 0
            || self.reimbursement_terms_salt.iter().all(|byte| *byte == 0)
            || self.amount == 0
            || self.memo.len() > PRIVATE_SETTLEMENT_MAX_AUDIT_MEMO_BYTES_V1
            || self.policy_references.len() > PRIVATE_SETTLEMENT_MAX_AUDIT_POLICY_REFERENCES_V1
            || self.inputs.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
            || self.outputs.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        if self.policy_references.iter().any(hash_is_zero)
            || self
                .policy_references
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        if !self.inputs[0].active {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        for input in &self.inputs {
            input.validate()?;
        }
        self.payer_authorization.validate_shape()?;
        let authorized_nullifiers = self
            .payer_authorization
            .body
            .inputs
            .iter()
            .map(|input| input.nullifier)
            .collect::<Vec<_>>();
        if self.payer_authorization.body != self.payer_authorization_body(&authorized_nullifiers)? {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        self.validate_output_authorizations()?;
        if !self.outputs[0].note.active
            || self.outputs[0].note.value != self.amount
            || self.outputs[2].note.active != (self.sponsor_reimbursement_amount != 0)
            || self.outputs[2].note.value != self.sponsor_reimbursement_amount
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        let input_total = self
            .inputs
            .iter()
            .try_fold(0_u128, |total, input| total.checked_add(input.value));
        let output_total = self
            .outputs
            .iter()
            .try_fold(0_u128, |total, output| total.checked_add(output.note.value));
        if input_total.is_none() || input_total != output_total {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        let distinct_commitments = self
            .inputs
            .iter()
            .map(|input| input.commitment)
            .chain(self.outputs.iter().map(|output| output.note.commitment))
            .collect::<BTreeSet<_>>();
        if distinct_commitments.len()
            != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 + PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
        }
        Ok(())
    }

    // Check output ownership after the fixed-slot and payer-authorization guards.
    fn validate_output_authorizations(&self) -> Result<(), PrivateSettlementValidationError> {
        let expected_roles = [
            PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
            PrivateSettlementAuditOutputRoleV1::PayerChange,
            PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
        ];
        let mut view_keys = BTreeSet::new();
        for (index, (output, expected_role)) in self.outputs.iter().zip(expected_roles).enumerate()
        {
            if output.role != expected_role
                || output.recipient_view_key.iter().all(|byte| *byte == 0)
                || output
                    .encryption_opening
                    .ephemeral_secret
                    .iter()
                    .all(|byte| *byte == 0)
                || !view_keys.insert(output.recipient_view_key)
            {
                return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
            }
            output.view_key_authorization.validate_shape()?;
            if output.view_key_authorization.body
                != self.output_view_key_authorization_body(index)?
            {
                return Err(PrivateSettlementValidationError::InvalidAuditPlaintext);
            }
            output.note.validate()?;
        }
        Ok(())
    }

    /// Validate private business material against the exact public manifest leg.
    ///
    /// # Errors
    ///
    /// Returns a redacted binding error for any mismatch.
    pub fn validate_against_manifest(
        &self,
        manifest: &AtomicPrivateSettlementV1,
    ) -> Result<(), PrivateSettlementValidationError> {
        manifest.validate()?;
        self.validate_against_proof_intent(&manifest.proof_intent())
    }

    /// Validate original private terms against the distinct pre-proof public intent.
    ///
    /// This checks intent and authorization shape, not proof or final artifact availability.
    /// # Errors
    /// Rejects malformed private terms and any cross-intent, fee, asset or reimbursement join.
    pub fn validate_against_proof_intent(
        &self,
        manifest: &PrivateSettlementProofIntentV1,
    ) -> Result<(), PrivateSettlementValidationError> {
        self.validate()?;
        manifest.validate()?;
        let leg = manifest
            .legs
            .get(usize::from(self.leg_ordinal))
            .ok_or(PrivateSettlementValidationError::UnknownLeg)?;
        let asset_binding = self
            .asset_binding_commitment()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if self.network_id != manifest.network_id
            || self.bundle_id != manifest.bundle_id
            || self.route != leg.route
            || self.pool_id != leg.pool_id
            || self.sponsor != manifest.sponsor
            || asset_binding != leg.asset_binding_commitment
            || self.fee_intent_digest != manifest.fee_intent_digest
            || self.settlement_expiry_height != manifest.expiry_height
            || (self.leg_ordinal == manifest.reimbursement_leg_ordinal)
                != (self.sponsor_reimbursement_amount != 0)
        {
            return Err(PrivateSettlementValidationError::AuditPlaintextBindingMismatch);
        }
        if self.leg_ordinal == manifest.reimbursement_leg_ordinal {
            let reimbursement_terms = self
                .reimbursement_terms_commitment()
                .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
            if reimbursement_terms != manifest.reimbursement_terms_commitment {
                return Err(PrivateSettlementValidationError::ReimbursementTermsMismatch);
            }
        }
        Ok(())
    }
}

/// Public authenticated-data fields for an encrypted audit capsule.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditAadV1")]
pub struct PrivateSettlementAuditAadV1 {
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact route and incarnation.
    pub route: PrivateSettlementRouteV1,
    /// Digest of the exact four-validator committee roster and proofs of possession.
    pub authority_digest: Hash,
    /// Global/catalog height at which the exact committee authority is resolved.
    pub authority_context_height: u64,
    /// Digest of the governed policy.
    pub audit_policy_digest: Hash,
    /// Exact auditor key epoch.
    pub audit_key_epoch: u64,
    /// Commitment to the unpadded audit-capsule plaintext.
    pub plaintext_commitment: Hash,
}

/// Hybrid X25519 plus ML-KEM-768 public encryption key.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementHybridPublicKeyV1"
)]
pub struct PrivateSettlementHybridPublicKeyV1 {
    /// X25519 public component.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub x25519: [u8; 32],
    /// Canonical ML-KEM-768 public key bytes.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub ml_kem_768: Vec<u8>,
}

impl PrivateSettlementHybridPublicKeyV1 {
    /// Construct the wire key from a validated hybrid public key.
    #[must_use]
    pub fn from_hybrid(key: &HybridPublicKey) -> Self {
        Self {
            x25519: key.x25519_bytes(),
            ml_kem_768: key.kyber_bytes().to_vec(),
        }
    }

    /// Parse and validate both public-key components.
    ///
    /// # Errors
    ///
    /// Returns a structural validation error for an invalid hybrid key.
    pub fn to_hybrid(&self) -> Result<HybridPublicKey, PrivateSettlementValidationError> {
        if self.ml_kem_768.len() != PRIVATE_SETTLEMENT_ML_KEM_768_PUBLIC_KEY_BYTES_V1 {
            return Err(PrivateSettlementValidationError::InvalidHybridPublicKey);
        }
        HybridPublicKey::from_bytes(self.x25519, &self.ml_kem_768)
            .map_err(|_| PrivateSettlementValidationError::InvalidHybridPublicKey)
    }

    /// Domain-separated digest used to detect duplicate encryption keys.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the key cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(AUDITOR_KEY_DIGEST_DOMAIN_V1, self)
    }
}

/// One auditor authorized by a dataspace-local policy.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditorV1")]
pub struct PrivateSettlementAuditorV1 {
    /// Stable auditor account identity.
    pub auditor_id: AccountId,
    /// Purpose-specific approval signing key.
    pub signing_key: PublicKey,
    /// Purpose-specific capsule encryption key.
    pub encryption_key: PrivateSettlementHybridPublicKeyV1,
}

impl fmt::Debug for PrivateSettlementAuditorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditorV1(<restricted>)")
    }
}

/// Self-authenticating body of one governed local auditor policy.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditPolicyBodyV1"
)]
pub struct PrivateSettlementAuditPolicyBodyV1 {
    /// Policy wire version.
    pub version: u8,
    /// Dataspace governed by this policy.
    pub dataspace_id: DataSpaceId,
    /// Stable policy lineage identifier.
    pub policy_id: Hash,
    /// Monotonic non-zero policy revision.
    pub revision: u64,
    /// Monotonic non-zero encryption/signing key epoch.
    pub key_epoch: u64,
    /// First global height at which approvals are valid.
    pub activation_height: u64,
    /// Optional first height at which approvals are no longer valid.
    #[norito(required)]
    pub retirement_height: Option<u64>,
    /// Required distinct approval count; defaults operationally to one.
    pub min_approvals: u8,
    /// Strictly ordered authorized auditors.
    pub auditors: Vec<PrivateSettlementAuditorV1>,
}

impl fmt::Debug for PrivateSettlementAuditPolicyBodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditPolicyBodyV1(<restricted>)")
    }
}

impl PrivateSettlementAuditPolicyBodyV1 {
    /// Recompute the domain-separated digest of this exact policy body.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when the canonical policy body cannot be encoded.
    pub fn computed_policy_digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(AUDIT_POLICY_DIGEST_DOMAIN_V1, self)
    }
}

/// Governed auditor policy with a domain-separated self-digest.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditPolicyV1"
)]
pub struct PrivateSettlementAuditPolicyV1 {
    /// Exact policy body.
    pub body: PrivateSettlementAuditPolicyBodyV1,
    /// Domain-separated canonical body digest.
    pub policy_digest: Hash,
}

impl fmt::Debug for PrivateSettlementAuditPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditPolicyV1(<restricted>)")
    }
}

impl PrivateSettlementAuditPolicyV1 {
    /// Construct a self-authenticating policy.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for malformed policy material.
    pub fn new(
        body: PrivateSettlementAuditPolicyBodyV1,
    ) -> Result<Self, PrivateSettlementValidationError> {
        let policy_digest = body
            .computed_policy_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let policy = Self {
            body,
            policy_digest,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate policy lifecycle, threshold, canonical auditors, keys, and self-digest.
    ///
    /// # Errors
    ///
    /// Returns a typed fail-closed policy error.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        let body = &self.body;
        if body.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: body.version,
            });
        }
        if hash_is_zero(&body.policy_id)
            || body.revision == 0
            || body.key_epoch == 0
            || body.activation_height == 0
            || body
                .retirement_height
                .is_some_and(|height| height <= body.activation_height)
        {
            return Err(PrivateSettlementValidationError::InvalidAuditPolicyLifecycle);
        }
        if body.auditors.is_empty()
            || body.auditors.len() > PRIVATE_SETTLEMENT_MAX_AUDITORS_V1
            || body.min_approvals == 0
            || usize::from(body.min_approvals) > body.auditors.len()
        {
            return Err(PrivateSettlementValidationError::InvalidAuditThreshold);
        }
        let mut previous = None;
        let mut signing_keys = BTreeSet::new();
        let mut encryption_keys = BTreeSet::new();
        for auditor in &body.auditors {
            if previous
                .as_ref()
                .is_some_and(|value| value >= &auditor.auditor_id)
            {
                return Err(PrivateSettlementValidationError::NonCanonicalAuditorOrder);
            }
            previous = Some(auditor.auditor_id.clone());
            auditor.encryption_key.to_hybrid()?;
            let encryption_digest = auditor
                .encryption_key
                .digest()
                .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
            if !signing_keys.insert(auditor.signing_key.clone())
                || !encryption_keys.insert(encryption_digest)
            {
                return Err(PrivateSettlementValidationError::DuplicateAuditorKey);
            }
        }
        let expected = body
            .computed_policy_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if expected != self.policy_digest {
            return Err(PrivateSettlementValidationError::AuditPolicyDigestMismatch);
        }
        Ok(())
    }

    /// Return whether the policy is active at a global block height.
    #[must_use]
    pub fn is_active_at(&self, height: u64) -> bool {
        height >= self.body.activation_height
            && self
                .body
                .retirement_height
                .is_none_or(|retirement| height < retirement)
    }

    /// Recompute the domain-separated digest of this policy's exact body.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when the canonical policy body cannot be encoded.
    pub fn computed_policy_digest(&self) -> Result<Hash, norito::Error> {
        self.body.computed_policy_digest()
    }
}

/// Canonical activation interval and revision of one restricted pool mapping.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPoolGovernanceLifecycleV1"
)]
pub struct PrivateSettlementPoolGovernanceLifecycleV1 {
    /// Monotonic non-zero revision within this opaque pool's governance lineage.
    pub governance_revision: u64,
    /// First global height at which this exact mapping may be used.
    pub activation_height: u64,
    /// Optional first global height at which this exact mapping is retired.
    #[norito(required)]
    pub retirement_height: Option<u64>,
}

impl PrivateSettlementPoolGovernanceLifecycleV1 {
    fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.governance_revision == 0
            || self.activation_height == 0
            || self
                .retirement_height
                .is_some_and(|retirement| retirement <= self.activation_height)
        {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceLifecycle);
        }
        Ok(())
    }

    /// Return whether the exact governance revision is active at `height`.
    #[must_use]
    pub fn is_active_at(self, height: u64) -> bool {
        height >= self.activation_height
            && self
                .retirement_height
                .is_none_or(|retirement| height < retirement)
    }
}

/// Restricted body mapping one opaque settlement pool to one exact asset.
///
/// This body contains the literal asset identifier and its random commitment
/// opening. It belongs only in access-controlled governance state and auditor
/// capsules; public manifests and receipts carry only `pool_id`,
/// `asset_binding_commitment`, and `audit_policy_digest`.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPoolGovernanceBodyV1"
)]
pub struct PrivateSettlementPoolGovernanceBodyV1 {
    /// Wire version; must be [`ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1`].
    pub version: u8,
    /// Exact dataspace, lane, and active incarnation hosting this pool.
    pub route: PrivateSettlementRouteV1,
    /// Singular opaque private-note pool identifier.
    pub pool_id: PrivacyPoolIdV1,
    /// Exact restricted asset definition mapped to `pool_id`.
    pub asset_definition_id: AssetDefinitionId,
    /// Random non-zero opening salt for `asset_binding_commitment`.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub asset_binding_salt: [u8; 32],
    /// Domain-separated commitment to the complete route, pool, asset, and salt.
    pub asset_binding_commitment: Hash,
    /// Digest of the exact governed local audit policy.
    pub audit_policy_digest: Hash,
    /// Exact non-zero signing/encryption epoch of that audit policy.
    pub audit_key_epoch: u64,
    /// Activation interval and monotonic revision of this mapping.
    pub lifecycle: PrivateSettlementPoolGovernanceLifecycleV1,
}

impl fmt::Debug for PrivateSettlementPoolGovernanceBodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementPoolGovernanceBodyV1(<restricted>)")
    }
}

impl PrivateSettlementPoolGovernanceBodyV1 {
    /// Wipe the literal asset identifier and random commitment opening before discard.
    ///
    /// Public route, pool, commitment, policy, and lifecycle bindings remain
    /// intact. The body intentionally becomes invalid and must not be used after
    /// this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        zeroize_value_for_confidential_discard(&mut self.asset_definition_id.aid_bytes);
        zeroize_value_for_confidential_discard(&mut self.asset_binding_salt);
    }

    /// Construct a restricted mapping while deriving its asset and policy commitments.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the route, policy, lifecycle, pool, or salt is invalid.
    pub fn new(
        route: PrivateSettlementRouteV1,
        pool_id: PrivacyPoolIdV1,
        asset_definition_id: AssetDefinitionId,
        asset_binding_salt: [u8; 32],
        policy: &PrivateSettlementAuditPolicyV1,
        lifecycle: PrivateSettlementPoolGovernanceLifecycleV1,
    ) -> Result<Self, PrivateSettlementValidationError> {
        policy.validate()?;
        let asset_binding_commitment = private_settlement_asset_binding_commitment_v1(
            route,
            pool_id,
            &asset_definition_id,
            asset_binding_salt,
        )
        .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let audit_policy_digest = policy
            .computed_policy_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let body = Self {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            route,
            pool_id,
            asset_definition_id,
            asset_binding_salt,
            asset_binding_commitment,
            audit_policy_digest,
            audit_key_epoch: policy.body.key_epoch,
            lifecycle,
        };
        body.validate()?;
        if body.route.dataspace_id != policy.body.dataspace_id {
            return Err(PrivateSettlementValidationError::PoolGovernancePolicyMismatch);
        }
        Ok(body)
    }

    /// Recompute the domain-separated asset-binding commitment from its opening.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when the exact opening cannot be canonically encoded.
    pub fn computed_asset_binding_commitment(&self) -> Result<Hash, norito::Error> {
        private_settlement_asset_binding_commitment_v1(
            self.route,
            self.pool_id,
            &self.asset_definition_id,
            self.asset_binding_salt,
        )
    }

    fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.route.dataspace_id == DataSpaceId::UNIVERSAL
            || hash_is_zero(&self.route.lane_incarnation)
        {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceRoute);
        }
        self.lifecycle.validate()?;
        if self.pool_id.is_zero()
            || self.asset_binding_salt.iter().all(|byte| *byte == 0)
            || hash_is_zero(&self.asset_binding_commitment)
            || hash_is_zero(&self.audit_policy_digest)
            || self.audit_key_epoch == 0
        {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceBinding);
        }
        let expected = self
            .computed_asset_binding_commitment()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if expected != self.asset_binding_commitment {
            return Err(PrivateSettlementValidationError::PoolGovernanceAssetBindingMismatch);
        }
        Ok(())
    }
}

impl Drop for PrivateSettlementPoolGovernanceBodyV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// Self-authenticating restricted governance record for one confidential pool.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPoolGovernanceV1"
)]
pub struct PrivateSettlementPoolGovernanceV1 {
    /// Exact restricted pool mapping and lifecycle.
    pub body: PrivateSettlementPoolGovernanceBodyV1,
    /// Domain-separated canonical self-digest of `body`.
    pub governance_digest: Hash,
}

impl fmt::Debug for PrivateSettlementPoolGovernanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementPoolGovernanceV1(<restricted>)")
    }
}

impl PrivateSettlementPoolGovernanceV1 {
    /// Wipe the restricted pool-to-asset opening before discard.
    ///
    /// The public governance digest remains intact. The record intentionally
    /// becomes invalid and must not be used after this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.body.zeroize_for_confidential_discard();
    }

    /// Construct a self-authenticating restricted governance record.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the body or its canonical encoding is invalid.
    pub fn new(
        body: PrivateSettlementPoolGovernanceBodyV1,
    ) -> Result<Self, PrivateSettlementValidationError> {
        let governance_digest = canonical_hash(POOL_GOVERNANCE_DIGEST_DOMAIN_V1, &body)
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let record = Self {
            body,
            governance_digest,
        };
        record.validate()?;
        Ok(record)
    }

    /// Construct a self-authenticating record from one exact restricted mapping.
    ///
    /// # Errors
    ///
    /// Returns a typed error when any binding, policy, or lifecycle field is invalid.
    pub fn from_restricted_mapping(
        route: PrivateSettlementRouteV1,
        pool_id: PrivacyPoolIdV1,
        asset_definition_id: AssetDefinitionId,
        asset_binding_salt: [u8; 32],
        policy: &PrivateSettlementAuditPolicyV1,
        lifecycle: PrivateSettlementPoolGovernanceLifecycleV1,
    ) -> Result<Self, PrivateSettlementValidationError> {
        let activation_height = lifecycle.activation_height;
        let record = Self::new(PrivateSettlementPoolGovernanceBodyV1::new(
            route,
            pool_id,
            asset_definition_id,
            asset_binding_salt,
            policy,
            lifecycle,
        )?)?;
        record.validate_against_policy_at(policy, activation_height)?;
        Ok(record)
    }

    /// Recompute this record's domain-separated canonical self-digest.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when the exact body cannot be canonically encoded.
    pub fn computed_governance_digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(POOL_GOVERNANCE_DIGEST_DOMAIN_V1, &self.body)
    }

    /// Validate all structural bindings and the canonical self-digest.
    ///
    /// # Errors
    ///
    /// Returns a typed fail-closed governance validation error.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        self.body.validate()?;
        let expected = self
            .computed_governance_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if hash_is_zero(&self.governance_digest) || expected != self.governance_digest {
            return Err(PrivateSettlementValidationError::PoolGovernanceDigestMismatch);
        }
        Ok(())
    }

    /// Verify an exact restricted route, pool, asset, and salt opening.
    ///
    /// The error deliberately does not reveal which restricted component was
    /// wrong so callers can keep denial responses uniform.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch when any opening component differs.
    pub fn validate_asset_opening(
        &self,
        route: PrivateSettlementRouteV1,
        pool_id: PrivacyPoolIdV1,
        asset_definition_id: &AssetDefinitionId,
        asset_binding_salt: [u8; 32],
    ) -> Result<(), PrivateSettlementValidationError> {
        self.validate()?;
        if self.body.route != route
            || self.body.pool_id != pool_id
            || &self.body.asset_definition_id != asset_definition_id
            || self.body.asset_binding_salt != asset_binding_salt
        {
            return Err(PrivateSettlementValidationError::PoolGovernanceAssetBindingMismatch);
        }
        let expected = private_settlement_asset_binding_commitment_v1(
            route,
            pool_id,
            asset_definition_id,
            asset_binding_salt,
        )
        .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if expected != self.body.asset_binding_commitment {
            return Err(PrivateSettlementValidationError::PoolGovernanceAssetBindingMismatch);
        }
        Ok(())
    }

    /// Validate the exact audit policy, key epoch, lifecycle coverage, and height.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch for the wrong policy or epoch, an invalid
    /// lifecycle error when the mapping outlives its policy, or a stale error
    /// when either record is inactive at `height`.
    pub fn validate_against_policy_at(
        &self,
        policy: &PrivateSettlementAuditPolicyV1,
        height: u64,
    ) -> Result<(), PrivateSettlementValidationError> {
        self.validate()?;
        policy.validate()?;
        let expected_policy_digest = policy
            .computed_policy_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if self.body.route.dataspace_id != policy.body.dataspace_id
            || self.body.audit_policy_digest != expected_policy_digest
            || self.body.audit_policy_digest != policy.policy_digest
            || self.body.audit_key_epoch != policy.body.key_epoch
        {
            return Err(PrivateSettlementValidationError::PoolGovernancePolicyMismatch);
        }
        if self.body.lifecycle.activation_height < policy.body.activation_height
            || policy
                .body
                .retirement_height
                .is_some_and(|policy_retirement| {
                    self.body
                        .lifecycle
                        .retirement_height
                        .is_none_or(|retirement| retirement > policy_retirement)
                })
        {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceLifecycle);
        }
        if !self.body.lifecycle.is_active_at(height) || !policy.is_active_at(height) {
            return Err(PrivateSettlementValidationError::StalePoolGovernance);
        }
        Ok(())
    }

    /// Return whether this exact mapping revision is active at `height`.
    #[must_use]
    pub fn is_active_at(&self, height: u64) -> bool {
        self.body.lifecycle.is_active_at(height)
    }
}

impl Drop for PrivateSettlementPoolGovernanceV1 {
    fn drop(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}

/// One hybrid KEM-wrapped data-encryption key addressed to an auditor.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementWrappedDekV1"
)]
pub struct PrivateSettlementWrappedDekV1 {
    /// Auditor that may unwrap this DEK.
    pub auditor_id: AccountId,
    /// Sender's ephemeral X25519 public component.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub ephemeral_x25519: [u8; 32],
    /// ML-KEM-768 encapsulation ciphertext.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub ml_kem_ciphertext: Vec<u8>,
    /// XChaCha20-Poly1305 nonce used to wrap the DEK.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub nonce: [u8; PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1],
    /// Encrypted 32-byte DEK and authentication tag.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub wrapped_dek: Vec<u8>,
}

impl fmt::Debug for PrivateSettlementWrappedDekV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementWrappedDekV1(<redacted>)")
    }
}

/// Padded encrypted auditor capsule and independently wrapped DEKs.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditCapsuleV1"
)]
pub struct PrivateSettlementAuditCapsuleV1 {
    /// Capsule wire version.
    pub version: u8,
    /// Exact public authenticated data.
    pub aad: PrivateSettlementAuditAadV1,
    /// Fixed padding class.
    pub padding: PrivateSettlementCapsulePaddingV1,
    /// XChaCha20-Poly1305 nonce used for the capsule payload.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub nonce: [u8; PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1],
    /// Padded encrypted capsule and authentication tag.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub ciphertext: Vec<u8>,
    /// Strictly ordered independently wrapped DEKs.
    pub wrapped_deks: Vec<PrivateSettlementWrappedDekV1>,
}

impl fmt::Debug for PrivateSettlementAuditCapsuleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditCapsuleV1(<redacted>)")
    }
}

impl PrivateSettlementAuditCapsuleV1 {
    /// Compute the digest bound by the proof statement and auditor approval.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the capsule cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(CAPSULE_DIGEST_DOMAIN_V1, self)
    }

    /// Validate padding, authenticated-data fields, and recipient wrapping shape.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a malformed or policy-inconsistent capsule.
    pub fn validate_against(
        &self,
        policy: &PrivateSettlementAuditPolicyV1,
    ) -> Result<(), PrivateSettlementValidationError> {
        policy.validate()?;
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.aad.route.dataspace_id != policy.body.dataspace_id
            || self.aad.audit_policy_digest != policy.policy_digest
            || self.aad.audit_key_epoch != policy.body.key_epoch
            || self.aad.network_id.as_bytes().iter().all(|byte| *byte == 0)
            || hash_is_zero(&self.aad.bundle_id)
            || hash_is_zero(&self.aad.route.lane_incarnation)
            || hash_is_zero(&self.aad.authority_digest)
            || self.aad.authority_context_height == 0
            || hash_is_zero(&self.aad.plaintext_commitment)
        {
            return Err(PrivateSettlementValidationError::AuditCapsuleBindingMismatch);
        }
        if self.nonce.iter().all(|byte| *byte == 0)
            || self.ciphertext.len() != self.padding.ciphertext_bytes()
            || self.ciphertext.iter().all(|byte| *byte == 0)
        {
            return Err(PrivateSettlementValidationError::InvalidAuditCapsuleCiphertext);
        }
        if self.wrapped_deks.len() != policy.body.auditors.len() {
            return Err(PrivateSettlementValidationError::AuditCapsuleRecipientMismatch);
        }
        for (wrapped, auditor) in self.wrapped_deks.iter().zip(&policy.body.auditors) {
            if wrapped.auditor_id != auditor.auditor_id
                || wrapped.ephemeral_x25519.iter().all(|byte| *byte == 0)
                || wrapped.ml_kem_ciphertext.len()
                    != PRIVATE_SETTLEMENT_ML_KEM_768_CIPHERTEXT_BYTES_V1
                || wrapped.ml_kem_ciphertext.iter().all(|byte| *byte == 0)
                || wrapped.nonce.iter().all(|byte| *byte == 0)
                || wrapped.wrapped_dek.len() != PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1
                || wrapped.wrapped_dek.iter().all(|byte| *byte == 0)
            {
                return Err(PrivateSettlementValidationError::InvalidWrappedDek);
            }
        }
        Ok(())
    }
}

/// Exact restricted-DA statement certified by one participant committee.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementSidecarAvailabilityBodyV1"
)]
pub struct PrivateSettlementSidecarAvailabilityBodyV1 {
    /// Certificate body wire version.
    pub version: u8,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable bundle identifier.
    pub bundle_id: Hash,
    /// Canonical participant-leg ordinal.
    pub leg_ordinal: u8,
    /// Exact participant route and lane incarnation.
    pub route: PrivateSettlementRouteV1,
    /// Digest of the exact four-validator committee authority.
    pub authority_digest: Hash,
    /// Global/catalog height used to resolve the committee.
    pub authority_context_height: u64,
    /// Digest of the complete sidecar material excluding this ticket.
    pub payload_digest: Hash,
    /// Canonical byte length of sidecar material excluding this certificate.
    pub payload_bytes: u32,
    /// Height through which restricted DA must retain the sidecar.
    pub retention_until_height: u64,
}

impl PrivateSettlementSidecarAvailabilityBodyV1 {
    /// Canonical purpose-separated bytes signed by each availability validator.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the body cannot be canonically encoded.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, norito::Error> {
        private_settlement_signature_preimage(
            SIDECAR_AVAILABILITY_SIGNATURE_DOMAIN_V1,
            self,
            "availability certificate body is too large",
        )
    }

    /// Validate the immutable availability statement before any signature work.
    ///
    /// # Errors
    ///
    /// Returns a typed error for reserved fields or invalid height bounds.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.network_id.as_bytes().iter().all(|byte| *byte == 0)
            || hash_is_zero(&self.bundle_id)
            || hash_is_zero(&self.route.lane_incarnation)
            || hash_is_zero(&self.authority_digest)
            || hash_is_zero(&self.payload_digest)
            || self.authority_context_height == 0
            || self.payload_bytes == 0
            || self.retention_until_height <= self.authority_context_height
        {
            return Err(PrivateSettlementValidationError::InvalidAvailabilityCertificate);
        }
        Ok(())
    }
}

/// One independently authenticated availability share from a committee validator.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAvailabilityShareV1"
)]
pub struct PrivateSettlementAvailabilityShareV1 {
    /// Share wire version.
    pub version: u8,
    /// Exact immutable body signed by the validator.
    pub body: PrivateSettlementSidecarAvailabilityBodyV1,
    /// Exact committee identity that produced the share.
    pub signer: PeerId,
    /// Compressed BLS-normal signature over [`Self::body`].
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub signature: Vec<u8>,
}

impl PrivateSettlementAvailabilityShareV1 {
    /// Validate fixed wire shape before committee membership and cryptography.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a malformed share.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        self.body.validate_shape()?;
        if self.signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1 {
            return Err(PrivateSettlementValidationError::InvalidAvailabilityShare);
        }
        Ok(())
    }
}

/// Signed restricted-DA availability certificate carried with one leg.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementSidecarAvailabilityV1"
)]
pub struct PrivateSettlementSidecarAvailabilityV1 {
    /// Exact same-message body certified by the committee.
    pub body: PrivateSettlementSidecarAvailabilityBodyV1,
    /// Exact three-of-four LSB-first signer bitmap.
    pub signers_bitmap: u8,
    /// Compressed aggregate BLS-normal signature over the canonical body.
    pub aggregate_signature: Vec<u8>,
}

impl PrivateSettlementSidecarAvailabilityV1 {
    /// Compute the manifest-committed certificate digest.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the certificate cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(
            b"iroha:nexus:private-settlement:availability-certificate:v1\0",
            self,
        )
    }

    /// Canonical same-message bytes signed by the availability quorum.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the body cannot be encoded.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, norito::Error> {
        self.body.signature_preimage()
    }

    /// Validate certificate cardinality and fixed wire shape before cryptography.
    ///
    /// # Errors
    ///
    /// Returns a typed structural error for malformed or zero fields.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        self.body.validate_shape()?;
        if self.signers_bitmap & !0x0f != 0
            || self.signers_bitmap.count_ones() != u32::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1)
            || self.aggregate_signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1
        {
            return Err(PrivateSettlementValidationError::InvalidAvailabilityCertificate);
        }
        Ok(())
    }
}

/// Exact restricted auditor view committed by a node response attestation.
///
/// This material is not a second HTTP shape. It is the canonical, typed input
/// to [`Self::digest`], so implementations cannot silently omit a response
/// field when authenticating an auditor view.
#[derive(Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditorViewDigestMaterialV1"
)]
pub struct PrivateSettlementAuditorViewDigestMaterialV1 {
    /// Digest-material wire version.
    pub version: u8,
    /// Node-authoritative height used for access and policy evaluation.
    pub authoritative_height: u64,
    /// Exact public bundle manifest.
    pub manifest: AtomicPrivateSettlementV1,
    /// Exact historical governed policy bound by the encrypted sidecar.
    pub audit_policy: PrivateSettlementAuditPolicyV1,
    /// Exact current policy used to authorize restricted access.
    ///
    /// This can equal `audit_policy` or be a later policy in the same governed
    /// lineage when retained historical capsule material is read after key
    /// rotation.
    pub access_audit_policy: PrivateSettlementAuditPolicyV1,
    /// Exact four-validator participant authority.
    pub committee_authority: PrivateSettlementCommitteeAuthorityV1,
    /// Restricted proof statement; proof bytes remain absent.
    pub statement: PrivateSettlementProofStatementV1,
    /// Opaque fixed-shape private-state transition.
    pub delta: PrivateSettlementDeltaV1,
    /// Padded hybrid-encrypted auditor capsule.
    pub audit_capsule: PrivateSettlementAuditCapsuleV1,
    /// Durable restricted-DA certificate.
    pub availability: PrivateSettlementSidecarAvailabilityV1,
    /// Explicit stable code for the durable lifecycle projected by Torii.
    pub lifecycle_code: u8,
}

impl fmt::Debug for PrivateSettlementAuditorViewDigestMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementAuditorViewDigestMaterialV1")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("leg_ordinal", &self.statement.leg_ordinal)
            .field("route", &self.statement.route)
            .field("authoritative_height", &self.authoritative_height)
            .field("lifecycle_code", &self.lifecycle_code)
            .finish_non_exhaustive()
    }
}

impl PrivateSettlementAuditorViewDigestMaterialV1 {
    /// Compute the purpose-separated digest of the complete restricted view.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the exact typed view cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(AUDITOR_VIEW_DIGEST_DOMAIN_V1, self)
    }
}

/// Exact node-authenticated statement over one restricted auditor view.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditorViewAttestationBodyV1"
)]
pub struct PrivateSettlementAuditorViewAttestationBodyV1 {
    /// Attestation wire version.
    pub version: u8,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Content address of the exact encrypted participant leg.
    pub payload_digest: Hash,
    /// Digest of every unsigned auditor-response field.
    pub view_digest: Hash,
    /// Digest of the exact four-validator authority.
    pub authority_digest: Hash,
    /// Stable code for the exact lifecycle included in the view digest.
    pub lifecycle_code: u8,
    /// Exact height included in the view digest.
    pub authoritative_height: u64,
    /// Committee validator that served and authenticated the view.
    pub responder: PeerId,
}

impl PrivateSettlementAuditorViewAttestationBodyV1 {
    /// Canonical purpose-separated bytes signed by the responding validator.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the body cannot be canonically encoded.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, norito::Error> {
        private_settlement_signature_preimage(
            AUDITOR_VIEW_ATTESTATION_SIGNATURE_DOMAIN_V1,
            self,
            "auditor view attestation body is too large",
        )
    }

    /// Validate fixed attestation fields before authority and signature work.
    ///
    /// # Errors
    ///
    /// Returns a typed error for reserved values or an unknown lifecycle code.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.network_id.as_bytes().iter().all(|byte| *byte == 0)
            || hash_is_zero(&self.payload_digest)
            || hash_is_zero(&self.view_digest)
            || hash_is_zero(&self.authority_digest)
            || self.authoritative_height == 0
            || self.lifecycle_code > PRIVATE_SETTLEMENT_LIFECYCLE_EXPIRED_V1
        {
            return Err(PrivateSettlementValidationError::InvalidAuditorViewAttestation);
        }
        Ok(())
    }
}

/// One committee validator's BLS authentication of an auditor capsule view.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditorViewAttestationV1"
)]
pub struct PrivateSettlementAuditorViewAttestationV1 {
    /// Exact purpose-separated body signed by the responder.
    pub body: PrivateSettlementAuditorViewAttestationBodyV1,
    /// Compressed BLS-normal signature over [`Self::body`].
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub signature: Vec<u8>,
}

impl PrivateSettlementAuditorViewAttestationV1 {
    /// Validate fixed wire shape before roster and cryptographic verification.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed body or signature bytes.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        self.body.validate_shape()?;
        if self.signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1 {
            return Err(PrivateSettlementValidationError::InvalidAuditorViewAttestation);
        }
        Ok(())
    }
}

/// Exact approval-acknowledgement view committed by a node attestation.
#[derive(Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditApprovalAcknowledgementDigestMaterialV1"
)]
pub struct PrivateSettlementAuditApprovalAcknowledgementDigestMaterialV1 {
    /// Digest-material wire version.
    pub version: u8,
    /// Node-authoritative height at which the approval became durable.
    pub authoritative_height: u64,
    /// Public bundle identifier.
    pub bundle_id: Hash,
    /// Content address of the encrypted leg.
    pub payload_digest: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact four-validator participant authority returned by the node.
    pub committee_authority: PrivateSettlementCommitteeAuthorityV1,
    /// Number of distinct governed approvals now durable.
    pub collected: u8,
    /// Governed approval threshold.
    pub required: u8,
    /// Whether this request inserted new durable approval material.
    pub newly_recorded: bool,
    /// Stable code for the exact durable lifecycle returned by the node.
    pub lifecycle_code: u8,
}

impl fmt::Debug for PrivateSettlementAuditApprovalAcknowledgementDigestMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementAuditApprovalAcknowledgementDigestMaterialV1")
            .field("bundle_id", &self.bundle_id)
            .field("payload_digest", &self.payload_digest)
            .field("leg_ordinal", &self.leg_ordinal)
            .field("authoritative_height", &self.authoritative_height)
            .field("collected", &self.collected)
            .field("required", &self.required)
            .field("newly_recorded", &self.newly_recorded)
            .field("lifecycle_code", &self.lifecycle_code)
            .finish_non_exhaustive()
    }
}

impl PrivateSettlementAuditApprovalAcknowledgementDigestMaterialV1 {
    /// Compute the purpose-separated digest of the complete acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the exact typed view cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(AUDIT_APPROVAL_ACKNOWLEDGEMENT_DIGEST_DOMAIN_V1, self)
    }
}

/// Exact node-authenticated statement over one durable approval acknowledgement.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditApprovalAcknowledgementAttestationBodyV1"
)]
pub struct PrivateSettlementAuditApprovalAcknowledgementAttestationBodyV1 {
    /// Attestation wire version.
    pub version: u8,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Content address of the exact encrypted participant leg.
    pub payload_digest: Hash,
    /// Digest of the exact signed auditor approval request.
    pub approval_digest: Hash,
    /// Digest of every unsigned acknowledgement-response field.
    pub acknowledgement_digest: Hash,
    /// Digest of the exact four-validator authority.
    pub authority_digest: Hash,
    /// Stable code for the exact lifecycle included in the acknowledgement.
    pub lifecycle_code: u8,
    /// Exact height included in the acknowledgement.
    pub authoritative_height: u64,
    /// Committee validator that persisted and authenticated the approval.
    pub responder: PeerId,
}

impl PrivateSettlementAuditApprovalAcknowledgementAttestationBodyV1 {
    /// Canonical purpose-separated bytes signed by the responding validator.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the body cannot be canonically encoded.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, norito::Error> {
        private_settlement_signature_preimage(
            AUDIT_APPROVAL_ACKNOWLEDGEMENT_ATTESTATION_SIGNATURE_DOMAIN_V1,
            self,
            "audit approval acknowledgement attestation body is too large",
        )
    }

    /// Validate fixed fields before authority and signature verification.
    ///
    /// # Errors
    ///
    /// Returns a typed error for reserved values or an invalid lifecycle.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.network_id.as_bytes().iter().all(|byte| *byte == 0)
            || hash_is_zero(&self.payload_digest)
            || hash_is_zero(&self.approval_digest)
            || hash_is_zero(&self.acknowledgement_digest)
            || hash_is_zero(&self.authority_digest)
            || self.authoritative_height == 0
            || self.lifecycle_code > PRIVATE_SETTLEMENT_LIFECYCLE_AUDITED_V1
        {
            return Err(
                PrivateSettlementValidationError::InvalidAuditApprovalAcknowledgementAttestation,
            );
        }
        Ok(())
    }
}

/// One committee validator's BLS authentication of an approval acknowledgement.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditApprovalAcknowledgementAttestationV1"
)]
pub struct PrivateSettlementAuditApprovalAcknowledgementAttestationV1 {
    /// Exact purpose-separated body signed by the responder.
    pub body: PrivateSettlementAuditApprovalAcknowledgementAttestationBodyV1,
    /// Compressed BLS-normal signature over [`Self::body`].
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub signature: Vec<u8>,
}

impl PrivateSettlementAuditApprovalAcknowledgementAttestationV1 {
    /// Validate fixed wire shape before roster and cryptographic verification.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed body or signature bytes.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        self.body.validate_shape()?;
        if self.signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1 {
            return Err(
                PrivateSettlementValidationError::InvalidAuditApprovalAcknowledgementAttestation,
            );
        }
        Ok(())
    }
}

/// Complete restricted sidecar verified by one participant committee.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementLegPayloadV1"
)]
pub struct PrivateSettlementLegPayloadV1 {
    /// Restricted proof statement.
    pub statement: PrivateSettlementProofStatementV1,
    /// Native proof bytes.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub proof: Vec<u8>,
    /// Fixed-shape state delta.
    pub delta: PrivateSettlementDeltaV1,
    /// Padded auditor-only capsule.
    pub audit_capsule: PrivateSettlementAuditCapsuleV1,
    /// Restricted-DA availability metadata.
    pub availability: PrivateSettlementSidecarAvailabilityV1,
}

impl fmt::Debug for PrivateSettlementLegPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementLegPayloadV1")
            .field("bundle_id", &self.statement.bundle_id)
            .field("leg_ordinal", &self.statement.leg_ordinal)
            .field("route", &self.statement.route)
            .finish_non_exhaustive()
    }
}

impl PrivateSettlementLegPayloadV1 {
    /// Compute the proof-byte digest committed by the delta.
    #[must_use]
    pub fn proof_digest(&self) -> Hash {
        private_settlement_proof_digest_v1(&self.proof)
    }

    fn sidecar_material_digest(&self) -> Result<Hash, norito::Error> {
        private_settlement_sidecar_material_digest_v1(
            &self.statement,
            &self.proof,
            &self.delta,
            &self.audit_capsule,
        )
    }

    /// Compute the sidecar digest committed by the public manifest.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if sidecar material cannot be encoded.
    pub fn payload_digest(&self) -> Result<Hash, norito::Error> {
        self.sidecar_material_digest()
    }

    /// Return the canonical byte length of the complete sidecar, including its ticket.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the sidecar cannot be encoded.
    pub fn canonical_bytes_len(&self) -> Result<usize, norito::Error> {
        norito::encode_canonical(self).map(|encoded| encoded.len())
    }

    /// Return the canonical sidecar-material byte length excluding its certificate.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error when material cannot be encoded.
    pub fn sidecar_material_bytes_len(&self) -> Result<usize, norito::Error> {
        private_settlement_sidecar_material_bytes_len_v1(
            &self.statement,
            &self.proof,
            &self.delta,
            &self.audit_capsule,
        )
    }

    /// Validate all cross-object bindings before proof verification or staging.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed, substituted, stale, or unavailable material.
    pub fn validate_against(
        &self,
        manifest: &AtomicPrivateSettlementV1,
        policy: &PrivateSettlementAuditPolicyV1,
    ) -> Result<(), PrivateSettlementValidationError> {
        let (delta_digest, payload_digest, canonical_payload_bytes) =
            self.validate_material_against_v1(manifest, policy, false)?;
        let leg = manifest
            .legs
            .get(usize::from(self.statement.leg_ordinal))
            .ok_or(PrivateSettlementValidationError::UnknownLeg)?;
        self.availability.validate_shape()?;
        let certificate_digest = self
            .availability
            .digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let availability = &self.availability.body;
        if leg.delta_digest != delta_digest
            || leg.payload_digest != payload_digest
            || leg.availability_certificate_digest != certificate_digest
            || availability.network_id != manifest.network_id
            || availability.bundle_id != manifest.bundle_id
            || availability.leg_ordinal != self.statement.leg_ordinal
            || availability.route != self.statement.route
            || availability.authority_digest != self.audit_capsule.aad.authority_digest
            || availability.authority_context_height != manifest.authority_context_height
            || availability.payload_digest != payload_digest
            || usize::try_from(availability.payload_bytes).ok() != Some(canonical_payload_bytes)
            || availability.retention_until_height < manifest.expiry_height
        {
            return Err(PrivateSettlementValidationError::SidecarAvailabilityMismatch);
        }
        Ok(())
    }

    fn validate_material_against_v1(
        &self,
        manifest: &AtomicPrivateSettlementV1,
        policy: &PrivateSettlementAuditPolicyV1,
        provisional: bool,
    ) -> Result<(Hash, Hash, usize), PrivateSettlementValidationError> {
        if provisional {
            manifest.validate_provisional()?;
        } else {
            manifest.validate()?;
        }
        policy.validate()?;
        if self.proof.is_empty() || self.proof.len() > PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1 {
            return Err(PrivateSettlementValidationError::InvalidProofSize);
        }
        self.statement.validate()?;
        let leg = manifest
            .legs
            .get(usize::from(self.statement.leg_ordinal))
            .ok_or(PrivateSettlementValidationError::UnknownLeg)?;
        if self.statement.network_id != manifest.network_id
            || self.statement.bundle_id != manifest.bundle_id
            || self.statement.route != leg.route
            || self.statement.authority_context_height != manifest.authority_context_height
            || self.statement.pool_id != leg.pool_id
            || self.statement.asset_binding_commitment != leg.asset_binding_commitment
            || self.statement.audit_policy_digest != leg.audit_policy_digest
            || self.statement.fee_intent_digest != manifest.fee_intent_digest
            || self.statement.reimbursement_terms_commitment
                != manifest.reimbursement_terms_commitment
            || self.statement.reimbursement_leg_ordinal != manifest.reimbursement_leg_ordinal
            || self.statement.expiry_height != manifest.expiry_height
            || policy.body.dataspace_id != leg.route.dataspace_id
            || policy.policy_digest != leg.audit_policy_digest
            || policy.body.key_epoch != self.statement.audit_key_epoch
            || !policy.is_active_at(manifest.authority_context_height)
            || policy
                .body
                .retirement_height
                .is_some_and(|retirement| manifest.expiry_height >= retirement)
        {
            return Err(PrivateSettlementValidationError::ManifestPayloadMismatch);
        }
        self.audit_capsule.validate_against(policy)?;
        if self.audit_capsule.aad.network_id != self.statement.network_id
            || self.audit_capsule.aad.bundle_id != self.statement.bundle_id
            || self.audit_capsule.aad.leg_ordinal != self.statement.leg_ordinal
            || self.audit_capsule.aad.route != self.statement.route
            || self.audit_capsule.aad.authority_context_height
                != self.statement.authority_context_height
            || self.audit_capsule.aad.plaintext_commitment
                != self.statement.audit_plaintext_commitment
        {
            return Err(PrivateSettlementValidationError::AuditCapsuleBindingMismatch);
        }
        let capsule_digest = self
            .audit_capsule
            .digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if capsule_digest != self.statement.audit_capsule_digest {
            return Err(PrivateSettlementValidationError::AuditCapsuleDigestMismatch);
        }
        self.delta.validate_against(&self.statement)?;
        if self.delta.proof_digest != self.proof_digest() {
            return Err(PrivateSettlementValidationError::ProofDigestMismatch);
        }
        let delta_digest = self
            .delta
            .digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let payload_digest = self
            .sidecar_material_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let canonical_payload_bytes = self
            .sidecar_material_bytes_len()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if leg.delta_digest != delta_digest || leg.payload_digest != payload_digest {
            return Err(PrivateSettlementValidationError::ManifestPayloadMismatch);
        }
        Ok((delta_digest, payload_digest, canonical_payload_bytes))
    }
}

/// Immutable restricted leg material persisted before availability shares are issued.
///
/// The manifest must carry reserved-zero availability certificate digests for
/// every leg. Proof bytes, the opaque delta, and the encrypted audit capsule
/// are already final and content addressed by `availability_body.payload_digest`.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementProvisionalLegMaterialV1"
)]
pub struct PrivateSettlementProvisionalLegMaterialV1 {
    /// Provisional material wire version.
    pub version: u8,
    /// Exact all-leg manifest with reserved-zero availability digests.
    pub manifest: AtomicPrivateSettlementV1,
    /// Governed local audit policy.
    pub audit_policy: PrivateSettlementAuditPolicyV1,
    /// Exact four-validator committee authority.
    pub committee_authority: PrivateSettlementCommitteeAuthorityV1,
    /// Restricted proof statement.
    pub statement: PrivateSettlementProofStatementV1,
    /// Native proof bytes.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub proof: Vec<u8>,
    /// Fixed-shape opaque state delta.
    pub delta: PrivateSettlementDeltaV1,
    /// Padded auditor-only encrypted capsule.
    pub audit_capsule: PrivateSettlementAuditCapsuleV1,
    /// Exact body each committee member must sign after durable persistence.
    pub availability_body: PrivateSettlementSidecarAvailabilityBodyV1,
}

impl fmt::Debug for PrivateSettlementProvisionalLegMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementProvisionalLegMaterialV1")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("leg_ordinal", &self.statement.leg_ordinal)
            .field("route", &self.statement.route)
            .field("payload_digest", &self.availability_body.payload_digest)
            .finish_non_exhaustive()
    }
}

impl PrivateSettlementProvisionalLegMaterialV1 {
    /// Build the exact payload that will carry a completed certificate.
    #[must_use]
    pub fn payload_with_certificate(
        &self,
        availability: PrivateSettlementSidecarAvailabilityV1,
    ) -> PrivateSettlementLegPayloadV1 {
        PrivateSettlementLegPayloadV1 {
            statement: self.statement.clone(),
            proof: self.proof.clone(),
            delta: self.delta.clone(),
            audit_capsule: self.audit_capsule.clone(),
            availability,
        }
    }

    /// Compute the content address of the exact immutable restricted material.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if material cannot be canonically encoded.
    pub fn payload_digest(&self) -> Result<Hash, norito::Error> {
        self.payload_with_certificate(PrivateSettlementSidecarAvailabilityV1 {
            body: self.availability_body,
            signers_bitmap: 0,
            aggregate_signature: Vec::new(),
        })
        .payload_digest()
    }

    /// Return the canonical byte length of material excluding the certificate.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if material cannot be canonically encoded.
    pub fn sidecar_material_bytes_len(&self) -> Result<usize, norito::Error> {
        self.payload_with_certificate(PrivateSettlementSidecarAvailabilityV1 {
            body: self.availability_body,
            signers_bitmap: 0,
            aggregate_signature: Vec::new(),
        })
        .sidecar_material_bytes_len()
    }

    /// Validate every provisional manifest, material, authority, and body binding.
    ///
    /// Cryptographic committee proofs of possession and shares are verified by
    /// the node runtime after this structural boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed fail-closed validation error.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        self.committee_authority.validate()?;
        let payload = self.payload_with_certificate(PrivateSettlementSidecarAvailabilityV1 {
            body: self.availability_body,
            signers_bitmap: 0,
            aggregate_signature: Vec::new(),
        });
        let (_, payload_digest, payload_bytes) =
            payload.validate_material_against_v1(&self.manifest, &self.audit_policy, true)?;
        self.availability_body.validate_shape()?;
        let authority_digest = self
            .committee_authority
            .digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if self.committee_authority.route != self.statement.route
            || self.availability_body.network_id != self.manifest.network_id
            || self.availability_body.bundle_id != self.manifest.bundle_id
            || self.availability_body.leg_ordinal != self.statement.leg_ordinal
            || self.availability_body.route != self.statement.route
            || self.availability_body.authority_digest != authority_digest
            || self.audit_capsule.aad.authority_digest != authority_digest
            || self.audit_capsule.aad.authority_context_height
                != self.availability_body.authority_context_height
            || self.availability_body.authority_context_height
                != self.manifest.authority_context_height
            || self.availability_body.payload_digest != payload_digest
            || usize::try_from(self.availability_body.payload_bytes).ok() != Some(payload_bytes)
            || self.availability_body.retention_until_height < self.manifest.expiry_height
        {
            return Err(PrivateSettlementValidationError::SidecarAvailabilityMismatch);
        }
        Ok(())
    }
}

/// Content address of actual proof-complete restricted material, without manufacturing a certificate.
/// # Errors
/// Canonical encoding failure. Callers validate actual proof/ciphertext bindings separately.
pub fn private_settlement_sidecar_material_digest_v1(
    statement: &PrivateSettlementProofStatementV1,
    proof: &[u8],
    delta: &PrivateSettlementDeltaV1,
    capsule: &PrivateSettlementAuditCapsuleV1,
) -> Result<Hash, norito::Error> {
    canonical_hash(
        SIDECAR_DIGEST_DOMAIN_V1,
        &(
            statement.clone(),
            proof.to_vec(),
            delta.clone(),
            capsule.clone(),
        ),
    )
}
/// Exact canonical size of the existing certificate-free material tuple.
/// # Errors
/// Canonical encoding or length overflow.
pub fn private_settlement_sidecar_material_bytes_len_v1(
    statement: &PrivateSettlementProofStatementV1,
    proof: &[u8],
    delta: &PrivateSettlementDeltaV1,
    capsule: &PrivateSettlementAuditCapsuleV1,
) -> Result<usize, norito::Error> {
    norito::canonical_frame_len(&(
        statement.clone(),
        proof.to_vec(),
        delta.clone(),
        capsule.clone(),
    ))
}

/// Compute the canonical domain-separated digest of settlement proof bytes.
///
/// This helper lets restricted clients verify committee responses without
/// reconstructing an encrypted capsule or a complete leg payload.
#[must_use]
pub fn private_settlement_proof_digest_v1(proof: &[u8]) -> Hash {
    Hash::new_from_chunks(&[
        PROOF_DIGEST_DOMAIN_V1,
        &u64::try_from(proof.len())
            .expect("proof length fits u64")
            .to_le_bytes(),
        proof,
    ])
}

/// Exact purpose-separated body signed by a local auditor.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditApprovalBodyV1"
)]
pub struct PrivateSettlementAuditApprovalBodyV1 {
    /// Approval wire version.
    pub version: u8,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable bundle identifier.
    pub bundle_id: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Participant dataspace.
    pub dataspace_id: DataSpaceId,
    /// Auditor producing this approval.
    pub auditor_id: AccountId,
    /// Governed policy digest.
    pub audit_policy_digest: Hash,
    /// Exact policy key epoch.
    pub audit_key_epoch: u64,
    /// Restricted proof digest.
    pub proof_digest: Hash,
    /// Encrypted capsule digest.
    pub capsule_digest: Hash,
    /// Fixed-shape delta digest.
    pub delta_digest: Hash,
    /// Current private root.
    pub old_root: PrivacyRootV1,
    /// Successor private root.
    pub new_root: PrivacyRootV1,
    /// Last global height at which this approval is valid.
    pub expiry_height: u64,
}

impl fmt::Debug for PrivateSettlementAuditApprovalBodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditApprovalBodyV1(<restricted>)")
    }
}

/// Signed local-auditor approval required before participant Prepare.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditApprovalV1"
)]
pub struct PrivateSettlementAuditApprovalV1 {
    /// Exact purpose-separated signed body.
    pub body: PrivateSettlementAuditApprovalBodyV1,
    /// Auditor signature over `body`.
    pub signature: SignatureOf<PrivateSettlementAuditApprovalBodyV1>,
}

impl fmt::Debug for PrivateSettlementAuditApprovalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSettlementAuditApprovalV1(<restricted>)")
    }
}

impl PrivateSettlementAuditApprovalV1 {
    /// Compute the purpose-separated digest of the complete signed approval.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the approval cannot be canonically encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(AUDIT_APPROVAL_DIGEST_DOMAIN_V1, self)
    }

    /// Verify membership, signature, policy/key epoch, and height validity.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid or unauthorized approval.
    pub fn verify(
        &self,
        policy: &PrivateSettlementAuditPolicyV1,
        at_height: u64,
    ) -> Result<(), PrivateSettlementValidationError> {
        policy.validate()?;
        if self.body.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.body.version,
            });
        }
        if !policy.is_active_at(at_height)
            || self.body.expiry_height < at_height
            || self.body.dataspace_id != policy.body.dataspace_id
            || self.body.audit_policy_digest != policy.policy_digest
            || self.body.audit_key_epoch != policy.body.key_epoch
        {
            return Err(PrivateSettlementValidationError::StaleAuditApproval);
        }
        let auditor = policy
            .body
            .auditors
            .iter()
            .find(|auditor| auditor.auditor_id == self.body.auditor_id)
            .ok_or(PrivateSettlementValidationError::UnauthorizedAuditor)?;
        self.signature
            .verify(&auditor.signing_key, &self.body)
            .map_err(|_| PrivateSettlementValidationError::InvalidAuditSignature)
    }
}

/// Validate one local-auditor approval against the exact encrypted leg.
///
/// This checks every purpose-separated policy, proof, capsule, delta, root,
/// route, bundle, network, epoch, and expiry binding without imposing the
/// policy threshold.  Durable collectors use it while gathering a multi-
/// auditor threshold one approval at a time.
///
/// # Errors
///
/// Returns a typed error if the signature, governed membership, lifecycle, or
/// any immutable leg binding is invalid.
pub fn validate_private_settlement_audit_approval_v1(
    approval: &PrivateSettlementAuditApprovalV1,
    policy: &PrivateSettlementAuditPolicyV1,
    payload: &PrivateSettlementLegPayloadV1,
    at_height: u64,
) -> Result<(), PrivateSettlementValidationError> {
    approval.verify(policy, at_height)?;
    let delta_digest = payload
        .delta
        .digest()
        .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
    if approval.body.network_id != payload.statement.network_id
        || approval.body.bundle_id != payload.statement.bundle_id
        || approval.body.leg_ordinal != payload.statement.leg_ordinal
        || approval.body.dataspace_id != payload.statement.route.dataspace_id
        || approval.body.proof_digest != payload.delta.proof_digest
        || approval.body.capsule_digest != payload.delta.capsule_digest
        || approval.body.delta_digest != delta_digest
        || approval.body.old_root != payload.delta.old_root
        || approval.body.new_root != payload.delta.new_root
        || approval.body.expiry_height != payload.statement.expiry_height
    {
        return Err(PrivateSettlementValidationError::AuditApprovalBindingMismatch);
    }
    Ok(())
}

/// Validate a canonical set of distinct local-auditor approvals.
///
/// # Errors
///
/// Returns a typed error if signatures are invalid, bindings differ, approvals
/// are duplicated or unordered, or the governed threshold is not met.
pub fn validate_private_settlement_audit_approvals_v1(
    approvals: &[PrivateSettlementAuditApprovalV1],
    policy: &PrivateSettlementAuditPolicyV1,
    payload: &PrivateSettlementLegPayloadV1,
    at_height: u64,
) -> Result<(), PrivateSettlementValidationError> {
    policy.validate()?;
    if approvals.len() < usize::from(policy.body.min_approvals) {
        return Err(
            PrivateSettlementValidationError::InsufficientAuditApprovals {
                actual: approvals.len(),
                required: policy.body.min_approvals,
            },
        );
    }
    let mut previous = None;
    for approval in approvals {
        validate_private_settlement_audit_approval_v1(approval, policy, payload, at_height)?;
        if previous
            .as_ref()
            .is_some_and(|auditor| auditor >= &approval.body.auditor_id)
        {
            return Err(PrivateSettlementValidationError::NonCanonicalApprovalOrder);
        }
        previous = Some(approval.body.auditor_id.clone());
    }
    Ok(())
}

/// Native AMX phase certified for a private settlement leg.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "phase",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPhaseV1")]
pub enum PrivateSettlementPhaseV1 {
    /// Proof, audit, state, and sidecar availability have been durably staged.
    Prepare,
    /// The committee binds its leg to the exact whole-bundle manifest.
    Commit,
}

/// Route-free four-validator committee roster stored once in an authority catalog.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementCommitteeRosterV1"
)]
pub struct PrivateSettlementCommitteeRosterV1 {
    /// Canonical hash of `validators`.
    pub validator_set_hash: HashOf<Vec<PeerId>>,
    /// Exactly four ordered validator identities.
    pub validators: Vec<PeerId>,
    /// BLS proofs of possession aligned one-for-one with `validators`.
    pub validator_pops: Vec<Vec<u8>>,
}

impl PrivateSettlementCommitteeRosterV1 {
    /// Validate exact four-validator committee shape and proofs of possession.
    ///
    /// # Errors
    ///
    /// Returns a typed structural error.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.validators.len() != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1
            || self.validator_pops.len() != self.validators.len()
            || self.validators.iter().collect::<BTreeSet<_>>().len() != self.validators.len()
            || self
                .validator_pops
                .iter()
                .any(|pop| pop.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1)
            || self.validator_set_hash != HashOf::new(&self.validators)
        {
            return Err(PrivateSettlementValidationError::InvalidCommitteeAuthority);
        }
        Ok(())
    }

    /// Reconstruct the route-bound authority committed by a phase body.
    #[must_use]
    pub fn with_route(
        &self,
        route: PrivateSettlementRouteV1,
    ) -> PrivateSettlementCommitteeAuthorityV1 {
        PrivateSettlementCommitteeAuthorityV1 {
            route,
            validator_set_hash: self.validator_set_hash,
            validators: self.validators.clone(),
            validator_pops: self.validator_pops.clone(),
        }
    }
}

/// Route-bound committee authority used by sidecars and phase signatures.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementCommitteeAuthorityV1"
)]
pub struct PrivateSettlementCommitteeAuthorityV1 {
    /// Exact route governed by this committee.
    pub route: PrivateSettlementRouteV1,
    /// Canonical hash of `validators`.
    pub validator_set_hash: HashOf<Vec<PeerId>>,
    /// Exactly four ordered validator identities.
    pub validators: Vec<PeerId>,
    /// BLS proofs of possession aligned one-for-one with `validators`.
    pub validator_pops: Vec<Vec<u8>>,
}

impl PrivateSettlementCommitteeAuthorityV1 {
    /// Return the route-free roster material stored in compact public catalogs.
    #[must_use]
    pub fn roster(&self) -> PrivateSettlementCommitteeRosterV1 {
        PrivateSettlementCommitteeRosterV1 {
            validator_set_hash: self.validator_set_hash,
            validators: self.validators.clone(),
            validator_pops: self.validator_pops.clone(),
        }
    }

    /// Compute the compact authority-record digest signed into phase bodies.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the record cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(AUTHORITY_DIGEST_DOMAIN_V1, self)
    }

    /// Validate exact four-validator committee shape and proofs of possession.
    ///
    /// # Errors
    ///
    /// Returns a typed structural error.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if hash_is_zero(&self.route.lane_incarnation) || self.roster().validate().is_err() {
            return Err(PrivateSettlementValidationError::InvalidCommitteeAuthority);
        }
        Ok(())
    }
}

/// Compact two-level committee catalog shared by every public bundle object.
///
/// Phase certificates keep indexing the logical leg slot. The corresponding
/// entry in `leg_roster_indices` selects a route-free roster, which is combined
/// with the manifest leg route before authority-digest or QC verification.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAuthorityCatalogV1"
)]
pub struct PrivateSettlementAuthorityCatalogV1 {
    /// Unique committee rosters in canonical first-use order.
    pub rosters: Vec<PrivateSettlementCommitteeRosterV1>,
    /// Roster index for every canonical manifest leg.
    pub leg_roster_indices: Vec<u8>,
}

impl PrivateSettlementAuthorityCatalogV1 {
    /// Build the canonical compact catalog from route-bound per-leg authorities.
    ///
    /// # Errors
    ///
    /// Returns a typed error if a route is missing, a roster is malformed, or
    /// the same validator-set hash is supplied with different roster material.
    pub fn from_leg_authorities(
        manifest: &AtomicPrivateSettlementV1,
        authorities: &[PrivateSettlementCommitteeAuthorityV1],
    ) -> Result<Self, PrivateSettlementValidationError> {
        manifest.validate()?;
        if authorities.len() != manifest.legs.len() {
            return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
        }
        let mut catalog = Self::default();
        for (leg, authority) in manifest.legs.iter().zip(authorities) {
            authority.validate()?;
            if authority.route != leg.route {
                return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
            }
            let roster = authority.roster();
            let roster_index = if let Some(index) = catalog
                .rosters
                .iter()
                .position(|candidate| candidate.validator_set_hash == roster.validator_set_hash)
            {
                if catalog.rosters[index] != roster {
                    return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
                }
                index
            } else {
                let index = catalog.rosters.len();
                catalog.rosters.push(roster);
                index
            };
            catalog.leg_roster_indices.push(
                u8::try_from(roster_index)
                    .map_err(|_| PrivateSettlementValidationError::InvalidAuthorityCatalog)?,
            );
        }
        catalog.validate_for_manifest(manifest)?;
        Ok(catalog)
    }

    /// Validate bounds, uniqueness, references, and canonical first-use order.
    ///
    /// # Errors
    ///
    /// Returns a typed error for any malformed or non-canonical catalog.
    pub fn validate_for_manifest(
        &self,
        manifest: &AtomicPrivateSettlementV1,
    ) -> Result<(), PrivateSettlementValidationError> {
        manifest.validate()?;
        if self.leg_roster_indices.len() != manifest.legs.len()
            || self.rosters.is_empty()
            || self.rosters.len() > manifest.legs.len()
            || self.rosters.len() > usize::from(u8::MAX)
        {
            return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
        }
        let mut roster_hashes = BTreeSet::new();
        for roster in &self.rosters {
            roster.validate()?;
            if !roster_hashes.insert(roster.validator_set_hash) {
                return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
            }
        }
        let mut seen = vec![false; self.rosters.len()];
        let mut next_first_use = 0_usize;
        for &roster_index in &self.leg_roster_indices {
            let roster_index = usize::from(roster_index);
            let Some(was_seen) = seen.get_mut(roster_index) else {
                return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
            };
            if !*was_seen {
                if roster_index != next_first_use {
                    return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
                }
                *was_seen = true;
                next_first_use += 1;
            }
        }
        if next_first_use != self.rosters.len() {
            return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
        }
        Ok(())
    }

    /// Resolve one logical leg slot to its exact route-bound authority.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the manifest ordinal or catalog reference is invalid.
    pub fn authority_for_leg(
        &self,
        manifest: &AtomicPrivateSettlementV1,
        leg_index: usize,
    ) -> Result<PrivateSettlementCommitteeAuthorityV1, PrivateSettlementValidationError> {
        let leg = manifest
            .legs
            .get(leg_index)
            .ok_or(PrivateSettlementValidationError::InvalidAuthorityCatalog)?;
        if usize::from(leg.ordinal) != leg_index {
            return Err(PrivateSettlementValidationError::InvalidAuthorityCatalog);
        }
        let roster_index = self
            .leg_roster_indices
            .get(leg_index)
            .copied()
            .map(usize::from)
            .ok_or(PrivateSettlementValidationError::InvalidAuthorityCatalog)?;
        self.rosters
            .get(roster_index)
            .map(|roster| roster.with_route(leg.route))
            .ok_or(PrivateSettlementValidationError::InvalidAuthorityCatalog)
    }
}

/// Context bound by a participant committee phase certificate.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPhaseBodyV1")]
pub struct PrivateSettlementPhaseBodyV1 {
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Digest of the exact whole manifest.
    pub manifest_digest: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Exact participant route.
    pub route: PrivateSettlementRouteV1,
    /// Digest of the fixed-shape state delta.
    pub delta_digest: Hash,
    /// Digest of the reconstructed route-bound authority record.
    pub authority_digest: Hash,
    /// Digest of the exact all-leg Prepare barrier.
    ///
    /// Prepare bodies reserve the all-zero value because the barrier is not yet
    /// complete. Commit bodies must carry the same non-zero digest over the
    /// manifest, authority catalog, every delta, and every Prepare QC.
    pub prepared_bundle_digest: Hash,
    /// Certified protocol phase.
    pub phase: PrivateSettlementPhaseV1,
    /// Global/catalog authority context height.
    pub authority_context_height: u64,
    /// Final admissible global height.
    pub expiry_height: u64,
}

impl PrivateSettlementPhaseBodyV1 {
    /// Canonical purpose-separated bytes signed by one participant validator.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the body cannot be canonically encoded.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, norito::Error> {
        private_settlement_signature_preimage(
            PHASE_SIGNATURE_DOMAIN_V1,
            self,
            "phase body is too large",
        )
    }
}

/// One independently authenticated participant phase vote before aggregation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPhaseVoteV1")]
pub struct PrivateSettlementPhaseVoteV1 {
    /// Vote wire version.
    pub version: u8,
    /// Exact purpose-separated phase body.
    pub body: PrivateSettlementPhaseBodyV1,
    /// Exact committee validator producing the vote.
    pub signer: PeerId,
    /// Compressed BLS-normal signature over the canonical phase body.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub signature: Vec<u8>,
}

impl PrivateSettlementPhaseVoteV1 {
    /// Validate fixed vote wire shape before roster and signature verification.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a malformed or unsupported vote.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1
            || hash_is_zero(&self.body.bundle_id)
            || hash_is_zero(&self.body.manifest_digest)
            || hash_is_zero(&self.body.delta_digest)
            || hash_is_zero(&self.body.authority_digest)
            || match self.body.phase {
                PrivateSettlementPhaseV1::Prepare => {
                    !hash_is_zero(&self.body.prepared_bundle_digest)
                }
                PrivateSettlementPhaseV1::Commit => hash_is_zero(&self.body.prepared_bundle_digest),
            }
        {
            return Err(PrivateSettlementValidationError::InvalidPhaseVote);
        }
        Ok(())
    }
}

/// Compact phase certificate referencing a receipt-level logical leg slot.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPhaseCertificateV1"
)]
pub struct PrivateSettlementPhaseCertificateV1 {
    /// Exact signed phase body.
    pub body: PrivateSettlementPhaseBodyV1,
    /// Logical leg-slot index resolved through the catalog's `leg_roster_indices` map.
    pub authority_catalog_index: u8,
    /// Four-bit LSB-first signer bitmap.
    pub signers_bitmap: u8,
    /// Compressed aggregate BLS-normal signature.
    pub aggregate_signature: Vec<u8>,
}

impl PrivateSettlementPhaseCertificateV1 {
    /// Validate bitmap and signature wire shape.
    ///
    /// Cryptographic aggregate verification is performed by core against the
    /// authority record after this inexpensive structural check.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed certificate shape.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.signers_bitmap & !0x0f != 0
            || self.signers_bitmap.count_ones() != u32::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1)
            || self.aggregate_signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1
            || hash_is_zero(&self.body.bundle_id)
            || hash_is_zero(&self.body.manifest_digest)
            || hash_is_zero(&self.body.delta_digest)
            || hash_is_zero(&self.body.authority_digest)
            || match self.body.phase {
                PrivateSettlementPhaseV1::Prepare => {
                    !hash_is_zero(&self.body.prepared_bundle_digest)
                }
                PrivateSettlementPhaseV1::Commit => hash_is_zero(&self.body.prepared_bundle_digest),
            }
        {
            return Err(PrivateSettlementValidationError::InvalidPhaseCertificate);
        }
        Ok(())
    }
}

/// Complete all-Prepare barrier that every Commit vote must bind.
///
/// The vectors are aligned by canonical leg ordinal. Core independently
/// verifies every authority, delta, and Prepare QC before recomputing
/// `prepared_bundle_digest`; carrying this material prevents a coordinator
/// from substituting one leg or certified statement for another at Commit
/// time. The digest normalizes quorum-equivalent certificate encodings: two
/// exact three-of-four signer subsets over the same signed body certify the
/// same logical barrier and therefore cannot fork coordinator recovery.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementPrepareBarrierV1"
)]
pub struct PrivateSettlementPrepareBarrierV1 {
    /// Barrier wire version.
    pub version: u8,
    /// Exact finalized public manifest.
    pub manifest: AtomicPrivateSettlementV1,
    /// Compact participant authority catalog with one logical slot per leg.
    pub authority_catalog: PrivateSettlementAuthorityCatalogV1,
    /// Every fixed-shape delta in canonical leg order.
    pub deltas: Vec<PrivateSettlementDeltaV1>,
    /// Every cryptographically valid Prepare QC in canonical leg order.
    pub prepare_certificates: Vec<PrivateSettlementPhaseCertificateV1>,
    /// Canonical digest of all preceding fields except `version`.
    pub prepared_bundle_digest: Hash,
}

impl PrivateSettlementPrepareBarrierV1 {
    /// Recompute the canonical complete-bundle digest.
    ///
    /// Aggregate signatures and signer bitmaps are deliberately excluded from
    /// the digest. They are independently verified against the authority
    /// catalog, while the signed body and authority-catalog index are included.
    /// This makes every valid exact three-of-four certificate for one statement
    /// quorum-equivalent and preserves restart liveness with one unavailable
    /// validator.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if the complete barrier material cannot be encoded.
    pub fn computed_prepared_bundle_digest(&self) -> Result<Hash, norito::Error> {
        let certified_statements = self
            .prepare_certificates
            .iter()
            .map(|certificate| (certificate.authority_catalog_index, certificate.body))
            .collect::<Vec<_>>();
        let material = (
            self.manifest.clone(),
            self.authority_catalog.clone(),
            self.deltas.clone(),
            certified_statements,
        );
        canonical_hash(PREPARED_BUNDLE_DIGEST_DOMAIN_V1, &material)
    }

    /// Return whether two barriers carry the same certified statements.
    ///
    /// Signer bitmaps and aggregate signatures may differ because any valid
    /// three-of-four subset certifies the same Prepare body. This comparison
    /// deliberately remains structural: callers must independently validate
    /// both barriers and their aggregate signatures before treating them as
    /// quorum-equivalent.
    #[must_use]
    pub fn quorum_equivalent_to(&self, other: &Self) -> bool {
        self.version == other.version
            && self.manifest == other.manifest
            && self.authority_catalog == other.authority_catalog
            && self.deltas == other.deltas
            && self.prepared_bundle_digest == other.prepared_bundle_digest
            && self.prepare_certificates.len() == other.prepare_certificates.len()
            && self
                .prepare_certificates
                .iter()
                .zip(&other.prepare_certificates)
                .all(|(left, right)| {
                    left.body == right.body
                        && left.authority_catalog_index == right.authority_catalog_index
                })
    }

    /// Validate bounded canonical vector alignment before cryptographic checks.
    ///
    /// # Errors
    ///
    /// Returns a typed error for unsupported, incomplete, or misaligned material.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        self.manifest.validate()?;
        let leg_count = self.manifest.legs.len();
        if self.deltas.len() != leg_count
            || self.prepare_certificates.len() != leg_count
            || hash_is_zero(&self.prepared_bundle_digest)
        {
            return Err(PrivateSettlementValidationError::InvalidPrepareBarrier);
        }
        self.authority_catalog
            .validate_for_manifest(&self.manifest)
            .map_err(|_| PrivateSettlementValidationError::InvalidPrepareBarrier)?;
        let mut output_recipients = BTreeSet::new();
        for (index, ((manifest_leg, delta), certificate)) in self
            .manifest
            .legs
            .iter()
            .zip(&self.deltas)
            .zip(&self.prepare_certificates)
            .enumerate()
        {
            let ordinal =
                u8::try_from(index).expect("private settlement has at most 255 participant legs");
            if manifest_leg.ordinal != ordinal
                || delta.leg_ordinal != ordinal
                || delta.route != manifest_leg.route
                || delta.validate_public_shape().is_err()
                || delta
                    .encrypted_outputs
                    .iter()
                    .any(|output| !output_recipients.insert(output.recipient))
                || certificate.authority_catalog_index != ordinal
                || certificate.body.phase != PrivateSettlementPhaseV1::Prepare
                || certificate.body.leg_ordinal != ordinal
                || certificate.body.route != manifest_leg.route
                || certificate.validate_shape().is_err()
            {
                return Err(PrivateSettlementValidationError::InvalidPrepareBarrier);
            }
        }
        Ok(())
    }
}

/// Finalized receipt row for one private settlement leg.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementLegReceiptV1"
)]
pub struct PrivateSettlementLegReceiptV1 {
    /// Fixed-shape public state delta.
    pub delta: PrivateSettlementDeltaV1,
    /// Participant Prepare certificate.
    pub prepare: PrivateSettlementPhaseCertificateV1,
    /// Participant Commit certificate.
    pub commit: PrivateSettlementPhaseCertificateV1,
}

/// Complete committee-certified bundle carried before global block finality.
///
/// The actual finalization height is deliberately absent: a sponsor cannot
/// predict the block that will include its signed transaction. Consensus adds
/// that height when it constructs the terminal [`PrivateSettlementReceiptV1`].
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementCommitBundleV1"
)]
pub struct PrivateSettlementCommitBundleV1 {
    /// Carrier wire version.
    pub version: u8,
    /// Exact public manifest.
    pub manifest: AtomicPrivateSettlementV1,
    /// Compact participant authority catalog with one logical slot per leg.
    pub authority_catalog: PrivateSettlementAuthorityCatalogV1,
    /// One Prepare/Commit-certified row per canonical participant leg.
    pub legs: Vec<PrivateSettlementLegReceiptV1>,
}

impl PrivateSettlementCommitBundleV1 {
    /// Return the canonical direct-instruction byte length used for carrier preflight.
    ///
    /// This includes the registered [`crate::isi::InstructionBox`] framing for
    /// [`crate::isi::private_settlement::FinalizeAtomicPrivateSettlementV1`].
    /// Runtime admission additionally limits the complete sponsor-signed
    /// transaction, including its authority, metadata, fee intent, and signature.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the complete boxed instruction cannot be encoded.
    pub fn canonical_carrier_bytes_len(&self) -> Result<usize, norito::Error> {
        let instruction =
            crate::isi::private_settlement::FinalizeAtomicPrivateSettlementV1::new(self.clone());
        let boxed = crate::isi::InstructionBox::from(instruction);
        norito::encode_canonical(&boxed).map(|encoded| encoded.len())
    }

    /// Construct the terminal receipt at the deterministic inclusion height.
    #[must_use]
    pub fn into_receipt(self, finalized_height: u64) -> PrivateSettlementReceiptV1 {
        PrivateSettlementReceiptV1 {
            version: self.version,
            manifest: self.manifest,
            authority_catalog: self.authority_catalog,
            legs: self.legs,
            finalized_height,
        }
    }
}

/// Compact globally finalized private settlement receipt.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::private_settlement::PrivateSettlementReceiptV1")]
pub struct PrivateSettlementReceiptV1 {
    /// Receipt wire version.
    pub version: u8,
    /// Exact public manifest.
    pub manifest: AtomicPrivateSettlementV1,
    /// Compact participant authority catalog with one logical slot per leg.
    pub authority_catalog: PrivateSettlementAuthorityCatalogV1,
    /// One finalized leg record per canonical participant leg.
    pub legs: Vec<PrivateSettlementLegReceiptV1>,
    /// Global height at which every delta became active atomically.
    pub finalized_height: u64,
}

impl PrivateSettlementReceiptV1 {
    /// Return the canonical pre-finality direct-instruction length represented by this receipt.
    ///
    /// The consensus-assigned `finalized_height` is not part of the carrier.
    /// This reconstructs the registered finalization instruction for deterministic
    /// WSV preflight; signed-transaction admission separately measures the exact
    /// complete sponsor-signed transaction.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the represented commit bundle cannot be encoded.
    pub fn canonical_carrier_bytes_len(&self) -> Result<usize, norito::Error> {
        PrivateSettlementCommitBundleV1 {
            version: self.version,
            manifest: self.manifest.clone(),
            authority_catalog: self.authority_catalog.clone(),
            legs: self.legs.clone(),
        }
        .canonical_carrier_bytes_len()
    }

    /// Validate the compact receipt's complete non-cryptographic shape and bindings.
    ///
    /// # Errors
    ///
    /// Returns a typed error before aggregate signature verification or state application.
    pub fn validate_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        self.manifest.validate()?;
        if self.finalized_height < self.manifest.authority_context_height
            || self.finalized_height > self.manifest.expiry_height
            || self.legs.len() != self.manifest.legs.len()
        {
            return Err(PrivateSettlementValidationError::InvalidReceiptShape);
        }
        self.authority_catalog
            .validate_for_manifest(&self.manifest)
            .map_err(|_| PrivateSettlementValidationError::InvalidReceiptShape)?;
        let manifest_digest = self
            .manifest
            .manifest_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let mut prepared_bundle_digest = None;
        let mut output_recipients = BTreeSet::new();
        for (index, (manifest_leg, leg)) in self.manifest.legs.iter().zip(&self.legs).enumerate() {
            let authority = self
                .authority_catalog
                .authority_for_leg(&self.manifest, index)
                .map_err(|_| PrivateSettlementValidationError::InvalidReceiptShape)?;
            authority.validate()?;
            leg.delta.validate_public_shape()?;
            if leg
                .delta
                .encrypted_outputs
                .iter()
                .any(|output| !output_recipients.insert(output.recipient))
            {
                return Err(PrivateSettlementValidationError::DuplicateStateItem);
            }
            leg.prepare.validate_shape()?;
            leg.commit.validate_shape()?;
            let ordinal = u8::try_from(index).expect("receipt has at most 255 legs");
            let authority_digest = authority
                .digest()
                .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
            let delta_digest = leg
                .delta
                .digest()
                .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
            if authority.route != manifest_leg.route
                || (
                    leg.delta.bundle_id,
                    leg.delta.leg_ordinal,
                    leg.delta.route,
                    leg.delta.pool_id,
                    leg.delta.asset_binding_commitment,
                    leg.delta.audit_policy_digest,
                    delta_digest,
                ) != (
                    self.manifest.bundle_id,
                    ordinal,
                    manifest_leg.route,
                    manifest_leg.pool_id,
                    manifest_leg.asset_binding_commitment,
                    manifest_leg.audit_policy_digest,
                    manifest_leg.delta_digest,
                )
                || leg.prepare.authority_catalog_index != ordinal
                || leg.commit.authority_catalog_index != ordinal
                || leg.prepare.body.phase != PrivateSettlementPhaseV1::Prepare
                || leg.commit.body.phase != PrivateSettlementPhaseV1::Commit
            {
                return Err(PrivateSettlementValidationError::ReceiptBindingMismatch);
            }
            if prepared_bundle_digest
                .replace(leg.commit.body.prepared_bundle_digest)
                .is_some_and(|digest| digest != leg.commit.body.prepared_bundle_digest)
            {
                return Err(PrivateSettlementValidationError::ReceiptBindingMismatch);
            }
            for body in [&leg.prepare.body, &leg.commit.body] {
                if body.network_id != self.manifest.network_id
                    || body.bundle_id != self.manifest.bundle_id
                    || body.manifest_digest != manifest_digest
                    || body.leg_ordinal != ordinal
                    || body.route != manifest_leg.route
                    || body.delta_digest != delta_digest
                    || body.authority_digest != authority_digest
                    || body.authority_context_height != self.manifest.authority_context_height
                    || body.expiry_height != self.manifest.expiry_height
                {
                    return Err(PrivateSettlementValidationError::ReceiptBindingMismatch);
                }
            }
        }
        let encoded = norito::encode_canonical(self)
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if encoded.len() > PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1 {
            return Err(PrivateSettlementValidationError::ReceiptTooLarge {
                bytes: encoded.len(),
            });
        }
        Ok(())
    }
}

/// Public terminal reason class for an aborted private settlement.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "reason",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAbortReasonV1"
)]
pub enum PrivateSettlementAbortReasonV1 {
    /// Bundle reached its globally defined expiry height.
    Expired,
    /// At least one participant committee rejected its opaque leg.
    ParticipantRejected,
    /// The required local auditor threshold was unavailable or rejected the leg.
    AuditUnavailable,
    /// Restricted proof/capsule availability could not be certified.
    SidecarUnavailable,
}

/// Optional public replay marker for an aborted private settlement.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::private_settlement::PrivateSettlementAbortReceiptV1"
)]
pub struct PrivateSettlementAbortReceiptV1 {
    /// Receipt wire version.
    pub version: u8,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Stable settlement bundle identifier.
    pub bundle_id: Hash,
    /// Digest of the exact public manifest.
    pub manifest_digest: Hash,
    /// Final global height of the abort marker.
    pub finalized_height: u64,
    /// Public non-sensitive reason class.
    pub reason: PrivateSettlementAbortReasonV1,
}

impl PrivateSettlementAbortReceiptV1 {
    /// Validate version and non-zero public replay fields.
    ///
    /// # Errors
    ///
    /// Returns a typed structural error.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if hash_is_zero(&self.bundle_id)
            || hash_is_zero(&self.manifest_digest)
            || self.finalized_height == 0
        {
            return Err(PrivateSettlementValidationError::InvalidAbortReceipt);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests;

#[cfg(test)]
mod captured_private_settlement_ordinary_schema_tests;

#[cfg(test)]
mod frame_owner_identity_tests {
    //! Frame roots observed in the original codec before the identity cutover.

    #[test]
    fn captured_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_serialize::<
            super::PrivateSettlementAuditCommitmentMaterialV1,
        >(
            "iroha_data_model::nexus::private_settlement::PrivateSettlementAuditCommitmentMaterialV1",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::PrivateSettlementProofStatementV1,
        >("iroha_data_model::nexus::private_settlement::PrivateSettlementProofStatementV1");
        crate::frame_owner_identity_tests::assert_serialize::<
            super::PrivateSettlementReimbursementTermsMaterialV1,
        >(
            "iroha_data_model::nexus::private_settlement::PrivateSettlementReimbursementTermsMaterialV1",
        );
    }
}
