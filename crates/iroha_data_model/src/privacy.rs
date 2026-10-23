//! Canonical first-release privacy protocol wire types.
//!
//! The types in this module deliberately form a closed protocol surface.
//! Protocol identities, proof systems, and native verifier engines are separate
//! enums, and proof envelopes must bind all three together with governed
//! parameter, verifier, statement-schema, and engine-manifest digests. There
//! are no free-form identifiers, aliases, or fallback proof variants.
use crate::{AssetDefinitionId, NetworkId, account::AccountId, asset::AssetBalanceScope};

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_schema::IntoSchema;
pub use iroha_zkp_poseidon::vega_constants::{
    VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1, VEGA_MDL_BIRTH_RANDOM_BYTES_V1,
    VEGA_MDL_FULL_DATE_TEXT_BYTES_V1, VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1,
    VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1, VEGA_MDL_MAX_PRESENTATION_YEAR_V1,
    VEGA_MDL_MIN_AGE_THRESHOLD_YEARS_V1, VEGA_MDL_MIN_PRESENTATION_YEAR_V1,
    VEGA_MDL_MSO_PAYLOAD_BYTES_V1, VEGA_MDL_RFC3339_UTC_SECONDS_TEXT_BYTES_V1,
};
use norito::codec::{Decode, Encode};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
/// Domain separator used to hash canonical [`PrivacyStatementV1`] values.
pub const PRIVACY_STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:statement:v1";
/// Domain separator used to hash canonical [`PrivacyNativeConsensusBindingV1`] values.
pub const PRIVACY_NATIVE_CONSENSUS_BINDING_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:native-consensus-binding:v1";
/// Permanent Norito schema identity for the top-level typed privacy statement.
pub const PRIVACY_STATEMENT_SCHEMA_NAME_V1: &str = "iroha.privacy.statement.v1";
/// Permanent Norito schema identity for the shared native consensus binding.
pub const PRIVACY_NATIVE_CONSENSUS_BINDING_SCHEMA_NAME_V1: &str =
    "iroha.privacy.native-consensus-binding.v1";
/// Permanent Norito schema identity for the top-level typed privacy proof.
pub const PRIVACY_PROOF_SCHEMA_NAME_V1: &str = "iroha.privacy.proof.v1";
/// Permanent Norito schema identity for the cross-SDK privacy proof envelope.
pub const PRIVACY_PROOF_ENVELOPE_SCHEMA_NAME_V1: &str = "iroha.privacy.proof-envelope.v1";
/// Exact binary marker that begins every first-release privacy proof envelope.
pub const PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1: [u8; 8] = *b"IRHZK1\xA5\x5A";
/// Stable identity of the final first-release Exact12 catalog.
pub const PRIVACY_EXACT12_CATALOG_ID_V1: &[u8] = b"iroha-privacy-exact12-v1";
/// Canonical ordered catalog material committed by every proof and release manifest.
///
/// Each row is `decimal ordinal NUL protocol-id NUL security-model NUL`.
/// The prefix prevents the row encoding from being reused under another
/// catalog construction.
pub const PRIVACY_EXACT12_CATALOG_PREIMAGE_V1: &[u8] = concat!(
    "iroha.privacy.exact12.catalog.v1\0",
    "0\0zk-ace-pq-authorization-v1\0pq-qrom\0",
    "1\0anonymous-pgc-k-out-of-n-v1\0classical-rom\0",
    "2\0verange-transparent-range-v1\0classical-rom\0",
    "3\0iroha-zk-ams-v1\0classical-rom\0",
    "4\0vega-existing-credential-zk-v1\0classical-rom\0",
    "5\0iroha-zk-x509-stark-p256-v1\0classical-rom\0",
    "6\0iroha-jindo-polynomial-commitment-v1\0pq-qrom\0",
    "7\0iroha-bootle-lantern-anoncred-v1\0pq-qrom\0",
    "8\0orchard-halo2-actions-v1\0classical-rom\0",
    "9\0monero-fcmp-plus-plus-v1\0classical-rom\0",
    "10\0iroha-ivm-private-note-stark-v1\0pq-qrom\0",
    "11\0pq-masp-stark-v1\0pq-qrom\0",
)
.as_bytes();
/// Permanent Norito schema identity for local compiled-profile build metadata.
pub const PRIVACY_COMPILED_PROFILE_CATALOG_SCHEMA_NAME_V1: &str =
    "iroha.privacy.compiled-profile-catalog.v1";
/// Permanent Norito schema identity for the public Exact12 capability manifest.
pub const PRIVACY_EXACT12_CAPABILITY_MANIFEST_SCHEMA_NAME_V1: &str =
    "iroha.privacy.exact12-capability-manifest.v1";
/// Domain separator for the self-authenticating Exact12 capability manifest digest.
pub const PRIVACY_EXACT12_CAPABILITY_MANIFEST_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:exact12-capability-manifest:v1";
/// Permanent Norito schema identity for the concrete ZK-ACE authorization statement.
pub const ZK_ACE_AUTHORIZATION_STATEMENT_SCHEMA_NAME_V1: &str =
    "iroha.privacy.zk-ace.authorization-statement.v1";
/// Permanent Norito schema identity for authoritative ZK-ACE policy digest material.
pub const ZK_ACE_POLICY_DIGEST_MATERIAL_SCHEMA_NAME_V1: &str =
    "iroha.privacy.zk-ace.policy-digest-material.v1";
/// Domain separator used to hash canonical [`PrivacyRootPublicationV1`] values.
pub const PRIVACY_ROOT_PUBLICATION_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:root-publication:v1";
/// Domain separator used to hash canonical [`PrivacyOrchardPoolBootstrapV1`] values.
pub const PRIVACY_ORCHARD_POOL_BOOTSTRAP_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:orchard-pool-bootstrap:v1";
/// Domain separator for FCMP++, private-IVM, and PQ-MASP pool bootstraps.
pub const PRIVACY_PROOF_MANAGED_POOL_BOOTSTRAP_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:proof-managed-pool-bootstrap:v1";
/// Domain separator for the ledger index of one complete FCMP++ `(O, I, C)` tuple.
///
/// This identifier is never substituted for the tuple in the curve tree or
/// membership relation.
pub const PRIVACY_FCMP_OUTPUT_ID_DOMAIN_V1: &[u8] =
    b"iroha.privacy.monero-fcmp-plus-plus.output-id.v1";
/// Domain separator for the shared root-history commitment to a typed FCMP++
/// Selene/Helios root.
pub const PRIVACY_FCMP_ROOT_COMMITMENT_DOMAIN_V1: &[u8] =
    b"iroha.privacy.monero-fcmp-plus-plus.root-commitment.v1";
/// Domain separator used to hash canonical [`PrivacyPgcAccountBootstrapV1`] payloads.
pub const PRIVACY_PGC_ACCOUNT_BOOTSTRAP_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:pgc-account-bootstrap:v1";
/// Domain separator used to hash canonical Anonymous PGC bootstrap proof bytes.
pub const PRIVACY_PGC_BOOTSTRAP_PROOF_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:pgc-bootstrap-proof:v1";
/// Domain separator for core's deterministic PGC account-state root derivation.
pub const PRIVACY_PGC_ACCOUNT_STATE_ROOT_DOMAIN_V1: &[u8] =
    b"iroha:privacy:pgc-account-state-root:v1";
/// Domain separator for the exact private-IVM action selected by a statement.
pub const IVM_PRIVATE_NOTE_ACTION_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:ivm-private-note:action:v1";
/// Domain separator for canonical Bootle/Lantern issuer-policy record digests.
pub const BOOTLE_LANTERN_ISSUER_POLICY_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:bootle-lantern:issuer-policy:v1";
/// Domain separator for the exact Bootle/Lantern issuer verification matrix.
pub const BOOTLE_LANTERN_ISSUER_PARAMETER_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:bootle-lantern:issuer-parameter:v1";
/// Domain separator for canonical Vega issuer-key/policy revision self-digests.
pub const VEGA_ISSUER_RECORD_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:vega:issuer-record:v1";
/// Domain for canonical length-delimited Vega issuer-record hashing.
pub const VEGA_ISSUER_RECORD_HASH_FRAME_DOMAIN_V1: &[u8] =
    b"iroha.privacy.vega.issuer-record.sha256-frame.v1";
/// Implicit version committed by every Vega issuer governance record.
pub const VEGA_ISSUER_GOVERNANCE_RECORD_VERSION_V1: u16 = 1;
/// Domain separator for canonical ZK-AMS Personhood Credential hashes.
pub const ZK_AMS_PHC_HASH_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-ams:phc:v1";
/// Domain separator for canonical ZK-AMS issuer-policy records.
pub const ZK_AMS_ISSUER_POLICY_RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-ams:issuer-policy-record:v1";
/// Domain separator for canonical ZK-AMS registry-snapshot records.
pub const ZK_AMS_REGISTRY_RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-ams:registry-record:v1";
/// Domain separator for canonical ZK-AMS registry bootstrap provenance.
pub const ZK_AMS_REGISTRY_BOOTSTRAP_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-ams:registry-bootstrap:v1";
/// Domain separator for canonical authoritative ZK-ACE policy records.
pub const ZK_ACE_POLICY_RECORD_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-ace:policy-record:v1";
/// Domain separator for canonical X.509 trust-anchor revision self-digests.
pub const ZK_X509_TRUST_ANCHOR_RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:trust-anchor-record:v1";
/// Domain separator for canonical X.509 certificate-policy revision self-digests.
pub const ZK_X509_CERTIFICATE_POLICY_RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:certificate-policy-record:v1";
/// Domain separator for canonical signed-CRL revision self-digests.
pub const ZK_X509_CRL_RECORD_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:crl-record:v1";
/// Domain for canonical SHA-256 field framing in the X.509 relation.
pub const ZK_X509_HASH_FRAME_DOMAIN_V1: &[u8] = b"iroha.zk-x509.sha256.frame.v1";
/// Domain for the exact signed DER CRL digest.
pub const ZK_X509_CRL_DER_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-x509.crl.der.v1";
/// Domain for the exact CRL issuer-SPKI digest.
pub const ZK_X509_CRL_ISSUER_SPKI_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-x509.crl.issuer-spki.v1";
/// Implicit version committed by every X.509 governance-record digest.
pub const ZK_X509_GOVERNANCE_RECORD_VERSION_V1: u16 = 1;
/// Maximum privacy actions admitted in one Taira transaction.
pub const TAIRA_PRIVACY_MAX_ACTIONS_PER_TRANSACTION_V1: u32 = 1;
/// Maximum privacy actions admitted in one Taira block.
pub const TAIRA_PRIVACY_MAX_ACTIONS_PER_BLOCK_V1: u32 = 2;
/// Maximum proof payload bytes admitted for one Taira privacy action.
pub const TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1: u32 = 9 * 1024 * 1024;
/// Maximum canonical bytes admitted for one Anonymous PGC bootstrap proof.
pub const TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1: u32 = 4 * 1024 * 1024;
/// The only account-state epoch admitted for an Anonymous PGC bootstrap.
///
/// Successor proofs advance this epoch by exactly one. Keeping the origin
/// fixed prevents governance or a caller from creating ambiguous histories.
pub const PRIVACY_PGC_BOOTSTRAP_INITIAL_EPOCH_V1: u64 = 1;
/// The sole initial epoch for a node-derived Orchard empty frontier.
pub const PRIVACY_ORCHARD_POOL_INITIAL_EPOCH_V1: u64 = 1;
/// The only authorization epoch admitted for a new ZK-ACE policy.
pub const PRIVACY_ZK_ACE_POLICY_INITIAL_EPOCH_V1: u64 = 1;
/// Maximum number of source accounts in one authoritative ZK-ACE policy.
pub const PRIVACY_ZK_ACE_MAX_SOURCE_ACCOUNTS_V1: usize = 256;
/// Maximum number of authoritative ZK-ACE policy lineages in world state.
pub const PRIVACY_ZK_ACE_MAX_POLICIES_V1: usize = 4_096;
/// Fixed identifier and canonical framing allowance beyond a proof and its whole statement.
///
/// Current closed protocol layouts, including the additional ZK-AMS discriminant, are
/// measured against this allowance. It never increases the native proof payload ceiling.
pub const TAIRA_PRIVACY_PROOF_ENVELOPE_METADATA_ALLOWANCE_BYTES_V1: u32 = 512;
/// Maximum encoded bytes admitted for one Taira privacy action.
///
/// The complete canonical envelope carries one ceiling proof, the bounded whole statement
/// (including encrypted outputs), and 512 bytes for fixed identifiers and Norito framing.
/// The signed transaction independently remains bounded by its 10 MiB aggregate cap. The
/// 1 MiB between the proof ceiling and that cap holds the required context of a ceiling-proof
/// transaction: up to the committed `max_signatures` signers of any supported algorithm with
/// their authority, this envelope's statement and allowance, the authority fee intent with its
/// Nexus and `PipelineGas` charge limits, the lifetime and nonce, the `tx_sequence` and
/// `expires_at_height` metadata that the governed `require_sequence` and `require_height_ttl`
/// flags make mandatory, and the Submit and transaction framing. Resource coherence
/// (`validate_privacy_action_context`) refuses committed parameters under which one maximal
/// action and this context no longer fit the transaction cap. Larger multisig member sets and
/// other transaction metadata share the same cap with no promise that a ceiling proof still
/// fits. `tests/maximum_proof_transport_v1.rs` measures these transport sizes and derives the
/// context terms; they are not the widths of any native proof catalog.
pub const TAIRA_PRIVACY_MAX_ACTION_BYTES_V1: u32 = TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1
    + TAIRA_PRIVACY_MAX_STATEMENT_AND_ENCRYPTED_OUTPUT_BYTES_PER_TRANSACTION_V1
    + TAIRA_PRIVACY_PROOF_ENVELOPE_METADATA_ALLOWANCE_BYTES_V1;
/// Maximum privacy bytes admitted in one Taira transaction.
pub const TAIRA_PRIVACY_MAX_BYTES_PER_TRANSACTION_V1: u32 = TAIRA_PRIVACY_MAX_ACTION_BYTES_V1;
/// Maximum privacy bytes admitted in one Taira block.
///
/// Action count and actual aggregate bytes are independent bounds: two smaller actions
/// can fit, while two ceiling-sized envelopes cannot. Complete block framing has its own
/// payload limit and retains the non-transaction reserve.
pub const TAIRA_PRIVACY_MAX_BYTES_PER_BLOCK_V1: u32 =
    16 * 1024 * 1024 - crate::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
/// Maximum public-statement and encrypted-output payload bytes in one Taira transaction.
pub const TAIRA_PRIVACY_MAX_STATEMENT_AND_ENCRYPTED_OUTPUT_BYTES_PER_TRANSACTION_V1: u32 =
    256 * 1024;
/// Maximum nullifiers admitted for one Taira privacy action.
pub const TAIRA_PRIVACY_MAX_NULLIFIERS_PER_ACTION_V1: u32 = 8;
/// Maximum commitments admitted for one Taira privacy action.
pub const TAIRA_PRIVACY_MAX_COMMITMENTS_PER_ACTION_V1: u32 = 8;
/// Number of recent privacy roots retained by the Taira first-release profile.
pub const TAIRA_PRIVACY_RETAINED_ROOT_COUNT_V1: u32 = 2_048;
/// Canonical first-release privacy protocol identity.
///
/// Variant order is part of the Norito wire contract. New protocols require a
/// new data-model release; unknown discriminants are rejected.
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
#[norito(tag = "protocol", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyProtocolIdV1")]
pub enum PrivacyProtocolIdV1 {
    /// Native ZK-ACE post-quantum authorization protocol v1.
    #[norito(rename = "zk-ace-pq-authorization-v1")]
    ZkAcePqAuthorizationV1,
    /// Anonymous PGC k-out-of-n payment protocol v1.
    #[norito(rename = "anonymous-pgc-k-out-of-n-v1")]
    AnonymousPgcKOutOfNV1,
    /// `VeRange` transparent range-proof protocol v1.
    #[norito(rename = "verange-transparent-range-v1")]
    VeRangeTransparentRangeV1,
    /// Native Iroha ZK-AMS admission and anonymous-account provisioning suite v1.
    #[norito(rename = "iroha-zk-ams-v1")]
    IrohaZkAmsV1,
    /// Vega proof over an existing credential v1.
    #[norito(rename = "vega-existing-credential-zk-v1")]
    VegaExistingCredentialZkV1,
    /// Native Iroha P-256 X.509 predicate STARK protocol v1.
    #[norito(rename = "iroha-zk-x509-stark-p256-v1")]
    IrohaZkX509StarkP256V1,
    /// Native Iroha Jindo batched univariate lattice polynomial-commitment protocol v1.
    #[norito(rename = "iroha-jindo-polynomial-commitment-v1")]
    IrohaJindoPolynomialCommitmentV1,
    /// Native Bootle Lantern/LNP22 module-lattice anonymous credential v1.
    #[norito(rename = "iroha-bootle-lantern-anoncred-v1")]
    IrohaBootleLanternAnoncredV1,
    /// Orchard Halo2 action protocol v1.
    #[norito(rename = "orchard-halo2-actions-v1")]
    OrchardHalo2ActionsV1,
    /// Monero FCMP++ full-chain membership protocol v1.
    #[norito(rename = "monero-fcmp-plus-plus-v1")]
    MoneroFcmpPlusPlusV1,
    /// Native IVM private-note STARK protocol v1.
    #[norito(rename = "iroha-ivm-private-note-stark-v1")]
    IrohaIvmPrivateNoteStarkV1,
    /// Post-quantum MASP STARK protocol v1.
    #[norito(rename = "pq-masp-stark-v1")]
    PqMaspStarkV1,
}
/// Overall security model claimed by a final first-release privacy protocol.
///
/// This records the weakest primitive in the complete protocol composition.
/// A post-quantum STARK component therefore does not upgrade a protocol that
/// also depends on P-256, Pasta, or another classical primitive.
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
#[norito(tag = "security_model", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacySecurityModelV1")]
pub enum PrivacySecurityModelV1 {
    /// Post-quantum security in the quantum random-oracle model.
    #[norito(rename = "pq-qrom")]
    PostQuantumQrom,
    /// Classical security in the random-oracle model.
    #[norito(rename = "classical-rom")]
    ClassicalRom,
}

impl PrivacySecurityModelV1 {
    /// Exact label committed by the final Exact12 catalog.
    #[must_use]
    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::PostQuantumQrom => "pq-qrom",
            Self::ClassicalRom => "classical-rom",
        }
    }
}
impl PrivacyProtocolIdV1 {
    /// Number of protocols in the closed first-release registry.
    pub const COUNT: usize = 12;
    /// Every protocol in canonical Norito discriminant order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::ZkAcePqAuthorizationV1,
        Self::AnonymousPgcKOutOfNV1,
        Self::VeRangeTransparentRangeV1,
        Self::IrohaZkAmsV1,
        Self::VegaExistingCredentialZkV1,
        Self::IrohaZkX509StarkP256V1,
        Self::IrohaJindoPolynomialCommitmentV1,
        Self::IrohaBootleLanternAnoncredV1,
        Self::OrchardHalo2ActionsV1,
        Self::MoneroFcmpPlusPlusV1,
        Self::IrohaIvmPrivateNoteStarkV1,
        Self::PqMaspStarkV1,
    ];
    /// Exact external identifier used by SDK catalogs, governance tooling, and
    /// the BOI Privacy Lab.
    ///
    /// These labels are part of the first-release contract. Callers must not
    /// trim, case-fold, normalize, or accept aliases for them.
    #[must_use]
    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::ZkAcePqAuthorizationV1 => "zk-ace-pq-authorization-v1",
            Self::AnonymousPgcKOutOfNV1 => "anonymous-pgc-k-out-of-n-v1",
            Self::VeRangeTransparentRangeV1 => "verange-transparent-range-v1",
            Self::IrohaZkAmsV1 => "iroha-zk-ams-v1",
            Self::VegaExistingCredentialZkV1 => "vega-existing-credential-zk-v1",
            Self::IrohaZkX509StarkP256V1 => "iroha-zk-x509-stark-p256-v1",
            Self::IrohaJindoPolynomialCommitmentV1 => "iroha-jindo-polynomial-commitment-v1",
            Self::IrohaBootleLanternAnoncredV1 => "iroha-bootle-lantern-anoncred-v1",
            Self::OrchardHalo2ActionsV1 => "orchard-halo2-actions-v1",
            Self::MoneroFcmpPlusPlusV1 => "monero-fcmp-plus-plus-v1",
            Self::IrohaIvmPrivateNoteStarkV1 => "iroha-ivm-private-note-stark-v1",
            Self::PqMaspStarkV1 => "pq-masp-stark-v1",
        }
    }
    /// Exact Norito statement/proof variant label carried by the first-release
    /// cross-SDK matrix.
    ///
    /// Statement and proof envelopes deliberately use the same closed variant
    /// name for each protocol. Keeping this mapping next to the canonical
    /// protocol identifier lets release tooling validate the complete matrix
    /// without maintaining a second, drift-prone list.
    #[must_use]
    pub const fn canonical_typed_variant_label(self) -> &'static str {
        match self {
            Self::ZkAcePqAuthorizationV1 => "ZkAcePqAuthorizationV1",
            Self::AnonymousPgcKOutOfNV1 => "AnonymousPgcKOutOfNV1",
            Self::VeRangeTransparentRangeV1 => "VeRangeTransparentRangeV1",
            Self::IrohaZkAmsV1 => "IrohaZkAmsV1",
            Self::VegaExistingCredentialZkV1 => "VegaExistingCredentialZkV1",
            Self::IrohaZkX509StarkP256V1 => "IrohaZkX509StarkP256V1",
            Self::IrohaJindoPolynomialCommitmentV1 => "IrohaJindoPolynomialCommitmentV1",
            Self::IrohaBootleLanternAnoncredV1 => "IrohaBootleLanternAnoncredV1",
            Self::OrchardHalo2ActionsV1 => "OrchardHalo2ActionsV1",
            Self::MoneroFcmpPlusPlusV1 => "MoneroFcmpPlusPlusV1",
            Self::IrohaIvmPrivateNoteStarkV1 => "IrohaIvmPrivateNoteStarkV1",
            Self::PqMaspStarkV1 => "PqMaspStarkV1",
        }
    }
    /// Parse one exact first-release external identifier.
    ///
    /// Returns `None` for aliases, retired identifiers, and non-canonical
    /// spellings.
    #[must_use]
    pub const fn from_canonical_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"zk-ace-pq-authorization-v1" => Some(Self::ZkAcePqAuthorizationV1),
            b"anonymous-pgc-k-out-of-n-v1" => Some(Self::AnonymousPgcKOutOfNV1),
            b"verange-transparent-range-v1" => Some(Self::VeRangeTransparentRangeV1),
            b"iroha-zk-ams-v1" => Some(Self::IrohaZkAmsV1),
            b"vega-existing-credential-zk-v1" => Some(Self::VegaExistingCredentialZkV1),
            b"iroha-zk-x509-stark-p256-v1" => Some(Self::IrohaZkX509StarkP256V1),
            b"iroha-jindo-polynomial-commitment-v1" => Some(Self::IrohaJindoPolynomialCommitmentV1),
            b"iroha-bootle-lantern-anoncred-v1" => Some(Self::IrohaBootleLanternAnoncredV1),
            b"orchard-halo2-actions-v1" => Some(Self::OrchardHalo2ActionsV1),
            b"monero-fcmp-plus-plus-v1" => Some(Self::MoneroFcmpPlusPlusV1),
            b"iroha-ivm-private-note-stark-v1" => Some(Self::IrohaIvmPrivateNoteStarkV1),
            b"pq-masp-stark-v1" => Some(Self::PqMaspStarkV1),
            _ => None,
        }
    }
    /// Overall security model of the complete protocol composition.
    #[must_use]
    pub const fn security_model(self) -> PrivacySecurityModelV1 {
        match self {
            Self::ZkAcePqAuthorizationV1
            | Self::IrohaJindoPolynomialCommitmentV1
            | Self::IrohaBootleLanternAnoncredV1
            | Self::IrohaIvmPrivateNoteStarkV1
            | Self::PqMaspStarkV1 => PrivacySecurityModelV1::PostQuantumQrom,
            Self::AnonymousPgcKOutOfNV1
            | Self::VeRangeTransparentRangeV1
            | Self::IrohaZkAmsV1
            | Self::VegaExistingCredentialZkV1
            | Self::IrohaZkX509StarkP256V1
            | Self::OrchardHalo2ActionsV1
            | Self::MoneroFcmpPlusPlusV1 => PrivacySecurityModelV1::ClassicalRom,
        }
    }
    /// Exact proof system required by this protocol.
    #[must_use]
    pub const fn expected_proof_system(self) -> PrivacyProofSystemIdV1 {
        match self {
            Self::ZkAcePqAuthorizationV1
            | Self::IrohaZkX509StarkP256V1
            | Self::IrohaIvmPrivateNoteStarkV1
            | Self::PqMaspStarkV1 => PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks,
            Self::IrohaBootleLanternAnoncredV1 => {
                PrivacyProofSystemIdV1::LanternLnp22ModuleLinearNorm
            }
            Self::IrohaZkAmsV1 => {
                PrivacyProofSystemIdV1::ZkAmsMaskedRelaxedSpartanT256Ristretto255Sha3_512
            }
            Self::AnonymousPgcKOutOfNV1 => PrivacyProofSystemIdV1::AnonymousPgcP256,
            Self::VeRangeTransparentRangeV1 => PrivacyProofSystemIdV1::IrohaVeRangeP256,
            Self::VegaExistingCredentialZkV1 => {
                PrivacyProofSystemIdV1::VegaNeutronNovaSpartanHyraxT256
            }
            Self::IrohaJindoPolynomialCommitmentV1 => {
                PrivacyProofSystemIdV1::JindoPolynomialCommitment
            }
            Self::OrchardHalo2ActionsV1 => PrivacyProofSystemIdV1::Halo2IpaPasta,
            Self::MoneroFcmpPlusPlusV1 => PrivacyProofSystemIdV1::FcmpPlusPlusCurveTreeBulletproofs,
        }
    }
    /// Exact native verifier engine required by this protocol.
    #[must_use]
    pub const fn expected_engine(self) -> PrivacyEngineIdV1 {
        match self {
            Self::ZkAcePqAuthorizationV1
            | Self::IrohaZkX509StarkP256V1
            | Self::IrohaIvmPrivateNoteStarkV1
            | Self::PqMaspStarkV1 => PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri,
            Self::IrohaBootleLanternAnoncredV1 => PrivacyEngineIdV1::NativeLanternLnp22,
            Self::IrohaZkAmsV1 => {
                PrivacyEngineIdV1::NativeZkAmsMaskedRelaxedSpartanT256Ristretto255
            }
            Self::AnonymousPgcKOutOfNV1 => PrivacyEngineIdV1::NativeAnonymousPgcP256,
            Self::VeRangeTransparentRangeV1 => PrivacyEngineIdV1::NativeVeRangeP256,
            Self::VegaExistingCredentialZkV1 => PrivacyEngineIdV1::NativeVega,
            Self::IrohaJindoPolynomialCommitmentV1 => PrivacyEngineIdV1::NativeJindo,
            Self::OrchardHalo2ActionsV1 => PrivacyEngineIdV1::NativeHalo2Orchard,
            Self::MoneroFcmpPlusPlusV1 => PrivacyEngineIdV1::NativeFcmpPlusPlus,
        }
    }
}
#[cfg(any(test, feature = "privacy-exact12-conformance"))]
pub use exact12_fixture::{
    PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1, PrivacyActionRoleSampleV1,
    PrivacyExact12FixtureBundleV1, PrivacyExact12FixtureBundleValidationStatusV1,
    PrivacyExact12FixtureErrorV1, PrivacyExact12TypedEnvelopeRowV1,
    PrivacyExact12TypedFixtureRowV1, privacy_action_role_samples_v1,
    privacy_exact12_fixture_bundle_bytes_v1, privacy_exact12_fixture_bundle_v1,
    privacy_exact12_matrix_bytes_v1, privacy_exact12_typed_envelope_rows_v1,
    validate_privacy_exact12_fixture_bundle_v1,
};
/// Return whether `label` is an exact member of the first-release privacy catalog.
///
/// This predicate deliberately performs no trimming, normalization, alias
/// matching, or recognition of pre-release identifiers.
#[must_use]
pub fn privacy_protocol_label_is_exact12_v1(label: &str) -> bool {
    PrivacyProtocolIdV1::from_canonical_label(label).is_some()
}
/// Exact proof-system profile selected by a privacy protocol.
///
/// This is intentionally distinct from [`PrivacyProtocolIdV1`] because several
/// protocols can share one proof system without becoming interchangeable.
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
#[norito(tag = "proof_system", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyProofSystemIdV1")]
pub enum PrivacyProofSystemIdV1 {
    /// SHA3-384 outer commitments and transcript with STARK/FRI over Goldilocks.
    #[norito(rename = "stark-fri-sha3-384-goldilocks-v1")]
    StarkFriSha3_384Goldilocks,
    /// ZK-AMS masked relaxed-R1CS admission plus Ristretto255 possession and LSAG.
    ///
    /// Batch admission uses Poseidon2/Goldilocks commitment digests and a
    /// transparent STARK/FRI proof. Account provisioning uses MLSAGS over
    /// Ristretto255 with SHA3-512 for the transcript and hash-to-group suite.
    #[norito(rename = "zk-ams-masked-relaxed-spartan-t256-ristretto255-sha3-512")]
    ZkAmsMaskedRelaxedSpartanT256Ristretto255Sha3_512,
    /// Anonymous PGC k-out-of-n proof system over P-256.
    #[norito(rename = "anonymous-pgc-p256")]
    AnonymousPgcP256,
    /// Iroha Type-1 `VeRange` profile over P-256 with SHA-256.
    ///
    /// This profile is distinct from the upstream BN254-and-Keccak reference.
    #[norito(rename = "iroha-verange-p256")]
    IrohaVeRangeP256,
    /// Vega Neutron/Nova/Spartan proof system with Hyrax commitments over T256.
    #[norito(rename = "vega-neutron-nova-spartan-hyrax-t256")]
    VegaNeutronNovaSpartanHyraxT256,
    /// Jindo batched univariate lattice polynomial-commitment proof system.
    #[norito(rename = "jindo-polynomial-commitment")]
    JindoPolynomialCommitment,
    /// Halo2 IPA proof system over the Pasta curve cycle.
    #[norito(rename = "halo2-ipa-pasta")]
    Halo2IpaPasta,
    /// FCMP++ Curve Tree and Bulletproofs proof composition.
    #[norito(rename = "fcmp-plus-plus-curve-tree-bulletproofs")]
    FcmpPlusPlusCurveTreeBulletproofs,
    /// Bootle Lantern/LNP22 module-lattice linear-and-norm proof system.
    #[norito(rename = "lantern-lnp22-module-linear-norm")]
    LanternLnp22ModuleLinearNorm,
}
/// Native verifier engine implementation selected by a privacy protocol.
///
/// Engine identity binds the pinned final Rust implementation
/// independently of the mathematical proof-system profile.
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
#[norito(tag = "engine", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyEngineIdV1")]
pub enum PrivacyEngineIdV1 {
    /// Native Goldilocks STARK/FRI verifier with the SHA3-384 outer byte suite.
    #[norito(rename = "native-goldilocks-sha3-384-stark-fri-v1")]
    NativeGoldilocksSha3_384StarkFri,
    /// Native ZK-AMS masked relaxed-R1CS and Ristretto255 verifier suite.
    #[norito(rename = "native-zk-ams-masked-relaxed-spartan-t256-ristretto255")]
    NativeZkAmsMaskedRelaxedSpartanT256Ristretto255,
    /// Native Anonymous PGC verifier over P-256.
    #[norito(rename = "native-anonymous-pgc-p256")]
    NativeAnonymousPgcP256,
    /// Native `VeRange` verifier over P-256.
    #[norito(rename = "native-verange-p256")]
    NativeVeRangeP256,
    /// Native Vega verifier.
    #[norito(rename = "native-vega")]
    NativeVega,
    /// Native Jindo verifier.
    #[norito(rename = "native-jindo")]
    NativeJindo,
    /// Native Orchard Halo2 verifier.
    #[norito(rename = "native-halo2-orchard")]
    NativeHalo2Orchard,
    /// Native FCMP++ verifier.
    #[norito(rename = "native-fcmp-plus-plus")]
    NativeFcmpPlusPlus,
    /// Native Bootle Lantern/LNP22 module-lattice verifier.
    #[norito(rename = "native-lantern-lnp22")]
    NativeLanternLnp22,
}
/// Validated first-release privacy proof wire marker.
///
/// Its field is private and both Norito and JSON decoders compare all eight
/// bytes to [`PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1`]. This makes pre-release
/// envelopes fail while decoding, before an ordinal can be interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyProofWireMagicV1")]
pub struct PrivacyProofWireMagicV1([u8; 8]);

impl PrivacyProofWireMagicV1 {
    /// Return the sole valid first-release marker.
    #[must_use]
    pub const fn canonical() -> Self {
        Self(PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1)
    }

    /// Borrow the exact marker bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    fn from_bytes(bytes: [u8; 8]) -> Option<Self> {
        (bytes == PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1).then_some(Self(bytes))
    }
}

impl Default for PrivacyProofWireMagicV1 {
    fn default() -> Self {
        Self::canonical()
    }
}

impl norito::core::SerializePayload for PrivacyProofWireMagicV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1.len())
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        Some(PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1.len())
    }
}

impl<'de> norito::core::DeserializePayload<'de> for PrivacyProofWireMagicV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical privacy proof wire magic")
    }

    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<
            { PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1.len() },
        >(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Self::from_bytes(bytes).ok_or_else(|| {
            norito::core::Error::Message("invalid first-release privacy proof wire magic".into())
        })
    }
}

impl<'de> norito::core::DecodeFromSlice<'de> for PrivacyProofWireMagicV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let raw = bytes
            .get(..PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1.len())
            .ok_or(norito::core::Error::LengthMismatch)?;
        let mut magic = [0_u8; PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1.len()];
        magic.copy_from_slice(raw);
        let used = PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1.len();
        norito::core::note_payload_access(bytes, used);
        Self::from_bytes(magic)
            .map(|value| (value, used))
            .ok_or_else(|| {
                norito::core::Error::Message(
                    "invalid first-release privacy proof wire magic".into(),
                )
            })
    }
}

impl norito::json::FastJsonWrite for PrivacyProofWireMagicV1 {
    fn write_json(&self, out: &mut String) {
        crate::json_helpers::fixed_bytes::serialize(&self.0, out);
    }

    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        crate::json_helpers::fixed_bytes::serialize_bounded(&self.0, out)
    }
}

impl norito::json::JsonDeserialize for PrivacyProofWireMagicV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let bytes = crate::json_helpers::fixed_bytes::deserialize(parser)?;
        Self::from_bytes(bytes).ok_or_else(|| {
            norito::json::Error::Message(
                "invalid first-release privacy proof wire magic".to_owned(),
            )
        })
    }
}

/// Canonical 384-bit native-STARK digest encoded as six little-endian
/// Goldilocks field elements.
///
/// Construction and every decoder reject words greater than or equal to the
/// Goldilocks modulus. Keeping the words private prevents callers from
/// manufacturing a non-canonical wire value after validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::GoldilocksDigest384V1")]
pub struct GoldilocksDigest384V1([u8; fastpq_isi::GOLDILOCKS_DIGEST384_BYTES_V1]);

impl Default for GoldilocksDigest384V1 {
    fn default() -> Self {
        Self([0; fastpq_isi::GOLDILOCKS_DIGEST384_BYTES_V1])
    }
}

impl GoldilocksDigest384V1 {
    /// Canonical encoded byte length.
    pub const BYTES: usize = fastpq_isi::GOLDILOCKS_DIGEST384_BYTES_V1;

    /// Construct from six canonical Goldilocks field elements.
    #[must_use]
    pub fn new(words: [u64; fastpq_isi::GOLDILOCKS_DIGEST384_LANES_V1]) -> Option<Self> {
        fastpq_isi::GoldilocksDigest384V1::new(words).map(|digest| Self(digest.to_le_bytes()))
    }

    /// Decode six canonical little-endian Goldilocks field elements.
    #[must_use]
    pub fn from_le_bytes(bytes: [u8; Self::BYTES]) -> Option<Self> {
        fastpq_isi::GoldilocksDigest384V1::from_le_bytes(bytes).map(|_| Self(bytes))
    }

    /// Borrow the six canonical field elements in lane order.
    #[must_use]
    pub fn words(&self) -> [u64; fastpq_isi::GOLDILOCKS_DIGEST384_LANES_V1] {
        self.as_fastpq().words()
    }

    /// Consume the digest and return its canonical field elements.
    #[must_use]
    pub fn into_words(self) -> [u64; fastpq_isi::GOLDILOCKS_DIGEST384_LANES_V1] {
        self.as_fastpq().words()
    }

    /// Encode the six words in canonical little-endian lane order.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; Self::BYTES] {
        self.0
    }

    /// Convert to the shared scalar digest representation.
    #[must_use]
    pub fn as_fastpq(self) -> fastpq_isi::GoldilocksDigest384V1 {
        fastpq_isi::GoldilocksDigest384V1::from_le_bytes(self.0)
            .expect("GoldilocksDigest384V1 preserves canonical construction")
    }
}

impl From<fastpq_isi::GoldilocksDigest384V1> for GoldilocksDigest384V1 {
    fn from(digest: fastpq_isi::GoldilocksDigest384V1) -> Self {
        Self(digest.to_le_bytes())
    }
}

impl AsRef<[u8; fastpq_isi::GOLDILOCKS_DIGEST384_BYTES_V1]> for GoldilocksDigest384V1 {
    fn as_ref(&self) -> &[u8; fastpq_isi::GOLDILOCKS_DIGEST384_BYTES_V1] {
        &self.0
    }
}

impl norito::core::SerializePayload for GoldilocksDigest384V1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::BYTES)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for GoldilocksDigest384V1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical GoldilocksDigest384V1 decode")
    }

    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<{ Self::BYTES }>(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Self::from_le_bytes(bytes).ok_or_else(|| {
            norito::core::Error::Message("non-canonical GoldilocksDigest384V1 field element".into())
        })
    }
}

impl<'de> norito::core::DecodeFromSlice<'de> for GoldilocksDigest384V1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let prefix = bytes
            .get(..Self::BYTES)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let mut encoded = [0_u8; Self::BYTES];
        encoded.copy_from_slice(prefix);
        let digest = Self::from_le_bytes(encoded).ok_or_else(|| {
            norito::core::Error::Message("non-canonical GoldilocksDigest384V1 field element".into())
        })?;
        norito::core::note_payload_access(bytes, Self::BYTES);
        Ok((digest, Self::BYTES))
    }
}

impl norito::json::FastJsonWrite for GoldilocksDigest384V1 {
    fn write_json(&self, out: &mut String) {
        crate::json_helpers::fixed_bytes::serialize(&self.to_le_bytes(), out);
    }

    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        crate::json_helpers::fixed_bytes::serialize_bounded(&self.to_le_bytes(), out)
    }
}

impl norito::json::JsonDeserialize for GoldilocksDigest384V1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let bytes = crate::json_helpers::fixed_bytes::deserialize(parser)?;
        Self::from_le_bytes(bytes).ok_or_else(|| {
            norito::json::Error::Message(
                "non-canonical GoldilocksDigest384V1 field element".to_owned(),
            )
        })
    }
}

macro_rules! define_zk_ace_digest384 {
    ($(#[$meta:meta])* $name:ident, $schema_name:literal) => {
        $(#[$meta])*
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = $schema_name)]
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            IntoSchema,
        )]
        #[repr(transparent)]
        pub struct $name(GoldilocksDigest384V1);

        impl $name {
            /// Construct from six canonical Goldilocks field elements.
            #[must_use]
            pub fn new(
                words: [u64; fastpq_isi::GOLDILOCKS_DIGEST384_LANES_V1],
            ) -> Option<Self> {
                GoldilocksDigest384V1::new(words).map(Self)
            }

            /// Wrap an already validated canonical six-lane digest.
            #[must_use]
            pub const fn from_digest(digest: GoldilocksDigest384V1) -> Self {
                Self(digest)
            }

            /// Decode six canonical little-endian Goldilocks field elements.
            #[must_use]
            pub fn from_le_bytes(bytes: [u8; GoldilocksDigest384V1::BYTES]) -> Option<Self> {
                GoldilocksDigest384V1::from_le_bytes(bytes).map(Self)
            }

            /// Borrow the canonical 48-byte lane encoding.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; GoldilocksDigest384V1::BYTES] {
                self.0.as_ref()
            }

            /// Consume this value and return its canonical 48-byte encoding.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; GoldilocksDigest384V1::BYTES] {
                self.0.to_le_bytes()
            }

            /// Return the validated six-lane digest.
            #[must_use]
            pub const fn digest(self) -> GoldilocksDigest384V1 {
                self.0
            }

            /// Return true only for the all-zero six-field sentinel.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.words().iter().all(|word| *word == 0)
            }
        }

impl norito::core::SerializePayload for $name {
            fn serialize(
                &self,
                writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), norito::core::Error> {
                norito::core::SerializePayload::serialize(&self.0, writer)
            }

            fn encoded_len_hint(&self) -> Option<usize> {
                Some(GoldilocksDigest384V1::BYTES)
            }

            fn encoded_len_exact(&self) -> Option<usize> {
                Some(GoldilocksDigest384V1::BYTES)
            }
        }

impl<'de> norito::core::DeserializePayload<'de> for $name {
            fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                Self::try_deserialize(archived).expect("canonical ZK-ACE digest decode")
            }

            fn try_deserialize(
                archived: &'de norito::core::Archived<Self>,
            ) -> Result<Self, norito::core::Error> {
                <GoldilocksDigest384V1 as norito::core::DeserializePayload>::try_deserialize(
                    archived.cast(),
                ).map(Self)
            }
        }

        impl<'de> norito::core::DecodeFromSlice<'de> for $name {
            fn decode_from_slice(
                bytes: &'de [u8],
            ) -> Result<(Self, usize), norito::core::Error> {
                <GoldilocksDigest384V1 as norito::core::DecodeFromSlice>::decode_from_slice(bytes)
                    .map(|(digest, used)| (Self(digest), used))
            }
        }


        impl norito::json::FastJsonWrite for $name {
            fn write_json(&self, out: &mut String) {
                norito::json::FastJsonWrite::write_json(&self.0, out);
            }

            fn write_json_to(
                &self,
                out: &mut dyn norito::json::JsonWriteSink,
            ) -> Result<(), norito::json::BoundedJsonError> {
                norito::json::FastJsonWrite::write_json_to(&self.0, out)
            }
        }


        impl norito::json::JsonDeserialize for $name {
            fn json_deserialize(
                parser: &mut norito::json::Parser<'_>,
            ) -> Result<Self, norito::json::Error> {
                GoldilocksDigest384V1::json_deserialize(parser).map(Self)
            }
        }
    };
}

define_zk_ace_digest384!(
    /// Canonical six-lane identity commitment used only by ZK-ACE.
    PrivacyZkAceIdentityCommitmentV1,
    "iroha_data_model::privacy::PrivacyZkAceIdentityCommitmentV1"
);
define_zk_ace_digest384!(
    /// Canonical six-lane replay nullifier used only by ZK-ACE.
    PrivacyZkAceReplayNullifierV1,
    "iroha_data_model::privacy::PrivacyZkAceReplayNullifierV1"
);

/// Pinned full native commitment to [`PRIVACY_EXACT12_CATALOG_PREIMAGE_V1`].
pub use iroha_crypto::privacy::PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1;

/// Recompute the Exact12 catalog through the sole canonical native frame owner.
///
/// This commits to all ordered protocol ordinals, labels and security models.
/// It does not establish the cryptographic qualification asserted by any row.
#[must_use]
pub fn compute_privacy_exact12_catalog_commitment_v1()
-> iroha_crypto::native_commitment::NativeCommitmentDigestV1 {
    use iroha_crypto::native_commitment::{NativeCommitmentDomainV1, NativeCommitmentFrameV1};
    NativeCommitmentFrameV1::new(
        NativeCommitmentDomainV1 {
            catalog: PRIVACY_EXACT12_CATALOG_ID_V1,
            protocol: b"privacy-exact12-catalog-v1",
            role: b"catalog",
            phase: b"commitment",
            level: 0,
            index: 0,
            counter: 0,
        },
        &[PRIVACY_EXACT12_CATALOG_PREIMAGE_V1],
    )
    .expect("the fixed Exact12 catalog preimage is within framing limits")
    .digest()
}

/// Validated full native commitment to the only first-release Exact12 catalog.
///
/// Every decoder requires the sole pinned 32-byte value. A proof envelope
/// cannot select a different catalog while retaining valid protocol ordinals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1")]
pub struct PrivacyExact12CatalogCommitmentV1([u8; 32]);

impl PrivacyExact12CatalogCommitmentV1 {
    /// Exact full native digest width; no marker, field reduction or truncation.
    pub const BYTES: usize = 32;

    /// Return the sole catalog commitment accepted by first-release nodes.
    #[must_use]
    pub const fn canonical() -> Self {
        Self(PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1)
    }

    /// Borrow every byte in native BLAKE3 output order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }

    fn from_bytes(bytes: [u8; Self::BYTES]) -> Option<Self> {
        (bytes == PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1).then_some(Self(bytes))
    }
}
impl Default for PrivacyExact12CatalogCommitmentV1 {
    fn default() -> Self {
        Self::canonical()
    }
}
impl norito::core::SerializePayload for PrivacyExact12CatalogCommitmentV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
}
impl<'de> norito::core::DeserializePayload<'de> for PrivacyExact12CatalogCommitmentV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical Exact12 catalog commitment")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<{ Self::BYTES }>(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Self::from_bytes(bytes).ok_or_else(|| {
            norito::core::Error::Message("unknown first-release Exact12 catalog commitment".into())
        })
    }
}
impl<'de> norito::core::DecodeFromSlice<'de> for PrivacyExact12CatalogCommitmentV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let raw = bytes
            .get(..Self::BYTES)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let mut value = [0; Self::BYTES];
        value.copy_from_slice(raw);
        let commitment = Self::from_bytes(value).ok_or_else(|| {
            norito::core::Error::Message("unknown first-release Exact12 catalog commitment".into())
        })?;
        norito::core::note_payload_access(bytes, Self::BYTES);
        Ok((commitment, Self::BYTES))
    }
}
impl norito::json::FastJsonWrite for PrivacyExact12CatalogCommitmentV1 {
    fn write_json(&self, out: &mut String) {
        crate::json_helpers::fixed_bytes::serialize(&self.0, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        crate::json_helpers::fixed_bytes::serialize_bounded(&self.0, out)
    }
}
impl norito::json::JsonDeserialize for PrivacyExact12CatalogCommitmentV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let bytes = crate::json_helpers::fixed_bytes::deserialize(parser)?;
        Self::from_bytes(bytes).ok_or_else(|| {
            norito::json::Error::Message(
                "unknown first-release Exact12 catalog commitment".to_owned(),
            )
        })
    }
}

macro_rules! define_privacy_digest {
    ($(#[$meta:meta])* $name:ident, $schema_name:literal) => {
        $(#[$meta])*
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = $schema_name)]
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
        )]
        #[repr(transparent)]
        #[norito(decode_from_slice)]
        #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
        pub struct $name(
            /// The exact 32-byte digest value.
            #[norito (json = "crate::json_helpers::fixed_bytes")]
            pub [u8; 32],
        );
        impl $name {
            /// Construct a digest from exactly 32 bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Borrow the exact digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            /// Consume the digest and return its exact bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
            /// Return `true` when every digest byte is zero.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }
        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self::new(bytes)
            }
        }
        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }
        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                self.as_bytes()
            }
        }
    };
}
define_privacy_digest!(
    /// Digest of the governed public parameter set for a protocol.
    PrivacyParameterDigestV1,
    "iroha_data_model::privacy::PrivacyParameterDigestV1"
);
define_privacy_digest!(
    /// Digest of the exact native verifier key or verifier artifact.
    PrivacyVerifierDigestV1,
    "iroha_data_model::privacy::PrivacyVerifierDigestV1"
);
define_privacy_digest!(
    /// Digest of the canonical public-statement schema.
    PrivacyStatementSchemaDigestV1,
    "iroha_data_model::privacy::PrivacyStatementSchemaDigestV1"
);
define_privacy_digest!(
    /// Digest of the exact native engine manifest.
    PrivacyEngineManifestDigestV1,
    "iroha_data_model::privacy::PrivacyEngineManifestDigestV1"
);
define_privacy_digest!(
    /// Self-digest of one canonical committed Exact12 capability manifest.
    PrivacyExact12CapabilityManifestDigestV1,
    "iroha_data_model::privacy::PrivacyExact12CapabilityManifestDigestV1"
);
define_privacy_digest!(
    /// Digest of one final protocol security-reduction artifact.
    PrivacySecurityReductionDigestV1,
    "iroha_data_model::privacy::PrivacySecurityReductionDigestV1"
);
define_privacy_digest!(
    /// Digest of one independently reviewed final protocol security claim.
    PrivacySecurityClaimDigestV1,
    "iroha_data_model::privacy::PrivacySecurityClaimDigestV1"
);
define_privacy_digest!(
    /// Digest of the portable final Exact12 release manifest.
    PrivacyExact12ReleaseManifestDigestV1,
    "iroha_data_model::privacy::PrivacyExact12ReleaseManifestDigestV1"
);
define_privacy_digest!(
    /// Digest of the network-bound four-validator deployment qualification.
    PrivacyExact12DeploymentQualificationDigestV1,
    "iroha_data_model::privacy::PrivacyExact12DeploymentQualificationDigestV1"
);
define_privacy_digest!(
    /// Digest of the complete independent audit and disposition bundle.
    PrivacyAuditBundleDigestV1,
    "iroha_data_model::privacy::PrivacyAuditBundleDigestV1"
);
define_privacy_digest!(
    /// Digest of one immutable source, build, proof, SDK, hardware, audit, or deployment artifact.
    PrivacyReleaseArtifactDigestV1,
    "iroha_data_model::privacy::PrivacyReleaseArtifactDigestV1"
);
define_privacy_digest!(
    /// Digest of a canonical protocol-specific public statement.
    PrivacyStatementDigestV1,
    "iroha_data_model::privacy::PrivacyStatementDigestV1"
);
define_privacy_digest!(
    /// Digest of the canonical transaction-intent projection bound by a privacy statement.
    PrivacyTransactionIntentDigestV1,
    "iroha_data_model::privacy::PrivacyTransactionIntentDigestV1"
);
define_privacy_digest!(
    /// Digest of the canonical chain, genesis, action, and governed-artifact binding
    /// consumed by a native privacy prover or verifier.
    PrivacyNativeConsensusBindingDigestV1,
    "iroha_data_model::privacy::PrivacyNativeConsensusBindingDigestV1"
);
define_privacy_digest!(
    /// Digest of a canonical governance root publication.
    PrivacyRootPublicationDigestV1,
    "iroha_data_model::privacy::PrivacyRootPublicationDigestV1"
);
define_privacy_digest!(
    /// Digest of one canonical governed Orchard pool bootstrap.
    PrivacyOrchardPoolBootstrapDigestV1,
    "iroha_data_model::privacy::PrivacyOrchardPoolBootstrapDigestV1"
);
define_privacy_digest!(
    /// Digest of one canonical governed FCMP++, private-IVM, or PQ-MASP pool bootstrap.
    PrivacyProofManagedPoolBootstrapDigestV1,
    "iroha_data_model::privacy::PrivacyProofManagedPoolBootstrapDigestV1"
);
define_privacy_digest!(
    /// Ledger-only identifier of one complete canonical FCMP++ `(O, I, C)` output tuple.
    PrivacyFcmpOutputIdV1,
    "iroha_data_model::privacy::PrivacyFcmpOutputIdV1"
);
define_privacy_digest!(
    /// Typed FCMP++ linkability key image `L` used by the durable replay registry.
    PrivacyFcmpKeyImageV1,
    "iroha_data_model::privacy::PrivacyFcmpKeyImageV1"
);
define_privacy_digest!(
    /// Digest of a canonical PGC account bootstrap payload.
    PrivacyPgcAccountBootstrapDigestV1,
    "iroha_data_model::privacy::PrivacyPgcAccountBootstrapDigestV1"
);
define_privacy_digest!(
    /// Digest of exact canonical Anonymous PGC bootstrap proof bytes.
    PrivacyPgcBootstrapProofDigestV1,
    "iroha_data_model::privacy::PrivacyPgcBootstrapProofDigestV1"
);
define_privacy_digest!(
    /// Fixed identifier of a governed privacy parameter set.
    PrivacyParameterIdV1,
    "iroha_data_model::privacy::PrivacyParameterIdV1"
);
define_privacy_digest!(
    /// Canonical replay-prevention nullifier emitted by a privacy action.
    PrivacyNullifierV1,
    "iroha_data_model::privacy::PrivacyNullifierV1"
);
define_privacy_digest!(
    /// Canonical output or account commitment emitted by a privacy action.
    PrivacyCommitmentV1,
    "iroha_data_model::privacy::PrivacyCommitmentV1"
);
define_privacy_digest!(
    /// Fixed identifier of a privacy pool or accumulator namespace.
    PrivacyPoolIdV1,
    "iroha_data_model::privacy::PrivacyPoolIdV1"
);
define_privacy_digest!(
    /// Fixed identifier of a ZK-AMS admitted-identity registry.
    PrivacyZkAmsRegistryIdV1,
    "iroha_data_model::privacy::PrivacyZkAmsRegistryIdV1"
);
define_privacy_digest!(
    /// Fixed identifier of a governed privacy policy.
    PrivacyPolicyIdV1,
    "iroha_data_model::privacy::PrivacyPolicyIdV1"
);
define_privacy_digest!(
    /// Digest of the governed contents of a privacy policy.
    PrivacyPolicyDigestV1,
    "iroha_data_model::privacy::PrivacyPolicyDigestV1"
);
define_privacy_digest!(
    /// Self-digest of one complete authoritative ZK-ACE policy record.
    PrivacyZkAcePolicyRecordDigestV1,
    "iroha_data_model::privacy::PrivacyZkAcePolicyRecordDigestV1"
);
define_privacy_digest!(
    /// Digest of one canonical committed Bootle/Lantern issuer-policy record.
    PrivacyBootleLanternIssuerPolicyDigestV1,
    "iroha_data_model::privacy::PrivacyBootleLanternIssuerPolicyDigestV1"
);
define_privacy_digest!(
    /// Fixed identifier of a credential or certificate issuer.
    PrivacyIssuerIdV1,
    "iroha_data_model::privacy::PrivacyIssuerIdV1"
);
define_privacy_digest!(
    /// Digest of one canonically encoded credential attribute.
    PrivacyAttributeDigestV1,
    "iroha_data_model::privacy::PrivacyAttributeDigestV1"
);
define_privacy_digest!(
    /// Reader or wallet challenge bound into a credential presentation.
    PrivacyChallengeV1,
    "iroha_data_model::privacy::PrivacyChallengeV1"
);
define_privacy_digest!(
    /// Digest of an ISO 18013-5 session transcript.
    PrivacySessionTranscriptDigestV1,
    "iroha_data_model::privacy::PrivacySessionTranscriptDigestV1"
);
define_privacy_digest!(
    /// Public SHA-256 device-authentication digest `H_dev` in Vega Figure 9.
    PrivacyVegaDeviceAuthenticationDigestV1,
    "iroha_data_model::privacy::PrivacyVegaDeviceAuthenticationDigestV1"
);
define_privacy_digest!(
    /// Self-digest of one complete authoritative Vega issuer-key/policy revision.
    PrivacyVegaIssuerRecordDigestV1,
    "iroha_data_model::privacy::PrivacyVegaIssuerRecordDigestV1"
);
define_privacy_digest!(
    /// Fixed cryptographic recipient identity used by an encrypted output.
    PrivacyRecipientIdV1,
    "iroha_data_model::privacy::PrivacyRecipientIdV1"
);
define_privacy_digest!(
    /// Fixed ephemeral public encryption key used by an encrypted output.
    PrivacyEncryptionKeyV1,
    "iroha_data_model::privacy::PrivacyEncryptionKeyV1"
);
define_privacy_digest!(
    /// Fixed identifier of a private IVM program.
    PrivacyProgramIdV1,
    "iroha_data_model::privacy::PrivacyProgramIdV1"
);
define_privacy_digest!(
    /// Digest of the exact private IVM action selected by a statement.
    PrivacyActionDigestV1,
    "iroha_data_model::privacy::PrivacyActionDigestV1"
);
define_privacy_digest!(
    /// Digest of a certificate subject public key.
    PrivacyCertificateKeyDigestV1,
    "iroha_data_model::privacy::PrivacyCertificateKeyDigestV1"
);
define_privacy_digest!(
    /// Digest of one canonical ordered RFC 5280 P-256/SHA-256 trust store.
    PrivacyX509TrustStoreDigestV1,
    "iroha_data_model::privacy::PrivacyX509TrustStoreDigestV1"
);
define_privacy_digest!(
    /// Self-digest of one immutable authoritative X.509 trust-anchor revision.
    PrivacyZkX509TrustAnchorRecordDigestV1,
    "iroha_data_model::privacy::PrivacyZkX509TrustAnchorRecordDigestV1"
);
define_privacy_digest!(
    /// Self-digest of one immutable authoritative X.509 certificate-policy revision.
    PrivacyZkX509CertificatePolicyRecordDigestV1,
    "iroha_data_model::privacy::PrivacyZkX509CertificatePolicyRecordDigestV1"
);
define_privacy_digest!(
    /// Domain-framed SHA-256 digest of one exact signed DER certificate-revocation list.
    PrivacyX509CrlDerDigestV1,
    "iroha_data_model::privacy::PrivacyX509CrlDerDigestV1"
);
define_privacy_digest!(
    /// Domain-framed SHA-256 digest of the exact SPKI that signs one governed CRL lineage.
    PrivacyX509CrlIssuerSpkiDigestV1,
    "iroha_data_model::privacy::PrivacyX509CrlIssuerSpkiDigestV1"
);
define_privacy_digest!(
    /// Self-digest of one immutable authoritative signed-CRL revision.
    PrivacyZkX509CrlRecordDigestV1,
    "iroha_data_model::privacy::PrivacyZkX509CrlRecordDigestV1"
);
impl PrivacyX509CrlDerDigestV1 {
    /// Hash the complete exact signed DER CRL with the canonical X.509 frame.
    #[must_use]
    pub fn digest_exact_der(der: &[u8]) -> Self {
        Self::new(privacy_zk_x509_sha256_frame_v1(
            ZK_X509_CRL_DER_DIGEST_DOMAIN_V1,
            &[der],
        ))
    }
}
impl PrivacyX509CrlIssuerSpkiDigestV1 {
    /// Hash the complete exact issuer SPKI DER with the canonical X.509 frame.
    #[must_use]
    pub fn digest_exact_der(spki_der: &[u8]) -> Self {
        Self::new(privacy_zk_x509_sha256_frame_v1(
            ZK_X509_CRL_ISSUER_SPKI_DIGEST_DOMAIN_V1,
            &[spki_der],
        ))
    }
}
define_privacy_digest!(
    /// Canonical commitment-tree or accumulator root.
    PrivacyRootV1,
    "iroha_data_model::privacy::PrivacyRootV1"
);
define_privacy_digest!(
    /// Digest of a post-quantum transaction authorization key.
    PrivacyAuthorizationKeyDigestV1,
    "iroha_data_model::privacy::PrivacyAuthorizationKeyDigestV1"
);
define_privacy_digest!(
    /// Digest of a post-quantum note-encryption key.
    PrivacyNoteEncryptionKeyDigestV1,
    "iroha_data_model::privacy::PrivacyNoteEncryptionKeyDigestV1"
);
define_privacy_digest!(
    /// Fixed 32-byte digest of one canonical Personhood Credential in ZK-AMS.
    PrivacyZkAmsPhcHashV1,
    "iroha_data_model::privacy::PrivacyZkAmsPhcHashV1"
);
define_privacy_digest!(
    /// Hidden subject commitment carried by a canonical ZK-AMS credential.
    PrivacyZkAmsSubjectCommitmentV1,
    "iroha_data_model::privacy::PrivacyZkAmsSubjectCommitmentV1"
);
define_privacy_digest!(
    /// Issuer-selected nonce making one canonical ZK-AMS credential unique.
    PrivacyZkAmsCredentialNonceV1,
    "iroha_data_model::privacy::PrivacyZkAmsCredentialNonceV1"
);
define_privacy_digest!(
    /// Digest of an authoritative ZK-AMS issuer-policy record.
    PrivacyZkAmsIssuerPolicyRecordDigestV1,
    "iroha_data_model::privacy::PrivacyZkAmsIssuerPolicyRecordDigestV1"
);
define_privacy_digest!(
    /// Digest of an authoritative ZK-AMS registry snapshot record.
    PrivacyZkAmsRegistryRecordDigestV1,
    "iroha_data_model::privacy::PrivacyZkAmsRegistryRecordDigestV1"
);
define_privacy_digest!(
    /// Digest of one canonical governed ZK-AMS registry bootstrap.
    PrivacyZkAmsRegistryBootstrapDigestV1,
    "iroha_data_model::privacy::PrivacyZkAmsRegistryBootstrapDigestV1"
);
macro_rules! define_ristretto255_encoding {
    ($(#[$meta:meta])* $name:ident, $schema_name:literal) => {
        $(#[$meta])*
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = $schema_name)]
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
        )]
        #[repr(transparent)]
        #[norito(decode_from_slice)]
        #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
        pub struct $name(
            /// Exact canonical compressed Ristretto255 encoding.
            #[norito (json = "crate::json_helpers::fixed_bytes")]
            pub [u8; 32],
        );
        impl $name {
            /// Construct from exactly 32 encoded bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Borrow the exact compressed bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            /// Return `true` for the all-zero sentinel encoding.
            ///
            /// The native engine additionally decodes the point, rejects
            /// non-canonical encodings, and rejects the group identity.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }
    };
}
define_ristretto255_encoding!(
    /// Canonical compressed Ristretto255 ZK-AMS seed public key.
    PrivacyZkAmsSeedPublicKeyV1,
    "iroha_data_model::privacy::PrivacyZkAmsSeedPublicKeyV1"
);
define_ristretto255_encoding!(
    /// Canonical compressed Ristretto255 MLSAGS key image.
    PrivacyZkAmsKeyImageV1,
    "iroha_data_model::privacy::PrivacyZkAmsKeyImageV1"
);
// Keep wire declarations in this public module so their Norito identities
// remain stable; validation implementations have focused private owners.
include!("privacy/protocol.rs");
mod action_role;
mod capability_manifest;
mod policy;
pub use action_role::PrivacyActionRoleV1;
pub use capability_manifest::*;
mod release_manifest;
pub use release_manifest::*;
mod zk_x509_interval;
pub use zk_x509_interval::*;
include!("privacy/credentials.rs");
include!("privacy/statements.rs");
include!("privacy/proofs.rs");
#[cfg(test)]
pub(crate) mod tests {
    include!("privacy/tests/protocol_and_proofs.rs");
    include!("privacy/tests/capability_manifest.rs");
    include!("privacy/tests/release_manifest.rs");
    include!("privacy/tests/namespaces_and_governance.rs");
    include!("privacy/tests/adversarial.rs");
}

#[cfg(test)]
mod captured_privacy_ordinary_schema_tests;

#[cfg(test)]
mod privacy_proof_wire_magic_raw_wire_tests {
    use super::*;

    #[test]
    fn privacy_proof_wire_magic_keeps_sole_raw_wire_and_zero_storage_charge() {
        #[repr(align(16))]
        struct Aligned([u8; 512]);
        let value = PrivacyProofWireMagicV1::canonical();
        let raw = *value.as_bytes();
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let mut encoded = Vec::new();
            norito::core::serialize_to_buffer(&value, &mut encoded).unwrap();
            assert_eq!(encoded, raw);
            let mut aligned = Aligned([0; 512]);
            aligned.0[..encoded.len()].copy_from_slice(&encoded);
            let bytes = &aligned.0[..encoded.len()];
            let zero = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                let _context = norito::core::PayloadCtxGuard::enter(bytes);
                let decoded =
                    norito::core::decode_field_canonical::<PrivacyProofWireMagicV1>(bytes)?;
                assert_eq!(
                    norito::core::payload_ctx(),
                    Some((bytes.as_ptr() as usize, bytes.len()))
                );
                Ok::<_, norito::Error>(decoded)
            });
            assert_eq!(decoded.unwrap(), (value, bytes.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            let mut alternate = Vec::new();
            norito::core::serialize_to_buffer(&raw, &mut alternate).unwrap();
            let mut extra = raw.to_vec();
            extra.push(0);
            for invalid in [&raw[..raw.len() - 1], &extra[..], &alternate[..]] {
                aligned.0[..invalid.len()].copy_from_slice(invalid);
                let bytes = &aligned.0[..invalid.len()];
                let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                    norito::core::decode_field_canonical::<PrivacyProofWireMagicV1>(bytes)
                });
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(usage.total_elements(), 0);
            }
        }
    }
}

#[cfg(test)]
mod goldilocks_digest_raw_wire_tests {
    use super::*;

    #[test]
    fn goldilocks_digest_keeps_sole_raw_wire_and_zero_storage_charge() {
        #[repr(align(16))]
        struct Aligned([u8; 512]);
        let value = GoldilocksDigest384V1::new([1, 2, 3, 4, 5, 6]).unwrap();
        let raw = value.to_le_bytes();
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let mut encoded = Vec::new();
            norito::core::serialize_to_buffer(&value, &mut encoded).unwrap();
            assert_eq!(encoded, raw);
            let mut aligned = Aligned([0; 512]);
            aligned.0[..encoded.len()].copy_from_slice(&encoded);
            let bytes = &aligned.0[..encoded.len()];
            let zero = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                let _context = norito::core::PayloadCtxGuard::enter(bytes);
                let decoded = norito::core::decode_field_canonical::<GoldilocksDigest384V1>(bytes)?;
                assert_eq!(
                    norito::core::payload_ctx(),
                    Some((bytes.as_ptr() as usize, bytes.len()))
                );
                Ok::<_, norito::Error>(decoded)
            });
            assert_eq!(decoded.unwrap(), (value, bytes.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            let mut alternate = Vec::new();
            norito::core::serialize_to_buffer(&raw, &mut alternate).unwrap();
            let mut extra = raw.to_vec();
            extra.push(0);
            for invalid in [&raw[..raw.len() - 1], &extra[..], &alternate[..]] {
                aligned.0[..invalid.len()].copy_from_slice(invalid);
                let bytes = &aligned.0[..invalid.len()];
                let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                    norito::core::decode_field_canonical::<GoldilocksDigest384V1>(bytes)
                });
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(usage.total_elements(), 0);
            }
        }
    }
}
