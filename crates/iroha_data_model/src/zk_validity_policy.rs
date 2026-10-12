//! Committed ZK validity policy of a chain.
//!
//! [`ZkValidityPolicyV1`] is the typed payload of the custom parameter
//! [`ZkValidityPolicyV1::PARAMETER_ID_STR`]. It carries every proof limit,
//! window, registry cap, relation-selecting verifying-key reference and
//! verification gas charge that validators must agree on. A chain installs it
//! with an ordinary authorized `SetParameter`, in genesis or later; a change
//! takes effect from the block after the one that commits it. A chain that
//! never installs the parameter uses [`ZkValidityPolicyV1::protocol_default`].
//!
//! This module owns the type, the protocol default and the canonical
//! structural and coherence validation, so genesis tools and SDKs author and
//! check a policy without a node. Applying a policy to State is Core's job.

use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    parameter::custom::{CustomParameter, CustomParameterId},
};

/// Largest value of a policy field that sizes an in-memory buffer or
/// collection.
///
/// It is a fixed protocol constant, independent of the pointer width of the
/// validator that checks it, so the same committed payload is valid on every
/// supported target.
pub const MAX_SIZE_FIELD: u64 = u32::MAX as u64;

/// Largest SCCP byte limit: the largest integer every JSON reader of an SCCP
/// V1 message represents exactly.
pub const MAX_EXACT_JSON_U64: u64 = crate::parliament_types::FIRST_RELEASE_MAX_EXACT_JSON_U64;

/// Why a ZK validity policy value is not a valid chain policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZkValidityPolicyError {
    /// The committed payload does not decode as the exact V1 policy.
    #[error("the ZK validity policy payload is not a canonical V1 policy: {0}")]
    Malformed(String),
    /// A field that must be positive is zero.
    #[error("ZK validity policy field `{0}` must be non-zero")]
    Zero(&'static str),
    /// A size field exceeds [`MAX_SIZE_FIELD`], or an SCCP byte limit exceeds
    /// [`MAX_EXACT_JSON_U64`].
    #[error("ZK validity policy field `{0}` exceeds the protocol maximum of the field")]
    OutOfRange(&'static str),
    /// A verifying-key reference is not one this release defines.
    #[error("ZK validity policy field `{0}` names an unsupported value `{1}`")]
    Unsupported(&'static str, String),
    /// Two fields contradict each other.
    #[error("ZK validity policy is incoherent: {0}")]
    Incoherent(&'static str),
}

macro_rules! policy_section {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$field_meta:meta])* $field:ident: $type:ty ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Encode,
            Decode,
            IntoSchema,
            DeriveJsonSerialize,
            DeriveJsonDeserialize,
        )]
        #[norito(deny_unknown_fields)]
        pub struct $name {
            $( $(#[$field_meta])* pub $field: $type, )+
        }

        impl $name {
            /// Names of the fields of this section, in declaration order.
            pub const FIELD_NAMES: &'static [&'static str] = &[ $( stringify!($field) ),+ ];

            /// Names of the fields whose values differ from `other`.
            fn differing_fields(&self, other: &Self, section: &'static str, out: &mut Vec<String>) {
                $(
                    if self.$field != other.$field {
                        out.push(format!("{section}.{}", stringify!($field)));
                    }
                )+
            }

            /// Copies of this section in which `field` alone holds another value.
            #[cfg(any(test, feature = "test-fixtures"))]
            fn perturbed(&self, field: &str, salt: u32) -> Vec<Self> {
                $(
                    if field == stringify!($field) {
                        return perturb::PolicyField::others(&self.$field, stringify!($field), salt)
                            .into_iter()
                            .map(|value| {
                                let mut section = self.clone();
                                section.$field = value;
                                section
                            })
                            .collect();
                    }
                )+
                Vec::new()
            }
        }
    };
}

/// Reference to a registered verifying key by backend and name.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ZkVerifyingKeyRefV1 {
    /// Backend identifier of the verifying key.
    pub backend: String,
    /// Name of the verifying key inside the backend namespace.
    pub name: String,
}

policy_section! {
    /// Native PIPA-R verification policy.
    #[derive(Copy)]
    ZkPipaRValidityV1 {
        /// Whether Native PIPA-R proofs are verified.
        // TODO(F.4): the plan author decided this switch is deleted (verification
        // always runs). It stays a committed field until the consensus-policy hash
        // and the pinned first-release history are regenerated in one declared cutover.
        enabled: bool,
        /// Largest accepted Norito envelope, in bytes.
        max_envelope_bytes: u64,
        /// Largest accepted proof payload, in bytes.
        max_proof_bytes: u64,
    }
}

policy_section! {
    /// Native STARK/FRI verification policy.
    #[derive(Copy)]
    ZkStarkValidityV1 {
        /// Whether native STARK proofs are verified.
        // TODO(F.4): deleted together with `pipa_r.enabled`; see there.
        enabled: bool,
        /// Largest accepted outer envelope, in bytes.
        max_envelope_bytes: u64,
        /// Largest accepted proof payload, in bytes.
        max_proof_bytes: u64,
    }
}

policy_section! {
    /// SCCP proof-admission and verifier-work limits.
    #[derive(Copy)]
    ZkSccpValidityV1 {
        /// Closed SCCP proofs in one transaction.
        max_proofs_per_transaction: u32,
        /// Closed SCCP proofs in one block.
        max_proofs_per_block: u32,
        /// Canonical bytes of one closed SCCP proof.
        max_proof_bytes_per_proof: u64,
        /// Aggregate SCCP proof bytes in one transaction.
        max_proof_bytes_per_transaction: u64,
        /// Aggregate SCCP proof bytes in one block.
        max_proof_bytes_per_block: u64,
        /// Native-finality continuation headers in one transaction.
        max_native_headers_per_transaction: u32,
        /// Native-finality continuation headers in one block.
        max_native_headers_per_block: u32,
        /// Ethereum light-client updates in one transaction.
        max_ethereum_light_client_updates_per_transaction: u32,
        /// Ethereum light-client updates in one block.
        max_ethereum_light_client_updates_per_block: u32,
        /// Native header bytes in one transaction.
        max_native_header_bytes_per_transaction: u64,
        /// Native header bytes in one block.
        max_native_header_bytes_per_block: u64,
        /// Ed25519 signature checks in one transaction.
        max_ed25519_signature_checks_per_transaction: u32,
        /// Ed25519 signature checks in one block.
        max_ed25519_signature_checks_per_block: u32,
        /// BLS vote attestations in one transaction.
        max_bls_vote_attestations_per_transaction: u32,
        /// BLS vote attestations in one block.
        max_bls_vote_attestations_per_block: u32,
    }
}

policy_section! {
    /// Proof record retention, bridge-proof windows and relation-selecting keys.
    ZkProofValidityV1 {
        /// Largest batch one verification call accepts.
        max_verify_batch: u32,
        /// Recent ballot ciphertexts kept per election.
        ballot_history_cap: u64,
        /// Largest proof accepted by stateless pre-verification, in bytes.
        preverify_max_bytes: u64,
        /// Byte budget of stateless pre-verification (0 = unlimited).
        preverify_budget_bytes: u64,
        /// Proof records retained per backend (0 = unlimited).
        proof_history_cap: u64,
        /// Blocks a proof record is retained regardless of the cap.
        proof_retention_grace_blocks: u64,
        /// Proof records pruned per enforcement pass (0 = unlimited).
        proof_prune_batch: u64,
        /// Largest bridge-proof height range (0 = unlimited).
        bridge_proof_max_range_len: u64,
        /// Blocks a bridge proof's end height may trail the current block (0 = unlimited).
        bridge_proof_max_past_age_blocks: u64,
        /// Blocks a bridge proof's end height may lead the current block (0 = unlimited).
        bridge_proof_max_future_drift_blocks: u64,
        /// Poseidon parameter set embedded into policies, if any.
        #[norito(required)]
        poseidon_params_id: Option<u32>,
        /// Pedersen parameter set embedded into policies, if any.
        #[norito(required)]
        pedersen_params_id: Option<u32>,
        /// Verifying key that selects the Kaigi authorization relation.
        #[norito(required)]
        kaigi_authorization_vk: Option<ZkVerifyingKeyRefV1>,
        /// Verifying key that selects the Kaigi usage relation.
        #[norito(required)]
        kaigi_usage_vk: Option<ZkVerifyingKeyRefV1>,
    }
}

policy_section! {
    /// Confidential-operation limits, anchor and transition windows, registry caps.
    #[derive(Copy)]
    ZkConfidentialValidityV1 {
        /// Largest proof of one confidential operation, in bytes.
        max_proof_size_bytes: u32,
        /// Nullifiers one transaction may consume (0 = unlimited).
        max_nullifiers_per_tx: u32,
        /// Commitments one transaction may create (0 = unlimited).
        max_commitments_per_tx: u32,
        /// Confidential operations in one block.
        max_confidential_ops_per_block: u32,
        /// Largest age, in blocks, of an anchor a confidential proof references.
        max_anchor_age_blocks: u64,
        /// Aggregate proof bytes in one block.
        max_proof_bytes_block: u64,
        /// Verification calls in one transaction.
        max_verify_calls_per_tx: u32,
        /// Verification calls in one block.
        max_verify_calls_per_block: u32,
        /// Public inputs of one proof.
        max_public_inputs: u32,
        /// Reorganization depth for which commitment-tree checkpoints are retained.
        reorg_depth_bound: u64,
        /// Blocks between a policy change request and its activation.
        policy_transition_delay_blocks: u64,
        /// Conversion window, in blocks, around a policy activation.
        policy_transition_window_blocks: u64,
        /// Confidential-policy transitions that may share one effective height.
        policy_transition_max_per_height: u32,
        /// Commitment-tree roots retained.
        tree_roots_history_len: u64,
        /// Blocks between frontier checkpoints.
        tree_frontier_checkpoint_interval: u64,
        /// Active verifier entries in the registry.
        registry_max_vk_entries: u32,
        /// Active parameter sets in the registry.
        registry_max_params_entries: u32,
        /// Registry mutations in one block.
        registry_max_delta_per_block: u32,
    }
}

policy_section! {
    /// Gas charged for confidential proof verification.
    #[derive(Copy)]
    ZkVerificationGasV1 {
        /// Base charge of one verification.
        proof_base: u64,
        /// Charge per public input.
        per_public_input: u64,
        /// Charge per proof byte.
        per_proof_byte: u64,
        /// Charge per nullifier.
        per_nullifier: u64,
        /// Charge per commitment.
        per_commitment: u64,
    }
}

/// The complete first-release ZK validity policy of a chain.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ZkValidityPolicyV1 {
    /// Native PIPA-R verification policy.
    pub pipa_r: ZkPipaRValidityV1,
    /// Native STARK/FRI verification policy.
    pub stark: ZkStarkValidityV1,
    /// SCCP proof-admission and verifier-work limits.
    pub sccp: ZkSccpValidityV1,
    /// Proof retention, bridge-proof windows and relation-selecting keys.
    pub proofs: ZkProofValidityV1,
    /// Confidential-operation limits and windows.
    pub confidential: ZkConfidentialValidityV1,
    /// Verification gas schedule.
    pub gas: ZkVerificationGasV1,
}

fn non_zero_u32(value: u32, field: &'static str) -> Result<(), ZkValidityPolicyError> {
    if value == 0 {
        return Err(ZkValidityPolicyError::Zero(field));
    }
    Ok(())
}

fn non_zero_u64(value: u64, field: &'static str) -> Result<(), ZkValidityPolicyError> {
    if value == 0 {
        return Err(ZkValidityPolicyError::Zero(field));
    }
    Ok(())
}

fn size_field(value: u64, field: &'static str) -> Result<(), ZkValidityPolicyError> {
    if value > MAX_SIZE_FIELD {
        return Err(ZkValidityPolicyError::OutOfRange(field));
    }
    Ok(())
}

fn key_reference(
    value: Option<&ZkVerifyingKeyRefV1>,
    field: &'static str,
) -> Result<(), ZkValidityPolicyError> {
    match value {
        Some(key) if key.backend.is_empty() || key.name.is_empty() => Err(
            ZkValidityPolicyError::Unsupported(field, format!("{}::{}", key.backend, key.name)),
        ),
        _ => Ok(()),
    }
}

fn coherent(holds: bool, rule: &'static str) -> Result<(), ZkValidityPolicyError> {
    if holds {
        return Ok(());
    }
    Err(ZkValidityPolicyError::Incoherent(rule))
}

impl ZkValidityPolicyV1 {
    /// Identifier of the committed custom parameter that carries the policy.
    pub const PARAMETER_ID_STR: &'static str = "zk_validity_policy_v1";

    /// Names of the six sections, in declaration order.
    pub const SECTION_NAMES: [&'static str; 6] =
        ["pipa_r", "stark", "sccp", "proofs", "confidential", "gas"];

    /// The [`CustomParameterId`] of the committed policy.
    ///
    /// # Panics
    ///
    /// Never: the identifier is a valid parameter name.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("the ZK validity policy parameter identifier is a valid name")
    }

    /// The policy of a chain that installs none: the protocol defaults of this
    /// release, identical in every binary.
    #[must_use]
    pub fn protocol_default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            pipa_r: ZkPipaRValidityV1 {
                enabled: true,
                max_envelope_bytes: MIB,
                max_proof_bytes: 192 * 1024,
            },
            stark: ZkStarkValidityV1 {
                enabled: true,
                max_envelope_bytes: MIB,
                max_proof_bytes: MIB,
            },
            sccp: ZkSccpValidityV1 {
                max_proofs_per_transaction: 1,
                max_proofs_per_block: 4,
                max_proof_bytes_per_proof: 8 * MIB,
                max_proof_bytes_per_transaction: 8 * MIB,
                max_proof_bytes_per_block: 32 * MIB,
                max_native_headers_per_transaction: 4_096,
                max_native_headers_per_block: 16_384,
                max_ethereum_light_client_updates_per_transaction: 128,
                max_ethereum_light_client_updates_per_block: 512,
                max_native_header_bytes_per_transaction: 8 * MIB,
                max_native_header_bytes_per_block: 32 * MIB,
                max_ed25519_signature_checks_per_transaction: 65_536,
                max_ed25519_signature_checks_per_block: 262_144,
                max_bls_vote_attestations_per_transaction: 64,
                max_bls_vote_attestations_per_block: 256,
            },
            proofs: ZkProofValidityV1 {
                max_verify_batch: 16,
                ballot_history_cap: 1_024,
                preverify_max_bytes: MIB,
                preverify_budget_bytes: 0,
                proof_history_cap: 4_096,
                proof_retention_grace_blocks: 256,
                proof_prune_batch: 512,
                bridge_proof_max_range_len: 4_096,
                bridge_proof_max_past_age_blocks: 0,
                bridge_proof_max_future_drift_blocks: 0,
                poseidon_params_id: None,
                pedersen_params_id: None,
                kaigi_authorization_vk: None,
                kaigi_usage_vk: None,
            },
            confidential: ZkConfidentialValidityV1 {
                max_proof_size_bytes: 1_048_576,
                max_nullifiers_per_tx: 8,
                max_commitments_per_tx: 8,
                max_confidential_ops_per_block: 256,
                max_anchor_age_blocks: 10_000,
                max_proof_bytes_block: MIB,
                max_verify_calls_per_tx: 128,
                max_verify_calls_per_block: 128,
                max_public_inputs: 32,
                reorg_depth_bound: 10_000,
                policy_transition_delay_blocks: 100,
                policy_transition_window_blocks: 200,
                policy_transition_max_per_height: 256,
                tree_roots_history_len: 10_000,
                tree_frontier_checkpoint_interval: 100,
                registry_max_vk_entries: 64,
                registry_max_params_entries: 32,
                registry_max_delta_per_block: 4,
            },
            gas: ZkVerificationGasV1 {
                proof_base: 250_000,
                per_public_input: 2_000,
                per_proof_byte: 5,
                per_nullifier: 300,
                per_commitment: 500,
            },
        }
    }

    /// Names of every policy field as `section.field`, in declaration order.
    #[must_use]
    pub fn field_names() -> Vec<String> {
        let sections: [(&str, &[&str]); 6] = [
            ("pipa_r", ZkPipaRValidityV1::FIELD_NAMES),
            ("stark", ZkStarkValidityV1::FIELD_NAMES),
            ("sccp", ZkSccpValidityV1::FIELD_NAMES),
            ("proofs", ZkProofValidityV1::FIELD_NAMES),
            ("confidential", ZkConfidentialValidityV1::FIELD_NAMES),
            ("gas", ZkVerificationGasV1::FIELD_NAMES),
        ];
        sections
            .iter()
            .flat_map(|(section, fields)| {
                fields.iter().map(move |field| format!("{section}.{field}"))
            })
            .collect()
    }

    /// Check every structural and coherence rule a committed policy must satisfy.
    ///
    /// The decision uses the policy value alone and fixed protocol constants,
    /// so every validator on every supported target reaches the same result.
    ///
    /// Structural rules: the listed counts are positive, every field that
    /// sizes a buffer or collection is at most [`MAX_SIZE_FIELD`], every SCCP
    /// byte limit is at most [`MAX_EXACT_JSON_U64`], and a verifying-key
    /// reference names a backend and a key.
    ///
    /// Coherence rules: a proof limit does not exceed the envelope that carries
    /// it; a per-proof limit does not exceed the per-transaction limit and a
    /// per-transaction limit does not exceed the per-block limit of the same
    /// resource; and the retained commitment-tree roots cover every admissible
    /// anchor (`tree_roots_history_len >= max_anchor_age_blocks`). Limits may
    /// shrink as long as these rules hold.
    ///
    /// # Errors
    ///
    /// Returns the first rule that fails, in the fixed order of this function.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ZkValidityPolicyError> {
        let Self {
            pipa_r,
            stark,
            sccp,
            proofs,
            confidential,
            gas: _,
        } = self;
        size_field(pipa_r.max_envelope_bytes, "pipa_r.max_envelope_bytes")?;
        size_field(pipa_r.max_proof_bytes, "pipa_r.max_proof_bytes")?;
        size_field(stark.max_envelope_bytes, "stark.max_envelope_bytes")?;
        size_field(stark.max_proof_bytes, "stark.max_proof_bytes")?;
        non_zero_u32(
            sccp.max_proofs_per_transaction,
            "sccp.max_proofs_per_transaction",
        )?;
        non_zero_u32(sccp.max_proofs_per_block, "sccp.max_proofs_per_block")?;
        non_zero_u64(
            sccp.max_proof_bytes_per_proof,
            "sccp.max_proof_bytes_per_proof",
        )?;
        non_zero_u64(
            sccp.max_proof_bytes_per_transaction,
            "sccp.max_proof_bytes_per_transaction",
        )?;
        non_zero_u64(
            sccp.max_proof_bytes_per_block,
            "sccp.max_proof_bytes_per_block",
        )?;
        non_zero_u32(
            sccp.max_native_headers_per_transaction,
            "sccp.max_native_headers_per_transaction",
        )?;
        non_zero_u32(
            sccp.max_native_headers_per_block,
            "sccp.max_native_headers_per_block",
        )?;
        non_zero_u32(
            sccp.max_ethereum_light_client_updates_per_transaction,
            "sccp.max_ethereum_light_client_updates_per_transaction",
        )?;
        non_zero_u32(
            sccp.max_ethereum_light_client_updates_per_block,
            "sccp.max_ethereum_light_client_updates_per_block",
        )?;
        non_zero_u64(
            sccp.max_native_header_bytes_per_transaction,
            "sccp.max_native_header_bytes_per_transaction",
        )?;
        non_zero_u64(
            sccp.max_native_header_bytes_per_block,
            "sccp.max_native_header_bytes_per_block",
        )?;
        non_zero_u32(
            sccp.max_ed25519_signature_checks_per_transaction,
            "sccp.max_ed25519_signature_checks_per_transaction",
        )?;
        non_zero_u32(
            sccp.max_ed25519_signature_checks_per_block,
            "sccp.max_ed25519_signature_checks_per_block",
        )?;
        non_zero_u32(
            sccp.max_bls_vote_attestations_per_transaction,
            "sccp.max_bls_vote_attestations_per_transaction",
        )?;
        non_zero_u32(
            sccp.max_bls_vote_attestations_per_block,
            "sccp.max_bls_vote_attestations_per_block",
        )?;
        for (value, field) in [
            (
                sccp.max_proof_bytes_per_proof,
                "sccp.max_proof_bytes_per_proof",
            ),
            (
                sccp.max_proof_bytes_per_transaction,
                "sccp.max_proof_bytes_per_transaction",
            ),
            (
                sccp.max_proof_bytes_per_block,
                "sccp.max_proof_bytes_per_block",
            ),
            (
                sccp.max_native_header_bytes_per_transaction,
                "sccp.max_native_header_bytes_per_transaction",
            ),
            (
                sccp.max_native_header_bytes_per_block,
                "sccp.max_native_header_bytes_per_block",
            ),
        ] {
            if value > MAX_EXACT_JSON_U64 {
                return Err(ZkValidityPolicyError::OutOfRange(field));
            }
        }
        size_field(proofs.ballot_history_cap, "proofs.ballot_history_cap")?;
        size_field(proofs.preverify_max_bytes, "proofs.preverify_max_bytes")?;
        size_field(proofs.proof_history_cap, "proofs.proof_history_cap")?;
        size_field(proofs.proof_prune_batch, "proofs.proof_prune_batch")?;
        key_reference(
            proofs.kaigi_authorization_vk.as_ref(),
            "proofs.kaigi_authorization_vk",
        )?;
        key_reference(proofs.kaigi_usage_vk.as_ref(), "proofs.kaigi_usage_vk")?;
        non_zero_u32(
            confidential.policy_transition_max_per_height,
            "confidential.policy_transition_max_per_height",
        )?;
        non_zero_u64(
            confidential.tree_roots_history_len,
            "confidential.tree_roots_history_len",
        )?;
        size_field(
            confidential.tree_roots_history_len,
            "confidential.tree_roots_history_len",
        )?;

        coherent(
            pipa_r.max_proof_bytes <= pipa_r.max_envelope_bytes,
            "pipa_r.max_proof_bytes exceeds pipa_r.max_envelope_bytes",
        )?;
        coherent(
            stark.max_proof_bytes <= stark.max_envelope_bytes,
            "stark.max_proof_bytes exceeds stark.max_envelope_bytes",
        )?;
        coherent(
            sccp.max_proofs_per_transaction <= sccp.max_proofs_per_block,
            "sccp.max_proofs_per_transaction exceeds sccp.max_proofs_per_block",
        )?;
        coherent(
            sccp.max_proof_bytes_per_proof <= sccp.max_proof_bytes_per_transaction,
            "sccp.max_proof_bytes_per_proof exceeds sccp.max_proof_bytes_per_transaction",
        )?;
        coherent(
            sccp.max_proof_bytes_per_transaction <= sccp.max_proof_bytes_per_block,
            "sccp.max_proof_bytes_per_transaction exceeds sccp.max_proof_bytes_per_block",
        )?;
        coherent(
            sccp.max_native_headers_per_transaction <= sccp.max_native_headers_per_block,
            "sccp.max_native_headers_per_transaction exceeds sccp.max_native_headers_per_block",
        )?;
        coherent(
            sccp.max_ethereum_light_client_updates_per_transaction
                <= sccp.max_ethereum_light_client_updates_per_block,
            "sccp.max_ethereum_light_client_updates_per_transaction exceeds \
             sccp.max_ethereum_light_client_updates_per_block",
        )?;
        coherent(
            sccp.max_native_header_bytes_per_transaction <= sccp.max_native_header_bytes_per_block,
            "sccp.max_native_header_bytes_per_transaction exceeds \
             sccp.max_native_header_bytes_per_block",
        )?;
        coherent(
            sccp.max_ed25519_signature_checks_per_transaction
                <= sccp.max_ed25519_signature_checks_per_block,
            "sccp.max_ed25519_signature_checks_per_transaction exceeds \
             sccp.max_ed25519_signature_checks_per_block",
        )?;
        coherent(
            sccp.max_bls_vote_attestations_per_transaction
                <= sccp.max_bls_vote_attestations_per_block,
            "sccp.max_bls_vote_attestations_per_transaction exceeds \
             sccp.max_bls_vote_attestations_per_block",
        )?;
        coherent(
            u64::from(confidential.max_proof_size_bytes) <= confidential.max_proof_bytes_block,
            "confidential.max_proof_size_bytes exceeds confidential.max_proof_bytes_block",
        )?;
        coherent(
            confidential.max_verify_calls_per_tx <= confidential.max_verify_calls_per_block,
            "confidential.max_verify_calls_per_tx exceeds confidential.max_verify_calls_per_block",
        )?;
        coherent(
            confidential.tree_roots_history_len >= confidential.max_anchor_age_blocks,
            "confidential.tree_roots_history_len does not cover \
             confidential.max_anchor_age_blocks",
        )?;
        Ok(())
    }

    /// Names of the policy fields whose values differ between `self` and `other`.
    #[must_use]
    pub fn differing_fields(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        self.pipa_r
            .differing_fields(&other.pipa_r, "pipa_r", &mut out);
        self.stark.differing_fields(&other.stark, "stark", &mut out);
        self.sccp.differing_fields(&other.sccp, "sccp", &mut out);
        self.proofs
            .differing_fields(&other.proofs, "proofs", &mut out);
        self.confidential
            .differing_fields(&other.confidential, "confidential", &mut out);
        self.gas.differing_fields(&other.gas, "gas", &mut out);
        out
    }

    /// Wrap the policy as the committed custom parameter.
    #[must_use]
    pub fn into_custom_parameter(self) -> CustomParameter {
        CustomParameter::new(Self::parameter_id(), Json::new(self))
    }

    /// Decode and validate the policy carried by `custom`.
    ///
    /// Returns `None` when `custom` is another parameter.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload is not the exact V1 policy or a
    /// value violates a rule of [`Self::validate`]. Every validator derives
    /// the same error from the same committed bytes.
    pub fn from_custom_parameter(
        custom: &CustomParameter,
    ) -> Option<Result<Self, ZkValidityPolicyError>> {
        if custom.id() != &Self::parameter_id() {
            return None;
        }
        Some(Self::from_payload(custom.payload()))
    }

    /// Decode and validate a policy payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload is not the exact V1 policy or a
    /// value violates a rule of [`Self::validate`].
    pub fn from_payload(payload: &Json) -> Result<Self, ZkValidityPolicyError> {
        let policy = payload
            .try_into_any_norito::<Self>()
            .map_err(|error| ZkValidityPolicyError::Malformed(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Replace the value of the field named `section.field` by another value
    /// that keeps the policy valid, derived from `salt`.
    ///
    /// Returns `false`, leaving the policy untouched, when the name is not a
    /// policy field or the field admits no other valid value. Coverage tests use
    /// it to visit every field without naming them, so a new field cannot be
    /// skipped.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn perturb_field(&mut self, name: &str, salt: u32) -> bool {
        let Some((section, field)) = name.split_once('.') else {
            return false;
        };
        let candidates: Vec<Self> = match section {
            "pipa_r" => self
                .pipa_r
                .perturbed(field, salt)
                .into_iter()
                .map(|pipa_r| Self {
                    pipa_r,
                    ..self.clone()
                })
                .collect(),
            "stark" => self
                .stark
                .perturbed(field, salt)
                .into_iter()
                .map(|stark| Self {
                    stark,
                    ..self.clone()
                })
                .collect(),
            "sccp" => self
                .sccp
                .perturbed(field, salt)
                .into_iter()
                .map(|sccp| Self {
                    sccp,
                    ..self.clone()
                })
                .collect(),
            "proofs" => self
                .proofs
                .perturbed(field, salt)
                .into_iter()
                .map(|proofs| Self {
                    proofs,
                    ..self.clone()
                })
                .collect(),
            "confidential" => self
                .confidential
                .perturbed(field, salt)
                .into_iter()
                .map(|confidential| Self {
                    confidential,
                    ..self.clone()
                })
                .collect(),
            "gas" => self
                .gas
                .perturbed(field, salt)
                .into_iter()
                .map(|gas| Self {
                    gas,
                    ..self.clone()
                })
                .collect(),
            _ => Vec::new(),
        };
        for candidate in candidates {
            if candidate != *self && candidate.validate().is_ok() {
                *self = candidate;
                return true;
            }
        }
        false
    }
}

/// Other values of a policy field, for coverage tests.
#[cfg(any(test, feature = "test-fixtures"))]
mod perturb {
    use super::ZkVerifyingKeyRefV1;

    /// A policy field type that can produce values other than its current one.
    pub(super) trait PolicyField: Sized {
        /// Candidate replacement values, most preferred first.
        fn others(&self, field: &'static str, salt: u32) -> Vec<Self>;
    }

    impl PolicyField for bool {
        fn others(&self, _field: &'static str, _salt: u32) -> Vec<Self> {
            vec![!*self]
        }
    }

    impl PolicyField for u32 {
        fn others(&self, _field: &'static str, salt: u32) -> Vec<Self> {
            let step = salt.max(1);
            [
                self.checked_add(step),
                self.checked_sub(step),
                self.checked_add(1),
                self.checked_sub(1),
            ]
            .into_iter()
            .flatten()
            .collect()
        }
    }

    impl PolicyField for u64 {
        fn others(&self, _field: &'static str, salt: u32) -> Vec<Self> {
            let step = u64::from(salt.max(1));
            [
                self.checked_add(step),
                self.checked_sub(step),
                self.checked_add(1),
                self.checked_sub(1),
            ]
            .into_iter()
            .flatten()
            .collect()
        }
    }

    impl PolicyField for Option<u32> {
        fn others(&self, _field: &'static str, salt: u32) -> Vec<Self> {
            self.as_ref().map_or_else(
                || vec![Some(salt.max(1))],
                |value| vec![Some(value.wrapping_add(salt.max(1))), None],
            )
        }
    }

    impl PolicyField for Option<ZkVerifyingKeyRefV1> {
        fn others(&self, field: &'static str, salt: u32) -> Vec<Self> {
            let other = Some(ZkVerifyingKeyRefV1 {
                backend: "pipa-r/pasta".to_owned(),
                name: format!("{field}-{salt}"),
            });
            if *self == other {
                vec![None]
            } else {
                vec![other]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_default_is_valid_and_round_trips_through_the_parameter() {
        let policy = ZkValidityPolicyV1::protocol_default();
        policy.validate().expect("the protocol default is valid");
        let encoded = policy.encode();
        assert_eq!(
            ZkValidityPolicyV1::decode(&mut encoded.as_slice()).expect("decode native policy"),
            policy,
        );
        let custom = policy.clone().into_custom_parameter();
        assert_eq!(custom.id(), &ZkValidityPolicyV1::parameter_id());
        assert_eq!(
            ZkValidityPolicyV1::from_custom_parameter(&custom),
            Some(Ok(policy.clone()))
        );
        assert_eq!(
            ZkValidityPolicyV1::from_payload(custom.payload()),
            Ok(policy)
        );
        let other = CustomParameter::new(
            "another_parameter".parse().expect("valid name"),
            Json::new(1_u32),
        );
        assert!(ZkValidityPolicyV1::from_custom_parameter(&other).is_none());
    }

    #[test]
    fn field_names_list_every_field_once() {
        let names = ZkValidityPolicyV1::field_names();
        assert_eq!(names.len(), 58);
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
        for name in &names {
            let (section, _) = name.split_once('.').expect("section.field");
            assert!(ZkValidityPolicyV1::SECTION_NAMES.contains(&section));
        }
        // The JSON payload has exactly these members: a field added to a
        // section appears in the committed payload and in this list together.
        let value = norito::json::to_value(&ZkValidityPolicyV1::protocol_default())
            .expect("the policy serializes");
        let mut payload_names = Vec::new();
        for section in ZkValidityPolicyV1::SECTION_NAMES {
            let members = value
                .get(section)
                .and_then(norito::json::Value::as_object)
                .expect("a section object");
            for key in members.keys() {
                payload_names.push(format!("{section}.{key}"));
            }
        }
        payload_names.sort();
        let mut sorted = names;
        sorted.sort();
        assert_eq!(payload_names, sorted);
    }

    #[test]
    fn every_field_is_perturbed_into_another_valid_policy() {
        let default = ZkValidityPolicyV1::protocol_default();
        let mut all_changed = default.clone();
        for (index, name) in ZkValidityPolicyV1::field_names().iter().enumerate() {
            let salt = u32::try_from(index).expect("field count fits") + 1;
            let mut single = default.clone();
            let changed = single.perturb_field(name, salt);
            assert!(changed, "{name} is perturbed");
            assert_eq!(
                single.differing_fields(&default),
                std::slice::from_ref(name)
            );
            single.validate().expect("a perturbed policy stays valid");
            assert!(all_changed.perturb_field(name, salt), "{name} in sequence");
        }
        all_changed.validate().expect("valid");
        assert_eq!(all_changed.differing_fields(&default).len(), 58);
        assert!(!default.clone().perturb_field("pipa_r.unknown", 1));
        assert!(!default.clone().perturb_field("unknown", 1));
    }

    #[test]
    fn structural_rules_reject_identically_on_every_target() {
        let default = ZkValidityPolicyV1::protocol_default;
        let mut zero = default();
        zero.sccp.max_proofs_per_block = 0;
        assert_eq!(
            zero.validate(),
            Err(ZkValidityPolicyError::Zero("sccp.max_proofs_per_block"))
        );
        let mut roots = default();
        roots.confidential.tree_roots_history_len = 0;
        assert_eq!(
            roots.validate(),
            Err(ZkValidityPolicyError::Zero(
                "confidential.tree_roots_history_len"
            ))
        );
        let mut key = default();
        key.proofs.kaigi_authorization_vk = Some(ZkVerifyingKeyRefV1 {
            backend: String::new(),
            name: "kaigi".to_owned(),
        });
        assert!(matches!(
            key.validate(),
            Err(ZkValidityPolicyError::Unsupported(
                "proofs.kaigi_authorization_vk",
                _
            ))
        ));
        // A size above the fixed protocol maximum is rejected by its value, not
        // by the pointer width of the validator: 2^32 fits a 64-bit `usize`.
        for field in [
            "pipa_r.max_envelope_bytes",
            "stark.max_envelope_bytes",
            "proofs.ballot_history_cap",
            "proofs.preverify_max_bytes",
            "proofs.proof_history_cap",
            "proofs.proof_prune_batch",
            "confidential.tree_roots_history_len",
        ] {
            let mut policy = default();
            let over = MAX_SIZE_FIELD + 1;
            match field {
                "pipa_r.max_envelope_bytes" => policy.pipa_r.max_envelope_bytes = over,
                "stark.max_envelope_bytes" => policy.stark.max_envelope_bytes = over,
                "proofs.ballot_history_cap" => policy.proofs.ballot_history_cap = over,
                "proofs.preverify_max_bytes" => policy.proofs.preverify_max_bytes = over,
                "proofs.proof_history_cap" => policy.proofs.proof_history_cap = over,
                "proofs.proof_prune_batch" => policy.proofs.proof_prune_batch = over,
                _ => policy.confidential.tree_roots_history_len = over,
            }
            assert_eq!(
                policy.validate(),
                Err(ZkValidityPolicyError::OutOfRange(field)),
                "{field}"
            );
        }
        // SCCP byte limits stay exactly representable by every JSON reader.
        let mut sccp = default();
        sccp.sccp.max_proof_bytes_per_block = MAX_EXACT_JSON_U64 + 1;
        assert_eq!(
            sccp.validate(),
            Err(ZkValidityPolicyError::OutOfRange(
                "sccp.max_proof_bytes_per_block"
            ))
        );
        sccp.sccp.max_proof_bytes_per_block = MAX_EXACT_JSON_U64;
        sccp.validate().expect("the JSON-exact maximum is accepted");
        let malformed = Json::new("not a policy");
        assert!(matches!(
            ZkValidityPolicyV1::from_payload(&malformed),
            Err(ZkValidityPolicyError::Malformed(_))
        ));
    }

    #[test]
    fn coherence_rules_allow_shrinking_and_reject_contradictions() {
        let default = ZkValidityPolicyV1::protocol_default;
        // Shrinking is allowed while the rules hold.
        let mut smaller = default();
        smaller.confidential.max_anchor_age_blocks = 10;
        smaller.confidential.tree_roots_history_len = 10;
        smaller.confidential.max_proof_size_bytes = 1;
        smaller.proofs.proof_history_cap = 1;
        smaller.proofs.proof_retention_grace_blocks = 0;
        smaller.validate().expect("a coherent smaller policy");

        let incoherent = |edit: fn(&mut ZkValidityPolicyV1)| {
            let mut policy = default();
            edit(&mut policy);
            policy.validate()
        };
        // Retention must cover every admissible anchor.
        assert!(matches!(
            incoherent(|policy| policy.confidential.tree_roots_history_len = 9_999),
            Err(ZkValidityPolicyError::Incoherent(rule)) if rule.contains("tree_roots_history_len")
        ));
        assert!(matches!(
            incoherent(|policy| policy.confidential.max_anchor_age_blocks = 10_001),
            Err(ZkValidityPolicyError::Incoherent(rule)) if rule.contains("max_anchor_age_blocks")
        ));
        assert!(matches!(
            incoherent(|policy| policy.pipa_r.max_proof_bytes = policy.pipa_r.max_envelope_bytes + 1),
            Err(ZkValidityPolicyError::Incoherent(rule)) if rule.contains("pipa_r.max_proof_bytes")
        ));
        assert!(matches!(
            incoherent(|policy| policy.stark.max_proof_bytes = policy.stark.max_envelope_bytes + 1),
            Err(ZkValidityPolicyError::Incoherent(rule)) if rule.contains("stark.max_proof_bytes")
        ));
        assert!(matches!(
            incoherent(|policy| policy.sccp.max_proof_bytes_per_proof += 1),
            Err(ZkValidityPolicyError::Incoherent(rule)) if rule.contains("per_proof")
        ));
        assert!(matches!(
            incoherent(|policy| policy.sccp.max_proofs_per_transaction = 5),
            Err(ZkValidityPolicyError::Incoherent(rule))
                if rule.contains("max_proofs_per_transaction")
        ));
        assert!(matches!(
            incoherent(|policy| policy.confidential.max_proof_size_bytes += 1),
            Err(ZkValidityPolicyError::Incoherent(rule)) if rule.contains("max_proof_size_bytes")
        ));
        assert!(matches!(
            incoherent(|policy| policy.confidential.max_verify_calls_per_tx += 1),
            Err(ZkValidityPolicyError::Incoherent(rule))
                if rule.contains("max_verify_calls_per_tx")
        ));
    }

    #[test]
    fn sccp_limits_keep_their_order_and_exact_json_range() {
        type SetLimit = fn(&mut ZkSccpValidityV1, u64);
        let default = ZkValidityPolicyV1::protocol_default;
        // Every SCCP byte limit accepts the exact-JSON maximum and rejects one above it.
        let mut boundary = default();
        boundary.sccp.max_proof_bytes_per_proof = MAX_EXACT_JSON_U64;
        boundary.sccp.max_proof_bytes_per_transaction = MAX_EXACT_JSON_U64;
        boundary.sccp.max_proof_bytes_per_block = MAX_EXACT_JSON_U64;
        boundary.sccp.max_native_header_bytes_per_transaction = MAX_EXACT_JSON_U64;
        boundary.sccp.max_native_header_bytes_per_block = MAX_EXACT_JSON_U64;
        boundary
            .validate()
            .expect("the exact-JSON maximum is accepted");
        let mutations: [(SetLimit, &str); 5] = [
            (
                |sccp, limit| sccp.max_proof_bytes_per_proof = limit,
                "sccp.max_proof_bytes_per_proof",
            ),
            (
                |sccp, limit| sccp.max_proof_bytes_per_transaction = limit,
                "sccp.max_proof_bytes_per_transaction",
            ),
            (
                |sccp, limit| sccp.max_proof_bytes_per_block = limit,
                "sccp.max_proof_bytes_per_block",
            ),
            (
                |sccp, limit| sccp.max_native_header_bytes_per_transaction = limit,
                "sccp.max_native_header_bytes_per_transaction",
            ),
            (
                |sccp, limit| sccp.max_native_header_bytes_per_block = limit,
                "sccp.max_native_header_bytes_per_block",
            ),
        ];
        for (mutate, field) in mutations {
            let mut hostile = boundary.clone();
            mutate(&mut hostile.sccp, MAX_EXACT_JSON_U64 + 1);
            assert_eq!(
                hostile.validate(),
                Err(ZkValidityPolicyError::OutOfRange(field)),
                "{field}"
            );
        }
        // A per-proof limit above the transaction limit is rejected.
        let mut per_proof = default();
        per_proof.sccp.max_proof_bytes_per_transaction = 1;
        assert_eq!(
            per_proof.validate(),
            Err(ZkValidityPolicyError::Incoherent(
                "sccp.max_proof_bytes_per_proof exceeds sccp.max_proof_bytes_per_transaction"
            ))
        );
        // A transaction work limit above the block limit is rejected.
        let mut work = default();
        work.sccp.max_ed25519_signature_checks_per_transaction = 2;
        work.sccp.max_ed25519_signature_checks_per_block = 1;
        assert!(matches!(
            work.validate(),
            Err(ZkValidityPolicyError::Incoherent(rule))
                if rule.starts_with("sccp.max_ed25519_signature_checks_per_transaction exceeds")
        ));
        // The defaults are ordered.
        let sccp = default().sccp;
        assert!(sccp.max_proofs_per_transaction <= sccp.max_proofs_per_block);
        assert!(sccp.max_proof_bytes_per_proof <= sccp.max_proof_bytes_per_transaction);
        assert!(sccp.max_proof_bytes_per_transaction <= sccp.max_proof_bytes_per_block);
        assert!(
            sccp.max_bls_vote_attestations_per_transaction
                <= sccp.max_bls_vote_attestations_per_block
        );
    }

    #[test]
    fn taira_genesis_template_carries_a_valid_policy() {
        // The tracked Taira deployment sets its two non-default confidential
        // limits as chain policy in its genesis template, not in node
        // configuration.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../configs/soranexus/taira/genesis.template.json");
        let text = std::fs::read_to_string(&path).expect("the Taira genesis template is tracked");
        let template: norito::json::Value =
            norito::json::from_str(&text).expect("the template is JSON");
        let entry = template
            .get("transactions")
            .and_then(|transactions| transactions.get(0))
            .and_then(|transaction| transaction.get("parameters"))
            .and_then(|parameters| parameters.get("custom"))
            .and_then(|custom| custom.get(ZkValidityPolicyV1::PARAMETER_ID_STR))
            .expect("the template installs the ZK validity policy");
        assert_eq!(
            entry.get("id").and_then(norito::json::Value::as_str),
            Some(ZkValidityPolicyV1::PARAMETER_ID_STR)
        );
        let payload = entry.get("payload").expect("the parameter has a payload");
        let policy = ZkValidityPolicyV1::from_payload(&Json::from(payload))
            .expect("the template policy is a valid V1 policy");
        assert_eq!(policy.confidential.max_proof_size_bytes, 8 * 1024 * 1024);
        assert_eq!(policy.confidential.max_proof_bytes_block, 16 * 1024 * 1024);
        assert_eq!(
            policy.differing_fields(&ZkValidityPolicyV1::protocol_default()),
            [
                "confidential.max_proof_size_bytes",
                "confidential.max_proof_bytes_block"
            ],
            "every other value of the Taira policy is the protocol default"
        );
    }

    #[test]
    fn retired_backend_policy_sections_are_rejected() {
        let policy = ZkValidityPolicyV1::protocol_default();
        let mut value = norito::json::to_value(&policy).expect("serialize native policy");
        let members = value.as_object_mut().expect("policy object");
        let native = members.remove("pipa_r").expect("native section");
        members.insert("halo2".to_owned(), native);
        assert!(matches!(
            ZkValidityPolicyV1::from_payload(&Json::from(&value)),
            Err(ZkValidityPolicyError::Malformed(_))
        ));
        let mut value = norito::json::to_value(&policy).expect("serialize native policy");
        value
            .get_mut("sccp")
            .and_then(norito::json::Value::as_object_mut)
            .expect("SCCP section")
            .insert(
                "max_secp256k1_recoveries_per_block".to_owned(),
                norito::json::Value::from(1_u64),
            );
        assert!(matches!(
            ZkValidityPolicyV1::from_payload(&Json::from(&value)),
            Err(ZkValidityPolicyError::Malformed(_))
        ));
    }

    #[test]
    fn payload_with_an_unknown_or_missing_field_is_malformed() {
        let mut value = norito::json::to_value(&ZkValidityPolicyV1::protocol_default())
            .expect("the policy serializes");
        let gas = value
            .get_mut("gas")
            .and_then(norito::json::Value::as_object_mut)
            .expect("gas section");
        gas.insert("per_unknown".to_owned(), norito::json::Value::from(1_u64));
        assert!(matches!(
            ZkValidityPolicyV1::from_payload(&Json::from(&value)),
            Err(ZkValidityPolicyError::Malformed(_))
        ));
        let mut value = norito::json::to_value(&ZkValidityPolicyV1::protocol_default())
            .expect("the policy serializes");
        let proofs = value
            .get_mut("proofs")
            .and_then(norito::json::Value::as_object_mut)
            .expect("proofs section");
        proofs.remove("kaigi_usage_vk");
        assert!(matches!(
            ZkValidityPolicyV1::from_payload(&Json::from(&value)),
            Err(ZkValidityPolicyError::Malformed(_))
        ));
    }
}
