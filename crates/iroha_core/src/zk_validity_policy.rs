//! Core application of the committed ZK validity policy.
//!
//! Every limit, window, verifier switch, relation-selecting verifying-key
//! identity and verification gas charge that
//! [`crate::state::compute_zk_consensus_policy_hash`] binds is chain policy.
//! Its source is committed State: the typed custom parameter
//! [`ZkValidityPolicyV1::PARAMETER_ID_STR`], defined with its protocol default
//! and canonical validation in [`iroha_data_model::zk_validity_policy`]. An
//! ordinary authorized `SetParameter` installs or changes it, in genesis or
//! later, and the change governs every block after the one that commits it:
//! block construction freezes the policy of the predecessor's committed
//! parameters for the whole block. A chain that never installs the parameter
//! uses the protocol default. Executor data-model reconciliation never writes
//! the parameter.
//!
//! A node's own `[zk]` and `[confidential]` configuration contributes local
//! resource settings only (verifier workers and queues, wall-clock budgets,
//! prover devices); it never changes what a validator accepts, charges or
//! certifies.

use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::RwLock,
};

use iroha_config::parameters::actual::{
    ConfidentialGas, Halo2, Halo2Backend, Sccp, Stark, VerifyingKeyRef, Zk, ZkCurve,
};
use iroha_data_model::parameter::{CustomParameter, Parameters};
pub use iroha_data_model::zk_validity_policy::{
    ZkConfidentialValidityV1, ZkHalo2ValidityV1, ZkProofValidityV1, ZkSccpValidityV1,
    ZkStarkValidityV1, ZkValidityPolicyError, ZkValidityPolicyV1, ZkVerificationGasV1,
    ZkVerifyingKeyRefV1,
};
use iroha_primitives::json::Json;

/// Why a `SetParameter` of the ZK validity policy is rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZkValidityPolicyChangeError {
    /// The payload is malformed or violates a structural or coherence rule.
    #[error(transparent)]
    Policy(#[from] ZkValidityPolicyError),
    /// Committed pending confidential-policy transitions exceed the new
    /// per-height limit. The pending transitions are State obligations a
    /// policy change cannot strand.
    #[error(
        "committed confidential-policy transitions at height {effective_height} ({count}) exceed \
         the new confidential.policy_transition_max_per_height ({maximum})"
    )]
    PendingTransitionsExceedLimit {
        /// Effective height whose committed transition count exceeds the new limit.
        effective_height: u64,
        /// Committed pending transitions at that height.
        count: u32,
        /// The per-height limit of the submitted policy.
        maximum: u32,
    },
}

fn count(value: usize) -> u64 {
    u64::try_from(value).expect("Iroha targets have a pointer width of at most 64 bits")
}

fn size(value: u64, field: &'static str) -> Result<usize, ZkValidityPolicyError> {
    // `ZkValidityPolicyV1::validate` bounds every size field by a fixed
    // protocol maximum that fits the narrowest supported pointer width, so a
    // validated policy never takes this error.
    usize::try_from(value).map_err(|_| ZkValidityPolicyError::OutOfRange(field))
}

fn curve_tag(curve: ZkCurve) -> &'static str {
    match curve {
        ZkCurve::Pallas => "pallas",
        ZkCurve::Pasta => "pasta",
        ZkCurve::Goldilocks => "goldilocks",
        ZkCurve::Bn254 => "bn254",
    }
}

fn curve_from_tag(tag: &str) -> Result<ZkCurve, ZkValidityPolicyError> {
    match tag {
        "pallas" => Ok(ZkCurve::Pallas),
        "pasta" => Ok(ZkCurve::Pasta),
        "goldilocks" => Ok(ZkCurve::Goldilocks),
        "bn254" => Ok(ZkCurve::Bn254),
        other => Err(ZkValidityPolicyError::Unsupported(
            "halo2.curve",
            other.to_owned(),
        )),
    }
}

fn backend_tag(backend: Halo2Backend) -> &'static str {
    match backend {
        Halo2Backend::Ipa => "ipa",
    }
}

fn backend_from_tag(tag: &str) -> Result<Halo2Backend, ZkValidityPolicyError> {
    match tag {
        "ipa" => Ok(Halo2Backend::Ipa),
        other => Err(ZkValidityPolicyError::Unsupported(
            "halo2.backend",
            other.to_owned(),
        )),
    }
}

fn key_ref(value: Option<&VerifyingKeyRef>) -> Option<ZkVerifyingKeyRefV1> {
    value.map(|key| ZkVerifyingKeyRefV1 {
        backend: key.backend.clone(),
        name: key.name.clone(),
    })
}

fn key_ref_to_actual(value: Option<&ZkVerifyingKeyRefV1>) -> Option<VerifyingKeyRef> {
    value.map(|key| VerifyingKeyRef {
        backend: key.backend.clone(),
        name: key.name.clone(),
    })
}

fn non_zero_u32(value: u32, field: &'static str) -> Result<NonZeroU32, ZkValidityPolicyError> {
    NonZeroU32::new(value).ok_or(ZkValidityPolicyError::Zero(field))
}

fn non_zero_u64(value: u64, field: &'static str) -> Result<NonZeroU64, ZkValidityPolicyError> {
    NonZeroU64::new(value).ok_or(ZkValidityPolicyError::Zero(field))
}

/// Project the validity-affecting values out of a ZK settings value.
///
/// Every field of the settings value and of its nested sections is named
/// here: it is either read into the policy or marked as a local resource. A
/// field added to the settings does not compile until it is classified.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn policy_of(zk: &Zk) -> ZkValidityPolicyV1 {
    let Zk {
        halo2,
        fastpq: _, // local resource: prover devices, sidecar queue
        stark,
        sccp,
        ballot_history_cap,
        preverify_max_bytes,
        preverify_budget_bytes,
        proof_history_cap,
        proof_retention_grace_blocks,
        proof_prune_batch,
        bridge_proof_max_range_len,
        bridge_proof_max_past_age_blocks,
        bridge_proof_max_future_drift_blocks,
        poseidon_params_id,
        pedersen_params_id,
        kaigi_authorization_vk,
        kaigi_usage_vk,
        max_proof_size_bytes,
        max_nullifiers_per_tx,
        max_commitments_per_tx,
        max_confidential_ops_per_block,
        verify_timeout: _, // local resource: wall-clock budget
        max_anchor_age_blocks,
        max_proof_bytes_block,
        max_verify_calls_per_tx,
        max_verify_calls_per_block,
        max_public_inputs,
        reorg_depth_bound,
        policy_transition_delay_blocks,
        policy_transition_window_blocks,
        policy_transition_max_per_height,
        tree_roots_history_len,
        tree_frontier_checkpoint_interval,
        registry_max_vk_entries,
        registry_max_params_entries,
        registry_max_delta_per_block,
        gas,
    } = zk;
    let Halo2 {
        enabled: halo2_enabled,
        curve,
        backend,
        max_k,
        verifier_budget_ms: _, // local resource
        verifier_max_batch,
        verifier_worker_threads: _,     // local resource
        verifier_queue_cap: _,          // local resource
        verifier_enqueue_wait_ms: _,    // local resource
        verifier_retry_ring_cap: _,     // local resource
        verifier_retry_max_attempts: _, // local resource
        verifier_retry_tick_ms: _,      // local resource
        max_envelope_bytes: halo2_max_envelope_bytes,
        max_proof_bytes: halo2_max_proof_bytes,
        max_transcript_label_len,
        enforce_transcript_label_ascii,
    } = halo2;
    let Stark {
        enabled: stark_enabled,
        max_envelope_bytes: stark_max_envelope_bytes,
        max_proof_bytes: stark_max_proof_bytes,
    } = stark;
    let Sccp {
        max_proofs_per_transaction,
        max_proofs_per_block,
        max_proof_bytes_per_proof,
        max_proof_bytes_per_transaction,
        max_proof_bytes_per_block,
        max_native_headers_per_transaction,
        max_native_headers_per_block,
        max_ethereum_light_client_updates_per_transaction,
        max_ethereum_light_client_updates_per_block,
        max_native_header_bytes_per_transaction,
        max_native_header_bytes_per_block,
        max_secp256k1_recoveries_per_transaction,
        max_secp256k1_recoveries_per_block,
        max_ed25519_signature_checks_per_transaction,
        max_ed25519_signature_checks_per_block,
        max_bls_vote_attestations_per_transaction,
        max_bls_vote_attestations_per_block,
    } = sccp;
    let ConfidentialGas {
        proof_base,
        per_public_input,
        per_proof_byte,
        per_nullifier,
        per_commitment,
    } = gas;
    ZkValidityPolicyV1 {
        halo2: ZkHalo2ValidityV1 {
            enabled: *halo2_enabled,
            curve: curve_tag(*curve).to_owned(),
            backend: backend_tag(*backend).to_owned(),
            max_k: *max_k,
            verifier_max_batch: *verifier_max_batch,
            max_envelope_bytes: count(*halo2_max_envelope_bytes),
            max_proof_bytes: count(*halo2_max_proof_bytes),
            max_transcript_label_len: count(*max_transcript_label_len),
            enforce_transcript_label_ascii: *enforce_transcript_label_ascii,
        },
        stark: ZkStarkValidityV1 {
            enabled: *stark_enabled,
            max_envelope_bytes: count(*stark_max_envelope_bytes),
            max_proof_bytes: count(*stark_max_proof_bytes),
        },
        sccp: ZkSccpValidityV1 {
            max_proofs_per_transaction: max_proofs_per_transaction.get(),
            max_proofs_per_block: max_proofs_per_block.get(),
            max_proof_bytes_per_proof: max_proof_bytes_per_proof.get(),
            max_proof_bytes_per_transaction: max_proof_bytes_per_transaction.get(),
            max_proof_bytes_per_block: max_proof_bytes_per_block.get(),
            max_native_headers_per_transaction: max_native_headers_per_transaction.get(),
            max_native_headers_per_block: max_native_headers_per_block.get(),
            max_ethereum_light_client_updates_per_transaction:
                max_ethereum_light_client_updates_per_transaction.get(),
            max_ethereum_light_client_updates_per_block:
                max_ethereum_light_client_updates_per_block.get(),
            max_native_header_bytes_per_transaction: max_native_header_bytes_per_transaction.get(),
            max_native_header_bytes_per_block: max_native_header_bytes_per_block.get(),
            max_secp256k1_recoveries_per_transaction: max_secp256k1_recoveries_per_transaction
                .get(),
            max_secp256k1_recoveries_per_block: max_secp256k1_recoveries_per_block.get(),
            max_ed25519_signature_checks_per_transaction:
                max_ed25519_signature_checks_per_transaction.get(),
            max_ed25519_signature_checks_per_block: max_ed25519_signature_checks_per_block.get(),
            max_bls_vote_attestations_per_transaction: max_bls_vote_attestations_per_transaction
                .get(),
            max_bls_vote_attestations_per_block: max_bls_vote_attestations_per_block.get(),
        },
        proofs: ZkProofValidityV1 {
            ballot_history_cap: count(*ballot_history_cap),
            preverify_max_bytes: count(*preverify_max_bytes),
            preverify_budget_bytes: *preverify_budget_bytes,
            proof_history_cap: count(*proof_history_cap),
            proof_retention_grace_blocks: *proof_retention_grace_blocks,
            proof_prune_batch: count(*proof_prune_batch),
            bridge_proof_max_range_len: *bridge_proof_max_range_len,
            bridge_proof_max_past_age_blocks: *bridge_proof_max_past_age_blocks,
            bridge_proof_max_future_drift_blocks: *bridge_proof_max_future_drift_blocks,
            poseidon_params_id: *poseidon_params_id,
            pedersen_params_id: *pedersen_params_id,
            kaigi_authorization_vk: key_ref(kaigi_authorization_vk.as_ref()),
            kaigi_usage_vk: key_ref(kaigi_usage_vk.as_ref()),
        },
        confidential: ZkConfidentialValidityV1 {
            max_proof_size_bytes: *max_proof_size_bytes,
            max_nullifiers_per_tx: *max_nullifiers_per_tx,
            max_commitments_per_tx: *max_commitments_per_tx,
            max_confidential_ops_per_block: *max_confidential_ops_per_block,
            max_anchor_age_blocks: *max_anchor_age_blocks,
            max_proof_bytes_block: *max_proof_bytes_block,
            max_verify_calls_per_tx: *max_verify_calls_per_tx,
            max_verify_calls_per_block: *max_verify_calls_per_block,
            max_public_inputs: *max_public_inputs,
            reorg_depth_bound: *reorg_depth_bound,
            policy_transition_delay_blocks: *policy_transition_delay_blocks,
            policy_transition_window_blocks: *policy_transition_window_blocks,
            policy_transition_max_per_height: policy_transition_max_per_height.get(),
            tree_roots_history_len: count(tree_roots_history_len.get()),
            tree_frontier_checkpoint_interval: *tree_frontier_checkpoint_interval,
            registry_max_vk_entries: *registry_max_vk_entries,
            registry_max_params_entries: *registry_max_params_entries,
            registry_max_delta_per_block: *registry_max_delta_per_block,
        },
        gas: ZkVerificationGasV1 {
            proof_base: *proof_base,
            per_public_input: *per_public_input,
            per_proof_byte: *per_proof_byte,
            per_nullifier: *per_nullifier,
            per_commitment: *per_commitment,
        },
    }
}

/// Replace the validity-affecting values of `zk` with `policy`.
///
/// Local resource settings of `zk` (worker and queue sizes, wall-clock
/// budgets, FASTPQ prover settings) are carried over. `zk` is not modified
/// when an error is returned. The new value is one exhaustive literal: a field
/// added to the settings does not compile until it is given a source.
///
/// # Errors
///
/// Returns the first rule of [`ZkValidityPolicyV1::validate`] that fails.
#[allow(clippy::too_many_lines)]
pub fn apply_policy(policy: &ZkValidityPolicyV1, zk: &mut Zk) -> Result<(), ZkValidityPolicyError> {
    policy.validate()?;
    let ZkValidityPolicyV1 {
        halo2,
        stark,
        sccp,
        proofs,
        confidential,
        gas,
    } = policy;
    let applied = Zk {
        halo2: Halo2 {
            enabled: halo2.enabled,
            curve: curve_from_tag(&halo2.curve)?,
            backend: backend_from_tag(&halo2.backend)?,
            max_k: halo2.max_k,
            verifier_budget_ms: zk.halo2.verifier_budget_ms,
            verifier_max_batch: halo2.verifier_max_batch,
            verifier_worker_threads: zk.halo2.verifier_worker_threads,
            verifier_queue_cap: zk.halo2.verifier_queue_cap,
            verifier_enqueue_wait_ms: zk.halo2.verifier_enqueue_wait_ms,
            verifier_retry_ring_cap: zk.halo2.verifier_retry_ring_cap,
            verifier_retry_max_attempts: zk.halo2.verifier_retry_max_attempts,
            verifier_retry_tick_ms: zk.halo2.verifier_retry_tick_ms,
            max_envelope_bytes: size(halo2.max_envelope_bytes, "halo2.max_envelope_bytes")?,
            max_proof_bytes: size(halo2.max_proof_bytes, "halo2.max_proof_bytes")?,
            max_transcript_label_len: size(
                halo2.max_transcript_label_len,
                "halo2.max_transcript_label_len",
            )?,
            enforce_transcript_label_ascii: halo2.enforce_transcript_label_ascii,
        },
        fastpq: zk.fastpq.clone(),
        stark: Stark {
            enabled: stark.enabled,
            max_envelope_bytes: size(stark.max_envelope_bytes, "stark.max_envelope_bytes")?,
            max_proof_bytes: size(stark.max_proof_bytes, "stark.max_proof_bytes")?,
        },
        sccp: Sccp {
            max_proofs_per_transaction: non_zero_u32(
                sccp.max_proofs_per_transaction,
                "sccp.max_proofs_per_transaction",
            )?,
            max_proofs_per_block: non_zero_u32(
                sccp.max_proofs_per_block,
                "sccp.max_proofs_per_block",
            )?,
            max_proof_bytes_per_proof: non_zero_u64(
                sccp.max_proof_bytes_per_proof,
                "sccp.max_proof_bytes_per_proof",
            )?,
            max_proof_bytes_per_transaction: non_zero_u64(
                sccp.max_proof_bytes_per_transaction,
                "sccp.max_proof_bytes_per_transaction",
            )?,
            max_proof_bytes_per_block: non_zero_u64(
                sccp.max_proof_bytes_per_block,
                "sccp.max_proof_bytes_per_block",
            )?,
            max_native_headers_per_transaction: non_zero_u32(
                sccp.max_native_headers_per_transaction,
                "sccp.max_native_headers_per_transaction",
            )?,
            max_native_headers_per_block: non_zero_u32(
                sccp.max_native_headers_per_block,
                "sccp.max_native_headers_per_block",
            )?,
            max_ethereum_light_client_updates_per_transaction: non_zero_u32(
                sccp.max_ethereum_light_client_updates_per_transaction,
                "sccp.max_ethereum_light_client_updates_per_transaction",
            )?,
            max_ethereum_light_client_updates_per_block: non_zero_u32(
                sccp.max_ethereum_light_client_updates_per_block,
                "sccp.max_ethereum_light_client_updates_per_block",
            )?,
            max_native_header_bytes_per_transaction: non_zero_u64(
                sccp.max_native_header_bytes_per_transaction,
                "sccp.max_native_header_bytes_per_transaction",
            )?,
            max_native_header_bytes_per_block: non_zero_u64(
                sccp.max_native_header_bytes_per_block,
                "sccp.max_native_header_bytes_per_block",
            )?,
            max_secp256k1_recoveries_per_transaction: non_zero_u32(
                sccp.max_secp256k1_recoveries_per_transaction,
                "sccp.max_secp256k1_recoveries_per_transaction",
            )?,
            max_secp256k1_recoveries_per_block: non_zero_u32(
                sccp.max_secp256k1_recoveries_per_block,
                "sccp.max_secp256k1_recoveries_per_block",
            )?,
            max_ed25519_signature_checks_per_transaction: non_zero_u32(
                sccp.max_ed25519_signature_checks_per_transaction,
                "sccp.max_ed25519_signature_checks_per_transaction",
            )?,
            max_ed25519_signature_checks_per_block: non_zero_u32(
                sccp.max_ed25519_signature_checks_per_block,
                "sccp.max_ed25519_signature_checks_per_block",
            )?,
            max_bls_vote_attestations_per_transaction: non_zero_u32(
                sccp.max_bls_vote_attestations_per_transaction,
                "sccp.max_bls_vote_attestations_per_transaction",
            )?,
            max_bls_vote_attestations_per_block: non_zero_u32(
                sccp.max_bls_vote_attestations_per_block,
                "sccp.max_bls_vote_attestations_per_block",
            )?,
        },
        ballot_history_cap: size(proofs.ballot_history_cap, "proofs.ballot_history_cap")?,
        preverify_max_bytes: size(proofs.preverify_max_bytes, "proofs.preverify_max_bytes")?,
        preverify_budget_bytes: proofs.preverify_budget_bytes,
        proof_history_cap: size(proofs.proof_history_cap, "proofs.proof_history_cap")?,
        proof_retention_grace_blocks: proofs.proof_retention_grace_blocks,
        proof_prune_batch: size(proofs.proof_prune_batch, "proofs.proof_prune_batch")?,
        bridge_proof_max_range_len: proofs.bridge_proof_max_range_len,
        bridge_proof_max_past_age_blocks: proofs.bridge_proof_max_past_age_blocks,
        bridge_proof_max_future_drift_blocks: proofs.bridge_proof_max_future_drift_blocks,
        poseidon_params_id: proofs.poseidon_params_id,
        pedersen_params_id: proofs.pedersen_params_id,
        kaigi_authorization_vk: key_ref_to_actual(proofs.kaigi_authorization_vk.as_ref()),
        kaigi_usage_vk: key_ref_to_actual(proofs.kaigi_usage_vk.as_ref()),
        max_proof_size_bytes: confidential.max_proof_size_bytes,
        max_nullifiers_per_tx: confidential.max_nullifiers_per_tx,
        max_commitments_per_tx: confidential.max_commitments_per_tx,
        max_confidential_ops_per_block: confidential.max_confidential_ops_per_block,
        verify_timeout: zk.verify_timeout,
        max_anchor_age_blocks: confidential.max_anchor_age_blocks,
        max_proof_bytes_block: confidential.max_proof_bytes_block,
        max_verify_calls_per_tx: confidential.max_verify_calls_per_tx,
        max_verify_calls_per_block: confidential.max_verify_calls_per_block,
        max_public_inputs: confidential.max_public_inputs,
        reorg_depth_bound: confidential.reorg_depth_bound,
        policy_transition_delay_blocks: confidential.policy_transition_delay_blocks,
        policy_transition_window_blocks: confidential.policy_transition_window_blocks,
        policy_transition_max_per_height: non_zero_u32(
            confidential.policy_transition_max_per_height,
            "confidential.policy_transition_max_per_height",
        )?,
        tree_roots_history_len: NonZeroUsize::new(size(
            confidential.tree_roots_history_len,
            "confidential.tree_roots_history_len",
        )?)
        .ok_or(ZkValidityPolicyError::Zero(
            "confidential.tree_roots_history_len",
        ))?,
        tree_frontier_checkpoint_interval: confidential.tree_frontier_checkpoint_interval,
        registry_max_vk_entries: confidential.registry_max_vk_entries,
        registry_max_params_entries: confidential.registry_max_params_entries,
        registry_max_delta_per_block: confidential.registry_max_delta_per_block,
        gas: ConfidentialGas {
            proof_base: gas.proof_base,
            per_public_input: gas.per_public_input,
            per_proof_byte: gas.per_proof_byte,
            per_nullifier: gas.per_nullifier,
            per_commitment: gas.per_commitment,
        },
    };
    *zk = applied;
    Ok(())
}

/// The ZK settings a node installs from its own configuration: its local
/// resource settings with every validity-affecting value replaced by the
/// protocol default. The committed policy, when the chain installs one, is
/// applied over this value by [`effective_zk`].
#[must_use]
pub fn node_local_resources(mut node: Zk) -> Zk {
    apply_policy(&ZkValidityPolicyV1::protocol_default(), &mut node)
        .expect("the protocol default ZK validity policy is structurally valid");
    node
}

/// Names of the validity-affecting fields a settings value holds with a value
/// other than the protocol default. A node configuration cannot set them; a
/// tool or test that builds a settings value by hand learns which of its
/// values a node ignores.
#[must_use]
pub fn node_validity_overrides(node: &Zk) -> Vec<String> {
    policy_of(node).differing_fields(&ZkValidityPolicyV1::protocol_default())
}

/// [`ZkValidityPolicyV1::from_payload`] of a committed payload, remembering
/// the last valid one: every State view reads the policy and it changes
/// rarely. The memo is keyed by the exact canonical payload text, so it
/// returns exactly what decoding returns.
fn from_committed_payload(payload: &Json) -> Result<ZkValidityPolicyV1, ZkValidityPolicyError> {
    static LAST: RwLock<Option<(String, ZkValidityPolicyV1)>> = RwLock::new(None);
    let text: &str = payload.as_ref();
    if let Ok(last) = LAST.read()
        && let Some((known, policy)) = last.as_ref()
        && known == text
    {
        return Ok(policy.clone());
    }
    let policy = ZkValidityPolicyV1::from_payload(payload)?;
    if let Ok(mut last) = LAST.write() {
        *last = Some((text.to_owned(), policy.clone()));
    }
    Ok(policy)
}

/// The policy committed in `parameters`, or `None` when the chain uses the
/// protocol default.
///
/// # Errors
///
/// Returns an error when the committed payload is malformed. `SetParameter`
/// validates the payload before it is committed and nothing else writes the
/// parameter, so this indicates State that no valid transition produced.
pub fn committed(
    parameters: &Parameters,
) -> Result<Option<ZkValidityPolicyV1>, ZkValidityPolicyError> {
    parameters
        .custom()
        .get(&ZkValidityPolicyV1::parameter_id())
        .map(|custom| from_committed_payload(custom.payload()))
        .transpose()
}

/// The ZK settings validation reads: `installed` with the committed policy of
/// `parameters`, when there is one, applied over it.
///
/// The function is pure: it reads its arguments and writes nothing. Block
/// construction calls it with the predecessor's committed parameters and
/// freezes the result for the block, so a policy committed in block `N`
/// governs block `N + 1` onwards and the genesis block runs under the
/// protocol default.
///
/// A malformed committed payload leaves `installed` unchanged. No valid
/// transition commits one; [`crate::state::State::install_node_zk`] refuses to
/// start on restored State that holds one.
#[must_use]
pub fn effective_zk(installed: Zk, parameters: &Parameters) -> Zk {
    let mut effective = installed;
    if let Ok(Some(policy)) = committed(parameters) {
        apply_policy(&policy, &mut effective).expect("a validated ZK validity policy applies");
    }
    effective
}

/// Validate a `SetParameter` of the committed ZK validity policy.
///
/// Returns `Ok(false)` when `custom` is another parameter and `Ok(true)` when
/// it is a policy that may be committed. `pending_transition_counts` are the
/// committed confidential-policy transition counts by effective height.
///
/// The decision uses the instruction bytes and committed State only, so every
/// validator reaches it identically. A committed change takes effect from the
/// next block; proofs submitted under the previous policy are judged by the
/// policy frozen for the block that executes them, without grandfathering.
/// Limits and retention windows may shrink while the policy stays coherent;
/// widening a retention window does not restore records already pruned.
///
/// # Errors
///
/// Returns an error when the payload is malformed, violates a structural or
/// coherence rule, or lowers the per-height transition limit below a committed
/// pending count.
pub fn validate_set_parameter(
    custom: &CustomParameter,
    pending_transition_counts: impl IntoIterator<Item = (u64, u32)>,
) -> Result<bool, ZkValidityPolicyChangeError> {
    let Some(policy) = ZkValidityPolicyV1::from_custom_parameter(custom) else {
        return Ok(false);
    };
    let policy = policy?;
    let maximum = policy.confidential.policy_transition_max_per_height;
    for (effective_height, count) in pending_transition_counts {
        if count > maximum {
            return Err(ZkValidityPolicyChangeError::PendingTransitionsExceedLimit {
                effective_height,
                count,
                maximum,
            });
        }
    }
    Ok(true)
}

#[cfg(test)]
#[path = "zk_validity_policy_parity_tests.rs"]
mod parity_tests;

#[cfg(test)]
#[path = "zk_validity_policy_boundary_tests.rs"]
mod boundary_tests;

#[cfg(test)]
mod tests {
    use iroha_data_model::parameter::Parameter;

    use super::*;
    use crate::state::{compute_zk_consensus_policy_hash, default_zk_config};

    /// The local resource settings of `zk`, for comparison. Exhaustive like
    /// [`policy_of`]: every field is either a local resource listed here or a
    /// validity value named as ignored.
    #[allow(clippy::too_many_lines)]
    fn local_resources_of(zk: &Zk) -> String {
        let Zk {
            halo2,
            fastpq,
            stark: _,
            sccp: _,
            ballot_history_cap: _,
            preverify_max_bytes: _,
            preverify_budget_bytes: _,
            proof_history_cap: _,
            proof_retention_grace_blocks: _,
            proof_prune_batch: _,
            bridge_proof_max_range_len: _,
            bridge_proof_max_past_age_blocks: _,
            bridge_proof_max_future_drift_blocks: _,
            poseidon_params_id: _,
            pedersen_params_id: _,
            kaigi_authorization_vk: _,
            kaigi_usage_vk: _,
            max_proof_size_bytes: _,
            max_nullifiers_per_tx: _,
            max_commitments_per_tx: _,
            max_confidential_ops_per_block: _,
            verify_timeout,
            max_anchor_age_blocks: _,
            max_proof_bytes_block: _,
            max_verify_calls_per_tx: _,
            max_verify_calls_per_block: _,
            max_public_inputs: _,
            reorg_depth_bound: _,
            policy_transition_delay_blocks: _,
            policy_transition_window_blocks: _,
            policy_transition_max_per_height: _,
            tree_roots_history_len: _,
            tree_frontier_checkpoint_interval: _,
            registry_max_vk_entries: _,
            registry_max_params_entries: _,
            registry_max_delta_per_block: _,
            gas: _,
        } = zk;
        let Halo2 {
            enabled: _,
            curve: _,
            backend: _,
            max_k: _,
            verifier_budget_ms,
            verifier_max_batch: _,
            verifier_worker_threads,
            verifier_queue_cap,
            verifier_enqueue_wait_ms,
            verifier_retry_ring_cap,
            verifier_retry_max_attempts,
            verifier_retry_tick_ms,
            max_envelope_bytes: _,
            max_proof_bytes: _,
            max_transcript_label_len: _,
            enforce_transcript_label_ascii: _,
        } = halo2;
        format!(
            "{verifier_budget_ms} {verifier_worker_threads} {verifier_queue_cap} \
             {verifier_enqueue_wait_ms} {verifier_retry_ring_cap} {verifier_retry_max_attempts} \
             {verifier_retry_tick_ms} {verify_timeout:?} {fastpq:?}"
        )
    }

    /// Settings whose every local resource differs from the default.
    fn scarce_local_resources() -> Zk {
        let mut node = default_zk_config();
        node.halo2.verifier_budget_ms += 4_321;
        node.halo2.verifier_worker_threads += 7;
        node.halo2.verifier_queue_cap += 33;
        node.halo2.verifier_enqueue_wait_ms += 5;
        node.halo2.verifier_retry_ring_cap += 9;
        node.halo2.verifier_retry_max_attempts += 2;
        node.halo2.verifier_retry_tick_ms += 3;
        node.verify_timeout = std::time::Duration::from_millis(5);
        node.fastpq.metal_trace = !node.fastpq.metal_trace;
        node.fastpq.device_class = Some("local-device".to_owned());
        node
    }

    fn changed_policy() -> ZkValidityPolicyV1 {
        let mut policy = ZkValidityPolicyV1::protocol_default();
        for (index, name) in ZkValidityPolicyV1::field_names().iter().enumerate() {
            let salt = u32::try_from(index).expect("field count fits") + 1;
            policy.perturb_field(name, salt);
        }
        policy
    }

    fn parameters_with(policy: &ZkValidityPolicyV1) -> Parameters {
        let mut parameters = Parameters::default();
        parameters.set_parameter(Parameter::Custom(policy.clone().into_custom_parameter()));
        parameters
    }

    #[test]
    fn protocol_default_is_the_default_of_the_settings_value() {
        // One default: the data-model protocol default and the default of the
        // State-owned settings value never drift apart.
        assert_eq!(
            policy_of(&default_zk_config()),
            ZkValidityPolicyV1::protocol_default()
        );
        assert!(node_validity_overrides(&default_zk_config()).is_empty());
    }

    #[test]
    fn every_policy_field_reaches_the_settings_and_the_consensus_hash() {
        let default_hash = compute_zk_consensus_policy_hash(&default_zk_config());
        let default = ZkValidityPolicyV1::protocol_default();
        let names = ZkValidityPolicyV1::field_names();
        assert_eq!(names.len(), 65);
        let mut seen_hashes = std::collections::BTreeSet::from([default_hash]);
        for (index, name) in names.iter().enumerate() {
            if name == "halo2.backend" {
                // One defined tag: the field has no second value to carry.
                continue;
            }
            let salt = u32::try_from(index).expect("field count fits") + 1;
            let mut policy = default.clone();
            assert!(policy.perturb_field(name, salt), "{name}");
            // The value reaches the settings and is read back unchanged, so the
            // field is neither dropped nor wired to another one.
            let mut zk = default_zk_config();
            apply_policy(&policy, &mut zk).expect("a valid policy applies");
            assert_eq!(policy_of(&zk), policy, "{name}");
            // It is part of the consensus-policy hash.
            let hash = compute_zk_consensus_policy_hash(&zk);
            assert!(seen_hashes.insert(hash), "{name} moves the hash uniquely");
            // A node that holds the value reports it and does not install it.
            assert_eq!(node_validity_overrides(&zk), std::slice::from_ref(name));
            let installed = node_local_resources(zk);
            assert!(node_validity_overrides(&installed).is_empty(), "{name}");
            assert_eq!(
                compute_zk_consensus_policy_hash(&installed),
                default_hash,
                "{name}"
            );
            // The committed value overrides whatever a node installed.
            let effective = effective_zk(scarce_local_resources(), &parameters_with(&policy));
            assert_eq!(policy_of(&effective), policy, "{name}");
        }
    }

    #[test]
    fn all_fields_changed_round_trip_and_are_stripped_from_a_node() {
        let all_changed = changed_policy();
        let default = ZkValidityPolicyV1::protocol_default();
        assert_eq!(all_changed.differing_fields(&default).len(), 64);
        let mut zk = default_zk_config();
        apply_policy(&all_changed, &mut zk).expect("valid policy");
        assert_eq!(policy_of(&zk), all_changed);
        assert_eq!(node_validity_overrides(&zk).len(), 64);
        assert!(node_validity_overrides(&node_local_resources(zk)).is_empty());
    }

    #[test]
    fn local_resources_survive_and_never_move_the_consensus_hash() {
        let default = default_zk_config();
        let scarce = scarce_local_resources();
        assert_ne!(local_resources_of(&scarce), local_resources_of(&default));
        // Local resources are not part of the consensus-policy hash.
        assert_eq!(
            compute_zk_consensus_policy_hash(&scarce),
            compute_zk_consensus_policy_hash(&default)
        );
        assert!(node_validity_overrides(&scarce).is_empty());
        // Installing a node keeps them, and so does a committed policy.
        let mut node = scarce.clone();
        apply_policy(&changed_policy(), &mut node).expect("valid policy");
        assert_eq!(local_resources_of(&node), local_resources_of(&scarce));
        let installed = node_local_resources(node);
        assert_eq!(local_resources_of(&installed), local_resources_of(&scarce));
        assert_eq!(
            policy_of(&installed),
            ZkValidityPolicyV1::protocol_default()
        );
        let effective = effective_zk(installed, &parameters_with(&changed_policy()));
        assert_eq!(local_resources_of(&effective), local_resources_of(&scarce));
        assert_eq!(policy_of(&effective), changed_policy());
    }

    #[test]
    fn effective_zk_is_pure_and_reads_the_committed_policy() {
        let committed_policy = changed_policy();
        assert_eq!(committed(&Parameters::default()), Ok(None));
        let parameters = parameters_with(&committed_policy);
        assert_eq!(committed(&parameters), Ok(Some(committed_policy.clone())));
        // Two nodes with different installed settings read the same policy.
        let mut second = default_zk_config();
        second.halo2.max_k = 3;
        second.max_proof_size_bytes = 9;
        let first = effective_zk(default_zk_config(), &parameters);
        let second = effective_zk(second, &parameters);
        assert_eq!(policy_of(&first), committed_policy);
        assert_eq!(policy_of(&second), committed_policy);
        assert_eq!(
            compute_zk_consensus_policy_hash(&first),
            compute_zk_consensus_policy_hash(&second)
        );
        // The committed schedule is part of the returned settings; a State
        // without the policy still reads the protocol default.
        assert_ne!(first.gas.proof_base, crate::gas::DEFAULT_ZK_GAS.proof_base);
        assert_eq!(
            effective_zk(default_zk_config(), &Parameters::default())
                .gas
                .proof_base,
            crate::gas::DEFAULT_ZK_GAS.proof_base
        );
        // A different committed payload is decoded afresh, not served from the memo.
        let mut other = ZkValidityPolicyV1::protocol_default();
        other.confidential.max_nullifiers_per_tx += 1;
        assert_eq!(
            policy_of(&effective_zk(default_zk_config(), &parameters_with(&other))),
            other
        );
        assert_eq!(
            policy_of(&effective_zk(default_zk_config(), &parameters)),
            committed_policy
        );
        // Without a committed policy the installed value is returned as is.
        assert_eq!(
            policy_of(&effective_zk(default_zk_config(), &Parameters::default())),
            ZkValidityPolicyV1::protocol_default()
        );
        // A payload no valid transition commits leaves the installed value and
        // is reported by `committed`.
        let mut malformed = Parameters::default();
        malformed.set_parameter(Parameter::Custom(CustomParameter::new(
            ZkValidityPolicyV1::parameter_id(),
            Json::new("not a policy"),
        )));
        assert!(matches!(
            committed(&malformed),
            Err(ZkValidityPolicyError::Malformed(_))
        ));
        assert_eq!(
            policy_of(&effective_zk(default_zk_config(), &malformed)),
            ZkValidityPolicyV1::protocol_default()
        );
    }

    #[test]
    fn set_parameter_validation_uses_bytes_and_committed_state_only() {
        let other = CustomParameter::new(
            "another_parameter".parse().expect("valid name"),
            Json::new(1_u32),
        );
        assert_eq!(validate_set_parameter(&other, []), Ok(false));
        let valid = changed_policy().into_custom_parameter();
        assert_eq!(validate_set_parameter(&valid, []), Ok(true));
        let not_a_policy = CustomParameter::new(
            ZkValidityPolicyV1::parameter_id(),
            Json::new("not a policy"),
        );
        assert!(matches!(
            validate_set_parameter(&not_a_policy, []),
            Err(ZkValidityPolicyChangeError::Policy(
                ZkValidityPolicyError::Malformed(_)
            ))
        ));
        let mut incoherent = ZkValidityPolicyV1::protocol_default();
        incoherent.confidential.tree_roots_history_len = 1;
        assert!(matches!(
            validate_set_parameter(&incoherent.into_custom_parameter(), []),
            Err(ZkValidityPolicyChangeError::Policy(
                ZkValidityPolicyError::Incoherent(_)
            ))
        ));
        // Pending committed transitions are obligations the new limit must cover.
        let mut tight = ZkValidityPolicyV1::protocol_default();
        tight.confidential.policy_transition_max_per_height = 2;
        let tight = tight.into_custom_parameter();
        assert_eq!(validate_set_parameter(&tight, [(40, 2), (41, 1)]), Ok(true));
        assert_eq!(
            validate_set_parameter(&tight, [(40, 2), (41, 3)]),
            Err(ZkValidityPolicyChangeError::PendingTransitionsExceedLimit {
                effective_height: 41,
                count: 3,
                maximum: 2,
            })
        );
    }

    #[test]
    fn a_failed_application_leaves_the_settings_untouched() {
        let mut untouched = scarce_local_resources();
        let before = format!("{untouched:?}");
        let mut invalid = changed_policy();
        invalid.confidential.tree_roots_history_len = 0;
        assert_eq!(
            apply_policy(&invalid, &mut untouched),
            Err(ZkValidityPolicyError::Zero(
                "confidential.tree_roots_history_len"
            ))
        );
        assert_eq!(format!("{untouched:?}"), before);
        // The conversions agree with the data-model tag lists.
        for tag in iroha_data_model::zk_validity_policy::HALO2_CURVE_TAGS {
            assert_eq!(curve_tag(curve_from_tag(tag).expect("defined curve")), tag);
        }
        for tag in iroha_data_model::zk_validity_policy::HALO2_BACKEND_TAGS {
            assert_eq!(
                backend_tag(backend_from_tag(tag).expect("defined backend")),
                tag
            );
        }
        assert!(curve_from_tag("secp256k1").is_err());
        assert!(backend_from_tag("kzg").is_err());
        assert_eq!(count(7), 7);
        assert_eq!(size(7, "field"), Ok(7));
        assert!(non_zero_u32(0, "field").is_err());
        assert!(non_zero_u64(0, "field").is_err());
        assert_eq!(key_ref(None), None);
        assert!(key_ref_to_actual(None).is_none());
        // A relation-selecting key reference is carried unchanged in both directions.
        let mut keyed = ZkValidityPolicyV1::protocol_default();
        keyed.proofs.kaigi_usage_vk = Some(ZkVerifyingKeyRefV1 {
            backend: "halo2/ipa".to_owned(),
            name: "kaigi-usage-v1".to_owned(),
        });
        let mut zk = default_zk_config();
        apply_policy(&keyed, &mut zk).expect("a valid policy applies");
        let usage = zk.kaigi_usage_vk.as_ref().expect("the usage key is set");
        let committed_usage = keyed.proofs.kaigi_usage_vk.as_ref().expect("set above");
        assert_eq!(usage.backend, committed_usage.backend);
        assert_eq!(usage.name, committed_usage.name);
        assert!(zk.kaigi_authorization_vk.is_none());
        assert_eq!(policy_of(&zk), keyed);
    }
}
