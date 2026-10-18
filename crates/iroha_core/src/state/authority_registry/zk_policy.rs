//! Typed State-owned consensus proof policy.
//!
//! This is the complete configuration value inventory hashed by
//! `compute_zk_consensus_policy_hash`. Governed SCCP routes and bridge state are separate
//! World authority. Prover device choice, worker queues and wall-clock budgets
//! are local resources and are not independent consensus policy.

use iroha_config::parameters::actual::{Sccp, Zk};
use norito::{Decode, Encode, NoritoSchema};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:zk-stark:v1")]
struct ZkStarkPolicyV1 {
    enabled: bool,
    max_envelope_bytes: u64,
    max_proof_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:zk-pipa-r:v1")]
struct ZkPipaRPolicyV1 {
    enabled: bool,
    max_envelope_bytes: u64,
    max_proof_bytes: u64,
}

macro_rules! sccp_policy {
    ($($field:ident: $type:ty),+ $(,)?) => {
        #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
        #[norito(deny_unknown_fields)]
        #[norito_schema(name = "iroha:state:zk-sccp:v1")]
        struct ZkSccpPolicyV1 {
            $($field: $type,)+
        }

        impl ZkSccpPolicyV1 {
            fn from_actual(value: &Sccp) -> Self {
                Self { $($field: value.$field.get(),)+ }
            }
        }

        #[cfg(test)]
        fn assert_every_sccp_limit_is_bound() {
            let baseline = crate::state::default_zk_config();
            let expected = norito::encode_canonical(&ZkConsensusPolicyV1::from_actual(&baseline))
                .unwrap();
            let expected_hash = crate::state::compute_zk_consensus_policy_hash(&baseline);
            $(
                let mut changed = baseline.clone();
                let next = if changed.sccp.$field.get() == 1 { 2 } else { 1 };
                changed.sccp.$field = std::num::NonZero::new(next).unwrap();
                assert_ne!(
                    norito::encode_canonical(&ZkConsensusPolicyV1::from_actual(&changed)).unwrap(),
                    expected,
                    stringify!($field)
                );
                assert_ne!(
                    crate::state::compute_zk_consensus_policy_hash(&changed),
                    expected_hash,
                    stringify!($field)
                );
            )+
        }
    };
}

sccp_policy! {
    max_proofs_per_transaction: u32,
    max_proofs_per_block: u32,
    max_proof_bytes_per_proof: u64,
    max_proof_bytes_per_transaction: u64,
    max_proof_bytes_per_block: u64,
    max_native_headers_per_transaction: u32,
    max_native_headers_per_block: u32,
    max_ethereum_light_client_updates_per_transaction: u32,
    max_ethereum_light_client_updates_per_block: u32,
    max_native_header_bytes_per_transaction: u64,
    max_native_header_bytes_per_block: u64,
    max_ed25519_signature_checks_per_transaction: u32,
    max_ed25519_signature_checks_per_block: u32,
    max_bls_vote_attestations_per_transaction: u32,
    max_bls_vote_attestations_per_block: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:zk-verifying-key-ref:v1")]
struct ZkVerifyingKeyRefV1 {
    backend: String,
    name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:zk-proof-retention:v1")]
struct ZkProofRetentionPolicyV1 {
    ballot_history_cap: u64,
    preverify_max_bytes: u64,
    preverify_budget_bytes: u64,
    proof_history_cap: u64,
    proof_retention_grace_blocks: u64,
    proof_prune_batch: u64,
    bridge_proof_max_range_len: u64,
    bridge_proof_max_past_age_blocks: u64,
    bridge_proof_max_future_drift_blocks: u64,
    poseidon_params_id: Option<u32>,
    pedersen_params_id: Option<u32>,
    kaigi_authorization_vk: Option<ZkVerifyingKeyRefV1>,
    kaigi_usage_vk: Option<ZkVerifyingKeyRefV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:zk-confidential:v1")]
struct ZkConfidentialPolicyV1 {
    max_proof_size_bytes: u32,
    max_nullifiers_per_tx: u32,
    max_commitments_per_tx: u32,
    max_confidential_ops_per_block: u32,
    max_anchor_age_blocks: u64,
    max_proof_bytes_block: u64,
    max_verify_calls_per_tx: u32,
    max_verify_calls_per_block: u32,
    max_public_inputs: u32,
    reorg_depth_bound: u64,
    policy_transition_delay_blocks: u64,
    policy_transition_window_blocks: u64,
    policy_transition_max_per_height: u32,
    tree_roots_history_len: u64,
    tree_frontier_checkpoint_interval: u64,
    registry_max_vk_entries: u32,
    registry_max_params_entries: u32,
    registry_max_delta_per_block: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:zk-verification-gas:v1")]
struct ZkVerificationGasPolicyV1 {
    proof_base: u64,
    per_public_input: u64,
    per_proof_byte: u64,
    per_nullifier: u64,
    per_commitment: u64,
}

/// Exact first-release proof-admission and deterministic verifier-work policy.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:zk:v1")]
pub(super) struct ZkConsensusPolicyV1 {
    max_verify_batch: u32,
    pipa_r: ZkPipaRPolicyV1,
    stark: ZkStarkPolicyV1,
    sccp: ZkSccpPolicyV1,
    retention: ZkProofRetentionPolicyV1,
    confidential: ZkConfidentialPolicyV1,
    gas: ZkVerificationGasPolicyV1,
}

fn count(value: usize) -> u64 {
    u64::try_from(value).expect("ZK policy usize field must fit into u64")
}

fn key_ref(
    value: Option<&iroha_config::parameters::actual::VerifyingKeyRef>,
) -> Option<ZkVerifyingKeyRefV1> {
    value.map(|key| ZkVerifyingKeyRefV1 {
        backend: key.backend.clone(),
        name: key.name.clone(),
    })
}

impl ZkConsensusPolicyV1 {
    /// Project every value used by the current ZK consensus-policy hash.
    pub(super) fn from_actual(config: &Zk) -> Self {
        Self {
            max_verify_batch: config.max_verify_batch,
            pipa_r: ZkPipaRPolicyV1 {
                enabled: config.pipa_r.enabled,
                max_envelope_bytes: count(config.pipa_r.max_envelope_bytes),
                max_proof_bytes: count(config.pipa_r.max_proof_bytes),
            },
            stark: ZkStarkPolicyV1 {
                enabled: config.stark.enabled,
                max_envelope_bytes: count(config.stark.max_envelope_bytes),
                max_proof_bytes: count(config.stark.max_proof_bytes),
            },
            sccp: ZkSccpPolicyV1::from_actual(&config.sccp),
            retention: ZkProofRetentionPolicyV1 {
                ballot_history_cap: count(config.ballot_history_cap),
                preverify_max_bytes: count(config.preverify_max_bytes),
                preverify_budget_bytes: config.preverify_budget_bytes,
                proof_history_cap: count(config.proof_history_cap),
                proof_retention_grace_blocks: config.proof_retention_grace_blocks,
                proof_prune_batch: count(config.proof_prune_batch),
                bridge_proof_max_range_len: config.bridge_proof_max_range_len,
                bridge_proof_max_past_age_blocks: config.bridge_proof_max_past_age_blocks,
                bridge_proof_max_future_drift_blocks: config.bridge_proof_max_future_drift_blocks,
                poseidon_params_id: config.poseidon_params_id,
                pedersen_params_id: config.pedersen_params_id,
                kaigi_authorization_vk: key_ref(config.kaigi_authorization_vk.as_ref()),
                kaigi_usage_vk: key_ref(config.kaigi_usage_vk.as_ref()),
            },
            confidential: ZkConfidentialPolicyV1 {
                max_proof_size_bytes: config.max_proof_size_bytes,
                max_nullifiers_per_tx: config.max_nullifiers_per_tx,
                max_commitments_per_tx: config.max_commitments_per_tx,
                max_confidential_ops_per_block: config.max_confidential_ops_per_block,
                max_anchor_age_blocks: config.max_anchor_age_blocks,
                max_proof_bytes_block: config.max_proof_bytes_block,
                max_verify_calls_per_tx: config.max_verify_calls_per_tx,
                max_verify_calls_per_block: config.max_verify_calls_per_block,
                max_public_inputs: config.max_public_inputs,
                reorg_depth_bound: config.reorg_depth_bound,
                policy_transition_delay_blocks: config.policy_transition_delay_blocks,
                policy_transition_window_blocks: config.policy_transition_window_blocks,
                policy_transition_max_per_height: config.policy_transition_max_per_height.get(),
                tree_roots_history_len: count(config.tree_roots_history_len.get()),
                tree_frontier_checkpoint_interval: config.tree_frontier_checkpoint_interval,
                registry_max_vk_entries: config.registry_max_vk_entries,
                registry_max_params_entries: config.registry_max_params_entries,
                registry_max_delta_per_block: config.registry_max_delta_per_block,
            },
            gas: ZkVerificationGasPolicyV1 {
                proof_base: config.gas.proof_base,
                per_public_input: config.gas.per_public_input,
                per_proof_byte: config.gas.per_proof_byte,
                per_nullifier: config.gas.per_nullifier,
                per_commitment: config.gas.per_commitment,
            },
        }
    }
}

/// Borrow the validated policy retained by the original parameter MV owner.
pub(super) fn borrowed(
    policy: &iroha_data_model::zk_validity_policy::ZkValidityPolicyV1,
) -> impl norito::SerializePayload + '_ {
    use super::policy_borrowed::{Ref, record};
    record!(
        policy.proofs.max_verify_batch,
        record!(
            Ref(&policy.pipa_r.enabled),
            Ref(&policy.pipa_r.max_envelope_bytes),
            Ref(&policy.pipa_r.max_proof_bytes)
        ),
        record!(
            Ref(&policy.stark.enabled),
            Ref(&policy.stark.max_envelope_bytes),
            Ref(&policy.stark.max_proof_bytes)
        ),
        record!(
            Ref(&policy.sccp.max_proofs_per_transaction),
            Ref(&policy.sccp.max_proofs_per_block),
            Ref(&policy.sccp.max_proof_bytes_per_proof),
            Ref(&policy.sccp.max_proof_bytes_per_transaction),
            Ref(&policy.sccp.max_proof_bytes_per_block),
            Ref(&policy.sccp.max_native_headers_per_transaction),
            Ref(&policy.sccp.max_native_headers_per_block),
            Ref(&policy
                .sccp
                .max_ethereum_light_client_updates_per_transaction),
            Ref(&policy.sccp.max_ethereum_light_client_updates_per_block),
            Ref(&policy.sccp.max_native_header_bytes_per_transaction),
            Ref(&policy.sccp.max_native_header_bytes_per_block),
            Ref(&policy.sccp.max_ed25519_signature_checks_per_transaction),
            Ref(&policy.sccp.max_ed25519_signature_checks_per_block),
            Ref(&policy.sccp.max_bls_vote_attestations_per_transaction),
            Ref(&policy.sccp.max_bls_vote_attestations_per_block)
        ),
        record!(
            Ref(&policy.proofs.ballot_history_cap),
            Ref(&policy.proofs.preverify_max_bytes),
            Ref(&policy.proofs.preverify_budget_bytes),
            Ref(&policy.proofs.proof_history_cap),
            Ref(&policy.proofs.proof_retention_grace_blocks),
            Ref(&policy.proofs.proof_prune_batch),
            Ref(&policy.proofs.bridge_proof_max_range_len),
            Ref(&policy.proofs.bridge_proof_max_past_age_blocks),
            Ref(&policy.proofs.bridge_proof_max_future_drift_blocks),
            Ref(&policy.proofs.poseidon_params_id),
            Ref(&policy.proofs.pedersen_params_id),
            Ref(&policy.proofs.kaigi_authorization_vk),
            Ref(&policy.proofs.kaigi_usage_vk)
        ),
        record!(
            Ref(&policy.confidential.max_proof_size_bytes),
            Ref(&policy.confidential.max_nullifiers_per_tx),
            Ref(&policy.confidential.max_commitments_per_tx),
            Ref(&policy.confidential.max_confidential_ops_per_block),
            Ref(&policy.confidential.max_anchor_age_blocks),
            Ref(&policy.confidential.max_proof_bytes_block),
            Ref(&policy.confidential.max_verify_calls_per_tx),
            Ref(&policy.confidential.max_verify_calls_per_block),
            Ref(&policy.confidential.max_public_inputs),
            Ref(&policy.confidential.reorg_depth_bound),
            Ref(&policy.confidential.policy_transition_delay_blocks),
            Ref(&policy.confidential.policy_transition_window_blocks),
            Ref(&policy.confidential.policy_transition_max_per_height),
            Ref(&policy.confidential.tree_roots_history_len),
            Ref(&policy.confidential.tree_frontier_checkpoint_interval),
            Ref(&policy.confidential.registry_max_vk_entries),
            Ref(&policy.confidential.registry_max_params_entries),
            Ref(&policy.confidential.registry_max_delta_per_block)
        ),
        record!(
            Ref(&policy.gas.proof_base),
            Ref(&policy.gas.per_public_input),
            Ref(&policy.gas.per_proof_byte),
            Ref(&policy.gas.per_nullifier),
            Ref(&policy.gas.per_commitment)
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::VerifyingKeyRef;

    fn policy() -> Zk {
        crate::state::default_zk_config()
    }

    fn frame(config: &Zk) -> Vec<u8> {
        super::super::policy_borrowed::assert_same_payload(
            &borrowed(&crate::zk_validity_policy::policy_of(config)),
            &ZkConsensusPolicyV1::from_actual(config),
        );
        norito::encode_canonical(&ZkConsensusPolicyV1::from_actual(config)).unwrap()
    }

    fn assert_changed(original: &Zk, changed: &Zk, name: &str) {
        assert_ne!(frame(changed), frame(original), "{name} projection");
        assert_ne!(
            crate::state::compute_zk_consensus_policy_hash(changed),
            crate::state::compute_zk_consensus_policy_hash(original),
            "{name} existing consensus hash"
        );
    }

    macro_rules! check_top_number {
        ($baseline:ident, $field:ident) => {{
            let mut changed = $baseline.clone();
            changed.$field = if changed.$field == 1 { 2 } else { 1 };
            assert_changed(&$baseline, &changed, stringify!($field));
        }};
    }

    macro_rules! check_nested_number {
        ($baseline:ident, $owner:ident.$field:ident) => {{
            let mut changed = $baseline.clone();
            changed.$owner.$field = if changed.$owner.$field == 1 { 2 } else { 1 };
            assert_changed(&$baseline, &changed, stringify!($owner.$field));
        }};
    }

    macro_rules! check_top_nonzero {
        ($baseline:ident, $field:ident) => {{
            let mut changed = $baseline.clone();
            let next = if changed.$field.get() == 1 { 2 } else { 1 };
            changed.$field = std::num::NonZero::new(next).unwrap();
            assert_changed(&$baseline, &changed, stringify!($field));
        }};
    }

    #[test]
    fn zk_policy_has_canonical_v1_roundtrip() {
        let projected = ZkConsensusPolicyV1::from_actual(&policy());
        assert_eq!(ZkConsensusPolicyV1::nominal_name(), "iroha:state:zk:v1");
        let encoded = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<ZkConsensusPolicyV1>(&encoded).unwrap(),
            projected
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projected).unwrap(), encoded);
    }

    #[test]
    fn pipa_r_admission_inputs_bind_projection() {
        let baseline = policy();
        let mut changed = baseline.clone();
        changed.pipa_r.enabled = !changed.pipa_r.enabled;
        assert_changed(&baseline, &changed, "pipa_r.enabled");
        check_nested_number!(baseline, pipa_r.max_envelope_bytes);
        check_nested_number!(baseline, pipa_r.max_proof_bytes);
    }

    #[test]
    fn batch_and_stark_admission_inputs_bind_projection() {
        let baseline = policy();
        let mut changed = baseline.clone();
        changed.max_verify_batch += 1;
        assert_changed(&baseline, &changed, "max_verify_batch");
        let mut changed = baseline.clone();
        changed.stark.enabled = !changed.stark.enabled;
        assert_changed(&baseline, &changed, "stark.enabled");
        check_nested_number!(baseline, stark.max_envelope_bytes);
        check_nested_number!(baseline, stark.max_proof_bytes);
    }

    #[test]
    fn every_sccp_work_limit_binds_projection() {
        assert_every_sccp_limit_is_bound();
    }

    #[test]
    fn proof_retention_and_key_references_bind_projection() {
        let baseline = policy();
        check_top_number!(baseline, ballot_history_cap);
        check_top_number!(baseline, preverify_max_bytes);
        check_top_number!(baseline, preverify_budget_bytes);
        check_top_number!(baseline, proof_history_cap);
        check_top_number!(baseline, proof_retention_grace_blocks);
        check_top_number!(baseline, proof_prune_batch);
        check_top_number!(baseline, bridge_proof_max_range_len);
        check_top_number!(baseline, bridge_proof_max_past_age_blocks);
        check_top_number!(baseline, bridge_proof_max_future_drift_blocks);
        let mut changed = baseline.clone();
        changed.poseidon_params_id = Some(match baseline.poseidon_params_id {
            Some(1) => 2,
            _ => 1,
        });
        assert_changed(&baseline, &changed, "poseidon_params_id");
        let mut changed = baseline.clone();
        changed.pedersen_params_id = Some(match baseline.pedersen_params_id {
            Some(1) => 2,
            _ => 1,
        });
        assert_changed(&baseline, &changed, "pedersen_params_id");
        let alternate_key = |existing: &Option<VerifyingKeyRef>| VerifyingKeyRef {
            backend: "pipa-r/pasta".to_owned(),
            name: format!(
                "{}-alternate",
                existing.as_ref().map_or("test", |key| &key.name)
            ),
        };
        let mut changed = baseline.clone();
        changed.kaigi_authorization_vk = Some(alternate_key(&baseline.kaigi_authorization_vk));
        assert_changed(&baseline, &changed, "kaigi_authorization_vk");
        let mut changed = baseline.clone();
        changed.kaigi_usage_vk = Some(alternate_key(&baseline.kaigi_usage_vk));
        assert_changed(&baseline, &changed, "kaigi_usage_vk");
    }

    #[test]
    fn confidential_verification_limits_bind_projection() {
        let baseline = policy();
        check_top_number!(baseline, max_proof_size_bytes);
        check_top_number!(baseline, max_nullifiers_per_tx);
        check_top_number!(baseline, max_commitments_per_tx);
        check_top_number!(baseline, max_confidential_ops_per_block);
        check_top_number!(baseline, max_anchor_age_blocks);
        check_top_number!(baseline, max_proof_bytes_block);
        check_top_number!(baseline, max_verify_calls_per_tx);
        check_top_number!(baseline, max_verify_calls_per_block);
        check_top_number!(baseline, max_public_inputs);
        check_top_number!(baseline, reorg_depth_bound);
        check_top_number!(baseline, policy_transition_delay_blocks);
        check_top_number!(baseline, policy_transition_window_blocks);
        check_top_nonzero!(baseline, policy_transition_max_per_height);
        check_top_nonzero!(baseline, tree_roots_history_len);
        check_top_number!(baseline, tree_frontier_checkpoint_interval);
        check_top_number!(baseline, registry_max_vk_entries);
        check_top_number!(baseline, registry_max_params_entries);
        check_top_number!(baseline, registry_max_delta_per_block);
    }

    #[test]
    fn confidential_gas_and_local_scheduling_are_separated() {
        let baseline = policy();
        check_nested_number!(baseline, gas.proof_base);
        check_nested_number!(baseline, gas.per_public_input);
        check_nested_number!(baseline, gas.per_proof_byte);
        check_nested_number!(baseline, gas.per_nullifier);
        check_nested_number!(baseline, gas.per_commitment);
        let expected = frame(&baseline);
        let expected_hash = crate::state::compute_zk_consensus_policy_hash(&baseline);
        let mut local = baseline;
        local.ipa_commitment.max_k += 1;
        local.ipa_commitment.max_transcript_label_len += 1;
        local.ipa_commitment.max_envelope_bytes += 1;
        local.ipa_commitment.enforce_transcript_label_ascii =
            !local.ipa_commitment.enforce_transcript_label_ascii;
        local.trace.enabled = !local.trace.enabled;
        local.trace.max_batch += 1;
        local.trace.worker_threads += 1;
        local.trace.queue_cap += 1;
        local.trace.enqueue_wait_ms += 1;
        local.trace.retry_ring_cap += 1;
        local.trace.retry_max_attempts += 1;
        local.trace.retry_tick_ms += 1;
        local.fastpq.metal_trace = !local.fastpq.metal_trace;
        local.verify_timeout += std::time::Duration::from_millis(1);
        assert_eq!(frame(&local), expected);
        assert_eq!(
            crate::state::compute_zk_consensus_policy_hash(&local),
            expected_hash
        );
    }
}
