//! Portable policy proofs retain the immutable pricing anchor after historical compaction.
//!
//! These are structural verifier fixtures with genuine native certificates and synthetic
//! ordinary writes. They do not execute Parliament enactment or qualify reward settlement.

use std::collections::BTreeMap;

use super::{tests::*, *};
use iroha_data_model::{
    asset::AssetDefinitionId,
    block::consensus::{ExecKv, ExecWitness},
    smart_contract::ContractAddress,
    sumeragi_finality::{SUMERAGI_LANE_STATE_WITNESS_KEY, SumeragiLaneStateCommitment},
    sumeragi_lanes::SumeragiLaneState,
    testing::native_finality::NativeFinalityFixture,
    validation_fee::{
        RetailFeeScheduleV1, VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        VALIDATION_FEE_POLICY_WITNESS_KEY_V1, VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS,
        ValidationFeeChargingMode, ValidationFeePayoutPolicyEntryV1,
        ValidationFeePayoutPolicyRegistryV1, ValidationFeePolicySnapshotCommitmentV1,
        initial_validation_fee_amount,
    },
};
use iroha_model_base::{
    domain::DomainId,
    topology::{DataSpaceId, LaneId},
};

fn authorized(proposal: ProposalKind, height: u64) -> ValidationFeeParliamentAuthorizationV1 {
    let mut authorization = parliament_authorization(proposal.fingerprint(), height);
    authorization.governance_certificate.effect_preimage_hash = proposal.effect_preimage_hash_v1();
    authorization.governance_certificate_id =
        iroha_data_model::governance::types::GovernanceCertificateId::derive_v1(
            &authorization.governance_certificate,
        );
    authorization
}

fn registry(network_id: NetworkId) -> ValidationFeePolicyRegistryV1 {
    let asset = |domain, name: &str| {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new(domain, "universal").expect("fixture asset domain"),
            name.parse().expect("fixture asset name"),
        )
    };
    let contract_address =
        ContractAddress::derive(&network_id, &fixture_account(1), 41, DataSpaceId::UNIVERSAL)
            .expect("fixture treasury contract");
    let pool_contract_address =
        ContractAddress::derive(&network_id, &fixture_account(2), 43, DataSpaceId::UNIVERSAL)
            .expect("fixture conversion pool");
    let binding = ValidationFeeTreasuryPayoutBindingV1 {
        treasury_account_id: contract_address.subject_id(),
        contract_address,
        code_hash: [0x34; 32],
        entrypoint: "autonomous_validation_fee_tick".parse().unwrap(),
        ds_asset_id: asset("cbsi", "ds"),
        xor_asset_id: asset("xor", "xor"),
        pool_vault_account_id: pool_contract_address.subject_id(),
        pool_contract_address,
        pool_code_hash: [0x36; 32],
        reward_pool_account_id: fixture_account(3),
        reference_feed_id: "xor_per_sbd".parse().unwrap(),
        reference_feed_config_version: 1,
        reference_provider_accounts: (20..25).map(fixture_account).collect(),
        max_sbd_per_attempt_minor: 1_000,
        max_sbd_per_day_minor: 100_000,
        min_interval_ms: 60_000,
        max_source_age_ms: 300_000,
        max_slippage_bps: 100,
        validator_lane_id: LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    };
    let first = ValidationFeePolicyV1 {
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id,
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: binding.ds_asset_id.clone(),
        ds_scale: VALIDATION_FEE_DS_SCALE,
        retail_schedule: RetailFeeScheduleV1::default(),
        effective_from_ms: 1_793_451_600_000,
        notice_published_at_ms: 1_790_859_600_000,
        fee: initial_validation_fee_amount(),
        treasury_account_id: binding.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.to_owned()],
        reward_custody: binding.custody(),
    };
    let pricing = |policy: ValidationFeePolicyV1, height| {
        let authorization = authorized(
            ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
                proposal_operator: fixture_account(3),
                policy: policy.clone(),
            }),
            height,
        );
        ValidationFeePolicyRegistryEntryV1::from_enactment(policy, authorization)
            .expect("fixture policy hash")
    };
    let first = pricing(first, 1_024);
    let mut second = first.policy.clone();
    second.policy_version = 2;
    second.previous_policy_hash = Some(first.policy_hash);
    // November has 30 days, so this is the next exact Honiara month boundary.
    second.effective_from_ms += 30 * 86_400_000;
    let second = pricing(second, 1_025);
    let authorization = authorized(
        ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
            proposal_operator: fixture_account(3),
            payout_binding: binding.clone(),
        }),
        1_024,
    );
    let registry = ValidationFeePolicyRegistryV1 {
        history: None,
        registered_policies: vec![first, second],
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![ValidationFeePayoutPolicyEntryV1 {
                revision: 1,
                proposal_id: authorization.proposal_fingerprint,
                lifecycle_seal: binding.lifecycle_seal().expect("fixture lifecycle seal"),
                payout_binding: binding,
                parliament_authorization: authorization,
            }],
        },
    };
    registry.validate().expect("structural policy registry");
    registry
}

// Independently construct the ordinary-write path for the two fixture leaves. The
// fixture's native lane proof computes and authenticates the same root separately.
fn policy_path(witness: &ExecWitness) -> ValidationFeePolicyWitnessProofV1 {
    let write = witness
        .writes
        .iter()
        .find(|write| write.key == VALIDATION_FEE_POLICY_WITNESS_KEY_V1)
        .expect("policy ordinary write");
    let empty = Hash::new([]);
    let mut nodes: BTreeMap<[u8; 32], Hash> = witness
        .writes
        .iter()
        .map(|write| {
            let path = Hash::new(&write.key);
            let value = Hash::new(&write.value);
            (
                path.into(),
                Hash::new_from_chunks(&[&[0], path.as_ref(), value.as_ref()]),
            )
        })
        .collect();
    let mut target: [u8; 32] = Hash::new(&write.key).into();
    let mut siblings = Vec::with_capacity(256);
    for bit in (0..256).rev() {
        let byte = bit / 8;
        let mask = 1_u8 << (bit % 8);
        let mut sibling = target;
        sibling[byte] ^= mask;
        siblings.push(nodes.get(&sibling).copied().unwrap_or(empty));
        let mut parents = BTreeMap::new();
        for (&path, &node) in &nodes {
            let mut sibling = path;
            sibling[byte] ^= mask;
            let other = nodes.get(&sibling).copied().unwrap_or(empty);
            let (left, right) = if path[byte] & mask == 0 {
                (node, other)
            } else {
                (other, node)
            };
            let mut parent = path;
            parent[byte] &= !mask;
            parents.insert(
                parent,
                Hash::new_from_chunks(&[&[1], left.as_ref(), right.as_ref()]),
            );
        }
        target[byte] &= !mask;
        nodes = parents;
    }
    ValidationFeePolicyWitnessProofV1 {
        key: write.key.clone(),
        value: write.value.clone(),
        siblings,
    }
}

#[test]
fn compacted_policy_proof_preserves_immutable_genesis_and_rejects_tampering() {
    let mut chain = NativeFinalityFixture::new();
    let network = chain.network_id();
    let checkpoint = chain.checkpoint();
    let original = registry(network);
    let genesis_hash = original.registered_policies[0].policy_hash;
    let compacted = original
        .compacted_suffix(2_048, u64::MAX, 2_048)
        .expect("valid compaction")
        .expect("retire first pricing policy");
    compacted
        .validate_history_source(2_048, &original)
        .expect("exact original snapshot binds the anchor");
    assert_eq!(compacted.registered_policies[0].policy.policy_version, 2);
    assert_ne!(compacted.registered_policies[0].policy_hash, genesis_hash);

    // The supplied registry is synthetic execution output. Native finality authenticates
    // its exact bytes; the production World compaction/enactment is tested in iroha_core.
    let header = chain.next_header();
    let height = header.height().get();
    let timestamp = u64::try_from(header.creation_time().as_millis()).unwrap();
    let snapshot =
        ValidationFeePolicySnapshotCommitmentV1::from_registry(height, timestamp, Some(&compacted));
    let lanes =
        SumeragiLaneStateCommitment::from_state(network, height, &SumeragiLaneState::default())
            .expect("canonical empty lane state");
    let witness = ExecWitness {
        writes: vec![
            ExecKv {
                key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
                value: norito::encode_canonical(&lanes).unwrap(),
            },
            ExecKv {
                key: VALIDATION_FEE_POLICY_WITNESS_KEY_V1.to_vec(),
                value: norito::encode_canonical(&snapshot).unwrap(),
            },
        ],
        ..ExecWitness::default()
    };
    let block = chain.block_with_submitted_work(header);
    let certified = chain.certify_with_witness(block, &witness);
    let verified = chain
        .verifier()
        .verify_retained_decision(&certified)
        .expect("genuine exact-quorum certificate");
    let proof = ValidationFeeCurrentPolicyProofV1 {
        version: VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
        registry: Some(compacted),
        policy_witness: policy_path(&witness),
        finality_chain: vec![checkpoint.tip().clone(), certified],
        evaluated_context_id: verified.context_id(),
        evaluated_block_height: height,
        evaluated_block_hash: hex::encode(verified.header().hash().as_ref()),
        observed_ledger_tip_height: height,
        more_available: false,
    };
    let encoded = norito::encode_canonical(&proof).expect("canonical compacted proof");
    let proof: ValidationFeeCurrentPolicyProofV1 =
        norito::decode_canonical(&encoded).expect("compacted proof Norito roundtrip");
    let (projection, promoted) = proof
        .verify_with_immutable_binding(network, genesis_hash, &checkpoint)
        .expect("compaction preserves original immutable deployment binding");
    assert_eq!(
        projection.policy_chain_genesis_hash,
        hex::encode(genesis_hash)
    );
    assert_eq!(projection.head_policy_version, 2);
    assert_eq!(promoted.height(), height);

    let retained_hash = proof.registry.as_ref().unwrap().registered_policies[0].policy_hash;
    assert!(
        proof
            .verify_with_immutable_binding(network, retained_hash, &checkpoint)
            .expect_err("retained policy cannot replace the original anchor")
            .contains("policy-chain genesis hash mismatch")
    );
    let mut tampered = proof.clone();
    tampered
        .registry
        .as_mut()
        .unwrap()
        .history
        .as_mut()
        .unwrap()
        .genesis_policy_hash = Some(retained_hash);
    assert!(
        tampered
            .verify_with_immutable_binding(network, retained_hash, &checkpoint)
            .expect_err(
                "changing both offered and pinned anchor cannot forge the certified registry"
            )
            .contains("differs from its finalized snapshot commitment")
    );
}
