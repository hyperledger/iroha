//! Existing typed proposal fixtures shared by committed and actual frozen owners.

use crate::state::{GovernanceProposalRecord, GovernanceProposalStatus, World};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{account::AccountId, governance::types::ProposalKind};
use iroha_data_model::{
    governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal,
        ValidationFeePayoutLifecycleProposal,
    },
    smart_contract::ContractAddress,
    validation_fee::ValidationFeeTreasuryPayoutBindingV1,
};
use iroha_model_base::topology::DataSpaceId;

pub(in crate::state) fn proposal(kind: u8, height: u64) -> GovernanceProposalRecord {
    let ProposalKind::ValidationFeePolicy(policy) =
        crate::governance::parliament::tests::validation_fee_policy_proposal()
    else {
        unreachable!("canonical typed fee fixture");
    };
    let proposer = policy.proposal_operator.clone();
    let kind = match kind {
        0 => ProposalKind::ValidationFeePolicy(policy),
        1 => {
            let pool = ContractAddress::derive(
                &policy.policy.network_id,
                &proposer,
                99,
                DataSpaceId::UNIVERSAL,
            )
            .unwrap();
            let custody = policy.policy.reward_custody;
            let binding = ValidationFeeTreasuryPayoutBindingV1 {
                contract_address: custody.contract_address,
                code_hash: [46; 32],
                entrypoint: "autonomous_validation_fee_tick".parse().unwrap(),
                treasury_account_id: custody.treasury_account_id,
                ds_asset_id: custody.ds_asset_id,
                xor_asset_id: custody.xor_asset_id,
                pool_vault_account_id: pool.subject_id(),
                pool_contract_address: pool,
                pool_code_hash: [48; 32],
                reward_pool_account_id: custody.reward_pool_account_id,
                reference_feed_id: "xor_per_sbd".parse().unwrap(),
                reference_feed_config_version: 1,
                reference_provider_accounts: (60..65)
                    .map(|tag| {
                        let key =
                            KeyPair::try_from_seed(vec![tag; 32], Algorithm::Ed25519).unwrap();
                        AccountId::new(key.public_key().clone())
                    })
                    .collect(),
                max_sbd_per_attempt_minor: 1000,
                max_sbd_per_day_minor: 100_000,
                min_interval_ms: 60000,
                max_source_age_ms: 300_000,
                max_slippage_bps: 100,
                validator_lane_id: custody.validator_lane_id,
                min_reward_claim_xor_minor: 1,
            };
            assert_eq!(binding.invariant_error(), None);
            ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                proposal_operator: proposer.clone(),
                payout_binding: binding,
            })
        }
        2 => ProposalKind::DeployContract(DeployContractProposal {
            proposal_operator: proposer.clone(),
            contract_address: policy.policy.reward_custody.contract_address,
            code_hash: ContractCodeHash::new([31; 32]),
            abi_hash: ContractAbiHash::new([41; 32]),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        }),
        _ => unreachable!(),
    };
    GovernanceProposalRecord {
        proposer,
        kind,
        created_height: height,
        status: GovernanceProposalStatus::Proposed,
    }
}

pub(in crate::state) fn fixture() -> Box<World> {
    let mut world = Box::new(World::default());
    for kind in 0..3 {
        world
            .governance_proposals
            .insert([kind; 32], proposal(kind, 41));
    }
    world.rebuild_governance_read_indexes().unwrap();
    world
}
