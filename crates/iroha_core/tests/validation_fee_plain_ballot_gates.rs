//! Validation-fee proposals reject the standalone public PLAIN ballot path.

use core::num::NonZeroU64;

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{
        GovernanceProposalRecord, GovernanceProposalStatus, GovernanceReferendumRecord,
        GovernanceReferendumStatus, State, World, WorldReadOnly,
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    asset::AssetDefinitionId,
    block::BlockHeader,
    domain::Domain,
    governance::types::{ProposalKind, ValidationFeePolicyProposal},
    isi::{Grant, governance::CastPlainBallot},
    permission::Permission,
    validation_fee::{
        VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION, ValidationFeeChargingMode,
        ValidationFeePolicyV1,
    },
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;

const BALLOT_HEIGHT: u64 = 10;

fn account(seed: u8) -> AccountId {
    let key_pair =
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic key pair");
    AccountId::new(key_pair.public_key().clone())
}

#[test]
fn validation_fee_proposal_rejects_plain_ballot_without_state_effects() {
    let proposer = account(1);
    let domain_id = DomainId::try_new("validation_fee", "universal").expect("domain");
    let fee_asset_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "xor".parse().expect("asset name"),
    );
    let domain = Domain::new(domain_id).build(&proposer);
    let proposer_account = Account::new(proposer.clone()).build(&proposer);
    let world = World::with([domain], [proposer_account], []);
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut governance = state.gov.clone();
    governance.plain_voting_enabled = true;
    governance.min_bond_amount = Quantity::zero();
    governance.conviction_step_blocks = 1;
    state.set_gov(governance);

    let contract = iroha_data_model::smart_contract::ContractAddress::derive(
        state.network_id_ref(),
        &proposer,
        1,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let pool = iroha_data_model::smart_contract::ContractAddress::derive(
        state.network_id_ref(),
        &proposer,
        2,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let payout = iroha_data_model::validation_fee::ValidationFeeTreasuryPayoutBindingV1 {
        treasury_account_id: contract.subject_id(),
        contract_address: contract,
        code_hash: [1; 32],
        entrypoint: "fee_tick".parse().unwrap(),
        ds_asset_id: fee_asset_id.clone(),
        xor_asset_id: AssetDefinitionId::derive_from_components(
            DomainId::try_new("validation_fee", "universal").unwrap(),
            "xor_reward".parse().unwrap(),
        ),
        pool_vault_account_id: pool.subject_id(),
        pool_contract_address: pool,
        pool_code_hash: [2; 32],
        reward_pool_account_id: account(3),
        reference_feed_id: "xor_per_sbd".parse().unwrap(),
        reference_feed_config_version: 1,
        reference_provider_accounts: (10..15).map(account).collect(),
        max_sbd_per_attempt_minor: 1000,
        max_sbd_per_day_minor: 100_000,
        min_interval_ms: 60000,
        max_source_age_ms: 300_000,
        max_slippage_bps: 100,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    };
    let policy = ValidationFeePolicyV1 {
        retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
        effective_from_ms: 1_793_451_600_000,
        notice_published_at_ms: 1_790_859_600_000,
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id: *state.network_id_ref(),
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: fee_asset_id,
        ds_scale: VALIDATION_FEE_DS_SCALE,
        fee: "0.10".parse().unwrap(),
        treasury_account_id: payout.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,

        exemption_classes: vec!["TREASURY_PAYOUT".into()],
        reward_custody: payout.custody(),
    };
    assert_eq!(policy.policy_invariant_error(), None);
    let proposal_kind = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: proposer.clone(),
        policy,
    });
    let proposal_id = proposal_kind.fingerprint();
    let referendum_id = hex::encode(proposal_id);

    let header = BlockHeader::new(
        NonZeroU64::new(BALLOT_HEIGHT).expect("non-zero ballot height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut state_transaction = block.transaction();
    let ballot_permission: Permission = CanSubmitGovernanceBallot {
        referendum_id: referendum_id.clone(),
    }
    .into();
    Grant::account_permission(ballot_permission, proposer.clone())
        .execute(&proposer, &mut state_transaction)
        .expect("grant exact generic ballot permission");
    state_transaction.world.governance_proposals_mut().insert(
        proposal_id,
        GovernanceProposalRecord {
            proposer: proposer.clone(),
            kind: proposal_kind,
            created_height: BALLOT_HEIGHT,
            status: GovernanceProposalStatus::Proposed,
        },
    );
    state_transaction.world.governance_referenda_mut().insert(
        referendum_id.clone(),
        GovernanceReferendumRecord {
            h_start: BALLOT_HEIGHT,
            h_end: BALLOT_HEIGHT + 100,
            status: GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context: iroha_core::query::standalone_plain_test_fixture::context(
                &state_transaction.gov,
                0,
            ),
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );

    let error = CastPlainBallot {
        referendum_id: referendum_id.clone(),
        owner: proposer.clone(),
        direction: 0,
        amount: Quantity::from(1_u32),
        duration_blocks: 100,
    }
    .execute(&proposer, &mut state_transaction)
    .expect_err("validation-fee proposals must reject public PLAIN ballots");
    let message = error.to_string();
    assert!(
        message.contains("typed governance proposals") && message.contains("private Parliament"),
        "unexpected validation-fee PLAIN rejection: {message}"
    );
    assert!(
        state_transaction
            .world
            .governance_locks()
            .get(&referendum_id)
            .is_none(),
        "a rejected validation-fee PLAIN ballot must not create a governance lock"
    );
}
