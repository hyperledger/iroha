//! Governance instruction validation tests.

#![allow(clippy::items_after_statements)]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use iroha_core::{kura::Kura, query::store::LiveQueryStore, smartcontracts::Execute, state::State};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ProposalKind,
    },
    permission::Permission,
    prelude::*,
};
use iroha_executor_data_model::permission::governance::{
    CanProposeContractDeployment, CanSubmitGovernanceBallot,
};
use iroha_model_base::domain::DomainId;
use nonzero_ext::nonzero;
fn checked_random_governance_proposal_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked governance proposal keypair")
}
#[test]
fn governance_proposal_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_governance_proposal_keypair();
}
fn mk_state_and_authority() -> (State, iroha_data_model::account::AccountId) {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_governance_proposal_keypair();
    let (pk, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("apps", "universal").unwrap();
    let account_id = AccountId::of(pk);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world =
        iroha_core::state::World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query);
    (state, account_id)
}
fn proposal_contract_address(
    authority: &iroha_data_model::account::AccountId,
) -> iroha_data_model::smart_contract::ContractAddress {
    iroha_data_model::smart_contract::ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        authority,
        0,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("proposal contract address")
}
fn canonical_abi_hex() -> String {
    hex::encode(ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1))
}
#[test]
fn propose_rejects_non_canonical_abi_hash_for_v1() {
    let (state, authority) = mk_state_and_authority();
    let contract_address = proposal_contract_address(&authority);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm: Permission = CanProposeContractDeployment {
        contract_address: contract_address.clone(),
    }
    .into();
    Grant::account_permission(perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant propose");
    let result = iroha_data_model::isi::governance::ProposeDeployContract {
        contract_address,
        code_hash: ContractCodeHash::new([0x11; 32]),
        abi_hash: ContractAbiHash::new([0; 32]),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    }
    .execute(&authority, &mut stx);
    assert!(
        result.is_err(),
        "v1 contract proposals must use the canonical ABI hash"
    );
}
#[test]
fn propose_rejects_non_v1_abi_version() {
    let (state, authority) = mk_state_and_authority();
    let contract_address = proposal_contract_address(&authority);
    let header = BlockHeader::new(nonzero!(4_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm: Permission = CanProposeContractDeployment {
        contract_address: contract_address.clone(),
    }
    .into();
    Grant::account_permission(perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant propose");
    let result = iroha_data_model::isi::governance::ProposeDeployContract {
        contract_address,
        code_hash: ContractCodeHash::new([0x11; 32]),
        abi_hash: ContractAbiHash::from_hex_str(&canonical_abi_hex()).expect("ABI hash"),
        abi_version: AbiVersion::new(2),
        manifest_provenance: None,
    }
    .execute(&authority, &mut stx);
    assert!(result.is_err(), "only ABI version one is admitted");
}
#[test]
fn proposal_record_exposes_deploy_payload() {
    let (_state, authority) = mk_state_and_authority();
    let contract_address = proposal_contract_address(&authority);
    let record = iroha_core::state::GovernanceProposalRecord {
        proposer: authority.clone(),
        kind: ProposalKind::DeployContract(DeployContractProposal {
            proposal_operator: authority.clone(),
            contract_address: contract_address.clone(),
            code_hash: ContractCodeHash::from_hex_str(&"11".repeat(32)).expect("code hash"),
            abi_hash: ContractAbiHash::from_hex_str(&canonical_abi_hex()).expect("abi hash"),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        }),
        created_height: 42,
        status: iroha_core::state::GovernanceProposalStatus::Proposed,
    };
    let payload = record
        .as_deploy_contract()
        .expect("payload must be present");
    assert_eq!(payload.contract_address, contract_address);
}
#[test]
fn zk_ballot_rejects_oversized_proof() {
    let (mut state, authority) = mk_state_and_authority();
    state.gov.min_bond_amount = 0_u64.into();
    let mut zk_cfg = state.view().zk.clone();
    zk_cfg.preverify_max_bytes = 4;
    state
        .set_zk(zk_cfg)
        .expect("empty state accepts governance test configuration");
    let header = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm: Permission = CanSubmitGovernanceBallot {
        referendum_id: "election-1".into(),
    }
    .into();
    Grant::account_permission(perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant ballot permission");
    let oversized = vec![0u8; 16];
    let proof_b64 = BASE64_STD.encode(oversized);
    let res = iroha_data_model::isi::governance::CastZkBallot {
        election_id: "election-1".into(),
        proof_b64,
        public_inputs_json: "{}".into(),
    }
    .execute(&authority, &mut stx);
    assert!(res.is_err(), "oversized proofs must be rejected");
}
