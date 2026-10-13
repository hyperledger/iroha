//! Real multisig execution records authenticated under the complete certified World cut.

use super::*;
use crate::{
    smartcontracts::isi::multisig::{
        multisig_approval_outcome_state_key, multisig_proposal_terminal_execution_state_key,
    },
    state::{World, WorldReadOnly},
    sumeragi::{
        finality::build_proof,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetId},
    domain::Domain,
    isi::{Burn, InstructionBox, Mint, Register},
    sumeragi_finality::{SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};
use iroha_executor_data_model::isi::multisig::{
    DEFAULT_MULTISIG_TTL_MS, MultisigApprovalOutcomeStatusV1, MultisigApprovalOutcomeV1,
    MultisigApprove, MultisigProposalId, MultisigProposalNonce,
    MultisigProposalTerminalExecutionStateV1, MultisigProposalTerminalStatus, MultisigPropose,
    MultisigRegister, MultisigSpec,
};
use iroha_model_base::{domain::DomainId, state_path::StatePath};
use iroha_primitives::numeric::Quantity;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
};

struct ExecutedMultisig {
    chain: CertifiedTestChain,
    account: AccountId,
    holding: AssetId,
    instructions: Vec<InstructionBox>,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    proposal_id: MultisigProposalId,
    entrypoint_hash: [u8; 32],
    keys: [StatePath; 2],
    approval_height: u64,
}

fn executed_multisig() -> ExecutedMultisig {
    let first = KeyPair::from_seed(vec![0x81; 32], Algorithm::Ed25519);
    let second = KeyPair::from_seed(vec![0x82; 32], Algorithm::Ed25519);
    let first_id = AccountId::new(first.public_key().clone());
    let second_id = AccountId::new(second.public_key().clone());
    let anchor = AccountId::new(
        KeyPair::from_seed(vec![0x83; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let domain = DomainId::try_new("multisig_snapshot", "universal").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "coin".parse().unwrap());
    let mut config = TestChainConfig::new(World::new(), 1_000);
    let genesis_key = config.genesis_key.clone();
    config.genesis_instructions = vec![
        Register::domain(Domain::new(domain.clone())).into(),
        Register::account(Account::new(first_id.clone())).into(),
        Register::account(Account::new(second_id.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            definition.clone(),
            "Multisig snapshot coin",
            AssetBalancePolicy::Global,
            Some(domain.clone()),
        ))
        .into(),
    ];
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let spec = MultisigSpec::new(
        BTreeMap::from([(first_id, 1), (second_id, 1)]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
    );
    let register = chain.sign(
        &genesis_key,
        [MultisigRegister::with_account(anchor, domain, spec).into()],
        2_000,
    );
    assert_eq!(chain.commit_at(2_000, vec![register]), [true]);
    let account = chain
        .state()
        .view()
        .world()
        .accounts_iter()
        .find(|account| account.id().multisig_policy().is_some())
        .unwrap()
        .id()
        .clone();
    let holding = AssetId::new(definition, account.clone());
    let mint = chain.sign(
        &genesis_key,
        [Mint::asset_quantity(10_u32, holding.clone()).into()],
        3_000,
    );
    assert_eq!(chain.commit_at(3_000, vec![mint]), [true]);
    let instructions = vec![InstructionBox::from(Burn::asset_quantity(
        3_u32,
        holding.clone(),
    ))];
    let instructions_hash = HashOf::new(&instructions);
    let nonce = MultisigProposalNonce::new([7; 32]).unwrap();
    let proposal_id = MultisigProposalId::derive(&chain.network_id(), &account, &nonce);
    let propose = chain.sign(
        &first,
        [MultisigPropose::new(account.clone(), nonce, instructions.clone(), None).into()],
        4_000,
    );
    assert_eq!(chain.commit_at(4_000, vec![propose]), [true]);
    let approve = chain.sign(
        &second,
        [MultisigApprove::new(account.clone(), proposal_id, instructions_hash).into()],
        5_000,
    );
    let entrypoint_hash = *approve.hash_as_entrypoint().as_ref();
    assert_eq!(chain.commit_at(5_000, vec![approve]), [true]);
    let approval_height = chain.height();
    let keys = [
        multisig_approval_outcome_state_key(entrypoint_hash, &account, &proposal_id),
        multisig_proposal_terminal_execution_state_key(entrypoint_hash, &account, &proposal_id),
    ];
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .assets()
            .get(&holding)
            .unwrap()
            .as_ref(),
        &Quantity::from(7_u32)
    );
    ExecutedMultisig {
        chain,
        account,
        holding,
        instructions,
        instructions_hash,
        proposal_id,
        entrypoint_hash,
        keys,
        approval_height,
    }
}

fn verified_tip(chain: &CertifiedTestChain) -> VerifiedSumeragiBlock {
    // The original signed genesis and its four real validator PoPs are selected
    // from fixture custody, independently of the snapshot response under test.
    let view = chain.state().view();
    let genesis = build_proof(&view, 1).unwrap();
    let mut verifier = SumeragiFinalityVerifier::new(
        chain.genesis(),
        view.chain_id().as_ref(),
        genesis.committee.clone(),
    )
    .unwrap();
    let mut authenticated = verifier.verify(&genesis).unwrap();
    for height in 2..=chain.height() {
        authenticated = verifier
            .verify(&build_proof(&view, height).unwrap())
            .unwrap();
    }
    authenticated
}

#[test]
fn native_multisig_records_are_authenticated_by_real_certified_execution() {
    let mut fixture = executed_multisig();
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let immediate = fixture.chain.committed(fixture.approval_height);
    // Ordinary execution currently writes both records before the certified
    // result is sealed. If this lifecycle ever changes, a tail-only row must not
    // be represented by the applied root instead of its certified pre-tail root.
    fixture
        .chain
        .state()
        .with_native_execution_records_snapshot_v1(
            &immediate,
            &fixture.keys,
            &budget,
            |snapshot, first, second| {
                let authenticated = snapshot
                    .authenticate(&verified_tip(&fixture.chain))
                    .unwrap();
                authenticated
                    .verify_table_value("world.smart_contract_state", &fixture.keys[0], first)
                    .unwrap();
                authenticated
                    .verify_table_value("world.smart_contract_state", &fixture.keys[1], second)
                    .unwrap();
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(budget.reserved_bytes(), 0);

    // A genuine later signed block makes retained execution records eligible
    // even when their original creation occurred after a prior sealed result.
    fixture.chain.commit_at(6_000, Vec::new());
    let tip = fixture.chain.committed(fixture.chain.height());
    let verified_block = verified_tip(&fixture.chain);
    fixture
        .chain
        .state()
        .with_native_execution_records_snapshot_v1(
            &tip,
            &fixture.keys,
            &budget,
            |snapshot, first, second| {
                let authenticated = snapshot.authenticate(&verified_block).unwrap();
                for (key, raw) in [(&fixture.keys[0], first), (&fixture.keys[1], second)] {
                    authenticated
                        .verify_table_value("world.smart_contract_state", key, raw)
                        .unwrap();
                    let mut mutated = raw.clone();
                    mutated[0] ^= 1;
                    assert!(
                        authenticated
                            .verify_table_value("world.smart_contract_state", key, &mutated)
                            .is_err()
                    );
                }
                let outcome =
                    norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(first).unwrap();
                let terminal =
                    norito::decode_from_bytes::<MultisigProposalTerminalExecutionStateV1>(second)
                        .unwrap();
                assert_eq!(outcome.status, MultisigApprovalOutcomeStatusV1::Executed);
                assert_eq!(outcome.entrypoint_account_id, fixture.account);
                assert_eq!(outcome.resolved_multisig_account_id, fixture.account);
                assert_eq!(outcome.instructions_hash, fixture.instructions_hash);
                assert_eq!(outcome.proposal_id, fixture.proposal_id);
                assert_eq!(outcome.block_height, fixture.approval_height);
                assert_eq!(outcome.entrypoint_hash, fixture.entrypoint_hash);
                assert_eq!(terminal.entrypoint_account_id, fixture.account);
                assert_eq!(terminal.terminal_entrypoint_hash, fixture.entrypoint_hash);
                assert_eq!(terminal.terminal_block_height, fixture.approval_height);
                assert_eq!(
                    terminal.terminal.status,
                    MultisigProposalTerminalStatus::Finalized
                );
                assert_eq!(
                    terminal.terminal.proposal.instructions,
                    fixture.instructions
                );
                assert_eq!(
                    terminal.terminal.instructions_hash,
                    fixture.instructions_hash
                );
                assert_eq!(terminal.terminal.multisig_account_id, fixture.account);
                assert_eq!(terminal.terminal.proposal_id, fixture.proposal_id);
                assert!(
                    authenticated
                        .verify_table_value("world.smart_contract_state", &fixture.keys[1], first)
                        .is_err()
                );
                assert!(
                    authenticated
                        .verify_table_value(
                            "world.smart_contract_state",
                            &fixture.keys[0],
                            &outcome
                        )
                        .is_err()
                );
                assert!(budget.reserved_bytes() > 0);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        fixture
            .chain
            .state()
            .view()
            .world()
            .assets()
            .get(&fixture.holding)
            .unwrap()
            .as_ref(),
        &Quantity::from(7_u32)
    );
    assert!(
        fixture
            .chain
            .state()
            .with_native_execution_records_snapshot_v1(
                &immediate,
                &fixture.keys,
                &budget,
                |_, _, _| Ok(()),
            )
            .is_err()
    );
    assert!(
        fixture
            .chain
            .state()
            .with_native_execution_records_snapshot_v1(
                &tip,
                &[fixture.keys[0].clone(), fixture.keys[0].clone()],
                &budget,
                |_, _, _| Ok(()),
            )
            .is_err()
    );
    assert!(
        fixture
            .chain
            .state()
            .with_native_execution_records_snapshot_v1(
                &tip,
                &fixture.keys,
                &AllocationBudget::new(0),
                |_, _, _| Ok(()),
            )
            .is_err()
    );
}
