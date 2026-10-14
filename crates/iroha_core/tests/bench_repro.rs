//! Reproduces the ISI gas calibration benchmark setup for debugging.

use iroha_core::{
    executor::{Executor, InstructionExecutionProfile},
    gas,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    alias_setup::{
        AliasDomainIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1, AliasQuoteGuardV1,
        ResolvedDomainV1,
    },
    isi::alias_setup::EnsureAlias,
    prelude::*,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::gen_account_in;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn bench_block_header() -> BlockHeader {
    BlockHeader::new(nonzero!(2_u64), None, None, 0, 0)
}
fn build_bench_state() -> (State, AccountId, AccountId) {
    let (authority, _) = gen_account_in("wonderland");
    let (recipient, _) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let genesis_domain =
        Domain::new(DomainId::try_new("genesis", "universal").expect("valid genesis domain id"))
            .build(&authority);
    let bench_domain =
        Domain::new(DomainId::try_new("bench", "universal").expect("valid bench domain id"))
            .build(&authority);
    let authority_account = Account::new(authority.clone()).build(&authority);
    let recipient_account = Account::new(recipient.clone()).build(&recipient);
    let world = World::with(
        [genesis_domain, domain, bench_domain],
        [authority_account, recipient_account],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    (state, authority, recipient)
}
#[test]
fn execute_register_domain_like_bench() {
    let (state, authority, _recipient) = build_bench_state();
    let executor = Executor::default();
    let mut block = state.block(bench_block_header());
    let mut tx = block.transaction();
    let domain_id = DomainId::try_new("bench", "universal").expect("valid domain id");
    let instr = EnsureAlias::new(
        AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain_id.clone(), DataSpaceId::UNIVERSAL),
            owner: authority.clone(),
        }),
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: 0,
            expected_payment_asset: AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("valid payment asset domain"),
                "xor".parse().expect("valid payment asset name"),
            ),
            max_amount: 0_u64.into(),
            valid_until_ms: 0,
        },
    )
    .into();
    let _ = gas::meter_instruction(&instr, &iroha_core::gas::DEFAULT_ZK_GAS)
        .expect("gas quote must complete for this fixture");
    executor
        .execute_instruction_with_profile(
            &mut tx,
            &authority,
            instr,
            InstructionExecutionProfile::Bench,
        )
        .expect("bench profile execution");
    assert!(
        tx.world.domains().get(&domain_id).is_some(),
        "domain remains present after exact alias lifecycle execution"
    );
    assert!(
        tx.world.accounts().get(&authority).is_some(),
        "authority account present"
    );
}
