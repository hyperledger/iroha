//! Verify explicit Kotodama CNTR selection enters `main` and reaches `write_detail`.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::CoreHost,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{account::NewAccount, prelude::*};
use iroha_model_base::name::Name;
use ivm::{IVM, ProgramMetadata};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn seeded_authority(seed: u8) -> AccountId {
    let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("seeded Kotodama authority keypair should be valid");
    AccountId::new(keypair.public_key().clone())
}
fn select_kotodama_entrypoint(vm: &mut IVM, program: &[u8], name: &str) {
    let metadata = ProgramMetadata::parse(program).expect("parse Kotodama V1 artifact");
    let entrypoint = metadata
        .contract_interface
        .as_ref()
        .expect("Kotodama V1 artifact must embed CNTR")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == name)
        .unwrap_or_else(|| panic!("missing Kotodama V1 entrypoint `{name}`"));
    let entrypoint_pc = u64::try_from(metadata.prefix_len()).expect("program prefix fits u64")
        + entrypoint.entry_pc;
    vm.set_program_counter(entrypoint_pc)
        .unwrap_or_else(|error| panic!("select Kotodama V1 entrypoint `{name}`: {error:?}"));
}
#[test]
fn selected_kotodama_hello_main_entrypoint_writes_expected_detail() {
    let program = KotodamaCompiler::new()
        .compile_source(include_str!("../../../examples/hello/hello.ko"))
        .expect("compile hello contract");
    let authority = seeded_authority(7);
    let mut vm = IVM::new(5_000_000);
    vm.set_host(CoreHost::new(authority.clone()));
    vm.load_program(&program).expect("load hello contract");
    select_kotodama_entrypoint(&mut vm, &program, "main");
    vm.run().expect("run hello contract");
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query_handle);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    {
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let executor = tx.world.executor().clone();
        executor
            .execute_instruction(
                &mut tx,
                &authority,
                InstructionBox::from(Register::account(NewAccount::new(authority.clone()))),
            )
            .expect("register authority account");
        let queued = CoreHost::with_host(&mut vm, |host| host.apply_queued(&mut tx, &authority))
            .expect("apply queued hello instructions");
        assert_eq!(
            queued.len(),
            1,
            "expected selected `main` to queue exactly one detail write",
        );
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit hello block");
    }
    let key: Name = "example".parse().expect("metadata key");
    let view = state.view();
    let account = view
        .world
        .accounts()
        .get(&authority)
        .expect("authority account should exist");
    assert_eq!(
        account.metadata().get(&key).map(AsRef::as_ref),
        Some("{\"hello\":\"world\"}"),
    );
}
