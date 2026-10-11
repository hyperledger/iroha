//! End-to-end test for Kotodama pointer ABI asset operations.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::explicit_into_iter_loop, clippy::map_unwrap_or)]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::{CoreHost, CoreHostImpl},
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use ivm::{IVM, ProgramMetadata};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use kotodama_lang::compiler::{CompilerMode, CompilerOptions};
use mv::storage::StorageReadOnly;
use std::sync::Arc;
fn pointer_abi_test_compiler() -> KotodamaCompiler {
    KotodamaCompiler::new_with_options(CompilerOptions {
        mode: CompilerMode::Production,
        ..CompilerOptions::default()
    })
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
fn prepare_kotodama_arguments(
    program: &[u8],
    entrypoint_name: &str,
    payload: &Json,
) -> ivm::PreparedArgumentRecord {
    let metadata = ProgramMetadata::parse(program).expect("parse Kotodama V1 artifact");
    let schema = metadata
        .contract_interface
        .as_ref()
        .expect("Kotodama V1 artifact must embed CNTR")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == entrypoint_name)
        .unwrap_or_else(|| panic!("missing Kotodama V1 entrypoint `{entrypoint_name}`"))
        .argument_schema
        .as_ref()
        .unwrap_or_else(|| {
            panic!("Kotodama V1 entrypoint `{entrypoint_name}` must declare an argument schema")
        });
    let canonical = ivm_abi::arguments::encode_argument_record_from_json(schema, payload)
        .unwrap_or_else(|error| panic!("encode `{entrypoint_name}` arguments: {error}"));
    ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), u64::MAX)
        .unwrap_or_else(|error| panic!("prepare `{entrypoint_name}` arguments: {error:?}"))
}
fn parsed_asset_definition_literal(literal: &str) -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(literal).expect("canonical asset definition literal")
}
fn world_with_asset_definitions(
    authority: &AccountId,
    asset_definitions: &[AssetDefinitionId],
) -> World {
    let definitions = asset_definitions.iter().cloned().map(|id| {
        let name = id.canonical_address();
        AssetDefinition::numeric(
            id,
            name,
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(authority)
    });
    World::with_assets([], [], definitions, [], [])
}
fn state_with_asset_definitions(
    authority: &AccountId,
    asset_definitions: &[AssetDefinitionId],
) -> State {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    State::new_for_testing(
        world_with_asset_definitions(authority, asset_definitions),
        kura,
        query_handle,
    )
}
#[test]
fn kotodama_pointer_abi_asset_ops_end_to_end() {
    // Compile Kotodama sample
    let asset_domain_id = DomainId::try_new("wonder", "universal").unwrap();
    let asset_name: Name = "coin".parse().unwrap();
    let asset_def_seed: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            asset_domain_id.clone(),
            asset_name.clone(),
        );
    let sample_asset_literal = asset_def_seed.canonical_address();
    let src = include_str!("../../kotodama_lang/src/samples/asset_ops.ko")
        .replace("coin#wonder", &sample_asset_literal)
        .replace("6pEP9RjNoZ7beWkT3pLfKoM1dyfi", &sample_asset_literal);
    let compiler = KotodamaCompiler::new();
    let program = compiler.compile_source(&src).expect("compile kotodama");
    // Prepare VM with CoreHost
    let from = ALICE_ID.clone();
    let to = BOB_ID.clone();
    let query_asset_def = parsed_asset_definition_literal(&sample_asset_literal);
    let query_state = state_with_asset_definitions(&from, &[query_asset_def]);
    let query_view = query_state.view();
    let mut host = CoreHostImpl::new(from.clone());
    host.set_query_state(&query_view);
    let mut vm = IVM::new(50_000_000);
    vm.load_program(&program).expect("load program");
    select_kotodama_entrypoint(&mut vm, &program, "execute");
    vm.run_with_host(&mut host).expect("run VM");
    // Drain queued ISIs
    let queued = host.drain_instructions();
    assert!(!queued.is_empty());
    eprintln!("queued {} instructions", queued.len());
    for (i, instr) in queued.iter().enumerate() {
        eprintln!("queued[{i}]: {instr:?}");
    }
    // Seed the canonical asset definition directly. This test exercises the
    // generated asset operations, not registration authorization.
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let account_domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let asset_def = AssetDefinitionId::parse_address_literal(&sample_asset_literal)
        .expect("canonical asset definition literal");
    let account_domain = Domain::new(account_domain_id).build(&from);
    let asset_domain_record = Domain::new(asset_domain_id).build(&from);
    let from_account = Account::new(from.clone()).build(&from);
    let to_account = Account::new(to.clone()).build(&to);
    let asset_definition = AssetDefinition::numeric(
        asset_def.clone(),
        asset_name.to_string(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&from);
    let world = World::with(
        [account_domain, asset_domain_record],
        [from_account, to_account],
        [asset_definition],
    );
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let executor = tx.world.executor().clone();
    // Apply deterministic ISIs mirroring the sample program
    assert_eq!(queued.len(), 3, "expected three enqueued instructions");
    let expected_asset_id = AssetId::of(asset_def.clone(), from.clone());
    let expected_asset_id_to = AssetId::of(asset_def.clone(), to.clone());
    let mint = iroha_data_model::isi::Mint::asset_quantity(1000u32, expected_asset_id.clone());
    let transfer = iroha_data_model::isi::Transfer::asset_quantity(
        expected_asset_id.clone(),
        500u32,
        to.clone(),
    );
    let burn = iroha_data_model::isi::Burn::asset_quantity(100u32, expected_asset_id_to.clone());
    tx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
        [0x51; iroha_crypto::Hash::LENGTH],
    ));
    for instr in [
        InstructionBox::from(iroha_data_model::isi::MintBox::from(mint)),
        InstructionBox::from(iroha_data_model::isi::TransferBox::from(transfer)),
        InstructionBox::from(iroha_data_model::isi::BurnBox::from(burn)),
    ] {
        eprintln!("applying {instr:?}");
        executor
            .execute_instruction(&mut tx, &from, instr)
            .expect("execution should succeed");
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit block");
    // Rough balance checks: after sample, net effect:
    // mint 1000 to from, transfer 500 from->to, burn 100 from to
    // from: 1000 - 500 = 500; to: +500 - 100 = 400
    let from_asset = AssetId::of(asset_def.clone(), from.clone());
    let to_asset = AssetId::of(asset_def.clone(), to.clone());
    let from_bal = state
        .view()
        .world
        .assets()
        .get(&from_asset)
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    let to_bal = state
        .view()
        .world
        .assets()
        .get(&to_asset)
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    assert_eq!(from_bal, Quantity::from(500u32));
    assert_eq!(to_bal, Quantity::from(400u32));
}
#[test]
fn kotodama_state_loaded_pointers_drive_transfer_asset() {
    let asset_domain_id = DomainId::try_new("wonder", "universal").unwrap();
    let asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            asset_domain_id.clone(),
            "coin".parse().unwrap(),
        );
    let asset_literal = asset_def.canonical_address();
    let src = format!(
        r#"
        seiyaku PointerStateTransfer {{ permission TransferAsset;
          state StateMap<int, AssetDefinitionId> PoolAsset;
          kotoage fn main() authorize(TransferAsset) {{
            let key = 7;
            let quantity amount = 1;
            PoolAsset[key] = AssetDefinitionId::parse("{asset_literal}");
            let asset = PoolAsset.get(key).unwrap_or(AssetDefinitionId::parse("{asset_literal}"));
            ledger::asset::transfer(source: context::authority(), destination: context::authority(), asset_definition: asset, amount: amount, dataspace: DataSpaceId::parse("0"));
          }}
        }}
    "#
    );
    let program = pointer_abi_test_compiler()
        .compile_source(&src)
        .expect("compile pointer state transfer");
    let authority = ALICE_ID.clone();
    let query_asset_def = parsed_asset_definition_literal(&asset_literal);
    let query_state = state_with_asset_definitions(&authority, &[query_asset_def]);
    let query_view = query_state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_local_contract_debug_execution();
    host.set_query_state(&query_view);
    let mut vm = IVM::new(50_000_000);
    vm.load_program(&program).expect("load program");
    select_kotodama_entrypoint(&mut vm, &program, "main");
    vm.run_with_host(&mut host)
        .expect("state-loaded pointers should be accepted by transfer_asset");
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let account_domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_domain = Domain::new(account_domain_id).build(&authority);
    let asset_domain = Domain::new(asset_domain_id.clone()).build(&authority);
    let authority_account = Account::new(authority.clone()).build(&authority);
    let asset_definition = AssetDefinition::numeric(
        asset_def.clone(),
        "coin".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(asset_domain_id),
    )
    .build(&authority);
    let world = World::with(
        [account_domain, asset_domain],
        [authority_account],
        [asset_definition],
    );
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let mint = MintBox::from(Mint::asset_quantity(
        1u32,
        AssetId::of(asset_def.clone(), authority.clone()),
    ));
    let executor = tx.world.executor().clone();
    executor
        .execute_instruction(&mut tx, &authority, InstructionBox::from(mint))
        .expect("setup mint should succeed");
    let queued = host.drain_instructions();
    assert_eq!(queued.len(), 1, "expected one queued transfer");
    let transfer = queued[0]
        .as_any()
        .downcast_ref::<TransferBox>()
        .expect("queued instruction must be a transfer");
    let TransferBox::Asset(transfer) = transfer else {
        panic!("queued instruction must be an asset transfer");
    };
    assert_eq!(
        transfer.source,
        AssetId::of(asset_def.clone(), authority.clone())
    );
    assert_eq!(transfer.destination, authority);
    assert_eq!(transfer.object, Quantity::from(1_u32));
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit block");
    let balance = state
        .view()
        .world
        .assets()
        .get(&AssetId::of(asset_def, authority.clone()))
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    assert_eq!(balance, Quantity::from(1u32));
}
#[test]
fn kotodama_name_keyed_state_loaded_pointers_survive_cross_call() {
    let asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonder", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let asset_literal = asset_def.canonical_address();
    let write_src = format!(
        r#"
        seiyaku PointerStateWrite {{ permission WriteState;
          state StateMap<Name, AssetDefinitionId> PoolAsset;
          kotoage fn main() authorize(WriteState) {{
            let key = Name::parse("pool");
            PoolAsset[key] = AssetDefinitionId::parse("{asset_literal}");
          }}
        }}
    "#
    );
    let read_src = format!(
        r#"
        seiyaku PointerStateRead {{ permission TransferAsset;
          state StateMap<Name, AssetDefinitionId> PoolAsset;
          kotoage fn main() authorize(TransferAsset) {{
            let key = Name::parse("pool");
            let quantity amount = 1;
            let asset = PoolAsset.get(key).unwrap_or(AssetDefinitionId::parse("{asset_literal}"));
            ledger::asset::transfer(source: context::authority(), destination: context::authority(), asset_definition: asset, amount: amount, dataspace: DataSpaceId::parse("0"));
          }}
        }}
    "#
    );
    let authority = ALICE_ID.clone();
    let write_program = pointer_abi_test_compiler()
        .compile_source(&write_src)
        .expect("compile writer");
    let mut write_vm = IVM::new(50_000_000);
    let mut write_host = CoreHost::new(authority.clone());
    write_host.set_local_contract_debug_execution();
    write_vm.set_host(write_host);
    write_vm.load_program(&write_program).expect("load writer");
    select_kotodama_entrypoint(&mut write_vm, &write_program, "main");
    write_vm.run().expect("writer run");
    let overlay = CoreHost::with_host(&mut write_vm, CoreHost::drain_durable_state_overlay);
    assert_eq!(overlay.len(), 1, "expected one durable state write");
    let query_asset_def = parsed_asset_definition_literal(&asset_literal);
    let mut world = world_with_asset_definitions(&authority, &[query_asset_def]);
    for (path, value) in overlay {
        let stored = value.expect("state value must be present");
        world
            .smart_contract_state_mut_for_testing()
            .insert(path, stored);
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let view = state.view();
    let read_program = pointer_abi_test_compiler()
        .compile_source(&read_src)
        .expect("compile reader");
    let mut read_vm = IVM::new(50_000_000);
    let mut read_host = CoreHostImpl::new(authority.clone());
    read_host.set_local_contract_debug_execution();
    read_host.set_durable_state_snapshot_from_world(&view.world);
    read_host.set_query_state(&view);
    read_vm.load_program(&read_program).expect("load reader");
    select_kotodama_entrypoint(&mut read_vm, &read_program, "main");
    read_vm
        .run_with_host(&mut read_host)
        .expect("name-keyed state-loaded pointers should survive cross-call");
    let queued = read_host.drain_instructions();
    assert_eq!(queued.len(), 1, "expected one queued transfer");
}
#[test]
fn kotodama_mixed_name_keyed_state_loaded_pointers_survive_cross_call() {
    let asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonder", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let asset_literal = asset_def.canonical_address();
    let authority = ALICE_ID.clone();
    let vault = BOB_ID.clone();
    let vault_literal = vault.to_string();
    let write_src = format!(
        r#"
        seiyaku PointerStateWrite {{ permission WriteState;
          state StateMap<Name, AssetDefinitionId> PoolAsset;
          state StateMap<Name, AccountId> VaultAccount;
          kotoage fn main() authorize(WriteState) {{
            let key = Name::parse("pool");
            PoolAsset[key] = AssetDefinitionId::parse("{asset_literal}");
            VaultAccount[key] = AccountId::parse("{vault_literal}");
          }}
        }}
    "#
    );
    let read_src = format!(
        r#"
        seiyaku PointerStateRead {{ permission TransferAsset;
          state StateMap<Name, AssetDefinitionId> PoolAsset;
          state StateMap<Name, AccountId> VaultAccount;
          kotoage fn main() authorize(TransferAsset) {{
            let key = Name::parse("pool");
            let quantity amount = 1;
            let vault = VaultAccount.get(key).unwrap_or(AccountId::parse("{vault_literal}"));
            let asset = PoolAsset.get(key).unwrap_or(AssetDefinitionId::parse("{asset_literal}"));
            ledger::asset::transfer(source: context::authority(), destination: vault, asset_definition: asset, amount: amount, dataspace: DataSpaceId::parse("0"));
          }}
        }}
    "#
    );
    let write_program = pointer_abi_test_compiler()
        .compile_source(&write_src)
        .expect("compile writer");
    let mut write_vm = IVM::new(50_000_000);
    let mut write_host = CoreHost::new(authority.clone());
    write_host.set_local_contract_debug_execution();
    write_vm.set_host(write_host);
    write_vm.load_program(&write_program).expect("load writer");
    select_kotodama_entrypoint(&mut write_vm, &write_program, "main");
    write_vm.run().expect("writer run");
    let overlay = CoreHost::with_host(&mut write_vm, CoreHost::drain_durable_state_overlay);
    assert_eq!(overlay.len(), 2, "expected two durable state writes");
    let query_asset_def = parsed_asset_definition_literal(&asset_literal);
    let mut world = world_with_asset_definitions(&authority, &[query_asset_def]);
    for (path, value) in overlay {
        let stored = value.expect("state value must be present");
        world
            .smart_contract_state_mut_for_testing()
            .insert(path, stored);
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let view = state.view();
    let read_program = pointer_abi_test_compiler()
        .compile_source(&read_src)
        .expect("compile reader");
    let mut read_vm = IVM::new(50_000_000);
    let mut read_host = CoreHostImpl::new(authority.clone());
    read_host.set_local_contract_debug_execution();
    read_host.set_durable_state_snapshot_from_world(&view.world);
    read_host.set_query_state(&view);
    read_vm.load_program(&read_program).expect("load reader");
    select_kotodama_entrypoint(&mut read_vm, &read_program, "main");
    read_vm
        .run_with_host(&mut read_host)
        .expect("mixed state-loaded pointers should survive cross-call");
    let queued = read_host.drain_instructions();
    assert_eq!(queued.len(), 1, "expected one queued transfer");
}
#[test]
fn kotodama_event_to_state_loaded_transfer_asset_survives_cross_call() {
    let asset_literal = "6qLb5RYJbzychndCXgFa9aZzjWyx";
    let authority = ALICE_ID.clone();
    let vault = BOB_ID.clone();
    let authority_literal = authority.to_string();
    let vault_literal = vault.to_string();
    let write_src = format!(
        r#"
        seiyaku PointerStateWrite {{ permission WriteState;
          state StateMap<Name, AssetDefinitionId> BaseAsset;
          state StateMap<Name, AccountId> VaultAccount;
          kotoage fn main() authorize(WriteState) {{
            let key = Name::parse("pool");
            BaseAsset[key] = AssetDefinitionId::parse("{asset_literal}");
            VaultAccount[key] = AccountId::parse("{vault_literal}");
          }}
        }}
    "#
    );
    let read_src = format!(
        r#"
        seiyaku PointerStateRead {{ permission TransferAsset;
          state StateMap<Name, AssetDefinitionId> BaseAsset;
          state StateMap<Name, AccountId> VaultAccount;
          kotoage fn main() authorize(TransferAsset) {{
            let key = Name::parse("pool");
            let quantity event_base_amount = 1000;
            let ev = json {{ provider: AccountId::parse("{authority_literal}"), base_amount: event_base_amount }};
            let provider = ev.get_account_id(Name::parse("provider")).unwrap_or(AccountId::parse("{authority_literal}"));
            let quantity zero = 0;
            let base_amount = ev.get_quantity(Name::parse("base_amount")).unwrap_or(zero);
            let vault = VaultAccount.get(key).unwrap_or(AccountId::parse("{vault_literal}"));
            let asset = BaseAsset.get(key).unwrap_or(AssetDefinitionId::parse("{asset_literal}"));
            if base_amount > zero {{
              ledger::asset::transfer(source: provider, destination: vault, asset_definition: asset, amount: base_amount, dataspace: DataSpaceId::parse("0"));
            }}
          }}
        }}
    "#
    );
    let write_program = pointer_abi_test_compiler()
        .compile_source(&write_src)
        .expect("compile writer");
    let mut write_vm = IVM::new(50_000_000);
    let mut write_host = CoreHost::new(authority.clone());
    write_host.set_local_contract_debug_execution();
    write_vm.set_host(write_host);
    write_vm.load_program(&write_program).expect("load writer");
    select_kotodama_entrypoint(&mut write_vm, &write_program, "main");
    write_vm.run().expect("writer run");
    let overlay = CoreHost::with_host(&mut write_vm, CoreHost::drain_durable_state_overlay);
    assert_eq!(overlay.len(), 2, "expected two durable state writes");
    let query_asset_def = parsed_asset_definition_literal(asset_literal);
    let mut world = world_with_asset_definitions(&authority, &[query_asset_def]);
    for (path, value) in overlay {
        let stored = value.expect("state value must be present");
        world
            .smart_contract_state_mut_for_testing()
            .insert(path, stored);
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let view = state.view();
    let read_program = pointer_abi_test_compiler()
        .compile_source(&read_src)
        .expect("compile reader");
    let mut read_vm = IVM::new(50_000_000);
    let mut read_host = CoreHostImpl::new(authority.clone());
    read_host.set_local_contract_debug_execution();
    read_host.set_durable_state_snapshot_from_world(&view.world);
    read_host.set_query_state(&view);
    read_vm.load_program(&read_program).expect("load reader");
    select_kotodama_entrypoint(&mut read_vm, &read_program, "main");
    read_vm
        .run_with_host(&mut read_host)
        .expect("event-fed state-loaded transfer_asset should survive cross-call");
    let queued = read_host.drain_instructions();
    assert_eq!(queued.len(), 1, "expected one queued transfer");
}
#[test]
fn dlmm_pool_seed_bin_entrypoint_survives_cross_call() {
    let source = r#"
        seiyaku DlmmPool { permission Admin;
          state StateMap<Name, AssetDefinitionId> BaseAsset;
          state StateMap<Name, AssetDefinitionId> QuoteAsset;
          state StateMap<Name, AccountId> VaultAccount;
          state StateMap<Name, int> FeePips;
          state StateMap<Name, int> BinStep;
          state StateMap<Name, int> ActiveBin;
          state StateMap<int, quantity> SeededBase;
          state StateMap<int, quantity> SeededQuote;

          kotoage fn init_pool(AssetDefinitionId base_asset,
                             AssetDefinitionId quote_asset,
                             AccountId vault_account,
                             int fee_pips,
                             int bin_step,
                             int active_bin) authorize(Admin) {
            let pool = Name::parse("pool");
            BaseAsset[pool] = base_asset;
            QuoteAsset[pool] = quote_asset;
            VaultAccount[pool] = vault_account;
            FeePips[pool] = fee_pips;
            BinStep[pool] = bin_step;
            ActiveBin[pool] = active_bin;
          }

          kotoage fn seed_bin(AccountId provider,
                            int bin_id,
                            quantity base_amount,
            quantity quote_amount) authorize(Admin) {
            let pool = Name::parse("pool");
            let vault = VaultAccount.get(pool).unwrap_or(provider);
            let base_asset = BaseAsset.get(pool).unwrap_or(AssetDefinitionId::parse("6qLb5RYJbzychndCXgFa9aZzjWyx"));
            let quote_asset = QuoteAsset.get(pool).unwrap_or(AssetDefinitionId::parse("7Dsw1EgqCsPmv9HpEztf26xEL2qo"));
            ledger::asset::transfer(source: provider, destination: vault, asset_definition: base_asset, amount: base_amount, dataspace: DataSpaceId::parse("0"));
            ledger::asset::transfer(source: provider, destination: vault, asset_definition: quote_asset, amount: quote_amount, dataspace: DataSpaceId::parse("0"));
            SeededBase[bin_id] = base_amount;
            SeededQuote[bin_id] = quote_amount;
          }
        }
    "#;
    let program = pointer_abi_test_compiler()
        .compile_source(source)
        .expect("compile dlmm_pool");
    let artifact = ProgramMetadata::parse(&program).expect("parse contract artifact");
    let contract_interface = artifact
        .contract_interface
        .as_ref()
        .expect("contract interface");
    let prefix_len = (artifact.code_offset - artifact.header_len) as u64;
    let init_pool_pc = prefix_len
        + contract_interface
            .entrypoints
            .iter()
            .find(|entry| entry.name == "init_pool")
            .expect("init_pool entrypoint")
            .entry_pc;
    let seed_bin_pc = prefix_len
        + contract_interface
            .entrypoints
            .iter()
            .find(|entry| entry.name == "seed_bin")
            .expect("seed_bin entrypoint")
            .entry_pc;
    let authority = ALICE_ID.clone();
    let authority_literal = authority.to_string();
    let accounts = Arc::new(vec![authority.clone()]);
    let init_args = Json::new(norito::json!({
        "base_asset": "6qLb5RYJbzychndCXgFa9aZzjWyx",
        "quote_asset": "7Dsw1EgqCsPmv9HpEztf26xEL2qo",
        "vault_account": authority_literal,
        "fee_pips": "3000",
        "bin_step": "1",
        "active_bin": "0"
    }));
    let init_arguments = prepare_kotodama_arguments(&program, "init_pool", &init_args);
    let mut init_vm = IVM::new(50_000_000);
    let mut init_host = CoreHost::with_accounts_and_argument_record(
        authority.clone(),
        Arc::clone(&accounts),
        Some(init_arguments.clone()),
    );
    init_host.set_local_contract_debug_execution();
    init_vm.load_program(&program).expect("load dlmm_pool");
    init_vm
        .set_program_counter(init_pool_pc)
        .expect("set init_pool pc");
    init_vm.set_register(1, init_vm.memory.code_len());
    init_vm.set_host(init_host);
    init_arguments
        .precharge_vm(&mut init_vm)
        .expect("precharge init_pool arguments");
    init_vm.run().expect("init_pool run");
    let overlay = CoreHost::with_host(&mut init_vm, CoreHost::drain_durable_state_overlay);
    assert!(
        !overlay.is_empty(),
        "expected durable state writes from init_pool"
    );
    let base_asset = parsed_asset_definition_literal("6qLb5RYJbzychndCXgFa9aZzjWyx");
    let quote_asset = parsed_asset_definition_literal("7Dsw1EgqCsPmv9HpEztf26xEL2qo");
    let mut world = world_with_asset_definitions(&authority, &[base_asset, quote_asset]);
    for (path, value) in overlay {
        let stored = value.expect("state value must be present");
        world
            .smart_contract_state_mut_for_testing()
            .insert(path, stored);
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let view = state.view();
    let provider_literal = authority.to_string();
    let seed_args = Json::new(norito::json!({
        "provider": provider_literal,
        "bin_id": "0",
        "base_amount": "1000",
        "quote_amount": "1000"
    }));
    let seed_arguments = prepare_kotodama_arguments(&program, "seed_bin", &seed_args);
    let mut seed_vm = IVM::new(50_000_000);
    let mut seed_host = CoreHostImpl::with_accounts_and_argument_record(
        authority.clone(),
        Arc::clone(&accounts),
        Some(seed_arguments.clone()),
    );
    seed_host.set_local_contract_debug_execution();
    seed_host.set_durable_state_snapshot_from_world(&view.world);
    seed_host.set_query_state(&view);
    seed_vm.load_program(&program).expect("load dlmm_pool");
    seed_vm
        .set_program_counter(seed_bin_pc)
        .expect("set seed_bin pc");
    seed_vm.set_register(1, seed_vm.memory.code_len());
    seed_arguments
        .precharge_vm(&mut seed_vm)
        .expect("precharge seed_bin arguments");
    seed_vm.run_with_host(&mut seed_host).expect("seed_bin run");
    let queued = seed_host.drain_instructions();
    assert_eq!(queued.len(), 2, "expected two queued transfer instructions");
}
