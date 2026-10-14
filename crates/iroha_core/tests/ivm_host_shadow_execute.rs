//! CoreHost shadow-execute parity tests (IVM syscalls vs native Execute).

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::CoreHost,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, PointerType, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use norito::NoritoSerialize;
const AMPLE_TEST_GAS_LIMIT: u64 = 1_000_000;
fn tlv_blob<T: NoritoSerialize>(val: &T, ty: PointerType) -> Vec<u8> {
    let payload = norito::to_bytes(val).expect("encode payload");
    let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    blob.extend_from_slice(&(ty as u16).to_be_bytes());
    blob.push(1);
    blob.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(&payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(&payload).into();
    blob.extend_from_slice(&hash);
    blob
}
fn quantity_tlv(value: &Quantity) -> Vec<u8> {
    ivm_abi::numeric_tlv::encode_quantity(value).expect("encode quantity pointer envelope")
}
fn load_input_blob(vm: &mut IVM, cursor: &mut u64, blob: &[u8]) -> u64 {
    vm.memory
        .input_write_aligned(cursor, blob, 8)
        .expect("write INPUT blob")
}
fn scall_program(syscall: u32) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("syscall id fits in u8"),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut program = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1_000_000,
        abi_version: 1,
    }
    .encode();
    program.extend_from_slice(&code);
    program
}
fn run_syscall(vm: &mut IVM, syscall: u32, regs: &[(u8, u64)]) {
    let program = scall_program(syscall);
    vm.load_program(&program).expect("load program");
    for &(reg, value) in regs {
        vm.set_register(usize::from(reg), value);
    }
    vm.run()
        .unwrap_or_else(|err| panic!("run syscall 0x{syscall:02X}: {err:?}"));
}
fn setup_state(
    authority: &AccountId,
    asset_def: &AssetDefinitionId,
    asset_domain: &DomainId,
    asset_name: &Name,
) -> State {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let domain = Domain::new(asset_domain.clone()).build(authority);
    let account = Account::new(authority.clone()).build(authority);
    let asset_definition = AssetDefinition::numeric(
        asset_def.clone(),
        asset_name.to_string(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(asset_domain.clone()),
    )
    .build(authority);
    let state = State::new_for_testing(
        World::with([domain], [account], [asset_definition]),
        kura,
        query_handle,
    );
    // Finalize the genesis fixture so its asset has an incarnation before
    // executing the height-two native and IVM transactions.
    state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0))
        .commit_empty_block_for_testing()
        .expect("commit genesis fixture");
    state
}
fn data_event_debug(events: Vec<iroha_data_model::events::EventBox>) -> Vec<String> {
    events
        .into_iter()
        .filter_map(|ev| match ev {
            iroha_data_model::events::EventBox::Data(d) => Some(d),
            _ => None,
        })
        .map(|ev| format!("{:?}", ev.as_ref()))
        .collect()
}
#[test]
fn ivm_host_shadow_execute_matches_native_execute() {
    let authority = ALICE_ID.clone();
    let asset_domain = DomainId::try_new("wonderland", "universal").unwrap();
    let asset_name: Name = "coin".parse().unwrap();
    let asset_def_seed: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            asset_domain.clone(),
            asset_name.clone(),
        );
    let asset_def = AssetDefinitionId::parse_address_literal(&asset_def_seed.canonical_address())
        .expect("canonical asset definition literal");
    let key: Name = "parity_key".parse().unwrap();
    let value = iroha_primitives::json::Json::new("shadow");
    let amount = Quantity::from(100_u64);
    let direct_state = setup_state(&authority, &asset_def, &asset_domain, &asset_name);
    let host_state = setup_state(&authority, &asset_def, &asset_domain, &asset_name);
    // Direct Execute path.
    let direct_events = {
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = direct_state.block(header);
        let mut tx = block.transaction();
        let executor = tx.world.executor().clone();
        let set_detail: InstructionBox =
            SetKeyValue::account(authority.clone(), key.clone(), value.clone()).into();
        let mint: InstructionBox = Mint::asset_quantity(
            amount.clone(),
            AssetId::of(asset_def.clone(), authority.clone()),
        )
        .into();
        for instr in [set_detail, mint] {
            executor
                .execute_instruction(&mut tx, &authority, instr)
                .expect("direct execute");
        }
        let events = tx.world.take_external_events();
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit direct block");
        events
    };
    // CoreHost path via syscalls.
    let host_events = {
        let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
        vm.set_host(CoreHost::new(authority.clone()));
        let account_tlv = tlv_blob(&authority, PointerType::AccountId);
        let key_tlv = tlv_blob(&key, PointerType::Name);
        let value_tlv = tlv_blob(&value, PointerType::Json);
        let asset_tlv = tlv_blob(&asset_def, PointerType::AssetDefinitionId);
        let amount_tlv = quantity_tlv(&amount);
        let mut cursor = 0;
        let ptr_account = load_input_blob(&mut vm, &mut cursor, &account_tlv);
        let ptr_key = load_input_blob(&mut vm, &mut cursor, &key_tlv);
        let ptr_value = load_input_blob(&mut vm, &mut cursor, &value_tlv);
        let ptr_asset = load_input_blob(&mut vm, &mut cursor, &asset_tlv);
        let ptr_amount = load_input_blob(&mut vm, &mut cursor, &amount_tlv);
        run_syscall(
            &mut vm,
            ivm_sys::SYSCALL_SET_ACCOUNT_DETAIL,
            &[(10, ptr_account), (11, ptr_key), (12, ptr_value)],
        );
        run_syscall(
            &mut vm,
            ivm_sys::SYSCALL_MINT_ASSET,
            &[(10, ptr_account), (11, ptr_asset), (12, ptr_amount)],
        );
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = host_state.block(header);
        let mut tx = block.transaction();
        CoreHost::with_host(&mut vm, |host| {
            host.apply_queued(&mut tx, &authority)
                .expect("apply queued syscalls");
        });
        let events = tx.world.take_external_events();
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit host block");
        events
    };
    let direct_data = data_event_debug(direct_events);
    let host_data = data_event_debug(host_events);
    assert_eq!(direct_data, host_data, "data events must match");
    let asset_id = AssetId::of(asset_def.clone(), authority.clone());
    let direct_view = direct_state.view();
    let host_view = host_state.view();
    let direct_acc = direct_view.world.accounts().get(&authority).unwrap();
    let host_acc = host_view.world.accounts().get(&authority).unwrap();
    assert_eq!(
        direct_acc.metadata().get(&key).map(|v| v.as_ref()),
        host_acc.metadata().get(&key).map(|v| v.as_ref())
    );
    let direct_balance = direct_view
        .world
        .assets()
        .get(&asset_id)
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    let host_balance = host_view
        .world
        .assets()
        .get(&asset_id)
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    assert_eq!(direct_balance, host_balance);
    assert_eq!(direct_balance, amount);
}
