//! Verify IVM pointer ABI applies queued instructions correctly.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::too_many_lines)]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::{CoreHost, CoreHostImpl},
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{account::NewAccount, prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use ivm::{IVM, PointerType, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use kotodama_lang::compiler::Compiler;
use mv::storage::StorageReadOnly;
use norito::NoritoSerialize;
fn tlv_envelope<T: NoritoSerialize>(type_id: PointerType, val: &T) -> Vec<u8> {
    let payload = norito::to_bytes(val).expect("encode payload");
    let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + iroha_crypto::Hash::LENGTH);
    blob.extend_from_slice(&(type_id as u16).to_be_bytes());
    blob.push(1u8); // version
    blob.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
    blob.extend_from_slice(&payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(&payload).into();
    blob.extend_from_slice(&hash);
    blob
}
fn quantity_tlv(value: &Quantity) -> Vec<u8> {
    ivm_abi::numeric_tlv::encode_quantity(value).expect("encode quantity pointer envelope")
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
fn opaque_asset_definition_literal(aid_bytes: [u8; 16]) -> String {
    AssetDefinitionId::from_uuid_bytes(aid_bytes)
        .expect("opaque asset definition id")
        .to_string()
}
#[test]
fn apply_queued_isis_from_corehost_transfer_asset() {
    // Build a minimal IVM program that performs SCALL TRANSFER_ASSET_SCOPED and HALT
    let from = ALICE_ID.clone();
    let to = BOB_ID.clone();
    let asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let from_bytes = tlv_envelope(PointerType::AccountId, &from);
    let to_bytes = tlv_envelope(PointerType::AccountId, &to);
    let asset_bytes = tlv_envelope(PointerType::AssetDefinitionId, &asset_def);
    let amount = Quantity::from(500_u64);
    let amount_bytes = quantity_tlv(&amount);
    let dataspace = iroha_model_base::topology::DataSpaceId::UNIVERSAL;
    let dataspace_bytes = tlv_envelope(PointerType::DataSpaceId, &dataspace);
    let align8 = |n: u64| (n + 7) & !7;
    let off_from = 0u64;
    let off_to = align8(off_from + from_bytes.len() as u64);
    let off_asset = align8(off_to + to_bytes.len() as u64);
    let off_amount = align8(off_asset + asset_bytes.len() as u64);
    let off_dataspace = align8(off_amount + amount_bytes.len() as u64);
    let ptr_from = ivm::Memory::INPUT_START + off_from;
    let ptr_to = ivm::Memory::INPUT_START + off_to;
    let ptr_asset = ivm::Memory::INPUT_START + off_asset;
    let ptr_amount = ivm::Memory::INPUT_START + off_amount;
    let ptr_dataspace = ivm::Memory::INPUT_START + off_dataspace;
    let mut code = Vec::new();
    // SCALL transfer + HALT
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_TRANSFER_ASSET_SCOPED).unwrap(),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    // Full program (metadata + code)
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 10_000,
        abi_version: 1,
    };
    let mut program = meta.encode();
    program.extend_from_slice(&code);
    // Build VM with CoreHost and preload INPUT
    let mut vm = IVM::new(500_000);
    vm.memory
        .preload_input(off_from, &from_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_to, &to_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_asset, &asset_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_amount, &amount_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_dataspace, &dataspace_bytes)
        .expect("preload input");
    vm.load_program(&program).unwrap();
    vm.set_register(10, ptr_from);
    vm.set_register(11, ptr_to);
    vm.set_register(12, ptr_asset);
    vm.set_register(13, ptr_amount);
    vm.set_register(14, ptr_dataspace);
    // Build a minimal State and apply setup ISIs (register domain/accounts/asset, mint initial balance)
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    // Setup: register domain 'wonderland', register accounts, asset definition, and mint 1_000 to 'from'
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let new_domain = Domain::new(domain_id.clone());
    let reg_domain = RegisterBox::from(Register::domain(new_domain));
    let reg_from = RegisterBox::from(Register::account(NewAccount::new(from.clone())));
    let reg_to = RegisterBox::from(Register::account(NewAccount::new(to.clone())));
    let new_asset_def = AssetDefinition::numeric(
        asset_def.clone(),
        "coin".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
        Some(domain_id),
    );
    let reg_asset_def = RegisterBox::from(Register::asset_definition(new_asset_def));
    let mint = MintBox::from(Mint::asset_quantity(
        1000u64,
        AssetId::with_scope(
            asset_def.clone(),
            from.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace),
        ),
    ));
    let executor = tx.world.executor().clone();
    for instr in [
        InstructionBox::from(reg_domain),
        InstructionBox::from(reg_from),
        InstructionBox::from(reg_to),
        InstructionBox::from(reg_asset_def),
        InstructionBox::from(mint),
    ] {
        executor
            .execute_instruction(&mut tx, &from, instr)
            .expect("setup should succeed");
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit setup block");
    {
        let view = state.view();
        let mut host = CoreHostImpl::new(from.clone());
        host.set_query_state(&view);
        vm.run_with_host(&mut host).unwrap();
        let header = iroha_data_model::block::BlockHeader::new(
            core::num::NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut tx = block.transaction();
        // Apply queued transfer via CoreHost bridge.
        let queued = host
            .apply_queued(&mut tx, &from)
            .expect("apply queued instructions");
        assert_eq!(queued.len(), 1);
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit transfer block");
    }
    // Assert balances updated: from decreased by 500, to increased by 500
    let from_asset = AssetId::with_scope(
        asset_def.clone(),
        from.clone(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace),
    );
    let to_asset = AssetId::with_scope(
        asset_def.clone(),
        to.clone(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace),
    );
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
    assert_eq!(to_bal, Quantity::from(500u32));
}
#[test]
#[ignore = "debug helper for live encoded account ids and opaque asset definitions"]
fn apply_queued_isis_from_corehost_transfer_asset_with_env_encoded_ids() {
    let from_raw =
        std::env::var("IVM_DEBUG_FROM_ACCOUNT").expect("IVM_DEBUG_FROM_ACCOUNT must be set");
    let to_raw = std::env::var("IVM_DEBUG_TO_ACCOUNT").expect("IVM_DEBUG_TO_ACCOUNT must be set");
    let asset_raw = std::env::var("IVM_DEBUG_ASSET_DEFINITION")
        .expect("IVM_DEBUG_ASSET_DEFINITION must be set");
    let domain_raw = std::env::var("IVM_DEBUG_DOMAIN").unwrap_or_else(|_| "centralbank".to_owned());
    let from = iroha_data_model::account::AccountId::parse_encoded(&from_raw)
        .expect("valid encoded source account");
    let to = iroha_data_model::account::AccountId::parse_encoded(&to_raw)
        .expect("valid encoded destination account");
    let asset_def: AssetDefinitionId = asset_raw.parse().expect("valid asset definition");
    let amount = Quantity::from(500_u64);
    let from_bytes = tlv_envelope(PointerType::AccountId, &from);
    let to_bytes = tlv_envelope(PointerType::AccountId, &to);
    let asset_bytes = tlv_envelope(PointerType::AssetDefinitionId, &asset_def);
    let amount_bytes = quantity_tlv(&amount);
    let dataspace = iroha_model_base::topology::DataSpaceId::UNIVERSAL;
    let dataspace_bytes = tlv_envelope(PointerType::DataSpaceId, &dataspace);
    let align8 = |n: u64| (n + 7) & !7;
    let off_from = 0u64;
    let off_to = align8(off_from + from_bytes.len() as u64);
    let off_asset = align8(off_to + to_bytes.len() as u64);
    let off_amount = align8(off_asset + asset_bytes.len() as u64);
    let off_dataspace = align8(off_amount + amount_bytes.len() as u64);
    let ptr_from = ivm::Memory::INPUT_START + off_from;
    let ptr_to = ivm::Memory::INPUT_START + off_to;
    let ptr_asset = ivm::Memory::INPUT_START + off_asset;
    let ptr_amount = ivm::Memory::INPUT_START + off_amount;
    let ptr_dataspace = ivm::Memory::INPUT_START + off_dataspace;
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_TRANSFER_ASSET_SCOPED).unwrap(),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 10_000,
        abi_version: 1,
    };
    let mut program = meta.encode();
    program.extend_from_slice(&code);
    let mut vm = IVM::new(500_000);
    vm.set_host(CoreHost::new(from.clone()));
    vm.memory
        .preload_input(off_from, &from_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_to, &to_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_asset, &asset_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_amount, &amount_bytes)
        .expect("preload input");
    vm.memory
        .preload_input(off_dataspace, &dataspace_bytes)
        .expect("preload input");
    vm.load_program(&program).unwrap();
    vm.set_register(10, ptr_from);
    vm.set_register(11, ptr_to);
    vm.set_register(12, ptr_asset);
    vm.set_register(13, ptr_amount);
    vm.set_register(14, ptr_dataspace);
    vm.run().unwrap();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let domain_id = DomainId::try_new(domain_raw, "universal").expect("domain id");
    let new_domain = Domain::new(domain_id.clone());
    let reg_domain = RegisterBox::from(Register::domain(new_domain));
    let reg_from = RegisterBox::from(Register::account(NewAccount::new(from.clone())));
    let reg_to = RegisterBox::from(Register::account(NewAccount::new(to.clone())));
    let reg_asset_def = RegisterBox::from(Register::asset_definition(AssetDefinition::numeric(
        asset_def.clone(),
        asset_def.to_string(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )));
    let mint = MintBox::from(Mint::asset_quantity(
        1000u64,
        AssetId::with_scope(
            asset_def.clone(),
            from.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace),
        ),
    ));
    let executor = tx.world.executor().clone();
    for instr in [
        InstructionBox::from(reg_domain),
        InstructionBox::from(reg_from),
        InstructionBox::from(reg_to),
        InstructionBox::from(reg_asset_def),
        InstructionBox::from(mint),
    ] {
        executor
            .execute_instruction(&mut tx, &from, instr)
            .expect("setup should succeed");
    }
    let queued = CoreHost::with_host(&mut vm, |host| host.apply_queued(&mut tx, &from))
        .expect("apply queued instructions");
    assert_eq!(queued.len(), 1);
}
#[test]
#[ignore = "debug helper for live trigger-style JSON-driven transfers"]
fn apply_queued_isis_from_compiled_json_driven_double_transfer() {
    let reserve_raw =
        std::env::var("IVM_DEBUG_FROM_ACCOUNT").expect("IVM_DEBUG_FROM_ACCOUNT must be set");
    let dst_raw = std::env::var("IVM_DEBUG_TO_ACCOUNT").expect("IVM_DEBUG_TO_ACCOUNT must be set");
    let aed_asset_raw = std::env::var("IVM_DEBUG_AED_ASSET_DEFINITION").unwrap_or_else(|_| {
        opaque_asset_definition_literal([
            0x68, 0x72, 0x45, 0x4e, 0x9c, 0x04, 0x46, 0x41, 0xaa, 0x58, 0x1e, 0xc5, 0xf3, 0x80,
            0x16, 0x19,
        ])
    });
    let cbdc_asset_raw = std::env::var("IVM_DEBUG_CBDC_ASSET_DEFINITION").unwrap_or_else(|_| {
        opaque_asset_definition_literal([
            0x2e, 0x3d, 0x34, 0xbe, 0xb8, 0xa8, 0x42, 0x39, 0xb3, 0xd9, 0x59, 0x07, 0x70, 0xf1,
            0x18, 0x9e,
        ])
    });
    let domain_raw =
        std::env::var("IVM_DEBUG_DOMAIN").unwrap_or_else(|_| "centralbank.universal".to_owned());
    let ratio_raw = std::env::var("IVM_DEBUG_RATIO").unwrap_or_else(|_| "76".to_owned());
    let reserve = iroha_data_model::account::AccountId::parse_encoded(&reserve_raw)
        .expect("valid encoded reserve account");
    let dst = iroha_data_model::account::AccountId::parse_encoded(&dst_raw)
        .expect("valid encoded destination account");
    let aed_asset_def: AssetDefinitionId = aed_asset_raw.parse().expect("valid AED asset");
    let cbdc_asset_def: AssetDefinitionId = cbdc_asset_raw.parse().expect("valid CBDC asset");
    let domain_id = DomainId::parse_fully_qualified(&domain_raw).expect("valid domain");
    let ratio: u64 = ratio_raw.parse().expect("valid ratio");
    let authority = ALICE_ID.clone();
    let compiler = Compiler::new();
    let src = format!(
        r#"
        seiyaku DebugTransfer {{ permission TransferAsset;
          kotoage fn main() authorize(TransferAsset) {{
            let ev = Json::parse("{{\"account_domain\":\"{domain}\",\"account_id\":\"{dst}\",\"amount\":\"1\",\"asset_definition_id\":\"{aed}\",\"kind\":\"asset_change\",\"op\":\"added\"}}");
            let recipient = ev.get_account_id(Name::parse("account_id")).unwrap_or(AccountId::parse("{dst}"));
            let quantity amount = ev.get_quantity(Name::parse("amount")).unwrap_or(0);
            ledger::asset::transfer(source: recipient, destination: AccountId::parse("{reserve}"), asset_definition: AssetDefinitionId::parse("{aed}"), amount: amount, dataspace: DataSpaceId::parse("0"));
            ledger::asset::transfer(source: AccountId::parse("{reserve}"), destination: recipient, asset_definition: AssetDefinitionId::parse("{cbdc}"), amount: amount * {ratio}, dataspace: DataSpaceId::parse("0"));
          }}
        }}
        "#,
        aed = aed_asset_raw,
        domain = domain_raw,
        dst = dst_raw,
        reserve = reserve_raw,
        cbdc = cbdc_asset_raw,
        ratio = ratio,
    );
    let program = compiler.compile_source(&src).expect("compile");
    let mut vm = IVM::new(500_000);
    vm.set_host(CoreHost::new(authority.clone()));
    vm.load_program(&program).expect("load");
    select_kotodama_entrypoint(&mut vm, &program, "main");
    vm.run().expect("run");
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let reg_domain = RegisterBox::from(Register::domain(Domain::new(domain_id.clone())));
    let reg_authority = RegisterBox::from(Register::account(NewAccount::new(authority.clone())));
    let reg_reserve = RegisterBox::from(Register::account(NewAccount::new(reserve.clone())));
    let reg_dst = RegisterBox::from(Register::account(NewAccount::new(dst.clone())));
    let reg_aed = RegisterBox::from(Register::asset_definition(AssetDefinition::numeric(
        aed_asset_def.clone(),
        "aed".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )));
    let reg_cbdc = RegisterBox::from(Register::asset_definition(AssetDefinition::numeric(
        cbdc_asset_def.clone(),
        "cbdc".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )));
    let mint_aed = MintBox::from(Mint::asset_quantity(
        1u64,
        AssetId::of(aed_asset_def.clone(), dst.clone()),
    ));
    let mint_cbdc = MintBox::from(Mint::asset_quantity(
        ratio * 2,
        AssetId::of(cbdc_asset_def.clone(), reserve.clone()),
    ));
    let executor = tx.world.executor().clone();
    for instr in [
        InstructionBox::from(reg_domain),
        InstructionBox::from(reg_authority),
        InstructionBox::from(reg_reserve),
        InstructionBox::from(reg_dst),
        InstructionBox::from(reg_aed),
        InstructionBox::from(reg_cbdc),
        InstructionBox::from(mint_aed),
        InstructionBox::from(mint_cbdc),
    ] {
        executor
            .execute_instruction(&mut tx, &authority, instr)
            .expect("setup should succeed");
    }
    let queued = CoreHost::with_host(&mut vm, |host| host.apply_queued(&mut tx, &authority))
        .expect("apply queued instructions");
    assert_eq!(queued.len(), 2);
    let dst_aed_bal = tx
        .world
        .assets()
        .get(&AssetId::of(aed_asset_def, dst.clone()))
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    let dst_cbdc_bal = tx
        .world
        .assets()
        .get(&AssetId::of(cbdc_asset_def, dst))
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    assert_eq!(dst_aed_bal, Quantity::zero());
    assert_eq!(dst_cbdc_bal, Quantity::from(ratio));
}
