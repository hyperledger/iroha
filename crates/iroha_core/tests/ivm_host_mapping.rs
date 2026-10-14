//! Host mapping parity tests: ensure SCALLs bridge to native ISIs with identical effects.

#![allow(
    clippy::cast_possible_truncation,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::map_unwrap_or
)]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::{CoreHost, CoreHostImpl},
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::NewAccount,
    isi::error::{InstructionExecutionError, MathError},
    nft::NftId,
    prelude::*,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use ivm::{IVM, PointerType, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use mv::storage::StorageReadOnly;
use norito::NoritoSerialize;
const AMPLE_TEST_GAS_LIMIT: u64 = 1_000_000;
fn with_core_host<R>(vm: &mut IVM, f: impl FnOnce(&mut CoreHost) -> R) -> R {
    CoreHost::with_host(vm, f)
}
fn tlv_blob<T: NoritoSerialize>(val: &T, type_id: u16) -> Vec<u8> {
    let payload = norito::to_bytes(val).expect("encode payload");
    tlv_from_payload(&payload, type_id)
}
fn norito_bytes_tlv<T: norito::core::NoritoSerialize>(val: &T) -> Vec<u8> {
    let payload = norito::to_bytes(val).expect("encode NoritoBytes payload");
    tlv_from_payload(&payload, PointerType::NoritoBytes as u16)
}
fn quantity_tlv(value: Quantity) -> Vec<u8> {
    ivm_abi::numeric_tlv::encode_quantity(&value).expect("encode quantity pointer envelope")
}
fn tlv_from_payload(payload: &[u8], type_id: u16) -> Vec<u8> {
    let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    blob.extend_from_slice(&type_id.to_be_bytes());
    blob.push(1u8); // version
    blob.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    blob.extend_from_slice(&hash);
    blob
}
fn seeded_account(seed: u8) -> AccountId {
    seeded_account_in(seed, "wonder")
}
fn seeded_account_in(seed: u8, domain_name: &str) -> AccountId {
    let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("seeded IVM host mapping account keypair should be valid");
    let _domain = DomainId::try_new(domain_name, "universal").unwrap();
    AccountId::new(keypair.public_key().clone())
}
fn new_account_in_domain(account_id: &AccountId) -> NewAccount {
    NewAccount::new(account_id.clone())
}
fn built_account_in_domain(account_id: &AccountId) -> Account {
    new_account_in_domain(account_id).build(account_id)
}
fn make_header() -> Vec<u8> {
    ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 4,
        max_cycles: 1_000_000,
        abi_version: 1,
    }
    .encode()
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
    let mut program = make_header();
    program.extend_from_slice(&code);
    program
}
fn load_input_blob(vm: &mut IVM, cursor: &mut u64, blob: &[u8]) -> u64 {
    vm.memory
        .input_write_aligned(cursor, blob, 8)
        .expect("write INPUT blob")
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
#[test]
fn host_bridges_nft_mint_and_transfer() {
    // Accounts and NFT id
    let owner = seeded_account(1);
    let recipient = seeded_account(2);
    let nft_id: NftId = "n0$wonder".parse().unwrap();
    let nft_blob = tlv_blob(&nft_id, PointerType::NftId as u16);
    let owner_blob = tlv_blob(&owner, PointerType::AccountId as u16);
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(owner.clone()));
    let mut cursor = 0;
    let ptr_nft = load_input_blob(&mut vm, &mut cursor, &nft_blob);
    let ptr_owner = load_input_blob(&mut vm, &mut cursor, &owner_blob);
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_NFT_MINT_ASSET,
        &[(10, ptr_nft), (11, ptr_owner)],
    );
    // Minimal world setup: domain + accounts
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
    {
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonder", "universal").unwrap();
        let new_domain = Domain::new(domain_id.clone());
        let reg_domain = RegisterBox::from(Register::domain(new_domain));
        let reg_owner = RegisterBox::from(Register::account(new_account_in_domain(&owner)));
        let reg_recipient = RegisterBox::from(Register::account(new_account_in_domain(&recipient)));
        let executor = tx.world.executor().clone();
        for instr in [
            InstructionBox::from(reg_domain),
            InstructionBox::from(reg_owner),
            InstructionBox::from(reg_recipient),
        ] {
            executor
                .execute_instruction(&mut tx, &owner, instr)
                .unwrap();
        }
        // Apply queued NFT_MINT_ASSET
        let queued =
            CoreHost::with_host(&mut vm, |host| host.apply_queued(&mut tx, &owner)).unwrap();
        assert_eq!(queued.len(), 1);
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    // NFT exists and is owned by owner
    {
        let view = state.view();
        let entry = view.world.nfts().get(&nft_id).expect("nft exists");
        assert_eq!(entry.owned_by, owner);
    }
    // Now transfer NFT to recipient via SCALL NFT_TRANSFER_ASSET
    let from_blob = tlv_blob(&owner, PointerType::AccountId as u16);
    let nft_blob2 = tlv_blob(&nft_id, PointerType::NftId as u16);
    let to_blob = tlv_blob(&recipient, PointerType::AccountId as u16);
    let mut vm2 = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm2.set_host(CoreHost::new(owner.clone()));
    let mut cursor2 = 0;
    let ptr_from = load_input_blob(&mut vm2, &mut cursor2, &from_blob);
    let ptr_nft2 = load_input_blob(&mut vm2, &mut cursor2, &nft_blob2);
    let ptr_to = load_input_blob(&mut vm2, &mut cursor2, &to_blob);
    run_syscall(
        &mut vm2,
        ivm_sys::SYSCALL_NFT_TRANSFER_ASSET,
        &[(10, ptr_from), (11, ptr_nft2), (12, ptr_to)],
    );
    // Apply queued NFT_TRANSFER_ASSET in a new block scope
    let header_transfer = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(2).unwrap(),
        None,
        None,
        0,
        0,
    );
    {
        let mut block = state.block(header_transfer);
        let mut tx = block.transaction();
        let queued2 =
            CoreHost::with_host(&mut vm2, |host| host.apply_queued(&mut tx, &owner)).unwrap();
        assert_eq!(queued2.len(), 1);
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    // Owner changed to recipient
    let view = state.view();
    let entry2 = view.world.nfts().get(&nft_id).expect("nft exists");
    assert_eq!(entry2.owned_by, recipient);
}
#[test]
fn host_rejects_insufficient_asset_transfer() {
    // Setup accounts and asset def
    let from = seeded_account(3);
    let to = seeded_account(4);
    let asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonder", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    // Build program: TRANSFER_ASSET_SCOPED(&from, &to, &asset_def, 1000, &dataspace) -> expect rejection when applying queued ISIs
    let from_tlv = tlv_blob(&from, PointerType::AccountId as u16);
    let to_tlv = tlv_blob(&to, PointerType::AccountId as u16);
    let asset_tlv = tlv_blob(&asset_def, PointerType::AssetDefinitionId as u16);
    let amount_tlv = quantity_tlv(Quantity::from(1000_u64));
    let dataspace_tlv = tlv_blob(
        &iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        PointerType::DataSpaceId as u16,
    );
    // Setup world: domain, accounts, asset def, mint only 100
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
    let domain_id: DomainId = DomainId::try_new("wonder", "universal").unwrap();
    let new_domain = Domain::new(domain_id.clone());
    let reg_domain = RegisterBox::from(Register::domain(new_domain));
    let reg_from = RegisterBox::from(Register::account(new_account_in_domain(&from)));
    let reg_to = RegisterBox::from(Register::account(new_account_in_domain(&to)));
    let new_asset_def = AssetDefinition::numeric(
        asset_def.clone(),
        "coin".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id),
    );
    let reg_asset_def = RegisterBox::from(Register::asset_definition(new_asset_def));
    let mint = MintBox::from(Mint::asset_quantity(
        100u64,
        AssetId::of(asset_def.clone(), from.clone()),
    ));
    let executor = tx.world.executor().clone();
    for instr in [
        InstructionBox::from(reg_domain),
        InstructionBox::from(reg_from),
        InstructionBox::from(reg_to),
        InstructionBox::from(reg_asset_def),
        InstructionBox::from(mint),
    ] {
        executor.execute_instruction(&mut tx, &from, instr).unwrap();
    }
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    let mut cursor = 0;
    let ptr_from = load_input_blob(&mut vm, &mut cursor, &from_tlv);
    let ptr_to = load_input_blob(&mut vm, &mut cursor, &to_tlv);
    let ptr_asset = load_input_blob(&mut vm, &mut cursor, &asset_tlv);
    let ptr_amount = load_input_blob(&mut vm, &mut cursor, &amount_tlv);
    let ptr_dataspace = load_input_blob(&mut vm, &mut cursor, &dataspace_tlv);
    vm.load_program(&scall_program(ivm_sys::SYSCALL_TRANSFER_ASSET_SCOPED))
        .expect("load program");
    for (register, value) in [
        (10, ptr_from),
        (11, ptr_to),
        (12, ptr_asset),
        (13, ptr_amount),
        (14, ptr_dataspace),
    ] {
        vm.set_register(register, value);
    }
    let mut host = CoreHostImpl::new(from.clone());
    let view = state.view();
    host.set_query_state(&view);
    vm.run_with_host(&mut host)
        .unwrap_or_else(|err| panic!("run syscall 0x2C: {err:?}"));
    // Apply queued transfer: should be rejected due to insufficient funds
    let header = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(2).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let err = host
        .apply_queued(&mut tx, &from)
        .expect_err("transfer must reject spending more than the source balance");
    assert!(
        matches!(
            err,
            ValidationFail::InstructionFailed(InstructionExecutionError::Math(
                MathError::NotEnoughQuantity
            ))
        ),
        "expected insufficient balance rejection, got {err:?}"
    );
    assert_eq!(
        tx.world
            .assets()
            .get(&AssetId::of(asset_def.clone(), from.clone()))
            .map(|value| value.as_ref().clone()),
        Some(Quantity::from(100_u64)),
        "rejected transfer must preserve the source balance"
    );
    assert!(
        tx.world.assets().get(&AssetId::of(asset_def, to)).is_none(),
        "rejected transfer must not create a destination balance"
    );
}
#[test]
fn host_batches_transfer_v1_calls() {
    let from = seeded_account(5);
    let to_a = seeded_account(6);
    let to_b = seeded_account(7);
    let domain_id: DomainId = DomainId::try_new("wonder", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonder", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let domain = Domain::new(domain_id.clone()).build(&from);
    let from_account = built_account_in_domain(&from);
    let first_recipient_account = built_account_in_domain(&to_a);
    let second_recipient_account = built_account_in_domain(&to_b);
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&from);
    let from_asset = Asset::new(
        AssetId::new(asset_def_id.clone(), from.clone()),
        Quantity::from(25_u32),
    );
    let world = World::with_assets(
        [domain],
        [
            from_account,
            first_recipient_account,
            second_recipient_account,
        ],
        [asset_def],
        [from_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let header = iroha_data_model::block::BlockHeader::new(
        core::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(Hash::prehashed([0x55; Hash::LENGTH]));
    let from_tlv = tlv_blob(&from, PointerType::AccountId as u16);
    let first_recipient_tlv = tlv_blob(&to_a, PointerType::AccountId as u16);
    let second_recipient_tlv = tlv_blob(&to_b, PointerType::AccountId as u16);
    let asset_tlv = tlv_blob(&asset_def_id, PointerType::AssetDefinitionId as u16);
    let amount_a_tlv = quantity_tlv(Quantity::from(7_u64));
    let amount_b_tlv = quantity_tlv(Quantity::from(4_u64));
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(from.clone()));
    let mut cursor = 0;
    let ptr_from = load_input_blob(&mut vm, &mut cursor, &from_tlv);
    let ptr_to_a = load_input_blob(&mut vm, &mut cursor, &first_recipient_tlv);
    let ptr_to_b = load_input_blob(&mut vm, &mut cursor, &second_recipient_tlv);
    let ptr_asset = load_input_blob(&mut vm, &mut cursor, &asset_tlv);
    let ptr_amount_a = load_input_blob(&mut vm, &mut cursor, &amount_a_tlv);
    let ptr_amount_b = load_input_blob(&mut vm, &mut cursor, &amount_b_tlv);
    run_syscall(&mut vm, ivm_sys::SYSCALL_TRANSFER_V1_BATCH_BEGIN, &[]);
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_TRANSFER_V1,
        &[
            (10, ptr_from),
            (11, ptr_to_a),
            (12, ptr_asset),
            (13, ptr_amount_a),
        ],
    );
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_TRANSFER_V1,
        &[
            (10, ptr_from),
            (11, ptr_to_b),
            (12, ptr_asset),
            (13, ptr_amount_b),
        ],
    );
    run_syscall(&mut vm, ivm_sys::SYSCALL_TRANSFER_V1_BATCH_END, &[]);
    let queued = with_core_host(&mut vm, |host| host.apply_queued(&mut tx, &from)).unwrap();
    assert_eq!(queued.len(), 1, "single batch instruction enqueued");
    let batch = queued[0]
        .as_any()
        .downcast_ref::<TransferAssetBatch>()
        .expect("queued instruction is a TransferAssetBatch");
    assert_eq!(batch.entries().len(), 2, "two entries batched");
    tx.apply();
    let from_asset_id = AssetId::new(asset_def_id.clone(), from.clone());
    let from_balance = block.world.asset(&from_asset_id).expect("authority asset");
    assert_eq!(**from_balance, Quantity::from(14_u32));
    let first_recipient_asset_id = AssetId::new(asset_def_id.clone(), to_a.clone());
    let first_recipient_balance = block
        .world
        .asset(&first_recipient_asset_id)
        .expect("recipient a asset");
    assert_eq!(**first_recipient_balance, Quantity::from(7_u32));
    let second_recipient_asset_id = AssetId::new(asset_def_id.clone(), to_b.clone());
    let second_recipient_balance = block
        .world
        .asset(&second_recipient_asset_id)
        .expect("recipient b asset");
    assert_eq!(**second_recipient_balance, Quantity::from(4_u32));
    let transcripts = block.drain_transfer_transcripts();
    assert_eq!(transcripts.len(), 1);
    let (_, batches) = transcripts.into_iter().next().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].deltas.len(), 2);
    assert!(batches[0].poseidon_preimage_digest.is_none());
}
#[test]
fn host_rejects_nft_transfer_from_non_owner() {
    // Setup accounts and NFT owned by bob; alice attempts transfer -> reject
    let alice = seeded_account(8);
    let bob = seeded_account(9);
    let charlie = seeded_account(10);
    let nft_id: NftId = "n0$wonder".parse().unwrap();
    // Build program: TRANSFER_NFT(from=alice, nft_id, to=charlie)
    let from_tlv = tlv_blob(&alice, PointerType::AccountId as u16);
    let nft_tlv = tlv_blob(&nft_id, PointerType::NftId as u16);
    let to_tlv = tlv_blob(&charlie, PointerType::AccountId as u16);
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(alice.clone()));
    let mut cursor = 0;
    let ptr_from = load_input_blob(&mut vm, &mut cursor, &from_tlv);
    let ptr_nft = load_input_blob(&mut vm, &mut cursor, &nft_tlv);
    let ptr_to = load_input_blob(&mut vm, &mut cursor, &to_tlv);
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_NFT_TRANSFER_ASSET,
        &[(10, ptr_from), (11, ptr_nft), (12, ptr_to)],
    );
    // Seed a valid ledger fixture directly. This test exercises transfer
    // authorization, not account/NFT registration authorization.
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("wonder", "universal").unwrap();
    let domain = Domain::new(domain_id).build(&alice);
    let alice_account = Account::new(alice.clone()).build(&alice);
    let bob_account = Account::new(bob.clone()).build(&bob);
    let charlie_account = Account::new(charlie.clone()).build(&charlie);
    let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&bob);
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account, charlie_account],
        [],
        [],
        [nft],
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
    // Apply queued transfer: should be rejected since alice is not the owner
    let err = with_core_host(&mut vm, |host| host.apply_queued(&mut tx, &alice))
        .expect_err("should reject");
    drop(err);
}
#[test]
fn host_bridges_set_account_detail() {
    // Build program: set_account_detail(authority(), name("cursor"), json("1")); HALT
    let key: Name = "cursor".parse().unwrap();
    let val: iroha_primitives::json::Json = "1".parse().unwrap();
    let authority = seeded_account(11);
    let key_tlv = tlv_blob(&key, PointerType::Name as u16);
    let val_tlv = tlv_blob(&val, PointerType::Json as u16);
    let authority_tlv = tlv_blob(&authority, PointerType::AccountId as u16);
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(authority.clone()));
    let mut cursor = 0;
    let ptr_account = load_input_blob(&mut vm, &mut cursor, &authority_tlv);
    let ptr_key = load_input_blob(&mut vm, &mut cursor, &key_tlv);
    let ptr_val = load_input_blob(&mut vm, &mut cursor, &val_tlv);
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_SET_ACCOUNT_DETAIL,
        &[(10, ptr_account), (11, ptr_key), (12, ptr_val)],
    );
    // Minimal world setup: register domain and account
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
    {
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonder", "universal").unwrap();
        let new_domain = Domain::new(domain_id.clone());
        let reg_domain = RegisterBox::from(Register::domain(new_domain));
        let reg_acc = RegisterBox::from(Register::account(new_account_in_domain(&authority)));
        let executor = tx.world.executor().clone();
        for instr in [
            InstructionBox::from(reg_domain),
            InstructionBox::from(reg_acc),
        ] {
            executor
                .execute_instruction(&mut tx, &authority, instr)
                .unwrap();
        }
        // Apply queued detail set via host
        let queued =
            with_core_host(&mut vm, |host| host.apply_queued(&mut tx, &authority)).unwrap();
        assert_eq!(queued.len(), 1);
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    } // drop block + tx before taking a read-only view
    // Check metadata present
    let view = state.view();
    let acc = view.world.accounts().get(&authority).unwrap();
    assert_eq!(
        acc.metadata()
            .get(&key)
            .map(<iroha_primitives::json::Json as AsRef<str>>::as_ref),
        Some("1")
    );
}
#[test]
fn host_bridges_mint_asset() {
    // Build program: mint_asset(authority(), asset_definition("coin#wonder"), 123); HALT
    let authority = seeded_account(12);
    let asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonder", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let authority_tlv = tlv_blob(&authority, PointerType::AccountId as u16);
    let asset_tlv = tlv_blob(&asset_def, PointerType::AssetDefinitionId as u16);
    let amount_tlv = quantity_tlv(Quantity::from(123_u64));
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(authority.clone()));
    let mut cursor = 0;
    let ptr_authority = load_input_blob(&mut vm, &mut cursor, &authority_tlv);
    let ptr_asset = load_input_blob(&mut vm, &mut cursor, &asset_tlv);
    let ptr_amount = load_input_blob(&mut vm, &mut cursor, &amount_tlv);
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_MINT_ASSET,
        &[(10, ptr_authority), (11, ptr_asset), (12, ptr_amount)],
    );
    // Minimal world setup: domain, account, asset def
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
    {
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonder", "universal").unwrap();
        let new_domain = Domain::new(domain_id.clone());
        let reg_domain = RegisterBox::from(Register::domain(new_domain));
        let reg_acc = RegisterBox::from(Register::account(new_account_in_domain(&authority)));
        let new_asset_def = AssetDefinition::numeric(
            asset_def.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id),
        );
        let reg_asset_def = RegisterBox::from(Register::asset_definition(new_asset_def));
        let executor = tx.world.executor().clone();
        for instr in [
            InstructionBox::from(reg_domain),
            InstructionBox::from(reg_acc),
            InstructionBox::from(reg_asset_def),
        ] {
            executor
                .execute_instruction(&mut tx, &authority, instr)
                .unwrap();
        }
        // Apply queued mint via host
        let queued =
            with_core_host(&mut vm, |host| host.apply_queued(&mut tx, &authority)).unwrap();
        assert_eq!(queued.len(), 1);
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let balance = state
        .view()
        .world
        .assets()
        .get(&AssetId::of(asset_def.clone(), authority.clone()))
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    assert_eq!(balance, Quantity::from(123_u32));
}
#[test]
fn host_bridges_nft_set_metadata_and_burn() {
    // Setup an owner and NFT id
    let owner = seeded_account(13);
    let nft_id: NftId = "n0$wonder".parse().unwrap();
    // Build program: NFT_MINT_ASSET, NFT_SET_METADATA(nft_id, "flag", true), NFT_BURN_ASSET(nft_id)
    let nft_tlv = tlv_blob(&nft_id, PointerType::NftId as u16);
    let key: Name = "flag".parse().unwrap();
    let key_tlv = tlv_blob(&key, PointerType::Name as u16);
    let val: iroha_primitives::json::Json = true.into();
    let val_tlv = tlv_blob(&val, PointerType::Json as u16);
    let owner_tlv = tlv_blob(&owner, PointerType::AccountId as u16);
    // VM
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(owner.clone()));
    let mut cursor = 0;
    let ptr_nft = load_input_blob(&mut vm, &mut cursor, &nft_tlv);
    let ptr_owner = load_input_blob(&mut vm, &mut cursor, &owner_tlv);
    let ptr_key = load_input_blob(&mut vm, &mut cursor, &key_tlv);
    let ptr_val = load_input_blob(&mut vm, &mut cursor, &val_tlv);
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_NFT_MINT_ASSET,
        &[(10, ptr_nft), (11, ptr_owner)],
    );
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_NFT_SET_METADATA,
        &[(10, ptr_nft), (11, ptr_key), (12, ptr_val)],
    );
    run_syscall(&mut vm, ivm_sys::SYSCALL_NFT_BURN_ASSET, &[(10, ptr_nft)]);
    // Minimal world: domain + owner
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
    {
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonder", "universal").unwrap();
        let reg_domain = RegisterBox::from(Register::domain(Domain::new(domain_id.clone())));
        let reg_owner = RegisterBox::from(Register::account(new_account_in_domain(&owner)));
        let executor = tx.world.executor().clone();
        for instr in [
            InstructionBox::from(reg_domain),
            InstructionBox::from(reg_owner),
        ] {
            executor
                .execute_instruction(&mut tx, &owner, instr)
                .unwrap();
        }
        // Apply queued NFT_MINT_ASSET, NFT_SET_METADATA, NFT_BURN_ASSET
        let queued = with_core_host(&mut vm, |host| host.apply_queued(&mut tx, &owner)).unwrap();
        assert_eq!(queued.len(), 3);
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    // NFT should not exist after burn; before burn, metadata should have been set correctly
    let view = state.view();
    assert!(view.world.nfts().get(&nft_id).is_none());
}
#[test]
fn transfer_batch_apply_syscall_enqueues_batch() {
    let from = seeded_account(14);
    let to_a = seeded_account(15);
    let to_b = seeded_account(16);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonder", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let batch = TransferAssetBatch::new(vec![
        TransferAssetBatchEntry::new(from.clone(), to_a.clone(), asset_def_id.clone(), 7_u32),
        TransferAssetBatchEntry::new(from.clone(), to_b.clone(), asset_def_id.clone(), 4_u32),
    ]);
    let encoded_batch = norito::to_bytes(&batch).expect("encode batch");
    let decoded: TransferAssetBatch =
        norito::decode_from_bytes(&encoded_batch).expect("batch roundtrip");
    assert_eq!(decoded.entries().len(), 2, "encode/decode sanity check");
    let batch_tlv = norito_bytes_tlv(&batch);
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(from.clone()));
    let mut cursor = 0;
    let ptr_batch = load_input_blob(&mut vm, &mut cursor, &batch_tlv);
    run_syscall(
        &mut vm,
        ivm_sys::SYSCALL_TRANSFER_V1_BATCH_APPLY,
        &[(10, ptr_batch)],
    );
    let queued = with_core_host(&mut vm, |host| host.drain_instructions());
    assert_eq!(queued.len(), 1, "transfer batch apply enqueues instruction");
    let batch_instr = queued[0]
        .as_any()
        .downcast_ref::<TransferAssetBatch>()
        .expect("queued instruction is a TransferAssetBatch");
    assert_eq!(batch_instr.entries().len(), 2, "two entries preserved");
    assert_eq!(batch_instr.entries()[0].to(), &to_a);
    assert_eq!(batch_instr.entries()[1].to(), &to_b);
}
