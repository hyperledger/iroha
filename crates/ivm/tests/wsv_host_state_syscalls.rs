//! WsvHost durable state syscalls: STATE_GET/SET/DEL with pointer-ABI.
use crate::common;
use iroha_crypto::PublicKey;
use ivm::{
    IVM, Memory, PointerType, VMError,
    host::IVMHost,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    syscalls,
};
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
fn make_tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
    let payload = common::payload_for_type(pty, payload);
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&(pty as u16).to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
fn state_path_tlv(path: &str) -> Vec<u8> {
    let path: iroha_model_base::state_path::StatePath = path.parse().expect("canonical state path");
    let payload = norito::to_bytes(&path).expect("encode state path");
    make_tlv(PointerType::NoritoBytes, &payload)
}
fn account(_domain: &str, public_key: &str) -> AccountId {
    let public_key: PublicKey = public_key.parse().expect("public key");
    AccountId::new(public_key)
}
fn saturate_input(vm: &mut IVM) {
    let filler = make_tlv(PointerType::Blob, b"");
    while vm.alloc_input_tlv(&filler).is_ok() {}
}
fn bytes_state_program(name: &str) -> Vec<u8> {
    common::assemble_bytes_state_schema_contract(&[name])
}

#[test]
fn wsv_host_state_set_get_del_roundtrip() {
    let wsv = MockWorldStateView::new();
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut vm = IVM::new(u64::MAX);
    let mut host = WsvHost::new_with_subject(wsv, caller.clone());
    let path_tlv = state_path_tlv("bar");
    let expected = vec![9u8, 8, 7];
    let val1 = common::encode_bytes_state_value(&expected);
    let val1_tlv = make_tlv(PointerType::NoritoBytes, &val1);
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    let p_val1 = vm.alloc_input_tlv(&val1_tlv).expect("alloc val");
    // SET
    let set_prog = bytes_state_program("bar");
    vm.set_register(10, p_path);
    vm.set_register(11, p_val1);
    vm.load_program(&set_prog).expect("load set");
    host.syscall(syscalls::SYSCALL_STATE_SET, &mut vm)
        .expect("state set");
    // GET
    let get_prog = bytes_state_program("bar");
    vm.set_register(10, p_path);
    vm.load_program(&get_prog).expect("load get");
    host.syscall(syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("state get");
    let p_out = vm.register(10);
    assert!(p_out >= Memory::INPUT_START);
    let tlv = vm.memory.validate_tlv(p_out).expect("validate out");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    assert_eq!(tlv.payload, &val1[..]);
    assert_eq!(common::decode_bytes_state_value(tlv.payload), expected);
    // DEL
    let del_prog = bytes_state_program("bar");
    vm.set_register(10, p_path);
    vm.load_program(&del_prog).expect("load del");
    host.syscall(syscalls::SYSCALL_STATE_DEL, &mut vm)
        .expect("state del");
    // GET -> 0
    vm.set_register(10, p_path);
    vm.load_program(&get_prog).expect("load get again");
    host.syscall(syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("state get again");
    assert_eq!(vm.register(10), 0);
}
#[test]
fn durable_state_overlay_persists_and_restores() {
    let base = std::env::temp_dir().join(format!(
        "ivm_state_overlay_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis()
    ));
    fs::create_dir_all(&base).expect("create temp dir");
    let store_path = base.join("state.json");
    let mut wsv = MockWorldStateView::with_state_store(store_path.clone()).expect("persisted wsv");
    let payload = b"abc".to_vec();
    wsv.sc_set("counter", payload.clone()).expect("set state");
    assert_eq!(wsv.sc_get("counter"), Some(payload.clone()));
    drop(wsv);
    let wsv_reloaded =
        MockWorldStateView::with_state_store(store_path.clone()).expect("reload persisted");
    assert_eq!(wsv_reloaded.sc_get("counter"), Some(payload.clone()));
    let mut wsv_mut = wsv_reloaded;
    let snap = wsv_mut.sc_snapshot();
    let payload_new = b"new".to_vec();
    wsv_mut
        .sc_set("counter", payload_new.clone())
        .expect("set newer value");
    assert_eq!(wsv_mut.sc_get("counter"), Some(payload_new));
    wsv_mut.sc_restore(&snap).expect("restore snapshot");
    assert_eq!(wsv_mut.sc_get("counter"), Some(payload.clone()));
    drop(wsv_mut);
    let persisted =
        MockWorldStateView::with_state_store(store_path.clone()).expect("reload after restore");
    assert_eq!(persisted.sc_get("counter"), Some(payload));
    let _ = fs::remove_dir_all(base);
}
#[test]
fn wsv_host_state_get_returns_canonical_record_in_input_when_space_is_available() {
    let mut wsv = MockWorldStateView::new();
    let expected = b"inline".to_vec();
    let stored = common::encode_bytes_state_value(&expected);
    wsv.sc_set("inline_value", stored.clone())
        .expect("seed canonical state");
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut vm = IVM::new(u64::MAX);
    let mut host = WsvHost::new_with_subject(wsv, caller);
    let path_tlv = state_path_tlv("inline_value");
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    let get_prog = bytes_state_program("inline_value");
    vm.set_register(10, p_path);
    vm.load_program(&get_prog).expect("load get");
    host.syscall(syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("state get");
    let p_out = vm.register(10);
    assert!(
        (Memory::INPUT_START..Memory::INPUT_START + Memory::INPUT_SIZE).contains(&p_out),
        "state value should stay in input while there is still input space"
    );
    let tlv = vm
        .memory
        .validate_tlv(p_out)
        .expect("validate canonical output");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    assert_eq!(tlv.payload, &stored[..]);
    assert_eq!(common::decode_bytes_state_value(tlv.payload), expected);
}
#[test]
fn wsv_host_state_get_spills_to_heap_when_input_bump_is_full() {
    let wsv = MockWorldStateView::new();
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut vm = IVM::new(u64::MAX);
    let mut host = WsvHost::new_with_subject(wsv, caller);
    let path_tlv = state_path_tlv("spill");
    let expected = vec![0xCD; 64];
    let stored = common::encode_bytes_state_value(&expected);
    let val_tlv = make_tlv(PointerType::NoritoBytes, &stored);
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    let p_val = vm.alloc_input_tlv(&val_tlv).expect("alloc value");
    let set_prog = bytes_state_program("spill");
    vm.set_register(10, p_path);
    vm.set_register(11, p_val);
    vm.load_program(&set_prog).expect("load set");
    host.syscall(syscalls::SYSCALL_STATE_SET, &mut vm)
        .expect("state set");
    saturate_input(&mut vm);
    let get_prog = bytes_state_program("spill");
    vm.set_register(10, p_path);
    vm.load_program(&get_prog).expect("load get");
    host.syscall(syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("state get");
    let p_out = vm.register(10);
    assert!(
        (Memory::HEAP_START..Memory::INPUT_START).contains(&p_out),
        "state_get should spill WSV host return into heap when input is exhausted"
    );
    let tlv = vm.validate_tlv(p_out).expect("validate spilled output");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    assert_eq!(tlv.payload, &stored[..]);
    assert_eq!(common::decode_bytes_state_value(tlv.payload), expected);
}
#[test]
fn wsv_host_state_get_spills_canonical_record_when_input_bump_is_full() {
    let mut wsv = MockWorldStateView::new();
    let expected = b"spilled-state".to_vec();
    let stored = common::encode_bytes_state_value(&expected);
    wsv.sc_set("spilled_value", stored.clone())
        .expect("seed canonical state");
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut vm = IVM::new(u64::MAX);
    let mut host = WsvHost::new_with_subject(wsv, caller);
    let path_tlv = state_path_tlv("spilled_value");
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    saturate_input(&mut vm);
    let get_prog = bytes_state_program("spilled_value");
    vm.set_register(10, p_path);
    vm.load_program(&get_prog).expect("load get");
    host.syscall(syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("state get");
    let p_out = vm.register(10);
    assert!(
        (Memory::HEAP_START..Memory::INPUT_START).contains(&p_out),
        "state value should spill into heap when input is exhausted"
    );
    let tlv = vm.validate_tlv(p_out).expect("validate spilled output");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    assert_eq!(tlv.payload, &stored[..]);
    assert_eq!(common::decode_bytes_state_value(tlv.payload), expected);
}
#[test]
fn wsv_host_overlay_state_get_spills_to_heap_when_input_bump_is_full() {
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    let mut vm = IVM::new(u64::MAX);
    let path_tlv = state_path_tlv("overlay");
    let expected = vec![0x5A; 48];
    let val_tlv = make_tlv(PointerType::NoritoBytes, &expected);
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    let p_val = vm.alloc_input_tlv(&val_tlv).expect("alloc value");
    IVMHost::begin_tx(&mut host, &Default::default()).expect("begin overlay tx");
    vm.set_register(10, p_path);
    vm.set_register(11, p_val);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_SET, &mut vm).expect("stage overlay set");
    saturate_input(&mut vm);
    vm.set_register(10, p_path);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_GET, &mut vm).expect("overlay state get");
    let p_out = vm.register(10);
    assert!(
        (Memory::HEAP_START..Memory::INPUT_START).contains(&p_out),
        "overlay state_get should spill into heap when input is exhausted"
    );
    let tlv = vm
        .validate_tlv(p_out)
        .expect("validate spilled overlay output");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    assert_eq!(tlv.payload, &expected[..]);
    IVMHost::finish_tx(&mut host).expect("finish overlay tx");
}
#[test]
fn wsv_state_ingress_rejects_oversized_raw_payload() {
    let mut wsv = MockWorldStateView::new();
    assert!(matches!(
        wsv.sc_set(
            "bad",
            vec![0u8; syscalls::STATE_MAX_VALUE_BYTES.saturating_add(1)],
        ),
        Err(VMError::NoritoInvalid)
    ));
}
#[test]
fn wsv_host_overlay_delete_shadows_base_value_during_tx() {
    let mut wsv = MockWorldStateView::new();
    wsv.sc_set("shadowed", b"persisted".to_vec())
        .expect("seed base state");
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(wsv, caller);
    let mut vm = IVM::new(u64::MAX);
    let path_tlv = state_path_tlv("shadowed");
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    IVMHost::begin_tx(&mut host, &Default::default()).expect("begin overlay tx");
    vm.set_register(10, p_path);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_DEL, &mut vm).expect("stage delete");
    vm.set_register(10, p_path);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("overlay delete should shadow base state");
    assert_eq!(
        vm.register(10),
        0,
        "overlay tombstone should hide base value"
    );
    IVMHost::finish_tx(&mut host).expect("finish overlay tx");
}
#[test]
fn wsv_host_overlay_delete_persists_base_removal_after_finish_tx() {
    let mut wsv = MockWorldStateView::new();
    wsv.sc_set("shadowed", b"persisted".to_vec())
        .expect("seed base state");
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(wsv, caller);
    let mut vm = IVM::new(u64::MAX);
    let path_tlv = state_path_tlv("shadowed");
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    IVMHost::begin_tx(&mut host, &Default::default()).expect("begin overlay tx");
    vm.set_register(10, p_path);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_DEL, &mut vm).expect("stage delete");
    IVMHost::finish_tx(&mut host).expect("finish overlay tx");
    vm.set_register(10, p_path);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("flushed delete should remove persisted base value");
    assert_eq!(
        vm.register(10),
        0,
        "flushed delete should keep the value absent"
    );
}
#[test]
fn wsv_host_overlay_set_overrides_and_persists_base_value() {
    let mut wsv = MockWorldStateView::new();
    wsv.sc_set("shadowed", b"persisted".to_vec())
        .expect("seed base state");
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(wsv, caller);
    let mut vm = IVM::new(u64::MAX);
    let path_tlv = state_path_tlv("shadowed");
    let value_tlv = make_tlv(PointerType::NoritoBytes, b"overlay");
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    let p_value = vm.alloc_input_tlv(&value_tlv).expect("alloc value");
    IVMHost::begin_tx(&mut host, &Default::default()).expect("begin overlay tx");
    vm.set_register(10, p_path);
    vm.set_register(11, p_value);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_SET, &mut vm).expect("stage overlay set");
    vm.set_register(10, p_path);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("overlay set should override base state");
    let during_tx = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("overlay tlv");
    assert_eq!(during_tx.type_id, PointerType::NoritoBytes);
    assert_eq!(during_tx.payload, b"overlay");
    IVMHost::finish_tx(&mut host).expect("finish overlay tx");
    vm.set_register(10, p_path);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("flushed overlay set should persist");
    let after_finish = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("persisted tlv");
    assert_eq!(after_finish.type_id, PointerType::NoritoBytes);
    assert_eq!(after_finish.payload, b"overlay");
}
#[test]
fn wsv_host_state_count_uses_overlay_and_tombstones() {
    let mut wsv = MockWorldStateView::new();
    wsv.sc_set("orders/1", b"one".to_vec())
        .expect("seed first order");
    wsv.sc_set("orders/2", b"two".to_vec())
        .expect("seed second order");
    wsv.sc_set("accounts/1", b"account".to_vec())
        .expect("seed unrelated state");
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(wsv, caller);
    let mut vm = IVM::new(u64::MAX);
    let deleted_tlv = state_path_tlv("orders/1");
    let added_tlv = state_path_tlv("orders/3");
    let prefix_tlv = state_path_tlv("orders");
    let value_tlv = make_tlv(PointerType::NoritoBytes, b"three");
    let deleted_ptr = vm.alloc_input_tlv(&deleted_tlv).expect("alloc deleted key");
    let added_ptr = vm.alloc_input_tlv(&added_tlv).expect("alloc added key");
    let prefix_ptr = vm.alloc_input_tlv(&prefix_tlv).expect("alloc prefix");
    let value_ptr = vm.alloc_input_tlv(&value_tlv).expect("alloc value");
    let prefix_payload_len = vm
        .validate_tlv(prefix_ptr)
        .expect("validate prefix")
        .payload
        .len();
    let scanned_key_gas = ["orders/1", "orders/2", "orders/3"]
        .into_iter()
        .map(|key| 1 + u64::try_from(key.len()).expect("key length fits"))
        .sum::<u64>();
    IVMHost::begin_tx(&mut host, &Default::default()).expect("begin overlay tx");
    vm.set_register(10, deleted_ptr);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_DEL, &mut vm).expect("stage delete");
    vm.set_register(10, added_ptr);
    vm.set_register(11, value_ptr);
    IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_SET, &mut vm).expect("stage set");
    vm.set_register(10, prefix_ptr);
    assert_eq!(
        (IVMHost::syscall(&mut host, syscalls::SYSCALL_STATE_COUNT, &mut vm))
            .expect("expected successful fixture result"),
        ivm::host::STATE_QUERY_GAS_BASE
            + u64::try_from(prefix_payload_len).expect("prefix length fits")
            + scanned_key_gas
    );
    assert_eq!(vm.register(10), 2);
}
#[test]
fn wsv_host_pointer_helpers_charge_envelope_bytes() {
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    let mut vm = IVM::new(u64::MAX);
    let payload = b"deterministic";
    let ptr = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, payload))
        .expect("alloc blob");
    let envelope_len = 2 + 1 + 4 + payload.len() + iroha_crypto::Hash::LENGTH;
    vm.set_register(10, ptr);
    assert_eq!(
        (IVMHost::syscall(&mut host, syscalls::SYSCALL_POINTER_TO_NORITO, &mut vm))
            .expect("expected successful fixture result"),
        16 + u64::try_from(envelope_len).expect("test envelope length")
    );
    let wrapped_ptr = vm.register(10);
    let wrapped_payload = {
        let wrapped = vm.validate_tlv(wrapped_ptr).expect("wrapped tlv");
        assert_eq!(wrapped.type_id, PointerType::NoritoBytes);
        assert_eq!(wrapped.payload.len(), envelope_len);
        wrapped.payload.to_vec()
    };
    vm.set_register(10, wrapped_ptr);
    vm.set_register(11, PointerType::Blob as u64);
    assert_eq!(
        (IVMHost::syscall(&mut host, syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm))
            .expect("expected successful fixture result"),
        16 + u64::try_from(envelope_len).expect("test envelope length")
    );
    let roundtrip = vm.validate_tlv(vm.register(10)).expect("roundtrip tlv");
    assert_eq!(roundtrip.type_id, PointerType::Blob);
    assert_eq!(roundtrip.payload, payload);
    let retired_blob_carrier = make_tlv(PointerType::Blob, &wrapped_payload);
    let retired_blob_carrier_ptr = vm
        .alloc_input_tlv(&retired_blob_carrier)
        .expect("allocate retired blob carrier");
    vm.set_register(10, retired_blob_carrier_ptr);
    vm.set_register(11, PointerType::Blob as u64);
    assert!(matches!(
        IVMHost::syscall(&mut host, syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm),
        Err(VMError::NoritoInvalid)
    ));
    assert_eq!(vm.register(10), retired_blob_carrier_ptr);
}
#[test]
fn wsv_host_tlv_eq_charges_payload_bytes() {
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    let mut vm = IVM::new(u64::MAX);
    let left = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, b"same"))
        .expect("alloc left");
    let right = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, b"same"))
        .expect("alloc right");
    vm.set_register(10, left);
    vm.set_register(11, right);
    assert_eq!(
        (IVMHost::syscall(&mut host, syscalls::SYSCALL_TLV_EQ, &mut vm))
            .expect("expected successful fixture result"),
        16 + 4 + 4
    );
    assert_eq!(vm.register(10), 1);
}
#[test]
fn wsv_host_tlv_len_charges_payload_bytes() {
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    let mut vm = IVM::new(u64::MAX);
    let ptr = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, b"length"))
        .expect("alloc tlv");
    vm.set_register(10, ptr);
    assert_eq!(
        (IVMHost::syscall(&mut host, syscalls::SYSCALL_TLV_LEN, &mut vm))
            .expect("expected successful fixture result"),
        16 + 6
    );
    assert_eq!(vm.register(10), 6);
}
