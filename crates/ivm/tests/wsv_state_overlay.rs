//! WsvHost state overlay staging and commit/rollback behaviour.
use ivm::{IVM, Memory, MockWorldStateView, PointerType, WsvHost, host::IVMHost, syscalls};
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
mod common;
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
fn decode_state_payload(ptr: u64, vm: &IVM) -> Vec<u8> {
    assert!(
        (Memory::INPUT_START..Memory::INPUT_START + Memory::INPUT_SIZE).contains(&ptr),
        "state TLV should live in INPUT: 0x{ptr:08x}"
    );
    let tlv = vm.memory.validate_tlv(ptr).expect("valid TLV pointer");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    common::decode_bytes_state_value(tlv.payload)
}
fn sample_account() -> ivm::mock_wsv::AccountId {
    let _domain: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain id");
    ivm::mock_wsv::AccountId::new(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key"),
    )
}
fn alternate_account() -> ivm::mock_wsv::AccountId {
    ivm::mock_wsv::AccountId::new(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("alternate public key"),
    )
}
fn state_schema_program() -> Vec<u8> {
    common::assemble_bytes_state_schema_contract(&["counter"])
}
fn set_and_get(host: &mut WsvHost, vm: &mut IVM) -> Result<u64, ivm::VMError> {
    host.syscall(syscalls::SYSCALL_STATE_SET, vm)?;
    host.syscall(syscalls::SYSCALL_STATE_GET, vm)
}

#[test]
fn overlay_stages_and_flushes_on_finish() {
    let p_path = state_path_tlv("counter");
    let p_val = make_tlv(
        PointerType::NoritoBytes,
        &common::encode_bytes_state_value(b"5"),
    );
    let program = state_schema_program();
    let mut vm = IVM::new(u64::MAX);
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), sample_account());
    {
        let host = &mut host;
        IVMHost::begin_tx(host, &Default::default()).expect("begin_tx");
    }
    let p_path_ptr = vm.alloc_input_tlv(&p_path).expect("alloc path");
    let p_val_ptr = vm.alloc_input_tlv(&p_val).expect("alloc val");
    vm.set_register(10, p_path_ptr);
    vm.set_register(11, p_val_ptr);
    vm.load_program(&program).expect("load program");
    let res = set_and_get(&mut host, &mut vm);
    assert!(res.is_ok(), "execute overlay program: {res:?}");
    let value_ptr = vm.register(10);
    assert_eq!(decode_state_payload(value_ptr, &vm), b"5");
    {
        let host = &mut host;
        assert!(
            host.wsv.sc_get("counter").is_none(),
            "state should not flush before finish_tx"
        );
        IVMHost::finish_tx(host).expect("finish_tx");
        let stored = host
            .wsv
            .sc_get("counter")
            .expect("state flushed after finish_tx");
        assert_eq!(common::decode_bytes_state_value(&stored), b"5");
    }
}
#[test]
fn overlay_restores_snapshot_on_rollback() {
    let p_path = state_path_tlv("counter");
    let initial = common::encode_bytes_state_value(b"1");
    let updated = make_tlv(
        PointerType::NoritoBytes,
        &common::encode_bytes_state_value(b"9"),
    );
    let program = state_schema_program();
    let mut wsv = MockWorldStateView::new();
    wsv.sc_set("counter", initial).expect("seed durable state");
    let mut vm = IVM::new(u64::MAX);
    let mut host = WsvHost::new_with_subject(wsv, sample_account());
    {
        let host = &mut host;
        IVMHost::begin_tx(host, &Default::default()).expect("begin_tx");
    }
    let snapshot = {
        let host = &mut host;
        host.checkpoint().expect("checkpoint captured")
    };
    let p_path_ptr = vm.alloc_input_tlv(&p_path).expect("alloc path");
    let p_val_ptr = vm.alloc_input_tlv(&updated).expect("alloc val");
    vm.set_register(10, p_path_ptr);
    vm.set_register(11, p_val_ptr);
    vm.load_program(&program).expect("load program");
    let res = set_and_get(&mut host, &mut vm);
    assert!(res.is_ok(), "execute overlay program: {res:?}");
    assert_eq!(decode_state_payload(vm.register(10), &vm), b"9");
    {
        let host = &mut host;
        host.restore(snapshot.as_ref()).expect("restore checkpoint");
        IVMHost::finish_tx(host).expect("finish_tx after restore");
        let stored = host
            .wsv
            .sc_get("counter")
            .expect("state after rollback should exist");
        assert_eq!(common::decode_bytes_state_value(&stored), b"1");
    }
}
#[test]
fn checkpoint_restore_flushes_persisted_wsv_state() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "ivm_overlay_restore_flush_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&tmp_dir).expect("tmp dir");
    let persist_path = tmp_dir.join("state.json");
    let initial = b"1".to_vec();
    let updated = b"9".to_vec();
    let mut wsv =
        MockWorldStateView::with_state_store(persist_path.clone()).expect("persisted WSV");
    wsv.sc_set("counter", initial).expect("seed durable state");
    let mut host = WsvHost::new_with_subject(wsv, sample_account());
    let snapshot = host.checkpoint().expect("checkpoint captured");
    host.wsv
        .sc_set("counter", updated)
        .expect("persist updated state");
    let reloaded =
        MockWorldStateView::with_state_store(persist_path.clone()).expect("reload updated state");
    let stored = reloaded.sc_get("counter").expect("updated persisted state");
    assert_eq!(stored, b"9");
    host.restore(snapshot.as_ref()).expect("restore checkpoint");
    let stored = host.wsv.sc_get("counter").expect("restored host state");
    assert_eq!(stored, b"1");
    let reloaded =
        MockWorldStateView::with_state_store(persist_path.clone()).expect("reload restored state");
    let stored = reloaded
        .sc_get("counter")
        .expect("restored persisted state");
    assert_eq!(stored, b"1");
    let _ = fs::remove_dir_all(&tmp_dir);
}
#[test]
fn checkpoint_restore_persistence_failure_is_reported_without_panicking() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "ivm_overlay_restore_failure_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let store_dir = tmp_dir.join("store");
    fs::create_dir_all(&store_dir).expect("state store directory");
    let persist_path = store_dir.join("state.json");
    let original_caller = sample_account();
    let mut wsv =
        MockWorldStateView::with_state_store(persist_path).expect("persisted WSV available");
    wsv.sc_set("counter", b"1".to_vec())
        .expect("seed durable state");
    let mut host = WsvHost::new_with_subject(wsv, original_caller.clone());
    let snapshot = host.checkpoint().expect("checkpoint captured");
    host.wsv
        .sc_set("counter", b"9".to_vec())
        .expect("persist updated state");
    host.set_caller_subject(alternate_account());

    fs::remove_dir_all(&store_dir).expect("remove state store directory");
    fs::write(&store_dir, b"block parent directory creation").expect("install blocker file");
    assert!(matches!(
        host.restore(snapshot.as_ref()),
        Err(ivm::VMError::NoritoInvalid)
    ));
    assert_eq!(host.wsv.sc_get("counter"), Some(b"1".to_vec()));
    assert_eq!(host.caller, original_caller);
    let _ = fs::remove_dir_all(&tmp_dir);
}
#[test]
fn overlay_flush_errors_surface_and_reset_overlay() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "ivm_overlay_flush_err_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&tmp_dir).expect("tmp dir");
    let blocker = tmp_dir.join("blocker");
    let persist_path = blocker.join("state.json");
    let wsv =
        MockWorldStateView::with_state_store(persist_path).expect("persisted mock WSV available");
    fs::write(&blocker, b"block").expect("blocker file");
    let mut vm = IVM::new(u64::MAX);
    let mut host = WsvHost::new_with_subject(wsv, sample_account());
    let p_path = state_path_tlv("counter");
    let p_val = make_tlv(
        PointerType::NoritoBytes,
        &common::encode_bytes_state_value(b"5"),
    );
    let program = state_schema_program();
    {
        let host = &mut host;
        IVMHost::begin_tx(host, &Default::default()).expect("begin_tx");
    }
    let p_path_ptr = vm.alloc_input_tlv(&p_path).expect("alloc path");
    let p_val_ptr = vm.alloc_input_tlv(&p_val).expect("alloc val");
    vm.set_register(10, p_path_ptr);
    vm.set_register(11, p_val_ptr);
    vm.load_program(&program).expect("load program");
    set_and_get(&mut host, &mut vm).expect("execute overlay program");
    {
        let host = &mut host;
        assert!(
            host.wsv.sc_get("counter").is_none(),
            "flush should not occur before finish_tx"
        );
        let finish_err = IVMHost::finish_tx(host);
        assert!(
            finish_err.is_err(),
            "finish_tx should return the flush error"
        );
        assert!(
            host.wsv.sc_get("counter").is_none(),
            "state should stay unflushed after error"
        );
        let retry = IVMHost::finish_tx(host);
        assert!(
            retry.is_ok(),
            "finish_tx should clear overlay and become idempotent after errors"
        );
    }
    let _ = fs::remove_dir_all(&tmp_dir);
}
