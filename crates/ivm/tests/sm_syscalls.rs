use hex::decode;
use iroha_crypto::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature, Sm3Digest};
use ivm::{
    CoreHost, Memory, PointerType, VMError, encoding, instruction,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
};
const TEST_CALLER_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
fn test_caller_account() -> AccountId {
    AccountId::parse_encoded(TEST_CALLER_ID)
        .expect("test account literal must be valid canonical AccountId")
}
use crate::common;
use common::{assemble, payload_for_type};
fn make_tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
    use iroha_crypto::Hash;
    let payload = payload_for_type(kind, payload);
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&(kind as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(&payload).into();
    out.extend_from_slice(&h);
    out
}
fn make_blob_tlv(payload: &[u8]) -> Vec<u8> {
    make_tlv(PointerType::Blob, payload)
}
fn core_host_with_sm(enable: bool) -> CoreHost {
    CoreHost::new().with_sm_enabled(enable)
}
fn wsv_host(caller: AccountId) -> WsvHost {
    WsvHost::new_with_subject(MockWorldStateView::new(), caller)
}
#[test]
fn syscall_sm3_hash_returns_digest_blob() {
    use ivm::IVM;
    let message = b"ivm-sm3";
    let expected = Sm3Digest::hash(message);
    let tlv = make_blob_tlv(message);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    vm.memory
        .preload_input(0, &tlv)
        .expect("preload input blob");
    let ptr_input = Memory::INPUT_START;
    vm.set_register(10, ptr_input);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM3_HASH as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    let out_ptr = vm.register(10);
    assert_ne!(out_ptr, 0, "output pointer should not be zero");
    let tlv_out = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate output TLV");
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    assert_eq!(tlv_out.payload, expected.as_bytes());
}
fn run_sm3_with_host<H>(host: H, message: &[u8]) -> Vec<u8>
where
    H: ivm::host::IVMHost + Send + Sync + 'static,
{
    use ivm::IVM;
    let tlv = make_blob_tlv(message);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    vm.set_host(host);
    vm.memory
        .preload_input(0, &tlv)
        .expect("preload input blob");
    vm.set_register(10, Memory::INPUT_START);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM3_HASH as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    let out_ptr = vm.register(10);
    assert_ne!(out_ptr, 0, "output pointer should not be zero");
    let tlv_out = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate output TLV");
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    tlv_out.payload.to_vec()
}
#[test]
fn core_host_sm3_hash_returns_digest_blob() {
    let message = b"corehost-sm3";
    let expected = Sm3Digest::hash(message);
    let payload = run_sm3_with_host(core_host_with_sm(true), message);
    assert_eq!(payload.as_slice(), expected.as_bytes());
}
#[test]
fn mock_wsv_sm3_hash_returns_digest_blob() {
    let message = b"mockwsv-sm3";
    let expected = Sm3Digest::hash(message);
    let caller: AccountId = test_caller_account();
    let host = wsv_host(caller).with_sm_enabled(true);
    let payload = run_sm3_with_host(host, message);
    assert_eq!(payload.as_slice(), expected.as_bytes());
}
#[test]
fn wsv_host_sm2_verify_succeeds_when_enabled() {
    use ivm::IVM;
    let secret = [0x35u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"wsv-sm2-enabled";
    let signature = private.sign(message).to_bytes();
    let caller: AccountId = test_caller_account();
    let host = wsv_host(caller).with_sm_enabled(true);
    let mut vm = IVM::new(10_000);
    vm.set_host(host);
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let pk_bytes = public.to_sec1_bytes(false);
    let p_pk = preload_blob(&mut vm, &mut offset, &pk_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(
        vm.register(10),
        1,
        "SM2 verification should succeed when enabled"
    );
}
#[test]
fn default_host_sm3_hash_requires_enable_flag() {
    use ivm::IVM;
    let message = b"ivm-sm3-disabled";
    let tlv = make_blob_tlv(message);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new());
    vm.memory
        .preload_input(0, &tlv)
        .expect("preload input blob");
    vm.set_register(10, Memory::INPUT_START);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM3_HASH as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("SM3 syscall should be gated when SM support is disabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
#[test]
fn core_host_sm3_hash_requires_enable_flag() {
    use ivm::IVM;
    let message = b"corehost-sm3-disabled";
    let tlv = make_blob_tlv(message);
    let mut vm = IVM::new(10_000);
    vm.set_host(core_host_with_sm(false));
    vm.memory
        .preload_input(0, &tlv)
        .expect("preload input blob");
    vm.set_register(10, Memory::INPUT_START);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM3_HASH as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("CoreHost should gate SM syscalls unless enabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
#[test]
fn wsv_host_sm3_hash_requires_enable_flag() {
    use ivm::IVM;
    let message = b"wsv-sm3-disabled";
    let tlv = make_blob_tlv(message);
    let caller: AccountId = test_caller_account();
    let host = wsv_host(caller);
    let mut vm = IVM::new(10_000);
    vm.set_host(host);
    vm.memory
        .preload_input(0, &tlv)
        .expect("preload input blob");
    vm.set_register(10, Memory::INPUT_START);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM3_HASH as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("WsvHost should gate SM syscalls unless enabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
fn preload_tlv(vm: &mut ivm::IVM, offset: &mut u64, kind: PointerType, payload: &[u8]) -> u64 {
    let tlv = make_tlv(kind, payload);
    vm.memory
        .preload_input(*offset, &tlv)
        .expect("preload blob");
    let ptr = Memory::INPUT_START + *offset;
    *offset += tlv.len() as u64 + 8;
    ptr
}
fn preload_blob(vm: &mut ivm::IVM, offset: &mut u64, payload: &[u8]) -> u64 {
    preload_tlv(vm, offset, PointerType::Blob, payload)
}
#[test]
fn syscall_sm2_verify_success() {
    use ivm::IVM;
    let secret = [0x11u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2";
    let signature = private.sign(message);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let sig_bytes = signature.to_bytes();
    let p_sig = preload_blob(&mut vm, &mut offset, sig_bytes.as_ref());
    let pk_bytes = public.to_sec1_bytes(false);
    let p_pk = preload_blob(&mut vm, &mut offset, &pk_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0); // default distid
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(vm.register(10), 1, "SM2 verification should succeed");
}
#[test]
fn syscall_sm2_verify_charges_input_bytes() {
    use ivm::{
        IVM,
        host::{DefaultHost, IVMHost},
    };
    let secret = [0x33u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-gas";
    let signature = private.sign(message);
    let signature_bytes = signature.to_bytes();
    let public_key_bytes = public.to_sec1_bytes(false);
    let mut host = DefaultHost::new().with_sm_enabled(true);
    let mut vm = IVM::new(10_000);
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature_bytes.as_ref());
    let p_pk = preload_blob(&mut vm, &mut offset, &public_key_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let expected_gas =
        64 + message.len() as u64 + signature_bytes.len() as u64 + public_key_bytes.len() as u64;
    assert_eq!(
        (host.syscall(ivm::syscalls::SYSCALL_SM2_VERIFY, &mut vm))
            .expect("expected successful fixture result"),
        expected_gas
    );
    assert_eq!(vm.register(10), 1);
    let mut bad_sig = signature_bytes.as_ref().to_vec();
    bad_sig.truncate(Sm2Signature::LENGTH - 1);
    let mut vm = IVM::new(10_000);
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, &bad_sig);
    let p_pk = preload_blob(&mut vm, &mut offset, &public_key_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let expected_bad_gas =
        64 + message.len() as u64 + bad_sig.len() as u64 + public_key_bytes.len() as u64;
    assert_eq!(
        (host.syscall(ivm::syscalls::SYSCALL_SM2_VERIFY, &mut vm))
            .expect("expected successful fixture result"),
        expected_bad_gas
    );
    assert_eq!(vm.register(10), 0);
}
#[test]
fn syscall_sm2_verify_accepts_custom_distid() {
    use ivm::IVM;
    let secret = [0xABu8; 32];
    let distid = "cnca:test-distid";
    let private = Sm2PrivateKey::new(distid, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-distid";
    let signature = private.sign(message);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.to_bytes().as_ref());
    let p_pk = preload_blob(&mut vm, &mut offset, &public.to_sec1_bytes(false));
    let p_distid = preload_blob(&mut vm, &mut offset, distid.as_bytes());
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, p_distid);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(
        vm.register(10),
        1,
        "SM2 verification should succeed with custom distid"
    );
}
#[test]
fn syscall_sm2_verify_fails_for_bad_signature() {
    use ivm::IVM;
    let secret = [0x22u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-bad";
    let mut sig_bytes = private.sign(message).to_bytes();
    sig_bytes[0] ^= 0xFF;
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, sig_bytes.as_ref());
    let pk_bytes = public.to_sec1_bytes(false);
    let p_pk = preload_blob(&mut vm, &mut offset, &pk_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(vm.register(10), 0, "SM2 verification should fail");
}
#[test]
fn syscall_sm2_verify_returns_zero_for_truncated_signature() {
    use ivm::IVM;
    let secret = [0x44u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-short-sig";
    let mut sig = private.sign(message).to_bytes().to_vec();
    sig.truncate(Sm2Signature::LENGTH - 1);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, &sig);
    let p_pk = preload_blob(&mut vm, &mut offset, &public.to_sec1_bytes(false));
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(
        vm.register(10),
        0,
        "SM2 verification should reject truncated signatures"
    );
}
#[test]
fn syscall_sm2_verify_returns_zero_for_all_zero_signature() {
    use ivm::IVM;
    let secret = [0x45u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-zero-sig";
    let sig = [0u8; Sm2Signature::LENGTH];
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, &sig);
    let p_pk = preload_blob(&mut vm, &mut offset, &public.to_sec1_bytes(false));
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(
        vm.register(10),
        0,
        "SM2 verification should reject all-zero signatures"
    );
}
#[test]
fn syscall_sm2_verify_returns_zero_for_invalid_public_key() {
    use ivm::IVM;
    let secret = [0x55u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let message = b"ivm-sm2-bad-pk";
    let signature = private.sign(message).to_bytes();
    let mut public_bytes = private.public_key().to_sec1_bytes(false);
    // mutate the affine point so it cannot be decoded
    public_bytes[0] ^= 0xFF;
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let p_pk = preload_blob(&mut vm, &mut offset, &public_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(
        vm.register(10),
        0,
        "SM2 verification should reject malformed public keys"
    );
}
#[test]
fn syscall_sm2_verify_rejects_mismatched_distid() {
    use ivm::IVM;
    let secret = [0x26u8; 32];
    let signing_distid = "device:alpha";
    let private = Sm2PrivateKey::new(signing_distid, secret).expect("construct key");
    let message = b"ivm-sm2-mismatched-distid";
    let signature = private.sign(message).to_bytes();
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let p_pk = preload_blob(
        &mut vm,
        &mut offset,
        &private.public_key().to_sec1_bytes(false),
    );
    let p_other_distid = preload_blob(&mut vm, &mut offset, b"device:beta");
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, p_other_distid);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(
        vm.register(10),
        0,
        "SM2 verification must fail when distinguishing ID does not match"
    );
}
#[test]
fn syscall_sm2_verify_supports_empty_distid_blob() {
    use ivm::IVM;
    let secret = [0x19u8; 32];
    let private = Sm2PrivateKey::new("", secret).expect("construct key");
    let message = b"ivm-sm2-empty-distid";
    let signature = private.sign(message).to_bytes();
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let p_pk = preload_blob(
        &mut vm,
        &mut offset,
        &private.public_key().to_sec1_bytes(false),
    );
    let p_distid = preload_blob(&mut vm, &mut offset, b"");
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, p_distid);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(
        vm.register(10),
        1,
        "SM2 verification should support empty distinguishing identifier payloads"
    );
}
#[test]
fn syscall_sm2_verify_requires_enable_flag() {
    use ivm::IVM;
    let secret = [0x33u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-disabled";
    let signature = private.sign(message).to_bytes();
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new());
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let pk_bytes = public.to_sec1_bytes(false);
    let p_pk = preload_blob(&mut vm, &mut offset, &pk_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("SM2 verification should be gated when SM support is disabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
#[test]
fn syscall_sm2_verify_errors_on_non_blob_inputs() {
    use ivm::IVM;
    let secret = [0x66u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let signature = private.sign(b"ivm-sm2-nonblob").to_bytes();
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_tlv(
        &mut vm,
        &mut offset,
        PointerType::Json,
        b"{\"not\":\"blob\"}",
    );
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let p_pk = preload_blob(
        &mut vm,
        &mut offset,
        &private.public_key().to_sec1_bytes(false),
    );
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("non-blob inputs should trigger NoritoInvalid");
    assert!(
        matches!(err, VMError::NoritoInvalid),
        "expected NoritoInvalid, got {err:?}"
    );
}
#[test]
fn syscall_sm2_verify_errors_on_non_utf8_distid() {
    use ivm::IVM;
    let secret = [0x77u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-invalid-distid";
    let signature = private.sign(message).to_bytes();
    let invalid_utf8 = [0xFF, 0xFE, 0xFD];
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let p_pk = preload_blob(&mut vm, &mut offset, &public.to_sec1_bytes(false));
    let p_distid = preload_blob(&mut vm, &mut offset, &invalid_utf8);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, p_distid);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("non-UTF8 distid should trigger NoritoInvalid");
    assert!(
        matches!(err, VMError::NoritoInvalid),
        "expected NoritoInvalid, got {err:?}"
    );
}
#[test]
fn syscall_sm4_gcm_seal_matches_vector() {
    use ivm::IVM;
    let key = decode("0123456789abcdeffedcba9876543210").expect("hex key");
    let nonce = decode("00001234567800000000abcd").expect("hex nonce");
    let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex aad");
    let plaintext = decode("d9313225f88406e5a55909c5aff5269a").expect("hex plaintext");
    let expected_cipher = decode("6468017fde4979a107326ee77d8a265c").expect("hex cipher");
    let expected_tag = decode("cadf422b1af7ec6df46004dc8d3ba855").expect("hex tag");
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_pt = preload_blob(&mut vm, &mut offset, &plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_pt);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_GCM_SEAL as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    let out_ptr = vm.register(10);
    assert_ne!(out_ptr, 0, "SM4 seal should produce output");
    let tlv_out = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate output TLV");
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    let payload = tlv_out.payload;
    assert_eq!(payload.len(), expected_cipher.len() + expected_tag.len());
    assert_eq!(
        &payload[..expected_cipher.len()],
        expected_cipher.as_slice()
    );
    assert_eq!(&payload[expected_cipher.len()..], expected_tag.as_slice());
}
#[test]
fn syscall_sm4_gcm_open_returns_plaintext() {
    use ivm::IVM;
    let key = decode("0123456789abcdeffedcba9876543210").expect("hex key");
    let nonce = decode("00001234567800000000abcd").expect("hex nonce");
    let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex aad");
    let plaintext = decode("d9313225f88406e5a55909c5aff5269a").expect("hex plaintext");
    let cipher = decode("6468017fde4979a107326ee77d8a265c").expect("hex cipher");
    let tag = decode("cadf422b1af7ec6df46004dc8d3ba855").expect("hex tag");
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_ct = preload_blob(&mut vm, &mut offset, &cipher_tag);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_ct);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_GCM_OPEN as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    let out_ptr = vm.register(10);
    assert_ne!(out_ptr, 0, "SM4 open should produce plaintext");
    let tlv_out = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate output TLV");
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    assert_eq!(tlv_out.payload, plaintext.as_slice());
}
#[test]
fn syscall_sm4_gcm_open_rejects_bad_tag() {
    use ivm::IVM;
    let key = decode("0123456789abcdeffedcba9876543210").expect("hex key");
    let nonce = decode("00001234567800000000abcd").expect("hex nonce");
    let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex aad");
    let cipher = decode("6468017fde4979a107326ee77d8a265c").expect("hex cipher");
    let mut tag = decode("cadf422b1af7ec6df46004dc8d3ba855").expect("hex tag");
    tag[0] ^= 0xFF;
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_ct = preload_blob(&mut vm, &mut offset, &cipher_tag);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_ct);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_GCM_OPEN as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(vm.register(10), 0, "SM4 open should fail with bad tag");
}
#[test]
fn syscall_sm4_ccm_seal_matches_vector() {
    use ivm::IVM;
    let key = decode("404142434445464748494a4b4c4d4e4f").expect("hex key");
    let nonce = decode("10111213141516").expect("hex nonce");
    let aad = decode("000102030405060708090a0b0c0d0e0f").expect("hex aad");
    let plaintext = decode("202122232425262728292a2b2c2d2e2f").expect("hex plaintext");
    let expected_cipher = decode("a9550cebab5f227d9590e8979caafd1f").expect("hex cipher");
    let expected_tag = decode("03a1f305").expect("hex tag");
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_pt = preload_blob(&mut vm, &mut offset, &plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_pt);
    vm.set_register(14, expected_tag.len() as u64);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_CCM_SEAL as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    let out_ptr = vm.register(10);
    assert_ne!(out_ptr, 0, "SM4 CCM seal should produce output");
    let tlv_out = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate output TLV");
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    let payload = tlv_out.payload;
    assert_eq!(payload.len(), expected_cipher.len() + expected_tag.len());
    assert_eq!(
        &payload[..expected_cipher.len()],
        expected_cipher.as_slice()
    );
    assert_eq!(&payload[expected_cipher.len()..], expected_tag.as_slice());
}
#[test]
fn syscall_sm4_ccm_open_returns_plaintext() {
    use ivm::IVM;
    let key = decode("404142434445464748494a4b4c4d4e4f").expect("hex key");
    let nonce = decode("10111213141516").expect("hex nonce");
    let aad = decode("000102030405060708090a0b0c0d0e0f").expect("hex aad");
    let plaintext = decode("202122232425262728292a2b2c2d2e2f").expect("hex plaintext");
    let cipher = decode("a9550cebab5f227d9590e8979caafd1f").expect("hex cipher");
    let tag = decode("03a1f305").expect("hex tag");
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_ct = preload_blob(&mut vm, &mut offset, &cipher_tag);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_ct);
    vm.set_register(14, tag.len() as u64);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_CCM_OPEN as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    let out_ptr = vm.register(10);
    assert_ne!(out_ptr, 0, "SM4 CCM open should produce plaintext");
    let tlv_out = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate output TLV");
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    assert_eq!(tlv_out.payload, plaintext.as_slice());
}
#[test]
fn syscall_sm4_ccm_open_rejects_bad_tag() {
    use ivm::IVM;
    let key = decode("404142434445464748494a4b4c4d4e4f").expect("hex key");
    let nonce = decode("10111213141516").expect("hex nonce");
    let aad = decode("000102030405060708090a0b0c0d0e0f").expect("hex aad");
    let cipher = decode("7162015b4dac2555").expect("hex cipher");
    let mut tag = decode("4d26de5a").expect("hex tag");
    tag[0] ^= 0x02;
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_ct = preload_blob(&mut vm, &mut offset, &cipher_tag);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_ct);
    vm.set_register(14, tag.len() as u64);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_CCM_OPEN as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(vm.register(10), 0, "SM4 CCM open should fail with bad tag");
}
#[test]
fn syscall_sm4_ccm_seal_rejects_wide_tag_length_without_truncation() {
    use ivm::IVM;
    let key = [0x77u8; 16];
    let nonce = [0x88u8; 7];
    let plaintext = [0x99u8; 8];
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_pt = preload_blob(&mut vm, &mut offset, &plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, 0);
    vm.set_register(13, p_pt);
    // This aliases tag length 4 if a 64-bit protocol register is narrowed to
    // a 32-bit usize with `as`.
    vm.set_register(14, u64::from(u32::MAX) + 5);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_CCM_SEAL as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    vm.load_program(&assemble(&program)).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(vm.register(10), 0);
}
#[test]
fn syscall_sm4_ccm_open_rejects_wide_tag_length_without_truncation() {
    use ivm::IVM;
    let key = decode("404142434445464748494a4b4c4d4e4f").expect("hex key");
    let nonce = decode("10111213141516").expect("hex nonce");
    let aad = decode("000102030405060708090a0b0c0d0e0f").expect("hex aad");
    let cipher = decode("a9550cebab5f227d9590e8979caafd1f").expect("hex cipher");
    let tag = decode("03a1f305").expect("hex tag");
    let mut cipher_tag = cipher;
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new().with_sm_enabled(true));
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_ct = preload_blob(&mut vm, &mut offset, &cipher_tag);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_ct);
    vm.set_register(14, u64::from(u32::MAX) + 5);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_CCM_OPEN as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    vm.load_program(&assemble(&program)).expect("load program");
    vm.run().expect("vm run");
    assert_eq!(vm.register(10), 0);
}
#[test]
fn syscall_sm4_gcm_seal_requires_enable_flag() {
    use ivm::IVM;
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let plaintext = [0u8; 16];
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new());
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_pt = preload_blob(&mut vm, &mut offset, &plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, 0); // no AAD
    vm.set_register(13, p_pt);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_GCM_SEAL as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("SM4 GCM seal should be gated when SM support is disabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
#[test]
fn wsv_host_sm2_verify_requires_enable_flag() {
    use ivm::IVM;
    let secret = [0x55u8; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct key");
    let public = private.public_key();
    let message = b"ivm-sm2-wsvhost-disabled";
    let signature = private.sign(message).to_bytes();
    let caller: AccountId = test_caller_account();
    let host = wsv_host(caller);
    let mut vm = IVM::new(10_000);
    vm.set_host(host);
    let mut offset = 0u64;
    let p_msg = preload_blob(&mut vm, &mut offset, message);
    let p_sig = preload_blob(&mut vm, &mut offset, signature.as_ref());
    let pk_bytes = public.to_sec1_bytes(false);
    let p_pk = preload_blob(&mut vm, &mut offset, &pk_bytes);
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 0);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM2_VERIFY as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("WsvHost should gate SM2 verification unless SM is enabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
#[test]
fn wsv_host_sm4_gcm_seal_matches_vector_when_enabled() {
    use ivm::IVM;
    let key = decode("0123456789abcdeffedcba9876543210").expect("hex key");
    let nonce = decode("00001234567800000000abcd").expect("hex nonce");
    let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex aad");
    let plaintext = decode("d9313225f88406e5a55909c5aff5269a").expect("hex plaintext");
    let expected_cipher = decode("6468017fde4979a107326ee77d8a265c").expect("hex cipher");
    let expected_tag = decode("cadf422b1af7ec6df46004dc8d3ba855").expect("hex tag");
    let caller: AccountId = test_caller_account();
    let host = wsv_host(caller).with_sm_enabled(true);
    let mut vm = IVM::new(10_000);
    vm.set_host(host);
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, &aad);
    let p_pt = preload_blob(&mut vm, &mut offset, &plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_pt);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_GCM_SEAL as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    vm.run().expect("vm run");
    let out_ptr = vm.register(10);
    assert_ne!(
        out_ptr, 0,
        "SM4 GCM seal should produce output when enabled"
    );
    let tlv_out = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate output TLV");
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    let payload = tlv_out.payload;
    assert_eq!(payload.len(), expected_cipher.len() + expected_tag.len());
    assert_eq!(
        &payload[..expected_cipher.len()],
        expected_cipher.as_slice()
    );
    assert_eq!(&payload[expected_cipher.len()..], expected_tag.as_slice());
}
#[test]
fn wsv_host_sm4_gcm_seal_returns_byte_counted_gas_when_enabled() {
    use ivm::{IVM, host::IVMHost};
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let aad = b"aad";
    let plaintext = b"plaintext";
    let caller: AccountId = test_caller_account();
    let mut host = wsv_host(caller).with_sm_enabled(true);
    let mut vm = IVM::new(10_000);
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_aad = preload_blob(&mut vm, &mut offset, aad);
    let p_pt = preload_blob(&mut vm, &mut offset, plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, p_aad);
    vm.set_register(13, p_pt);
    assert_eq!(
        (IVMHost::syscall(&mut host, ivm::syscalls::SYSCALL_SM4_GCM_SEAL, &mut vm))
            .expect("expected successful fixture result"),
        64 + u64::try_from(aad.len() + plaintext.len()).expect("test length")
    );
    let out = vm.memory.validate_tlv(vm.register(10)).expect("sealed tlv");
    assert_eq!(out.type_id, PointerType::Blob);
    assert_eq!(out.payload.len(), plaintext.len() + 16);
}
#[test]
fn wsv_host_sm4_gcm_seal_requires_enable_flag() {
    use ivm::IVM;
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let plaintext = [0x33u8; 16];
    let caller: AccountId = test_caller_account();
    let host = wsv_host(caller);
    let mut vm = IVM::new(10_000);
    vm.set_host(host);
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_pt = preload_blob(&mut vm, &mut offset, &plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, 0);
    vm.set_register(13, p_pt);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_GCM_SEAL as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("WsvHost should gate SM4 GCM sealing unless SM is enabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
#[test]
fn default_host_sm4_ccm_seal_requires_enable_flag() {
    use ivm::IVM;
    let key = [0x77u8; 16];
    let nonce = [0x88u8; 7];
    let plaintext = [0x99u8; 8];
    let mut vm = IVM::new(10_000);
    vm.set_host(ivm::host::DefaultHost::new());
    let mut offset = 0u64;
    let p_key = preload_blob(&mut vm, &mut offset, &key);
    let p_nonce = preload_blob(&mut vm, &mut offset, &nonce);
    let p_pt = preload_blob(&mut vm, &mut offset, &plaintext);
    vm.set_register(10, p_key);
    vm.set_register(11, p_nonce);
    vm.set_register(12, 0);
    vm.set_register(13, p_pt);
    vm.set_register(14, 16);
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_SM4_CCM_SEAL as u8,
    );
    let halt = encoding::wide::encode_halt();
    let mut program = Vec::new();
    program.extend_from_slice(&syscall.to_le_bytes());
    program.extend_from_slice(&halt.to_le_bytes());
    let program = assemble(&program);
    vm.load_program(&program).expect("load program");
    let err = vm
        .run()
        .expect_err("SM4 CCM seal should be gated when SM support is disabled");
    assert!(matches!(err, VMError::PermissionDenied));
}
