//! Canonical full-width Int conversion through the single V1 pointer codec.
use crate::common;
use ivm::{CoreHost, IVM, PointerType, encoding, syscalls};
fn make_tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&(pty as u16).to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
fn decode_program() -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            ivm::instruction::wide::system::SCALL,
            syscalls::SYSCALL_POINTER_FROM_NORITO as u8,
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    common::assemble(&code)
}
#[test]
fn core_host_int_pointer_codec_preserves_signed_512_boundary() {
    for signed in [[0x7f_u8; 64], [0x80_u8; 64]] {
        let value = iroha_primitives::bigint::BigInt::from_twos_bytes(&signed)
            .expect("signed 512-bit value");
        let inner = ivm_abi::numeric_tlv::encode_int(&value).expect("Int pointer");
        let outer = make_tlv(PointerType::NoritoBytes, &inner);
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(CoreHost::new());
        let ptr = vm.alloc_input_tlv(&outer).expect("allocate wrapped Int");
        vm.load_program(&decode_program()).expect("load");
        vm.set_register(10, ptr);
        vm.set_register(11, u64::from(PointerType::Int as u16));
        vm.run().expect("decode full-width Int");
        let restored = vm.validate_tlv(vm.register(10)).expect("Int output");
        assert_eq!(
            (ivm::numeric_tlv::decode_int_bytes(&make_tlv(PointerType::Int, restored.payload)))
                .expect("expected successful fixture result"),
            value
        );
    }
}
#[test]
fn core_host_int_pointer_codec_rejects_noncanonical_frame() {
    let inner = make_tlv(PointerType::Int, b"-42");
    let outer = make_tlv(PointerType::NoritoBytes, &inner);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let ptr = vm
        .alloc_input_tlv(&outer)
        .expect("allocate malformed frame");
    vm.load_program(&decode_program()).expect("load");
    vm.set_register(10, ptr);
    vm.set_register(11, u64::from(PointerType::Int as u16));
    assert!(vm.run().is_err());
    assert_eq!(vm.register(10), ptr);
}
