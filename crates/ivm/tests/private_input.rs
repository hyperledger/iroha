//! Typed private-input ABI boundary tests.
use ivm::{IVM, Memory, ProgramMetadata, VMError, encoding, host::DefaultHost, syscalls};
use ivm_abi::private_input::{PrivateInputKindV1, PrivateInputRecordV1};
fn private_input_program() -> Vec<u8> {
    let mut program = ProgramMetadata {
        mode: ivm::ivm_mode::ZK,
        max_cycles: 16,
        ..ProgramMetadata::default()
    }
    .encode();
    program.extend_from_slice(
        &encoding::wide::encode_sys(
            ivm::instruction::wide::system::SCALL,
            u8::try_from(syscalls::SYSCALL_GET_PRIVATE_INPUT)
                .expect("private-input syscall fits compact SCALL"),
        )
        .to_le_bytes(),
    );
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    program
}
fn int_host(value: u64) -> DefaultHost {
    let record = ivm::private_input::int_record(value.into()).expect("encode private int");
    DefaultHost::with_private_inputs(vec![record]).expect("construct bounded host")
}
fn run_private_input(host: DefaultHost, kind: PrivateInputKindV1, gas: u64) -> IVM {
    let mut vm = IVM::new(gas);
    vm.set_host(host);
    vm.set_register(10, 0);
    vm.set_register(11, kind.tag());
    vm.load_program(&private_input_program())
        .expect("load private-input program");
    vm.run().expect("private-input syscall failed");
    vm
}
#[test]
fn typed_private_input_returns_an_opaque_private_heap_pointer() {
    let vm = run_private_input(int_host(42), PrivateInputKindV1::Int, 10_000);
    assert!(vm.register(10) >= Memory::HEAP_START);
    assert!(vm.registers.tag(10));
}
#[test]
fn private_input_index_rejects_high_bits_without_usize_truncation() {
    let mut vm = IVM::new(10_000);
    vm.set_host(int_host(42));
    // This aliases index zero if a protocol register is narrowed to a 32-bit
    // usize with `as`.
    vm.set_register(10, u64::from(u32::MAX) + 1);
    vm.set_register(11, PrivateInputKindV1::Int.tag());
    vm.load_program(&private_input_program())
        .expect("load private-input program");
    assert!(matches!(vm.run(), Err(VMError::PermissionDenied)));
}
#[test]
fn wrong_requested_kind_fails_before_private_heap_allocation() {
    let mut vm = IVM::new(10_000);
    vm.set_host(int_host(42));
    vm.set_register(10, 0);
    vm.set_register(11, PrivateInputKindV1::Decimal.tag());
    vm.load_program(&private_input_program())
        .expect("load private-input program");
    assert!(matches!(vm.run(), Err(VMError::NoritoInvalid)));
    assert_eq!(
        vm.alloc_heap(1).expect("probe untouched heap"),
        Memory::HEAP_START
    );
}
#[test]
fn malformed_bounded_record_is_metered_and_fails_before_allocation() {
    let raw = norito::to_bytes(&PrivateInputRecordV1::new(
        PrivateInputKindV1::Int,
        Vec::new(),
    ))
    .expect("encode malformed but bounded outer record");
    let host = DefaultHost::with_encoded_private_inputs(vec![raw])
        .expect("bounded malformed transport is admitted for metered decoding");
    let mut vm = IVM::new(10_000);
    vm.set_host(host);
    vm.set_register(10, 0);
    vm.set_register(11, PrivateInputKindV1::Int.tag());
    vm.load_program(&private_input_program())
        .expect("load private-input program");
    assert!(matches!(vm.run(), Err(VMError::NoritoInvalid)));
    assert_eq!(
        vm.alloc_heap(1).expect("probe untouched heap"),
        Memory::HEAP_START
    );
}
#[test]
fn unaffordable_private_input_does_not_decode_or_allocate() {
    let mut vm = IVM::new(1);
    vm.set_host(int_host(42));
    vm.set_register(10, 0);
    vm.set_register(11, PrivateInputKindV1::Int.tag());
    vm.load_program(&private_input_program())
        .expect("load private-input program");
    assert!(matches!(vm.run(), Err(VMError::OutOfGas)));
    assert_eq!(
        vm.alloc_heap(1).expect("probe untouched heap"),
        Memory::HEAP_START
    );
}
