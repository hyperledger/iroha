//! Regression coverage for an unassigned pre-release decimal-i64 map-key number.
use ivm::{CoreHost, IVM, VMError, encoding, syscalls};
mod common;
#[test]
fn decimal_i64_map_key_helper_is_not_part_of_abi_v1() {
    let unassigned = 0x54;
    assert!(!syscalls::is_syscall_allowed(
        ivm::SyscallPolicy::AbiV1,
        unassigned
    ));
    assert_eq!(syscalls::registered_syscall_access(unassigned), None);
    assert_eq!(syscalls::syscall_name(unassigned), None);
    assert!(!syscalls::abi_syscall_list().contains(&unassigned));
    assert_eq!(
        ivm::host::registered_host_syscall_gas_formula(unassigned),
        None
    );
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            ivm::instruction::wide::system::SCALL,
            u8::try_from(unassigned).expect("unassigned syscall fits compact encoding"),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut admitted = IVM::new(u64::MAX);
    admitted.set_host(CoreHost::new());
    assert!(
        matches!(admitted.load_program(&common::assemble(&code)), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (unassigned)),
        "metadata-bearing programs reject the unassigned number during admission"
    );
    let mut raw = IVM::new(u64::MAX);
    raw.set_host(CoreHost::new());
    raw.load_code(&code)
        .expect("load raw unassigned-syscall fixture");
    assert!(
        matches!(raw.run(), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (unassigned))
    );
}
