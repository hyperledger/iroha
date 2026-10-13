//! Admission regression for the removed invocation-local scalar nullifier number.
mod common;
use common::assemble_syscalls;
use ivm::{
    IVM, SyscallPolicy, VMError,
    host::{DefaultHost, IVMHost, registered_host_syscall_gas_formula},
    syscalls,
};
#[test]
fn invocation_local_u64_nullifier_is_rejected_by_abi_v1() {
    let removed_number = 0xFB;
    assert!(!syscalls::is_syscall_allowed(
        SyscallPolicy::AbiV1,
        removed_number
    ));
    assert_eq!(syscalls::registered_syscall_access(removed_number), None);
    assert_eq!(registered_host_syscall_gas_formula(removed_number), None);
    assert_eq!(syscalls::syscall_name(removed_number), None);
    let mut direct_host = DefaultHost::new();
    let mut direct_vm = IVM::new(u64::MAX);
    assert!(
        matches!(direct_host.prepare_syscall(removed_number, &direct_vm), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (removed_number))
    );
    assert!(
        matches!(direct_host.syscall(removed_number, &mut direct_vm), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (removed_number))
    );
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(DefaultHost::new());
    let program = assemble_syscalls(&[removed_number as u8]);
    if let Err(error) = vm.load_program(&program) {
        assert!(
            matches!(error, VMError::UnknownSyscall(__actual_error_field) if __actual_error_field == (removed_number))
        );
        return;
    }
    vm.set_register(10, 123);
    assert!(
        matches!(vm.run(), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (removed_number))
    );
}
