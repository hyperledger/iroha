//! Unknown syscalls must fail before gas debit or host mutation.
use ivm::{IVM, IVMHost, VMError, host::DefaultHost};
#[test]
fn default_host_unknown_syscalls_return_unknown() {
    for number in [
        0xAA, 0xAB, 0xAC, 0xB4, 0xAD, 0xAE, 0xAF, 0xBF, 0xDF, 0x01_0163, 0x01_0164, 0x01_0165,
    ] {
        let mut vm = IVM::new(1000);
        let mut host = DefaultHost::new();
        vm.set_register(10, 0x1111);
        vm.set_register(11, 0x2222);
        let registers_before = [vm.register(10), vm.register(11)];
        let heap_cursor_before = vm.memory.alloc(0).expect("read heap cursor");
        let gas_before = vm.remaining_gas();
        assert!(
            matches!(host.prepare_syscall(number, &vm), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (number))
        );
        match host.syscall(number, &mut vm) {
            Err(VMError::UnknownSyscall(actual)) => assert_eq!(actual, number),
            other => panic!("expected UnknownSyscall({number:#x}), got {other:?}"),
        }
        assert_eq!([vm.register(10), vm.register(11)], registers_before);
        assert_eq!(
            vm.memory
                .alloc(0)
                .expect("read heap cursor after rejection"),
            heap_cursor_before
        );
        assert_eq!(vm.remaining_gas(), gas_before);
    }
}
