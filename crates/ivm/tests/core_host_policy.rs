//! CoreHost AXT V1 policy and retired-syscall controls.

use iroha_data_model::nexus::{AxtPolicySnapshot, AxtPolicySnapshotValidationError};
use ivm::{CoreHost, IVM, IVMHost, VMError};

#[test]
fn core_host_rejects_noncanonical_policy_snapshot() {
    let snapshot = AxtPolicySnapshot {
        version: 1,
        entries: Vec::new(),
    };
    assert!(matches!(
        CoreHost::new().with_axt_policy_snapshot(&snapshot),
        Err(AxtPolicySnapshotValidationError::VersionMismatch {
            expected: 0,
            actual: 1,
        })
    ));
}

#[test]
fn core_host_rejects_retired_handle_syscall_without_effects() {
    let mut vm = IVM::new(1_000_000);
    vm.set_register(10, u64::MAX);
    let before = vm.remaining_gas();
    let mut host = CoreHost::new();
    assert!(
        matches!(host.syscall(0xB4, &mut vm), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (0xB4))
    );
    assert_eq!(vm.remaining_gas(), before);
}
