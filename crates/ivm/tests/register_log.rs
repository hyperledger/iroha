//! Retained diagnostic trace and execution behavior controls.
use std::any::Any;

use ivm::{IVM, IVMHost, TraceMode, VMError, encoding, instruction};
mod common;
use common::assemble_zk;
#[test]
fn test_register_events_logged() {
    // Program: store 0x11 at heap, load it back
    let store = encoding::wide::encode_store(instruction::wide::memory::STORE64, 1, 2, 0);
    let load = encoding::wide::encode_load(instruction::wide::memory::LOAD64, 3, 1, 0);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&store.to_le_bytes());
    bytes.extend_from_slice(&load.to_le_bytes());
    bytes.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let prog = assemble_zk(&bytes, 8);
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, ivm::Memory::HEAP_START);
    vm.set_register(2, 0x11);
    vm.load_program(&prog).unwrap();
    vm.set_zk_trace_enabled(true);
    vm.run().unwrap();
    let snapshot = common::diagnostic_snapshot(&vm);
    assert_ne!(snapshot.register_event_count(), 0);
    for event in snapshot.register_events() {
        assert!(!event.path.is_empty());
        assert_ne!(*event.root, [0u8; 32]);
    }
    // Step log should match cycle count
    let steps = vm.step_log();
    assert_eq!(steps.len() as u64, vm.get_cycle_count());
}

#[test]
fn replacing_vm_during_traced_host_callback_fails_closed() {
    struct ReplacingHost {
        retained_vm: Option<IVM>,
    }

    impl IVMHost for ReplacingHost {
        fn prepare_syscall(&self, _number: u32, vm: &IVM) -> Result<u64, VMError> {
            let _ = vm.register(1);
            let snapshot = common::diagnostic_snapshot(vm);
            let content_digest = |snapshot: &ivm::zk::DiagnosticTraceSnapshot| -> [u8; 32] {
                use sha2::Digest;
                let mut digest = sha2::Sha256::new();
                digest.update(snapshot.register_event_count().to_le_bytes());
                for event in snapshot.register_events() {
                    digest.update([u8::from(event.written)]);
                    digest.update(event.index.to_le_bytes());
                    digest.update(event.value.to_le_bytes());
                    digest.update([u8::from(event.tag)]);
                    digest.update(event.path.len().to_le_bytes());
                    for sibling in event.path {
                        digest.update(sibling);
                    }
                    digest.update(event.root);
                }
                digest.finalize().into()
            };
            let expected = content_digest(&snapshot);
            for index in 1..=64 {
                let _ = vm.register((index % 8) + 1);
            }
            assert!(
                content_digest(&snapshot) == expected,
                "register-log snapshots must not alias the active logger"
            );
            Ok(0)
        }

        fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            let mut code = Vec::new();
            code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
            code.extend_from_slice(
                &encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 7, 0, 9)
                    .to_le_bytes(),
            );
            code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
            let mut replacement = IVM::new(u64::MAX);
            replacement.load_code(&code)?;
            replacement
                .set_zk_mode(true)
                .expect("private lifecycle cleanup succeeds");
            replacement.set_zk_trace_enabled(true);
            replacement.set_max_cycles(8);
            self.retained_vm = Some(std::mem::replace(vm, replacement));
            vm.set_zk_trace_enabled(false);
            vm.set_register(6, 0xC0FFEE);
            Ok(0)
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    let syscall = ivm::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS;
    let mut code = Vec::new();
    code.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = assemble_zk(&code, 8);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("load ZK syscall program");
    vm.set_zk_trace_enabled(true);
    let mut host = ReplacingHost { retained_vm: None };

    assert!(matches!(
        vm.run_with_host(&mut host),
        Err(VMError::PrivacyViolation)
    ));

    assert_eq!(vm.register(6), 0xC0FFEE);
    assert_eq!(vm.register(7), 0);
    assert!(
        !vm.zk_trace_enabled(),
        "callback update becomes the next invocation's trace policy"
    );
    assert!(
        common::diagnostic_snapshot(&vm).register_event_count() == 0,
        "a rejected replacement must not inherit the invocation log"
    );
    let retained_vm = host
        .retained_vm
        .as_mut()
        .expect("callback retains the replaced VM");
    assert!(
        common::diagnostic_snapshot(&retained_vm).register_event_count() == 0,
        "a retained detached log must be scrubbed before isolation is dropped"
    );
    assert_eq!(
        retained_vm.execution_summary().register_log_len,
        0,
        "post-failure diagnostics must not repopulate the retained invocation log"
    );
}

#[test]
fn moved_detached_vm_cannot_adopt_the_outer_scratch_log() {
    struct NoopHost;

    impl IVMHost for NoopHost {
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            Ok(0)
        }

        fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
            Ok(0)
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    struct MovingHost {
        retained_vm: Option<IVM>,
        nested_result: Option<Result<(), VMError>>,
    }

    impl IVMHost for MovingHost {
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            Ok(0)
        }

        fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            let mut replacement = IVM::new(u64::MAX);
            replacement.load_code(&encoding::wide::encode_halt().to_le_bytes())?;
            replacement
                .set_zk_mode(true)
                .expect("private lifecycle cleanup succeeds");
            replacement.set_zk_trace_enabled(true);
            replacement.set_max_cycles(8);
            let mut retained_vm = std::mem::replace(vm, replacement);
            self.nested_result = Some(retained_vm.run_with_host(&mut NoopHost));
            self.retained_vm = Some(retained_vm);
            Ok(0)
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    let syscall = ivm::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS;
    let mut code = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 5, 0, 1)
        .to_le_bytes()
        .to_vec();
    code.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = assemble_zk(&code, 8);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("load outer ZK program");
    vm.set_zk_trace_enabled(true);
    let mut host = MovingHost {
        retained_vm: None,
        nested_result: None,
    };

    assert!(matches!(
        vm.run_with_host(&mut host),
        Err(VMError::PrivacyViolation)
    ));
    assert!(
        matches!(
            (&(host.nested_result), &(VMError::PrivacyViolation)),
            (
                Some(Err(VMError::PrivacyViolation)),
                VMError::PrivacyViolation
            )
        ),
        "a moved VM must reject reuse while it carries outer callback ownership"
    );
    let retained_vm = host.retained_vm.as_mut().expect("callback retains old VM");
    assert!(common::diagnostic_snapshot(&retained_vm).register_event_count() == 0);
    assert_eq!(retained_vm.execution_summary().register_log_len, 0);
}

#[test]
fn destructive_host_callback_lifecycle_changes_fail_closed() {
    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        Reset,
        ReloadSameProgram,
        ZkModeRoundTrip,
        MaxCyclesRoundTrip,
    }

    struct MutatingHost {
        mutation: Mutation,
        program: Vec<u8>,
    }

    impl IVMHost for MutatingHost {
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            Ok(0)
        }

        fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            assert!(!common::diagnostic_snapshot(&vm).states().is_empty());
            assert!(!vm.step_log().is_empty());
            assert!(!vm.constraints().is_empty());
            assert!(!vm.delta_register_trace().is_empty());

            match self.mutation {
                Mutation::Reset => vm.reset()?,
                Mutation::ReloadSameProgram => vm.load_program(&self.program)?,
                Mutation::ZkModeRoundTrip => {
                    vm.set_zk_mode(false)?;
                    vm.set_zk_mode(true)?;
                }
                Mutation::MaxCyclesRoundTrip => {
                    vm.set_max_cycles(0);
                    vm.set_max_cycles(8);
                }
            }
            Ok(0)
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    let syscall = ivm::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS;
    let mut code = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 5, 0, 1)
        .to_le_bytes()
        .to_vec();
    code.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::zk::ASSERT, 0, 0, 0).to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = assemble_zk(&code, 8);

    for mutation in [
        Mutation::Reset,
        Mutation::ReloadSameProgram,
        Mutation::ZkModeRoundTrip,
        Mutation::MaxCyclesRoundTrip,
    ] {
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program).expect("load ZK syscall program");
        vm.set_zk_trace_enabled(true);
        vm.set_trace_mode(TraceMode::DeltaRegisters);
        let mut host = MutatingHost {
            mutation,
            program: program.clone(),
        };

        assert!(
            matches!(vm.run_with_host(&mut host), Err(VMError::PrivacyViolation)),
            "{mutation:?} must invalidate the active proof"
        );
        assert!(
            common::diagnostic_snapshot(&vm).register_event_count() == 0,
            "{mutation:?}"
        );
        assert!(
            common::diagnostic_snapshot(&vm).states().is_empty(),
            "{mutation:?}"
        );
        assert!(vm.step_log().is_empty(), "{mutation:?}");
        assert!(vm.constraints().is_empty(), "{mutation:?}");
        assert!(vm.memory_log().is_empty(), "{mutation:?}");
        assert!(vm.trace_pcs().is_empty(), "{mutation:?}");
        assert!(vm.delta_register_trace().is_empty(), "{mutation:?}");
    }
}

#[test]
fn panicking_host_callbacks_scrub_detached_proof_state() {
    #[derive(Clone, Copy, Debug)]
    enum PanicPhase {
        AllowsSyscall,
        Prepare,
        Syscall,
    }

    struct PanickingHost(PanicPhase);

    impl IVMHost for PanickingHost {
        fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
            if matches!(self.0, PanicPhase::AllowsSyscall) {
                panic!("intentional allows_syscall panic");
            }
            ivm::syscalls::is_syscall_allowed(policy, number)
        }

        fn prepare_syscall(&self, _number: u32, vm: &IVM) -> Result<u64, VMError> {
            if matches!(self.0, PanicPhase::Prepare) {
                assert!(!vm.step_log().is_empty());
                assert!(!vm.constraints().is_empty());
                panic!("intentional prepare panic");
            }
            Ok(0)
        }

        fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            assert!(!vm.step_log().is_empty());
            assert!(!vm.constraints().is_empty());
            panic!("intentional syscall panic");
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    let syscall = ivm::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS;
    let mut code = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 5, 0, 1)
        .to_le_bytes()
        .to_vec();
    code.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::zk::ASSERT, 0, 0, 0).to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = assemble_zk(&code, 8);

    for phase in [
        PanicPhase::AllowsSyscall,
        PanicPhase::Prepare,
        PanicPhase::Syscall,
    ] {
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program).expect("load ZK syscall program");
        vm.set_zk_trace_enabled(true);
        vm.set_trace_mode(TraceMode::DeltaRegisters);
        let mut host = PanickingHost(phase);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = vm.run_with_host(&mut host);
        }));
        assert!(panic.is_err(), "{phase:?} panic must propagate");
        assert!(
            common::diagnostic_snapshot(&vm).register_event_count() == 0,
            "{phase:?}"
        );
        assert!(
            common::diagnostic_snapshot(&vm).states().is_empty(),
            "{phase:?}"
        );
        assert!(vm.step_log().is_empty(), "{phase:?}");
        assert!(vm.constraints().is_empty(), "{phase:?}");
        assert!(vm.memory_log().is_empty(), "{phase:?}");
        assert!(vm.trace_pcs().is_empty(), "{phase:?}");
        assert!(vm.delta_register_trace().is_empty(), "{phase:?}");

        // A stale detachment marker must not suppress out-of-run cleanup.
        vm.set_zk_trace_enabled(false);
        assert!(
            common::diagnostic_snapshot(&vm).register_event_count() == 0,
            "{phase:?}"
        );
    }
}

#[test]
fn nested_untraced_vm_masks_the_outer_register_logger() {
    struct NestedHost {
        policy_probe_vm: std::cell::RefCell<IVM>,
    }

    impl IVMHost for NestedHost {
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            Ok(0)
        }

        fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            let sentinel = 0x5A_u64;
            let foreign_secret = 0xA11C_E5EC_12E7_u64;
            let code = encoding::wide::encode_ri(
                instruction::wide::arithmetic::ADDI,
                7,
                0,
                sentinel as i8,
            )
            .to_le_bytes()
            .to_vec();
            let mut nested = IVM::new(u64::MAX);
            nested.load_code(&code)?;
            nested.set_register(8, foreign_secret);
            assert!(matches!(nested.run(), Err(VMError::MissingHalt)));
            vm.set_register(9, 0xC011_AB1E);
            vm.set_zk_trace_enabled(false);
            Ok(0)
        }

        fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
            self.policy_probe_vm
                .borrow_mut()
                .set_register(10, 0xA110_05CA_11AB1E);
            ivm::syscalls::is_syscall_allowed(policy, number)
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    let syscall = ivm::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS;
    let mut code = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 5, 0, 1)
        .to_le_bytes()
        .to_vec();
    code.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = assemble_zk(&code, 8);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("load outer ZK program");
    vm.set_zk_trace_enabled(true);
    let mut host = NestedHost {
        policy_probe_vm: std::cell::RefCell::new(IVM::new(u64::MAX)),
    };
    vm.run_with_host(&mut host)
        .expect("nested untraced execution succeeds");

    assert!(
        !common::diagnostic_snapshot(&vm)
            .register_events()
            .any(|event| event.written && event.index == 7 && event.value == 0x5A)
    );
    assert!(
        !common::diagnostic_snapshot(&vm)
            .register_events()
            .any(|event| event.written && event.index == 10 && event.value == 0xA110_05CA_11AB1E)
    );
    assert!(
        !common::diagnostic_snapshot(&vm)
            .register_events()
            .any(|event| event.written && event.index == 8 && event.value == 0xA11C_E5EC_12E7)
    );
    assert!(
        common::diagnostic_snapshot(&vm)
            .register_events()
            .any(|event| event.written && event.index == 9 && event.value == 0xC011_AB1E)
    );
    assert_eq!(
        vm.step_log().len() as u64,
        vm.get_cycle_count(),
        "callback trace toggle must not truncate the active invocation"
    );

    assert!(matches!(vm.run(), Err(VMError::MissingHalt)));
    assert!(
        common::diagnostic_snapshot(&vm).register_event_count() == 0,
        "an untraced invocation must clear the preceding register log"
    );
    assert!(common::diagnostic_snapshot(&vm).states().is_empty());
    assert!(vm.step_log().is_empty());
}
