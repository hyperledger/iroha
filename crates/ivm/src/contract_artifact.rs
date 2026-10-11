//! Native preparation adapter for the shared artifact-admission crate.
use crate::{
    SyscallPolicy,
    ivm::{
        decode_literal_table, prepare_instruction_stream, validate_indexed_literal_instructions,
    },
    ivm_cache::global_get,
    metadata::EmbeddedContractInterfaceV1,
    prepared::{PreparedContract, PreparedContractParts, PreparedControlFlow},
};
pub use ivm_artifact_admission::{
    ContractArtifactError, VerifiedContractArtifact, verify_contract_artifact,
    verify_contract_artifact_with_memory_budget,
};
use std::sync::Arc;
/// Prepare a validated self-describing contract for repeated VM loading.
///
/// Admission is delegated to [`ivm_artifact_admission`]. This module only constructs native cache
/// and execution structures after that shared policy has accepted the immutable artifact bytes.
pub fn prepare_contract(artifact: Arc<[u8]>) -> Result<PreparedContract, ContractArtifactError> {
    PreparedContract::prepare(artifact)
}
/// Prepare immutable instructions, runtime indexes and artifact bytes in the original State pool.
///
/// Funded operations stay outside process-global caches. The prepared shell,
/// entrypoint index and traversal scratch use that same pool; nested metadata
/// and analysis storage remain separate allocation obligations.
///
/// # Errors
/// Returns canonical admission errors or the original local allocation refusal.
pub fn prepare_contract_with_memory_budget(
    artifact: &[u8],
    budget: &iroha_allocation::AllocationBudget,
) -> Result<PreparedContract, ContractArtifactError> {
    let verified = verify_contract_artifact_with_memory_budget(artifact, budget)?;
    PreparedContract::prepare_shared_verified(artifact, verified, Some(budget))
}
/// A prepared compiler-produced Kotodama test-suite artifact.
///
/// This capability is the only value that unlocks the Kotodama test-syscall range: it can only be
/// obtained from [`prepare_koto_test_contract`], which admits test-harness artifacts exclusively,
/// and only [`crate::IVM::load_koto_test_harness`] consumes it. Production loaders never enable the
/// range, and production hosts still reject those syscalls.
#[derive(Clone)]
pub struct KotoTestHarnessContract(PreparedContract);

impl KotoTestHarnessContract {
    /// Borrow the underlying prepared contract (for hashes, entrypoint PCs and artifact bytes).
    ///
    /// Loading the borrowed contract through [`crate::IVM::load_prepared`] does not enable the
    /// Kotodama test-syscall range.
    #[inline]
    #[must_use]
    pub fn prepared(&self) -> &PreparedContract {
        &self.0
    }
}

/// Prepare a compiler-produced Kotodama test-suite artifact for local execution.
///
/// # Errors
///
/// Returns [`ContractArtifactError`] when the artifact is not an admissible Kotodama test-harness
/// image for `contract_interface` (production artifacts are rejected) or native preparation fails.
pub fn prepare_koto_test_contract(
    artifact: Arc<[u8]>,
    contract_interface: EmbeddedContractInterfaceV1,
) -> Result<KotoTestHarnessContract, ContractArtifactError> {
    PreparedContract::prepare_koto_test_harness(artifact, contract_interface)
        .map(KotoTestHarnessContract)
}
impl PreparedContract {
    /// Admit through the shared production verifier, then build native runtime indexes.
    pub fn prepare(artifact: Arc<[u8]>) -> Result<Self, ContractArtifactError> {
        let verified = ivm_artifact_admission::verify_contract_artifact(artifact.as_ref())?;
        Self::prepare_shared_verified(artifact.as_ref(), verified, None)
    }
    fn prepare_koto_test_harness(
        artifact: Arc<[u8]>,
        contract_interface: EmbeddedContractInterfaceV1,
    ) -> Result<Self, ContractArtifactError> {
        let verified = ivm_artifact_admission::verify_koto_test_artifact(
            artifact.as_ref(),
            contract_interface,
        )?;
        Self::prepare_shared_verified(artifact.as_ref(), verified, None)
    }
    fn prepare_shared_verified(
        artifact: &[u8],
        verified: VerifiedContractArtifact,
        budget: Option<&iroha_allocation::AllocationBudget>,
    ) -> Result<Self, ContractArtifactError> {
        // The verifier just admitted these same borrowed bytes. Carry its exact ranges through
        // native preparation instead of allocating and decoding the CNTR graph a second time.
        let decoded = decode_instruction_stream(artifact, verified.code_offset, budget)?;
        let instruction_region = artifact.get(verified.code_offset..).ok_or_else(|| {
            ContractArtifactError::invalid("executable stream offset exceeds artifact length")
        })?;
        let literal_table = decode_literal_table(
            artifact.as_ref(),
            verified.header_len,
            verified.literal_section(),
            SyscallPolicy::AbiV1,
            budget,
        )
        .map_err(|error| {
            ContractArtifactError::preparation(
                "literal index preparation after shared admission",
                error,
            )
        })?;
        validate_indexed_literal_instructions(decoded.as_ref(), literal_table.entries()).map_err(
            |error| {
                ContractArtifactError::preparation(
                    "literal instruction preparation after shared admission",
                    error,
                )
            },
        )?;
        let instruction_entry_pc = verified
            .code_offset
            .checked_sub(verified.header_len)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or_else(|| {
                ContractArtifactError::invalid("executable stream offset does not fit a VM address")
            })?;
        let prepared_program = prepare_instruction_stream(
            instruction_region,
            decoded.as_ref(),
            instruction_entry_pc,
            literal_table.entries(),
            budget,
        )
        .map_err(|error| ContractArtifactError::preparation("instruction preparation", error))?;
        let control_flow =
            PreparedControlFlow::from_decoded(decoded.as_ref(), budget).map_err(|error| {
                ContractArtifactError::preparation("control-flow preparation", error)
            })?;
        PreparedContract::from_parts(PreparedContractParts {
            // Take our own byte allocation; an input Arc may have unrelated owners
            // whose lifetimes cannot be governed by this preparation reservation.
            artifact: match budget {
                Some(budget) => {
                    crate::cache_memory::SharedAllocation::try_copy_from_slice_with_memory_budget(
                        artifact, budget,
                    )
                    .map_err(|error| {
                        ContractArtifactError::preparation("artifact backing", error)
                    })?
                }
                None => crate::cache_memory::SharedAllocation::try_from_iter(
                    artifact.iter().copied().map(Ok::<_, crate::VMError>),
                )
                .map_err(|error| ContractArtifactError::preparation("artifact backing", error))?,
            },
            metadata: verified.metadata,
            manifest: verified.manifest,
            header_len: verified.header_len,
            code_offset: verified.code_offset,
            code_hash: verified.code_hash,
            contract_interface: {
                let exclusively_owned = verified
                    .contract_interface
                    .entrypoints
                    .iter()
                    .all(|entry| entry.triggers.is_empty());
                crate::prepared::shared_metadata(verified.contract_interface, exclusively_owned)
            },
            literal_table,
            decoded,
            prepared_program,
            control_flow,
        }, budget)
        .map_err(|error| ContractArtifactError::preparation("contract indexing", error))
    }
}
fn decode_instruction_stream(
    artifact: &[u8],
    code_offset: usize,
    budget: Option<&iroha_allocation::AllocationBudget>,
) -> Result<crate::ivm_cache::DecodedStream, ContractArtifactError> {
    let instruction_region = artifact.get(code_offset..).ok_or_else(|| {
        ContractArtifactError::invalid("executable stream offset exceeds artifact length")
    })?;
    let decoded = match budget {
        Some(budget) => {
            crate::ivm_cache::IvmCache::decode_stream_with_memory_budget(instruction_region, budget)
        }
        None => global_get(instruction_region),
    };
    decoded.map_err(|error| {
        ContractArtifactError::preparation("instruction decode after shared admission", error)
    })
}

#[cfg(test)]
mod preparation_deferral_tests {
    use super::*;
    use crate::{VMError, error::ExecutionDeferral};
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn cold_native_preparation_defers_allocator_refusal_then_retries_same_artifact() {
        let artifact: Arc<[u8]> = kotodama_lang::compiler::Compiler::new()
            .compile_source(r#"seiyaku PreparationRefusal { permission Entry;  kotoage fn main() authorize(Entry) -> int { return 701; } }"#)
            .expect("compile an admitted first-release artifact")
            .into();
        let admitted = verify_contract_artifact(&artifact).expect("valid independent admission");
        let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
            capacity: 0,
            max_bytes: 0,
            max_decoded_ops: 0,
        });
        let error = crate::cache_memory::with_refused_shared_allocation_for_test(|| {
            prepare_contract(Arc::clone(&artifact))
        })
        .expect_err("cold native decode must expose local allocator refusal");
        let error = error.into_vm_error();
        assert_eq!(
            error,
            VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
        );
        assert_eq!(error.metered_gas(), None);
        let retried =
            prepare_contract(Arc::clone(&artifact)).expect("retry the same valid artifact");
        assert_eq!(retried.code_hash(), admitted.code_hash);
        assert_eq!(retried.artifact(), artifact.as_ref());
    }

    #[test]
    fn preparation_keeps_exact_pool_release_observation_through_error_conversion() {
        use iroha_allocation::release::ReleaseRegistration;
        let registration_bytes = ReleaseRegistration::allocation_layout().size();
        let budget = iroha_allocation::AllocationBudget::new(8 + registration_bytes);
        let mut registration = ReleaseRegistration::from_reservation(
            &mut budget
                .try_reserve(ReleaseRegistration::allocation_layout())
                .unwrap(),
        )
        .unwrap();
        assert!(registration.belongs_to(&budget));
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        let deferred = VMError::Metered {
            gas: 31,
            source: Box::new(VMError::AllocationDeferred(original.clone())),
        };
        let error =
            ContractArtifactError::preparation("prepared instructions", deferred).into_vm_error();
        assert_eq!(error, VMError::AllocationDeferred(original));
        assert_eq!(
            error.execution_deferral(),
            Some(ExecutionDeferral::ActiveMemoryCapacity)
        );
        assert_eq!(error.metered_gas(), None);
        let VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::Capacity {
            release,
            ..
        }) = error
        else {
            panic!("preparation must preserve the capacity owner's observation");
        };
        let mut wait = release.wait_for_release(&mut registration);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(Pin::new(&mut wait).poll(&mut cx), Poll::Pending);
        // A refund from another pool cannot make this failed attempt ready.
        let other = iroha_allocation::AllocationBudget::new(8);
        drop(other.try_reserve_bytes(8).unwrap());
        assert_eq!(Pin::new(&mut wait).poll(&mut cx), Poll::Pending);
        drop(occupied);
        assert_eq!(Pin::new(&mut wait).poll(&mut cx), Poll::Ready(()));
        drop(wait);
        assert_eq!(budget.reserved_bytes(), registration_bytes);
        assert!(budget.try_reserve_bytes(8).is_ok());
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[cfg(test)]
mod koto_test_harness_tests {
    use super::*;
    use crate::{IVM, IVMHost, VMError};
    use kotodama_lang::{
        compiler::{CompilerMode, CompilerOptions},
        session::{CompilerSession, TestCompileOutput, TestSourceUnit},
    };
    use std::any::Any;

    /// Host that accepts every syscall, so only the VM capability gate can refuse one.
    struct AcceptAllHost;
    impl IVMHost for AcceptAllHost {
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            Ok(0)
        }
        fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
            Ok(0)
        }
        fn allows_syscall(&self, _policy: SyscallPolicy, _number: u32) -> bool {
            true
        }
        fn as_any(&mut self) -> &mut dyn Any
        where
            Self: 'static,
        {
            self
        }
    }

    fn compile_suite() -> TestCompileOutput {
        let options = CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        };
        let target = TestSourceUnit {
            source_name: "harness_demo.ko".to_owned(),
            source: "seiyaku HarnessDemo { permission Test;  kotoage fn ping() authorize(Test) {} #[test] fn smoke() {} }"
                .to_owned(),
        };
        CompilerSession::new(options)
            .build_test_sources(&target, &[])
            .unwrap_or_else(|diagnostics| panic!("{}", diagnostics.render_human()))
    }

    fn koto_test_syscall_result(vm: &mut IVM) -> Result<(), VMError> {
        vm.execute_syscall(
            &mut AcceptAllHost,
            crate::syscalls::SYSCALL_KOTO_TEST_ACTOR_ACCOUNT,
        )
    }

    #[test]
    fn only_the_harness_capability_unlocks_koto_test_syscalls() {
        let outputs = compile_suite();
        let harness = prepare_koto_test_contract(
            Arc::from(outputs.suite.artifact.as_slice()),
            outputs.suite.contract_interface().clone(),
        )
        .unwrap_or_else(|error| panic!("test-harness artifact must prepare: {error}"));
        let unknown = Err(VMError::UnknownSyscall(
            crate::syscalls::SYSCALL_KOTO_TEST_ACTOR_ACCOUNT,
        ));

        let mut vm = IVM::new(u64::MAX);
        vm.load_koto_test_harness(&harness)
            .expect("harness contract loads with the test capability");
        assert_ne!(koto_test_syscall_result(&mut vm), unknown);

        let mut vm = IVM::new(u64::MAX);
        vm.load_prepared(harness.prepared())
            .expect("the borrowed prepared contract loads as an ordinary program");
        assert_eq!(koto_test_syscall_result(&mut vm), unknown);

        let runtime = outputs
            .runtime
            .expect("a target with a kotoage entrypoint has a production projection");
        prepare_contract(Arc::from(runtime.artifact.as_slice()))
            .unwrap_or_else(|error| panic!("production artifact must deploy: {error}"));
        assert!(
            prepare_koto_test_contract(
                Arc::from(runtime.artifact.as_slice()),
                runtime.contract_interface().clone(),
            )
            .is_err(),
            "a production artifact must never become a test-harness capability"
        );
    }
    #[test]
    fn retired_header_rejects_compiler_harness_and_contract_without_granting_capability() {
        let outputs = compile_suite();
        let runtime = outputs.runtime.as_ref().unwrap();
        let budget = iroha_allocation::AllocationBudget::new(16 * 1024 * 1024);
        let mut vm = IVM::try_new_with_memory_budget(100_000, &budget).unwrap();
        vm.set_register(7, 701);
        let before = (
            vm.pc(),
            vm.remaining_gas(),
            vm.code_hash(),
            budget.reserved_bytes(),
        );
        budget.set_limit_bytes(0);
        for output in [&outputs.suite, runtime] {
            assert_eq!(output.artifact[5], 1);
            let mut retired = output.artifact.clone();
            retired[5] = 0;
            let expected = VMError::UnsupportedProgramVersion { major: 1, minor: 0 };
            assert_eq!(IVM::validate_program(&retired), Err(expected.clone()));
            assert_eq!(vm.load_program(&retired), Err(expected));
            assert_eq!(
                (
                    vm.pc(),
                    vm.remaining_gas(),
                    vm.code_hash(),
                    budget.reserved_bytes()
                ),
                before
            );
            assert_eq!(vm.register(7), 701);
            let error = prepare_contract_with_memory_budget(&retired, &budget).unwrap_err();
            assert!(error.local_vm_error().is_none());
            assert!(error.to_string().contains("program version 1.0"), "{error}");
            let error =
                prepare_koto_test_contract(Arc::from(retired), output.contract_interface().clone())
                    .err()
                    .expect("retired harness cannot grant a capability");
            assert!(error.local_vm_error().is_none());
            assert!(error.to_string().contains("program version 1.0"), "{error}");
        }
        drop(vm);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[cfg(test)]
#[path = "contract_artifact/range_tests.rs"]
mod range_tests;
