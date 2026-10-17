//! Shared artifact fuzz assertions with explicit local-refusal custody.

use std::sync::Arc;

use ivm::{
    ContractArtifactError, ProgramMetadata, VMError, VerifiedContractArtifact, prepare_contract,
    verify_contract_artifact,
};
use libfuzzer_sys::Corpus;

#[derive(Debug)]
enum CompletedRejection {
    Invalid(String),
    AbiHashMismatch {
        diagnostic: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

fn completed_rejection(
    error: ContractArtifactError,
) -> Result<CompletedRejection, ContractArtifactError> {
    if error.is_local_deferral() {
        return Err(error);
    }
    let diagnostic = error.to_string();
    Ok(match error.into_vm_error() {
        VMError::InvalidMetadata => CompletedRejection::Invalid(diagnostic),
        VMError::ArtifactAbiHashMismatch { expected, actual } => {
            CompletedRejection::AbiHashMismatch {
                diagnostic,
                expected,
                actual,
            }
        }
        _ => panic!("completed artifact rejection exported a non-admission outcome"),
    })
}

fn completed_outcome<T>(
    outcome: Result<T, ContractArtifactError>,
) -> Result<Result<T, CompletedRejection>, ContractArtifactError> {
    match outcome {
        Ok(value) => Ok(Ok(value)),
        Err(error) => completed_rejection(error).map(Err),
    }
}

fn assert_rejections_equal(first: &CompletedRejection, second: &CompletedRejection) {
    match (first, second) {
        (CompletedRejection::Invalid(first), CompletedRejection::Invalid(second)) => {
            assert_eq!(first, second, "completed artifact rejections differ");
        }
        (
            CompletedRejection::AbiHashMismatch {
                diagnostic: first,
                expected: first_expected,
                actual: first_actual,
            },
            CompletedRejection::AbiHashMismatch {
                diagnostic: second,
                expected: second_expected,
                actual: second_actual,
            },
        ) => {
            assert_eq!(first, second, "completed artifact rejections differ");
            assert_eq!(
                first_expected, second_expected,
                "completed artifact rejections differ"
            );
            assert_eq!(
                first_actual, second_actual,
                "completed artifact rejections differ"
            );
        }
        _ => panic!("completed artifact rejections differ in kind"),
    }
}

fn export_local_refusal(error: ContractArtifactError) -> VMError {
    assert!(
        error.is_local_deferral(),
        "only local refusal makes an iteration inconclusive"
    );
    let original = match error.try_into_local_vm_error() {
        Ok(original) => original,
        Err(_) => panic!("local artifact refusal did not export its original owner"),
    };
    assert!(original.execution_deferral().is_some());
    assert!(original.metered_gas().is_none());
    assert!(original.fault_kind().is_none());
    original
}

/// Retain only conclusively checked inputs in the fuzzer's corpus.
pub fn finish_iteration(outcome: Result<(), ContractArtifactError>) -> Corpus {
    match outcome {
        Ok(()) => Corpus::Keep,
        Err(error) => {
            let _original = export_local_refusal(error);
            Corpus::Reject
        }
    }
}

fn metadata_tuple(metadata: &ProgramMetadata) -> (u8, u8, u8, u8, u64, u8) {
    (
        metadata.version_major,
        metadata.version_minor,
        metadata.mode,
        metadata.vector_length,
        metadata.max_cycles,
        metadata.abi_version,
    )
}

fn assert_verified_equal(first: &VerifiedContractArtifact, second: &VerifiedContractArtifact) {
    assert_eq!(
        metadata_tuple(&first.metadata),
        metadata_tuple(&second.metadata)
    );
    assert_eq!(first.header_len, second.header_len);
    assert_eq!(first.code_offset, second.code_offset);
    assert_eq!(first.code_hash, second.code_hash);
    assert_eq!(first.abi_hash, second.abi_hash);
    assert_eq!(first.contract_interface, second.contract_interface);
    assert_eq!(first.manifest, second.manifest);
}

/// Compare completed admission and preparation while returning any local owner unchanged.
pub fn exercise_admission(artifact: &[u8]) -> Result<(), ContractArtifactError> {
    let first = verify_contract_artifact(artifact);
    let second = verify_contract_artifact(artifact);

    match (completed_outcome(first)?, completed_outcome(second)?) {
        (Err(first_error), Err(second_error)) => {
            assert_rejections_equal(&first_error, &second_error);
            match completed_outcome(prepare_contract(Arc::<[u8]>::from(artifact)))? {
                Err(preparation_error) => assert_rejections_equal(&preparation_error, &first_error),
                Ok(_) => panic!("native preparation accepted a rejected artifact"),
            }
        }
        (Ok(first_verified), Ok(second_verified)) => {
            assert_verified_equal(&first_verified, &second_verified);
            let prepared = completed_outcome(prepare_contract(Arc::<[u8]>::from(artifact)))?
                .expect("production preparation must accept a verified artifact");
            assert_eq!(prepared.artifact(), artifact);
            assert_eq!(
                metadata_tuple(prepared.metadata()),
                metadata_tuple(&first_verified.metadata)
            );
            assert_eq!(prepared.header_len(), first_verified.header_len);
            assert_eq!(prepared.code_offset(), first_verified.code_offset);
            assert_eq!(prepared.code_hash(), first_verified.code_hash);
            assert_eq!(
                prepared.contract_interface(),
                &first_verified.contract_interface
            );
            assert_eq!(prepared.manifest(), &first_verified.manifest);
        }
        (first, second) => panic!(
            "artifact admission is nondeterministic: first={}, second={}",
            first.is_ok(),
            second.is_ok()
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
    use ivm_abi::error::ExecutionDeferral;

    use super::*;

    #[test]
    fn identical_completed_rejections_keep_the_exact_diagnostic() {
        let first = completed_rejection(ContractArtifactError::invalid("fixture A")).unwrap();
        let second = completed_rejection(ContractArtifactError::invalid("fixture A")).unwrap();
        assert!(matches!(
            &first,
            CompletedRejection::Invalid(message) if message == "invalid contract artifact: fixture A"
        ));
        assert_rejections_equal(&first, &second);
    }

    #[test]
    #[should_panic(expected = "completed artifact rejections differ")]
    fn different_invalid_diagnostics_fail_comparison() {
        let first = completed_rejection(ContractArtifactError::invalid("fixture A")).unwrap();
        let second = completed_rejection(ContractArtifactError::invalid("fixture B")).unwrap();
        assert_rejections_equal(&first, &second);
    }

    #[test]
    fn identical_abi_rejections_retain_both_hash_arrays() {
        let first = completed_rejection(ContractArtifactError::abi_hash_mismatch([1; 32], [2; 32]))
            .unwrap();
        let second =
            completed_rejection(ContractArtifactError::abi_hash_mismatch([1; 32], [2; 32]))
                .unwrap();
        assert!(
            matches!(&first, CompletedRejection::AbiHashMismatch { expected, actual, .. }
            if *expected == [1; 32] && *actual == [2; 32])
        );
        assert_rejections_equal(&first, &second);
    }

    #[test]
    #[should_panic(expected = "completed artifact rejections differ")]
    fn different_expected_abi_hash_fails_comparison() {
        let first = completed_rejection(ContractArtifactError::abi_hash_mismatch([1; 32], [2; 32]))
            .unwrap();
        let second =
            completed_rejection(ContractArtifactError::abi_hash_mismatch([3; 32], [2; 32]))
                .unwrap();
        assert_rejections_equal(&first, &second);
    }

    #[test]
    #[should_panic(expected = "completed artifact rejections differ")]
    fn different_actual_abi_hash_fails_comparison() {
        let first = completed_rejection(ContractArtifactError::abi_hash_mismatch([1; 32], [2; 32]))
            .unwrap();
        let second =
            completed_rejection(ContractArtifactError::abi_hash_mismatch([1; 32], [3; 32]))
                .unwrap();
        assert_rejections_equal(&first, &second);
    }

    fn capacity_refusal(budget: &AllocationBudget) -> AllocationRefusal {
        match budget.try_reserve_bytes(1) {
            Err(refusal @ AllocationRefusal::Capacity { .. }) => refusal,
            _ => panic!("fixture must refuse occupied original-pool capacity"),
        }
    }

    #[test]
    fn local_refusal_retains_original_release_observation_and_credits() {
        let budget = AllocationBudget::new(8);
        let held = budget.try_reserve_bytes(8).unwrap();
        let refusal = capacity_refusal(&budget);
        // A second real probe records the same pool and pre-refund epoch without
        // cloning the first refusal owner or manufacturing a release source.
        let AllocationRefusal::Capacity {
            release: expected_release,
            ..
        } = capacity_refusal(&budget)
        else {
            unreachable!("capacity_refusal checks the variant");
        };
        let error = ContractArtifactError::preparation(
            "fuzz custody fixture",
            VMError::AllocationDeferred(refusal),
        );
        let returned = completed_outcome::<()>(Err(error)).unwrap_err();
        assert!(returned.is_local_deferral());
        assert_eq!(budget.reserved_bytes(), 8);
        let original = export_local_refusal(returned);
        let VMError::AllocationDeferred(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = original
        else {
            panic!("local transport must return the exact allocation refusal variant");
        };
        assert_eq!((requested_bytes, reserved_bytes, limit_bytes), (1, 8, 8));
        assert_eq!(release, expected_release);
        assert_eq!(budget.reserved_bytes(), 8);

        let waiter_layout = ReleaseRegistration::allocation_layout();
        let waiter_budget = AllocationBudget::new(waiter_layout.size());
        let mut waiter_reservation = waiter_budget.try_reserve(waiter_layout).unwrap();
        let mut registration =
            ReleaseRegistration::from_reservation(&mut waiter_reservation).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Pending
        );
        assert_eq!(budget.reserved_bytes(), 8);
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Ready(())
        );
        drop(registration);
        drop(waiter_reservation);
        assert_eq!(waiter_budget.reserved_bytes(), 0);
    }

    #[test]
    fn completed_input_is_kept_and_only_local_refusal_is_inconclusive() {
        assert!(matches!(finish_iteration(Ok(())), Corpus::Keep));
        let local = ContractArtifactError::preparation(
            "local fixture",
            VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity),
        );
        assert!(matches!(finish_iteration(Err(local)), Corpus::Reject));
    }

    #[test]
    #[should_panic(expected = "only local refusal makes an iteration inconclusive")]
    fn ordinary_invalid_input_cannot_be_silently_rejected_as_inconclusive() {
        finish_iteration(Err(ContractArtifactError::invalid("ordinary rejection")));
    }

    #[test]
    fn native_admission_and_preparation_preserve_completed_outcomes() {
        const ARTIFACT: &[u8] = include_bytes!("../../kotodama_lang/src/samples/zk_vote_ballot.to");
        assert!(exercise_admission(b"invalid artifact").is_ok());
        verify_contract_artifact(ARTIFACT).expect("production fuzz seed must be valid");
        assert!(exercise_admission(ARTIFACT).is_ok());
    }
}
