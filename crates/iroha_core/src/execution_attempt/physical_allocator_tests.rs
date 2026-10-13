//! Original physical allocation causes across native block and Kura classifiers.

use super::*;
use crate::sumeragi::driver::traits::PublicationDeferral;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_allocation::{
    AllocationBudget, AllocatorRefusal, ChargedBuffer, ChargedBufferError,
    ChargedBufferFromChargeError, ChargedShared, PrepaidSharedError, SharedFromChargeError,
};
use iroha_data_model::block::{
    BlockSignatureCustodyError, PreparedSignatureBlockError, SharedBlockAdmissionError,
    SharedSignedBlock, commit_certificate::CertificateCustodyError,
};
use iroha_data_model::da::commitment::{DaCommitmentCustodyError, DaProofPolicyCustodyError};
use norito::core::{PreparedDecodeError, PreparedDecodeScopeError};
use std::alloc::Layout;

/// Include the classifier itself in the zero-allocation observation, then move
/// its exact original through Core, VM, artifact admission and publication.
fn transported(map: impl FnOnce() -> ExecutionDeferred) -> AllocatorRefusal {
    let mut retained = None;
    let allocations = allocations_during(|| {
        let original = map();
        assert_eq!(original.reason(), ExecutionDeferral::AllocationUnavailable);
        assert!(original.allocation_refusal().is_none());
        assert!(original.allocator_refusal().is_some());
        let vm = VMError::metered(91, original.into_vm_error());
        assert!(vm.fault_kind().is_none());
        assert!(vm.metered_gas().is_none());
        let artifact = ivm::ContractArtifactError::preparation("native block/Kura allocator", vm);
        assert!(artifact.is_local_deferral());
        let original = ExecutionDeferred::try_from_vm_error(artifact.into_vm_error()).unwrap();
        let publication = PublicationDeferral::Execution(original);
        assert!(publication.release_wait().is_none());
        assert!(publication.allocation_refusal().is_none());
        let PublicationDeferral::Execution(original) = publication else {
            unreachable!()
        };
        let VMError::AllocatorDeferred(original) = original.into_vm_error() else {
            panic!("exact physical allocator cause")
        };
        retained = Some(original);
    });
    assert_eq!(
        allocations, 0,
        "classifier and owner transport cannot allocate on refusal"
    );
    retained.unwrap()
}

fn prepared(error: PreparedSignatureBlockError) -> ExecutionDeferred {
    match prepared_signature_block_attempt_error::<()>(error, |_| {
        panic!("physical refusal cannot reject input")
    }) {
        ExecutionAttemptError::Deferred(original) => original,
        ExecutionAttemptError::Rejected(()) => panic!("unfinished physical allocation"),
    }
}

#[test]
fn shared_block_actual_shell_failure_preserves_original_and_retries_same_pool() {
    let layout = SharedSignedBlock::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let (result, denied) = refuse_one_layout_during(layout, || SharedSignedBlock::reserve(&budget));
    assert!(denied);
    let original = match result {
        Err(error) => error,
        Ok(_) => panic!("actual block shell denied"),
    };
    assert_eq!(budget.reserved_bytes(), 0);
    let retained = transported(|| original.into());
    assert_eq!(
        retained.shared_error(),
        Some(&PrepaidSharedError::Allocator {
            requested_bytes: layout.size()
        })
    );
    assert_eq!(
        retained.into_shared_error().unwrap(),
        PrepaidSharedError::Allocator {
            requested_bytes: layout.size()
        }
    );
    let retry = SharedSignedBlock::reserve(&budget).unwrap();
    assert_eq!(budget.reserved_bytes(), layout.size());
    drop(retry);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_buffer_failure_retains_bytes_through_storage_signature_and_kura_paths() {
    let layout = Layout::array::<u64>(19).unwrap();
    let budget = AllocationBudget::new(layout.size());
    for path in 0..3 {
        let (result, denied) =
            refuse_one_layout_during(layout, || ChargedBuffer::<u64>::new(19, &budget));
        assert!(denied);
        let original = match result {
            Err(error) => error,
            Ok(_) => panic!("actual buffer denied"),
        };
        assert_eq!(budget.reserved_bytes(), 0);
        let retained = transported(|| match path {
            0 => prepared(PreparedSignatureBlockError::Storage(original)),
            1 => prepared(PreparedSignatureBlockError::Decode(
                PreparedDecodeError::Destination(BlockSignatureCustodyError::Buffer(original)),
            )),
            2 => match kura_read_attempt_error::<()>(
                crate::kura::Error::NativeFrameAllocation(original),
                |_| panic!("Kura physical failure cannot be invalid bytes"),
            ) {
                ExecutionAttemptError::Deferred(original) => original,
                ExecutionAttemptError::Rejected(()) => panic!("unfinished Kura allocation"),
            },
            _ => unreachable!(),
        });
        assert!(
            matches!(retained.buffer_error(), Some(ChargedBufferError::Allocator { requested_bytes }) if *requested_bytes == layout.size())
        );
        assert!(
            matches!(retained.into_buffer_error().unwrap(), ChargedBufferError::Allocator { requested_bytes } if requested_bytes == layout.size())
        );
        drop(ChargedBuffer::<u64>::new(19, &budget).unwrap());
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn actual_prepaid_control_failure_survives_each_signature_scope_wrapper() {
    let layout = ChargedShared::<u64>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    for path in 0..3 {
        let mut reservation = budget.try_reserve(layout).unwrap();
        let (result, denied) = refuse_one_layout_during(layout, || {
            ChargedShared::from_reservation(71_u64, &mut reservation)
        });
        assert!(denied);
        let (value, original) = match result {
            Err(error) => error,
            Ok(_) => panic!("actual shared control denied"),
        };
        assert_eq!(value, 71);
        let retained = transported(|| {
            prepared(match path {
                0 => PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
                    BlockSignatureCustodyError::ControlAllocation(original),
                )),
                1 => PreparedSignatureBlockError::Scope(PreparedDecodeScopeError::Allocation(
                    original,
                )),
                2 => PreparedSignatureBlockError::Decode(PreparedDecodeError::Scope(
                    PreparedDecodeScopeError::Allocation(original),
                )),
                _ => unreachable!(),
            })
        });
        assert_eq!(
            retained.shared_error(),
            Some(&PrepaidSharedError::Allocator {
                requested_bytes: layout.size()
            })
        );
        assert_eq!(
            retained.into_shared_error().unwrap(),
            PrepaidSharedError::Allocator {
                requested_bytes: layout.size()
            }
        );
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut retry = budget.try_reserve(layout).unwrap();
        let shared = ChargedShared::from_reservation(value, &mut retry).unwrap();
        assert_eq!(*shared, 71);
        drop(shared);
        drop(retry);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn actual_from_charge_failures_preserve_layout_and_original_charge_for_all_three_children() {
    for child in 0..3 {
        for shared in [false, true] {
            let layout = if shared {
                ChargedShared::<[u64; 7]>::allocation_layout()
            } else {
                Layout::array::<u64>(7).unwrap()
            };
            let budget = AllocationBudget::new(layout.size());
            let charge = budget
                .try_reserve(layout)
                .unwrap()
                .try_split(layout)
                .unwrap();
            let (charge, error) = if shared {
                let (result, denied) = refuse_one_layout_during(layout, || {
                    ChargedShared::<[u64; 7]>::reserve_from_charge(charge)
                });
                assert!(denied);
                let (charge, original) = match result {
                    Err(error) => error,
                    Ok(_) => panic!("actual shared-from-charge denied"),
                };
                let error = match child {
                    0 => PreparedSignatureBlockError::Certificate(
                        CertificateCustodyError::Control(original),
                    ),
                    1 => PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Control(
                        original,
                    )),
                    2 => PreparedSignatureBlockError::Commitments(
                        DaCommitmentCustodyError::Control(original),
                    ),
                    _ => unreachable!(),
                };
                (charge, error)
            } else {
                let (result, denied) = refuse_one_layout_during(layout, || {
                    ChargedBuffer::<u64>::try_from_charge(7, charge)
                });
                assert!(denied);
                let (charge, original) = match result {
                    Err(error) => error,
                    Ok(_) => panic!("actual buffer-from-charge denied"),
                };
                let error = match child {
                    0 => PreparedSignatureBlockError::Certificate(CertificateCustodyError::Buffer(
                        original,
                    )),
                    1 => PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Buffer(
                        original,
                    )),
                    2 => PreparedSignatureBlockError::Commitments(
                        DaCommitmentCustodyError::Buffer(original),
                    ),
                    _ => unreachable!(),
                };
                (charge, error)
            };
            let retained = transported(|| prepared(error));
            assert!(charge.belongs_to(&budget));
            assert_eq!(charge.layout(), layout);
            assert_eq!(
                budget.reserved_bytes(),
                layout.size(),
                "transport cannot release separate original funding"
            );
            if shared {
                assert_eq!(
                    retained.shared_from_charge_error(),
                    Some(&SharedFromChargeError::Allocator { layout })
                );
                assert_eq!(
                    retained.into_shared_from_charge_error().unwrap(),
                    SharedFromChargeError::Allocator { layout }
                );
                let retry = match ChargedShared::<[u64; 7]>::reserve_from_charge(charge) {
                    Ok(shell) => shell,
                    Err(_) => panic!("same original charge retries"),
                };
                drop(retry.initialize([71; 7]));
            } else {
                assert_eq!(
                    retained.buffer_from_charge_error(),
                    Some(&ChargedBufferFromChargeError::Allocator { layout })
                );
                assert_eq!(
                    retained.into_buffer_from_charge_error().unwrap(),
                    ChargedBufferFromChargeError::Allocator { layout }
                );
                let retry = match ChargedBuffer::<u64>::try_from_charge(7, charge) {
                    Ok(buffer) => buffer,
                    Err(_) => panic!("same original charge retries"),
                };
                drop(retry);
            }
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn existing_reservation_and_invariant_classification_is_not_relabelled_as_allocator_failure() {
    let budget = AllocationBudget::new(0);
    let mut reservation = budget.try_reserve_bytes(0).unwrap();
    let (_, error) = match ChargedShared::from_reservation(71_u64, &mut reservation) {
        Err(error) => error,
        Ok(_) => panic!("actual insufficient reservation"),
    };
    let PrepaidSharedError::Reservation(insufficient) = error else {
        panic!("no physical allocator was reached")
    };
    let direct: ExecutionDeferred = SharedBlockAdmissionError::Allocation(error).into();
    assert_eq!(direct.reason(), ExecutionDeferral::ActiveMemoryCapacity);
    assert!(direct.allocator_refusal().is_none());
    assert!(direct.allocation_refusal().is_none());
    for error in [
        PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
            BlockSignatureCustodyError::ControlAllocation(PrepaidSharedError::Reservation(
                insufficient,
            )),
        )),
        PreparedSignatureBlockError::Scope(PreparedDecodeScopeError::Allocation(
            PrepaidSharedError::Reservation(insufficient),
        )),
        PreparedSignatureBlockError::Decode(PreparedDecodeError::Scope(
            PreparedDecodeScopeError::Allocation(PrepaidSharedError::Reservation(insufficient)),
        )),
        PreparedSignatureBlockError::Scope(PreparedDecodeScopeError::Reservation(insufficient)),
        PreparedSignatureBlockError::Decode(PreparedDecodeError::Scope(
            PreparedDecodeScopeError::Reservation(insufficient),
        )),
    ] {
        let ExecutionAttemptError::<()>::Deferred(original) =
            prepared_signature_block_attempt_error(error, |_| {
                panic!("unchanged reservation classification")
            })
        else {
            panic!("existing reservation remains local")
        };
        assert_eq!(original.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        assert!(original.allocator_refusal().is_none());
        assert!(original.allocation_refusal().is_none());
    }
    let expected = Layout::new::<u64>();
    let actual = Layout::new::<u8>();
    for error in [
        PreparedSignatureBlockError::SourceChanged,
        PreparedSignatureBlockError::Certificate(CertificateCustodyError::Buffer(
            ChargedBufferFromChargeError::DemandOverflow,
        )),
        PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Buffer(
            ChargedBufferFromChargeError::LayoutMismatch { expected, actual },
        )),
        PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Control(
            SharedFromChargeError::LayoutMismatch { expected, actual },
        )),
    ] {
        let expected = error.to_string();
        let ExecutionAttemptError::Rejected(actual) =
            prepared_signature_block_attempt_error(error, std::convert::identity)
        else {
            panic!("existing contextual invariant classification unchanged")
        };
        assert_eq!(actual, expected);
    }
}
