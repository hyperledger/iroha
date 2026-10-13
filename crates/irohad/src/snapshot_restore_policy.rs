//! Snapshot startup classification preserves local failures and their retry owner.

use super::TryReadSnapshotError;

pub fn snapshot_read_error_is_recoverable(error: &TryReadSnapshotError) -> bool {
    // Recoverable snapshot loss still requires the caller's Strict mode and complete
    // genesis-backed prefix; node::prepare executes every original certified block.
    !matches!(
        error,
        TryReadSnapshotError::IO(_, _)
            | TryReadSnapshotError::PayloadAllocation(_)
            | TryReadSnapshotError::PayloadAllocatorFailure { .. }
            | TryReadSnapshotError::StateVmInitialization(_)
            | TryReadSnapshotError::StateRead(_)
            | TryReadSnapshotError::StateAdmission(_)
            | TryReadSnapshotError::StateExecutionDeferred(_)
            | TryReadSnapshotError::StateNativeSchedule(_)
            | TryReadSnapshotError::StateNativeLaneCustody(_)
            | TryReadSnapshotError::StateBeaconSession(_)
            | TryReadSnapshotError::ChainIdMismatch { .. }
            | TryReadSnapshotError::NetworkIdMismatch { .. }
            | TryReadSnapshotError::ZkConfigInstall(_)
            | TryReadSnapshotError::MismatchedHeight { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_failure_allows_empty_state_fallback;
    use iroha_allocation::{AllocationBudget, AllocationRefusal};
    use iroha_data_model::sumeragi_lanes::{
        CustodySignersAdmissionError, LaneSamplesAdmissionError, LaneStateAdmissionError,
    };
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn native_identity_mismatch_halts_but_execution_replay_requires_strict_mode() {
        let wrong_chain = TryReadSnapshotError::ChainIdMismatch {
            expected: "configured-native-chain".parse().unwrap(),
            actual: "foreign-native-chain".parse().unwrap(),
        };
        assert!(!snapshot_failure_allows_empty_state_fallback(
            &wrong_chain,
            false
        ));
        let replay = TryReadSnapshotError::NativeExecutionReplayRequired;
        assert!(snapshot_failure_allows_empty_state_fallback(&replay, false));
        assert!(!snapshot_failure_allows_empty_state_fallback(&replay, true));
        assert!(snapshot_failure_allows_empty_state_fallback(
            &TryReadSnapshotError::NotFound,
            false,
        ));
        assert!(!snapshot_failure_allows_empty_state_fallback(
            &TryReadSnapshotError::NotFound,
            true,
        ));
    }

    #[test]
    fn snapshot_local_refusal_never_authorizes_empty_state_fallback() {
        let budget = AllocationBudget::new(1);
        let _occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        for error in [
            TryReadSnapshotError::PayloadAllocation(refusal.clone()),
            TryReadSnapshotError::PayloadAllocation(AllocationRefusal::DemandOverflow),
            TryReadSnapshotError::PayloadAllocatorFailure { requested_bytes: 1 },
            TryReadSnapshotError::StateRead(iroha_core::state::StateViewError::Changed),
            TryReadSnapshotError::StateRead(iroha_core::state::StateViewError::Poisoned),
            TryReadSnapshotError::StateVmInitialization(ivm::VMError::AllocationDeferred(
                refusal.clone(),
            )),
            TryReadSnapshotError::StateVmInitialization(ivm::VMError::ExecutionDeferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable,
            )),
            TryReadSnapshotError::StateAdmission(iroha_core::state::StateAdmissionError::History(
                iroha_core::state::BlockHashAdmissionError::Capacity(refusal.clone()),
            )),
            TryReadSnapshotError::StateNativeSchedule(
                iroha_core::sumeragi::schedule::ScheduleError::Admission(refusal.clone()),
            ),
            TryReadSnapshotError::StateNativeSchedule(
                iroha_core::sumeragi::schedule::ScheduleError::Allocator { requested_bytes: 1 },
            ),
            TryReadSnapshotError::StateBeaconSession(
                iroha_core::beacon::GlobalThresholdBeaconSessionError::Admission(refusal.clone()),
            ),
            TryReadSnapshotError::StateBeaconSession(
                iroha_core::beacon::GlobalThresholdBeaconSessionError::DecodeResource(
                    norito::Error::AllocationFailed { bytes: 1 },
                ),
            ),
            TryReadSnapshotError::StateBeaconSession(
                iroha_core::beacon::GlobalThresholdBeaconSessionError::PlanChanged,
            ),
            TryReadSnapshotError::StateNativeLaneCustody(LaneStateAdmissionError::Signers(
                CustodySignersAdmissionError::ControlAdmission(refusal.clone()),
            )),
            TryReadSnapshotError::StateNativeLaneCustody(LaneStateAdmissionError::Samples(
                LaneSamplesAdmissionError::Admission(refusal.clone()),
            )),
            TryReadSnapshotError::StateNativeLaneCustody(LaneStateAdmissionError::Signers(
                CustodySignersAdmissionError::Invalid,
            )),
            TryReadSnapshotError::StateNativeLaneCustody(LaneStateAdmissionError::Samples(
                LaneSamplesAdmissionError::ForeignBudget,
            )),
            TryReadSnapshotError::StateExecutionDeferred(refusal.into()),
            TryReadSnapshotError::StateExecutionDeferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            ),
        ] {
            assert!(!snapshot_read_error_is_recoverable(&error));
            for emergency_fast in [false, true] {
                assert!(!snapshot_failure_allows_empty_state_fallback(
                    &error,
                    emergency_fast
                ));
            }
        }
    }

    #[test]
    fn classification_borrows_raw_failure_and_preserves_original_release_observation() {
        use iroha_allocation::release::ReleaseRegistration;
        for kind in 0..8 {
            let registration_bytes = ReleaseRegistration::allocation_layout().size();
            let budget = AllocationBudget::new(1 + registration_bytes);
            let mut prepaid = budget
                .try_reserve(ReleaseRegistration::allocation_layout())
                .unwrap();
            let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
            drop(prepaid);
            let occupied = budget.try_reserve_bytes(1).unwrap();
            let refusal = budget.try_reserve_bytes(1).unwrap_err();
            let error = match kind {
                0 => TryReadSnapshotError::PayloadAllocation(refusal),
                1 => TryReadSnapshotError::StateVmInitialization(ivm::VMError::AllocationDeferred(
                    refusal,
                )),
                2 => TryReadSnapshotError::StateAdmission(
                    iroha_core::state::StateAdmissionError::History(
                        iroha_core::state::BlockHashAdmissionError::Capacity(refusal),
                    ),
                ),
                3 => TryReadSnapshotError::StateExecutionDeferred(refusal.into()),
                4 => TryReadSnapshotError::StateNativeSchedule(
                    iroha_core::sumeragi::schedule::ScheduleError::Admission(refusal),
                ),
                5 => TryReadSnapshotError::StateBeaconSession(
                    iroha_core::beacon::GlobalThresholdBeaconSessionError::Admission(refusal),
                ),
                6 => {
                    TryReadSnapshotError::StateNativeLaneCustody(LaneStateAdmissionError::Signers(
                        CustodySignersAdmissionError::ControlAdmission(refusal),
                    ))
                }
                _ => TryReadSnapshotError::StateNativeLaneCustody(
                    LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Admission(refusal)),
                ),
            };
            assert!(!snapshot_failure_allows_empty_state_fallback(&error, false));
            let refusal = match &error {
                TryReadSnapshotError::PayloadAllocation(refusal)
                | TryReadSnapshotError::StateNativeLaneCustody(
                    LaneStateAdmissionError::Signers(
                        CustodySignersAdmissionError::ControlAdmission(refusal),
                    )
                    | LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Admission(refusal)),
                )
                | TryReadSnapshotError::StateBeaconSession(
                    iroha_core::beacon::GlobalThresholdBeaconSessionError::Admission(refusal),
                )
                | TryReadSnapshotError::StateNativeSchedule(
                    iroha_core::sumeragi::schedule::ScheduleError::Admission(refusal),
                )
                | TryReadSnapshotError::StateVmInitialization(ivm::VMError::AllocationDeferred(
                    refusal,
                ))
                | TryReadSnapshotError::StateAdmission(
                    iroha_core::state::StateAdmissionError::History(
                        iroha_core::state::BlockHashAdmissionError::Capacity(refusal),
                    ),
                ) => refusal,
                TryReadSnapshotError::StateExecutionDeferred(reason) => {
                    reason.allocation_refusal().unwrap()
                }
                _ => unreachable!("fixture retains a typed capacity failure"),
            };
            let AllocationRefusal::Capacity {
                requested_bytes,
                reserved_bytes,
                limit_bytes,
                release,
            } = refusal
            else {
                panic!("classification must preserve the raw original capacity refusal");
            };
            assert_eq!(
                (*requested_bytes, *reserved_bytes, *limit_bytes),
                (1, 1 + registration_bytes, 1 + registration_bytes)
            );
            let mut wait = pin!(release.clone().wait_for_release(&mut registration));
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
            let unrelated = AllocationBudget::new(1);
            drop(unrelated.try_reserve_bytes(1).unwrap());
            assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
            drop(occupied);
            assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
        }
    }

    #[test]
    fn snapshot_busy_reader_preserves_actual_publication_wait_without_empty_fallback() {
        use iroha_allocation::release::ReleaseRegistration;
        use iroha_core::state::StateViewError;
        let source = mv::storage::Storage::<u64, u64>::new();
        let journal = source
            .block()
            .try_detach(|_| Ok::<_, std::convert::Infallible>(()))
            .unwrap_or_else(|_| panic!("detach original publication"));
        let prepared = journal
            .try_prepare_publication(&source, |_, _| Ok::<_, std::convert::Infallible>(()))
            .unwrap_or_else(|_| panic!("hold original publication"));
        let Err(error) = source.try_committed_view_nonblocking() else {
            panic!("original reader must be busy");
        };
        let error = TryReadSnapshotError::StateRead(StateViewError::from(error));
        for emergency_fast in [false, true] {
            assert!(!snapshot_failure_allows_empty_state_fallback(
                &error,
                emergency_fast
            ));
        }
        let TryReadSnapshotError::StateRead(StateViewError::Busy(release)) = &error else {
            panic!("classification preserves actual original release");
        };
        let budget = AllocationBudget::new(ReleaseRegistration::allocation_layout().size());
        let mut prepaid = budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let mut pending = pin!(release.clone().wait_for_release(&mut registration));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(pending.as_mut().poll(&mut context), Poll::Pending);
        let foreign = mv::storage::Storage::<u64, u64>::new();
        foreign.block().commit();
        assert_eq!(pending.as_mut().poll(&mut context), Poll::Pending);
        drop(prepared);
        assert_eq!(pending.as_mut().poll(&mut context), Poll::Ready(()));
        assert!(source.try_committed_view_nonblocking().is_ok());
    }
}
