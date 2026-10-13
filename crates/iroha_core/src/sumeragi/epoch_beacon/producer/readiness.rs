//! Generation-bound diagnostics from the sole native pulse custodian.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedShared, PrepaidSharedError};
use iroha_data_model::sumeragi::BeaconHorizonStatusV1;
use std::{
    sync::{Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
    generation: u64,
    height: u64,
    applied: u64,
    horizon: BeaconHorizonStatusV1,
    ready: bool,
}

/// Shared fixed-size report: no key, proof, transcript or mutable signing API escapes.
#[derive(Clone, Debug)]
pub(crate) struct NativeBeaconReadiness(ChargedShared<Mutex<Option<Observation>>>);
/// The original failed readiness-control admission, without a fabricated release source.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeBeaconReadinessError {
    /// Exact demand against the original State execution pool.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The prepaid control could not be physically constructed.
    #[error(transparent)]
    Allocator(PrepaidSharedError),
    /// The existing producer already retains its original reporting control.
    #[error("native beacon readiness owner is already attached")]
    AlreadyAttached,
}
impl NativeBeaconReadiness {
    pub(super) fn new(budget: &AllocationBudget) -> Result<Self, NativeBeaconReadinessError> {
        let mut reservation = budget
            .try_reserve(ChargedShared::<Mutex<Option<Observation>>>::allocation_layout())
            .map_err(NativeBeaconReadinessError::Admission)?;
        ChargedShared::from_reservation(Mutex::new(None), &mut reservation)
            .map(Self)
            .map_err(|(_, error)| NativeBeaconReadinessError::Allocator(error))
    }

    /// Withdraw the previous result and exclude readers until this same probe finishes.
    /// Dropping the guard before publishing a validated observation leaves readiness absent.
    fn begin_refresh(&self) -> Result<MutexGuard<'_, Option<Observation>>, NativeBeaconError> {
        let mut observation = self
            .0
            .lock()
            .map_err(|_| NativeBeaconError::Source("readiness lock poisoned".into()))?;
        *observation = None;
        Ok(observation)
    }

    /// Read only an immediately available observation; a refresh never blocks this diagnostic.
    /// A concurrent publication or a different core height invalidates the entire observation.
    pub(crate) fn read(
        &self,
        generation: u64,
        height: u64,
        applied: u64,
    ) -> Option<(BeaconHorizonStatusV1, bool)> {
        let observed = *self.0.try_lock().ok()?;
        Self::at_cut(observed, generation, height, applied)
    }

    /// Wait for one validated observation under the caller's original monotonic deadline.
    /// Expiry or poisoning returns no observation and never cancels the authentic probe.
    /// Call this bounded blocking path only from a blocking worker.
    pub(crate) fn read_until(
        &self,
        generation: u64,
        height: u64,
        applied: u64,
        deadline: Instant,
    ) -> Option<(BeaconHorizonStatusV1, bool)> {
        let observed = loop {
            if Instant::now() >= deadline {
                return None;
            }
            match self.0.try_lock() {
                Ok(observation) => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    break *observation;
                }
                Err(TryLockError::Poisoned(_)) => return None,
                Err(TryLockError::WouldBlock) => {
                    let remaining = deadline.checked_duration_since(Instant::now())?;
                    std::thread::park_timeout(remaining.min(Duration::from_millis(1)));
                }
            }
        };
        if Instant::now() >= deadline {
            return None;
        }
        Self::at_cut(observed, generation, height, applied)
    }

    /// Both diagnostic paths accept only the exact stable publication cut.
    fn at_cut(
        observed: Option<Observation>,
        generation: u64,
        height: u64,
        applied: u64,
    ) -> Option<(BeaconHorizonStatusV1, bool)> {
        observed
            .filter(|value| {
                generation.is_multiple_of(2)
                    && value.generation == generation
                    && value.height == height
                    && value.applied == applied
            })
            .map(|value| (value.horizon, value.ready))
    }
}

impl NativeBeaconProducer {
    /// Admit this reporting control once from the original State execution pool.
    pub(crate) fn attach_readiness(
        &mut self,
        budget: &AllocationBudget,
    ) -> Result<NativeBeaconReadiness, NativeBeaconReadinessError> {
        if self.readiness.is_some() {
            return Err(NativeBeaconReadinessError::AlreadyAttached);
        }
        let reporting = NativeBeaconReadiness::new(budget)?;
        self.readiness = Some(reporting.clone());
        Ok(reporting)
    }

    /// Re-probe the same installed provider on every drive retry, including ordinary heights.
    /// The immutable source view remains held during the probe; this produces no partial.
    /// Readers wait for the complete probe, and every failed probe withdraws readiness.
    pub(crate) fn refresh_readiness(
        &self,
        state: &impl StateReadOnly,
        context: &ApplicationControlContext,
        applied: (u64, Hash32),
        generation: u64,
    ) -> Result<(), NativeBeaconError> {
        let Some(reporting) = &self.readiness else {
            return Ok(());
        };
        let mut observation = reporting.begin_refresh()?;
        if !generation.is_multiple_of(2) {
            return Err(NativeBeaconError::Context);
        }
        self.parent_source(state, context, applied)?;
        let retained = state.world().consensus_schedule();
        let current = &retained
            .ready(context.height)
            .map_err(|error| NativeBeaconError::Source(error.to_string()))?
            .epoch;
        if current.network_id != *state.network_id()
            || schedule::core_epoch(current)
                .map_err(|error| NativeBeaconError::Source(error.to_string()))?
                .id
                != context.epoch
        {
            return Err(NativeBeaconError::Context);
        }
        let world = state.world();
        let root_scope =
            crate::sumeragi::lanes::routing::committed_root_scope(world).ok_or_else(|| {
                NativeBeaconError::Source("native readiness requires immutable root scope".into())
            })?;
        if !super::super::owns_global_control(root_scope, world, current)
            .map_err(NativeBeaconError::Source)?
        {
            *observation = Some(Observation {
                generation,
                height: context.height,
                applied: applied.0,
                horizon: BeaconHorizonStatusV1 {
                    epoch_length_blocks: 0,
                    next_required_pulse_height: None,
                    active_session_id: None,
                    session_covers_next_pulse: false,
                    local_provider_ready: false,
                },
                ready: true,
            });
            return Ok(());
        }
        // The horizon is consensus-native only: the `NPoS` pre-boundary pulse, and nothing on a
        // Permissioned root. Governance slots never enter it.
        let next = (current.mode == ConsensusMode::Npos)
            .then(|| current.authorization.last_height.checked_sub(1))
            .flatten()
            .filter(|height| *height >= context.height);
        let local =
            current
                .committee
                .iter()
                .position(|seat| {
                    seat.validator.public_key().try_to_bytes().ok().is_some_and(
                        |(algorithm, bytes)| {
                            algorithm == iroha_crypto::Algorithm::BlsNormal
                                && self
                                    .local_bls
                                    .as_ref()
                                    .is_some_and(|key| key.as_slice() == bytes)
                        },
                    )
                })
                .and_then(|index| u16::try_from(index + 1).ok());
        let mut horizon = BeaconHorizonStatusV1 {
            epoch_length_blocks: if current.mode == ConsensusMode::Npos {
                current.authorization.last_height - current.authorization.first_height + 1
            } else {
                0
            },
            next_required_pulse_height: next,
            active_session_id: world.active_global_beacon_key_session(),
            session_covers_next_pulse: false,
            local_provider_ready: false,
        };
        if let Some(id) = horizon.active_session_id {
            let record = world.global_beacon_key_sessions().get(&id).ok_or_else(|| {
                NativeBeaconError::Source("active readiness session is absent".into())
            })?;
            // Check the installed sealed record within this probe. Every retry still
            // reacquires its original State view and re-probes the installed custodian.
            record
                .validate()
                .map_err(|error| NativeBeaconError::Source(error.to_string()))?;
            let binding = InstalledBeaconEpochBindingV1 {
                session_id: id,
                transcript_hash: record.session.transcript_hash,
            };
            let authenticated = record.session.network_id == current.network_id
                && record.session.adaptive_dkg.finalized_at_height <= applied.0
                && record.session.adaptive_dkg.session.authority_generation
                    == current.authorization.authority_generation
                && (current.authorization.beacon == BeaconEpochBindingV1::Bootstrap
                    || current.authorization.beacon == BeaconEpochBindingV1::Installed(binding));
            if authenticated {
                let peers = current.committee.iter().map(|seat| &seat.validator);
                let roster_hash = authenticated_global_threshold_beacon_roster_hash_iter_v1(
                    &record.session,
                    peers,
                )
                .map_err(|error| NativeBeaconError::Source(error.to_string()))?;
                let session = &record.session;
                session
                    .check_binding(&GlobalThresholdBeaconSessionBindingV1 {
                        network_id: current.network_id,
                        session_id: id,
                        roster_hash,
                        transcript_hash: record.session.transcript_hash,
                    })
                    .map_err(|error| NativeBeaconError::Source(error.to_string()))?;
                horizon.session_covers_next_pulse =
                    next.is_some_and(|height| record.is_active_at(height));
                horizon.local_provider_ready = record.is_active_at(context.height)
                    && local
                        .zip(self.signer.as_ref())
                        .is_some_and(|(index, signer)| {
                            signer
                                .attest_partial_signing_capability(session, index)
                                .is_ok()
                        });
            }
        }
        // A local validator needs custody only when an authenticated demand remains. No-demand
        // permissioned nodes and observers do not invent a mandatory signing obligation.
        let ready = local.is_none()
            || next.is_none()
            || (horizon.session_covers_next_pulse && horizon.local_provider_ready);
        *observation = Some(Observation {
            generation,
            height: context.height,
            applied: applied.0,
            horizon,
            ready,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    /// A fixed public observation makes publication races independent of provider timing.
    fn observation(ready: bool) -> Observation {
        Observation {
            generation: 8,
            height: 6,
            applied: 5,
            horizon: BeaconHorizonStatusV1 {
                epoch_length_blocks: 3600,
                next_required_pulse_height: Some(3599),
                active_session_id: Some([1; 32]),
                session_covers_next_pulse: true,
                local_provider_ready: ready,
            },
            ready,
        }
    }

    /// One reporting allocation retains the same production budget through each assertion.
    fn report() -> (AllocationBudget, NativeBeaconReadiness) {
        let bytes = ChargedShared::<Mutex<Option<Observation>>>::allocation_layout().size();
        let budget = AllocationBudget::new(bytes);
        let report = NativeBeaconReadiness::new(&budget).unwrap();
        (budget, report)
    }

    #[test]
    fn readiness_refresh_excludes_reader_until_validated_publication() {
        let (_budget, report) = report();
        *report.0.lock().unwrap() = Some(observation(true));
        let mut refresh = report.begin_refresh().unwrap();
        assert_eq!(*refresh, None);
        assert!(matches!(report.0.try_lock(), Err(TryLockError::WouldBlock)));
        assert_eq!(report.read(8, 6, 5), None);

        let reader = report.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            entered_tx.send(()).unwrap();
            result_tx
                .send(reader.read_until(8, 6, 5, Instant::now() + Duration::from_secs(5)))
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        // A real negative outcome must replace the old positive result as one publication.
        let validated = observation(false);
        *refresh = Some(validated);
        drop(refresh);
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Some((validated.horizon, false))
        );
        handle.join().unwrap();
    }

    #[test]
    fn readiness_failed_refresh_withdraws_old_positive_before_reader_returns() {
        let (_budget, report) = report();
        *report.0.lock().unwrap() = Some(observation(true));
        let refresh = report.begin_refresh().unwrap();
        assert_eq!(*refresh, None);
        assert_eq!(report.read(8, 6, 5), None);
        let reader = report.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            entered_tx.send(()).unwrap();
            result_tx
                .send(reader.read_until(8, 6, 5, Instant::now() + Duration::from_secs(5)))
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        // Every fallible production exit drops this guard without publishing a replacement.
        drop(refresh);
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            None
        );
        handle.join().unwrap();
        assert_eq!(report.read(8, 6, 5), None);
    }

    #[test]
    fn readiness_observation_requires_exact_even_generation_height_and_applied_cut() {
        let (_budget, report) = report();
        let validated = observation(true);
        let mut refresh = report.begin_refresh().unwrap();
        *refresh = Some(validated);
        drop(refresh);
        assert_eq!(report.read(8, 6, 5), Some((validated.horizon, true)));
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            report.read_until(8, 6, 5, deadline),
            Some((validated.horizon, true))
        );
        for (generation, height, applied) in [(9, 6, 5), (10, 6, 5), (8, 7, 5), (8, 6, 4)] {
            assert_eq!(report.read(generation, height, applied), None);
            assert_eq!(
                report.read_until(generation, height, applied, deadline),
                None
            );
        }
    }

    #[test]
    fn readiness_wait_expires_while_original_probe_guard_remains_held() {
        let (_budget, report) = report();
        *report.0.lock().unwrap() = Some(observation(true));
        let mut refresh = report.begin_refresh().unwrap();
        let deadline = Instant::now() + Duration::from_millis(30);
        assert_eq!(report.read_until(8, 6, 5, deadline), None);
        assert!(Instant::now() >= deadline);
        assert_eq!(*refresh, None, "the timeout cannot restore an old positive");
        assert!(matches!(report.0.try_lock(), Err(TryLockError::WouldBlock)));

        let validated = observation(true);
        *refresh = Some(validated);
        drop(refresh);
        assert_eq!(report.read_until(8, 6, 5, deadline), None);
        assert_eq!(report.read(8, 6, 5), Some((validated.horizon, true)));
    }

    #[test]
    fn readiness_poisoning_refuses_both_diagnostic_paths() {
        let (_budget, report) = report();
        let probe = report.clone();
        assert!(
            thread::spawn(move || {
                let _refresh = probe.begin_refresh().unwrap();
                panic!("failed authentic probe");
            })
            .join()
            .is_err()
        );
        assert_eq!(report.read(8, 6, 5), None);
        assert_eq!(
            report.read_until(8, 6, 5, Instant::now() + Duration::from_secs(5)),
            None
        );
        assert!(report.begin_refresh().is_err());
    }

    #[test]
    fn reporting_shell_retains_original_pool_charge_until_last_reader_drops() {
        use iroha_allocation::release::ReleaseRegistration;
        use std::task::{Context, Poll, Waker};
        let bytes = ChargedShared::<Mutex<Option<Observation>>>::allocation_layout().size();
        let registration_bytes = ReleaseRegistration::allocation_layout().size();
        let budget = AllocationBudget::new(bytes + registration_bytes);
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let report = NativeBeaconReadiness::new(&budget).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes + registration_bytes);
        let reader = report.clone();
        let NativeBeaconReadinessError::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            release,
            ..
        }) = NativeBeaconReadiness::new(&budget).unwrap_err()
        else {
            panic!("the last-reader control must retain its original capacity source");
        };
        assert_eq!(requested_bytes, bytes);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Pending
        );
        drop(report);
        assert_eq!(budget.reserved_bytes(), bytes + registration_bytes);
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Pending
        );
        drop(reader);
        assert_eq!(budget.reserved_bytes(), registration_bytes);
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Ready(())
        );
        registration.cancel();
        let retried = NativeBeaconReadiness::new(&budget).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes + registration_bytes);
        drop(retried);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn reporting_policy_refusal_and_duplicate_attach_preserve_original_owner() {
        let bytes = ChargedShared::<Mutex<Option<Observation>>>::allocation_layout().size();
        let budget = AllocationBudget::new(bytes - 1);
        let mut producer = NativeBeaconProducer::new(Hash32([4; 32]), None, None);
        let NativeBeaconReadinessError::Admission(AllocationRefusal::ExceedsLimit {
            requested_bytes,
            ..
        }) = producer.attach_readiness(&budget).unwrap_err()
        else {
            panic!("a policy shortfall is not a transient release-bearing refusal");
        };
        assert_eq!(requested_bytes, bytes);
        assert!(producer.readiness.is_none());
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(bytes);
        let reader = producer.attach_readiness(&budget).unwrap();
        assert!(matches!(
            producer.attach_readiness(&budget),
            Err(NativeBeaconReadinessError::AlreadyAttached)
        ));
        assert!(ChargedShared::ptr_eq(
            &reader.0,
            &producer.readiness.as_ref().unwrap().0
        ));
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(producer);
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(reader);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
