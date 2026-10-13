//! The concrete generated worker's empty, effect-free read prefix.
//!
//! Every original current-head parser and census remains. Only exact retained predecessors
//! and immutable snapshots share a lexical entry/exit. The prefix contains no wallet callback,
//! authorization claim, publication, retirement or signing. A canonical reread that discovers
//! an attempt returns its precise continuation after all native exits, before any callback.
//! Sibling changes may be reported at the exit; a wholly restored change may be unseen.

use super::*;
use crate::managed::native_operation::authorization::DispatchAuthorization;
use crate::managed::stream_token_custody::body_history::NativeClosureInspector;

pub(super) enum Progress {
    Initial,
    BeforeFirstWallet,
    BeforeFinalWallet(Origin),
    Complete(Origin),
}

fn empty(history: &History) -> bool {
    history.dispatch.is_none()
        && history.root.is_none()
        && history.attempts.is_empty()
        && !history.empty_tail
        && history.closing.is_none()
        && history.closed.is_none()
}

pub(super) fn read_empty_prefix(
    history: History,
    authorization: &dyn DispatchAuthorization,
    native: &NativeClosureInspector<'_>,
) -> Result<(History, Progress)> {
    if norito::core::decode_limits_active()
        || !matches!(history.scope, HistoryScope::Enrollment(_))
        || history.scope.predecessor().is_none()
        || !empty(&history)
    {
        return Ok((history, Progress::Initial));
    }
    let mut owner = EmptyGeneratedReadPhase { history };
    let scope = owner.history.scope.retained_copy();
    let mut output = None;
    scope.with_snapshot_read_pass(&mut |snapshot| {
        let Some(snapshot) = snapshot else {
            // A decoder installed after admission keeps the literal original continuation.
            output = Some(Progress::Initial);
            return Ok(());
        };
        let graph = retained_graph::ReadPhaseGraph::enter(&owner.history, snapshot, native)?;
        let pass = EnrollmentReadPass::empty_generated(snapshot, &owner);
        let result = owner.read(authorization, Some(&pass));
        #[cfg(test)]
        let result = result.and_then(|progress| {
            generated_tests::hit(generated_tests::Point::BeforeClose, &owner.history)?;
            Ok(progress)
        });
        // No writer ran in this scope. Even an unsuccessful current reread therefore closes
        // the last admitted current metadata as well as every original predecessor owner.
        let current = graph.close(&owner.history, true, result.is_ok());
        owner.history.revalidate_retained_handles()?;
        current?;
        output = Some(result?);
        Ok(())
    })?;
    #[cfg(test)]
    generated_tests::hit(generated_tests::Point::AfterClose, &owner.history)?;
    Ok((
        owner.history,
        output.ok_or_else(|| invalid("empty generated prefix did not run"))?,
    ))
}

// Private fields and construction prevent generic callbacks from minting predecessor cover.
pub(super) struct EmptyGeneratedReadPhase {
    history: History,
}
impl EmptyGeneratedReadPhase {
    pub(super) fn history(&self) -> &History {
        &self.history
    }

    fn refresh(&mut self, pass: Option<&EnrollmentReadPass<'_>>) -> Result<()> {
        let next = History::read_retained_with_pass(
            &self.history.operation,
            self.history.purpose,
            self.history.semantic,
            &self.history.scope,
            &self.history,
            pass,
        )?;
        self.history = next;
        Ok(())
    }
    fn verify_empty(&self, pass: Option<&EnrollmentReadPass<'_>>) -> Result<()> {
        // Eligibility is checked after each canonical reread, before reaching this call.
        // This closure cannot be used as a substitute native wallet result.
        self.history.verify_wallets_with_pass(
            |_| {
                Err(invalid(
                    "empty generated prefix unexpectedly requested a wallet",
                ))
            },
            pass,
        )
    }
    fn read(
        &mut self,
        authorization: &dyn DispatchAuthorization,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Progress> {
        self.verify_empty(pass)?;
        #[cfg(test)]
        generated_tests::hit(generated_tests::Point::BeforeFirstRead, &self.history)?;
        self.refresh(pass)?;
        if !empty(&self.history) {
            return Ok(Progress::BeforeFirstWallet);
        }
        self.verify_empty(pass)?;
        // DispatchAuthorization is sealed to the two native lease owners. origin only hashes
        // that immutable original epoch; its source position and error remain unchanged.
        let origin = authorization.origin()?;
        #[cfg(test)]
        generated_tests::hit(generated_tests::Point::BeforeFinalRead, &self.history)?;
        self.refresh(pass)?;
        if !empty(&self.history) {
            return Ok(Progress::BeforeFinalWallet(origin));
        }
        self.verify_empty(pass)?;
        #[cfg(test)]
        generated_tests::hit(generated_tests::Point::BeforeExit, &self.history)?;
        Ok(Progress::Complete(origin))
    }
}

#[cfg(test)]
use crate::managed::stream_token_custody::body_history::generated_phase_tests as generated_tests;

#[cfg(test)]
impl History {
    // The control runs the exact same empty read sequence with the original None pass.
    // It stops at the same pre-reservation boundary; no test can fabricate publication.
    pub(in crate::managed) fn test_generated_empty_prefix(
        self,
        authorization: &dyn DispatchAuthorization,
        native: &NativeClosureInspector<'_>,
        shared: bool,
    ) -> Result<(Self, u8)> {
        let (history, progress) = if shared {
            read_empty_prefix(self, authorization, native)?
        } else {
            (self, Progress::Initial)
        };
        // In the worker Initial enters these same original empty reads. Follow that
        // continuation here too, so inherited decoder tests compare actual equal work.
        let (history, progress) = if matches!(progress, Progress::Initial) && empty(&history) {
            let mut owner = EmptyGeneratedReadPhase { history };
            let progress = owner.read(authorization, None)?;
            (owner.history, progress)
        } else {
            (history, progress)
        };
        let position = match progress {
            Progress::Initial => 0,
            Progress::BeforeFirstWallet => 1,
            Progress::BeforeFinalWallet(_) => 2,
            Progress::Complete(_) => 3,
        };
        Ok((history, position))
    }
    pub(in crate::managed) fn test_generated_late_active(
        self,
        authorization: &dyn DispatchAuthorization,
        foreign: &Self,
    ) -> Result<()> {
        let scope = self.scope.retained_copy();
        let mut owner = EmptyGeneratedReadPhase { history: self };
        scope.with_snapshot_read_pass(&mut |snapshot| {
            let snapshot =
                snapshot.ok_or_else(|| invalid("late-active fixture snapshot absent"))?;
            owner.history.revalidate_retained_handles()?;
            if let Some(prior) = owner.history.scope.predecessor() {
                retained_graph::validate_predecessor_in_snapshot(prior, snapshot)?;
            }
            let pass = EnrollmentReadPass::empty_generated(snapshot, &owner);
            assert!(!pass.covers_predecessor(foreign.scope.predecessor()));
            let (ordinary, original_work) =
                Self::test_validation_work(usize::MAX, || foreign.require_current());
            ordinary?;
            let (lent, foreign_work) = Self::test_validation_work(usize::MAX, || {
                foreign.require_current_with_pass(Some(&pass))
            });
            lent?;
            assert_eq!(original_work.visits, foreign_work.visits);
            assert_eq!(
                original_work.native_tree_visits,
                foreign_work.native_tree_visits
            );
            assert_eq!(
                original_work.distinct_histories,
                foreign_work.distinct_histories
            );
            for allocation in [0, 1, 64 * 1024 * 1024] {
                let limits = || {
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
                };
                let ordinary = norito::core::with_decode_limits_measured(limits(), || {
                    owner
                        .history
                        .require_current()
                        .map_err(|error| error.to_string())
                });
                let lent = norito::core::with_decode_limits_measured(limits(), || {
                    assert!(pass.snapshot().is_none());
                    assert!(!pass.covers_predecessor(owner.history.scope.predecessor()));
                    owner
                        .history
                        .require_current_with_pass(Some(&pass))
                        .map_err(|error| error.to_string())
                });
                assert_eq!(ordinary.0, lent.0);
                if allocation <= 1 {
                    assert!(ordinary.0.is_err());
                    assert_eq!(ordinary.1, lent.1);
                } else {
                    assert!(ordinary.0.is_ok());
                    for usage in [ordinary.1, lent.1] {
                        assert!(usage.total_allocated_bytes() > 1);
                        assert!(usage.total_allocated_bytes() <= allocation);
                    }
                }
            }
            let result = owner.read(authorization, Some(&pass));
            let current = retained_graph::validate_in_snapshot(&owner.history, snapshot);
            owner.history.revalidate_retained_handles()?;
            current?;
            result.map(|_| ())
        })
    }
}

#[cfg(test)]
impl History {
    // Model a concurrent native writer using the actual reservation producer. The caller
    // supplies terms/origin from a genuine live lease and an authenticated observation;
    // no retained record or successful wallet evidence is fabricated by this hook.
    pub(in crate::managed) fn test_generated_reserve_observed(
        &self,
        origin: Origin,
        terms: Terms,
        observation: Observation,
    ) -> Result<()> {
        let attempt = self.reserve(&self.operation, origin, terms)?;
        attempt.retain_observation(observation)
    }
}
