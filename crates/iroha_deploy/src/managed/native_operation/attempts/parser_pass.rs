//! Lexical parser-only predecessor sharing; every retained graph closes before return.
//!
//! This pass is accepted only by read-only parsing and wallet inspection. Effectful dispatch
//! APIs never accept it. Every newly decoded body's complete local census still runs; only
//! already verified, pointer-identical predecessor closures avoid repeated full graph walks.
//! Read-only sibling replacement can therefore be reported at the final full census instead
//! of the next local body check. No receipt leaves this scope before that census succeeds;
//! signing, retirement and publication retain their independent unshared source fences.

use super::*;
use crate::managed::stream_token_custody::body_history::SnapshotReadPass;
use std::{cell::RefCell, rc::Rc};

pub(in crate::managed) struct EnrollmentReadPass<'a> {
    snapshot: &'a SnapshotReadPass<'a>,
    latest: RefCell<Option<Rc<History>>>,
    count: std::cell::Cell<usize>,
    retained: Option<&'a History>,
    parser_handles: bool,
}
// Consumed only by the immediately following wallet entry after check_successor has
// completed its current census and pure successor/binding checks. It is not a wallet or
// freshness receipt and cannot cross a callback, effect or inherited decoder boundary.
pub(super) struct CurrentReadAdmission<'history, 'pass, 'snapshot> {
    history: &'history History,
    pass: &'pass EnrollmentReadPass<'snapshot>,
}
impl CurrentReadAdmission<'_, '_, '_> {
    pub(super) fn covers(self, history: &History, pass: Option<&EnrollmentReadPass<'_>>) -> bool {
        !norito::core::decode_limits_active()
            && std::ptr::eq(self.history, history)
            && pass.is_some_and(|pass| std::ptr::eq(self.pass, pass))
            && self.pass.covers_predecessor(history.scope.predecessor())
    }
}
impl<'a> EnrollmentReadPass<'a> {
    pub(in crate::managed) fn parse(
        snapshot: &'a SnapshotReadPass<'a>,
        parser: crate::managed::stream_token_custody::body_history::ReadOnlyHistoryParser<'a, '_>,
        epochs: &mut crate::managed::native_operation::authorization::EpochReader,
    ) -> Result<()> {
        let retained = parser.retained_graph();
        if let Some(history) = retained {
            history.revalidate_retained_handles()?;
        }
        let pass = Self {
            snapshot,
            latest: RefCell::new(None),
            count: std::cell::Cell::new(0),
            retained,
            parser_handles: true,
        };
        // This sole production entry invokes the fixed BodyHistory parser and its existing
        // read-only wallet inspector. No signing/publication/retirement API receives this pass.
        let result = epochs.read_body_histories(parser, &pass);
        let current = pass.close_latest();
        // The original borrowed graph may have later siblings the parser never reached.
        // Close it on every ordinary result, even before the first closure was remembered.
        // Original handle refusal wins current-graph and inner parser errors; immutable
        // snapshot closure remains outside this owner and keeps its existing precedence.
        if let Some(history) = retained {
            history.revalidate_retained_handles()?;
        }
        current?;
        result
    }
    // The only caller is the closed unsigned transition phase. The concrete inspector is
    // intentionally required; arbitrary FnMut wallet callbacks cannot mint this pass.
    pub(super) fn unsigned_closure(
        snapshot: &'a SnapshotReadPass<'a>,
        history: &History,
        _inspector: &crate::managed::stream_token_custody::body_history::NativeClosureInspector<'_>,
    ) -> Self {
        Self {
            snapshot,
            latest: RefCell::new(
                history
                    .scope
                    .predecessor()
                    .map(|prior| Rc::clone(prior.shared_history())),
            ),
            count: std::cell::Cell::new(0),
            retained: None,
            parser_handles: true,
        }
    }
    // Only the concrete empty generated prefix can mint this pass. The owner contains
    // canonical current metadata and its fixed read sequence has no wallet/effect callback.
    pub(super) fn empty_generated(
        snapshot: &'a SnapshotReadPass<'a>,
        owner: &generated_read_phase::EmptyGeneratedReadPhase,
    ) -> Self {
        Self {
            snapshot,
            latest: RefCell::new(
                owner
                    .history()
                    .scope
                    .predecessor()
                    .map(|prior| Rc::clone(prior.shared_history())),
            ),
            count: std::cell::Cell::new(0),
            retained: None,
            parser_handles: true,
        }
    }
    pub(super) fn current_read<'history, 'pass>(
        &'pass self,
        history: &'history History,
    ) -> Result<Option<CurrentReadAdmission<'history, 'pass, 'a>>> {
        self.validate(history)?;
        Ok(self
            .covers_predecessor(history.scope.predecessor())
            .then_some(CurrentReadAdmission {
                history,
                pass: self,
            }))
    }
    pub(super) fn completed_predecessor(&self, prior: &VerifiedUnsignedClosure) -> bool {
        !norito::core::decode_limits_active()
            && self.count.get() > 0
            && self
                .latest
                .borrow()
                .as_ref()
                .is_some_and(|latest| Rc::ptr_eq(latest, prior.shared_history()))
    }
    fn close_latest(&self) -> Result<()> {
        if let Some(history) = self.latest.borrow().as_ref() {
            let current = retained_graph::validate_in_snapshot(history, self.snapshot);
            history.revalidate_retained_handles()?;
            current?;
        }
        Ok(())
    }
    pub(super) fn covers_retained(&self, history: &History) -> bool {
        self.parser_handles
            && !norito::core::decode_limits_active()
            && self
                .retained
                .is_some_and(|original| std::ptr::eq(original, history))
    }
    pub(super) fn revalidate_handles(&self, history: &History) -> Result<()> {
        if self.parser_handles && self.covers_predecessor(history.scope.predecessor()) {
            // Keep the current operation, attempt-root and each original attempt check
            // around the last wallet callback/canonical read. Only pointer-identical
            // read-only predecessor siblings wait for the unconditional full exit.
            history.revalidate_handles()
        } else {
            history.revalidate_retained_handles()
        }
    }
    #[cfg(test)]
    pub(in crate::managed) fn run<T>(
        snapshot: &'a SnapshotReadPass<'a>,
        action: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        let pass = Self {
            snapshot,
            latest: RefCell::new(None),
            count: std::cell::Cell::new(0),
            retained: None,
            parser_handles: false,
        };
        let result = action(&pass);
        if let Some(history) = pass.latest.borrow().as_ref() {
            history.require_current()?;
        }
        result
    }
    pub(super) fn snapshot(&self) -> Option<&SnapshotReadPass<'a>> {
        (!norito::core::decode_limits_active()).then_some(self.snapshot)
    }
    pub(super) fn covers_predecessor(&self, prior: Option<&VerifiedUnsignedClosure>) -> bool {
        if norito::core::decode_limits_active() {
            return false;
        }
        let Some(prior) = prior else { return true };
        let latest = self.latest.borrow();
        let mut next = latest.as_ref();
        for _ in 0..MAX_ATTEMPTS {
            let Some(current) = next else { return false };
            if Rc::ptr_eq(current, prior.shared_history()) {
                return true;
            }
            next = current
                .scope
                .predecessor()
                .map(VerifiedUnsignedClosure::shared_history);
        }
        false
    }
    pub(super) fn validate(&self, history: &History) -> Result<()> {
        if self.covers_predecessor(history.scope.predecessor()) {
            history.require_current_local(self.snapshot())
        } else {
            history.require_current()
        }
    }
    pub(super) fn remember(&self, closure: &VerifiedUnsignedClosure) -> Result<()> {
        let prior = self.latest.borrow();
        let predecessor = closure.retained_history().scope.predecessor();
        match (prior.as_ref(), predecessor) {
            (None, None) => {}
            (Some(prior), Some(predecessor)) if Rc::ptr_eq(prior, predecessor.shared_history()) => {
            }
            _ => {
                return Err(invalid(
                    "parser predecessor closure changed its exact chain",
                ));
            }
        }
        let count = self
            .count
            .get()
            .checked_add(1)
            .filter(|count| *count <= MAX_ATTEMPTS)
            .ok_or_else(|| invalid("parser history exceeds its body bound"))?;
        drop(prior);
        self.latest
            .replace(Some(Rc::clone(closure.shared_history())));
        self.count.set(count);
        Ok(())
    }
}

#[cfg(test)]
impl EnrollmentReadPass<'_> {
    pub(in crate::managed) fn test_retained_identity_and_fallback(
        snapshot: &SnapshotReadPass<'_>,
        original: &History,
        foreign: &History,
    ) -> Result<()> {
        let pass = EnrollmentReadPass {
            snapshot,
            latest: RefCell::new(None),
            count: std::cell::Cell::new(0),
            retained: Some(original),
            parser_handles: true,
        };
        assert_eq!(
            pass.covers_retained(original),
            !norito::core::decode_limits_active()
        );
        assert!(!pass.covers_retained(foreign));
        let current = History::read_retained_with_pass(
            &foreign.operation,
            foreign.purpose,
            foreign.semantic,
            &foreign.scope,
            foreign,
            Some(&pass),
        )?;
        current.require_current()
    }
    pub(in crate::managed) fn test_retain_predecessor(&self, history: &History) -> Result<()> {
        let prior = history
            .scope
            .predecessor()
            .ok_or_else(|| invalid("test parser predecessor absent"))?;
        // Reproduce the parser's oldest-to-newest order even when the genuine fixture
        // contains more than one predecessor. Keep the same finite body bound and each
        // original retained validation before lending its closure to the parser pass.
        let mut chain = [None; MAX_ATTEMPTS];
        let mut count = 0;
        let mut next = Some(prior);
        while let Some(prior) = next {
            let slot = chain
                .get_mut(count)
                .ok_or_else(|| invalid("test parser history exceeds its body bound"))?;
            *slot = Some(prior);
            count += 1;
            next = prior.retained_history().scope.predecessor();
        }
        for prior in chain[..count].iter().rev().flatten() {
            prior.require_retained_with_pass(None)?;
            self.remember(prior)?;
        }
        Ok(())
    }
    pub(in crate::managed) fn test_remember_immediate_predecessor(
        &self,
        history: &History,
    ) -> Result<()> {
        let prior = history
            .scope
            .predecessor()
            .ok_or_else(|| invalid("test parser predecessor absent"))?;
        prior.require_retained_with_pass(None)?;
        self.remember(prior)
    }
    pub(in crate::managed) fn test_validate(&self, history: &History) -> Result<()> {
        self.validate(history)
    }
}
