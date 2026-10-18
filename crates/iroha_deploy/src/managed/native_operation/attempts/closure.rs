//! Terminal unsigned closure under one exact reserved custody-body successor.
use super::*;
use crate::managed::native_operation::{Fees, authorization::DispatchAuthorization};
use std::time::Instant;

#[path = "closure_read_phase.rs"]
mod read_phase;
use crate::managed::stream_token_custody::body_history::NativeClosureInspector;
use read_phase::{ClosureInspection, PrepareNext, ReadPhase};

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::ClosureTail")]
pub(super) enum ClosureTail {
    Empty,
    Missing {
        authorization: [u8; 32],
    },
    Request {
        authorization: [u8; 32],
        request_sha256: String,
    },
}
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::ClosurePlan")]
pub(super) struct ClosurePlan {
    purpose: Purpose,
    semantic: [u8; 32],
    scope: DispatchScope,
    dispatch: Option<Dispatch>,
    successor: [u8; 32],
    tail: ClosureTail,
    cumulative_reserved: u8,
}
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::ClosureRecord")]
pub(super) struct ClosureRecord {
    plan: [u8; 32],
    tail: ClosureTail,
}

pub(in crate::managed) struct PendingUnsignedClosure {
    history: History,
}
// A consuming read returns the same owner when the exact closure is still pending.
#[expect(
    clippy::large_enum_variant,
    reason = "A pending consuming read returns the original history owner without a new allocation in bounded admission"
)]
pub(in crate::managed) enum UnsignedClosureVerification {
    Pending(History),
    Closed(VerifiedUnsignedClosure),
}
pub(in crate::managed) struct VerifiedUnsignedClosure {
    history: std::rc::Rc<History>,
    digest: [u8; 32],
    successor: [u8; 32],
    cumulative_reserved: usize,
    outer_intent: [u8; 32],
    root_identity: iroha_fs::FileIdentity,
    fees: Fees,
}
impl VerifiedUnsignedClosure {
    pub(in crate::managed) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(in crate::managed) fn purpose(&self) -> Purpose {
        self.history.purpose
    }
    pub(in crate::managed) fn closed_semantic(&self) -> [u8; 32] {
        self.history.semantic
    }
    pub(in crate::managed) fn successor_selection(&self) -> [u8; 32] {
        self.successor
    }
    pub(in crate::managed) fn cumulative_reserved_count(&self) -> usize {
        self.cumulative_reserved
    }
    pub(super) fn outer_intent(&self) -> [u8; 32] {
        self.outer_intent
    }
    pub(super) fn root_identity(&self) -> iroha_fs::FileIdentity {
        self.root_identity
    }
    pub(super) fn fees(&self) -> &Fees {
        &self.fees
    }
    pub(super) fn require_retained_with_pass(
        &self,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        self.history.require_current_with_pass(pass)?;
        self.require_receipt()
    }
    pub(super) fn shared_history(&self) -> &std::rc::Rc<History> {
        &self.history
    }
    pub(in crate::managed) fn retained_history(&self) -> &History {
        &self.history
    }
    // The bounded graph owner invokes this only as part of its complete before/after passes.
    pub(super) fn require_retained_local(
        &self,
        pass: Option<&crate::managed::stream_token_custody::body_history::SnapshotReadPass<'_>>,
        tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
        originals: Option<&retained_graph::OriginalReadPass<'_, '_>>,
        root_read: Option<&mut GraphRootReadPass<'_, '_>>,
    ) -> Result<()> {
        self.history
            .require_current_local_in_tree(pass, tree, originals, root_read)?;
        self.require_receipt()
    }
    pub(super) fn require_receipt(&self) -> Result<()> {
        let evidence = self.history.scope.enrollment()?;
        let plan = self
            .history
            .closing
            .as_ref()
            .ok_or_else(|| invalid("verified unsigned closure lost its closing plan"))?;
        if self.history.closed.as_ref().map(digest).transpose()? != Some(self.digest)
            || plan.successor != self.successor
            || usize::from(plan.cumulative_reserved) != self.cumulative_reserved
            || self.history.cumulative_reserved != self.cumulative_reserved
            || evidence.binding().outer_intent != self.outer_intent
            || evidence.root().identity()? != self.root_identity
            || evidence.fees() != &self.fees
        {
            return Err(invalid("verified unsigned closure was lost or changed"));
        }
        self.history.require_fees(&self.fees)?;
        self.history.validate_closure_records()
    }
}
impl History {
    pub(super) fn validate_closure_records(&self) -> Result<()> {
        let Some(plan) = &self.closing else {
            if self.closed.is_some() {
                return Err(invalid("unsigned closure lost its closing plan"));
            }
            return Ok(());
        };
        self.scope.enrollment()?;
        if self.reservation_pending()
            || self.empty_tail
            || plan.purpose != self.purpose
            || plan.semantic != self.semantic
            || plan.scope != self.scope.commitment()?
            || plan.dispatch != self.dispatch
            || plan.successor == [0; 32]
            || usize::from(plan.cumulative_reserved)
                != self
                    .scope
                    .prior_total()
                    .checked_add(self.reserved_attempt_count())
                    .ok_or_else(|| invalid("body dispatch count overflow"))?
            || usize::from(plan.cumulative_reserved) > MAX_ATTEMPTS
        {
            return Err(invalid(
                "unsigned closing plan changed original dispatch custody",
            ));
        }
        match (&plan.tail, self.attempts.last()) {
            (ClosureTail::Empty, None) if self.dispatch.is_none() && self.root.is_none() => {}
            (ClosureTail::Missing { authorization }, Some(last))
                if *authorization == last.digest()?
                    && last.commit.is_none()
                    && last.retirement.is_none() => {}
            (
                ClosureTail::Request {
                    authorization,
                    request_sha256,
                },
                Some(last),
            ) if *authorization == last.digest()?
                && last.observation.is_some()
                && last.retirement.is_none()
                && valid_sha256(request_sha256)
                && last
                    .commit
                    .as_ref()
                    .is_none_or(|value| value.request_sha256 == *request_sha256) => {}
            _ => return Err(invalid("unsigned closing plan selected another exact tail")),
        }
        if self
            .attempts
            .iter()
            .take(self.attempts.len().saturating_sub(1))
            .any(|attempt| attempt.retirement.is_none())
        {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        if let Some(closed) = &self.closed
            && (closed.plan != digest(plan)? || closed.tail != plan.tail)
        {
            return Err(invalid(
                "unsigned closure changed its reserved closing plan",
            ));
        }
        Ok(())
    }
    fn check_successor(&self, successor: &dyn SemanticSuccessor) -> Result<()> {
        self.check_successor_with_pass(successor, None)
    }
    fn check_successor_with_pass(
        &self,
        successor: &dyn SemanticSuccessor,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        self.require_current_with_pass(pass)?;
        self.check_successor_binding(successor, pass)
    }
    fn check_successor_for_wallets<'history, 'pass, 'snapshot>(
        &'history self,
        successor: &dyn SemanticSuccessor,
        pass: Option<&'pass EnrollmentReadPass<'snapshot>>,
    ) -> Result<Option<parser_pass::CurrentReadAdmission<'history, 'pass, 'snapshot>>> {
        let current = if let Some(pass) = pass {
            pass.current_read(self)?
        } else {
            self.require_current()?;
            None
        };
        self.check_successor_binding(successor, pass)?;
        Ok(current)
    }
    fn check_successor_binding(
        &self,
        successor: &dyn SemanticSuccessor,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        let snapshot = pass.and_then(EnrollmentReadPass::snapshot);
        // SemanticSuccessor is sealed to ReservedBodySuccessor. Its revalidate method and
        // this exact target's validation call the same immutable Target owner, with only
        // the infallible target getter between them. Keep the final complete native scan
        // before any binding comparison or wallet callback; no observation is retained.
        // An inherited or newly active decoder keeps both original physical observations.
        let repeat_successor = norito::core::decode_limits_active();
        #[cfg(test)]
        let repeat_successor = repeat_successor || ORIGINAL_SUCCESSOR_VALIDATION.get();
        if repeat_successor {
            successor.revalidate_with_snapshot_read_pass(snapshot)?;
        }
        let target = successor.target();
        target.validate_target_with_snapshot_read_pass(snapshot)?;
        let evidence = self.scope.enrollment()?;
        let binding = evidence.binding();
        if target.purpose() != self.purpose
            || target.predecessor_semantic() != Some(self.semantic)
            || target.outer_intent() != binding.outer_intent
            || target.predecessor_body() != binding.body_selection
            || target.successor_selection() == [0; 32]
            || target.fees() != evidence.fees()
            || self
                .closing
                .as_ref()
                .is_some_and(|plan| plan.successor != target.successor_selection())
        {
            return Err(invalid("unsigned closure selected another body successor"));
        }
        self.require_fees(evidence.fees())?;
        Ok(())
    }
    fn verify_unsigned_wallets_with_pass(
        &self,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        self.verify_unsigned_wallets_after_current(inspect, pass, None)
    }
    fn verify_unsigned_wallets_after_current(
        &self,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
        current: Option<parser_pass::CurrentReadAdmission<'_, '_, '_>>,
    ) -> Result<()> {
        if self.closing.is_some() || self.closed.is_some() {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        self.verify_wallets_inner_after_current(
            |attempt| {
                let value = inspect(attempt)?;
                if matches!(
                    value.phase(),
                    NativePreparationPhase::PayloadRetained | NativePreparationPhase::Signed
                ) {
                    return Err(invalid(
                        "body closure cannot replace retained paid material",
                    ));
                }
                Ok(value)
            },
            None,
            pass,
            current,
        )?;
        for attempt in &self.attempts {
            require_no_native_effects(attempt)?;
        }
        Ok(())
    }
    fn inspect_unsigned_tail(
        &self,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<ClosureTail> {
        self.verify_unsigned_wallets_with_pass(inspect, pass)?;
        if self
            .attempts
            .iter()
            .take(self.attempts.len().saturating_sub(1))
            .any(|attempt| attempt.retirement.is_none())
        {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        let Some(last) = self.attempts.last() else {
            return Ok(ClosureTail::Empty);
        };
        let authorization = last.digest()?;
        if last.observation.is_none() {
            require_missing_wallet(last)?;
            return Ok(ClosureTail::Missing { authorization });
        }
        let value = inspect(last)?;
        match value.phase() {
            NativePreparationPhase::Missing => {
                require_missing_wallet(last)?;
                Ok(ClosureTail::Missing { authorization })
            }
            NativePreparationPhase::RequestOnly => {
                let request_sha256 = value
                    .request_sha256()
                    .filter(|value| valid_sha256(value))
                    .ok_or_else(|| invalid("unsigned closure lost its exact request commitment"))?
                    .to_owned();
                Ok(ClosureTail::Request {
                    authorization,
                    request_sha256,
                })
            }
            NativePreparationPhase::Retired => {
                Err(invalid("retired tail lacks its exact closing plan"))
            }
            NativePreparationPhase::PayloadRetained | NativePreparationPhase::Signed => Err(
                invalid("body closure cannot replace retained paid material"),
            ),
        }
    }
    #[cfg(test)]
    pub(in crate::managed) fn prepare_unsigned_closure(
        self,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
        mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    ) -> Result<PendingUnsignedClosure> {
        self.prepare_unsigned_closure_inner(
            successor,
            authorization,
            deadline,
            ClosureInspection::Generic(&mut inspect),
            retire,
        )
    }
    pub(in crate::managed) fn prepare_unsigned_closure_native(
        self,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
        inspect: &mut NativeClosureInspector<'_>,
        retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    ) -> Result<PendingUnsignedClosure> {
        self.prepare_unsigned_closure_inner(
            successor,
            authorization,
            deadline,
            ClosureInspection::Native(inspect),
            retire,
        )
    }
    fn prepare_unsigned_closure_inner(
        mut self,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
        mut inspect: ClosureInspection<'_, '_>,
        mut retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    ) -> Result<PendingUnsignedClosure> {
        self.check_successor(successor)?;
        authorization.check(self.purpose, deadline)?;
        self.require_fees(authorization.fees())?;
        authorization.claim_body_replacement(successor.target(), deadline)?;
        let mut phase = ReadPhase::PrepareStart;
        loop {
            let next = inspect.prepare(&mut self, phase, successor, authorization, deadline)?;
            phase = match next {
                PrepareNext::Reservation => {
                    // Only the exact anchored original is published, never new Terms.
                    self.finish_reserved(&self.operation, true)?;
                    ReadPhase::PrepareAfterReservation
                }
                PrepareNext::Retirement => {
                    let previous = self
                        .predecessor()
                        .ok_or_else(|| invalid("unsigned predecessor absent"))?;
                    let last = self
                        .last()
                        .ok_or_else(|| invalid("unsigned successor absent"))?;
                    selection::retire_predecessor(
                        previous,
                        last,
                        &mut |attempt| inspect.inspect(attempt),
                        &mut retire,
                    )?;
                    ReadPhase::PrepareAfterRetirement
                }
                PrepareNext::Closing(plan) => {
                    metadata::retain(&self.operation, None, None, 1, &plan, |image| {
                        if !image.same_bytes(&self.image) {
                            return Err(invalid("closure source changed before publication"));
                        }
                        Ok(())
                    })?;
                    ReadPhase::PrepareAfterClosing
                }
                PrepareNext::Ready => return Ok(PendingUnsignedClosure { history: self }),
            };
        }
    }
    fn verify_wallets_for_pending_close(
        &self,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        match &self.closing {
            Some(plan) => self.verify_wallets_inner(inspect, Some(plan), pass),
            None => self.verify_unsigned_wallets_with_pass(inspect, pass),
        }
    }
    /// Verify the complete pending or closed transition. None means a valid incomplete closure,
    /// never permission to ignore an existing retired wallet or to resume ordinary dispatch.
    #[cfg(test)]
    pub(in crate::managed) fn verify_unsigned_closure(
        &self,
        successor: &dyn SemanticSuccessor,
        inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
    ) -> Result<Option<VerifiedUnsignedClosure>> {
        self.verify_unsigned_closure_with_pass(successor, inspect, None)
    }
    pub(in crate::managed) fn verify_unsigned_closure_with_pass(
        &self,
        successor: &dyn SemanticSuccessor,
        mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Option<VerifiedUnsignedClosure>> {
        if !self.verify_unsigned_closure_wallets(successor, &mut inspect, pass)? {
            return Ok(None);
        }
        let plan = self
            .closing
            .as_ref()
            .ok_or_else(|| invalid("verified unsigned closure lost its closing plan"))?;
        let closed = self
            .closed
            .as_ref()
            .ok_or_else(|| invalid("verified unsigned closure lost its closed record"))?;
        let evidence = self.scope.enrollment()?;
        let value = VerifiedUnsignedClosure {
            history: std::rc::Rc::new(Self::read_retained_with_pass(
                &self.operation,
                self.purpose,
                self.semantic,
                &self.scope,
                self,
                pass,
            )?),
            digest: digest(closed)?,
            successor: plan.successor,
            cumulative_reserved: usize::from(plan.cumulative_reserved),
            outer_intent: evidence.binding().outer_intent,
            root_identity: evidence.root().identity()?,
            fees: evidence.fees().clone(),
        };
        // The borrowed verifier still closes its newly parsed graph at the original
        // boundary. The consuming verifier below already owns that exact closure census.
        value.history.require_current_with_pass(pass)?;
        Self::finish_closure_receipt(value, successor, pass).map(Some)
    }

    // This path is only for callers that already own the exact parsed History. The active
    // decoder retains the original borrowed reparse and cumulative physical charge recipe.
    pub(in crate::managed) fn into_unsigned_closure_with_pass(
        self,
        successor: &dyn SemanticSuccessor,
        mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<UnsignedClosureVerification> {
        if norito::core::decode_limits_active() {
            return self
                .verify_unsigned_closure_with_pass(successor, inspect, pass)?
                .map_or_else(
                    || Ok(UnsignedClosureVerification::Pending(self)),
                    |value| Ok(UnsignedClosureVerification::Closed(value)),
                );
        }
        let Some(fields) = self.inspect_owned_closure(successor, &mut inspect, pass)? else {
            return Ok(UnsignedClosureVerification::Pending(self));
        };
        self.bind_owned_closure(fields, successor, pass)
    }

    fn inspect_owned_closure(
        &self,
        successor: &dyn SemanticSuccessor,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Option<ClosureFields>> {
        let checked = self.verify_unsigned_closure_wallets(successor, inspect, pass);
        if matches!(checked, Ok(false)) {
            return Ok(None);
        }
        // Both native wallet calls have returned. Keep the original local handle and
        // current-record exit even when inspection returned an ordinary error.
        self.revalidate_parser_handles(pass)?;
        let current = self.require_current_with_pass(pass);
        self.revalidate_parser_handles(pass)?;
        current?;
        checked?;
        self.closure_fields().map(Some)
    }

    fn bind_owned_closure(
        self,
        fields: ClosureFields,
        successor: &dyn SemanticSuccessor,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<UnsignedClosureVerification> {
        let value = fields.bind(self);
        // No callback, wallet inspection, write or authorization action occurs between
        // the current census above and the exact receipt checks below. They use
        // the same consumed History and original handles, so close this receipt without
        // a second identical census (full graph standalone, covered local census in
        // the sealed parser). All wallet callbacks and the original native
        // handle checks still precede receipt admission, including on ordinary errors.
        // This consolidates two adjacent source observations. A change after the remaining
        // census, including one changed and restored before return, may be unobserved until
        // another independent native check. No atomic snapshot or retained freshness
        // verdict is created. A later active decoder keeps the old physical recipe too;
        // the entry fallback above remains unchanged.
        let repeat_census = norito::core::decode_limits_active();
        #[cfg(test)]
        let repeat_census = repeat_census || original_receipt_census_for_test();
        if repeat_census {
            value.history.require_current_with_pass(pass)?;
        }
        Self::finish_closure_receipt(value, successor, pass)
            .map(UnsignedClosureVerification::Closed)
    }

    fn verify_unsigned_closure_wallets(
        &self,
        successor: &dyn SemanticSuccessor,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<bool> {
        // The private admission constructor performs the actual current census. Its
        // borrowed token is consumed only after pure successor/binding checks; no wallet
        // callback or effect intervenes. Active/foreign callers keep both original reads.
        let current = self.check_successor_for_wallets(successor, pass)?;
        let Some(plan) = &self.closing else {
            // A reserved outer successor may coexist with an interrupted same-body unsigned
            // retirement. Validate that exact prefix read-only; prepare closes it through the
            // sole canonical retire_predecessor owner before publishing a closing plan.
            self.verify_unsigned_wallets_after_current(inspect, pass, current)?;
            return Ok(false);
        };
        self.verify_wallets_inner_after_current(&mut *inspect, Some(plan), pass, current)?;
        for attempt in &self.attempts {
            require_no_native_effects(attempt)?;
        }
        if self.closed.is_none() {
            return Ok(false);
        }
        if let (ClosureTail::Request { request_sha256, .. }, Some(last)) =
            (&plan.tail, self.attempts.last())
        {
            let value = inspect(last)?;
            if value.phase() != NativePreparationPhase::Retired
                || value.request_sha256() != Some(request_sha256.as_str())
            {
                return Err(invalid(
                    "closed body lacks canonical exact unsigned retirement",
                ));
            }
        }
        Ok(true)
    }

    fn closure_fields(&self) -> Result<ClosureFields> {
        let plan = self
            .closing
            .as_ref()
            .ok_or_else(|| invalid("verified unsigned closure lost its closing plan"))?;
        let closed = self
            .closed
            .as_ref()
            .ok_or_else(|| invalid("verified unsigned closure lost its closed record"))?;
        let evidence = self.scope.enrollment()?;
        Ok(ClosureFields {
            digest: digest(closed)?,
            successor: plan.successor,
            cumulative_reserved: usize::from(plan.cumulative_reserved),
            outer_intent: evidence.binding().outer_intent,
            root_identity: evidence.root().identity()?,
            fees: evidence.fees().clone(),
        })
    }

    fn finish_closure_receipt(
        value: VerifiedUnsignedClosure,
        successor: &dyn SemanticSuccessor,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<VerifiedUnsignedClosure> {
        // Both private callers have just checked this exact History under their existing
        // standalone or sealed-parser scope. Retain every binding,
        // native root identity, fee, closure-record and successor check at this boundary.
        value.require_receipt()?;
        successor
            .revalidate_with_snapshot_read_pass(pass.and_then(EnrollmentReadPass::snapshot))?;
        if let Some(pass) = pass {
            pass.remember(&value)?;
        }
        Ok(value)
    }
}
struct ClosureFields {
    digest: [u8; 32],
    successor: [u8; 32],
    cumulative_reserved: usize,
    outer_intent: [u8; 32],
    root_identity: iroha_fs::FileIdentity,
    fees: Fees,
}
impl ClosureFields {
    fn bind(self, history: History) -> VerifiedUnsignedClosure {
        // Inherited decoders retain the original owned-record construction and charging.
        // No mutable scope, currentness verdict or wallet evidence enters the shared records.
        let history = if norito::core::decode_limits_active() {
            history
        } else {
            history.into_retained_records()
        };
        VerifiedUnsignedClosure {
            history: std::rc::Rc::new(history),
            digest: self.digest,
            successor: self.successor,
            cumulative_reserved: self.cumulative_reserved,
            outer_intent: self.outer_intent,
            root_identity: self.root_identity,
            fees: self.fees,
        }
    }
}
impl PendingUnsignedClosure {
    #[cfg(test)]
    pub(in crate::managed) fn finish(
        self,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
        mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    ) -> Result<VerifiedUnsignedClosure> {
        self.finish_inner(
            successor,
            authorization,
            deadline,
            ClosureInspection::Generic(&mut inspect),
            retire,
        )
    }
    pub(in crate::managed) fn finish_native(
        self,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
        inspect: &mut NativeClosureInspector<'_>,
        retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    ) -> Result<VerifiedUnsignedClosure> {
        self.finish_inner(
            successor,
            authorization,
            deadline,
            ClosureInspection::Native(inspect),
            retire,
        )
    }
    fn finish_inner(
        self,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
        mut inspect: ClosureInspection<'_, '_>,
        mut retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    ) -> Result<VerifiedUnsignedClosure> {
        authorization.check(self.history.purpose, deadline)?;
        self.history.require_fees(authorization.fees())?;
        authorization.claim_body_replacement(successor.target(), deadline)?;
        let mut history = match inspect.verify_into_closure(self.history, successor)? {
            UnsignedClosureVerification::Closed(value) => return Ok(value),
            UnsignedClosureVerification::Pending(history) => history,
        };
        let plan = history
            .closing
            .as_ref()
            .ok_or_else(|| invalid("unsigned closing plan absent"))?;
        if let ClosureTail::Request { request_sha256, .. } = &plan.tail {
            let last = history
                .attempts
                .last()
                .ok_or_else(|| invalid("unsigned closing tail absent"))?;
            authorization.check(history.purpose, deadline)?;
            successor.revalidate()?;
            let receipt = retire(last)?;
            if receipt.journal_path() != last.wallet_path()
                || receipt.request_sha256() != request_sha256
            {
                return Err(invalid("body retirement selected another original wallet"));
            }
            let value = inspect.inspect(last)?;
            if value.phase() != NativePreparationPhase::Retired
                || value.request_sha256() != Some(request_sha256.as_str())
            {
                return Err(invalid(
                    "body retirement is not retained at the original wallet",
                ));
            }
        }
        inspect.before_closed(&mut history, successor, authorization, deadline)?;
        let plan = history
            .closing
            .as_ref()
            .ok_or_else(|| invalid("unsigned closing plan absent"))?;
        metadata::retain(
            &history.operation,
            None,
            None,
            2,
            &ClosureRecord {
                plan: digest(plan)?,
                tail: plan.tail.clone(),
            },
            |image| {
                if !image.same_bytes(&history.image) {
                    return Err(invalid("closure source changed before completion"));
                }
                Ok(())
            },
        )?;
        inspect.after_closed(history, successor, authorization, deadline)
    }
}

impl ClosurePlan {
    pub(super) fn permits_retired_tail(
        &self,
        attempt: &Attempt,
        preparation: &VerifiedNativePreparation,
    ) -> Result<bool> {
        Ok(
            matches!(&self.tail, ClosureTail::Request { authorization, request_sha256 }
            if *authorization == attempt.digest()? && preparation.request_sha256() == Some(request_sha256.as_str())),
        )
    }
    pub(super) fn validate_tail_wallet(
        &self,
        attempt: &Attempt,
        preparation: &VerifiedNativePreparation,
    ) -> Result<()> {
        let valid = match &self.tail {
            ClosureTail::Missing { authorization } => {
                *authorization == attempt.digest()?
                    && preparation.phase() == NativePreparationPhase::Missing
            }
            ClosureTail::Request {
                authorization,
                request_sha256,
            } => {
                *authorization == attempt.digest()?
                    && matches!(
                        preparation.phase(),
                        NativePreparationPhase::RequestOnly | NativePreparationPhase::Retired
                    )
                    && preparation.request_sha256() == Some(request_sha256.as_str())
            }
            ClosureTail::Empty => false,
        };
        if valid {
            Ok(())
        } else {
            Err(invalid(
                "closing wallet changed its exact unsigned phase or request",
            ))
        }
    }
}
fn require_no_native_effects(attempt: &Attempt) -> Result<()> {
    if attempt
        .directory
        .entries(7)?
        .iter()
        .any(|name| name == "carrier.nrt" || name == "replay.nrt")
    {
        return Err(invalid("native execution custody cannot close as unsigned"));
    }
    Ok(())
}
fn require_missing_wallet(attempt: &Attempt) -> Result<()> {
    if attempt.is_committed() {
        return Err(invalid("committed request absence cannot close a body"));
    }
    if !attempt.directory.entries(1)?.is_empty() {
        return Err(invalid(
            "missing-wallet body closure found later or unknown custody",
        ));
    }
    Ok(())
}

#[cfg(test)]
std::thread_local! {
    static HISTORY_PARSES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    // Restore precisely the former second census, using the actual native graph walker.
    static ORIGINAL_RECEIPT_CENSUS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    // Restore the adjacent duplicate target scan through the sole native implementation.
    static ORIGINAL_SUCCESSOR_VALIDATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn original_receipt_census_for_test() -> bool {
    ORIGINAL_RECEIPT_CENSUS.with(std::cell::Cell::get)
}
#[cfg(test)]
pub(super) fn record_history_parse_for_test() {
    HISTORY_PARSES.with(|value| {
        if let Some(count) = value.get() {
            value.set(Some(count + 1));
        }
    });
}
#[cfg(test)]
impl History {
    pub(in crate::managed) fn test_original_successor_validation<T>(
        original: bool,
        read: impl FnOnce() -> T,
    ) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                ORIGINAL_SUCCESSOR_VALIDATION.set(self.0);
            }
        }
        let _restore = Restore(ORIGINAL_SUCCESSOR_VALIDATION.replace(original));
        read()
    }
    pub(in crate::managed) fn test_successor_binding(
        &self,
        successor: &dyn SemanticSuccessor,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        self.check_successor_binding(successor, pass)
    }
    pub(in crate::managed) fn test_original_receipt_census<T>(
        original: bool,
        read: impl FnOnce() -> T,
    ) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                ORIGINAL_RECEIPT_CENSUS.with(|value| value.set(self.0));
            }
        }
        let _restore = Restore(ORIGINAL_RECEIPT_CENSUS.with(|value| value.replace(original)));
        read()
    }
    pub(in crate::managed) fn test_owned_predecessor_closure_history(&self) -> Result<Self> {
        self.scope
            .predecessor()
            .ok_or_else(|| invalid("genuine test predecessor absent"))?
            .retained_history()
            .test_owned_closure_history()
    }
    pub(in crate::managed) fn test_owned_closure_history(&self) -> Result<Self> {
        Self::read_retained(
            &self.operation,
            self.purpose,
            self.semantic,
            &self.scope,
            self,
        )
    }
    pub(in crate::managed) fn test_closure_parse_work<T>(read: impl FnOnce() -> T) -> (T, usize) {
        struct Restore(Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                HISTORY_PARSES.with(|value| value.set(self.0));
            }
        }
        let _restore = Restore(HISTORY_PARSES.with(|value| value.replace(Some(0))));
        let result = read();
        (result, HISTORY_PARSES.with(|value| value.get().unwrap()))
    }
}
