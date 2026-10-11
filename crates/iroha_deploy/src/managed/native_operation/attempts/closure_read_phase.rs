//! Closed native read phases for the sole unsigned-body transition.
//!
//! Only the concrete read-only wallet owner can borrow predecessor/snapshot coverage. The
//! phase body is shared with test-only arbitrary inspectors, whose path has the original None
//! pass. Every effect occurs after this owner closes. A predecessor mutation may be reported
//! at that close; a change restored before all observations need not be seen. This is neither
//! an atomic snapshot nor authority retained across publication, retirement or signing.

use super::*;

pub(super) enum ClosureInspection<'borrow, 'source> {
    #[cfg(test)]
    Generic(&'borrow mut dyn FnMut(&Attempt) -> Result<VerifiedNativePreparation>),
    Native(&'borrow mut NativeClosureInspector<'source>),
}
#[derive(Clone, Copy)]
pub(super) enum ReadPhase {
    PrepareStart,
    PrepareAfterReservation,
    PrepareAfterRetirement,
    PrepareAfterClosing,
    Verify,
    BeforeClosed,
    AfterClosed,
}
pub(super) enum PrepareNext {
    Reservation,
    Retirement,
    Closing(ClosurePlan),
    Ready,
}
enum ReadResult {
    Prepare(PrepareNext),
    Verified(Option<ClosureFields>),
    BeforeClosed,
}

impl ClosureInspection<'_, '_> {
    fn is_generic(&self) -> bool {
        match self {
            #[cfg(test)]
            Self::Generic(_) => true,
            Self::Native(_) => false,
        }
    }
    pub(super) fn inspect(&mut self, attempt: &Attempt) -> Result<VerifiedNativePreparation> {
        match self {
            #[cfg(test)]
            Self::Generic(inspect) => inspect(attempt),
            Self::Native(inspect) => inspect.inspect(attempt),
        }
    }
    pub(super) fn prepare(
        &mut self,
        history: &mut History,
        phase: ReadPhase,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
    ) -> Result<PrepareNext> {
        match self.run(history, phase, successor, Some((authorization, deadline)))? {
            ReadResult::Prepare(value) => Ok(value),
            _ => Err(invalid("unsigned preparation selected another read phase")),
        }
    }
    pub(super) fn before_closed(
        &mut self,
        history: &mut History,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
    ) -> Result<()> {
        // Keep this original authorization check before the next source observation.
        authorization.check(history.purpose, deadline)?;
        match self.run(history, ReadPhase::BeforeClosed, successor, None)? {
            ReadResult::BeforeClosed => Ok(()),
            _ => Err(invalid("unsigned publication selected another read phase")),
        }
    }
    pub(super) fn into_closure(
        &mut self,
        mut history: History,
        successor: &dyn SemanticSuccessor,
    ) -> Result<UnsignedClosureVerification> {
        // The active decoder retains the original consuming/borrowed reparse path, including
        // every physical charge and refusal. No enclosing native phase is opened in this arm.
        if self.is_generic() || norito::core::decode_limits_active() {
            return history.into_unsigned_closure_with_pass(
                successor,
                |attempt| self.inspect(attempt),
                None,
            );
        }
        let ReadResult::Verified(fields) =
            self.run(&mut history, ReadPhase::Verify, successor, None)?
        else {
            return Err(invalid("unsigned verification selected another read phase"));
        };
        Self::bind(history, fields, successor)
    }
    pub(super) fn after_closed(
        &mut self,
        mut history: History,
        successor: &dyn SemanticSuccessor,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
    ) -> Result<VerifiedUnsignedClosure> {
        let value = if self.is_generic() || norito::core::decode_limits_active() {
            let history = history.reread()?;
            authorization.check(history.purpose, deadline)?;
            history.into_unsigned_closure_with_pass(
                successor,
                |attempt| self.inspect(attempt),
                None,
            )?
        } else {
            let ReadResult::Verified(fields) = self.run(
                &mut history,
                ReadPhase::AfterClosed,
                successor,
                Some((authorization, deadline)),
            )?
            else {
                return Err(invalid("unsigned closed read selected another read phase"));
            };
            Self::bind(history, fields, successor)?
        };
        match value {
            UnsignedClosureVerification::Closed(value) => Ok(value),
            UnsignedClosureVerification::Pending(_) => {
                Err(invalid("unsigned body closure was not retained"))
            }
        }
    }
    fn bind(
        history: History,
        fields: Option<ClosureFields>,
        successor: &dyn SemanticSuccessor,
    ) -> Result<UnsignedClosureVerification> {
        match fields {
            // The complete native phase and immutable snapshot have closed before receipt
            // construction. Keep the original receipt/successor checks, with no lent pass.
            Some(fields) => history.bind_owned_closure(fields, successor, None),
            None => Ok(UnsignedClosureVerification::Pending(history)),
        }
    }
    fn run(
        &mut self,
        history: &mut History,
        phase: ReadPhase,
        successor: &dyn SemanticSuccessor,
        authorization: Option<(&dyn DispatchAuthorization, Instant)>,
    ) -> Result<ReadResult> {
        let mut owner = UnsignedClosureReadPhase {
            history,
            phase,
            successor,
            authorization,
            // Before a canonical publication reread succeeds, the original metadata may
            // legitimately be stale. Such an error closes its native owners and predecessor,
            // rather than replacing a parser refusal with expected old-record inequality.
            head_admitted: !matches!(
                phase,
                ReadPhase::PrepareAfterReservation
                    | ReadPhase::PrepareAfterRetirement
                    | ReadPhase::PrepareAfterClosing
                    | ReadPhase::AfterClosed
            ),
        };
        match self {
            #[cfg(test)]
            Self::Generic(inspect) => owner.read(&mut |attempt| inspect(attempt), None),
            Self::Native(inspect) if norito::core::decode_limits_active() => {
                owner.read(&mut |attempt| inspect.inspect(attempt), None)
            }
            Self::Native(inspect) => owner.native(inspect),
        }
    }
}

// No arbitrary action or wallet callback can construct this owner. Its enum fixes every read
// and contains no retirement, record publication, authorization claim or signing operation.
struct UnsignedClosureReadPhase<'a> {
    history: &'a mut History,
    phase: ReadPhase,
    successor: &'a dyn SemanticSuccessor,
    authorization: Option<(&'a dyn DispatchAuthorization, Instant)>,
    head_admitted: bool,
}
impl UnsignedClosureReadPhase<'_> {
    fn native(&mut self, inspector: &mut NativeClosureInspector<'_>) -> Result<ReadResult> {
        let scope = self.history.scope.retained_copy();
        let mut output = None;
        scope.with_snapshot_read_pass(&mut |snapshot| {
            let Some(snapshot) = snapshot else {
                output = Some(self.read(&mut |attempt| inspector.inspect(attempt), None)?);
                return Ok(());
            };
            self.history.revalidate_retained_handles()?;
            if let Some(prior) = self.history.scope.predecessor() {
                retained_graph::validate_predecessor_in_snapshot(prior, snapshot)?;
            }
            let pass = EnrollmentReadPass::unsigned_closure(snapshot, self.history, inspector);
            let result = self.read(&mut |attempt| inspector.inspect(attempt), Some(&pass));
            let current = if self.head_admitted {
                retained_graph::validate_in_snapshot(self.history, snapshot)
            } else if let Some(prior) = self.history.scope.predecessor() {
                retained_graph::validate_predecessor_in_snapshot(prior, snapshot)
            } else {
                Ok(())
            };
            // The canonical reread retains the exact native handle Arcs, and only replaces
            // the History after its original-before/current-after custody checks succeed.
            // On every ordinary result, original custody wins graph and inner errors; the
            // outer immutable snapshot's exit remains last and can supersede all of them.
            self.history.revalidate_retained_handles()?;
            current?;
            output = Some(result?);
            Ok(())
        })?;
        output.ok_or_else(|| invalid("unsigned closure phase did not run"))
    }
    fn refresh(&mut self, pass: Option<&EnrollmentReadPass<'_>>) -> Result<()> {
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::ClosureRetainedRead);
        let next = History::read_retained_with_pass(
            &self.history.operation,
            self.history.purpose,
            self.history.semantic,
            &self.history.scope,
            self.history,
            pass,
        )?;
        *self.history = next;
        self.head_admitted = true;
        Ok(())
    }
    fn authorization(&self) -> Result<(&dyn DispatchAuthorization, Instant)> {
        self.authorization
            .ok_or_else(|| invalid("unsigned transition authorization absent"))
    }
    fn read(
        &mut self,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<ReadResult> {
        match self.phase {
            ReadPhase::PrepareStart => {
                self.history
                    .verify_wallets_for_pending_close(inspect, pass)?;
                if self.history.reservation_pending() {
                    return Ok(ReadResult::Prepare(PrepareNext::Reservation));
                }
                self.after_reservation(inspect, pass)
            }
            ReadPhase::PrepareAfterReservation => self.after_reservation(inspect, pass),
            ReadPhase::PrepareAfterRetirement => self.after_retirement(inspect, pass),
            ReadPhase::PrepareAfterClosing => self.after_closing(pass),
            ReadPhase::Verify => self
                .history
                .inspect_owned_closure(self.successor, inspect, pass)
                .map(ReadResult::Verified),
            ReadPhase::BeforeClosed => {
                self.history
                    .check_successor_with_pass(self.successor, pass)?;
                let plan = self
                    .history
                    .closing
                    .as_ref()
                    .ok_or_else(|| invalid("unsigned closing plan absent"))?;
                self.history
                    .verify_wallets_inner(inspect, Some(plan), pass)?;
                Ok(ReadResult::BeforeClosed)
            }
            ReadPhase::AfterClosed => {
                self.refresh(pass)?;
                let (authorization, deadline) = self.authorization()?;
                authorization.check(self.history.purpose, deadline)?;
                self.history
                    .inspect_owned_closure(self.successor, inspect, pass)
                    .map(ReadResult::Verified)
            }
        }
    }
    fn after_reservation(
        &mut self,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<ReadResult> {
        self.refresh(pass)?;
        self.history
            .check_successor_with_pass(self.successor, pass)?;
        if self.history.closing.is_none() {
            self.history
                .verify_unsigned_wallets_with_pass(inspect, pass)?;
            if let (Some(previous), Some(_last)) = (self.history.predecessor(), self.history.last())
            {
                if previous.retirement.is_none() {
                    let (authorization, deadline) = self.authorization()?;
                    authorization.check(self.history.purpose, deadline)?;
                    self.successor.revalidate()?;
                    self.history.require_current_with_pass(pass)?;
                    return Ok(ReadResult::Prepare(PrepareNext::Retirement));
                }
            }
        }
        self.after_retirement(inspect, pass)
    }
    fn after_retirement(
        &mut self,
        inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<ReadResult> {
        self.refresh(pass)?;
        self.history
            .check_successor_with_pass(self.successor, pass)?;
        let (authorization, deadline) = self.authorization()?;
        authorization.check(self.history.purpose, deadline)?;
        if self.history.closing.is_none() {
            let tail = self.history.inspect_unsigned_tail(inspect, pass)?;
            let cumulative = self
                .history
                .scope
                .prior_total()
                .checked_add(self.history.reserved_attempt_count())
                .ok_or_else(|| invalid("body dispatch count overflow"))?;
            let plan = ClosurePlan {
                purpose: self.history.purpose,
                semantic: self.history.semantic,
                scope: self.history.scope.commitment()?,
                dispatch: self.history.dispatch.clone(),
                successor: self.successor.target().successor_selection(),
                tail,
                cumulative_reserved: u8::try_from(cumulative)
                    .map_err(|_| invalid("body dispatch count overflow"))?,
            };
            authorization.check(self.history.purpose, deadline)?;
            self.successor.revalidate()?;
            self.history.require_current_with_pass(pass)?;
            Ok(ReadResult::Prepare(PrepareNext::Closing(plan)))
        } else {
            self.history
                .verify_unsigned_closure_with_pass(self.successor, inspect, pass)?;
            self.after_closing(pass)
        }
    }
    fn after_closing(&mut self, pass: Option<&EnrollmentReadPass<'_>>) -> Result<ReadResult> {
        self.refresh(pass)?;
        let (authorization, deadline) = self.authorization()?;
        authorization.check(self.history.purpose, deadline)?;
        Ok(ReadResult::Prepare(PrepareNext::Ready))
    }
}

#[cfg(test)]
impl History {
    pub(in crate::managed) fn test_into_unsigned_closure_native(
        self,
        successor: &dyn SemanticSuccessor,
        inspector: &mut NativeClosureInspector<'_>,
    ) -> Result<UnsignedClosureVerification> {
        ClosureInspection::Native(inspector).into_closure(self, successor)
    }
}

#[cfg(test)]
impl History {
    // Genuine caller supplies the retained native history and concrete inspector. Install the
    // decoder only after constructing the production phase's snapshot/pass and current token;
    // this tests at-use fallback, rather than mistaking an ended callback scope for late use.
    pub(in crate::managed) fn test_closure_phase_late_active(
        &self,
        inspector: &NativeClosureInspector<'_>,
    ) -> Result<()> {
        self.scope.with_snapshot_read_pass(&mut |snapshot| {
            let snapshot = snapshot.ok_or_else(|| invalid("late-active fixture began active"))?;
            self.revalidate_retained_handles()?;
            if let Some(prior) = self.scope.predecessor() {
                retained_graph::validate_predecessor_in_snapshot(prior, snapshot)?;
            }
            let pass = EnrollmentReadPass::unsigned_closure(snapshot, self, inspector);
            let current = pass
                .current_read(self)?
                .ok_or_else(|| invalid("native phase current token absent"))?;
            norito::core::with_decode_limits_measured(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, 64),
                || {
                    assert!(!current.covers(self, Some(&pass)));
                    assert!(pass.snapshot().is_none());
                    assert!(!pass.covers_predecessor(self.scope.predecessor()));
                },
            );
            for allocation in [0, 1, 64 * 1024 * 1024] {
                let limits = || {
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
                };
                let ordinary = norito::core::with_decode_limits_measured(limits(), || {
                    self.require_current().map_err(|error| error.to_string())
                });
                let covered = norito::core::with_decode_limits_measured(limits(), || {
                    retained_graph::validate_in_snapshot(self, snapshot)
                        .map_err(|error| error.to_string())
                });
                assert_eq!(ordinary.0, covered.0, "late-active allocation {allocation}");
                if allocation <= 1 {
                    assert!(ordinary.0.is_err());
                    assert_eq!(ordinary.1, covered.1);
                } else {
                    assert!(ordinary.0.is_ok());
                    for usage in [ordinary.1, covered.1] {
                        assert!(usage.total_allocated_bytes() > 1);
                        assert!(usage.total_allocated_bytes() <= allocation);
                    }
                }
            }
            let current = retained_graph::validate_in_snapshot(self, snapshot);
            self.revalidate_retained_handles()?;
            current
        })
    }
}
