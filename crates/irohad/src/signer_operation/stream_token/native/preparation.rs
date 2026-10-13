//! One private, current native capture for selecting and preparing a single Check phase.
//!
//! Captures supply public preparation data only. The pending Check still reconstructs its
//! signed execution and current authority from the original source after publication.

use super::*;

/// Move-only phase inputs tied to the source that acquired them; no caller supplies a snapshot.
pub(super) struct CapturedPhaseV1<'source> {
    source: &'source NativeStreamTokenSourceV1,
    current: StreamTokenAuthoritySnapshotV1,
}

impl<'source> CapturedPhaseV1<'source> {
    pub(super) fn capture(
        source: &'source NativeStreamTokenSourceV1,
        operation_id: [u8; 32],
    ) -> Result<Self, SignerOperationErrorV1> {
        Ok(Self {
            source,
            current: source.capture(operation_id)?,
        })
    }

    /// Take this capture's exact operation once, preserving the original local claim checks.
    pub(super) fn take_operation(
        &mut self,
        request: &SignerOperationReservationRequestV1<'_>,
        reservation: Option<SignerOperationReservationV1>,
    ) -> Result<StreamTokenNativeOperationV1, SignerOperationErrorV1> {
        let row = self
            .current
            .operation
            .take()
            .ok_or(SignerOperationErrorV1::StateUnavailable)?
            .operation;
        if row.operation.reviewed.intent != *request.intent()
            || row.operation.reviewed.intent.digest().ok() != Some(request.intent_digest())
            || row.operation.reviewed.request.original_custody
                != SignerOperationCustodyV1::from_verified(request.custody())
            || reservation.is_some_and(|expected| row.operation.reservation != expected)
        {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        Ok(row)
    }

    /// Consume the same capture into one fresh round; nothing survives for a later phase.
    pub(super) fn into_check(
        self,
        reviewed: &StreamTokenReviewedV1,
        phase: Phase,
    ) -> Result<PreparedStreamTokenCheckV1, SignerOperationErrorV1> {
        if self.current.operator != self.source.transactions.operator() {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        begin_stream_token_check_v1(
            Arc::clone(&self.source.state),
            StreamTokenCheckExpectedV1 {
                binding: self.source.binding.clone(),
                observer: self.source.transactions.observer(),
                expected_operator: self.current.operator,
                control_revision: self.current.control_revision,
                control_digest: self.current.anchor.state_digest,
                reviewed: *reviewed,
                phase,
                floor: self.current.floor,
            },
            self.source.timeout,
        )
        .map_err(|_| SignerOperationErrorV1::StateUnavailable)
    }
}

impl NativeStreamTokenSourceV1 {
    pub(super) fn prepare_check(
        &self,
        reviewed: &StreamTokenReviewedV1,
        phase: Phase,
    ) -> Result<PreparedStreamTokenCheckV1, SignerOperationErrorV1> {
        CapturedPhaseV1::capture(self, reviewed.request.operation_id)?.into_check(reviewed, phase)
    }

    pub(super) fn prepare_reserved_check(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
        phase: SignerReservedObservationPhaseV1,
    ) -> Result<PreparedStreamTokenCheckV1, SignerOperationErrorV1> {
        let mut captured = CapturedPhaseV1::capture(self, check.request().intent().operation_id)?;
        let row = captured.take_operation(check.request(), Some(check.reservation()))?;
        let reviewed = row.operation.reviewed;
        let phase = match phase {
            SignerReservedObservationPhaseV1::BeforeProvider => Phase::BeforeProvider(row),
            SignerReservedObservationPhaseV1::AfterProvider => Phase::AfterProvider(row),
            SignerReservedObservationPhaseV1::BeforeCommit => Phase::BeforeCommit(row),
        };
        captured.into_check(&reviewed, phase)
    }
    pub(super) fn prepare_committed_check(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
        phase: SignerCommittedObservationPhaseV1,
    ) -> Result<PreparedStreamTokenCheckV1, SignerOperationErrorV1> {
        let mut captured =
            CapturedPhaseV1::capture(self, request.check().request().intent().operation_id)?;
        let row = captured.take_operation(
            request.check().request(),
            Some(request.check().reservation()),
        )?;
        let StreamTokenOutcomeV1::Completed(completed) = row.operation.outcome else {
            return Err(SignerOperationErrorV1::StateUnavailable);
        };
        if completed.commitment != request.commitment()
            || completed.signatures_digest != request.signatures_digest()
            || completed.reviewed.request.original_custody != request.original_custody()
        {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        let reviewed = row.operation.reviewed;
        let phase = match phase {
            SignerCommittedObservationPhaseV1::AfterCommit => Phase::AfterCommit(row),
            SignerCommittedObservationPhaseV1::BeforeRelease => Phase::BeforeRelease(row),
        };
        captured.into_check(&reviewed, phase)
    }
}

/// Observes only successful real captures in unit tests; never supplies capture or finality.
#[cfg(test)]
pub(super) mod capture_counts {
    use std::cell::RefCell;

    thread_local! {
        static CAPTURES: RefCell<Option<Vec<u64>>> = const { RefCell::new(None) };
    }

    pub(in super::super) fn record(height: u64) {
        CAPTURES.with_borrow_mut(|captures| {
            if let Some(captures) = captures {
                captures.push(height);
            }
        });
    }

    pub(in super::super) fn measure<T>(run: impl FnOnce() -> T) -> (T, Vec<u64>) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                CAPTURES.with_borrow_mut(|captures| *captures = None);
            }
        }
        CAPTURES.with_borrow_mut(|captures| {
            assert!(captures.is_none(), "nested native capture measurement");
            *captures = Some(Vec::new());
        });
        let reset = Reset;
        let result = run();
        let captures = CAPTURES.with_borrow_mut(|captures| captures.take().unwrap());
        drop(reset);
        (result, captures)
    }
}
