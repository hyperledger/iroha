//! Concrete role-11 authority over the daemon's applied State and durable Kura history.
//!
//! Software keys use the same governed Reserve/Complete and fresh phase-specific native Checks.
//! No local journal, submitted acknowledgement or signed observer claim substitutes for execution.
use super::*;
use iroha_core::{
    query::stream_token_authority::observation::{
        PreparedStreamTokenCheckV1, StreamTokenAuthoritySnapshotV1, StreamTokenCheckExpectedV1,
        StreamTokenEligibilityTimeIntervalV1, VerifiedStreamTokenCheckV1,
        begin_stream_token_check_v1, capture_stream_token_authority_v1,
    },
    state::{State, StateReadOnly},
};
use iroha_data_model::{
    account::AccountId,
    isi::sorafs::MutateSorafsStreamTokenAuthority,
    sorafs::{
        capacity::ProviderId,
        stream_token_authority::{
            StreamTokenAuthorityActionV1 as Action, StreamTokenAuthorityRequestV1,
            StreamTokenCheckPhaseV1 as Phase, StreamTokenCompleteRequestV1,
            StreamTokenNativeOperationV1, StreamTokenOutcomeV1,
        },
    },
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod observer;
mod preparation;
use preparation::CapturedPhaseV1;
/// Daemon configuration assembly for the concrete native source, producer and observer.
pub mod runtime;
mod transactions;
use transactions::NativeTransactionsV1;

/// Exact State-owned native source; private construction requires configured transaction custody.
pub struct NativeStreamTokenSourceV1 {
    state: Arc<State>,
    binding: SignerCustodyBindingV1,
    custody_record: Vec<u8>,
    custody_trust: SignerCustodyTrustV1,
    transactions: NativeTransactionsV1,
    timeout: Duration,
    uncertainty_ms: u64,
}
impl NativeStreamTokenSourceV1 {
    fn capture(
        &self,
        operation: [u8; 32],
    ) -> Result<StreamTokenAuthoritySnapshotV1, SignerOperationErrorV1> {
        let current =
            capture_stream_token_authority_v1(&self.state.view(), &self.binding, operation)
                .map_err(|_| SignerOperationErrorV1::StateUnavailable)?;
        #[cfg(test)]
        preparation::capture_counts::record(current.floor.height);
        Ok(current)
    }
    fn time(&self) -> Result<StreamTokenEligibilityTimeIntervalV1, SignerOperationErrorV1> {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| SignerOperationErrorV1::StateUnavailable)?
                .as_millis(),
        )
        .map_err(|_| SignerOperationErrorV1::StateUnavailable)?;
        let earliest_unix_ms = now
            .checked_sub(self.uncertainty_ms)
            .filter(|time| *time > 0)
            .ok_or(SignerOperationErrorV1::StateUnavailable)?;
        let latest_unix_ms = now
            .checked_add(self.uncertainty_ms)
            .filter(|time| *time < u64::MAX)
            .ok_or(SignerOperationErrorV1::StateUnavailable)?;
        Ok(StreamTokenEligibilityTimeIntervalV1 {
            earliest_unix_ms,
            latest_unix_ms,
        })
    }
    fn context(
        &self,
        control: &sorafs_manifest::signer::custody_control::SignerCustodyControlStateV1,
        anchor: sorafs_manifest::signer::custody::SignerCustodyAnchorV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let time = self.time()?;
        if control.policy.binding != self.binding
            || control.signer_revoked
            || control.attester_revoked
            || time.earliest_unix_ms < control.policy.active_from_unix_ms
            || time.latest_unix_ms >= control.policy.active_until_unix_ms
        {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        let context = SignerCustodyUseContextV1 {
            now_unix_ms: time.latest_unix_ms,
            anchor_observed_at_unix_ms: time.earliest_unix_ms,
            current_anchor: anchor,
            active_head: control
                .active_head
                .ok_or(SignerOperationErrorV1::CustodyChanged)?,
            signer_revoked: control.signer_revoked,
            attester_revoked: control.attester_revoked,
        };
        for now_unix_ms in [time.earliest_unix_ms, time.latest_unix_ms] {
            let endpoint = SignerCustodyUseContextV1 {
                now_unix_ms,
                ..context
            };
            verify_signer_custody_use_v1(
                &self.custody_record,
                &self.binding,
                &self.custody_trust,
                &endpoint,
            )
            .map_err(SignerOperationErrorV1::Custody)?;
        }
        Ok(context)
    }
    fn checked(
        &self,
        reviewed: &StreamTokenReviewedV1,
        phase: Phase,
    ) -> Result<VerifiedStreamTokenCheckV1, SignerOperationErrorV1> {
        self.checked_prepared(self.prepare_check(reviewed, phase)?)
    }
    fn checked_prepared(
        &self,
        prepared: PreparedStreamTokenCheckV1,
    ) -> Result<VerifiedStreamTokenCheckV1, SignerOperationErrorV1> {
        let signed = self
            .transactions
            .sign(prepared.instruction(), true, prepared.deadline())?;
        let pending =
            crate::native_check_binding::complete_binding(prepared.bind_signed_transaction(signed))
                .map_err(|_| SignerOperationErrorV1::StateUnavailable)?;
        self.transactions
            .submit_and_wait(pending.signed_transaction(), pending.deadline())?;
        let verify = |pending: iroha_core::query::stream_token_authority::observation::PendingStreamTokenCheckV1| {
            pending.verify_finalized(|| self.time().map_err(|_| iroha_core::query::stream_token_authority::observation::StreamTokenObservationErrorV1::Clock))
        };
        crate::native_check_binding::complete_check(verify(pending), |failure| {
            verify(failure.into_pending())
        })
        .map_err(|_| SignerOperationErrorV1::StateUnavailable)
    }
    fn checked_context(
        &self,
        checked: &VerifiedStreamTokenCheckV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        checked
            .ensure_live()
            .map_err(|_| SignerOperationErrorV1::StateUnavailable)?;
        let snapshot = checked.snapshot();
        self.context(snapshot.control(), snapshot.anchor())
    }
    fn operation(
        &self,
        request: &SignerOperationReservationRequestV1<'_>,
        reservation: Option<SignerOperationReservationV1>,
    ) -> Result<StreamTokenNativeOperationV1, SignerOperationErrorV1> {
        CapturedPhaseV1::capture(self, request.intent().operation_id)?
            .take_operation(request, reservation)
    }
    fn mutate(
        &self,
        action: Action,
        operation_id: [u8; 32],
    ) -> Result<[u8; 32], SignerOperationErrorV1> {
        let current = self.capture(operation_id)?;
        if current.operator != self.transactions.operator() {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        let sorafs_manifest::signer::protocol::SignerPurposeBindingV1::StreamToken { provider_id } =
            self.binding.purpose
        else {
            return Err(SignerOperationErrorV1::InvalidOperation);
        };
        let instruction = MutateSorafsStreamTokenAuthority {
            request: StreamTokenAuthorityRequestV1 {
                network_id: self.binding.network_id,
                provider_id: ProviderId::new(provider_id),
                expected_control_revision: current.control_revision,
                expected_control_digest: current.anchor.state_digest,
                action,
            },
        };
        let deadline = self.transactions.start_deadline()?;
        let signed = self.transactions.sign(&instruction, false, deadline)?;
        self.transactions.submit_and_wait(&signed, deadline)?;
        Ok(*signed.hash().as_ref())
    }
}
impl SignerOperationStateSourceV1 for NativeStreamTokenSourceV1 {
    fn observe_signing_state(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerOperationSigningStateV1, SignerOperationErrorV1> {
        if binding != &self.binding {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        let current = self.capture([0; 32])?;
        Ok(SignerOperationSigningStateV1 {
            custody: self.context(&current.control, current.anchor)?,
            audit_head: current.head.audit,
        })
    }
    fn observe(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        self.observe_signing_state(binding)
            .map(|state| state.custody)
    }
    fn reserve(
        &self,
        _: &SignerOperationReservationRequestV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1> {
        Err(SignerOperationErrorV1::InvalidOperation)
    }
    fn reserve_stream_token(
        &self,
        request: &SignerOperationReservationRequestV1<'_>,
        review: &SignerStreamTokenReservationReviewV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1> {
        let (body, expected) =
            prepare_stream_token_signing_payload_v1(review.signing_payload(), &self.binding)
                .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        let derived = SignerStreamTokenRequestV1::new(request.custody(), &expected, &body)
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        if &body != review.body()
            || derived != review.reviewed().request
            || request.intent() != &review.reviewed().intent
            || request.intent().digest().ok() != Some(request.intent_digest())
        {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        self.checked_context(&self.checked(
            review.reviewed(),
            Phase::Current(request.intent().previous_audit),
        )?)?;
        let submitted = self.mutate(
            Action::Reserve(*review.reviewed()),
            request.intent().operation_id,
        )?;
        let row = self.operation(request, None)?;
        if row.operation.outcome != StreamTokenOutcomeV1::Reserved
            || row.reserved_execution.transaction_hash != submitted
        {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        let reservation = row.operation.reservation;
        let reviewed = row.operation.reviewed;
        self.checked_context(&self.checked(&reviewed, Phase::BeforeProvider(row))?)?;
        Ok(reservation)
    }
    fn observe_reserved(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
        phase: SignerReservedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        self.checked_context(&self.checked_prepared(self.prepare_reserved_check(check, phase)?)?)
    }
    fn commit(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let row = self.operation(
            request.check().request(),
            Some(request.check().reservation()),
        )?;
        if row.operation.outcome != StreamTokenOutcomeV1::Reserved
            || row.operation.reviewed.request.original_custody != request.original_custody()
        {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        let submitted = self.mutate(
            Action::Complete(StreamTokenCompleteRequestV1 {
                reviewed: row.operation.reviewed,
                reservation: request.check().reservation(),
                commitment: request.commitment(),
                signatures_digest: request.signatures_digest(),
            }),
            row.operation.reviewed.request.operation_id,
        )?;
        let committed = self.operation(
            request.check().request(),
            Some(request.check().reservation()),
        )?;
        if committed
            .terminal_execution
            .as_ref()
            .map(|execution| execution.transaction_hash)
            != Some(submitted)
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        self.observe_committed(request, SignerCommittedObservationPhaseV1::AfterCommit)
    }
    fn observe_committed(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
        phase: SignerCommittedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        self.checked_context(&self.checked_prepared(self.prepare_committed_check(request, phase)?)?)
    }
}

#[cfg(test)]
mod tests;
