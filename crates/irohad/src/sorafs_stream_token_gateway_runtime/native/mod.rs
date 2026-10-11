//! Native consensus gateway custody; every returned authority is an opaque challenged observation.
//!
//! Local credentials authorize signed native instructions. They do not own quotas, sequences,
//! callback acknowledgement, replay history or rollback authority. One caller-owned monotonic
//! deadline spans maintenance, admission, callback reconciliation and final Serving consumption.
//! Credentials use the shared Unix/Windows retained-handle custody reader. This provider does not
//! own the separate token issuer's bounded native receipt journal or its signing authority.
use super::*;
use crate::native_check_binding::{CheckTermination, complete_binding, complete_check};
use iroha_config::parameters::actual::SorafsStreamTokenGatewayNativeConfig;
use iroha_core::{
    query::stream_token_gateway::observation::{
        PreparedStreamTokenGatewayCheckV1 as Prepared, StreamTokenGatewayCheckAttemptFailureV1,
        StreamTokenGatewayCheckBindingFailureV1, StreamTokenGatewayCheckExpectedV1 as Expected,
        StreamTokenGatewayCheckReadbackV1 as VerifiedReadback,
        StreamTokenGatewayCheckSelectorV1 as Selector,
        StreamTokenGatewayEligibilityTimeV1 as EligibilityTime,
        StreamTokenGatewayObservationErrorV1 as ObservationError,
        VerifiedStreamTokenGatewayCheckV1 as Verified, begin_stream_token_gateway_check_v1,
    },
    queue::Queue,
    state::State,
};
use iroha_data_model::{
    account::AccountId,
    isi::sorafs::MutateSorafsStreamTokenGateway,
    sorafs::stream_token_gateway::{
        StreamTokenGatewayAdmissionAckV1 as Ack, StreamTokenGatewayAdmissionErrorV1 as Error,
        StreamTokenGatewayAdmissionQualificationV1 as Qualification,
        StreamTokenGatewayAdmissionReadbackV1 as Readback,
        StreamTokenGatewayAdmissionRecordV1 as Record,
        StreamTokenGatewayAdmissionRequestV1 as Request,
        StreamTokenGatewayAdmissionResultV1 as AdmissionResult,
        native::{
            STREAM_TOKEN_GATEWAY_MAX_EXPIRY_ITEMS_V1, StreamTokenGatewayActionV1 as Action,
            StreamTokenGatewayRequestV1 as NativeRequest,
        },
    },
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
mod reputation_delivery;
mod transactions;
use transactions::NativeTransactions;

/// Create the sole daemon gateway provider from explicit local transaction credentials.
///
/// Reject any injected provider before disabled or emergency selection. Qualification and
/// pending-prefix Checks are performed by `prepare_capture` after consensus starts. Construction
/// alone neither changes governed policy nor claims its current eligibility.
#[derive(Debug)]
pub(crate) struct NativeGatewayRuntime {
    /// Shared native quota, Check and lifecycle owner.
    pub(crate) provider: Arc<dyn StreamTokenGatewayAdmissionProviderV1>,
    /// Exact source-owned finalized reputation delivery on the same local custody.
    pub(crate) reputation: Arc<dyn StreamTokenReputationDeliveryV1>,
}

/// Construct the shared native gateway and exact reputation delivery owners.
pub(crate) fn build_native_runtime(
    tokens: &SorafsTokenConfig,
    compliance_gateway_id: Option<&str>,
    state: Arc<State>,
    queue: Arc<Queue>,
    injected: Option<&Arc<dyn StreamTokenGatewayAdmissionProviderV1>>,
    emergency_fast: bool,
) -> Result<Option<NativeGatewayRuntime>, StreamTokenGatewayRuntimeErrorV1> {
    if injected.is_some() {
        return Err(StreamTokenGatewayRuntimeErrorV1::UnexpectedProvider);
    }
    if emergency_fast {
        return Ok(None);
    }
    if !tokens.enabled {
        return if tokens.admission_native.is_none() {
            Ok(None)
        } else {
            Err(StreamTokenGatewayRuntimeErrorV1::UnexpectedProvider)
        };
    }
    let config = tokens
        .admission_native
        .as_ref()
        .ok_or(StreamTokenGatewayRuntimeErrorV1::MissingProvider)?;
    let (handle, qualification) =
        configured_binding(state.network_id_ref(), tokens, compliance_gateway_id)?;
    let runtime = NativeGateway::new(
        state,
        queue,
        handle,
        qualification,
        config,
        Duration::from_millis(tokens.admission_operation_timeout_ms),
    )?;
    let runtime = Arc::new(runtime);
    Ok(Some(NativeGatewayRuntime {
        provider: runtime.clone(),
        reputation: runtime,
    }))
}

struct NativeGateway {
    state: Arc<State>,
    transactions: NativeTransactions,
    handle: String,
    qualification: Qualification,
    uncertainty_ms: u64,
    operation_timeout: Duration,
}
impl fmt::Debug for NativeGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeGateway")
            .field("handle", &self.handle)
            .field("qualification", &self.qualification)
            .finish_non_exhaustive()
    }
}
impl NativeGateway {
    fn new(
        state: Arc<State>,
        queue: Arc<Queue>,
        handle: String,
        qualification: Qualification,
        config: &SorafsStreamTokenGatewayNativeConfig,
        operation_timeout: Duration,
    ) -> Result<Self, Error> {
        qualification.validate()?;
        if !iroha_config::parameters::is_production_runtime_handle(&handle)
            || config.clock_uncertainty_ms > 5_000
            || operation_timeout.is_zero()
            || operation_timeout > Duration::from_secs(60)
        {
            return Err(Error::BindingMismatch);
        }
        let transactions = NativeTransactions::new(state.clone(), queue, config, qualification)?;
        Ok(Self {
            state,
            transactions,
            handle,
            qualification,
            uncertainty_ms: config.clock_uncertainty_ms,
            operation_timeout,
        })
    }
    fn check_deadline(&self, deadline: Instant) -> Result<(), Error> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Unavailable)?;
        if remaining.is_zero() || remaining > self.operation_timeout {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn time(&self) -> Result<EligibilityTime, ObservationError> {
        eligibility_time(SystemTime::now(), self.uncertainty_ms)
    }
    fn prepare_check(&self, selector: Selector, deadline: Instant) -> Result<Prepared, Error> {
        self.check_deadline(deadline)?;
        begin_stream_token_gateway_check_v1(
            self.state.clone(),
            Expected {
                network_id: *self.state.network_id_ref(),
                qualification: self.qualification,
                operator: self.transactions.operator().clone(),
                observer: self.transactions.observer().clone(),
                selector,
            },
            deadline,
        )
        .map_err(observation_error)
    }
    fn checked(&self, selector: Selector, deadline: Instant) -> Result<Verified, Error> {
        self.complete_prepared_check(self.prepare_check(selector, deadline)?)
    }
    fn complete_prepared_check(&self, prepared: Prepared) -> Result<Verified, Error> {
        let deadline = prepared.deadline();
        self.check_deadline(deadline)?;
        let signed = self
            .transactions
            .sign(prepared.instruction(), true, deadline)?;
        let pending =
            complete_binding(prepared.bind_signed_transaction(signed)).map_err(binding_error)?;
        self.transactions
            .submit_and_wait(pending.signed_transaction(), pending.deadline())?;
        let verified = complete_check(pending.verify_finalized(|| self.time()), |failure| {
            failure.into_pending().verify_finalized(|| self.time())
        })
        .map_err(verification_error)?;
        self.check_deadline(deadline)?;
        Ok(verified)
    }
    fn mutate(&self, action: Action, deadline: Instant) -> Result<[u8; 32], Error> {
        self.check_deadline(deadline)?;
        let instruction = MutateSorafsStreamTokenGateway {
            request: NativeRequest {
                network_id: *self.state.network_id_ref(),
                gateway_id: self.qualification.gateway_id,
                expected_policy_revision: self.qualification.revision,
                expected_policy_digest: self.qualification.policy_digest,
                action,
            },
        };
        let signed = self.transactions.sign(&instruction, false, deadline)?;
        self.transactions.submit_and_wait(&signed, deadline)
    }
}
impl StreamTokenGatewayAdmissionProviderV1 for NativeGateway {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn configured_qualification(&self) -> Qualification {
        self.qualification
    }
    fn qualification(&self, deadline: Instant) -> Result<Qualification, Error> {
        let proof = self.checked(Selector::Qualification, deadline)?;
        match proof.readback() {
            VerifiedReadback::Qualification(value) if *value == self.qualification => Ok(*value),
            _ => Err(Error::SubstitutedOutcome),
        }
    }
    fn admit(&self, request: &Request, deadline: Instant) -> Result<AdmissionResult, Error> {
        request.validate()?;
        // One bounded maintenance instruction makes progress through abandoned leases. A backlog
        // can require a later request; it never extends this request's deadline or creates a grant.
        self.mutate(
            Action::Expire {
                max_items: STREAM_TOKEN_GATEWAY_MAX_EXPIRY_ITEMS_V1,
            },
            deadline,
        )?;
        self.mutate(Action::Admit(request.clone()), deadline)?;
        let proof = self.checked(Selector::Admission(request.clone()), deadline)?;
        match proof.readback() {
            VerifiedReadback::Admission(result) => {
                result.validate_for_request(request, self.qualification)?;
                Ok(*result)
            }
            _ => Err(Error::SubstitutedOutcome),
        }
    }
    fn pending(&self, max_items: u32, deadline: Instant) -> Result<Readback, Error> {
        let proof = self.checked(Selector::Pending { max_items }, deadline)?;
        match proof.readback() {
            VerifiedReadback::Pending(value) => Ok(value.clone()),
            _ => Err(Error::SubstitutedOutcome),
        }
    }
    fn pending_for_background(
        &self,
        max_items: u32,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayReconciliationReadV1, Error> {
        let prepared = self.prepare_check(Selector::Pending { max_items }, deadline)?;
        match prepared.pending_is_empty().map_err(observation_error)? {
            Some(true) => {
                self.check_deadline(deadline)?;
                // Drop the unsent original challenge and its State owner before reporting Idle.
                // This branch supplies no authenticated empty readback and authorizes no effect.
                drop(prepared);
                Ok(StreamTokenGatewayReconciliationReadV1::Idle)
            }
            Some(false) => {
                let proof = self.complete_prepared_check(prepared)?;
                match proof.readback() {
                    VerifiedReadback::Pending(value) => Ok(
                        StreamTokenGatewayReconciliationReadV1::Checked(value.clone()),
                    ),
                    _ => Err(Error::SubstitutedOutcome),
                }
            }
            None => Err(Error::SubstitutedOutcome),
        }
    }
    fn acknowledge(&self, record: Record, deadline: Instant) -> Result<Ack, Error> {
        let submitted = self.mutate(Action::Acknowledge(record), deadline)?;
        let proof = self.checked(Selector::Acknowledged(record), deadline)?;
        if !matches!(proof.readback(), VerifiedReadback::Acknowledged(value) if *value == record) {
            return Err(Error::SubstitutedOutcome);
        }
        let original = proof
            .acknowledgement_execution()
            .ok_or(Error::SubstitutedOutcome)?;
        Ok(acknowledgement_result(
            submitted,
            original.transaction_hash,
            false,
        ))
    }
    fn release_lease(&self, record: Record, deadline: Instant) -> Result<Ack, Error> {
        let submitted = self.mutate(Action::ReleaseLease(record), deadline)?;
        let proof = self.checked(Selector::Released(record), deadline)?;
        if !matches!(proof.readback(), VerifiedReadback::Released(value) if *value == record) {
            return Err(Error::SubstitutedOutcome);
        }
        let (original, expired) = proof
            .lease_terminal_execution()
            .ok_or(Error::SubstitutedOutcome)?;
        Ok(acknowledgement_result(
            submitted,
            original.transaction_hash,
            expired,
        ))
    }
    fn confirm_serving(
        &self,
        request: &Request,
        record: Record,
        deadline: Instant,
    ) -> Result<Record, Error> {
        let proof = self.checked(Selector::Serving(request.clone()), deadline)?;
        // Every freshly verified retry must retain the caller's exact accepted record.
        // The inner service result is completed; only Core's outer source refusal may retry.
        let consume = |proof: Verified| {
            if !matches!(proof.readback(), VerifiedReadback::Serving(value) if value.record == record)
            {
                return Ok(Err(Error::SubstitutedOutcome));
            }
            // The publication lease encloses only this handoff, never a wait or HTTP transport.
            proof.consume_for_serving(request, || self.time(), Ok)
        };
        complete_check(consume(proof), |failure| {
            consume(failure.into_pending().verify_finalized(|| self.time())?)
        })
        .map_err(verification_error)?
    }
}
fn acknowledgement_result(submitted: [u8; 32], original: [u8; 32], expired: bool) -> Ack {
    if !expired && submitted == original {
        Ack::Acknowledged
    } else {
        Ack::ExactReplay
    }
}
fn observation_error(error: ObservationError) -> Error {
    match error {
        ObservationError::Invalid => Error::InvalidRequest,
        ObservationError::Transaction => Error::SubstitutedOutcome,
        // Missing policy/history, failed Check, lost finality and UTC/deadline uncertainty all
        // fail unavailable. None fabricates a provider violation or a durable rejection result.
        _ => Error::Unavailable,
    }
}
fn binding_error(terminal: CheckTermination<StreamTokenGatewayCheckBindingFailureV1>) -> Error {
    match terminal {
        CheckTermination::Terminal(failure) => failure
            .rejection()
            .map_or(Error::Unavailable, observation_error),
        CheckTermination::Expired => Error::Unavailable,
    }
}
fn verification_error(outcome: CheckTermination<StreamTokenGatewayCheckAttemptFailureV1>) -> Error {
    match outcome {
        CheckTermination::Terminal(failure) => failure
            .rejection()
            .map_or(Error::Unavailable, observation_error),
        CheckTermination::Expired => Error::Unavailable,
    }
}
fn eligibility_time(
    now: SystemTime,
    uncertainty_ms: u64,
) -> Result<EligibilityTime, ObservationError> {
    if uncertainty_ms > 5_000 {
        return Err(ObservationError::Clock);
    }
    let now: u64 = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ObservationError::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| ObservationError::Clock)?;
    let earliest_unix_ms = now
        .checked_sub(uncertainty_ms)
        .filter(|time| *time > 0)
        .ok_or(ObservationError::Clock)?;
    let latest_unix_ms = now
        .checked_add(uncertainty_ms)
        .filter(|time| *time < u64::MAX)
        .ok_or(ObservationError::Clock)?;
    Ok(EligibilityTime {
        earliest_unix_ms,
        latest_unix_ms,
    })
}
#[cfg(test)]
mod tests;
