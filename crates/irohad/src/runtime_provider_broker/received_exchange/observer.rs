//! Retain one fully received observation response through local canonical admission.
//!
//! The original exchange still owns its connection lock/socket, retired request id,
//! admission permit, request and absolute deadline. This continuation performs no I/O.
//! TODO: server pre-write ownership, partial-I/O ambiguity, physical backing for all
//! codec/clone graphs and durable restart recovery remain separate open boundaries.
use super::*;

#[cfg(test)]
#[path = "observer/test_hooks.rs"]
pub(in super::super) mod test_hooks;

pub(super) fn receive(
    exchange: ReceivedExchangeV1<'_>,
    expected: &SignerStreamTokenObservationRequestV1,
) -> Result<StreamTokenObserverReplyV1, BrokerError> {
    if exchange.mutating
        || exchange.request.operation != OPERATION_STREAM_TOKEN_OBSERVE_V1
        || exchange.request.binding.slot != IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id()
        || exchange.decode_admission.operation != Some(OPERATION_STREAM_TOKEN_OBSERVE_V1)
    {
        return Err(BrokerError::Protocol);
    }
    ObservationResponse {
        exchange,
        expected,
        phase: Phase::Frame,
        frame: None,
        response: None,
        reply: None,
        observation: None,
    }
    .finish()
}

#[derive(Clone, Copy)]
enum Phase {
    Frame,
    Response,
    Envelope,
    Rejection,
    Reply,
    Observation,
    Binding,
    Complete,
}
struct ObservationResponse<'exchange, 'query> {
    exchange: ReceivedExchangeV1<'exchange>,
    expected: &'query SignerStreamTokenObservationRequestV1,
    phase: Phase,
    frame: Option<BrokerFrameV1>,
    response: Option<OperationResponseV1>,
    reply: Option<StreamTokenObserverReplyV1>,
    observation: Option<SignerStreamTokenStateObservationV1>,
}

enum AttemptError {
    Canonical(CanonicalAttemptErrorV1),
    Evidence(SignerStreamTokenEvidenceAdmissionErrorV1),
    Terminal(BrokerError),
}
impl From<CanonicalAttemptErrorV1> for AttemptError {
    fn from(error: CanonicalAttemptErrorV1) -> Self {
        Self::Canonical(error)
    }
}
impl From<BrokerError> for AttemptError {
    fn from(error: BrokerError) -> Self {
        Self::Terminal(error)
    }
}
impl AttemptError {
    fn retryable(&self) -> bool {
        match self {
            Self::Canonical(error) => error.retryable(),
            Self::Evidence(error) => error.is_retryable(),
            Self::Terminal(_) => false,
        }
    }
    fn service_error(&self) -> BrokerError {
        match self {
            Self::Canonical(error) => error.service_error(),
            Self::Evidence(error) => stream_token_evidence_error(error, BrokerError::Protocol),
            Self::Terminal(error) => *error,
        }
    }
}

impl ObservationResponse<'_, '_> {
    fn finish(mut self) -> Result<StreamTokenObserverReplyV1, BrokerError> {
        let mut delay = Duration::from_millis(1);
        loop {
            if self.exchange.deadline.remaining().is_err() {
                self.exchange.connection.poison_reason = Some(self.exchange.transport_failure);
                return Err(BrokerError::Unavailable);
            }
            #[cfg(test)]
            let step = test_hooks::advance(&mut self);
            #[cfg(not(test))]
            let step = self.advance();
            match step {
                Ok(Some(reply)) => return Ok(reply),
                Ok(None) => {}
                Err(error) if error.retryable() => {
                    #[cfg(test)]
                    test_hooks::refused(&self, &error);
                    // The original cause remains owned across this finite wait. Protocol
                    // work counters and the original pool permit are never reset/refunded.
                    let remaining = if let Ok(remaining) = self.exchange.deadline.remaining() {
                        remaining
                    } else {
                        self.exchange.connection.poison_reason =
                            Some(self.exchange.transport_failure);
                        return Err(BrokerError::Unavailable);
                    };
                    std::thread::sleep(delay.min(remaining));
                    delay = (delay * 2).min(Duration::from_millis(32));
                }
                Err(AttemptError::Terminal(BrokerError::Rejected)) => {
                    // An authenticated provider rejection does not poison the connection.
                    return Err(BrokerError::Rejected);
                }
                Err(error) => {
                    let category = error.service_error();
                    self.exchange.connection.poison_reason =
                        Some(if category == BrokerError::Unavailable {
                            self.exchange.transport_failure
                        } else {
                            BrokerConnectionFailure::Permanent(category)
                        });
                    return Err(category);
                }
            }
        }
    }

    fn advance(&mut self) -> Result<Option<StreamTokenObserverReplyV1>, AttemptError> {
        self.exchange.deadline.remaining()?;
        let limit = operation_frame_limit(OPERATION_STREAM_TOKEN_OBSERVE_V1);
        match self.phase {
            Phase::Frame => {
                let frame = decode_canonical_with_admission::<BrokerFrameV1>(
                    &self.exchange.response_frame,
                    limit,
                    &self.exchange.decode_admission,
                )?;
                if frame.magic != BROKER_MAGIC_V1
                    || frame.version != BROKER_VERSION_V1
                    || frame.kind != FRAME_KIND_OPERATION_RESPONSE_V1
                {
                    return Err(BrokerError::Protocol.into());
                }
                self.frame = Some(frame);
                self.phase = Phase::Response;
            }
            Phase::Response => {
                self.response = Some(decode_canonical_with_admission::<OperationResponseV1>(
                    &self.frame.as_ref().expect("retained decoded frame").body,
                    limit,
                    &self.exchange.decode_admission,
                )?);
                // This decoded intermediate has transferred its meaning to Response;
                // the original received frame remains retained throughout.
                self.frame = None;
                self.phase = Phase::Envelope;
            }
            Phase::Envelope => {
                let response = self.response.as_ref().expect("retained decoded response");
                validate_operation_response_envelope(self.exchange.request, response)?;
                self.phase = if response.status == STATUS_OK_V1 {
                    Phase::Reply
                } else {
                    Phase::Rejection
                };
            }
            Phase::Rejection => {
                let response = self.response.as_ref().expect("retained response");
                // Conflict and ambiguous are forbidden responses for this operation.
                if !matches!(
                    response.status,
                    STATUS_REJECTED_V1 | STATUS_STALE_OR_REVOKED_V1 | STATUS_UNAVAILABLE_V1
                ) {
                    return Err(BrokerError::Protocol.into());
                }
                decode_canonical_with_admission::<()>(
                    &response.result,
                    MAX_OPERATION_FRAME_BYTES_V1,
                    &self.exchange.decode_admission,
                )?;
                return Err(match response.status {
                    STATUS_REJECTED_V1 => BrokerError::Rejected,
                    STATUS_STALE_OR_REVOKED_V1 => BrokerError::StaleOrRevoked,
                    STATUS_UNAVAILABLE_V1 => BrokerError::Unavailable,
                    _ => unreachable!("validated operation status"),
                }
                .into());
            }
            Phase::Reply => {
                let mut wire = decode_canonical_with_admission::<StreamTokenObserverReplyWireV1>(
                    &self.response.as_ref().expect("retained response").result,
                    MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
                    &self.exchange.decode_admission,
                )?;
                self.reply = Some(take_stream_token_observer_reply(self.expected, &mut wire)?);
                self.phase = Phase::Observation;
            }
            Phase::Observation => {
                let reply = self.reply.as_ref().expect("retained exact reply leaves");
                let bytes = reply
                    .current_evidence()
                    .map(|(_, bytes)| bytes)
                    .or_else(|| reply.completed_observation())
                    .ok_or(BrokerError::Protocol)?;
                reserve_external_canonical_decode(
                    bytes.len(),
                    SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1,
                )?;
                self.observation = Some(
                    SignerStreamTokenStateObservationV1::decode_canonical(bytes)
                        .map_err(AttemptError::Evidence)?,
                );
                self.phase = Phase::Binding;
            }
            Phase::Binding => {
                validate_stream_token_observer_body(
                    &self.exchange.request.binding,
                    self.expected,
                    self.observation
                        .as_ref()
                        .expect("retained decoded observation"),
                )
                .map_err(AttemptError::Evidence)?;
                self.phase = Phase::Complete;
            }
            Phase::Complete => {
                self.exchange.deadline.remaining()?;
                return Ok(Some(self.reply.take().expect("one exact typed reply")));
            }
        }
        Ok(None)
    }
}
