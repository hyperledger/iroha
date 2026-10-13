//! One admitted observer dispatch and its retained result through the first reply write.
//!
//! The absolute admitted-operation deadline predates provider dispatch. It bounds
//! local continuation and publication, not cancellation of a synchronous provider.
//! Partial I/O and durable recovery remain separate; no retry invokes the provider.
use super::*;
use crate::runtime_provider_broker::api::RuntimeProviderBrokerCallPermitV1;

#[cfg(test)]
#[path = "server_observation/test_hooks.rs"]
pub(super) mod test_hooks;

/// Borrow the original accepted transport and every enclosing admission owner.
pub(super) struct Output<'a> {
    pub(super) state: &'a BrokerServerStateV1,
    pub(super) request: &'a OperationRequestV1,
    pub(super) stream: &'a mut UnixStream,
    // The lifetime retains the original ingress throughout every reply continuation.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the borrow ties ingress custody to the full output lifetime; tests inspect its original identity"
        )
    )]
    pub(super) request_frame: &'a ScrubbedBytes,
    pub(super) admission: &'a Arc<DecodeResourceAdmissionV1>,
    // Admission remains attached to the same accepted operation until output returns.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the borrow retains the accepted operation permit through output; tests inspect its original identity"
        )
    )]
    pub(super) operation_permit: &'a RuntimeProviderBrokerCallPermitV1,
    pub(super) deadline: BrokerDeadlineV1,
}

pub(super) fn serve(output: &mut Output<'_>) -> Result<bool, BrokerError> {
    #[cfg(test)]
    test_hooks::output(output);
    let prepared = CompletedReply::dispatch(
        output.state,
        output.request,
        Arc::clone(output.admission),
        output.deadline,
    )
    .and_then(|mut owner| {
        owner.finish(Phase::Ready)?;
        Ok(owner)
    });
    #[cfg(test)]
    test_hooks::retained_output(output);
    match prepared {
        Ok(owner) => {
            output.deadline.remaining()?;
            let frame = owner.frame.as_ref().expect("one completed frame");
            // Once the first byte is attempted, any I/O failure leaves this
            // continuation permanently. It cannot re-enter Observe or encoding.
            write_length_prefixed(
                &mut DeadlineUnixStreamV1::new(output.stream, output.deadline),
                frame,
                operation_frame_limit(output.request.operation),
            )?;
            Ok(false)
        }
        Err(error) => {
            output.deadline.remaining()?;
            let Some((status, terminate)) = broker_error_status(error) else {
                return Err(error);
            };
            // Terminal service categories are encoded once under the same bound.
            // They never grant another local attempt or another provider call.
            let result = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)?;
            output.deadline.remaining()?;
            let response =
                make_operation_response(output.request, status, result, &output.state.network_id)?;
            let limit = operation_frame_limit(output.request.operation);
            output.deadline.remaining()?;
            let frame = encode_frame(FRAME_KIND_OPERATION_RESPONSE_V1, &response, limit)?;
            output.deadline.remaining()?;
            write_length_prefixed(
                &mut DeadlineUnixStreamV1::new(output.stream, output.deadline),
                &frame,
                limit,
            )?;
            Ok(terminate)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Observation,
    Binding,
    Record,
    Leaf,
    Wire,
    Result,
    Digest,
    Response,
    Envelope,
    FrameBody,
    Frame,
    Qualified,
    Ready,
}
struct CompletedReply<'a> {
    state: &'a BrokerServerStateV1,
    request: &'a OperationRequestV1,
    admission: Arc<DecodeResourceAdmissionV1>,
    deadline: BrokerDeadlineV1,
    query: SignerStreamTokenObservationRequestV1,
    reply: StreamTokenObserverReplyV1,
    phase: Phase,
    observation: Option<SignerStreamTokenStateObservationV1>,
    record: Option<ScrubbedBytes>,
    observation_bytes: Option<ScrubbedBytes>,
    wire: Option<StreamTokenObserverReplyWireV1>,
    result: Option<ScrubbedBytes>,
    fields: Option<OperationResponseFieldsV1>,
    response_digest: Option<[u8; 32]>,
    response: Option<OperationResponseV1>,
    frame_body: Option<BrokerFrameV1>,
    frame: Option<ScrubbedBytes>,
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
impl<'a> CompletedReply<'a> {
    fn dispatch(
        state: &'a BrokerServerStateV1,
        request: &'a OperationRequestV1,
        admission: Arc<DecodeResourceAdmissionV1>,
        deadline: BrokerDeadlineV1,
    ) -> Result<Self, BrokerError> {
        deadline.remaining()?;
        if admission.operation != Some(OPERATION_STREAM_TOKEN_OBSERVE_V1) {
            return Err(BrokerError::Protocol);
        }
        qualify_stream_token_observer_metadata(state, request)?;
        let query = decode_stream_token_observer_request(&request.binding, &request.payload)?;
        // Existing binding graph construction occurs before the provider can
        // complete side effects. Full physical graph funding remains separate.
        let fields = OperationResponseFieldsV1 {
            session_id: request.session_id,
            request_id: request.request_id,
            request_digest: request.request_digest,
            observed_binding: request.binding.clone(),
            provider_metadata_digest: request.provider_metadata_digest,
            operation: request.operation,
            payload_digest: request.payload_digest,
            status: STATUS_OK_V1,
            result_digest: [0; 32],
            result_len: 0,
        };
        let observer = broker_backend!(state, stream_token_state_observer);
        #[cfg(test)]
        test_hooks::before_dispatch(deadline);
        deadline.remaining()?;
        let reply = observer
            .observe(&query)
            .map_err(|error| stream_token_backend_error(error, false))?;
        deadline.remaining()?;
        Ok(Self {
            state,
            request,
            admission,
            deadline,
            query,
            reply,
            phase: Phase::Observation,
            observation: None,
            record: None,
            observation_bytes: None,
            wire: None,
            result: None,
            fields: Some(fields),
            response_digest: None,
            response: None,
            frame_body: None,
            frame: None,
        })
    }
    fn finish(&mut self, target: Phase) -> Result<(), BrokerError> {
        debug_assert_eq!(
            self.admission.operation,
            Some(OPERATION_STREAM_TOKEN_OBSERVE_V1)
        );
        let mut delay = Duration::from_millis(1);
        while self.phase != target {
            self.deadline.remaining()?;
            #[cfg(test)]
            let step = test_hooks::advance(self);
            #[cfg(not(test))]
            let step = self.advance();
            match step {
                Ok(()) => {}
                Err(error) if error.retryable() => {
                    #[cfg(test)]
                    test_hooks::refused(self, &error);
                    let remaining = self.deadline.remaining()?;
                    std::thread::sleep(delay.min(remaining));
                    delay = (delay * 2).min(Duration::from_millis(32));
                }
                Err(error) => return Err(error.service_error()),
            }
        }
        self.deadline.remaining()?;
        Ok(())
    }
    fn advance(&mut self) -> Result<(), AttemptError> {
        self.deadline.remaining()?;
        let limit = operation_frame_limit(self.request.operation);
        match self.phase {
            Phase::Observation => {
                let bytes = self
                    .reply
                    .current_evidence()
                    .map(|(_, bytes)| bytes)
                    .or_else(|| self.reply.completed_observation())
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
                    &self.request.binding,
                    &self.query,
                    self.observation.as_ref().expect("retained observation"),
                )
                .map_err(AttemptError::Evidence)?;
                self.phase = Phase::Record;
            }
            Phase::Record => {
                match self.query.subject {
                    SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { .. } => {
                        let (record, _) =
                            self.reply.current_evidence().ok_or(BrokerError::Protocol)?;
                        self.record = Some(canonical_attempt::copy(record, limit)?);
                    }
                    SignerStreamTokenObservationRequestSubjectV1::CompletedOperation { .. } => {
                        self.reply
                            .completed_observation()
                            .ok_or(BrokerError::Protocol)?;
                    }
                }
                self.phase = Phase::Leaf;
            }
            Phase::Leaf => {
                let bytes = match self.query.subject {
                    SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { .. } => {
                        self.reply
                            .current_evidence()
                            .ok_or(BrokerError::Protocol)?
                            .1
                    }
                    SignerStreamTokenObservationRequestSubjectV1::CompletedOperation { .. } => self
                        .reply
                        .completed_observation()
                        .ok_or(BrokerError::Protocol)?,
                };
                self.observation_bytes = Some(canonical_attempt::copy(bytes, limit)?);
                self.phase = Phase::Wire;
            }
            Phase::Wire => {
                let mut observation = self.observation_bytes.take().expect("one observation copy");
                self.wire = Some(match self.query.subject {
                    SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { .. } => {
                        let mut record = self.record.take().expect("one retained record copy");
                        StreamTokenObserverReplyWireV1::Current {
                            record: record.take(),
                            observation: observation.take(),
                        }
                    }
                    SignerStreamTokenObservationRequestSubjectV1::CompletedOperation { .. } => {
                        StreamTokenObserverReplyWireV1::Completed {
                            observation: observation.take(),
                        }
                    }
                });
                self.phase = Phase::Result;
            }
            Phase::Result => {
                self.result = Some(ScrubbedBytes::new(canonical_attempt::encode(
                    self.wire.as_ref().expect("retained wire"),
                    MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
                )?));
                let result = self.result.as_ref().expect("retained result");
                let fields = self.fields.as_mut().expect("pre-dispatch fields");
                fields.result_digest = operation_result_digest(result);
                fields.result_len =
                    u64::try_from(result.len()).map_err(|_| BrokerError::Protocol)?;
                self.phase = Phase::Digest;
            }
            Phase::Digest => {
                self.response_digest = Some(operation_response_digest(
                    self.fields.as_ref().expect("retained fields"),
                )?);
                self.phase = Phase::Response;
            }
            Phase::Response => {
                self.response = Some(operation_response_from_fields(
                    self.fields.take().expect("one fields owner"),
                    self.response_digest.take().expect("admitted digest"),
                    self.result.take().expect("one encoded result"),
                ));
                self.phase = Phase::Envelope;
            }
            Phase::Envelope => {
                // Body admission already succeeded against the actual returned reply.
                // Keep the response and original typed envelope cause across a refusal.
                validate_operation_response_envelope(
                    self.request,
                    self.response.as_ref().expect("retained response"),
                )?;
                self.phase = Phase::FrameBody;
            }
            Phase::FrameBody => {
                self.frame_body = Some(BrokerFrameV1 {
                    magic: BROKER_MAGIC_V1,
                    version: BROKER_VERSION_V1,
                    kind: FRAME_KIND_OPERATION_RESPONSE_V1,
                    body: canonical_attempt::encode(
                        self.response.as_ref().expect("retained response"),
                        limit,
                    )?,
                });
                self.phase = Phase::Frame;
            }
            Phase::Frame => {
                self.frame = Some(ScrubbedBytes::new(canonical_attempt::encode(
                    self.frame_body.as_ref().expect("retained frame body"),
                    limit,
                )?));
                self.phase = Phase::Qualified;
            }
            Phase::Qualified => {
                qualify_stream_token_observer_metadata(self.state, self.request)?;
                self.phase = Phase::Ready;
            }
            Phase::Ready => {}
        }
        Ok(())
    }
}

/// Direct dispatch fixtures reuse the same provider and local admission stages.
#[cfg(test)]
pub(super) fn dispatch_fixture(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
    admission: Arc<DecodeResourceAdmissionV1>,
) -> Result<ScrubbedBytes, BrokerError> {
    let mut owner = CompletedReply::dispatch(
        state,
        request,
        admission,
        BrokerDeadlineV1::new(BROKER_IO_TIMEOUT_V1)?,
    )?;
    owner.finish(Phase::Digest)?;
    qualify_stream_token_observer_metadata(state, request)?;
    let mut result = owner.result.take().expect("retained fixture result");
    result.decode_admission = Some(Arc::clone(&owner.admission));
    Ok(result)
}
