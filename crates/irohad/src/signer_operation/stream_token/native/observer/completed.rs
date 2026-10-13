//! One native completed-observation attempt retained until its exact reply is returned.
//!
//! This is the producer's own Check, distinct from Torii's independently prepared Check.
//! No stage repeats observer I/O, transaction signing/submission or a completed signature.
//! TODO: `Queue/finalize_check` pre-return ambiguity, broker reply transport custody, nested
//! custody codec provenance and original-pool funding for existing cloned/boxed/codec graphs
//! remain separate gates. This process-local owner is not a durable recovery journal.

use super::*;
use std::time::Instant;

pub(super) fn observe(
    observer: &NativeStreamTokenObserverV1,
    request: &SignerStreamTokenObservationRequestV1,
    binding_digest: [u8; 32],
) -> Result<StreamTokenObserverReplyV1, Error> {
    let Subject::CompletedOperation {
        binding_digest: expected,
        operation_id,
        signing_payload_digest,
        signing_payload_size,
        signatures_digest,
        ..
    } = request.subject
    else {
        return Err(Error::Refused);
    };
    if expected != binding_digest {
        return Err(Error::Refused);
    }
    let current = observer
        .source
        .capture(operation_id)
        .map_err(|_| Error::Unavailable)?;
    let row = current.operation.ok_or(Error::Refused)?.operation;
    let reviewed = row.operation.reviewed;
    if reviewed.request.signing_payload_digest != signing_payload_digest
        || reviewed.request.signing_payload_size != signing_payload_size
    {
        return Err(Error::Refused);
    }
    let phase = match request.phase {
        ObservationPhase::AfterCommit => Phase::AfterCommit(row),
        ObservationPhase::BeforeRelease => Phase::BeforeRelease(row),
        _ => return Err(Error::Refused),
    };
    let prepared = observer
        .source
        .prepare_check(&reviewed, phase)
        .map_err(|_| Error::Unavailable)?;
    // Capture this exact prepared owner's absolute lifetime before it is consumed.
    let deadline = prepared.deadline();
    let check = observer
        .source
        .checked_prepared(prepared)
        .map_err(|_| Error::Unavailable)?;
    let completed = check
        .snapshot()
        .completed_operation()
        .ok_or(Error::Refused)?;
    if completed.signatures_digest != signatures_digest {
        return Err(Error::Refused);
    }
    let attempt = CompletedObservation {
        observer,
        request,
        check,
        deadline,
        binding_digest,
        stage: Some(Stage::Body),
    };
    attempt.finish()
}

// The exact owner stays alive while each stage is borrowed. A signed stage cannot
// transition back to payload construction or signature creation.
enum Stage {
    Body,
    Unsigned(SignerStreamTokenStateObservationBodyV1),
    Signed(SignerStreamTokenStateObservationV1),
    Encoded {
        signed: SignerStreamTokenStateObservationV1,
        reply: StreamTokenObserverReplyV1,
    },
}
struct CompletedObservation<'a> {
    observer: &'a NativeStreamTokenObserverV1,
    request: &'a SignerStreamTokenObservationRequestV1,
    check: VerifiedStreamTokenCheckV1,
    deadline: Instant,
    binding_digest: [u8; 32],
    stage: Option<Stage>,
}
impl CompletedObservation<'_> {
    fn finish(mut self) -> Result<StreamTokenObserverReplyV1, Error> {
        let mut delay = Duration::from_millis(1);
        loop {
            match self.advance() {
                Ok(false) => (),
                Ok(true) => {
                    let Some(Stage::Encoded { reply, .. }) = self.stage.take() else {
                        unreachable!("only the encoded stage can complete")
                    };
                    return Ok(reply);
                }
                Err(error) if error.retryable() => {
                    let Some(remaining) = self.deadline.checked_duration_since(Instant::now())
                    else {
                        return Err(Error::Unavailable);
                    };
                    if remaining.is_zero() {
                        return Err(Error::Unavailable);
                    }
                    // All State/history views were local to advance and are gone. The
                    // original error and entire attempt remain on this stack while waiting.
                    #[cfg(test)]
                    test_hooks::refused(&self, &error);
                    std::thread::sleep(delay.min(remaining));
                    delay = (delay * 2).min(Duration::from_millis(32));
                }
                Err(error) => return Err(error.service_error()),
            }
        }
    }

    fn advance(&mut self) -> Result<bool, AttemptError> {
        self.check
            .ensure_live()
            .map_err(|_| AttemptError::Terminal(Error::Unavailable))?;
        if Instant::now() >= self.deadline {
            return Err(AttemptError::Terminal(Error::Unavailable));
        }
        #[cfg(test)]
        test_hooks::before_advance(self);
        match self.stage.as_ref().expect("one original stage") {
            Stage::Body => {
                let Subject::CompletedOperation {
                    operation_id,
                    signing_payload_digest,
                    signing_payload_size,
                    ..
                } = self.request.subject
                else {
                    unreachable!("only completed requests enter");
                };
                let completed = self
                    .check
                    .snapshot()
                    .completed_operation()
                    .expect("the real verified Check retains its completed row");
                let body = self.observer.prepare_body(
                    self.request,
                    self.check.snapshot().control(),
                    self.check.snapshot().anchor(),
                    SignerStreamTokenStateSubjectV1::CompletedOperation {
                        binding_digest: self.binding_digest,
                        operation_id,
                        signing_payload_digest,
                        signing_payload_size,
                        completed_operation: Box::new(*completed),
                    },
                )?;
                self.stage = Some(Stage::Unsigned(body));
            }
            Stage::Unsigned(body) => {
                let payload = body
                    .signing_payload()
                    .map_err(|error| AttemptError::Evidence(error, Error::Unavailable))?;
                let signature = self
                    .observer
                    .source
                    .transactions
                    .sign_observation_payload(&payload)
                    .map_err(|_| AttemptError::Terminal(Error::Unavailable))?;
                #[cfg(test)]
                test_hooks::signed_observation();
                let Some(Stage::Unsigned(body)) = self.stage.take() else {
                    unreachable!("same unsigned owner");
                };
                self.stage = Some(Stage::Signed(SignerStreamTokenStateObservationV1 {
                    body,
                    signature,
                }));
            }
            Stage::Signed(signed) => {
                let bytes = signed
                    .encode_canonical()
                    .map_err(|error| AttemptError::Evidence(error, Error::InvalidResponse))?;
                let reply =
                    StreamTokenObserverReplyV1::completed(bytes).map_err(AttemptError::Terminal)?;
                let Some(Stage::Signed(signed)) = self.stage.take() else {
                    unreachable!("same signed owner");
                };
                self.stage = Some(Stage::Encoded { signed, reply });
            }
            Stage::Encoded { signed, .. } => {
                // Recheck native floor/time without changing the signed evidence. A
                // local read refusal retains this exact reply and the original Check.
                self.observer
                    .validate_floor(self.request, signed.body.current_anchor)?;
                let time = self
                    .observer
                    .source
                    .time()
                    .map_err(|_| AttemptError::Terminal(Error::Unavailable))?;
                let now = time.earliest_unix_ms + (time.latest_unix_ms - time.earliest_unix_ms) / 2;
                if now < signed.body.observed_at_unix_ms
                    || now >= signed.body.expires_at_unix_ms
                    || time.earliest_unix_ms < self.observer.trust.active_from_unix_ms
                    || time.latest_unix_ms >= self.observer.trust.active_until_unix_ms
                {
                    return Err(AttemptError::Terminal(Error::Refused));
                }
                self.check
                    .ensure_live()
                    .map_err(|_| AttemptError::Terminal(Error::Unavailable))?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
pub(in crate::signer_operation::stream_token::native) mod test_hooks;
