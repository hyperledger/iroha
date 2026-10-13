//! Move-only completion custody after one observer reply has actually returned.
//!
//! Local canonical admission may retry only these retained bytes and the original expectation.
//! This module cannot call the observer, sign, submit, recover or generate a new challenge.
//! TODO: receipt/custody nested codec provenance, pre-return observer transport custody and
//! original-pool funding for the existing reply/decoder/native Box graphs remain separate gates.

use super::super::{
    signer_completed_finality::{CompletedFinalityV1, PendingCompletedFinalityV1},
    signer_transport::{StreamTokenObserverReplyV1, StreamTokenSignerReceiptV1},
};
use super::*;
use sorafs_manifest::signer::{
    receipt::SignerCompletedOperationV1,
    stream_token::VerifiedStreamTokenSignerReceiptV1,
    stream_token_evidence::{
        SignerStreamTokenEvidenceAdmissionErrorV1 as Admission,
        VerifiedStreamTokenSignerCompletedObservationV1,
    },
};
use std::time::{Duration, Instant};

/// Borrow the original still-live operation; none of these inputs can be replaced on retry.
pub(super) struct Inputs<'a> {
    pub(super) receipt: &'a StreamTokenSignerReceiptV1,
    pub(super) token: &'a PendingToken,
    pub(super) prepared: &'a SignerStreamTokenExpectedV1,
    pub(super) original: &'a VerifiedSignerCustodyV1,
    pub(super) previous: Option<&'a VerifiedSignerCustodyV1>,
    pub(super) signing_anchor: SignerCustodyAnchorV1,
}

/// Exact returned bytes, expectation and native pending proof, before authentication.
pub(super) struct Received<'a> {
    driver: &'a SignerDriverV1,
    inputs: Inputs<'a>,
    floor: QueryFloor,
    expected: SignerStreamTokenObservationExpectedV1,
    reply: StreamTokenObserverReplyV1,
    native: Option<PendingCompletedFinalityV1>,
    deadline: Instant,
}

#[derive(Debug)]
enum Cause {
    Admission(Admission),
    Terminal(StreamTokenIssuerError),
}

/// All original phase inputs survive even a refusal after decoding has begun.
struct Refused<'a> {
    phase: Received<'a>,
    cause: Cause,
}

/// Authentication success does not authorize native proof use or token release.
pub(super) struct Authenticated<'a> {
    phase: Received<'a>,
    observation: SignerStreamTokenStateObservationV1,
    marker: Marker,
}

/// Native proof success still needs a fresh same-State/current-clock acceptance.
pub(super) struct NativeVerified<'a> {
    authenticated: Authenticated<'a>,
    native: CompletedFinalityV1,
}

/// The exact phase accepted by the lifecycle; no token or signature extraction exists here.
pub(super) struct Accepted<'a> {
    verified: NativeVerified<'a>,
}

// These distinct manifest markers retain their original phase's authority.
enum Marker {
    AfterCommit(VerifiedStreamTokenSignerCompletedObservationV1),
    BeforeRelease(VerifiedStreamTokenSignerReceiptV1),
}
impl Marker {
    fn custody(&self) -> &VerifiedSignerCustodyV1 {
        match self {
            Self::AfterCommit(value) => value.custody(),
            Self::BeforeRelease(value) => value.custody(),
        }
    }
    fn completion(&self) -> &SignerCompletedOperationV1 {
        match self {
            Self::AfterCommit(value) => value.completion(),
            Self::BeforeRelease(value) => value.completion(),
        }
    }
}

impl<'a> Received<'a> {
    pub(super) fn new(
        driver: &'a SignerDriverV1,
        inputs: Inputs<'a>,
        floor: QueryFloor,
        expected: SignerStreamTokenObservationExpectedV1,
        reply: StreamTokenObserverReplyV1,
        native: PendingCompletedFinalityV1,
    ) -> Self {
        // Copy the actual native owner's absolute deadline once; retries never renew it.
        let deadline = native.deadline();
        Self {
            driver,
            inputs,
            floor,
            expected,
            reply,
            native: Some(native),
            deadline,
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the original custody owner without allocating on the refusal path."
    )]
    fn authenticate(mut self) -> Result<Authenticated<'a>, Refused<'a>> {
        let result = (|| {
            if Instant::now() >= self.deadline {
                return Err(Cause::Terminal(
                    StreamTokenIssuerError::SignerFinalityUnavailable,
                ));
            }
            self.driver.check_handles().map_err(Cause::Terminal)?;
            let bytes = self
                .reply
                .completed_observation()
                .ok_or(Cause::Terminal(evidence_error()))?;
            let phase = self.expected.request().phase;
            #[cfg(test)]
            let observation = tests::decode(&self, bytes).map_err(Cause::Admission)?;
            #[cfg(not(test))]
            let observation = SignerStreamTokenStateObservationV1::decode_canonical(bytes)
                .map_err(Cause::Admission)?;
            let now = self.driver.now_unix_ms().map_err(Cause::Terminal)?;
            let expected = &mut self.expected;
            let verified = match phase {
                Phase::AfterCommit => verify_stream_token_signer_completed_observation_v1(
                    self.inputs.receipt.bytes(),
                    bytes,
                    self.inputs.token.token(),
                    self.inputs.prepared,
                    self.driver.pins.binding(),
                    self.driver.pins.custody_trust(),
                    self.driver.pins.observer_trust(),
                    expected,
                    now,
                )
                .map(Marker::AfterCommit),
                Phase::BeforeRelease => verify_stream_token_signer_evidence_v1(
                    self.inputs.receipt.bytes(),
                    bytes,
                    self.inputs.token.token(),
                    self.inputs.prepared,
                    self.driver.pins.binding(),
                    self.driver.pins.custody_trust(),
                    self.driver.pins.observer_trust(),
                    expected,
                    now,
                )
                .map(Marker::BeforeRelease),
                _ => {
                    return Err(Cause::Terminal(evidence_error()));
                }
            };
            let marker = match verified {
                Ok(marker) => marker,
                Err(error) => return Err(Cause::Admission(error)),
            };
            if !marker
                .custody()
                .continues_active_state(self.inputs.original)
                || self
                    .inputs
                    .previous
                    .is_some_and(|previous| !marker.custody().continues_active_state(previous))
            {
                return Err(Cause::Terminal(StreamTokenIssuerError::SignerStateChanged));
            }
            Ok((observation, marker))
        })();
        match result {
            Ok((observation, marker)) => Ok(Authenticated {
                phase: self,
                observation,
                marker,
            }),
            Err(cause) => Err(Refused { phase: self, cause }),
        }
    }

    pub(super) fn authenticate_waiting(self) -> Result<Authenticated<'a>, StreamTokenIssuerError> {
        let mut result = self.authenticate();
        let mut backoff = Duration::from_millis(4);
        loop {
            let failure = match result {
                Ok(authenticated) => return Ok(authenticated),
                Err(failure) => failure,
            };
            #[cfg(test)]
            tests::inspect_refusal(&failure);
            match &failure.cause {
                Cause::Terminal(_) => {
                    let Cause::Terminal(error) = failure.cause else {
                        unreachable!()
                    };
                    return Err(error);
                }
                Cause::Admission(error) if !error.is_retryable() => return Err(evidence_error()),
                Cause::Admission(_) => {}
            }
            let remaining = failure
                .phase
                .deadline
                .saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StreamTokenIssuerError::SignerFinalityUnavailable);
            }
            // This owner contains no State view, publication lease or history lock. Retain the
            // exact original cause while sleeping; no fabricated allocation wake source exists.
            std::thread::sleep(backoff.min(remaining));
            if Instant::now() >= failure.phase.deadline {
                return Err(StreamTokenIssuerError::SignerFinalityUnavailable);
            }
            result = failure.phase.authenticate();
            backoff = backoff.saturating_mul(2).min(Duration::from_millis(64));
        }
    }
}

impl<'a> Authenticated<'a> {
    pub(super) fn verify_native(mut self) -> Result<NativeVerified<'a>, StreamTokenIssuerError> {
        let native = self
            .phase
            .native
            .take()
            .expect("original native proof has not been consumed");
        // The existing native driver retains its Core failure and original deadline on local
        // read refusal. It returns only successful proof or terminal/expired service failure.
        let native = native.verify(
            &self.observation.body,
            self.phase.driver.clock.as_ref(),
            self.phase.driver.pins.clock_uncertainty_ms(),
        )?;
        Ok(NativeVerified {
            authenticated: self,
            native,
        })
    }
}

impl<'a> NativeVerified<'a> {
    pub(super) fn accept(self) -> Result<Accepted<'a>, StreamTokenIssuerError> {
        let phase = &self.authenticated.phase;
        let marker = &self.authenticated.marker;
        let expiry = phase
            .inputs
            .token
            .token()
            .body
            .ttl_epoch
            .checked_mul(1_000)
            .ok_or(StreamTokenIssuerError::TimeOverflow)?;
        // TODO: accept/SignerFinality::validate still project some original reader refusals.
        // This explicit final stage is not covered by the post-reply codec continuation yet.
        phase.driver.accept(
            marker.custody(),
            &self.authenticated.observation.body,
            &phase.floor,
            &[
                HistoricalFinalityV1::Custody(marker.custody().statement().anchor),
                HistoricalFinalityV1::Custody(phase.inputs.signing_anchor),
                HistoricalFinalityV1::Block(FinalityFloorV1 {
                    height: marker.completion().anchor.height,
                    block_hash: marker.completion().anchor.block_hash,
                }),
            ],
            Some((phase.inputs.token.token().body.issued_at, expiry)),
            Some(&self.native),
        )?;
        Ok(Accepted { verified: self })
    }
}

impl Accepted<'_> {
    pub(super) fn custody(&self) -> &VerifiedSignerCustodyV1 {
        self.verified.authenticated.marker.custody()
    }
}

#[cfg(test)]
#[path = "signer_completed_phase_tests.rs"]
mod tests;
