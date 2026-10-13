//! One-use native Check execution joined to the same node's authenticated applied State.
//!
//! Independent floor/context, account, custody, reviewed request and clock expectations enter
//! explicitly. This consumer owns the actual State and reuses canonical consensus continuity;
//! a decoded Check, isolated QC or successful submission acknowledgement cannot mint authority.
//! TODO: wire the production purpose-bound source, separate transaction signer and qualified
//! clock to this consumer, and qualify live phase latency and software custody independently.

mod completed_source;
mod reserved_source;

pub use crate::query::signer_check::NativeCheckBindingErrorV1;

use std::{sync::Arc, time::Duration};

use iroha_crypto::HashOf;
use iroha_data_model::{
    account::AccountId,
    block::consensus::HeightContextId,
    isi::sorafs::MutateSorafsFinalPromotionAuthority,
    sorafs::final_promotion_authority::{
        FINAL_PROMOTION_CUSTODY_MAX_REVISIONS_V1, FINAL_PROMOTION_MAX_OPERATIONS_V1,
        FINAL_PROMOTION_MAX_RECORD_BYTES_V1, FINAL_PROMOTION_RESERVATION_MS_V1,
        FinalPromotionAuthorityActionV1, FinalPromotionCheckSubjectV1, FinalPromotionCheckV1,
        FinalPromotionOperationOutcomeV1, FinalPromotionOperationRecordV1,
    },
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use sorafs_manifest::signer::{
    custody::SignerCustodyBindingV1,
    final_promotion::SignerFinalPromotionRequestV1,
    protocol::{SignerOperationActionV1, SignerPurposeBindingV1},
};

use super::{
    FinalPromotionAuthoritySnapshotV1,
    check::{check_applied_snapshot_v1, check_snapshot_eligibility_v1},
};
use crate::{
    query::signer_check::{
        BindingFailure, BindingScope, BoundNativeCheckV1, NativeCheckErrorV1, NativeCheckFloorV1,
        NativeCheckRoundV1, NativeCustodyCheckPurposeV1, NativeCustodyCheckRefV1,
        SignedCheckAttempt, authenticate_applied_check_v1, bind_signed_check_v1,
        validate_native_signatory_v1,
    },
    state::State,
};

/// Independently retained chain/committee floor; candidate proofs must not select these pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalPromotionCheckFloorV1 {
    /// One-based canonical height already trusted by the caller across restart.
    pub height: u64,
    /// Exact trusted canonical block-header hash at that height.
    pub block_hash: [u8; 32],
    /// Independently trusted height-context identity, including its committee authority.
    pub context_id: HeightContextId,
}

/// Independent, immutable expectations selected before creating a pending Check.
///
/// These are caller trust inputs, not decoded verification output. The source factory must pin
/// the reviewed request before constructing a coordinator that performs its initial observation.
pub struct FinalPromotionCheckExpectedV1 {
    /// Exact signer authorization binding for the reviewed final-promotion request.
    pub binding: SignerCustodyBindingV1,
    /// Independent single Ed25519 observer that must retain the exact deployment Check permission.
    pub observer: AccountId,
    /// Original operation account that must remain registered with deployment Operate permission.
    pub expected_operator: AccountId,
    /// Independently prepared request; native verification also rechecks its custody binding.
    pub request: SignerFinalPromotionRequestV1,
    /// Exact operation phase and native predecessor selected for this observation.
    pub subject: FinalPromotionCheckSubjectV1,
    /// Exact governed custody control revision.
    pub control_revision: u64,
    /// Exact governed custody control record digest.
    pub control_digest: [u8; 32],
    /// Independently retained canonical chain and committee floor.
    pub floor: FinalPromotionCheckFloorV1,
}

/// Independently supplied closed UTC interval for one eligibility observation.
///
/// This runtime-only value is a caller expectation, not qualified clock evidence. The production
/// source must independently establish its source, uncertainty and sampling lifetime. Both
/// endpoints must satisfy current custody and the exact operation phase at one applied State cut.
/// Equal endpoints retain exact-time semantics. No wire representation or scalar fallback exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalPromotionEligibilityTimeIntervalV1 {
    /// Earliest possible UTC time in milliseconds since the UNIX epoch, strictly greater than zero.
    pub earliest_unix_ms: u64,
    /// Latest possible UTC time, at least the earliest value and strictly less than `u64::MAX`.
    pub latest_unix_ms: u64,
}

/// Payload-free semantic verdicts, carried with original custody by verification failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalPromotionObservationErrorV1 {
    /// Independent expectations or canonical bounds are invalid.
    #[error("invalid final-promotion Check expectations")]
    Invalid,
    /// The local one-use observation interval has elapsed.
    #[error("final-promotion Check observation expired")]
    Expired,
    /// Unpredictable local challenge generation failed.
    #[error("final-promotion Check entropy unavailable")]
    Entropy,
    /// The signed envelope differs from the exact prepared Check.
    #[error("final-promotion Check signed transaction mismatch")]
    Transaction,
    /// The exact transaction has not been applied to this State cut.
    #[error("final-promotion Check is not applied")]
    NotApplied,
    /// Exact durable finality or independently anchored committee continuity failed.
    #[error("final-promotion Check finality unavailable")]
    Finality,
    /// Exact signed entry, executed wire or aligned successful result could not be proven.
    #[error("final-promotion Check execution proof rejected")]
    Execution,
    /// Current same-cut permission, control, custody or phase is no longer eligible.
    #[error("final-promotion Check current authority rejected")]
    Authority,
    /// The independently supplied eligibility interval is unavailable or malformed.
    #[error("final-promotion Check eligibility clock unavailable")]
    Clock,
}
use FinalPromotionObservationErrorV1 as Error;

/// Move-only challenge prepared before signing or submitting its exact native transaction.
#[must_use = "a prepared Check must be signed within its original observation interval"]
pub struct PreparedFinalPromotionCheckV1 {
    state: Arc<State>,
    expected: FinalPromotionCheckExpectedV1,
    instruction: MutateSorafsFinalPromotionAuthority,
    round: NativeCheckRoundV1,
}

/// Move-only exact signed attempt. Dropping or terminal verification retires its challenge.
#[must_use = "submit the exact transaction and consume the pending Check once applied"]
pub struct PendingFinalPromotionCheckV1 {
    prepared: PreparedFinalPromotionCheckV1,
    bound: BoundNativeCheckV1,
}

/// Original signed operation source required by the exact Check phase.
///
/// The original Reserve and Complete envelopes must be retained by the caller from ordinary
/// submission or same-envelope reconciliation. Decoded operation rows and Check envelopes cannot
/// replace either original source. Every phase has one exact source shape.
pub enum FinalPromotionCheckSourceV1<'a> {
    /// The custody and audit-head Check has no prior operation source.
    Current,
    /// A Reserved phase must prove this original signed role-15 Reserve against the native row.
    Reserved(&'a SignedTransaction),
    /// A completed phase must prove both original signed operation entries and their finality.
    Completed {
        /// Exact signed transaction that allocated the immutable reservation.
        reserve: &'a SignedTransaction,
        /// Exact signed transaction that completed it before the original expiry.
        complete: &'a SignedTransaction,
    },
}

/// Move-only success scoped to one exact native Check and one authenticated applied cut.
///
/// It has no wire representation. Use it immediately for its original phase; it cannot certify
/// that revocation will not race a later key call or authorize a different observation phase.
#[must_use = "use the verified Check only for its original live observation phase"]
pub struct VerifiedFinalPromotionCheckV1 {
    observer: AccountId,
    expected_operator: AccountId,
    instruction: MutateSorafsFinalPromotionAuthority,
    snapshot: FinalPromotionAuthoritySnapshotV1,
    check_height: u64,
    original_floor: FinalPromotionCheckFloorV1,
    applied_floor: FinalPromotionCheckFloorV1,
    entry_hash: HashOf<TransactionEntrypoint>,
    canonical_external: iroha_allocation::ChargedBuffer<u8>,
    check_block_hash: [u8; 32],
    eligibility_time_interval: FinalPromotionEligibilityTimeIntervalV1,
    round: NativeCheckRoundV1,
}

impl From<NativeCheckErrorV1> for Error {
    fn from(error: NativeCheckErrorV1) -> Self {
        match error {
            NativeCheckErrorV1::Invalid => Self::Invalid,
            NativeCheckErrorV1::Expired => Self::Expired,
            NativeCheckErrorV1::Entropy => Self::Entropy,
            NativeCheckErrorV1::Transaction => Self::Transaction,
            NativeCheckErrorV1::NotApplied => Self::NotApplied,
            NativeCheckErrorV1::Finality => Self::Finality,
            NativeCheckErrorV1::Execution => Self::Execution,
        }
    }
}
impl FinalPromotionCheckFloorV1 {
    fn coordinates(self) -> NativeCheckFloorV1 {
        NativeCheckFloorV1 {
            height: self.height,
            block_hash: self.block_hash,
            context_id: self.context_id,
        }
    }
}

/// Begin a purpose-native round with fresh OS entropy before any signing or State/proof I/O.
///
/// # Errors
/// Rejects invalid independent expectations, a zero or greater-than-60-second interval, failed
/// entropy, or expiry. The duration is an observation bound, not signed logical block time.
pub fn begin_final_promotion_check_v1(
    state: Arc<State>,
    expected: FinalPromotionCheckExpectedV1,
    max_elapsed: Duration,
) -> Result<PreparedFinalPromotionCheckV1, Error> {
    let mut round = NativeCheckRoundV1::start(max_elapsed)?;
    let binding = &expected.binding;
    expected
        .request
        .validate_binding(binding)
        .map_err(|_| Error::Invalid)?;
    let SignerPurposeBindingV1::FinalPromotionProvenance { deployment_id } = &binding.purpose
    else {
        return Err(Error::Invalid);
    };
    expected.floor.coordinates().validate()?;
    if expected.control_revision == 0
        || expected.control_revision > FINAL_PROMOTION_CUSTODY_MAX_REVISIONS_V1
        || !super::valid_deployment(deployment_id)
        || validate_native_signatory_v1(&expected.observer).is_err()
        || expected.expected_operator.try_signatory().is_none()
        || expected.observer == expected.expected_operator
        || expected.control_digest == [0; 32]
        || expected.request.original_custody.record_digest == [0; 32]
        || expected.request.original_custody.control_state_digest != expected.control_digest
    {
        return Err(Error::Invalid);
    }
    validate_expected_subject(&expected, deployment_id)?;
    let challenge = round.issue_challenge()?;
    let instruction = MutateSorafsFinalPromotionAuthority {
        deployment_id: deployment_id.clone(),
        expected_control_revision: expected.control_revision,
        expected_control_digest: expected.control_digest,
        action: FinalPromotionAuthorityActionV1::Check(FinalPromotionCheckV1 {
            challenge,
            network_id: binding.network_id,
            minimum_height: expected.floor.height,
            minimum_block_hash: expected.floor.block_hash,
            expected_operator: expected.expected_operator.clone(),
            request: expected.request,
            subject: expected.subject.clone(),
        }),
    };
    super::encode(&instruction).map_err(|_| Error::Invalid)?;
    round.ensure_live()?;
    Ok(PreparedFinalPromotionCheckV1 {
        state,
        expected,
        instruction,
        round,
    })
}

// Pure shape checks do not authenticate a row or replace the later same-State predicate/history.
// Bound borrowed nested data before copying it into the prepared instruction.
fn validate_expected_subject(
    expected: &FinalPromotionCheckExpectedV1,
    deployment: &str,
) -> Result<(), Error> {
    if norito::canonical_frame_len(&expected.subject).map_err(|_| Error::Invalid)?
        > FINAL_PROMOTION_MAX_RECORD_BYTES_V1
    {
        return Err(Error::Invalid);
    }
    let (row, reserved) = match &expected.subject {
        FinalPromotionCheckSubjectV1::Current(audit) => {
            return if audit.sequence <= FINAL_PROMOTION_MAX_OPERATIONS_V1
                && (audit.sequence == 0) == (audit.digest == [0; 32])
            {
                Ok(())
            } else {
                Err(Error::Invalid)
            };
        }
        FinalPromotionCheckSubjectV1::BeforeProvider(row)
        | FinalPromotionCheckSubjectV1::AfterProvider(row)
        | FinalPromotionCheckSubjectV1::BeforeCommit(row) => (row, true),
        FinalPromotionCheckSubjectV1::AfterCommit(row)
        | FinalPromotionCheckSubjectV1::BeforeRelease(row) => (row, false),
    };
    if row.deployment_id != deployment
        || row.revision == 0
        || row.revision > 2 * FINAL_PROMOTION_MAX_OPERATIONS_V1
        || (row.revision == 1) != (row.predecessor_digest == [0; 32])
        || row.request_digest == [0; 32]
        || row.reserved_origin.entry_hash == [0; 32]
        || !super::valid_execution(&row.reserved)
        || !super::valid_execution(&row.execution)
        || u64::from(row.reserved.ordinal) >= row.revision
        || u64::from(row.execution.ordinal) >= row.revision
        || row.intent.digest().is_err()
        || row.intent.action != SignerOperationActionV1::Sign
        || row.intent.operation_id != expected.request.operation_id
        || row.intent.request_digest != expected.request.digest().map_err(|_| Error::Invalid)?
        || row.custody != expected.request.original_custody
        || row.reserved.authority != expected.expected_operator
        || row.execution.authority != expected.expected_operator
        || row.reservation.reservation_id == [0; 32]
        || row.reservation.fence == 0
        || row.reservation.fence > FINAL_PROMOTION_MAX_OPERATIONS_V1
        || row.intent.previous_audit.sequence >= row.reservation.fence
        || row.reservation.expires_at_unix_ms <= row.reserved.recorded_at_unix_ms
        || row.reservation.expires_at_unix_ms == u64::MAX
        || row
            .reserved
            .recorded_at_unix_ms
            .checked_add(FINAL_PROMOTION_RESERVATION_MS_V1)
            .is_none_or(|limit| row.reservation.expires_at_unix_ms > limit)
    {
        return Err(Error::Invalid);
    }
    if reserved {
        if row.outcome != FinalPromotionOperationOutcomeV1::Reserved
            || row.reserved != row.execution
            || row.execution_origin != Some(row.reserved_origin)
        {
            return Err(Error::Invalid);
        }
    } else {
        let FinalPromotionOperationOutcomeV1::Completed(completed) = row.outcome else {
            return Err(Error::Invalid);
        };
        if row.execution.height <= row.reserved.height
            || row
                .execution_origin
                .is_none_or(|origin| origin.entry_hash == [0; 32])
            || super::adjacent_execution(&row.reserved, &row.execution).is_err()
            || row.execution.recorded_at_unix_ms >= row.reservation.expires_at_unix_ms
            || row.intent.previous_audit.sequence.checked_add(1)
                != Some(completed.commitment.audit.sequence)
            || completed.commitment.audit.digest == [0; 32]
            || completed.commitment.audit.digest == row.intent.previous_audit.digest
            || completed.commitment.response_digest == [0; 32]
            || completed.signatures_digest == [0; 32]
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

impl PreparedFinalPromotionCheckV1 {
    /// Original absolute deadline; no signing, binding or retry renews it.
    #[must_use]
    pub fn deadline(&self) -> std::time::Instant {
        self.round.deadline()
    }

    /// Original independently supplied role-14 binding; this is not verified current custody.
    #[must_use]
    pub const fn binding(&self) -> &SignerCustodyBindingV1 {
        &self.expected.binding
    }

    /// Original independently pinned account expected to submit this exact Check.
    #[must_use]
    pub const fn observer(&self) -> &AccountId {
        &self.expected.observer
    }

    /// Original operation account whose current Operate permission this Check must prove.
    #[must_use]
    pub const fn expected_operator(&self) -> &AccountId {
        &self.expected.expected_operator
    }

    /// Check the original local interval before signing; this never renews the challenge.
    ///
    /// # Errors
    /// Returns expiry without changing the retained binding, account or original deadline.
    /// This elapsed-time check establishes neither custody nor current native permission.
    pub fn ensure_live(&self) -> Result<(), Error> {
        self.round.ensure_live().map_err(Into::into)
    }

    /// Exact native instruction to sign; the challenge is already fixed and cannot be replaced.
    #[must_use]
    pub const fn instruction(&self) -> &MutateSorafsFinalPromotionAuthority {
        &self.instruction
    }

    /// Bind exactly one ordinary direct Check and retain its complete signed External bytes.
    ///
    /// # Errors
    /// Consumes the prepared challenge on expiry, size, account/network, instruction or signature
    /// mismatch. Signing and transport waits never reset the original interval.
    /// Every failure retains the exact signed graph and original preparation. Local refusals may
    /// retry only that same attempt; terminal rejection never reopens signing or renews its deadline.
    pub fn bind_signed_transaction(
        self,
        signed: SignedTransaction,
    ) -> Result<PendingFinalPromotionCheckV1, FinalPromotionCheckBindingFailureV1> {
        bind_signed_check_v1(self, SignedCheckAttempt::new(signed), Self::binding_scope)
            .map(|(prepared, bound)| PendingFinalPromotionCheckV1 { prepared, bound })
            .map_err(FinalPromotionCheckBindingFailureV1)
    }

    fn binding_scope(&mut self) -> Result<BindingScope<'_>, NativeCheckErrorV1> {
        Ok(BindingScope {
            state: &self.state,
            round: &mut self.round,
            instruction: NativeCustodyCheckRefV1::FinalPromotion(&self.instruction),
            chain_id: &self.expected.binding.chain_id,
            network_id: self.expected.binding.network_id,
            authority: &self.expected.observer,
            floor: self.expected.floor.coordinates(),
        })
    }
}

/// Exact original signed attempt retained after binding refusal.
/// Retry cannot replace the signer output, challenge, State pool, or original deadline.
#[must_use = "retain the original signed Check until binding completes or the attempt is retired"]
pub struct FinalPromotionCheckBindingFailureV1(
    BindingFailure<PreparedFinalPromotionCheckV1, Error>,
);

impl FinalPromotionCheckBindingFailureV1 {
    /// Borrow the original local refusal or completed rejection without erasing custody.
    #[must_use]
    pub fn error(&self) -> &NativeCheckBindingErrorV1<Error> {
        &self.0.error
    }

    /// Inspect a completed native rejection; local refusals have no transaction verdict.
    #[must_use]
    pub fn rejection(&self) -> Option<Error> {
        match &self.0.error {
            NativeCheckBindingErrorV1::Rejected(error) => Some(*error),
            _ => None,
        }
    }

    /// The unchanged absolute deadline, including after any number of local retries.
    #[must_use]
    pub fn deadline(&self) -> std::time::Instant {
        self.0.prepared.round.deadline()
    }

    /// Retry only this exact signed attempt; terminal failures return the same owner.
    ///
    /// # Errors
    /// Returns the unchanged signed custody and original rejection or latest local refusal.
    pub fn retry(self) -> Result<PendingFinalPromotionCheckV1, Self> {
        if !self.0.error.is_retryable() {
            return Err(self);
        }
        bind_signed_check_v1(
            self.0.prepared,
            self.0.signed,
            PreparedFinalPromotionCheckV1::binding_scope,
        )
        .map(|(prepared, bound)| PendingFinalPromotionCheckV1 { prepared, bound })
        .map_err(Self)
    }
}
impl std::fmt::Debug for FinalPromotionCheckBindingFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FinalPromotionCheckBindingFailureV1")
            .field("error", &self.0.error)
            .finish_non_exhaustive()
    }
}

impl PendingFinalPromotionCheckV1 {
    /// Original absolute deadline; no signing, binding or retry renews it.
    #[must_use]
    pub fn deadline(&self) -> std::time::Instant {
        self.prepared.round.deadline()
    }

    /// Exact signed envelope for ordinary native submission or reconciliation; no replacement API.
    #[must_use]
    pub fn signed_transaction(&self) -> &SignedTransaction {
        self.bound.signed_transaction()
    }

    /// Check the unchanged local interval while awaiting native application or ambiguous transport.
    ///
    /// # Errors
    /// Returns expiry; the caller must retire the attempt instead of creating a new deadline.
    pub fn ensure_live(&self) -> Result<(), Error> {
        self.prepared.round.ensure_live().map_err(Into::into)
    }

    /// Consume the attempt against its retained actual State, after native application is observed.
    ///
    /// `source` must match the Check phase. Reserved phases require the original signed Reserve;
    /// completed phases require both original signed Reserve and Complete. The independent floor
    /// must precede Reserve in either case.
    /// The callback supplies one independently established UTC interval after expensive proof work.
    /// Both endpoints must satisfy the shared custody and phase predicates at this same applied cut;
    /// this consumer does not qualify the clock source or derive its uncertainty from the candidate.
    /// Failed attempts retain the original signed owner and deadline. Local refusals may retry
    /// verification; transport reconciliation and semantic rejection remain separate decisions.
    ///
    /// # Errors
    /// Rejects expiry, missing exact application/finality, foreign committee continuity, changed
    /// signed envelope, rejected or misaligned result, unavailable clock, or current ineligibility.
    pub fn verify_finalized(
        self,
        source: FinalPromotionCheckSourceV1<'_>,
        sample_eligibility_time: impl FnOnce() -> Result<FinalPromotionEligibilityTimeIntervalV1, Error>,
    ) -> Result<VerifiedFinalPromotionCheckV1, FinalPromotionCheckAttemptFailureV1> {
        let Self {
            prepared,
            bound: original,
        } = self;
        let mut bound = Some(original);
        let result = (|| -> Result<_, crate::execution_attempt::ExecutionAttemptError<Error>> {
            enum PhaseSource<'a> {
                Current,
                Reserved(&'a FinalPromotionOperationRecordV1, &'a SignedTransaction),
                Completed {
                    row: &'a FinalPromotionOperationRecordV1,
                    reserve: &'a SignedTransaction,
                    complete: &'a SignedTransaction,
                },
            }
            prepared.round.ensure_live().map_err(Error::from)?;
            let p = &prepared;
            let phase_source = match (&p.expected.subject, source) {
                (
                    FinalPromotionCheckSubjectV1::Current(_),
                    FinalPromotionCheckSourceV1::Current,
                ) => PhaseSource::Current,
                (
                    FinalPromotionCheckSubjectV1::BeforeProvider(row)
                    | FinalPromotionCheckSubjectV1::AfterProvider(row)
                    | FinalPromotionCheckSubjectV1::BeforeCommit(row),
                    FinalPromotionCheckSourceV1::Reserved(signed),
                ) => PhaseSource::Reserved(row, signed),
                (
                    FinalPromotionCheckSubjectV1::AfterCommit(row)
                    | FinalPromotionCheckSubjectV1::BeforeRelease(row),
                    FinalPromotionCheckSourceV1::Completed { reserve, complete },
                ) => PhaseSource::Completed {
                    row,
                    reserve,
                    complete,
                },
                _ => return Err(Error::Execution.into()),
            };
            let cut = authenticate_applied_check_v1(
                &p.state,
                NativeCustodyCheckPurposeV1::FinalPromotion,
                &mut bound,
                &p.round,
            )
            .map_err(|error| error.map_rejection(Error::from))?;
            let view = cut.view();
            match phase_source {
                PhaseSource::Current => {}
                PhaseSource::Reserved(row, signed) => {
                    reserved_source::authenticate_reserved_source(
                        view,
                        p.expected.floor,
                        cut.applied_floor(),
                        row,
                        signed,
                        &p.round,
                    )?
                }
                PhaseSource::Completed {
                    row,
                    reserve,
                    complete,
                } => completed_source::authenticate_completed_source(
                    view,
                    p.expected.floor,
                    cut.applied_floor(),
                    row,
                    reserve,
                    complete,
                    &p.round,
                )?,
            }
            let eligibility_time_interval = sample_eligibility_time().map_err(|_| Error::Clock)?;
            let FinalPromotionEligibilityTimeIntervalV1 {
                earliest_unix_ms,
                latest_unix_ms,
            } = eligibility_time_interval;
            if earliest_unix_ms == 0
                || earliest_unix_ms > latest_unix_ms
                || latest_unix_ms == u64::MAX
            {
                return Err(Error::Clock.into());
            }
            p.round.ensure_live().map_err(Error::from)?;
            let snapshot = check_applied_snapshot_v1(
                view,
                &p.instruction,
                &p.expected.binding,
                &p.expected.observer,
                earliest_unix_ms,
            )
            .map_err(|_| Error::Authority)?;
            p.round.ensure_live().map_err(Error::from)?;
            // Reuse this exact native snapshot; do not repeat history traversal or capture a newer cut.
            // The shared owner rejects not-yet-valid lower bounds and expired upper bounds alike.
            // The earliest bound is also the observation time; uncertainty consumes anchor age.
            check_snapshot_eligibility_v1(
                &snapshot,
                &p.instruction,
                &p.expected.binding,
                &p.expected.observer,
                latest_unix_ms,
                earliest_unix_ms,
            )
            .map_err(|_| Error::Authority)?;
            p.round.ensure_live().map_err(Error::from)?;
            let check_height = cut.check_height();
            let native_floor = cut.applied_floor();
            let applied_floor = FinalPromotionCheckFloorV1 {
                height: native_floor.height,
                block_hash: native_floor.block_hash,
                context_id: native_floor.context_id,
            };
            let entry_hash = cut.entry_hash();
            let (canonical_external, check_block_hash) = cut.into_verified_entry();

            Ok((
                snapshot,
                check_height,
                applied_floor,
                entry_hash,
                canonical_external,
                check_block_hash,
                eligibility_time_interval,
            ))
        })();
        let (
            snapshot,
            check_height,
            applied_floor,
            entry_hash,
            canonical_external,
            check_block_hash,
            eligibility_time_interval,
        ) = match result {
            Ok(parts) => parts,
            Err(error) => {
                return Err(FinalPromotionCheckAttemptFailureV1 {
                    error,
                    pending: Self {
                        prepared,
                        bound: bound
                            .take()
                            .expect("failed verification retains original binding"),
                    },
                });
            }
        };
        let p = prepared;
        Ok(VerifiedFinalPromotionCheckV1 {
            observer: p.expected.observer,
            expected_operator: p.expected.expected_operator,
            instruction: p.instruction,
            snapshot,
            check_height,
            original_floor: p.expected.floor,
            applied_floor,
            entry_hash,
            canonical_external,
            check_block_hash,
            eligibility_time_interval,
            round: p.round,
        })
    }
}

impl VerifiedFinalPromotionCheckV1 {
    /// Independently pinned observer whose current Check permission was rechecked.
    #[must_use]
    pub const fn observer(&self) -> &AccountId {
        &self.observer
    }
    /// Original operation account whose current Operate permission was rechecked.
    #[must_use]
    pub const fn expected_operator(&self) -> &AccountId {
        &self.expected_operator
    }
    /// Exact one-use challenge, request, phase and control CAS authenticated by this success.
    #[must_use]
    pub const fn instruction(&self) -> &MutateSorafsFinalPromotionAuthority {
        &self.instruction
    }
    /// Raw snapshot from the exact authenticated applied cut, not a renewable freshness certificate.
    /// Production phase consumers must call `ensure_live` immediately before using this result.
    #[must_use]
    pub const fn snapshot(&self) -> &FinalPromotionAuthoritySnapshotV1 {
        &self.snapshot
    }
    /// Height of the exact signed Check and its aligned successful execution result.
    #[must_use]
    pub const fn check_height(&self) -> u64 {
        self.check_height
    }
    /// Exact canonical signed External bytes whose aligned successful result was authenticated.
    /// Borrowing historical execution material grants no renewed eligibility or authority.
    #[must_use]
    pub fn canonical_external(&self) -> &[u8] {
        self.canonical_external.as_slice()
    }
    /// Exact authenticated block hash at `check_height`, distinct from a later applied floor.
    #[must_use]
    pub const fn check_block_hash(&self) -> [u8; 32] {
        self.check_block_hash
    }
    /// Exact independent trust floor used for this original proof, including its committee pin.
    /// Retention does not authenticate how the caller provisioned that floor or renew this round.
    #[must_use]
    pub const fn original_floor(&self) -> FinalPromotionCheckFloorV1 {
        self.original_floor
    }
    /// Authenticated applied descendant floor, suitable for retaining continuity across rounds.
    #[must_use]
    pub const fn applied_floor(&self) -> FinalPromotionCheckFloorV1 {
        self.applied_floor
    }
    /// Exact signed intent's native entrypoint membership identity.
    #[must_use]
    pub const fn entry_hash(&self) -> HashOf<TransactionEntrypoint> {
        self.entry_hash
    }
    /// Exact independently supplied UTC interval checked after proof work at this same State cut.
    /// This preserves both uncertainty endpoints; success does not qualify the clock source.
    /// A production source must retain the earliest observation bound for later age checks and
    /// resample after blocking persistence. A later sample must not refresh this observation time.
    #[must_use]
    pub const fn eligibility_time_interval(&self) -> FinalPromotionEligibilityTimeIntervalV1 {
        self.eligibility_time_interval
    }
    /// Recheck time eligibility against this exact retained authenticated snapshot.
    ///
    /// Both independently supplied UTC endpoints must remain eligible under the original
    /// observation's earliest bound and unchanged local deadline. This neither samples or
    /// qualifies a clock, observes newer state, nor proves absence of a later revocation.
    /// Callers must still obtain a fresh Check for each required observation phase.
    ///
    /// # Errors
    /// Rejects expiry, malformed or backward intervals, excess original observation age,
    /// and custody or phase ineligibility. No success or failure renews this capability.
    pub fn recheck_use_interval(
        &self,
        interval: FinalPromotionEligibilityTimeIntervalV1,
    ) -> Result<(), Error> {
        self.ensure_live()?;
        let FinalPromotionEligibilityTimeIntervalV1 {
            earliest_unix_ms,
            latest_unix_ms,
        } = interval;
        let observed_at = self.eligibility_time_interval.earliest_unix_ms;
        if earliest_unix_ms == 0
            || earliest_unix_ms < observed_at
            || earliest_unix_ms > latest_unix_ms
            || latest_unix_ms == u64::MAX
        {
            return Err(Error::Clock);
        }
        for now in [earliest_unix_ms, latest_unix_ms] {
            self.ensure_live()?;
            check_snapshot_eligibility_v1(
                &self.snapshot,
                &self.instruction,
                &self.snapshot.control.policy.binding,
                &self.observer,
                now,
                observed_at,
            )
            .map_err(|_| Error::Authority)?;
        }
        self.ensure_live()
    }

    /// Check the original interval immediately before using this success for its pinned phase.
    ///
    /// # Errors
    /// Returns expiry; this never renews authority or proves absence of a subsequent revocation.
    pub fn ensure_live(&self) -> Result<(), Error> {
        self.round.ensure_live().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;

mod attempt_failure;
pub use attempt_failure::FinalPromotionCheckAttemptFailureV1;
