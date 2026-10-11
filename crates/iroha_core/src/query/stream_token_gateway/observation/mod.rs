//! One-use challenged gateway readback from exact native execution and one immutable State view.
//!
//! Decoded results, callback acknowledgements and observer signatures cannot construct these
//! capabilities. Serving is a separate purpose, consumed only after callback reconciliation.
//! The native envelope profile uses Ed25519 single-signature accounts. Historical certificates
//! are checked in one ascending walk per verification, bounded to 64 MiB of certificate frames.

pub use crate::query::signer_check::NativeCheckBindingErrorV1;

use std::{sync::Arc, time::Instant};

use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::sorafs::MutateSorafsStreamTokenGateway,
    sorafs::stream_token_gateway::{
        StreamTokenGatewayAdmissionDeliveryStateV1 as Delivery,
        StreamTokenGatewayAdmissionQualificationV1 as Qualification,
        StreamTokenGatewayAdmissionReadbackV1 as Readback,
        StreamTokenGatewayAdmissionRecordV1 as Record,
        StreamTokenGatewayAdmissionRequestV1 as Request,
        StreamTokenGatewayAdmissionResultV1 as AdmissionResult,
        native::{
            StreamTokenGatewayActionV1 as Action, StreamTokenGatewayCheckSubjectV1 as Subject,
            StreamTokenGatewayCheckV1 as Check, StreamTokenGatewayExecutionV1 as Execution,
            StreamTokenGatewayFinalityFloorV1 as Floor, StreamTokenGatewayRequestV1,
            stream_token_gateway_pending_readback_digest_v1,
        },
    },
    transaction::{SignedTransaction, TransactionEntrypoint},
};

use super::{
    check::{self, GatewayCheckedValueV1 as Value},
    rows::{GatewayRow, GatewayRowKey, GatewayRows},
    storage::{self, WorldGatewayRows},
    transition,
};
use crate::{
    query::signer_check::{
        BindingFailure, BindingScope, BoundNativeCheckV1, NativeCheckErrorV1, NativeCheckFloorV1,
        NativeCheckRoundV1, NativeCustodyCheckRefV1, SignedCheckAttempt, bind_signed_check_v1,
        validate_native_signatory_v1,
    },
    state::{State, StateReadOnly, StateView, WorldReadOnly, is_stable_state_view_generation},
};

/// Independently requested readback purpose. Admission is historical; Serving is current authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamTokenGatewayCheckSelectorV1 {
    /// Exact currently configured gateway qualification.
    Qualification,
    /// Original immutable result of this complete physical serving attempt.
    Admission(Request),
    /// Accepted, callback-acknowledged and still-live grant for this same physical serving attempt.
    Serving(Request),
    /// Complete bounded oldest-pending prefix, including authenticated emptiness.
    Pending {
        /// Maximum prefix length, from one through the native reconciliation item limit.
        max_items: u32,
    },
    /// Exact original record has a permanent ordered acknowledgement.
    Acknowledged(Record),
    /// Exact original grant has a permanent release or expiry terminal.
    Released(Record),
}
use StreamTokenGatewayCheckSelectorV1 as Selector;

/// Independent policy and account pins; data supplied here never constitutes proof.
pub struct StreamTokenGatewayCheckExpectedV1 {
    /// Network independently selected by the local daemon configuration.
    pub network_id: NetworkId,
    /// Complete current policy qualification, including revision and commitment.
    pub qualification: Qualification,
    /// Registered policy operator with the exact gateway operation permission.
    pub operator: AccountId,
    /// Independent registered policy observer with the exact gateway Check permission.
    pub observer: AccountId,
    /// Original request/record or bounded readback selector retained by the caller.
    pub selector: Selector,
}

/// Closed UTC uncertainty interval sampled after native execution proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamTokenGatewayEligibilityTimeV1 {
    /// Earliest possible current Unix millisecond, strictly positive.
    pub earliest_unix_ms: u64,
    /// Latest possible current Unix millisecond, below `u64::MAX`.
    pub latest_unix_ms: u64,
}
use StreamTokenGatewayEligibilityTimeV1 as Time;

/// Payload-free failure of an original one-use gateway observation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StreamTokenGatewayObservationErrorV1 {
    /// Invalid independent expectations, profile or bound.
    #[error("invalid gateway Check expectations")]
    Invalid,
    /// Original monotonic deadline expired.
    #[error("gateway Check expired")]
    Expired,
    /// Fresh operating-system entropy was unavailable.
    #[error("gateway Check entropy unavailable")]
    Entropy,
    /// Signed transaction differs from the exact native prepared Check.
    #[error("gateway Check signed transaction mismatch")]
    Transaction,
    /// Exact signed Check has not applied to this node's State.
    #[error("gateway Check not applied")]
    NotApplied,
    /// Original certified history or pinned floor is unavailable.
    #[error("gateway Check finality unavailable")]
    Finality,
    /// An original mutation or challenged Check did not execute successfully as claimed.
    #[error("gateway Check execution rejected")]
    Execution,
    /// Current same-cut policy, permission, record or lease predicate changed.
    #[error("gateway Check current authority rejected")]
    Authority,
    /// Independent UTC interval is unavailable or malformed.
    #[error("gateway Check clock unavailable")]
    Clock,
}
use StreamTokenGatewayObservationErrorV1 as Error;
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
fn native_floor(floor: Floor) -> NativeCheckFloorV1 {
    NativeCheckFloorV1 {
        height: floor.height,
        block_hash: floor.block_hash,
        context_id: floor.context_id,
    }
}
fn validate_time(time: Time) -> Result<(), Error> {
    if time.earliest_unix_ms == 0
        || time.latest_unix_ms < time.earliest_unix_ms
        || time.latest_unix_ms == u64::MAX
    {
        return Err(Error::Clock);
    }
    Ok(())
}

/// Move-only fresh challenge; its deadline starts before capture and cannot be renewed.
#[must_use = "sign this exact gateway Check within its original observation lifetime"]
pub struct PreparedStreamTokenGatewayCheckV1 {
    state: Arc<State>,
    expected: StreamTokenGatewayCheckExpectedV1,
    instruction: MutateSorafsStreamTokenGateway,
    chain_id: String,
    round: NativeCheckRoundV1,
    // Same-cut scheduling hint only. It cannot authenticate empty readback or grant authority.
    pending_is_empty: Option<bool>,
    // A successful observation establishes this floor for every later local retry.
    accepted_earliest_unix_ms: Option<u64>,
}
/// Move-only exact signed Check and its original monotonic lifetime.
#[must_use = "submit and consume this exact signed gateway Check once"]
pub struct PendingStreamTokenGatewayCheckV1 {
    prepared: PreparedStreamTokenGatewayCheckV1,
    bound: BoundNativeCheckV1,
}
/// Readback available only behind a successfully verified native Check capability.
pub enum StreamTokenGatewayCheckReadbackV1 {
    /// Current authenticated policy qualification.
    Qualification(Qualification),
    /// Historical exact original admission result, without current serving authority.
    Admission(AdmissionResult),
    /// Exact Accepted, acknowledged and live grant at the authenticated observation cut.
    Serving(AdmissionResult),
    /// Complete exact oldest-pending prefix, possibly empty.
    Pending(Readback),
    /// Exact permanently acknowledged original record.
    Acknowledged(Record),
    /// Exact permanently terminal original grant.
    Released(Record),
}
enum VerifiedOrigin {
    Acknowledgement(Execution),
    LeaseTerminal { execution: Execution, expired: bool },
}

/// Move-only verified readback scoped to its original subject and deadline.
#[must_use = "consume the verified gateway Check only for its original purpose"]
pub struct VerifiedStreamTokenGatewayCheckV1 {
    prepared: PreparedStreamTokenGatewayCheckV1,
    bound: BoundNativeCheckV1,
    generation: u64,
    origin: Option<VerifiedOrigin>,
    readback: StreamTokenGatewayCheckReadbackV1,
    applied_floor: Floor,
    entry_hash: HashOf<TransactionEntrypoint>,
    check_block_hash: [u8; 32],
    time: Time,
}

fn validate_expected(expected: &StreamTokenGatewayCheckExpectedV1) -> Result<(), Error> {
    expected
        .qualification
        .validate()
        .map_err(|_| Error::Invalid)?;
    if expected.network_id.as_bytes() == &[0; 32]
        || expected.operator == expected.observer
        || validate_native_signatory_v1(&expected.operator).is_err()
        || validate_native_signatory_v1(&expected.observer).is_err()
    {
        return Err(Error::Invalid);
    }
    match &expected.selector {
        Selector::Admission(request) | Selector::Serving(request) => {
            request.validate().map_err(|_| Error::Invalid)?;
            transition::request_digest(request).map_err(|_| Error::Invalid)?;
        }
        Selector::Acknowledged(record) | Selector::Released(record) => {
            record.validate_shape(expected.qualification).map_err(|_| Error::Invalid)?;
        }
        Selector::Pending { max_items }
            if *max_items == 0 || *max_items > iroha_data_model::sorafs::stream_token_gateway::STREAM_TOKEN_GATEWAY_RECONCILE_MAX_ITEMS_V1 => return Err(Error::Invalid),
        Selector::Pending { .. } | Selector::Qualification => {}
    }
    Ok(())
}

fn capture_subject(
    view: &StateView<'_>,
    expected: &StreamTokenGatewayCheckExpectedV1,
    now_ms: u64,
) -> Result<Subject, Error> {
    let current = storage::read_current(
        view.world(),
        &expected.network_id,
        expected.qualification.gateway_id,
    )
    .map_err(|_| Error::Authority)?
    .ok_or(Error::Authority)?;
    if current.policy.policy.qualification != expected.qualification {
        return Err(Error::Authority);
    }
    let rows = WorldGatewayRows::new(
        view.world(),
        &expected.network_id,
        expected.qualification.gateway_id,
    )
    .map_err(|_| Error::Authority)?;
    match &expected.selector {
        Selector::Qualification => Ok(Subject::Qualification),
        Selector::Admission(request) | Selector::Serving(request) => {
            let context_digest = request.context.digest().map_err(|_| Error::Invalid)?;
            let Some(GatewayRow::Context(context)) = rows
                .read(&GatewayRowKey::Context(context_digest))
                .map_err(|_| Error::Authority)?
            else {
                return Err(Error::Authority);
            };
            let request_digest = transition::request_digest(request).map_err(|_| Error::Invalid)?;
            if context.request_digest != request_digest {
                return Err(Error::Authority);
            }
            let original = check::read_admission(view, &current, context.sequence, now_ms)
                .map_err(|_| Error::Authority)?;
            if original.request != *request {
                return Err(Error::Authority);
            }
            let result = AdmissionResult {
                record: original.record,
                delivery_state: if context.sequence
                    <= current.head.head.acknowledged_through_sequence
                {
                    Delivery::AcknowledgedExactReplay {
                        acknowledged_through_sequence: current
                            .head
                            .head
                            .acknowledged_through_sequence,
                    }
                } else {
                    Delivery::Pending {
                        predecessor_sequence: context
                            .sequence
                            .checked_sub(1)
                            .ok_or(Error::Authority)?,
                    }
                },
            };
            result
                .validate_for_request(request, expected.qualification)
                .map_err(|_| Error::Authority)?;
            Ok(if matches!(expected.selector, Selector::Serving(_)) {
                Subject::Serving {
                    request_digest,
                    result,
                }
            } else {
                Subject::Admission {
                    request_digest,
                    result,
                }
            })
        }
        Selector::Pending { max_items } => {
            let readback = check::read_pending(view, &current, *max_items, now_ms)
                .map_err(|_| Error::Authority)?;
            let readback_digest = stream_token_gateway_pending_readback_digest_v1(
                expected.qualification,
                *max_items,
                &readback,
            )
            .map_err(|_| Error::Authority)?;
            Ok(Subject::Pending {
                max_items: *max_items,
                readback_digest,
            })
        }
        Selector::Acknowledged(record) => Ok(Subject::Acknowledged { record: *record }),
        Selector::Released(record) => Ok(Subject::Released { record: *record }),
    }
}

/// Start one challenge before capturing any floor or subject from State.
///
/// Pass the same absolute deadline established before the enclosing HTTP admission to every
/// phase. Construction does not grant another duration after callback or network latency.
///
/// # Errors
/// Rejects invalid pins, entropy failure, missing exact rows/finality, or the original deadline.
pub fn begin_stream_token_gateway_check_v1(
    state: Arc<State>,
    expected: StreamTokenGatewayCheckExpectedV1,
    deadline: Instant,
) -> Result<PreparedStreamTokenGatewayCheckV1, Error> {
    let mut round = NativeCheckRoundV1::start_until(deadline)?;
    validate_expected(&expected)?;
    let challenge = round.issue_challenge()?;
    let view = state.view();
    if view.network_id() != &expected.network_id {
        return Err(Error::Invalid);
    }
    let height = u64::try_from(view.block_hashes().len()).map_err(|_| Error::Finality)?;
    let block_hash = view
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or(Error::Finality)?;
    let finality =
        crate::query::signer_finality::verify_signer_finality_v1(&view, height, block_hash)
            .map_err(|_| Error::Finality)?;
    round.ensure_live()?;
    let floor = Floor {
        height,
        block_hash,
        context_id: finality.context_id(),
    };
    let now_ms = crate::sumeragi::certified_chain::committed_block(&view, height)
        .map_err(|_| Error::Finality)?
        .block_time_ms();
    let subject = capture_subject(&view, &expected, now_ms)?;
    let instruction = MutateSorafsStreamTokenGateway {
        request: StreamTokenGatewayRequestV1 {
            network_id: expected.network_id,
            gateway_id: expected.qualification.gateway_id,
            expected_policy_revision: expected.qualification.revision,
            expected_policy_digest: expected.qualification.policy_digest,
            action: Action::Check(Check {
                challenge,
                expected_operator: expected.operator.clone(),
                expected_observer: expected.observer.clone(),
                floor,
                subject,
            }),
        },
    };
    instruction.request.validate().map_err(|_| Error::Invalid)?;
    let current = check::evaluate_current(&view, &instruction.request, now_ms)
        .map_err(|_| Error::Authority)?;
    let pending_is_empty = match current.value {
        Value::Pending(readback) => Some(readback.records.is_empty()),
        _ => None,
    };
    let chain_id = view.chain_id().to_string();
    round.ensure_live()?;
    drop(view);
    Ok(PreparedStreamTokenGatewayCheckV1 {
        state,
        expected,
        instruction,
        chain_id,
        round,
        pending_is_empty,
        accepted_earliest_unix_ms: None,
    })
}

/// Begin a fresh historical Admission proof for one independently retained complete source record.
///
/// The original request is read from native State only to prepare a challenged assertion. Its exact
/// signed Admit and source-time policy must subsequently authenticate before delivery consumption.
/// This selector construction never grants signing authority or resets the supplied deadline.
///
/// # Errors
/// Rejects a missing/substituted original, malformed pins, unavailable finality or elapsed deadline.
pub fn begin_stream_token_reputation_delivery_v1(
    state: Arc<State>,
    network_id: NetworkId,
    qualification: Qualification,
    operator: AccountId,
    observer: AccountId,
    original: Record,
    deadline: Instant,
) -> Result<PreparedStreamTokenGatewayCheckV1, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Expired);
    }
    let request = {
        let view = state.view();
        if view.network_id() != &network_id
            || original.admitted_under.gateway_id != qualification.gateway_id
        {
            return Err(Error::Authority);
        }
        let rows = WorldGatewayRows::new(view.world(), &network_id, qualification.gateway_id)
            .map_err(|_| Error::Execution)?;
        let Some(GatewayRow::Admission(row)) = rows
            .read(&GatewayRowKey::Admission(
                original.outcome.binding.gateway_sequence,
            ))
            .map_err(|_| Error::Execution)?
        else {
            return Err(Error::Execution);
        };
        if row.record != original {
            return Err(Error::Authority);
        }
        row.request
    };
    begin_stream_token_gateway_check_v1(
        state,
        StreamTokenGatewayCheckExpectedV1 {
            network_id,
            qualification,
            operator,
            observer,
            selector: Selector::Admission(request),
        },
        deadline,
    )
}

/// Borrowed one-use delivery decision held inside a verified State publication lease.
///
/// Only the exact unexpired Pending payload is available for a synchronous operation with an
/// already-loaded original recorder credential. The holder must not perform filesystem, network,
/// queue, callback reconciliation or waiting inside the capture closure. Terminal/expiry data never
/// grants permission to manufacture a replacement payload or claim an append succeeded.
pub struct VerifiedStreamTokenReputationDeliveryV1<'a> {
    source: &'a crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::Source,
    disposition: &'a iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1,
    may_append: bool,
    needs_terminal_check: bool,
}
impl VerifiedStreamTokenReputationDeliveryV1<'_> {
    /// Exact immutable unsigned intent, present only when current source authority permits signing.
    #[must_use]
    pub fn append_intent(&self) -> Option<&iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryIntentV1>{
        self.may_append
            .then_some(self.source.intent.as_ref())
            .flatten()
    }
    /// Authenticated original disposition. Pending does not mean a callback has succeeded.
    #[must_use]
    pub fn disposition(&self) -> &iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1{
        self.disposition
    }
    /// Pending cannot be signed at the current clock endpoint; native Ack must prove any expiry.
    #[must_use]
    pub const fn needs_terminal_check(&self) -> bool {
        self.needs_terminal_check
    }
}

impl PreparedStreamTokenGatewayCheckV1 {
    /// Same-cut pending emptiness, solely for deciding whether to schedule background recovery.
    ///
    /// `Some(true)` permits dropping this unsent preparation without claiming an authenticated
    /// empty result. It cannot qualify startup, acknowledge delivery, or authorize serving.
    /// Other selectors return `None`. Nonempty work still requires this exact signed Check.
    ///
    /// # Errors
    /// Refuses the hint after this original preparation's deadline has expired.
    pub fn pending_is_empty(&self) -> Result<Option<bool>, Error> {
        self.ensure_live()?;
        Ok(self.pending_is_empty)
    }

    /// Original absolute HTTP/operation deadline, unchanged by capture or signing.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.round.deadline()
    }

    /// Exact native instruction containing the fresh challenge and captured floor/subject.
    #[must_use]
    pub const fn instruction(&self) -> &MutateSorafsStreamTokenGateway {
        &self.instruction
    }
    /// Check the unchanged original monotonic lifetime.
    ///
    /// # Errors
    /// Returns expiry without renewing the attempt.
    pub fn ensure_live(&self) -> Result<(), Error> {
        self.round.ensure_live().map_err(Into::into)
    }
    /// Bind one exact single-instruction signed observer transaction, consuming preparation.
    ///
    /// # Errors
    /// Rejects signed body, authority, network, floor, size or deadline substitution.
    /// Every failure retains the exact signed graph and original preparation. Local refusals may
    /// retry only that same attempt; terminal rejection never reopens signing or renews its deadline.
    pub fn bind_signed_transaction(
        self,
        signed: SignedTransaction,
    ) -> Result<PendingStreamTokenGatewayCheckV1, StreamTokenGatewayCheckBindingFailureV1> {
        bind_signed_check_v1(self, SignedCheckAttempt::new(signed), Self::binding_scope)
            .map(|(prepared, bound)| PendingStreamTokenGatewayCheckV1 { prepared, bound })
            .map_err(StreamTokenGatewayCheckBindingFailureV1)
    }

    fn binding_scope(&mut self) -> Result<BindingScope<'_>, NativeCheckErrorV1> {
        let Action::Check(check) = &self.instruction.request.action else {
            return Err(NativeCheckErrorV1::Invalid);
        };
        Ok(BindingScope {
            state: &self.state,
            round: &mut self.round,
            instruction: NativeCustodyCheckRefV1::StreamTokenGateway(&self.instruction),
            chain_id: &self.chain_id,
            network_id: *self.expected.network_id.as_bytes(),
            authority: &self.expected.observer,
            floor: native_floor(check.floor),
        })
    }
}

fn public_readback(
    value: Value,
    qualification: Qualification,
) -> StreamTokenGatewayCheckReadbackV1 {
    match value {
        Value::Qualification => StreamTokenGatewayCheckReadbackV1::Qualification(qualification),
        Value::Admission(result) => StreamTokenGatewayCheckReadbackV1::Admission(result),
        Value::Serving(result) => StreamTokenGatewayCheckReadbackV1::Serving(result),
        Value::Pending(readback) => StreamTokenGatewayCheckReadbackV1::Pending(readback),
        Value::Acknowledged(record) => StreamTokenGatewayCheckReadbackV1::Acknowledged(record),
        Value::Released(record) => StreamTokenGatewayCheckReadbackV1::Released(record),
    }
}
fn verified_origin(
    view: &StateView<'_>,
    instruction: &MutateSorafsStreamTokenGateway,
) -> Result<Option<VerifiedOrigin>, Error> {
    let Action::Check(check) = &instruction.request.action else {
        return Err(Error::Invalid);
    };
    let rows = WorldGatewayRows::new(
        view.world(),
        &instruction.request.network_id,
        instruction.request.gateway_id,
    )
    .map_err(|_| Error::Execution)?;
    match &check.subject {
        Subject::Acknowledged { record } => {
            let Some(GatewayRow::Acknowledgement(row)) = rows
                .read(&GatewayRowKey::Acknowledgement(
                    record.outcome.binding.gateway_sequence,
                ))
                .map_err(|_| Error::Execution)?
            else {
                return Err(Error::Execution);
            };
            if row.record != *record {
                return Err(Error::Execution);
            }
            Ok(Some(VerifiedOrigin::Acknowledgement(row.execution)))
        }
        Subject::Released { record } => {
            let Some(GatewayRow::LeaseTerminal(row)) = rows
                .read(&GatewayRowKey::LeaseTerminal(
                    record.lease_id.ok_or(Error::Execution)?,
                ))
                .map_err(|_| Error::Execution)?
            else {
                return Err(Error::Execution);
            };
            if row.grant.sequence != record.outcome.binding.gateway_sequence {
                return Err(Error::Execution);
            }
            Ok(Some(VerifiedOrigin::LeaseTerminal {
                execution: row.execution,
                expired: row.expired,
            }))
        }
        _ => Ok(None),
    }
}

/// Exact original signed attempt retained after binding refusal.
/// Retry cannot replace the signer output, challenge, State pool, or original deadline.
#[must_use = "retain the original signed Check until binding completes or the attempt is retired"]
pub struct StreamTokenGatewayCheckBindingFailureV1(
    BindingFailure<PreparedStreamTokenGatewayCheckV1, Error>,
);

impl StreamTokenGatewayCheckBindingFailureV1 {
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
    pub fn retry(self) -> Result<PendingStreamTokenGatewayCheckV1, Self> {
        if !self.0.error.is_retryable() {
            return Err(self);
        }
        bind_signed_check_v1(
            self.0.prepared,
            self.0.signed,
            PreparedStreamTokenGatewayCheckV1::binding_scope,
        )
        .map(|(prepared, bound)| PendingStreamTokenGatewayCheckV1 { prepared, bound })
        .map_err(Self)
    }
}
impl std::fmt::Debug for StreamTokenGatewayCheckBindingFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamTokenGatewayCheckBindingFailureV1")
            .field("error", &self.0.error)
            .finish_non_exhaustive()
    }
}

impl PendingStreamTokenGatewayCheckV1 {
    /// Original absolute deadline, unchanged by signed binding or submission.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.prepared.deadline()
    }

    /// Exact signed transaction for submission/reconciliation; this does not prove execution.
    #[must_use]
    pub fn signed_transaction(&self) -> &SignedTransaction {
        self.bound.signed_transaction()
    }
    /// Check the unchanged original monotonic lifetime before waiting or submitting again.
    ///
    /// # Errors
    /// Returns expiry without renewing the attempt.
    pub fn ensure_live(&self) -> Result<(), Error> {
        self.prepared.ensure_live()
    }
    /// Consume same-view signed execution/history and current authority after proof completion.
    ///
    /// # Errors
    /// Any missing proof, changed row/permission/policy, invalid UTC interval or deadline returns
    /// the attempt to the caller unchanged. Both clock endpoints must satisfy the original subject.
    pub fn verify_finalized(
        self,
        sample_time: impl FnOnce() -> Result<Time, Error>,
    ) -> Result<VerifiedStreamTokenGatewayCheckV1, StreamTokenGatewayCheckAttemptFailureV1> {
        let Self {
            mut prepared,
            bound: original,
        } = self;
        let mut bound = Some(original);
        let result = (|| -> Result<_, crate::execution_attempt::ExecutionAttemptError<Error>> {
            prepared.round.ensure_live().map_err(Error::from)?;
            let generation = prepared.state.state_view_generation();
            let view = prepared.state.view();
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            let cut = history::authenticate(&view, &prepared, &mut bound)?;
            prepared.round.ensure_live().map_err(Error::from)?;
            let time = sample_time().map_err(|_| Error::Clock)?;
            validate_time(time)?;
            if prepared
                .accepted_earliest_unix_ms
                .is_some_and(|floor| time.earliest_unix_ms < floor)
            {
                return Err(Error::Clock.into());
            }
            let snapshot = check::evaluate_current(
                cut.view(),
                &prepared.instruction.request,
                time.earliest_unix_ms,
            )
            .map_err(|_| Error::Authority)?;
            check::evaluate_current(
                cut.view(),
                &prepared.instruction.request,
                time.latest_unix_ms,
            )
            .map_err(|_| Error::Authority)?;
            prepared.round.ensure_live().map_err(Error::from)?;
            let floor = cut.applied_floor();
            let applied_floor = Floor {
                height: floor.height,
                block_hash: floor.block_hash,
                context_id: floor.context_id,
            };
            let entry_hash = cut.entry_hash();
            let origin = verified_origin(cut.view(), &prepared.instruction)?;
            let check_block_hash = cut.check_block_hash();
            let readback = public_readback(snapshot.value, prepared.expected.qualification);
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            drop(cut);
            drop(view);
            Ok((
                generation,
                origin,
                readback,
                applied_floor,
                entry_hash,
                check_block_hash,
                time,
            ))
        })();
        let (generation, origin, readback, applied_floor, entry_hash, check_block_hash, time) =
            match result {
                Ok(verified) => verified,
                Err(error) => {
                    return Err(StreamTokenGatewayCheckAttemptFailureV1 {
                        error,
                        pending: Self {
                            prepared,
                            bound: bound
                                .take()
                                .expect("original binding survives failed verification"),
                        },
                    });
                }
            };
        prepared.accepted_earliest_unix_ms = Some(time.earliest_unix_ms);
        Ok(VerifiedStreamTokenGatewayCheckV1 {
            prepared,
            bound: bound.take().expect("verified original binding"),
            generation,
            origin,
            readback,
            applied_floor,
            entry_hash,
            check_block_hash,
            time,
        })
    }
}

impl VerifiedStreamTokenGatewayCheckV1 {
    /// Original absolute deadline; proof completion does not create another interval.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.prepared.round.deadline()
    }

    /// Exact subject-specific authenticated data. Admission alone never authorizes serving.
    #[must_use]
    pub const fn readback(&self) -> &StreamTokenGatewayCheckReadbackV1 {
        &self.readback
    }
    /// Original successful native Acknowledge execution, only for an Acknowledged Check.
    /// Compare its transaction hash with the exact submitted External entry to distinguish
    /// the first mutation from a later no-op retry; a raw row cannot construct this capability.
    #[must_use]
    pub fn acknowledgement_execution(&self) -> Option<&Execution> {
        match &self.origin {
            Some(VerifiedOrigin::Acknowledgement(execution)) => Some(execution),
            _ => None,
        }
    }
    /// Original lease-terminal execution and whether it was deterministic expiry.
    /// Present only for a Released Check; an expiry or different originating transaction means
    /// a subsequently submitted explicit release was an exact replay.
    #[must_use]
    pub fn lease_terminal_execution(&self) -> Option<(&Execution, bool)> {
        match &self.origin {
            Some(VerifiedOrigin::LeaseTerminal { execution, expired }) => {
                Some((execution, *expired))
            }
            _ => None,
        }
    }
    /// Actual final applied cut of the successful Check and all current predicates.
    #[must_use]
    pub const fn applied_floor(&self) -> Floor {
        self.applied_floor
    }
    /// Exact successful signed Check identity.
    #[must_use]
    pub const fn entry_hash(&self) -> HashOf<TransactionEntrypoint> {
        self.entry_hash
    }
    /// Canonical signed External entry authenticated by the native output proof.
    #[must_use]
    pub fn canonical_external(&self) -> &[u8] {
        self.bound.canonical_external()
    }
    /// Certified block containing the exact successful Check.
    #[must_use]
    pub const fn check_block_hash(&self) -> [u8; 32] {
        self.check_block_hash
    }
    /// Original post-proof uncertainty interval; later calls do not refresh it.
    #[must_use]
    pub const fn time_interval(&self) -> Time {
        self.time
    }
    /// Exact challenged native instruction.
    #[must_use]
    pub const fn instruction(&self) -> &MutateSorafsStreamTokenGateway {
        &self.prepared.instruction
    }
    /// Check the original monotonic lifetime before consuming readback.
    ///
    /// # Errors
    /// Returns expiry without extending this capability.
    pub fn ensure_live(&self) -> Result<(), Error> {
        self.prepared.round.ensure_live().map_err(Into::into)
    }
    /// Consume one historical Admission proof for exact native reputation delivery custody.
    ///
    /// Reauthenticate the original signed Check, source policy, Admit and any terminal execution
    /// before taking the publication lease. Under the lease, use only current in-memory rows,
    /// permissions and the original lifetime. The short closure may copy the exact payload or use
    /// an already-loaded credential synchronously; it must not perform I/O, queue work or reentry.
    /// Core Append later rechecks the immutable envelope and current permission after publication.
    ///
    /// # Errors
    /// Rejects another purpose/source, changed State, missing durable evidence, stale permission,
    /// malformed clock or the original elapsed monotonic deadline. It never renews that deadline.
    pub fn consume_for_reputation_delivery<T>(
        self,
        original: &Record,
        sample_time: impl FnOnce() -> Result<Time, Error>,
        capture: impl FnOnce(VerifiedStreamTokenReputationDeliveryV1<'_>) -> T,
    ) -> Result<T, StreamTokenGatewayCheckAttemptFailureV1> {
        let Self {
            prepared,
            bound: original_bound,
            generation,
            readback,
            applied_floor,
            time: time_at_verification,
            ..
        } = self;
        let mut bound = Some(original_bound);
        let result = (|| -> Result<T, crate::execution_attempt::ExecutionAttemptError<Error>> {
            use iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1 as Disposition;
            prepared.round.ensure_live().map_err(Error::from)?;
            let Selector::Admission(request) = &prepared.expected.selector else {
                return Err(Error::Authority.into());
            };
            let StreamTokenGatewayCheckReadbackV1::Admission(result) = readback else {
                return Err(Error::Authority.into());
            };
            if result.record != *original {
                return Err(Error::Authority.into());
            }
            result
                .validate_for_request(request, prepared.expected.qualification)
                .map_err(|_| Error::Authority)?;
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            let view = prepared.state.view();
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            let cut = history::authenticate(&view, &prepared, &mut bound)?;
            if cut.applied_floor() != native_floor(applied_floor) {
                return Err(Error::Authority.into());
            }
            prepared.round.ensure_live().map_err(Error::from)?;
            let _publication = prepared.state.stream_token_gateway_publication_lease();
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            let time = sample_time().map_err(|_| Error::Clock)?;
            validate_time(time)?;
            if time.earliest_unix_ms < time_at_verification.earliest_unix_ms {
                return Err(Error::Clock.into());
            }
            for now in [time.earliest_unix_ms, time.latest_unix_ms] {
                check::evaluate_current_rows(cut.view(), &prepared.instruction.request, now)
                    .map_err(|_| Error::Authority)?;
            }
            let (source, delivery) =
                crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::read(
                    cut.view().world(),
                    &prepared.expected.network_id,
                    original,
                )
                .map_err(|_| Error::Authority)?;
            let height =
                u64::try_from(cut.view().block_hashes().len()).map_err(|_| Error::Execution)?;
            let mut may_append = false;
            let mut needs_terminal_check = false;
            if delivery.disposition == Disposition::Pending {
                let intent = source.intent.as_ref().ok_or(Error::Authority)?;
                needs_terminal_check = intent
                    .expired_at(height, time.latest_unix_ms)
                    .map_err(|_| Error::Authority)?;
                if !needs_terminal_check {
                    let permission: iroha_data_model::permission::Permission =
                    iroha_executor_data_model::permission::sorafs::CanRecordSorafsReputationJournal
                        .into();
                    let world = cut.view().world();
                    let account = &intent.payload.authority;
                    use mv::storage::StorageReadOnly;
                    if world.accounts().get(account).is_none()
                        || !(world.account_contains_inherent_permission(account, &permission)
                            || world
                                .account_roles_iter(account)
                                .filter_map(|id| world.roles().get(id))
                                .any(|role| role.permissions().any(|token| token == &permission)))
                    {
                        return Err(Error::Authority.into());
                    }
                    may_append = true;
                }
            }
            prepared.round.ensure_live().map_err(Error::from)?;
            Ok(capture(VerifiedStreamTokenReputationDeliveryV1 {
                source: &source,
                disposition: &delivery.disposition,
                may_append,
                needs_terminal_check,
            }))
        })();
        match result {
            Ok(result) => Ok(result),
            Err(error) => Err(StreamTokenGatewayCheckAttemptFailureV1 {
                error,
                pending: PendingStreamTokenGatewayCheckV1 {
                    prepared,
                    bound: bound
                        .take()
                        .expect("original binding survives refused consumption"),
                },
            }),
        }
    }

    /// Consume a Serving proof at the final synchronous response-capture boundary.
    ///
    /// Reauthenticate the original signed Check and durable certificates before acquiring the
    /// publication lease. Any State publication since verification rejects this capability;
    /// retry reauthenticates the same exact Check with its original absolute deadline. While holding
    /// the lease, only sample UTC, recheck in-memory current rows and invoke the short capture
    /// handoff. The capture callback must not reconcile callbacks, perform I/O or wait on consensus.
    /// The State publication lease does not serialize external removal of Kura certificates;
    /// their availability is checked afresh immediately before this final publication fence.
    ///
    /// # Errors
    /// Rejects a changed publication, purpose/attempt, durable proof, permission, policy, original
    /// lease deadline or UTC endpoint. Failure retains the original Pending without renewal.
    pub fn consume_for_serving<T>(
        self,
        original: &Request,
        sample_time: impl FnOnce() -> Result<Time, Error>,
        capture: impl FnOnce(Record) -> T,
    ) -> Result<T, StreamTokenGatewayCheckAttemptFailureV1> {
        let Self {
            prepared,
            bound: original_bound,
            generation,
            readback,
            applied_floor,
            time: time_at_verification,
            ..
        } = self;
        let mut bound = Some(original_bound);
        let result = (|| -> Result<T, crate::execution_attempt::ExecutionAttemptError<Error>> {
            prepared.round.ensure_live().map_err(Error::from)?;
            let Selector::Serving(expected) = &prepared.expected.selector else {
                return Err(Error::Authority.into());
            };
            let StreamTokenGatewayCheckReadbackV1::Serving(result) = readback else {
                return Err(Error::Authority.into());
            };
            if expected != original {
                return Err(Error::Authority.into());
            }
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            let view = prepared.state.view();
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            // One final source-bound walk; the retained binding is moved, never reconstructed from
            // DTOs or a cached success. Local QC loss since initial verification must fail closed.
            let cut = history::authenticate(&view, &prepared, &mut bound)?;
            if cut.applied_floor() != native_floor(applied_floor) {
                return Err(Error::Authority.into());
            }
            prepared.round.ensure_live().map_err(Error::from)?;
            let _publication = prepared.state.stream_token_gateway_publication_lease();
            if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            {
                return Err(Error::Authority.into());
            }
            let time = sample_time().map_err(|_| Error::Clock)?;
            validate_time(time)?;
            if time.earliest_unix_ms < time_at_verification.earliest_unix_ms {
                return Err(Error::Clock.into());
            }
            // These predicates use only the source view's in-memory World. Floor/Kura validation
            // happened above, outside the publication lease, on that same original source cut.
            check::evaluate_current_rows(
                cut.view(),
                &prepared.instruction.request,
                time.earliest_unix_ms,
            )
            .map_err(|_| Error::Authority)?;
            check::evaluate_current_rows(
                cut.view(),
                &prepared.instruction.request,
                time.latest_unix_ms,
            )
            .map_err(|_| Error::Authority)?;
            result
                .validate_for_request(original, prepared.expected.qualification)
                .map_err(|_| Error::Authority)?;
            prepared.round.ensure_live().map_err(Error::from)?;
            Ok(capture(result.record))
        })();
        match result {
            Ok(result) => Ok(result),
            Err(error) => Err(StreamTokenGatewayCheckAttemptFailureV1 {
                error,
                pending: PendingStreamTokenGatewayCheckV1 {
                    prepared,
                    bound: bound
                        .take()
                        .expect("original binding survives refused consumption"),
                },
            }),
        }
    }
}

mod attempt_failure;
pub use attempt_failure::StreamTokenGatewayCheckAttemptFailureV1;

mod history;
#[cfg(test)]
mod tests;
