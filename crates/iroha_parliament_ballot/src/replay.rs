//! The streaming core of independent full verification (design §3.9, integration
//! decision 8).
//!
//! Inputs: the target scope's checked context, the seal's published output with the complete
//! list bytes, the attempt facts, the opening, casting-clock and closure anchors, the recorded
//! closure record (and optionally the certified result root), and then, block by block, every
//! anonymous-ballot input of every block from the opening height through the closure height
//! inclusive with its recorded result. Contexts of other scopes whose ballots appear in that
//! interval are supplied too.
//!
//! [`verify_full_v1`] re-decides every input with the shared block decision
//! ([`check_block_ballot_v1`] followed by [`decide_valid_ballot_v1`], which together are
//! [`crate::ballot::decide_block_ballot_v1`]): every stamp and proof is verified again,
//! rejected ballots included, the window is decided before duplicates, accepted ballots are
//! appended to a rebuilt corpus in canonical order, and the rebuilt counts, root, outcome,
//! complete closure record and `result_root` are compared with the recorded ones. Missing or
//! out-of-interval data never produces success.
//!
//! Trust boundary: the verifier still trusts the finality and authenticity of the board (the
//! blocks, their results, the seal output and the closure record), and registration
//! eligibility and seat assignment, unless the preceding authenticated history is replayed
//! too. For ballots of other scopes it checks validity (the block could not have been valid
//! otherwise), not their window or duplicate decisions, which belong to those scopes'
//! verifications.
//!
//! TODO: the Core integration adds `TransactionEntrypoint::AnonymousBallot` and
//! `TransactionRejectionReason::AnonymousBallot`. An evidence reader must then (a) verify the
//! continuity and finality of every block from the opening height through the closure height
//! against externally authenticated finality evidence, (b) extract every anonymous-ballot
//! input with its global `input_index` from each block and check the extraction against the
//! block's input commitment, so that an omitted input is reported as incomplete evidence,
//! (c) read each input's recorded result from `NetworkExecutionOutputV1` under
//! `BlockResult.output_merkle`, and (d) authenticate the seal, casting-clock and closure
//! outputs from `BlockResult.outputs`, before it feeds [`verify_full_v1`]. Until then the
//! blocks given here are as authentic as their source.

use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc};

use iroha_data_model::{
    NetworkId,
    governance::{
        anonymous_ballot::{
            AnonymousBallotCodecErrorV1, AnonymousBallotRejectionV1, BallotClosureErrorV1,
            BallotClosureRecordV1, BallotContextErrorV1, BallotScopeV1, Digest512, NullifierV1,
            SealedCredentialListPublishedV1,
        },
        types::ProposalContentId,
    },
};

use crate::{
    ballot::{
        BlockBallotDecisionV1, BlockBallotStateV1, BlockBallotValidityV1, BlockInvalidReasonV1,
        CastingWindowV1, VerificationUnavailableV1, check_block_ballot_v1, decide_valid_ballot_v1,
    },
    context::ScopedBallotContextV1,
    corpus::{
        ClosureAnchorsV1, ClosureBuildErrorV1, CorpusAccumulatorV1, CorpusErrorV1,
        build_closure_record_v1, closing_ms_v1,
    },
};

/// The result recorded for one anonymous-ballot input of a finalized block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordedBallotResultV1 {
    /// Accepted: an ordinary successful result.
    Accepted,
    /// Recorded as rejected.
    Rejected(AnonymousBallotRejectionV1),
}

/// One anonymous-ballot input of a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayBallotV1 {
    /// Position in the block's global network-input projection.
    pub input_index: u32,
    /// The exact canonical envelope bytes carried by the block.
    pub envelope: Vec<u8>,
    /// The recorded result.
    pub recorded: RecordedBallotResultV1,
}

/// Every anonymous-ballot input of one block, in increasing `input_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayBlockV1 {
    /// Block height.
    pub height: u64,
    /// Block time in milliseconds.
    pub timestamp_ms: u64,
    /// The block's anonymous-ballot inputs.
    pub ballots: Vec<ReplayBallotV1>,
}

/// Why an evidence source could not supply the next block.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplaySourceErrorV1 {
    /// The block is not available (pruned or never retrieved).
    #[error("block {height} is not available")]
    Missing {
        /// Height of the missing block.
        height: u64,
    },
    /// The source failed for a local reason.
    #[error("the evidence source failed: {reason}")]
    Unavailable {
        /// The source's reason.
        reason: String,
    },
}

/// Everything a full verification starts from besides the blocks.
#[derive(Debug, Clone)]
pub struct FullVerificationRequestV1 {
    /// The target scope's checked context.
    pub context: Arc<ScopedBallotContextV1>,
    /// The seal's published output, with the complete list bytes.
    pub seal: SealedCredentialListPublishedV1,
    /// Checked contexts of other scopes whose ballots appear in the interval.
    pub other_scopes: Vec<Arc<ScopedBallotContextV1>>,
    /// The attempt's proposal content identifier.
    pub proposal_content_id: ProposalContentId,
    /// The opening, casting-clock and closure anchors.
    pub anchors: ClosureAnchorsV1,
    /// The recorded closure record.
    pub closure_record: BallotClosureRecordV1,
    /// The result root committed by a certificate, if one is being checked.
    pub certified_result_root: Option<Digest512>,
}

/// A successful independent full verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerificationReportV1 {
    /// The closure record, rebuilt and equal to the recorded one.
    pub closure_record: BallotClosureRecordV1,
    /// `result_root` of the closure record.
    pub result_root: Digest512,
    /// Blocks replayed, opening through closure.
    pub blocks: u64,
    /// Ballots whose stamp and proof were verified again, of every scope and result.
    pub ballots_verified: u64,
    /// Verified ballots of other scopes.
    pub other_scope_ballots: u64,
    /// Accepted ballots of the target scope.
    pub accepted: u32,
    /// Target-scope ballots rejected as outside the casting window.
    pub rejected_outside_window: u64,
    /// Target-scope ballots rejected as duplicates.
    pub rejected_duplicate: u64,
}

/// Evidence that contradicts itself or the protocol.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidEvidenceV1 {
    /// The seal output disagrees with the context.
    #[error("the seal output's {field} disagrees with the context")]
    SealMismatch {
        /// The disagreeing field.
        field: &'static str,
    },
    /// The seal's list bytes are not a valid canonical list.
    #[error("the seal's list bytes are invalid: {0}")]
    SealedList(BallotContextErrorV1),
    /// Two different contexts were supplied for one scope.
    #[error("two different contexts were supplied for one scope")]
    ContextConflict,
    /// A closure-record field is not the value the evidence determines.
    #[error("the closure record's {field} is not the value the evidence determines")]
    ClosureRecordField {
        /// The field.
        field: &'static str,
    },
    /// The recorded closure record is internally inconsistent.
    #[error("the closure record is inconsistent: {0}")]
    ClosureRecord(BallotClosureErrorV1),
    /// A block repeats or precedes an earlier one.
    #[error("block {height} repeats or precedes an earlier block")]
    BlockOrder {
        /// Height of the offending block.
        height: u64,
    },
    /// A block's time precedes its predecessor's.
    #[error("block {height}'s time precedes its predecessor's")]
    BlockTime {
        /// Height of the offending block.
        height: u64,
    },
    /// A block's time is not the time of the anchor at its height.
    #[error("block {height}'s time is not its anchor's time")]
    AnchorTime {
        /// Height of the offending block.
        height: u64,
    },
    /// Inputs of a block are not in strictly increasing `input_index`.
    #[error("input {input_index} of block {height} is out of order")]
    ItemOrder {
        /// Block height.
        height: u64,
        /// The offending input index.
        input_index: u32,
    },
    /// A finalized block carries an input that would make it invalid.
    #[error("input {input_index} of block {height} is invalid: {reason}")]
    InvalidBallot {
        /// Block height.
        height: u64,
        /// Input index.
        input_index: u32,
        /// Why the input is invalid.
        reason: BlockInvalidReasonV1,
    },
    /// A recorded result is not the re-decided one.
    #[error(
        "input {input_index} of block {height} recorded {recorded:?}, re-decided {recomputed:?}"
    )]
    RecordedResult {
        /// Block height.
        height: u64,
        /// Input index.
        input_index: u32,
        /// The re-decided result.
        recomputed: RecordedBallotResultV1,
        /// The recorded result.
        recorded: RecordedBallotResultV1,
    },
    /// An accepted ballot could not be appended to the rebuilt corpus.
    #[error("the rebuilt corpus refuses input {input_index} of block {height}: {error}")]
    Corpus {
        /// Block height.
        height: u64,
        /// Input index.
        input_index: u32,
        /// The corpus error.
        error: CorpusErrorV1,
    },
    /// The closure record cannot be rebuilt from the evidence.
    #[error("the closure record cannot be rebuilt: {0}")]
    Closure(ClosureBuildErrorV1),
    /// The certified result root is not the closure record's.
    #[error("the certified result root is not the closure record's")]
    ResultRoot,
}

/// Evidence that is missing something full verification needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IncompleteEvidenceV1 {
    /// A block of the interval is missing.
    #[error("block {height} of the interval is missing")]
    MissingBlock {
        /// Height of the first missing block.
        height: u64,
    },
    /// A block outside the declared interval was supplied.
    #[error("block {height} is outside the declared interval")]
    OutsideInterval {
        /// Height of the block.
        height: u64,
    },
    /// An input belongs to a scope whose context was not supplied.
    #[error("input {input_index} of block {height} belongs to a scope without a supplied context")]
    MissingScopeContext {
        /// Block height.
        height: u64,
        /// Input index.
        input_index: u32,
    },
    /// The replayed corpus has fewer accepted ballots than the recorded closure: inputs are
    /// missing from the evidence.
    #[error("the replay accepted {rebuilt} ballots but the closure records {recorded}")]
    CorpusShorterThanRecord {
        /// Ballots accepted by the replay.
        rebuilt: u32,
        /// Ballots the closure record counts.
        recorded: u32,
    },
}

/// A local failure that prevented verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResourceUnavailableV1 {
    /// The evidence source failed.
    #[error("the evidence source failed: {reason}")]
    Source {
        /// The source's reason.
        reason: String,
    },
    /// This node could not verify a ballot.
    #[error(transparent)]
    Verifier(VerificationUnavailableV1),
    /// The published seal's list could not be decoded under the local resources;
    /// retains the original refusal without concluding that the list is invalid.
    #[error("the seal's list cannot be decoded locally: {0}")]
    SealedList(norito::core::DecodeLocalRefusal),
    /// The empty corpus could not be computed.
    #[error(transparent)]
    Corpus(CorpusErrorV1),
}

/// The verdict of an independent full verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullVerificationV1 {
    /// Every check passed: the outcome follows from the authenticated board.
    IndependentFullVerification(Box<FullVerificationReportV1>),
    /// The evidence is inconsistent.
    InvalidEvidence(InvalidEvidenceV1),
    /// The evidence is incomplete.
    IncompleteEvidence(IncompleteEvidenceV1),
    /// A local resource failed; nothing is concluded about the evidence.
    ResourceUnavailable(ResourceUnavailableV1),
}

/// Early exit of the replay with its verdict.
type Verdict<T> = Result<T, FullVerificationV1>;

fn invalid<T>(error: InvalidEvidenceV1) -> Verdict<T> {
    Err(FullVerificationV1::InvalidEvidence(error))
}

fn incomplete<T>(error: IncompleteEvidenceV1) -> Verdict<T> {
    Err(FullVerificationV1::IncompleteEvidence(error))
}

/// The block state of the replay at one block.
struct ReplayState<'a> {
    network_id: NetworkId,
    contexts: &'a BTreeMap<BallotScopeV1, Arc<ScopedBallotContextV1>>,
    target: BallotScopeV1,
    casting_open: bool,
    corpus: &'a CorpusAccumulatorV1,
}

impl BlockBallotStateV1 for ReplayState<'_> {
    fn network_id(&self) -> NetworkId {
        self.network_id
    }

    fn scope_context(&self, scope: &BallotScopeV1) -> Option<Arc<ScopedBallotContextV1>> {
        self.contexts.get(scope).cloned()
    }

    fn casting_open(&self, scope: &BallotScopeV1) -> bool {
        *scope == self.target && self.casting_open
    }

    fn nullifier_accepted(&self, scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool {
        *scope == self.target && self.corpus.index_of(nullifier).is_some()
    }
}

/// Counters of the replay.
#[derive(Debug, Default)]
struct Tally {
    blocks: u64,
    ballots_verified: u64,
    other_scope_ballots: u64,
    rejected_outside_window: u64,
    rejected_duplicate: u64,
}

/// Check the seal output against the context.
fn check_seal(request: &FullVerificationRequestV1) -> Verdict<()> {
    let context = &request.context;
    let seal = &request.seal;
    let mismatch = |field| invalid(InvalidEvidenceV1::SealMismatch { field });
    if seal.body_context != *context.body_context() {
        return mismatch("body_context");
    }
    if seal.body_instance_id != *context.body_instance_id() {
        return mismatch("body_instance_id");
    }
    if seal.list_digest != *context.list_digest() {
        return mismatch("list_digest");
    }
    let list = match seal.sealed_list_bytes.decode_list() {
        Ok(list) => list,
        Err(BallotContextErrorV1::Codec(AnonymousBallotCodecErrorV1::DecodeUnavailable(
            refusal,
        ))) => {
            return Err(FullVerificationV1::ResourceUnavailable(
                ResourceUnavailableV1::SealedList(refusal),
            ));
        }
        Err(error) => return invalid(InvalidEvidenceV1::SealedList(error)),
    };
    let sealed = context.context();
    if list.profile_id != sealed.profile_id
        || list.body_context_digest != sealed.body_context_digest
        || list.seats != sealed.seats
        || list.commitments != sealed.commitments
    {
        return mismatch("sealed_list_bytes");
    }
    Ok(())
}

/// Every scope's context by scope; a conflicting duplicate is invalid evidence.
fn context_map(
    request: &FullVerificationRequestV1,
) -> Verdict<BTreeMap<BallotScopeV1, Arc<ScopedBallotContextV1>>> {
    let mut contexts = BTreeMap::new();
    for context in core::iter::once(&request.context).chain(&request.other_scopes) {
        if let Some(previous) = contexts.insert(*context.scope(), Arc::clone(context))
            && previous != *context
        {
            return invalid(InvalidEvidenceV1::ContextConflict);
        }
    }
    Ok(contexts)
}

/// Check every closure-record field the evidence determines before the replay.
fn check_record_facts(request: &FullVerificationRequestV1, closing_ms: Option<u64>) -> Verdict<()> {
    let record = &request.closure_record;
    let context = &request.context;
    let body = context.body_context();
    let anchors = &request.anchors;
    let facts = [
        ("network_id", record.network_id == body.network_id),
        (
            "proposal_content_id",
            record.proposal_content_id == request.proposal_content_id,
        ),
        (
            "proposal_digest",
            record.proposal_digest == context.context().proposal_digest,
        ),
        (
            "governance_attempt_id",
            record.governance_attempt_id == body.governance_attempt_id,
        ),
        (
            "election_attempt_id",
            record.election_attempt_id == body.election_attempt_id,
        ),
        (
            "body_instance_id",
            record.body_instance_id == *context.body_instance_id(),
        ),
        ("body_role", record.body_role == body.body_role),
        ("scope", record.scope == *context.scope()),
        ("seats", record.seats == context.seats()),
        ("profile_id", record.profile_id == *context.profile_id()),
        ("policy_hash", record.policy_hash == *context.policy_hash()),
        ("list_digest", record.list_digest == *context.list_digest()),
        (
            "registration_mapping_digest",
            record.registration_mapping_digest == request.seal.registration_mapping_digest,
        ),
        ("opening_anchor", record.opening_anchor == anchors.opening),
        (
            "casting_clock_height",
            record.casting_clock_height == anchors.casting_clock_height,
        ),
        (
            "casting_clock_timestamp_ms",
            record.casting_clock_timestamp_ms == anchors.casting_clock_timestamp_ms,
        ),
        (
            "casting_window_ms",
            record.casting_window_ms == context.policy().binding.casting_window_ms,
        ),
        ("closing_ms", Some(record.closing_ms) == closing_ms),
        ("closure_anchor", record.closure_anchor == anchors.closure),
    ];
    if let Some((field, _)) = facts.iter().find(|(_, holds)| !holds) {
        return invalid(InvalidEvidenceV1::ClosureRecordField { field });
    }
    // `policy_hash` was compared above with the context's, which the scoped context
    // recomputed: this is `validate_closure_record_v1` without hashing the policy twice.
    record
        .validate(context.policy())
        .or_else(|error| invalid(InvalidEvidenceV1::ClosureRecord(error)))
}

/// Check that a block is the next one of the interval and that its time is consistent with
/// its predecessor and with the anchor at its height.
fn check_block_position(
    anchors: &ClosureAnchorsV1,
    next: u64,
    previous_time: Option<u64>,
    block: &ReplayBlockV1,
) -> Verdict<()> {
    if block.height < anchors.opening.height || block.height > anchors.closure.height {
        return incomplete(IncompleteEvidenceV1::OutsideInterval {
            height: block.height,
        });
    }
    if block.height > next {
        return incomplete(IncompleteEvidenceV1::MissingBlock { height: next });
    }
    if block.height < next {
        return invalid(InvalidEvidenceV1::BlockOrder {
            height: block.height,
        });
    }
    if previous_time.is_some_and(|previous| block.timestamp_ms < previous) {
        return invalid(InvalidEvidenceV1::BlockTime {
            height: block.height,
        });
    }
    let anchored = [
        (anchors.opening.height, anchors.opening.timestamp_ms),
        (
            anchors.casting_clock_height,
            anchors.casting_clock_timestamp_ms,
        ),
        (anchors.closure.height, anchors.closure.timestamp_ms),
    ];
    if anchored
        .iter()
        .any(|(height, time)| *height == block.height && *time != block.timestamp_ms)
    {
        return invalid(InvalidEvidenceV1::AnchorTime {
            height: block.height,
        });
    }
    Ok(())
}

/// The replay of one block's inputs.
fn replay_block(
    request: &FullVerificationRequestV1,
    contexts: &BTreeMap<BallotScopeV1, Arc<ScopedBallotContextV1>>,
    window: &CastingWindowV1,
    block: &ReplayBlockV1,
    corpus: &mut CorpusAccumulatorV1,
    tally: &mut Tally,
) -> Verdict<()> {
    let target = *request.context.scope();
    let Some(height) = NonZeroU64::new(block.height) else {
        return invalid(InvalidEvidenceV1::BlockOrder { height: 0 });
    };
    let casting_open = window.is_open_at(block.height, block.timestamp_ms);
    let mut previous_index: Option<u32> = None;
    for ballot in &block.ballots {
        let input_index = ballot.input_index;
        if previous_index.is_some_and(|previous| input_index <= previous) {
            return invalid(InvalidEvidenceV1::ItemOrder {
                height: block.height,
                input_index,
            });
        }
        previous_index = Some(input_index);
        let state = ReplayState {
            network_id: *request.context.network_id(),
            contexts,
            target,
            casting_open,
            corpus,
        };
        let valid = match check_block_ballot_v1(&state, &ballot.envelope) {
            Ok(BlockBallotValidityV1::Valid(valid)) => valid,
            Ok(BlockBallotValidityV1::Invalid(BlockInvalidReasonV1::UnknownScope)) => {
                return incomplete(IncompleteEvidenceV1::MissingScopeContext {
                    height: block.height,
                    input_index,
                });
            }
            Ok(BlockBallotValidityV1::Invalid(reason)) => {
                return invalid(InvalidEvidenceV1::InvalidBallot {
                    height: block.height,
                    input_index,
                    reason,
                });
            }
            Err(error) => {
                return Err(FullVerificationV1::ResourceUnavailable(
                    ResourceUnavailableV1::Verifier(error),
                ));
            }
        };
        tally.ballots_verified += 1;
        let (scope, nullifier) = valid.identity();
        if scope != target {
            tally.other_scope_ballots += 1;
            continue;
        }
        let duplicate = state.nullifier_accepted(&scope, &nullifier);
        let decision = decide_valid_ballot_v1(&valid, casting_open, duplicate, height, input_index);
        let recomputed = match &decision {
            BlockBallotDecisionV1::Accepted(_) => RecordedBallotResultV1::Accepted,
            BlockBallotDecisionV1::Rejected(rejection) => {
                RecordedBallotResultV1::Rejected(*rejection)
            }
            BlockBallotDecisionV1::BlockInvalid(reason) => {
                return invalid(InvalidEvidenceV1::InvalidBallot {
                    height: block.height,
                    input_index,
                    reason: reason.clone(),
                });
            }
        };
        if recomputed != ballot.recorded {
            return invalid(InvalidEvidenceV1::RecordedResult {
                height: block.height,
                input_index,
                recomputed,
                recorded: ballot.recorded,
            });
        }
        match decision {
            BlockBallotDecisionV1::Accepted(entry) => {
                if let Err(error) = corpus.append(&entry) {
                    return invalid(InvalidEvidenceV1::Corpus {
                        height: block.height,
                        input_index,
                        error,
                    });
                }
            }
            BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::OutsideCastingWindow) => {
                tally.rejected_outside_window += 1;
            }
            BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::DuplicateNullifier) => {
                tally.rejected_duplicate += 1;
            }
            BlockBallotDecisionV1::BlockInvalid(_) => {}
        }
    }
    Ok(())
}

/// Compare the rebuilt closure record with the recorded one.
fn check_rebuilt_record(
    recorded: &BallotClosureRecordV1,
    rebuilt: &BallotClosureRecordV1,
) -> Verdict<()> {
    if rebuilt.accepted_ballots < recorded.accepted_ballots {
        return incomplete(IncompleteEvidenceV1::CorpusShorterThanRecord {
            rebuilt: rebuilt.accepted_ballots,
            recorded: recorded.accepted_ballots,
        });
    }
    let fields = [
        ("corpus_root", rebuilt.corpus_root == recorded.corpus_root),
        (
            "accepted_ballots",
            rebuilt.accepted_ballots == recorded.accepted_ballots,
        ),
        ("aye", rebuilt.aye == recorded.aye),
        ("nay", rebuilt.nay == recorded.nay),
        ("abstain", rebuilt.abstain == recorded.abstain),
        ("outcome", rebuilt.outcome == recorded.outcome),
        ("narrow", rebuilt.narrow == recorded.narrow),
    ];
    if let Some((field, _)) = fields.iter().find(|(_, holds)| !holds) {
        return invalid(InvalidEvidenceV1::ClosureRecordField { field });
    }
    if rebuilt != recorded {
        return invalid(InvalidEvidenceV1::ClosureRecordField {
            field: "closure_record",
        });
    }
    Ok(())
}

/// The verification itself, with early exits.
fn run<I>(request: &FullVerificationRequestV1, blocks: I) -> Verdict<FullVerificationReportV1>
where
    I: IntoIterator<Item = Result<ReplayBlockV1, ReplaySourceErrorV1>>,
{
    check_seal(request)?;
    let contexts = context_map(request)?;
    let anchors = request.anchors;
    let closing_ms = closing_ms_v1(
        anchors.casting_clock_timestamp_ms,
        request.context.policy().binding.casting_window_ms,
    );
    check_record_facts(request, closing_ms)?;
    let window = CastingWindowV1 {
        opening_height: anchors.opening.height,
        closing_ms,
        closure_height: Some(anchors.closure.height),
    };
    let mut corpus = CorpusAccumulatorV1::new(&request.context).map_err(|error| {
        FullVerificationV1::ResourceUnavailable(ResourceUnavailableV1::Corpus(error))
    })?;
    let mut tally = Tally::default();
    // `None` once the closure block has been replayed.
    let mut next = Some(anchors.opening.height);
    let mut previous_time = None;
    for item in blocks {
        let block = match item {
            Ok(block) => block,
            Err(ReplaySourceErrorV1::Missing { height }) => {
                return incomplete(IncompleteEvidenceV1::MissingBlock { height });
            }
            Err(ReplaySourceErrorV1::Unavailable { reason }) => {
                return Err(FullVerificationV1::ResourceUnavailable(
                    ResourceUnavailableV1::Source { reason },
                ));
            }
        };
        let Some(expected) = next else {
            return incomplete(IncompleteEvidenceV1::OutsideInterval {
                height: block.height,
            });
        };
        check_block_position(&anchors, expected, previous_time, &block)?;
        replay_block(request, &contexts, &window, &block, &mut corpus, &mut tally)?;
        tally.blocks += 1;
        previous_time = Some(block.timestamp_ms);
        next = block
            .height
            .checked_add(1)
            .filter(|_| block.height < anchors.closure.height);
    }
    if let Some(height) = next {
        return incomplete(IncompleteEvidenceV1::MissingBlock { height });
    }
    let rebuilt = build_closure_record_v1(
        &request.context,
        request.proposal_content_id,
        request.seal.registration_mapping_digest,
        &anchors,
        &corpus,
    )
    .or_else(|error| invalid(InvalidEvidenceV1::Closure(error)))?;
    check_rebuilt_record(&request.closure_record, &rebuilt)?;
    let result_root = rebuilt.result_root().map_err(|error| {
        FullVerificationV1::ResourceUnavailable(ResourceUnavailableV1::Corpus(
            CorpusErrorV1::Codec(error),
        ))
    })?;
    if request
        .certified_result_root
        .is_some_and(|certified| certified != result_root)
    {
        return invalid(InvalidEvidenceV1::ResultRoot);
    }
    Ok(FullVerificationReportV1 {
        closure_record: rebuilt,
        result_root,
        blocks: tally.blocks,
        ballots_verified: tally.ballots_verified,
        other_scope_ballots: tally.other_scope_ballots,
        accepted: corpus.accepted(),
        rejected_outside_window: tally.rejected_outside_window,
        rejected_duplicate: tally.rejected_duplicate,
    })
}

/// Independently verify one binding body's ballot from the opening through the closure.
///
/// `blocks` yields every block from `request.anchors.opening.height` through
/// `request.anchors.closure.height` inclusive, in order, each with all of its
/// anonymous-ballot inputs; it is consumed one block at a time.
pub fn verify_full_v1<I>(request: &FullVerificationRequestV1, blocks: I) -> FullVerificationV1
where
    I: IntoIterator<Item = Result<ReplayBlockV1, ReplaySourceErrorV1>>,
{
    match run(request, blocks) {
        Ok(report) => FullVerificationV1::IndependentFullVerification(Box::new(report)),
        Err(verdict) => verdict,
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::{
        GovernanceAnchorV1,
        anonymous_ballot::{
            AnonymousBallotCorpusEntryV1, BallotOutcomeV1, SealedCredentialListBytesV1,
            SealedRegistrationPairV1, digests::envelope_digest_v1,
        },
        types::{AssignmentId, BodyInstanceId},
    };

    use super::*;
    use crate::{
        inputs::registration_mapping_v1,
        test_support::{
            ABSTAIN_3, AYE_0, AYE_2, NAY_0, NAY_1, SEATS, body_context, body_instance_id,
            canonical_bytes, commitment_of, fixture_bytes, fixture_envelope, forged_envelope,
            proposal_content_id, scoped_context, sealed_list, secret_bytes,
        },
    };

    const ACCEPTED: RecordedBallotResultV1 = RecordedBallotResultV1::Accepted;
    const LATE: RecordedBallotResultV1 =
        RecordedBallotResultV1::Rejected(AnonymousBallotRejectionV1::OutsideCastingWindow);
    const DUPLICATE: RecordedBallotResultV1 =
        RecordedBallotResultV1::Rejected(AnonymousBallotRejectionV1::DuplicateNullifier);

    fn anchors() -> ClosureAnchorsV1 {
        ClosureAnchorsV1 {
            opening: GovernanceAnchorV1 {
                height: 100,
                position: 2,
                timestamp_ms: 1_000_000,
            },
            casting_clock_height: 101,
            casting_clock_timestamp_ms: 1_001_000,
            closure: GovernanceAnchorV1 {
                height: 104,
                position: 0,
                timestamp_ms: 87_402_000,
            },
        }
    }

    fn ballot(index: usize, input_index: u32, recorded: RecordedBallotResultV1) -> ReplayBallotV1 {
        ReplayBallotV1 {
            input_index,
            envelope: fixture_bytes(index),
            recorded,
        }
    }

    fn block(height: u64, timestamp_ms: u64, ballots: Vec<ReplayBallotV1>) -> ReplayBlockV1 {
        ReplayBlockV1 {
            height,
            timestamp_ms,
            ballots,
        }
    }

    /// The honest interval: accepted ballots in the opening block, the casting-clock block
    /// and the next; a conflicting duplicate and an identical replay; a late ballot after
    /// `closing_ms` while the closure is deferred; and a replay in the closure block.
    fn blocks() -> Vec<ReplayBlockV1> {
        vec![
            block(100, 1_000_000, vec![ballot(AYE_0, 0, ACCEPTED)]),
            block(
                101,
                1_001_000,
                vec![ballot(NAY_1, 0, ACCEPTED), ballot(NAY_0, 3, DUPLICATE)],
            ),
            block(
                102,
                1_002_000,
                vec![ballot(AYE_2, 1, ACCEPTED), ballot(AYE_0, 2, DUPLICATE)],
            ),
            block(103, 87_401_000, vec![ballot(ABSTAIN_3, 0, LATE)]),
            block(104, 87_402_000, vec![ballot(AYE_2, 0, LATE)]),
        ]
    }

    fn registration_mapping() -> Digest512 {
        let pairs: Vec<_> = (0..SEATS)
            .map(|member| SealedRegistrationPairV1 {
                assignment_id: AssignmentId::new([member + 1; 32]),
                commitment: commitment_of(&secret_bytes(member)),
            })
            .collect();
        registration_mapping_v1(&sealed_list(), &pairs).expect("mapping")
    }

    fn seal() -> SealedCredentialListPublishedV1 {
        let context = scoped_context();
        SealedCredentialListPublishedV1 {
            body_context: body_context(),
            body_instance_id: body_instance_id(),
            roster_root: Digest512::new([0x0a; 64]),
            list_digest: *context.list_digest(),
            registration_mapping_digest: registration_mapping(),
            sealed_list_bytes: SealedCredentialListBytesV1::from_list(&sealed_list())
                .expect("list bytes"),
        }
    }

    fn entry(index: usize, height: u64, input_index: u32) -> AnonymousBallotCorpusEntryV1 {
        AnonymousBallotCorpusEntryV1::from_envelope(
            &fixture_envelope(index),
            envelope_digest_v1(&fixture_bytes(index)).expect("digest"),
            height,
            input_index,
        )
        .expect("entry")
    }

    /// The closure record Core would have committed, built without the replay.
    fn recorded_closure() -> BallotClosureRecordV1 {
        let context = scoped_context();
        let corpus = CorpusAccumulatorV1::restore(
            &context,
            &[
                entry(AYE_0, 100, 0),
                entry(NAY_1, 101, 0),
                entry(AYE_2, 102, 1),
            ],
        )
        .expect("corpus");
        build_closure_record_v1(
            &context,
            proposal_content_id(),
            registration_mapping(),
            &anchors(),
            &corpus,
        )
        .expect("record")
    }

    fn request() -> FullVerificationRequestV1 {
        FullVerificationRequestV1 {
            context: scoped_context(),
            seal: seal(),
            other_scopes: Vec::new(),
            proposal_content_id: proposal_content_id(),
            anchors: anchors(),
            closure_record: recorded_closure(),
            certified_result_root: None,
        }
    }

    fn verify(
        request: &FullVerificationRequestV1,
        blocks: Vec<ReplayBlockV1>,
    ) -> FullVerificationV1 {
        verify_full_v1(request, blocks.into_iter().map(Ok))
    }

    #[test]
    fn a_valid_seal_under_a_local_decode_shortage_is_unavailable() {
        let request = request();
        assert_eq!(check_seal(&request), Ok(()));
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let (verdict, usage) =
            norito::core::with_decode_limits_measured(limits, || verify(&request, Vec::new()));
        let FullVerificationV1::ResourceUnavailable(ResourceUnavailableV1::SealedList(refusal)) =
            verdict
        else {
            panic!("a local shortage must not invalidate the genuine seal");
        };
        assert_eq!(
            refusal.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert_eq!(
            refusal.resource_error(),
            norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted: u64::from(request.context.seats()),
                limit: 0,
            }
        );
        assert_eq!(refusal.allocation_bytes(), None);
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), usize::from(request.context.seats()));
        // The refusal owns the original cause after its budget scope retires.
        assert_eq!(refusal.clone(), refusal);
        assert_eq!(check_seal(&request), Ok(()));
        assert_eq!(
            verify(&request, Vec::new()),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::MissingBlock {
                height: request.anchors.opening.height,
            })
        );
    }

    #[test]
    fn invalid_seal_evidence_is_not_relabelled_as_local_unavailability() {
        let mut request = request();
        // Malformed frames cannot enter the private validated carrier at all.
        let mut malformed = request.seal.sealed_list_bytes.as_bytes().to_vec();
        malformed.push(0);
        assert!(matches!(
            SealedCredentialListBytesV1::from_canonical_bytes(malformed),
            Err(BallotContextErrorV1::Codec(
                AnonymousBallotCodecErrorV1::Codec(_)
            ))
        ));
        // A well-formed published list can still contradict the authenticated
        // context. This remains invalid evidence at the actual replay entry.
        let mut conflicting = sealed_list();
        let mut digest = conflicting.body_context_digest.into_bytes();
        digest[0] ^= 1;
        conflicting.body_context_digest = Digest512::new(digest);
        request.seal.sealed_list_bytes = SealedCredentialListBytesV1::from_list(&conflicting)
            .expect("canonical conflicting list");
        assert_eq!(
            verify(&request, Vec::new()),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::SealMismatch {
                field: "sealed_list_bytes",
            })
        );
    }

    #[test]
    fn an_honest_interval_verifies_independently() {
        let mut request = request();
        let record = request.closure_record;
        request.certified_result_root = Some(record.result_root().expect("root"));
        let FullVerificationV1::IndependentFullVerification(report) = verify(&request, blocks())
        else {
            panic!("the honest interval verifies");
        };
        assert_eq!(report.closure_record, record);
        assert_eq!(report.result_root, record.result_root().expect("root"));
        assert_eq!(report.blocks, 5);
        assert_eq!(report.ballots_verified, 7);
        assert_eq!(report.other_scope_ballots, 0);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.rejected_outside_window, 2);
        assert_eq!(report.rejected_duplicate, 2);
        assert_eq!(record.outcome, BallotOutcomeV1::Approved);
        assert_eq!((record.aye, record.nay, record.abstain), (2, 1, 0));
    }

    #[test]
    fn missing_and_out_of_interval_blocks_are_incomplete() {
        let request = request();
        let mut gap = blocks();
        gap.remove(1);
        assert_eq!(
            verify(&request, gap),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::MissingBlock {
                height: 101
            })
        );
        assert_eq!(
            verify(&request, Vec::new()),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::MissingBlock {
                height: 100
            })
        );
        let mut early = blocks();
        early.insert(0, block(99, 999_000, Vec::new()));
        assert_eq!(
            verify(&request, early),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::OutsideInterval {
                height: 99
            })
        );
        assert_eq!(
            verify_full_v1(
                &request,
                [Err(ReplaySourceErrorV1::Missing { height: 100 })]
            ),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::MissingBlock {
                height: 100
            })
        );
        assert_eq!(
            verify_full_v1(
                &request,
                [Err(ReplaySourceErrorV1::Unavailable {
                    reason: "disk".to_owned()
                })]
            ),
            FullVerificationV1::ResourceUnavailable(ResourceUnavailableV1::Source {
                reason: "disk".to_owned()
            })
        );
    }

    #[test]
    fn an_interval_cut_short_at_the_end_is_incomplete() {
        // Only the empty prefix is replayed before the stream ends.
        let request = request();
        let empty: Vec<_> = blocks()
            .into_iter()
            .map(|mut block| {
                block.ballots.clear();
                block
            })
            .take(4)
            .collect();
        assert_eq!(
            verify(&request, empty),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::MissingBlock {
                height: 104
            })
        );
        // A block after the closure height.
        let mut extra: Vec<_> = blocks()
            .into_iter()
            .map(|mut block| {
                block.ballots.clear();
                block
            })
            .collect();
        extra.push(block(105, 87_403_000, Vec::new()));
        assert_eq!(
            verify(&request, extra),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::OutsideInterval {
                height: 105
            })
        );
    }

    #[test]
    fn reordered_blocks_items_and_anchor_times_are_invalid() {
        let request = request();
        let mut repeated = blocks();
        repeated.insert(1, block(100, 1_000_000, Vec::new()));
        assert_eq!(
            verify(&request, repeated),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::BlockOrder { height: 100 })
        );
        let mut items = blocks();
        items[0].ballots = vec![ballot(AYE_0, 5, ACCEPTED), ballot(NAY_1, 5, ACCEPTED)];
        assert_eq!(
            verify(&request, items),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::ItemOrder {
                height: 100,
                input_index: 5
            })
        );
        let mut time = blocks();
        time[0].timestamp_ms += 1;
        assert_eq!(
            verify(&request, time),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::AnchorTime { height: 100 })
        );
        let mut backwards = blocks();
        backwards[0].ballots.clear();
        backwards[2].timestamp_ms = 1_000_500;
        backwards[1].ballots.clear();
        assert_eq!(
            verify(&request, backwards),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::BlockTime { height: 102 })
        );
    }

    #[test]
    fn a_wrong_recorded_result_or_an_invalid_ballot_is_invalid_evidence() {
        let request = request();
        let mut wrong = blocks();
        wrong[0].ballots[0].recorded = DUPLICATE;
        assert_eq!(
            verify(&request, wrong),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::RecordedResult {
                height: 100,
                input_index: 0,
                recomputed: ACCEPTED,
                recorded: DUPLICATE
            })
        );
        let mut forged = blocks();
        forged[0].ballots.insert(
            0,
            ReplayBallotV1 {
                input_index: 0,
                envelope: canonical_bytes(&forged_envelope()),
                recorded: ACCEPTED,
            },
        );
        forged[0].ballots[1].input_index = 1;
        assert_eq!(
            verify(&request, forged),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::InvalidBallot {
                height: 100,
                input_index: 0,
                reason: BlockInvalidReasonV1::ProofRejected
            })
        );
    }

    #[test]
    fn a_ballot_of_an_unsupplied_scope_is_incomplete_and_a_supplied_one_is_verified() {
        // The fixture ballots under a second body instance (same roster and policy) are a
        // different scope; without its context the evidence is incomplete.
        let other = Arc::new(
            ScopedBallotContextV1::new(
                scoped_context().context().clone(),
                BodyInstanceId::new([0x07; 32]),
            )
            .expect("context"),
        );
        let mut foreign_envelope = fixture_envelope(AYE_0);
        foreign_envelope.ballot.scope = *other.scope();
        let mut with_foreign = blocks();
        with_foreign[0].ballots.push(ReplayBallotV1 {
            input_index: 9,
            envelope: canonical_bytes(&foreign_envelope),
            recorded: ACCEPTED,
        });
        assert_eq!(
            verify(&request(), with_foreign.clone()),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::MissingScopeContext {
                height: 100,
                input_index: 9
            })
        );
        // With the context supplied it must verify, and this one does not: its stamp and
        // proof were made for the target scope.
        let mut request = request();
        request.other_scopes.push(other);
        assert!(matches!(
            verify(&request, with_foreign),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::InvalidBallot {
                height: 100,
                input_index: 9,
                reason: BlockInvalidReasonV1::InsufficientStamp
            })
        ));
        // A conflicting second context for the target scope is refused before any replay.
        let mut conflicting = request.clone();
        let mut longer = sealed_list();
        longer.commitments.push(
            iroha_data_model::governance::anonymous_ballot::CredentialCommitmentV1::new(
                [0xff; 128],
            ),
        );
        longer.seats += 1;
        conflicting.other_scopes = vec![Arc::new(
            ScopedBallotContextV1::build(
                body_context(),
                crate::test_support::proposal_digest(),
                body_instance_id(),
                &longer,
                crate::test_support::policy(),
            )
            .expect("context"),
        )];
        assert_eq!(
            verify(&conflicting, blocks()),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::ContextConflict)
        );
    }

    /// A named change of one closure-record field.
    type Mutation = (&'static str, fn(&mut BallotClosureRecordV1));

    #[test]
    fn closure_record_mutations_are_invalid_evidence() {
        let base = request();
        let field = |request: &FullVerificationRequestV1| match verify(request, Vec::new()) {
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::ClosureRecordField {
                field,
            }) => field,
            other => panic!("expected a closure-record field mismatch, got {other:?}"),
        };
        let mutations: [Mutation; 16] = [
            ("network_id", |r| {
                r.network_id = crate::test_support::other_network_id();
            }),
            ("proposal_content_id", |r| {
                r.proposal_content_id = ProposalContentId::new([9; 32]);
            }),
            ("proposal_digest", |r| {
                r.proposal_digest = Digest512::new([9; 64])
            }),
            ("governance_attempt_id", |r| {
                r.governance_attempt_id =
                    iroha_data_model::governance::types::GovernanceAttemptId::new([9; 32]);
            }),
            ("election_attempt_id", |r| {
                r.election_attempt_id =
                    iroha_data_model::governance::types::BodyElectionAttemptId::new([9; 32]);
            }),
            ("body_instance_id", |r| {
                r.body_instance_id = BodyInstanceId::new([9; 32]);
            }),
            ("body_role", |r| {
                r.body_role = iroha_data_model::governance::types::ParliamentBody::ConfirmationJury;
            }),
            ("scope", |r| r.scope = BallotScopeV1::new([9; 64])),
            ("seats", |r| r.seats = 5),
            ("policy_hash", |r| r.policy_hash = Digest512::new([9; 64])),
            ("list_digest", |r| r.list_digest = Digest512::new([9; 64])),
            ("registration_mapping_digest", |r| {
                r.registration_mapping_digest = Digest512::new([9; 64]);
            }),
            ("opening_anchor", |r| r.opening_anchor.position += 1),
            ("casting_clock_timestamp_ms", |r| {
                r.casting_clock_timestamp_ms += 1;
            }),
            ("closing_ms", |r| r.closing_ms += 1),
            ("closure_anchor", |r| r.closure_anchor.position += 1),
        ];
        for (expected, mutate) in mutations {
            let mut request = base.clone();
            mutate(&mut request.closure_record);
            assert_eq!(field(&request), expected);
        }
        // A record with an inconsistent outcome is refused before the replay.
        let mut request = base.clone();
        request.closure_record.outcome = BallotOutcomeV1::Rejected;
        assert!(matches!(
            verify(&request, Vec::new()),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::ClosureRecord(_))
        ));
        // A seal for another list is refused.
        let mut request = base;
        request.seal.list_digest = Digest512::new([9; 64]);
        assert_eq!(
            verify(&request, Vec::new()),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::SealMismatch {
                field: "list_digest"
            })
        );
    }

    #[test]
    fn counts_roots_and_result_roots_must_match_the_replay() {
        // A record claiming a fourth accepted ballot: the replay finds only three.
        let mut request = request();
        let context = scoped_context();
        let longer = CorpusAccumulatorV1::restore(
            &context,
            &[
                entry(AYE_0, 100, 0),
                entry(NAY_1, 101, 0),
                entry(AYE_2, 102, 1),
                entry(ABSTAIN_3, 103, 0),
            ],
        )
        .expect("corpus");
        request.closure_record = build_closure_record_v1(
            &context,
            proposal_content_id(),
            registration_mapping(),
            &anchors(),
            &longer,
        )
        .expect("record");
        assert_eq!(
            verify(&request, blocks()),
            FullVerificationV1::IncompleteEvidence(IncompleteEvidenceV1::CorpusShorterThanRecord {
                rebuilt: 3,
                recorded: 4
            })
        );
        // The right counts with another certified result root.
        let mut request = self::request();
        request.certified_result_root = Some(Digest512::new([1; 64]));
        assert_eq!(
            verify(&request, blocks()),
            FullVerificationV1::InvalidEvidence(InvalidEvidenceV1::ResultRoot)
        );
    }
}
