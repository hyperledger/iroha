//! The accepted corpus of one scope and its closure record (design §3.7–§3.8, integration
//! decisions 2 and 9).
//!
//! [`CorpusAccumulatorV1`] maintains, incrementally and exactly as the data model's
//! `corpus_*_v1` digests define them:
//!
//! ```text
//! root_0     = H(Frame("PARL/CORPUS-EMPTY/v1"; profile_id, scope, R, policy_hash))
//! root_(i+1) = H(Frame("PARL/CORPUS-APPEND/v1"; root_i, u32_le(i), leaf_i))
//! ```
//!
//! An append takes an accepted ballot's compact entry in strictly increasing
//! `(height, input_index)` order with a fresh nullifier, at most `S` of them, and updates the
//! root, the nullifier index and the counts together or not at all. [`build_closure_record_v1`]
//! assembles the closure record from the attempt facts, the anchors and the corpus, decides
//! the outcome with the data model's decision rule and validates the record.

use std::collections::BTreeMap;

use iroha_data_model::governance::{
    GovernanceAnchorV1,
    anonymous_ballot::{
        AnonymousBallotCodecErrorV1, AnonymousBallotCorpusEntryV1, AnonymousBallotCorpusErrorV1,
        BallotChoiceV1, BallotClosureErrorV1, BallotClosureRecordV1, BallotScopeV1,
        BallotTallyErrorV1, Digest512, NullifierV1, ProofProfileIdV1,
        digests::{corpus_append_root_v1, corpus_empty_root_v1, corpus_leaf_v1},
    },
    types::ProposalContentId,
};

use crate::context::ScopedBallotContextV1;

/// Why an entry cannot be appended to the corpus, or a corpus cannot be restored.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CorpusErrorV1 {
    /// The entry itself is invalid (height zero).
    #[error(transparent)]
    Entry(#[from] AnonymousBallotCorpusErrorV1),
    /// The entry belongs to another scope.
    #[error("the entry belongs to another scope")]
    ForeignScope,
    /// The entry names another proof profile.
    #[error("the entry names another proof profile")]
    ForeignProfile,
    /// The entry is not strictly after the last accepted entry in `(height, input_index)`.
    #[error("the entry is not strictly after the last accepted entry")]
    Order,
    /// The nullifier was already accepted at this zero-based corpus index.
    #[error("the nullifier was already accepted at corpus index {index}")]
    DuplicateNullifier {
        /// Index of the accepted entry holding the nullifier.
        index: u32,
    },
    /// The corpus already holds one ballot per sealed seat.
    #[error("the corpus already holds {seats} ballots, one per sealed seat")]
    Full {
        /// Sealed seats `S`.
        seats: u16,
    },
    /// A corpus digest could not be computed.
    #[error(transparent)]
    Codec(#[from] AnonymousBallotCodecErrorV1),
}

/// Public Aye, Nay and Abstain counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct BallotCountsV1 {
    /// Aye count `A`.
    pub aye: u32,
    /// Nay count `N`.
    pub nay: u32,
    /// Abstain count `X`.
    pub abstain: u32,
}

/// The accepted corpus of one scope: its root, its counts and its live nullifier index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusAccumulatorV1 {
    profile_id: ProofProfileIdV1,
    scope: BallotScopeV1,
    list_digest: Digest512,
    policy_hash: Digest512,
    seats: u16,
    root: Digest512,
    last_position: Option<(u64, u32)>,
    nullifiers: BTreeMap<NullifierV1, u32>,
    counts: BallotCountsV1,
}

impl CorpusAccumulatorV1 {
    /// The empty corpus of `context`'s scope, with `root_0`.
    ///
    /// # Errors
    /// [`CorpusErrorV1::Codec`] if `root_0` cannot be computed, which 64-byte fields never
    /// cause.
    pub fn new(context: &ScopedBallotContextV1) -> Result<Self, CorpusErrorV1> {
        let root = corpus_empty_root_v1(
            context.profile_id(),
            context.scope(),
            context.list_digest(),
            context.policy_hash(),
        )?;
        Ok(Self {
            profile_id: *context.profile_id(),
            scope: *context.scope(),
            list_digest: *context.list_digest(),
            policy_hash: *context.policy_hash(),
            seats: context.seats(),
            root,
            last_position: None,
            nullifiers: BTreeMap::new(),
            counts: BallotCountsV1::default(),
        })
    }

    /// Recompute the corpus of `context`'s scope from its stored entries in order: the
    /// restore check of ordering, uniqueness, counts and root.
    ///
    /// # Errors
    /// The [`CorpusErrorV1`] of the first entry that cannot be appended.
    pub fn restore(
        context: &ScopedBallotContextV1,
        entries: &[AnonymousBallotCorpusEntryV1],
    ) -> Result<Self, CorpusErrorV1> {
        let mut corpus = Self::new(context)?;
        for entry in entries {
            corpus.append(entry)?;
        }
        Ok(corpus)
    }

    /// Append an accepted ballot's entry and return its zero-based corpus index. Nothing
    /// changes unless every check passes.
    ///
    /// # Errors
    /// [`CorpusErrorV1`] for an entry of height zero, of another scope or profile, out of
    /// order, with an accepted nullifier, or beyond `S` entries.
    pub fn append(&mut self, entry: &AnonymousBallotCorpusEntryV1) -> Result<u32, CorpusErrorV1> {
        entry.validate()?;
        if entry.scope != self.scope {
            return Err(CorpusErrorV1::ForeignScope);
        }
        if entry.profile_id != self.profile_id {
            return Err(CorpusErrorV1::ForeignProfile);
        }
        if self
            .last_position
            .is_some_and(|last| last >= entry.position())
        {
            return Err(CorpusErrorV1::Order);
        }
        if let Some(index) = self.nullifiers.get(&entry.nullifier) {
            return Err(CorpusErrorV1::DuplicateNullifier { index: *index });
        }
        let index = self.accepted();
        if index >= u32::from(self.seats) {
            return Err(CorpusErrorV1::Full { seats: self.seats });
        }
        let root = corpus_append_root_v1(&self.root, index, &corpus_leaf_v1(entry)?)?;
        // Every check passed: the update below cannot fail part-way.
        self.root = root;
        self.last_position = Some(entry.position());
        self.nullifiers.insert(entry.nullifier, index);
        match entry.vote {
            BallotChoiceV1::Aye => self.counts.aye += 1,
            BallotChoiceV1::Nay => self.counts.nay += 1,
            BallotChoiceV1::Abstain => self.counts.abstain += 1,
        }
        Ok(index)
    }

    /// The corpus root `root_M`.
    pub fn root(&self) -> &Digest512 {
        &self.root
    }

    /// Accepted ballots `M`.
    pub fn accepted(&self) -> u32 {
        // At most `S <= 1000` nullifiers are ever inserted.
        u32::try_from(self.nullifiers.len()).unwrap_or(u32::MAX)
    }

    /// The public counts.
    pub fn counts(&self) -> BallotCountsV1 {
        self.counts
    }

    /// The zero-based corpus index of the accepted ballot holding `nullifier`.
    pub fn index_of(&self, nullifier: &NullifierV1) -> Option<u32> {
        self.nullifiers.get(nullifier).copied()
    }

    /// The scope.
    pub fn scope(&self) -> &BallotScopeV1 {
        &self.scope
    }

    /// Sealed seats `S`, the most entries the corpus can hold.
    pub fn seats(&self) -> u16 {
        self.seats
    }

    /// `(height, input_index)` of the last accepted entry.
    pub fn last_position(&self) -> Option<(u64, u32)> {
        self.last_position
    }

    /// Whether the corpus belongs to `context` (scope, list, policy and profile).
    pub fn belongs_to(&self, context: &ScopedBallotContextV1) -> bool {
        self.scope == *context.scope()
            && self.list_digest == *context.list_digest()
            && self.policy_hash == *context.policy_hash()
            && self.profile_id == *context.profile_id()
            && self.seats == context.seats()
    }
}

/// The anchors of one ballot's lifecycle: the opening `s0`, the casting clock established
/// at `h_open + 1`, and the closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClosureAnchorsV1 {
    /// The opening anchor `s0`.
    pub opening: GovernanceAnchorV1,
    /// Height of the casting-clock block, `h_open + 1`.
    pub casting_clock_height: u64,
    /// Block time of the casting-clock block.
    pub casting_clock_timestamp_ms: u64,
    /// The closure transition's anchor.
    pub closure: GovernanceAnchorV1,
}

/// Why a closure record cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClosureBuildErrorV1 {
    /// The corpus belongs to another scope, list, policy or profile.
    #[error("the corpus belongs to another scope, list, policy or profile")]
    ForeignCorpus,
    /// `casting_clock_timestamp_ms + casting_window_ms` overflows.
    #[error("closing_ms overflows")]
    ClosingTime,
    /// The counts are not a closable tally.
    #[error(transparent)]
    Tally(#[from] BallotTallyErrorV1),
    /// The assembled record is inconsistent (for example its anchors).
    #[error(transparent)]
    Record(#[from] BallotClosureErrorV1),
}

/// `closing_ms = casting_clock_timestamp_ms + casting_window_ms`, checked.
pub const fn closing_ms_v1(casting_clock_timestamp_ms: u64, casting_window_ms: u64) -> Option<u64> {
    casting_clock_timestamp_ms.checked_add(casting_window_ms)
}

/// Assemble the closure record of `context`'s ballot from the attempt facts
/// (`proposal_content_id` and the seal's registration-mapping digest), the anchors and the
/// corpus; decide the outcome with the V1 decision rule under the frozen risk tier and
/// validate the record.
///
/// # Errors
/// [`ClosureBuildErrorV1`] for a foreign corpus, an overflowing deadline, or a record that
/// fails [`BallotClosureRecordV1::validate`].
pub fn build_closure_record_v1(
    context: &ScopedBallotContextV1,
    proposal_content_id: ProposalContentId,
    registration_mapping_digest: Digest512,
    anchors: &ClosureAnchorsV1,
    corpus: &CorpusAccumulatorV1,
) -> Result<BallotClosureRecordV1, ClosureBuildErrorV1> {
    if !corpus.belongs_to(context) {
        return Err(ClosureBuildErrorV1::ForeignCorpus);
    }
    let policy = context.policy();
    let closing_ms = closing_ms_v1(anchors.casting_clock_timestamp_ms, policy.casting_window_ms)
        .ok_or(ClosureBuildErrorV1::ClosingTime)?;
    let counts = corpus.counts();
    let body = context.body_context();
    let decision = policy.decision_rule.decide(
        body.body_role,
        policy.risk_tier,
        context.seats(),
        counts.aye,
        counts.nay,
        counts.abstain,
    )?;
    let record = BallotClosureRecordV1 {
        network_id: body.network_id,
        proposal_content_id,
        proposal_digest: context.context().proposal_digest,
        governance_attempt_id: body.governance_attempt_id,
        election_attempt_id: body.election_attempt_id,
        body_instance_id: *context.body_instance_id(),
        body_role: body.body_role,
        scope: *context.scope(),
        seats: context.seats(),
        profile_id: *context.profile_id(),
        policy_hash: *context.policy_hash(),
        list_digest: *context.list_digest(),
        registration_mapping_digest,
        opening_anchor: anchors.opening,
        casting_clock_height: anchors.casting_clock_height,
        casting_clock_timestamp_ms: anchors.casting_clock_timestamp_ms,
        casting_window_ms: policy.casting_window_ms,
        closing_ms,
        closure_anchor: anchors.closure,
        corpus_root: *corpus.root(),
        accepted_ballots: corpus.accepted(),
        aye: counts.aye,
        nay: counts.nay,
        abstain: counts.abstain,
        outcome: decision.outcome,
        narrow: decision.narrow,
    };
    record.validate(policy.risk_tier)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::anonymous_ballot::{
        BallotOutcomeV1, digests::corpus_root_v1,
    };

    use super::*;
    use crate::test_support::{
        ABSTAIN_3, AYE_0, AYE_2, NAY_0, NAY_1, fixture_bytes, fixture_envelope,
        proposal_content_id, scoped_context,
    };

    /// The compact entry of fixture ballot `index` accepted at `(height, input_index)`.
    fn entry(index: usize, height: u64, input_index: u32) -> AnonymousBallotCorpusEntryV1 {
        AnonymousBallotCorpusEntryV1::from_envelope(
            &fixture_envelope(index),
            iroha_data_model::governance::anonymous_ballot::digests::envelope_digest_v1(
                &fixture_bytes(index),
            )
            .expect("digest"),
            height,
            input_index,
        )
        .expect("entry")
    }

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

    #[test]
    fn appends_reproduce_the_data_model_corpus_root() {
        let context = scoped_context();
        let mut corpus = CorpusAccumulatorV1::new(&context).expect("corpus");
        let empty = *corpus.root();
        assert_eq!(
            empty,
            corpus_root_v1(
                context.profile_id(),
                context.scope(),
                context.list_digest(),
                context.policy_hash(),
                &[]
            )
            .expect("root")
        );
        let entries = [
            entry(AYE_0, 100, 0),
            entry(NAY_1, 101, 0),
            entry(AYE_2, 101, 7),
        ];
        for (expected, entry) in (0_u32..).zip(&entries) {
            assert_eq!(corpus.append(entry), Ok(expected));
        }
        assert_eq!(
            corpus.root(),
            &corpus_root_v1(
                context.profile_id(),
                context.scope(),
                context.list_digest(),
                context.policy_hash(),
                &entries
            )
            .expect("root")
        );
        assert_eq!(corpus.accepted(), 3);
        assert_eq!(
            corpus.counts(),
            BallotCountsV1 {
                aye: 2,
                nay: 1,
                abstain: 0
            }
        );
        assert_eq!(corpus.index_of(&entries[1].nullifier), Some(1));
        assert_eq!(corpus.last_position(), Some((101, 7)));
        assert_eq!(corpus.scope(), context.scope());
        assert_eq!(corpus.seats(), 4);
        assert_eq!(
            CorpusAccumulatorV1::restore(&context, &entries),
            Ok(corpus.clone())
        );
    }

    #[test]
    fn an_append_that_fails_changes_nothing() {
        let context = scoped_context();
        let mut corpus = CorpusAccumulatorV1::new(&context).expect("corpus");
        corpus.append(&entry(AYE_0, 100, 5)).expect("first");
        let before = corpus.clone();
        // The same nullifier with another choice, later in order.
        assert_eq!(
            corpus.append(&entry(NAY_0, 101, 0)),
            Err(CorpusErrorV1::DuplicateNullifier { index: 0 })
        );
        // Not strictly after the last entry.
        assert_eq!(
            corpus.append(&entry(NAY_1, 100, 5)),
            Err(CorpusErrorV1::Order)
        );
        assert_eq!(
            corpus.append(&entry(NAY_1, 99, 9)),
            Err(CorpusErrorV1::Order)
        );
        let mut foreign = entry(NAY_1, 102, 0);
        foreign.scope = BallotScopeV1::new([0x45; 64]);
        assert_eq!(corpus.append(&foreign), Err(CorpusErrorV1::ForeignScope));
        let mut foreign = entry(NAY_1, 102, 0);
        foreign.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(corpus.append(&foreign), Err(CorpusErrorV1::ForeignProfile));
        let mut zero = entry(NAY_1, 102, 0);
        zero.height = 0;
        assert_eq!(
            corpus.append(&zero),
            Err(CorpusErrorV1::Entry(
                AnonymousBallotCorpusErrorV1::ZeroHeight
            ))
        );
        assert_eq!(corpus, before);
    }

    #[test]
    fn the_corpus_holds_at_most_one_ballot_per_seat() {
        let context = scoped_context();
        let mut corpus = CorpusAccumulatorV1::new(&context).expect("corpus");
        for (input_index, index) in (0_u32..).zip([AYE_0, NAY_1, AYE_2, ABSTAIN_3]) {
            corpus
                .append(&entry(index, 100, input_index))
                .expect("append");
        }
        // A fifth nullifier (forged into the fixture scope) finds the corpus full.
        let mut fifth = entry(NAY_1, 101, 0);
        fifth.nullifier = NullifierV1::new([0x99; 128]);
        assert_eq!(corpus.append(&fifth), Err(CorpusErrorV1::Full { seats: 4 }));
        assert_eq!(corpus.accepted(), 4);
    }

    #[test]
    fn the_closure_record_recomputes_the_outcome_and_validates() {
        let context = scoped_context();
        let mut corpus = CorpusAccumulatorV1::new(&context).expect("corpus");
        for (input_index, index) in (0_u32..).zip([AYE_0, NAY_1, AYE_2, ABSTAIN_3]) {
            corpus
                .append(&entry(index, 101, input_index))
                .expect("append");
        }
        let mapping = Digest512::new([0x04; 64]);
        let record = build_closure_record_v1(
            &context,
            proposal_content_id(),
            mapping,
            &anchors(),
            &corpus,
        )
        .expect("record");
        assert_eq!(record.outcome, BallotOutcomeV1::Approved);
        assert!(!record.narrow);
        assert_eq!(
            (
                record.accepted_ballots,
                record.aye,
                record.nay,
                record.abstain
            ),
            (4, 2, 1, 1)
        );
        assert_eq!(record.corpus_root, *corpus.root());
        assert_eq!(record.closing_ms, 1_001_000 + 86_400_000);
        assert_eq!(record.scope, *context.scope());
        assert_eq!(record.body_instance_id, *context.body_instance_id());
        assert_eq!(record.registration_mapping_digest, mapping);
        assert_eq!(record.validate(context.policy().risk_tier), Ok(()));
        // Two ballots of four seats are below max(3, Q) = 3: NoQuorum, not an error.
        let mut low = CorpusAccumulatorV1::new(&context).expect("corpus");
        low.append(&entry(AYE_0, 101, 0)).expect("append");
        low.append(&entry(AYE_2, 101, 1)).expect("append");
        let record =
            build_closure_record_v1(&context, proposal_content_id(), mapping, &anchors(), &low)
                .expect("record");
        assert_eq!(record.outcome, BallotOutcomeV1::NoQuorum);
    }

    #[test]
    fn inconsistent_anchors_and_foreign_corpora_are_refused() {
        let context = scoped_context();
        let corpus = CorpusAccumulatorV1::new(&context).expect("corpus");
        let mapping = Digest512::new([0x04; 64]);
        let mut early = anchors();
        early.closure.timestamp_ms = early.casting_clock_timestamp_ms;
        assert_eq!(
            build_closure_record_v1(&context, proposal_content_id(), mapping, &early, &corpus),
            Err(ClosureBuildErrorV1::Record(
                BallotClosureErrorV1::ClosureAnchor
            ))
        );
        let mut skipped = anchors();
        skipped.casting_clock_height = 102;
        assert_eq!(
            build_closure_record_v1(&context, proposal_content_id(), mapping, &skipped, &corpus),
            Err(ClosureBuildErrorV1::Record(
                BallotClosureErrorV1::CastingClockHeight
            ))
        );
        let mut overflow = anchors();
        overflow.casting_clock_timestamp_ms = u64::MAX;
        assert_eq!(
            build_closure_record_v1(&context, proposal_content_id(), mapping, &overflow, &corpus),
            Err(ClosureBuildErrorV1::ClosingTime)
        );
        let other = ScopedBallotContextV1::new(
            context.context().clone(),
            iroha_data_model::governance::types::BodyInstanceId::new([0x04; 32]),
        )
        .expect("context");
        assert!(!corpus.belongs_to(&other));
        assert_eq!(
            build_closure_record_v1(&other, proposal_content_id(), mapping, &anchors(), &corpus),
            Err(ClosureBuildErrorV1::ForeignCorpus)
        );
        assert_eq!(closing_ms_v1(u64::MAX, 1), None);
        assert_eq!(closing_ms_v1(1, 2), Some(3));
    }
}
