//! Fixed DEEP context, typed commitments and atomic whole-tape transcript.
//!
//! Canonical PrefixFrame/BodyV1 serialization and SHA3/SHAKE hashing are owned by
//! `compact_sha3`; the frozen typed profile every input binds is owned by
//! `transcript_profile`. This owner supplies the closed geometry of the
//! statement context and the message schedule. Context construction
//! authenticates no public statement; the caller must perform the OOD AIR
//! identity and all opening/degree checks separately.
//! The bounded engine and producer use this schedule through the offline facade.
//!
//! The schedule is the frozen binding order of the shared backend transcript:
//! the profile, relation identity, geometry and complete statement precede
//! every commitment; the row root precedes the constraint coefficients; the
//! joined quotient and composition-mask root precedes the out-of-domain point;
//! all out-of-domain answers precede the batching scalar; each FRI root
//! precedes its folding challenge; the complete terminal precedes the query
//! positions. The profile has zero grinding bits, so no nonce exists.
//! TODO: B.2 supplies the exact-geometry reduction and checked security
//! accounting of this profile; authenticated ledger context is the caller's.

use fastpq_isi::{
    compact_challenge::{RawTapeErrorV1, RawTapeMessageV1, RawTapeRoundV1, RawTapeV1},
    keccak256::Sha3Digest256V1 as Digest,
};
use norito::NoritoSerialize;

#[cfg(any(test, feature = "fastpq-gpu", feature = "simd"))]
use super::compact_sha3::PreparedHashFrame;
use super::{
    compact_protocol::FixedAir,
    compact_public_columns::{COMMITTED_COLUMN_COUNT, LAYOUT_ID},
    compact_sha3::{BodyFields, Context as FramingContext, Frame},
    deep_geometry::{
        CONSTRAINTS, COSET_OFFSET, FRI_ARITIES, FRI_DEGREES, FRI_LENGTHS, LDE_ROOT, LDE_ROWS,
        QUERY_CANDIDATES, QUERY_COUNT, TRACE_ROWS,
    },
    deep_relation::DeepRelation,
};
use crate::field::{GOLDILOCKS_MODULUS_V1 as MODULUS, GoldilocksFp4V1 as F};

/// Width of every commitment and chain digest, in bytes.
pub(super) const COMMITMENT_BYTES: usize = Digest::BYTES;
/// Nonresidue `c` of the quartic extension `F_p[u]/(u^4 - c)`.
pub(super) const EXTENSION_NONRESIDUE: u64 = 7;
/// Longest statement the context binds; published as `air::MAX_STATEMENT_BYTES`.
pub(super) const MAX_STATEMENT_BYTES: usize = 240 * 1024;
/// Longest relation identity; published as `air::MAX_RELATION_IDENTITY_BYTES`.
pub(super) const MAX_RELATION_IDENTITY_BYTES: usize = 256;
#[cfg(test)]
const FIXTURE_RELATION_IDENTITY: &str = "fastpq:deep:explicit-context-fixture:v1";
/// Out-of-domain answers bound before the batching challenge: both retained
/// rows and the two quotient halves.
pub(super) const OOD_VALUES: usize = 2 * COMMITTED_COLUMN_COUNT + 2;

/// Failure of the fixed DEEP transcript or its typed input validation.
#[derive(Debug, thiserror::Error)]
pub(super) enum BindingError {
    /// The prepared relation, identity or statement violates the fixed context contract.
    #[error("DEEP relation must match the fixed schema and bounded identity/statement envelope")]
    Context,
    /// Only the ten specified whole-message rounds exist.
    #[error("DEEP verifier round is outside 1..=10")]
    Round,
    /// A commitment input has incorrect shape, position or canonical encoding.
    #[error("DEEP tree or OOD input has invalid geometry or field encoding")]
    Shape,
    /// A tape has the wrong fixed length or a noncanonical coordinate.
    #[error("DEEP whole tape has invalid length or field encoding")]
    Tape,
    /// Query sampling did not produce enough distinct accepted positions.
    #[error("DEEP fixed query tape exhausted")]
    Exhausted,
    /// Sampling an OOD point in the base field permanently aborts this attempt.
    #[error("DEEP OOD challenge lies in the base field")]
    BaseOod,
    /// The requested action differs from the fixed commitment/challenge schedule.
    #[error("DEEP transcript operation is out of sequence")]
    Phase,
    /// The shared canonical framing owner rejected the operation.
    #[error(transparent)]
    Framing(#[from] super::compact_sha3::CandidateError),
    /// Canonical Norito framing failed.
    #[error(transparent)]
    Encode(#[from] norito::core::Error),
}

type Result<T> = std::result::Result<T, BindingError>;

/// Convert a fixed DEEP geometry constant to its canonical `u32` context field.
pub(super) fn fixed_u32(value: usize) -> u32 {
    u32::try_from(value).expect("fixed DEEP geometry constant fits u32")
}

/// Ordinal of one indivisible verifier message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Round(u8);

impl Round {
    /// Accept exactly dummy, alpha, z, lambda, five betas and whole query subset.
    pub(super) fn new(ordinal: u8) -> Result<Self> {
        (1..=10)
            .contains(&ordinal)
            .then_some(Self(ordinal))
            .ok_or(BindingError::Round)
    }

    /// Include every materialized coordinate, including unused suffix values.
    pub(super) const fn tape_bytes(self) -> usize {
        match RawTapeRoundV1::new(self.0) {
            Some(round) => round.tape_bytes(),
            None => unreachable!(),
        }
    }
}

/// Whole decoded verifier message, with the complete tape retained internally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Message {
    /// Positive-length tape decoding to the initial empty message.
    Dummy,
    /// Independent alpha coefficients, one OOD point, or one lambda/beta scalar.
    Fields(Vec<F>),
    /// Exactly 77 distinct, ascending initial-domain positions.
    Queries(Vec<u32>),
}

/// Fixed oracles accepted by the new profile; no caller-selected geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Oracle {
    /// The 301 retained base-field trace cells.
    Row,
    /// Both quotient chunks and the independent composition mask in one leaf.
    QuotientAndMask,
    /// Complete fibers of arity 16,16,8,8,4 for source layers zero through four.
    Fri(u8),
    /// All 128 terminal extension-field values in one complete leaf.
    Terminal,
}

impl Oracle {
    pub(super) fn shape(self) -> Result<(u8, u8, usize, usize)> {
        match self {
            Self::Row => Ok((1, 0, LDE_ROWS, COMMITTED_COLUMN_COUNT * 8)),
            Self::QuotientAndMask => Ok((3, 0, LDE_ROWS, 3 * F::BYTES)),
            Self::Fri(round @ 0..=4) => {
                let i = usize::from(round);
                Ok((4, round, FRI_LENGTHS[i + 1], FRI_ARITIES[i] * F::BYTES))
            }
            Self::Terminal => Ok((4, 5, 1, FRI_LENGTHS[5] * F::BYTES)),
            Self::Fri(_) => Err(BindingError::Shape),
        }
    }
}

#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::deep_binding::StatementContext",
    frame = "fastpq_prover::deep::StatementContextV1"
)]
struct StatementContext {
    relation: String,
    layout: String,
    trace_rows: u32,
    lde_rows: u32,
    columns: u32,
    constraints: u32,
    modulus: u64,
    extension_nonresidue: u64,
    lde_root: u64,
    coset_offset: u64,
    fri_arities: [u32; 5],
    fri_lengths: [u32; 6],
    fri_degrees: [u32; 6],
    query_count: u32,
    query_candidates: u32,
    statement: Vec<u8>,
}

/// Nominal Norito frame of the statement context, as the profile descriptor names it.
pub(super) fn context_frame_name() -> String {
    use norito::schema::identity::NoritoSchema as _;
    StatementContext::frame_name()
}

/// Full fixed profile plus caller-owned canonical public statement.
#[derive(Clone, Debug)]
pub(super) struct Context {
    framing: FramingContext,
}

impl Context {
    /// Match the original immutable attempt owner, not merely equal statement bytes.
    pub(super) fn same_attempt(&self, other: &Self) -> bool {
        self.framing.same_attempt(&other.framing)
    }

    /// Bind the outer prepared relation identity and its exact complete statement.
    ///
    /// Only the closed relation bridge supplies the arithmetic owner. Reject any
    /// schema or statement divergence before framing or allocating context bytes.
    pub(super) fn for_relation(relation: &impl DeepRelation) -> Result<Self> {
        Self::preflight_relation(relation)?;
        Self::with_identity(relation.schema().identity, relation.statement_bytes())
    }

    /// Validate the closed relation and fixed envelope without framing or hashing.
    pub(super) fn preflight_relation(relation: &impl DeepRelation) -> Result<()> {
        let schema = relation.schema();
        let inner = relation.deep_relation();
        let reference = inner.schema();
        if schema.trace_rows != TRACE_ROWS
            || schema.width != 342
            || schema.constraints != CONSTRAINTS
            || reference.trace_rows != schema.trace_rows
            || reference.width != schema.width
            || reference.constraints != schema.constraints
            || relation.statement_bytes() != inner.statement_bytes()
        {
            return Err(BindingError::Context);
        }
        Self::check_envelope(schema.identity, relation.statement_bytes())
    }

    /// Explicit raw context fixture, never the prover/verifier relation entry.
    #[cfg(test)]
    pub(super) fn new(statement: &[u8]) -> Result<Self> {
        Self::with_identity(FIXTURE_RELATION_IDENTITY, statement)
    }

    fn check_envelope(identity: &str, statement: &[u8]) -> Result<()> {
        if identity.is_empty()
            || identity.len() > MAX_RELATION_IDENTITY_BYTES
            || statement.is_empty()
            || statement.len() > MAX_STATEMENT_BYTES
        {
            return Err(BindingError::Context);
        }
        Ok(())
    }

    /// The frozen statement context under another prefix, for binding-mutation
    /// tests only: `prefix` receives the encoded context and builds the framing
    /// owner with a changed version, catalog, construction or profile.
    #[cfg(test)]
    pub(super) fn with_prefix_for_test(
        identity: &str,
        statement: &[u8],
        prefix: impl FnOnce(
            &[u8],
        )
            -> std::result::Result<FramingContext, super::compact_sha3::CandidateError>,
    ) -> Result<Self> {
        Self::check_envelope(identity, statement)?;
        let encoded = Self::encode_statement_context(identity, statement)?;
        Ok(Self {
            framing: prefix(&encoded)?,
        })
    }

    fn with_identity(identity: &str, statement: &[u8]) -> Result<Self> {
        Self::check_envelope(identity, statement)?;
        let encoded = Self::encode_statement_context(identity, statement)?;
        Ok(Self {
            framing: FramingContext::new(&encoded)?,
        })
    }

    /// Canonical statement context: relation, layout, geometry and statement.
    fn encode_statement_context(identity: &str, statement: &[u8]) -> Result<Vec<u8>> {
        Ok(norito::encode_canonical(&StatementContext {
            relation: identity.to_owned(),
            layout: LAYOUT_ID.to_owned(),
            trace_rows: fixed_u32(TRACE_ROWS),
            lde_rows: fixed_u32(LDE_ROWS),
            columns: fixed_u32(COMMITTED_COLUMN_COUNT),
            constraints: fixed_u32(CONSTRAINTS),
            modulus: MODULUS,
            extension_nonresidue: EXTENSION_NONRESIDUE,
            lde_root: LDE_ROOT,
            coset_offset: COSET_OFFSET,
            fri_arities: FRI_ARITIES.map(fixed_u32),
            fri_lengths: FRI_LENGTHS.map(fixed_u32),
            fri_degrees: FRI_DEGREES.map(fixed_u32),
            query_count: fixed_u32(QUERY_COUNT),
            query_candidates: fixed_u32(QUERY_CANDIDATES),
            statement: statement.to_vec(),
        })?)
    }

    /// Retained shared public context/cache payload, including actual owner layouts.
    pub(super) fn maximum_retained_payload_bytes(&self) -> Result<usize> {
        Ok(self.framing.maximum_retained_payload_bytes()?)
    }

    /// Exact maximum canonical frame scratch for one fixed-shape leaf or parent.
    /// Public zeros serve length counting only; no commitment or entropy is made.
    pub(super) fn tree_frame_bytes(&self, oracle: Oracle) -> Result<usize> {
        let (leaf, parent) = self.tree_frame_lengths(oracle)?;
        Ok(leaf.max(parent))
    }
    fn tree_frame_lengths(&self, oracle: Oracle) -> Result<(usize, usize)> {
        let (tag, round, _, bytes) = oracle.shape()?;
        let zero = vec![0; bytes];
        let child = [0; Digest::BYTES];
        let leaf = norito::canonical_frame_len(&self.framing.frame(
            1,
            tag,
            round,
            0,
            0,
            Digest::BYTES,
            BodyFields::One(&zero),
        ))?;
        let parent = norito::canonical_frame_len(&self.framing.frame(
            2,
            tag,
            round,
            1,
            0,
            Digest::BYTES,
            BodyFields::Two(&child, &child),
        ))?;
        Ok((leaf, parent))
    }
    /// Exact per-node Keccak permutations; the canonical framing owner counts
    /// its actual body bytes, including fixed Norito header/sequence extents.
    pub(super) fn tree_permutations(&self, oracle: Oracle) -> Result<(usize, usize)> {
        let (leaf, parent) = self.tree_frame_lengths(oracle)?;
        Ok((
            self.framing.body_permutations(leaf)?,
            self.framing.body_permutations(parent)?,
        ))
    }
    /// Complete one-context transcript work: both cached prefixes, all ten
    /// atomic SHAKE tapes, nine whole-tape chains, and the one OOD commitment.
    pub(super) fn transcript_permutations(&self) -> Result<usize> {
        let mut total = self.framing.prefix_permutations();
        let root = [0; Digest::BYTES];
        for ordinal in 1..=10 {
            let round = Round(ordinal);
            let g = self.framing.frame(
                4,
                0,
                ordinal,
                0,
                0,
                round.tape_bytes(),
                BodyFields::One(&root),
            );
            total = total
                .checked_add(
                    self.framing
                        .body_permutations(norito::canonical_frame_len(&g)?)?,
                )
                .and_then(|v| v.checked_add((round.tape_bytes() - 1) / crate::keccak_batch::RATE))
                .ok_or(BindingError::Shape)?;
            if ordinal < 10 {
                let tape = vec![0; round.tape_bytes()];
                let h = self.framing.frame(
                    3,
                    0,
                    ordinal,
                    0,
                    0,
                    Digest::BYTES,
                    BodyFields::Two(&tape, &root),
                );
                total = total
                    .checked_add(
                        self.framing
                            .body_permutations(norito::canonical_frame_len(&h)?)?,
                    )
                    .ok_or(BindingError::Shape)?;
            }
        }
        let ood = vec![0; OOD_VALUES * F::BYTES];
        let h = self
            .framing
            .frame(1, 5, 0, 0, 0, Digest::BYTES, BodyFields::One(&ood));
        total
            .checked_add(
                self.framing
                    .body_permutations(norito::canonical_frame_len(&h)?)?,
            )
            .ok_or(BindingError::Shape)
    }

    /// Hash only canonical complete fixed-shape leaves at valid positions.
    pub(super) fn hash_leaf(&self, oracle: Oracle, index: u32, payload: &[u8]) -> Result<Digest> {
        Ok(self
            .framing
            .hash_frame(&self.leaf_frame(oracle, index, payload)?)?)
    }

    fn leaf_frame<'a>(&self, oracle: Oracle, index: u32, payload: &'a [u8]) -> Result<Frame<'a>> {
        let (tag, round, leaves, bytes) = oracle.shape()?;
        if index as usize >= leaves || payload.len() != bytes || !canonical_words(payload) {
            return Err(BindingError::Shape);
        }
        Ok(self.framing.frame(
            1,
            tag,
            round,
            0,
            index,
            Digest::BYTES,
            BodyFields::One(payload),
        ))
    }

    /// Prepare a complete shape-checked leaf under the unchanged canonical owner.
    #[cfg(any(test, feature = "fastpq-gpu", feature = "simd"))]
    pub(super) fn prepare_leaf(
        &self,
        oracle: Oracle,
        index: u32,
        payload: &[u8],
    ) -> crate::Result<PreparedHashFrame> {
        let frame = self.leaf_frame(oracle, index, payload).map_err(|error| {
            crate::Error::InvalidTraceShape {
                details: error.to_string(),
            }
        })?;
        self.framing.prepare_hash_frame(&frame)
    }

    /// Hash a binary authentication parent, retaining the sole-leaf duplicate rule.
    pub(super) fn hash_parent(
        &self,
        oracle: Oracle,
        level: u32,
        index: u32,
        left: Digest,
        right: Digest,
    ) -> Result<Digest> {
        let (tag, round, leaves, _) = oracle.shape()?;
        if level == 0
            || level > leaves.ilog2().max(1)
            || index as usize >= (leaves >> level).max(1)
            || (leaves == 1 && left != right)
        {
            return Err(BindingError::Shape);
        }
        Ok(self.framing.hash_frame(&self.framing.frame(
            2,
            tag,
            round,
            level,
            index,
            Digest::BYTES,
            BodyFields::Two(&left.into_bytes(), &right.into_bytes()),
        ))?)
    }

    /// Hash one parent addressed by in-memory `usize` tree coordinates.
    ///
    /// No fixed tree has a level or index beyond `u32`; such coordinates are
    /// rejected with the same shape error as every other invalid position.
    pub(super) fn hash_parent_at(
        &self,
        oracle: Oracle,
        level: usize,
        index: usize,
        left: Digest,
        right: Digest,
    ) -> Result<Digest> {
        let (Ok(level), Ok(index)) = (u32::try_from(level), u32::try_from(index)) else {
            return Err(BindingError::Shape);
        };
        self.hash_parent(oracle, level, index, left, right)
    }

    /// Prepare a complete parent; use the same strict shape checks as verification.
    #[cfg(any(test, feature = "fastpq-gpu", feature = "simd"))]
    pub(super) fn prepare_parent(
        &self,
        oracle: Oracle,
        level: u32,
        index: u32,
        left: Digest,
        right: Digest,
    ) -> crate::Result<PreparedHashFrame> {
        let (tag, round, leaves, _) =
            oracle
                .shape()
                .map_err(|error| crate::Error::InvalidTraceShape {
                    details: error.to_string(),
                })?;
        if level == 0
            || level > leaves.ilog2().max(1)
            || index as usize >= (leaves >> level).max(1)
            || (leaves == 1 && left != right)
        {
            return Err(crate::Error::InvalidTraceShape {
                details: BindingError::Shape.to_string(),
            });
        }
        self.framing.prepare_hash_frame(&self.framing.frame(
            2,
            tag,
            round,
            level,
            index,
            Digest::BYTES,
            BodyFields::Two(&left.into_bytes(), &right.into_bytes()),
        ))
    }

    fn hash_ood(&self, current: &[F], next: &[F], quotient: &[F]) -> Result<Digest> {
        let bytes = ood_bytes(current, next, quotient)?;
        Ok(self.framing.hash_frame(&self.framing.frame(
            1,
            5,
            0,
            0,
            0,
            Digest::BYTES,
            BodyFields::One(&bytes),
        ))?)
    }

    fn chain(&self, round: Round, tape: &[u8], root: Digest) -> Result<Digest> {
        if round.0 == 10 || tape.len() != round.tape_bytes() {
            return Err(BindingError::Phase);
        }
        Ok(self.framing.hash_frame(&self.framing.frame(
            3,
            0,
            round.0,
            0,
            0,
            Digest::BYTES,
            BodyFields::Two(tape, &root.into_bytes()),
        ))?)
    }
}

fn canonical_words(bytes: &[u8]) -> bool {
    bytes.len().is_multiple_of(8)
        && bytes
            .chunks_exact(8)
            .all(|word| u64::from_le_bytes(word.try_into().expect("exact field word")) < MODULUS)
}

fn ood_bytes(
    current: &[F],
    next: &[F],
    quotient: &[F],
) -> Result<super::secret_polynomial::SecretPolynomial<u8>> {
    if current.len() != COMMITTED_COLUMN_COUNT
        || next.len() != COMMITTED_COLUMN_COUNT
        || quotient.len() != 2
        || current
            .iter()
            .chain(next)
            .chain(quotient)
            .any(|v| v.coefficients().iter().any(|&c| c >= MODULUS))
    {
        return Err(BindingError::Shape);
    }
    let mut bytes = super::secret_polynomial::SecretPolynomial::<u8>::zeroed(OOD_VALUES * F::BYTES)
        .map_err(|_| BindingError::Tape)?;
    for (target, value) in bytes
        .chunks_exact_mut(F::BYTES)
        .zip(current.iter().chain(next).chain(quotient))
    {
        target.copy_from_slice(&value.to_le_bytes());
    }
    Ok(bytes)
}

fn decode_tape(tape: &RawTapeV1) -> Result<Message> {
    let decoded = tape.decode().map_err(|error| match error {
        RawTapeErrorV1::BaseOod => BindingError::BaseOod,
        RawTapeErrorV1::Exhausted => BindingError::Exhausted,
        RawTapeErrorV1::Allocation | RawTapeErrorV1::Length => BindingError::Tape,
    })?;
    Ok(match decoded {
        RawTapeMessageV1::Dummy => Message::Dummy,
        RawTapeMessageV1::Queries(queries) => Message::Queries(queries),
        RawTapeMessageV1::Fields(values) => Message::Fields(
            values
                .into_iter()
                .map(|v| F::new(v).expect("finite decoder returns canonical limbs"))
                .collect(),
        ),
    })
}
#[cfg(test)]
fn decode(round: Round, raw: &[u8]) -> Result<Message> {
    let tape = RawTapeV1::from_bytes(
        RawTapeRoundV1::new(round.0).ok_or(BindingError::Round)?,
        raw,
    )
    .map_err(|_| BindingError::Tape)?;
    decode_tape(&tape)
}
#[derive(Debug)]
enum Phase {
    Ready(Round),
    Pending { round: Round, raw: RawTapeV1 },
    Complete,
    Aborted,
}

/// Fixed schedule; success here does not mean the proof or statement is valid.
#[derive(Debug)]
pub(super) struct Transcript {
    context: Context,
    predecessor: Digest,
    phase: Phase,
}

impl Drop for Transcript {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.predecessor);
    }
}

impl Transcript {
    /// Begin with the fixed zero anchor and the dummy whole-message tape.
    pub(super) fn new(context: Context) -> Self {
        Self {
            context,
            predecessor: Digest::default(),
            phase: Phase::Ready(Round(1)),
        }
    }

    /// Decode one entire tape; a sampling or framing failure permanently aborts.
    pub(super) fn challenge(&mut self) -> Result<Message> {
        self.challenge_owned(|context, round, body| {
            Ok(context.framing.tape(
                RawTapeRoundV1::new(round.0).ok_or(BindingError::Round)?,
                body,
            )?)
        })
    }
    fn challenge_owned(
        &mut self,
        derive: impl FnOnce(&Context, Round, &[u8]) -> Result<RawTapeV1>,
    ) -> Result<Message> {
        let Phase::Ready(round) = self.phase else {
            self.phase = Phase::Aborted;
            return Err(BindingError::Phase);
        };
        self.phase = Phase::Aborted;
        let predecessor = self.predecessor.into_bytes();
        let frame = self.context.framing.frame(
            4,
            0,
            round.0,
            0,
            0,
            round.tape_bytes(),
            BodyFields::One(&predecessor),
        );
        let encoded = super::compact_sha3::encode_private_frame(&frame)?;
        let raw = derive(&self.context, round, &encoded)?;
        if raw.round().ordinal() != round.0 {
            return Err(BindingError::Phase);
        }
        let message = decode_tape(&raw)?;
        self.phase = if round.0 == 10 {
            Phase::Complete
        } else {
            Phase::Pending { round, raw }
        };
        Ok(message)
    }
    #[cfg(test)]
    fn challenge_with(
        &mut self,
        fill: impl FnOnce(&Context, Round, &[u8], &mut [u8]) -> Result<()>,
    ) -> Result<Message> {
        self.challenge_owned(|context, round, body| {
            let mut bytes = zeroize::Zeroizing::new(vec![0; round.tape_bytes()]);
            fill(context, round, body, &mut bytes)?;
            RawTapeV1::from_bytes(
                RawTapeRoundV1::new(round.0).ok_or(BindingError::Round)?,
                &bytes,
            )
            .map_err(|_| BindingError::Tape)
        })
    }

    /// Commit exactly the oracle expected after this message; OOD has its own API.
    pub(super) fn commit_root(&mut self, oracle: Oracle, root: Digest) -> Result<()> {
        let Phase::Pending { round, .. } = &self.phase else {
            self.phase = Phase::Aborted;
            return Err(BindingError::Phase);
        };
        let expected = match round.0 {
            1 => Oracle::Row,
            2 => Oracle::QuotientAndMask,
            4..=8 => Oracle::Fri(round.0 - 4),
            9 => Oracle::Terminal,
            _ => {
                self.phase = Phase::Aborted;
                return Err(BindingError::Phase);
            }
        };
        if oracle != expected {
            self.phase = Phase::Aborted;
            return Err(BindingError::Phase);
        }
        self.commit_digest(root)
    }

    /// Bind every coordinate of both OOD rows and quotient halves before lambda.
    pub(super) fn commit_ood(&mut self, current: &[F], next: &[F], quotient: &[F]) -> Result<()> {
        if !matches!(
            self.phase,
            Phase::Pending {
                round: Round(3),
                ..
            }
        ) {
            self.phase = Phase::Aborted;
            return Err(BindingError::Phase);
        }
        let digest = match self.context.hash_ood(current, next, quotient) {
            Ok(digest) => digest,
            Err(error) => {
                self.phase = Phase::Aborted;
                return Err(error);
            }
        };
        self.commit_digest(digest)
    }

    fn commit_digest(&mut self, root: Digest) -> Result<()> {
        let Phase::Pending { round, raw } = std::mem::replace(&mut self.phase, Phase::Aborted)
        else {
            return Err(BindingError::Phase);
        };
        self.predecessor = self.context.chain(round, raw.as_bytes(), root)?;
        self.phase = Phase::Ready(Round::new(round.0 + 1)?);
        Ok(())
    }
}

#[cfg(test)]
#[path = "deep_binding/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "deep_binding/retirement_tests.rs"]
mod retirement_tests;

#[cfg(test)]
#[path = "deep_binding/core_retirement_tests.rs"]
mod core_retirement_tests;

#[cfg(test)]
#[path = "deep_binding/frozen_tests.rs"]
mod frozen_tests;
