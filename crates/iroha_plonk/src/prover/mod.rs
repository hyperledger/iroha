//! The PIPA-v1 prover (task T12, spec sections 6, 7, 9 and 10).
//!
//! [`create_proof`] writes one proof for one circuit instance:
//!
//! 1. the prelude (`transcript_repr` and the instance frame) and the
//!    instances, committed or absorbed by value ([`advice`]);
//! 2. the advice commitments, then `theta` ([`advice`]);
//! 3. the permuted lookup columns `A'`, `S'`, then `beta`, `gamma`
//!    ([`lookup`]);
//! 4. the permutation products `z_s` ([`permutation`]) and the lookup
//!    products `z` ([`lookup`]);
//! 5. the random polynomial `R`, then `y` ([`vanishing`]);
//! 6. the quotient `h`, evaluated on exactly `d - 1` cosets by the compiled
//!    evaluator and recombined with a Vandermonde solve ([`quotient`]), split
//!    into `d - 1` blinded pieces, then `x` ([`vanishing`]);
//! 7. the evaluations of spec section 7 rows 7-11 and the multiopen with
//!    static query grouping, whose IPA returns the folded generator `G'_0`
//!    ([`multiopen`]); with a `FoldedGenerator` suffix, `G'_0` ends the proof.
//!
//! # Randomness (`BlindingScheduleV1`, S8)
//!
//! Every random value is a `Field::random` draw (eight `next_u64` words) from
//! one stream consumed on the calling thread, in the order of spec section 10:
//!
//! 1. advice rows `u..n`, column by column, then one blind per advice column;
//! 2. per lookup: `A'` rows `u..n`, `S'` rows `u..n`, the `A'` blind, the `S'`
//!    blind;
//! 3. per permutation set: `z_s` rows `n-b..n`, then its blind;
//! 4. per lookup: `z` rows `n-b..n`, then its blind;
//! 5. the `n` coefficients of `R`, then its blind;
//! 6. the `d - 1` blinds of the `h` pieces;
//! 7. the `q'` blind;
//! 8. the `n` coefficients of the IPA `s` polynomial and its blind, then per
//!    round the randomness of `L_j` and `R_j`.
//!
//! The stream comes from an opaque [`ProverRandomness`] with exactly three
//! production sources (the OS CSPRNG, a hedged derivation over fresh entropy,
//! the witness digest and the statement, and a recovery seed whose stream
//! this crate keys with the witness and statement digests, so a caller
//! cannot opt out of the binding). Fixed seeds exist only in this crate's
//! unit tests.
//!
//! # Determinism
//!
//! The proof bytes are a pure function of the key, the witness, the
//! instances and the random stream: every kernel is exact field and group
//! arithmetic, parallel loops write disjoint outputs, and the stream is
//! never touched off the calling thread, so the Rayon pool size changes no
//! byte.

use core::fmt;

use ff::Field;
use iroha_pasta::{
    PastaCurve, PastaField,
    fft::FftError,
    msm::{MemoryBudget, MsmError},
    poseidon::PoseidonField,
};
use rand_chacha::ChaCha20Rng;
use rand_core_06::{CryptoRng, RngCore, SeedableRng};

use crate::{
    cs::{
        CircuitDescriptorV1, CsError, DescriptorConfig, DescriptorError, ProtocolDescriptor,
        descriptor::{Blake2bPersonal, blake2b_personal},
    },
    frontend::{self, Circuit},
    keys::{KeyError, ProvingKey},
    pcs::{ipa::PinnedParams, multiopen::MultiopenError},
    protocol::{AllTerms, ConstraintFilter, Protocol, ProtocolError},
    transcript::{
        DescriptorHash, Transcript, TranscriptError, TranscriptRepr, TranscriptWrite,
        TranscriptWriter, absorb_prelude, absorb_prelude_v2,
    },
};

mod advice;
mod batch;
mod lookup;
mod multiopen;
mod permutation;
pub mod quotient;
pub use quotient::{QuotientWorkspace, WorkspaceError};
#[cfg(test)]
mod cancellation_tests;
#[cfg(test)]
mod tests;
mod vanishing;

/// `BLAKE2b` personalization of the statement digest.
pub const STATEMENT_PERSONA: &[u8; 16] = b"PIPA-v1-Statemnt";
/// `BLAKE2b` personalization of the witness digest.
pub const WITNESS_PERSONA: &[u8; 16] = b"PIPA-v1-WitnessD";
/// `BLAKE2b` personalization of the hedged stream seed.
pub const HEDGED_PERSONA: &[u8; 16] = b"PIPA-v1-ProveRng";
/// `BLAKE2b` personalization of the recovery-stream context.
pub const RECOVERY_PERSONA: &[u8; 16] = b"PIPA-v1-Recovery";
/// `BLAKE2b` personalization of the recovery-stream key, which binds the
/// bytes drawn from the caller's derivation to the context inside this crate.
pub const RECOVERY_KEY_PERSONA: &[u8; 16] = b"PIPA-v1-RecovKey";
/// The purpose label a recovery-seed derivation should use for prover
/// randomness (for example `seed.rng(RECOVERY_PURPOSE, context)` of a
/// caller-held secret recovery seed).
pub const RECOVERY_PURPOSE: &[u8] = b"iroha_plonk:pipa-v1:prover-randomness";

/// Proving failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProverError {
    /// The caller cancelled this operation; it has no completed proof result.
    Cancelled,
    /// The circuit failed to synthesize its witness.
    Synthesis(frontend::Error),
    /// The circuit's constraint system, fixed columns, selectors or copy
    /// constraints differ from the ones the proving key was generated for.
    CircuitMismatch,
    /// The parameters are not the ones the descriptor names.
    ParamsMismatch,
    /// The advice columns have the wrong shape.
    WitnessShape {
        /// The required count (columns) or length (rows).
        expected: usize,
        /// The supplied count or length.
        found: usize,
    },
    /// The number of instance columns differs from the descriptor.
    /// An instance value is outside its declared integer type.
    InstanceType {
        /// Instance column.
        column: usize,
        /// Row within the column.
        row: usize,
    },
    /// Incorrect instance-column count.
    InstanceColumns {
        /// The descriptor's count.
        expected: usize,
        /// The supplied count.
        found: usize,
    },
    /// An instance column does not have its exact declared length (S4).
    InstanceLength {
        /// The column.
        column: usize,
        /// The declared length.
        expected: usize,
        /// The supplied length.
        found: usize,
    },
    /// A lookup input value on a usable row is missing from the table.
    LookupInputMissing {
        /// The lookup index.
        lookup: usize,
    },
    /// A verifier-computed instance commitment is the identity (negligible).
    IdentityInstanceCommitment {
        /// The instance column.
        column: usize,
    },
    /// The OS random-number generator failed.
    Entropy,
    /// The recovery derivation returned no stream.
    RecoveryStream,
    /// The challenge `x` is zero or in the subgroup (negligible).
    DegenerateChallenge,
    /// The protocol tables could not be derived from the descriptor.
    Protocol(ProtocolError),
    /// The descriptor could not be rebuilt from the circuit.
    Descriptor(DescriptorError),
    /// A proving-key polynomial or coset was unavailable.
    Key(KeyError),
    /// The caller-owned quotient workspace could not admit its buffers.
    Workspace(WorkspaceError),
    /// An MSM failed (budget or size).
    Msm(MsmError),
    /// An FFT failed.
    Fft(FftError),
    /// A transcript write failed (an identity commitment, negligible).
    Transcript(TranscriptError),
    /// The multiopen failed.
    Multiopen(MultiopenError),
}

impl ProverError {
    /// Whether this failure is cooperative cancellation, never an invalid proof.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Cancelled => true,
            Self::Msm(error) => matches!(error, MsmError::Cancelled),
            Self::Fft(error) => matches!(error, FftError::Cancelled),
            Self::Key(error) => error.is_cancelled(),
            Self::Synthesis(error) => matches!(error, frontend::Error::Cancelled),
            Self::Multiopen(error) => error.is_cancelled(),
            _ => false,
        }
    }
}

impl fmt::Display for ProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::InstanceType { column, row } => {
                write!(f, "instance ({column}, {row}) is outside its declared type")
            }
            Self::Synthesis(error) => write!(f, "synthesis: {error}"),
            Self::CircuitMismatch => f.write_str("the circuit does not match the proving key"),
            Self::ParamsMismatch => f.write_str("the parameters do not match the descriptor"),
            Self::WitnessShape { expected, found } => {
                write!(f, "advice shape: {found} supplied, {expected} expected")
            }
            Self::InstanceColumns { expected, found } => {
                write!(f, "{found} instance columns supplied, {expected} declared")
            }
            Self::InstanceLength {
                column,
                expected,
                found,
            } => write!(
                f,
                "instance column {column} has {found} values, {expected} declared"
            ),
            Self::LookupInputMissing { lookup } => {
                write!(f, "lookup {lookup} has an input missing from its table")
            }
            Self::IdentityInstanceCommitment { column } => {
                write!(f, "instance column {column} commits to the identity")
            }
            Self::Entropy => f.write_str("the OS random-number generator failed"),
            Self::RecoveryStream => f.write_str("the recovery derivation returned no stream"),
            Self::DegenerateChallenge => f.write_str("the challenge x is degenerate"),
            Self::Protocol(error) => write!(f, "protocol: {error}"),
            Self::Descriptor(error) => write!(f, "descriptor: {error}"),
            Self::Key(error) => write!(f, "key: {error}"),
            Self::Workspace(error) => write!(f, "workspace: {error}"),
            Self::Msm(error) => write!(f, "MSM: {error}"),
            Self::Fft(error) => write!(f, "FFT: {error}"),
            Self::Transcript(error) => write!(f, "transcript: {error}"),
            Self::Multiopen(error) => write!(f, "multiopen: {error}"),
        }
    }
}

impl std::error::Error for ProverError {}

impl From<iroha_pasta::Cancelled> for ProverError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

impl From<frontend::Error> for ProverError {
    fn from(error: frontend::Error) -> Self {
        if matches!(error, frontend::Error::Cancelled) {
            Self::Cancelled
        } else {
            Self::Synthesis(error)
        }
    }
}

impl From<CsError> for ProverError {
    fn from(error: CsError) -> Self {
        Self::Synthesis(error.into())
    }
}

impl From<ProtocolError> for ProverError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<DescriptorError> for ProverError {
    fn from(error: DescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

impl From<KeyError> for ProverError {
    fn from(error: KeyError) -> Self {
        if matches!(error, KeyError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Key(error)
        }
    }
}

impl From<MsmError> for ProverError {
    fn from(error: MsmError) -> Self {
        if matches!(error, MsmError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Msm(error)
        }
    }
}

impl From<FftError> for ProverError {
    fn from(error: FftError) -> Self {
        if matches!(error, FftError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Fft(error)
        }
    }
}

impl From<TranscriptError> for ProverError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<MultiopenError> for ProverError {
    fn from(error: MultiopenError) -> Self {
        if matches!(error, MultiopenError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Multiopen(error)
        }
    }
}

/// A cryptographic random-number generator the prover may draw from.
pub trait ProverRng: RngCore + CryptoRng {}

impl<R: RngCore + CryptoRng + ?Sized> ProverRng for R {}

/// A recovery derivation: maps the context digest to a stream.
type RecoveryDerivation<'a> =
    Box<dyn FnOnce(&[u8; 32]) -> Option<Box<dyn ProverRng + Send + 'a>> + Send + 'a>;

/// Where the prover's random stream comes from.
enum Source<'a> {
    /// A `ChaCha20` stream keyed by 32 bytes of OS entropy.
    Os,
    /// A `ChaCha20` stream keyed by `BLAKE2b(OS entropy, statement, witness)`.
    Hedged,
    /// A caller derivation from the recovery context.
    Recovery(RecoveryDerivation<'a>),
    /// A caller-supplied stream (unit tests only).
    #[cfg(test)]
    External(Box<dyn ProverRng + Send + 'a>),
}

/// The prover's randomness: an opaque value with exactly three production
/// sources (spec section 10, S8).
///
/// - [`ProverRandomness::os`]: a `ChaCha20` stream keyed by 32 bytes of OS
///   entropy;
/// - [`ProverRandomness::hedged`]: a `ChaCha20` stream keyed by
///   `BLAKE2b(32, "PIPA-v1-ProveRng", os_entropy || statement || witness)`,
///   so a weak or repeating OS generator that still returns bytes yields
///   distinct streams for distinct witnesses and statements; an OS generator
///   that fails is an error ([`ProverError::Entropy`]), never a fallback;
/// - [`ProverRandomness::recovery`]: a deterministic stream for a recovery
///   seed (for example a wallet's secret recovery seed). The prover computes
///   the context `BLAKE2b(32, "PIPA-v1-Recovery", statement || witness)` from
///   the actual witness, hands it to the caller's derivation, draws 32 bytes
///   `r` from the stream the derivation returns, and keys the stream it
///   actually uses itself: `ChaCha20(BLAKE2b(32, "PIPA-v1-RecovKey", r ||
///   context))` ([`recovery_stream_key`]). Two witnesses or statements proved
///   under one seed therefore get unrelated blinds even when the derivation
///   ignores the context.
///
/// The statement digest is `BLAKE2b(32, "PIPA-v1-Statemnt",
/// descriptor_digest || transcript_repr || u32_le(columns) || (u32_le(len)
/// || values) per instance column)`; the witness digest is `BLAKE2b(32,
/// "PIPA-v1-WitnessD", u32_le(advice columns) || u32_le(u) || the usable
/// rows of every advice column)`.
///
/// No seed or byte buffer is accepted outside unit tests.
pub struct ProverRandomness<'a> {
    source: Source<'a>,
}

impl fmt::Debug for ProverRandomness<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            Source::Os => "Os",
            Source::Hedged => "Hedged",
            Source::Recovery(_) => "Recovery",
            #[cfg(test)]
            Source::External(_) => "External",
        };
        f.debug_struct("ProverRandomness")
            .field("source", &source)
            .finish()
    }
}

/// The statement and witness digests a stream may be bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Binding {
    statement: [u8; 32],
    witness: [u8; 32],
}

/// 32 bytes of OS entropy.
fn os_entropy() -> Result<[u8; 32], ProverError> {
    let mut seed = [0_u8; 32];
    rand_core_06::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|_| ProverError::Entropy)?;
    Ok(seed)
}

impl<'a> ProverRandomness<'a> {
    /// A `ChaCha20` stream keyed by 32 bytes of OS entropy.
    #[must_use]
    pub fn os() -> Self {
        Self { source: Source::Os }
    }

    /// The hedged derivation over fresh OS entropy, the statement digest and
    /// the witness digest (the recommended default).
    #[must_use]
    pub fn hedged() -> Self {
        Self {
            source: Source::Hedged,
        }
    }

    /// A deterministic recovery stream: `derive` receives the context digest
    /// `BLAKE2b(32, "PIPA-v1-Recovery", statement || witness)` and returns a
    /// stream, typically `seed.rng(RECOVERY_PURPOSE, context)` of a
    /// caller-held secret recovery seed. The prover draws 32 bytes `r` from
    /// it and proves with `ChaCha20(`[`recovery_stream_key`]`(r, context))`,
    /// so the witness and statement binding is enforced here and cannot be
    /// skipped by a derivation that ignores the context (two witnesses never
    /// share blinds). Secrecy of the blinds still requires the derivation to be
    /// keyed by a secret seed: with a public or constant derivation the
    /// blinds are a public function of the witness. The prover fails with
    /// [`ProverError::RecoveryStream`] when the derivation returns an error
    /// or its stream fails.
    #[must_use]
    pub fn recovery<R, E, D>(derive: D) -> Self
    where
        D: FnOnce(&[u8; 32]) -> Result<R, E> + Send + 'a,
        R: RngCore + CryptoRng + Send + 'a,
    {
        let derivation: RecoveryDerivation<'a> = Box::new(move |context: &[u8; 32]| {
            let rng = derive(context).ok()?;
            let boxed: Box<dyn ProverRng + Send + 'a> = Box::new(rng);
            Some(boxed)
        });
        Self {
            source: Source::Recovery(derivation),
        }
    }

    /// A caller-supplied stream. Unit tests only (spec
    /// 6.4): it reproduces vendored proofs from their fixed seeds.
    #[cfg(test)]
    #[doc(hidden)]
    #[must_use]
    pub fn from_rng_for_tests<R: ProverRng + Send + 'a>(rng: R) -> Self {
        Self {
            source: Source::External(Box::new(rng)),
        }
    }

    /// A `ChaCha20` stream from a fixed seed. Unit tests
    /// only.
    #[cfg(test)]
    #[doc(hidden)]
    #[must_use]
    pub fn fixed_seed_for_tests(seed: [u8; 32]) -> Self {
        Self::from_rng_for_tests(ChaCha20Rng::from_seed(seed))
    }

    /// Whether this source needs the statement and witness digests.
    fn needs_binding(&self) -> bool {
        matches!(self.source, Source::Hedged | Source::Recovery(_))
    }

    /// Opens the stream.
    fn into_stream(self, binding: Option<Binding>) -> Result<StreamRng<'a>, ProverError> {
        match self.source {
            Source::Os => Ok(StreamRng::ChaCha(Box::new(ChaCha20Rng::from_seed(
                os_entropy()?,
            )))),
            Source::Hedged => {
                let binding = binding.ok_or(ProverError::Entropy)?;
                let entropy = os_entropy()?;
                let seed = blake2b_personal::<32>(
                    HEDGED_PERSONA,
                    &[&entropy, &binding.statement, &binding.witness],
                );
                Ok(StreamRng::ChaCha(Box::new(ChaCha20Rng::from_seed(seed))))
            }
            Source::Recovery(derive) => {
                let binding = binding.ok_or(ProverError::RecoveryStream)?;
                let context = recovery_context(&binding.statement, &binding.witness);
                let mut caller = derive(&context).ok_or(ProverError::RecoveryStream)?;
                let mut drawn = [0_u8; 32];
                caller
                    .try_fill_bytes(&mut drawn)
                    .map_err(|_| ProverError::RecoveryStream)?;
                let key = recovery_stream_key(&drawn, &context);
                drawn.fill(0);
                Ok(StreamRng::ChaCha(Box::new(ChaCha20Rng::from_seed(key))))
            }
            #[cfg(test)]
            Source::External(rng) => Ok(StreamRng::Boxed(rng)),
        }
    }
}

/// `BLAKE2b(32, "PIPA-v1-Recovery", statement || witness)`.
#[must_use]
pub fn recovery_context(statement: &[u8; 32], witness: &[u8; 32]) -> [u8; 32] {
    blake2b_personal::<32>(RECOVERY_PERSONA, &[statement, witness])
}

/// The `ChaCha20` key of a recovery stream: `BLAKE2b(32, "PIPA-v1-RecovKey",
/// drawn || context)`, where `drawn` are the first 32 bytes of the caller's
/// derived stream and `context` is [`recovery_context`].
#[must_use]
pub fn recovery_stream_key(drawn: &[u8; 32], context: &[u8; 32]) -> [u8; 32] {
    blake2b_personal::<32>(RECOVERY_KEY_PERSONA, &[drawn, context])
}

/// The opened random stream.
enum StreamRng<'a> {
    ChaCha(Box<ChaCha20Rng>),
    /// A caller-supplied stream: only [`ProverRandomness::from_rng_for_tests`]
    /// (unit tests) constructs it; production streams are
    /// always the `ChaCha20` streams this crate keys.
    #[cfg_attr(not(test), allow(dead_code))]
    Boxed(Box<dyn ProverRng + Send + 'a>),
}

impl RngCore for StreamRng<'_> {
    fn next_u32(&mut self) -> u32 {
        match self {
            Self::ChaCha(rng) => rng.next_u32(),
            Self::Boxed(rng) => rng.next_u32(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            Self::ChaCha(rng) => rng.next_u64(),
            Self::Boxed(rng) => rng.next_u64(),
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            Self::ChaCha(rng) => rng.fill_bytes(dest),
            Self::Boxed(rng) => rng.fill_bytes(dest),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        match self {
            Self::ChaCha(rng) => rng.try_fill_bytes(dest),
            Self::Boxed(rng) => rng.try_fill_bytes(dest),
        }
    }
}

impl CryptoRng for StreamRng<'_> {}

/// A witness: the advice columns and the instance columns of one circuit
/// instance, checked against a proving key. Advice values are secret and
/// are zeroized when the witness is dropped.
pub struct Witness<F: PastaField> {
    advice: Vec<Vec<F>>,
    instances: Vec<Vec<F>>,
}

impl<F: PastaField> fmt::Debug for Witness<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Witness")
            .field("advice_columns", &self.advice.len())
            .field("instances", &self.instances)
            .finish()
    }
}

impl<F: PastaField> Drop for Witness<F> {
    fn drop(&mut self) {
        for column in &mut self.advice {
            for value in column.iter_mut() {
                value.zeroize();
            }
        }
    }
}

/// A reusable caller-owned witness or one whose advice buffers can be
/// transferred to the prover after shape and randomness-binding checks.
enum WitnessInput<'a, F: PastaField> {
    Borrowed(&'a Witness<F>),
    Owned(Witness<F>),
}

impl<F: PastaField> WitnessInput<'_, F> {
    fn witness(&self) -> &Witness<F> {
        match self {
            Self::Borrowed(witness) => witness,
            Self::Owned(witness) => witness,
        }
    }

    /// The returned columns are immediately placed in zeroizing [`advice::Advice`].
    fn take_advice(&mut self) -> Vec<Vec<F>> {
        match self {
            Self::Borrowed(witness) => witness.advice().to_vec(),
            Self::Owned(witness) => core::mem::take(&mut witness.advice),
        }
    }
}

/// Checks the instance shape against the descriptor (S4).
fn check_instances<F: PastaField>(
    descriptor: &ProtocolDescriptor,
    instances: &[Vec<F>],
) -> Result<(), ProverError> {
    if instances.len() != descriptor.instance_lengths.len() {
        return Err(ProverError::InstanceColumns {
            expected: descriptor.instance_lengths.len(),
            found: instances.len(),
        });
    }
    for (column, (values, length)) in instances
        .iter()
        .zip(&descriptor.instance_lengths)
        .enumerate()
    {
        let expected = usize::try_from(*length).map_err(|_| ProtocolError::Overflow)?;
        if values.len() != expected {
            return Err(ProverError::InstanceLength {
                column,
                expected,
                found: values.len(),
            });
        }
    }
    if let Some((column, row)) = descriptor.invalid_instance(instances) {
        return Err(ProverError::InstanceType { column, row });
    }
    Ok(())
}

impl<F: PastaField> Witness<F> {
    /// Synthesizes `circuit` with `instances` and checks that its constraint
    /// system, fixed columns, selectors and copy constraints are the ones
    /// `pk` was generated for. The copies are compared through the key's
    /// [`ProvingKey::copy_digest`], streamed in constant memory, not by
    /// recomputing `sigma`. The synthesized advice is moved into the witness
    /// (never cloned) right after synthesis, so it is zeroized on every
    /// return path.
    ///
    /// # Errors
    ///
    /// [`ProverError::Synthesis`] when synthesis fails,
    /// [`ProverError::CircuitMismatch`] when the circuit is not `pk`'s, and
    /// the shape errors of [`Witness::from_columns`].
    pub fn from_circuit<C, Ci>(
        pk: &ProvingKey<C>,
        circuit: &Ci,
        instances: &[Vec<F>],
    ) -> Result<Self, ProverError>
    where
        C: PastaCurve<ScalarExt = F>,
        Ci: Circuit<F>,
    {
        Self::from_circuit_cancellable(pk, circuit, instances, None)
    }

    /// Synthesizes and validates a witness with the caller's cancellation signal.
    ///
    /// # Errors
    /// As [`Self::from_circuit`], or [`ProverError::Cancelled`].
    pub fn from_circuit_cancellable<C, Ci>(
        pk: &ProvingKey<C>,
        circuit: &Ci,
        instances: &[Vec<F>],
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, ProverError>
    where
        C: PastaCurve<ScalarExt = F>,
        Ci: Circuit<F>,
    {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let descriptor = pk.binding().descriptor();
        check_instances(descriptor, instances)?;
        let k = u32::from(descriptor.k);
        let mut synthesized =
            frontend::synthesize_cancellable(circuit, k, Some(instances), cancellation)?;
        let advice = synthesized
            .tables
            .take_advice()
            .ok_or(frontend::Error::WitnessRequired)?;
        // Owned by a zeroizing witness from here on.
        let witness = Self {
            advice,
            instances: instances.to_vec(),
        };
        let tables = &synthesized.tables;
        let first_column = usize::try_from(descriptor.selectors.first_column)
            .map_err(|_| ProtocolError::Overflow)?;
        let finalized = synthesized
            .cs
            .clone()
            .finalize(tables.selectors(), descriptor.selectors.compress)?;
        let rebuilt = CircuitDescriptorV1::from_constraint_system(
            &finalized,
            DescriptorConfig {
                curve: descriptor.curve,
                k,
                transcript: crate::cs::TranscriptV1::Blake2bChallenge255,
                instance_mode: descriptor.instance_mode,
                proof_suffix: descriptor.proof_suffix,
            },
        )?;
        let mut rebuilt: ProtocolDescriptor = (&rebuilt).into();
        rebuilt.transcript = descriptor.transcript;
        rebuilt
            .instance_types
            .clone_from(&descriptor.instance_types);
        let fixed = pk.fixed_values();
        if rebuilt != *descriptor
            || fixed.get(..first_column) != Some(tables.fixed())
            || fixed.get(first_column..) != Some(finalized.selector_columns())
            || tables.permutation().mapping_digest() != *pk.copy_digest()
        {
            return Err(ProverError::CircuitMismatch);
        }
        witness.check_shape(pk)?;
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        Ok(witness)
    }

    /// A witness from explicit advice columns (`n` rows each; rows from `u`
    /// on are replaced by blinding values) and instance columns of their
    /// exact declared lengths. This is the assignment import for tables
    /// produced elsewhere (for example the oracle's vendored circuits).
    ///
    /// # Errors
    ///
    /// [`ProverError::WitnessShape`], [`ProverError::InstanceColumns`] or
    /// [`ProverError::InstanceLength`].
    pub fn from_columns<C>(
        pk: &ProvingKey<C>,
        advice: Vec<Vec<F>>,
        instances: Vec<Vec<F>>,
    ) -> Result<Self, ProverError>
    where
        C: PastaCurve<ScalarExt = F>,
    {
        let witness = Self { advice, instances };
        witness.check_shape(pk)?;
        Ok(witness)
    }

    /// Checks the advice and instance shapes against `pk`'s descriptor.
    fn check_shape<C>(&self, pk: &ProvingKey<C>) -> Result<(), ProverError>
    where
        C: PastaCurve<ScalarExt = F>,
    {
        let descriptor = pk.binding().descriptor();
        let columns =
            usize::try_from(descriptor.num_advice_columns).map_err(|_| ProtocolError::Overflow)?;
        if self.advice.len() != columns {
            return Err(ProverError::WitnessShape {
                expected: columns,
                found: self.advice.len(),
            });
        }
        let n = pk.binding().n();
        if let Some(column) = self.advice.iter().find(|column| column.len() != n) {
            return Err(ProverError::WitnessShape {
                expected: n,
                found: column.len(),
            });
        }
        check_instances(descriptor, &self.instances)
    }

    /// The instance columns.
    #[must_use]
    pub fn instances(&self) -> &[Vec<F>] {
        &self.instances
    }

    /// The advice columns (secret).
    pub(crate) fn advice(&self) -> &[Vec<F>] {
        &self.advice
    }

    /// The witness digest over the usable rows of every advice column,
    /// streamed value by value (no copy of the advice is built; each
    /// encoded value is wiped after it is absorbed).
    fn digest(
        &self,
        usable_rows: usize,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<[u8; 32], ProverError> {
        let mut hasher = Blake2bPersonal::<32>::new(WITNESS_PERSONA);
        hasher.update(
            &u32::try_from(self.advice.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        hasher.update(&u32::try_from(usable_rows).unwrap_or(u32::MAX).to_le_bytes());
        for column in &self.advice {
            for (index, value) in column.iter().take(usable_rows).enumerate() {
                if index % 1024 == 0 {
                    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                }
                let mut repr = value.to_repr();
                hasher.update(repr.as_ref());
                repr.as_mut().fill(0);
            }
        }
        Ok(hasher.finalize())
    }
}

/// The statement digest (see [`ProverRandomness`]).
#[must_use]
pub fn statement_digest<F: PastaField>(
    descriptor_digest: &[u8; 32],
    transcript_repr: &F,
    instances: &[Vec<F>],
) -> [u8; 32] {
    statement_digest_bytes(descriptor_digest, &transcript_repr.to_repr(), instances)
}

fn statement_digest_bytes<F: PastaField>(
    descriptor_digest: &[u8; 32],
    transcript_repr: &[u8; 32],
    instances: &[Vec<F>],
) -> [u8; 32] {
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX).to_le_bytes();
    let mut hasher = Blake2bPersonal::<32>::new(STATEMENT_PERSONA);
    hasher.update(descriptor_digest);
    hasher.update(transcript_repr.as_ref());
    hasher.update(&count(instances.len()));
    for column in instances {
        hasher.update(&count(column.len()));
        for value in column {
            hasher.update(value.to_repr().as_ref());
        }
    }
    hasher.finalize()
}

/// Resources of one proof.
#[derive(Clone, Copy, Debug)]
pub struct ProverConfig<'a> {
    /// Budget of each prover MSM.
    pub msm_budget: MemoryBudget,
    /// Per-proof cooperative cancellation; no signal means run to completion.
    pub cancellation: Option<&'a iroha_pasta::CancellationToken>,
}

impl Default for ProverConfig<'_> {
    fn default() -> Self {
        Self {
            msm_budget: MemoryBudget::DEFAULT,
            cancellation: None,
        }
    }
}

/// How the transcript is primed: production, or oracle mode with the
/// vendored `transcript_repr` (spec 6.4).
#[derive(Clone, Copy, Debug)]
struct Mode<C: PastaCurve> {
    oracle: bool,
    transcript_repr: TranscriptRepr<C>,
}

/// Proof bytes and the generator obligation produced by the same IPA run.
#[derive(Clone, Debug)]
pub struct ProverOutput<C: PastaCurve> {
    /// Canonical proof bytes.
    pub proof: Vec<u8>,
    /// The opening obligation; recursive consumers must fold or decide it.
    pub opening: crate::pcs::ipa::GeneratorClaim<C>,
}

/// Consumes the witness and returns proof bytes plus `(G, u)` without reparsing.
///
/// # Errors
/// As [`create_proof_owned`].
pub fn create_proof_owned_with_claim<C: PastaCurve>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    witness: Witness<C::ScalarExt>,
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
) -> Result<ProverOutput<C>, ProverError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let mode = Mode {
        oracle: false,
        transcript_repr: *pk.vk().transcript_repr(),
    };
    prove_output(
        params,
        pk,
        WitnessInput::Owned(witness),
        randomness,
        config,
        mode,
        &mut lookup::VendoredPermutation,
        &AllTerms,
        None,
    )
}

/// Writes a PIPA-v1 proof of `witness` under `pk` (see the module
/// documentation) and returns the proof bytes.
///
/// # Errors
///
/// [`ProverError`] when the parameters or witness do not match the key, a
/// lookup input is missing from its table, the randomness source fails, or
/// a kernel fails (budget, negligible-probability degeneracies).
pub fn create_proof<C: PastaCurve>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    witness: &Witness<C::ScalarExt>,
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
) -> Result<Vec<u8>, ProverError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let mode = Mode {
        oracle: false,
        transcript_repr: *pk.vk().transcript_repr(),
    };
    prove(
        params,
        pk,
        WitnessInput::Borrowed(witness),
        randomness,
        config,
        mode,
        &mut lookup::VendoredPermutation,
        &AllTerms,
    )
}

/// Creates a proof by consuming `witness` and reusing its advice buffers.
///
/// This produces the same bytes as [`create_proof`] for the same witness,
/// key and randomness source. Advice evaluations remain live until the
/// lookup and permutation products are built, then become coefficients in
/// place. These advice buffers are zeroized on success and every error path.
/// Prefer this entry point when the caller does not need to reuse a witness.
///
/// # Errors
///
/// As [`create_proof`].
pub fn create_proof_owned<C: PastaCurve>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    witness: Witness<C::ScalarExt>,
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
) -> Result<Vec<u8>, ProverError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let mode = Mode {
        oracle: false,
        transcript_repr: *pk.vk().transcript_repr(),
    };
    prove(
        params,
        pk,
        WitnessInput::Owned(witness),
        randomness,
        config,
        mode,
        &mut lookup::VendoredPermutation,
        &AllTerms,
    )
}

/// Consumes a witness and reuses caller-owned quotient buffers across proofs.
///
/// Returns the same bytes and opening obligation as
/// [`create_proof_owned_with_claim`]. Every lease is zeroized before returning,
/// including on failure; only the bounded empty allocation remains reusable.
/// The key and witness are checked afresh on every call. The workspace ceiling
/// is independent of, and does not relax, the process-wide MSM scratch ceiling.
///
/// # Errors
/// As [`create_proof_owned`], plus [`ProverError::Workspace`] if the explicit
/// buffer ceiling is too small or the admitted allocation cannot be made.
pub fn create_proof_owned_with_workspace<C: PastaCurve>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    witness: Witness<C::ScalarExt>,
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
    workspace: &mut QuotientWorkspace<C::ScalarExt>,
) -> Result<ProverOutput<C>, ProverError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    prove_output(
        params,
        pk,
        WitnessInput::Owned(witness),
        randomness,
        config,
        Mode {
            oracle: false,
            transcript_repr: *pk.vk().transcript_repr(),
        },
        &mut lookup::VendoredPermutation,
        &AllTerms,
        Some(workspace),
    )
}

/// Synthesizes `circuit` with `instances` ([`Witness::from_circuit`]) and
/// consumes its witness to prove it ([`create_proof_owned`]).
///
/// # Errors
///
/// As [`Witness::from_circuit`] and [`create_proof`].
pub fn prove_circuit<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    circuit: &Ci,
    instances: &[Vec<C::ScalarExt>],
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
) -> Result<Vec<u8>, ProverError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let witness = Witness::from_circuit_cancellable(pk, circuit, instances, config.cancellation)?;
    create_proof_owned(params, pk, witness, randomness, config)
}

/// [`create_proof`] in oracle mode (spec 6.4): the vendored
/// `transcript_repr` is injected, Poseidon points are absorbed with
/// `fe_to_fe` and the instance frame is omitted. Unit tests
/// only; never compiled into shipping binaries.
///
/// # Errors
///
/// As [`create_proof`].
#[cfg(test)]
#[doc(hidden)]
pub fn create_proof_oracle<C: PastaCurve>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    witness: &Witness<C::ScalarExt>,
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
    vendored_transcript_repr: C::ScalarExt,
) -> Result<Vec<u8>, ProverError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let mode = Mode {
        oracle: true,
        transcript_repr: TranscriptRepr::Scalar(vendored_transcript_repr),
    };
    prove(
        params,
        pk,
        WitnessInput::Borrowed(witness),
        randomness,
        config,
        mode,
        &mut lookup::VendoredPermutation,
        &AllTerms,
    )
}

/// The challenges squeezed before the quotient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Challenges<F> {
    theta: F,
    beta: F,
    gamma: F,
    y: F,
}

/// The prover body shared by production and oracle mode. Every real proof
/// passes [`lookup::VendoredPermutation`] and [`AllTerms`]; the
/// malicious-prover tests pass forged lookup permutations and omit the
/// constraint terms their forgery violates from the quotient.
#[allow(clippy::too_many_arguments)]
fn prove<C, P>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    input: WitnessInput<'_, C::ScalarExt>,
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
    mode: Mode<C>,
    permutation: &mut P,
    filter: &(impl ConstraintFilter + Sync),
) -> Result<Vec<u8>, ProverError>
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    P: lookup::LookupPermutation<C::ScalarExt>,
{
    Ok(prove_output(
        params,
        pk,
        input,
        randomness,
        config,
        mode,
        permutation,
        filter,
        None,
    )?
    .proof)
}

#[allow(clippy::too_many_arguments)]
fn prove_output<C, P>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    mut input: WitnessInput<'_, C::ScalarExt>,
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
    mode: Mode<C>,
    permutation: &mut P,
    filter: &(impl ConstraintFilter + Sync),
    workspace: Option<&mut QuotientWorkspace<C::ScalarExt>>,
) -> Result<ProverOutput<C>, ProverError>
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    P: lookup::LookupPermutation<C::ScalarExt>,
{
    let cancellation = config.cancellation;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let witness = input.witness();
    let descriptor = pk.binding().descriptor();
    if params.k() != u32::from(descriptor.k) || params.curve() != descriptor.curve {
        return Err(ProverError::ParamsMismatch);
    }
    let protocol = Protocol::new(descriptor)?;
    let shape = *protocol.shape();
    if let Some(workspace) = workspace.as_ref() {
        let bytes = quotient::workspace_elements(pk, &protocol)?
            .checked_mul(size_of::<C::ScalarExt>())
            .ok_or(ProtocolError::Overflow)?;
        workspace.check(bytes).map_err(ProverError::Workspace)?;
    }
    // Re-check the witness against this key (it may come from another one).
    if witness.advice.len() != shape.num_advice {
        return Err(ProverError::WitnessShape {
            expected: shape.num_advice,
            found: witness.advice.len(),
        });
    }
    if let Some(column) = witness.advice.iter().find(|column| column.len() != shape.n) {
        return Err(ProverError::WitnessShape {
            expected: shape.n,
            found: column.len(),
        });
    }
    check_instances(descriptor, &witness.instances)?;

    let binding = if randomness.needs_binding() {
        Some(Binding {
            statement: statement_digest_bytes(
                pk.binding().digest(),
                &mode.transcript_repr.to_repr(),
                &witness.instances,
            ),
            witness: witness.digest(shape.usable_rows, config.cancellation)?,
        })
    } else {
        None
    };
    let mut rng = randomness.into_stream(binding)?;
    let budget = config.msm_budget;

    let hash = if mode.oracle {
        oracle_hash::<C>(descriptor)?
    } else {
        DescriptorHash::<C>::production(descriptor.transcript)
    };
    let mut transcript = TranscriptWriter::<C, _>::new(hash);
    if mode.oracle {
        oracle_prelude(
            &mut transcript,
            mode.transcript_repr
                .scalar()
                .ok_or(TranscriptError::ProfileMismatch)?,
        );
    } else if let Some(types) = &descriptor.instance_types {
        absorb_prelude_v2::<C, _>(
            &mut transcript,
            &mode.transcript_repr,
            &descriptor.instance_lengths,
            types,
        )?;
    } else {
        absorb_prelude::<C, _>(
            &mut transcript,
            mode.transcript_repr
                .scalar()
                .ok_or(TranscriptError::ProfileMismatch)?,
            &descriptor.instance_lengths,
        );
    }

    // The instances, then row 1.
    let mut instance = advice::InstanceColumns::new(pk, witness.instances(), cancellation)?;
    instance.absorb(params, &shape, &mut transcript, budget, cancellation)?;
    let mut advice = advice::commit(
        params,
        pk,
        &shape,
        input.take_advice(),
        &mut rng,
        &mut transcript,
        budget,
        cancellation,
    )?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let theta = transcript.squeeze_challenge();

    // Row 2.
    let compiled_lookups = quotient::CompiledExpressions::compile(descriptor, false)?;
    let permuted = lookup::commit_permuted(
        params,
        pk,
        &shape,
        &compiled_lookups,
        &advice.values,
        &instance.values,
        theta,
        permutation,
        &mut rng,
        &mut transcript,
        budget,
        cancellation,
    )?;
    // Lookup inputs have been materialized. Do not retain this DAG while
    // constructing the products or the larger quotient expression table.
    drop(compiled_lookups);
    let beta = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();

    // Rows 3 and 4.
    let products = permutation::commit(
        params,
        pk,
        &protocol,
        &advice.values,
        &instance.values,
        beta,
        gamma,
        &mut rng,
        &mut transcript,
        budget,
        cancellation,
    )?;
    let lookups = lookup::commit_products(
        params,
        pk,
        &shape,
        permuted,
        beta,
        gamma,
        &mut rng,
        &mut transcript,
        budget,
        cancellation,
    )?;

    // Products are the final consumers of evaluations. Reuse the advice
    // allocation for its coefficient form instead of retaining both copies
    // through the quotient and IPA, and release padded public instances.
    advice.interpolate_in_place(pk, cancellation)?;
    instance.values.clear();

    // Row 5.
    let random = vanishing::commit_random(
        params,
        pk,
        &shape,
        &mut rng,
        &mut transcript,
        budget,
        cancellation,
    )?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let y = transcript.squeeze_challenge();

    // Row 6.
    let compiled = quotient::CompiledExpressions::compile(descriptor, true)?;
    let inputs = quotient::QuotientInputs {
        advice: &advice.polys,
        instance: &instance.polys,
        permutation_products: products.iter().map(|set| set.poly.as_slice()).collect(),
        lookups: lookups
            .iter()
            .map(|lookup| quotient::LookupPolys {
                product: &lookup.product_poly,
                input: &lookup.input_poly,
                table: &lookup.table_poly,
            })
            .collect(),
    };
    let challenges = Challenges {
        theta,
        beta,
        gamma,
        y,
    };
    let h = if let Some(workspace) = workspace {
        quotient::evaluate_with_workspace_cancellable(
            pk,
            &protocol,
            &compiled,
            &inputs,
            challenges,
            filter,
            workspace,
            cancellation,
        )?
    } else {
        quotient::evaluate_cancellable(
            pk,
            &protocol,
            &compiled,
            &inputs,
            challenges,
            filter,
            cancellation,
        )?
    };
    // The quotient evaluations are owned by `h`; no later phase reads the
    // compiled DAG, including quotient commitments and the opening proof.
    drop(compiled);
    let quotient = vanishing::commit_quotient(
        params,
        pk,
        &shape,
        h,
        &mut rng,
        &mut transcript,
        budget,
        cancellation,
    )?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let x = transcript.squeeze_challenge();
    let xn = x.pow_vartime([u64::try_from(shape.n).map_err(|_| ProtocolError::Overflow)?]);
    if bool::from(x.is_zero()) || xn == C::ScalarExt::ONE {
        return Err(ProverError::DegenerateChallenge);
    }

    // Rows 7-17.
    let opened = multiopen::Opened {
        instance: &instance,
        advice: &advice,
        products: &products,
        lookups: &lookups,
        random: &random,
        quotient: quotient.combine(xn),
    };
    opened.write_evaluations(pk, &protocol, x, &mut transcript)?;
    let folded = opened.open(
        params,
        pk,
        &protocol,
        x,
        &mut rng,
        &mut transcript,
        budget,
        cancellation,
    )?;
    if shape.folded_generator_suffix {
        transcript.append_unabsorbed_point(folded.g())?;
    }
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    Ok(ProverOutput {
        proof: transcript.finish(),
        opening: folded,
    })
}

/// The oracle-mode hash of the descriptor's transcript.
#[cfg(test)]
fn oracle_hash<C: PastaCurve>(
    descriptor: &ProtocolDescriptor,
) -> Result<DescriptorHash<C>, TranscriptError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    Ok(DescriptorHash::<C>::oracle(
        descriptor
            .transcript
            .retained()
            .ok_or(TranscriptError::ProfileMismatch)?,
    ))
}

/// Oracle mode does not exist in shipping builds; the production hash is
/// returned so the code path stays total.
#[cfg(not(test))]
fn oracle_hash<C: PastaCurve>(
    _descriptor: &ProtocolDescriptor,
) -> Result<DescriptorHash<C>, TranscriptError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    Err(TranscriptError::ProfileMismatch)
}

/// The oracle-mode prelude (`transcript_repr` only).
fn oracle_prelude<C: PastaCurve, T: Transcript<C>>(transcript: &mut T, repr: &C::ScalarExt) {
    transcript.common_scalar(repr);
}

/// `Field::random` draws in sequence.
fn random_values<F: Field, R: RngCore>(rng: &mut R, count: usize) -> Vec<F> {
    (0..count).map(|_| F::random(&mut *rng)).collect()
}

/// A point written to the transcript, with the identity mapped to an error.
fn write_point<C: PastaCurve, T: TranscriptWrite<C>>(
    transcript: &mut T,
    point: &C::AffineExt,
) -> Result<(), ProverError> {
    transcript.write_point(point).map_err(ProverError::from)
}
