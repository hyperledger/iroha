//! Non-hiding PIPA-AS-v1 prover and complete succinct verifier.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{
    PastaCurve,
    fold::fold_generators_cancellable,
    msm::{MemoryBudget, SharedMemoryBudget, msm_public_cancellable},
    poseidon::PoseidonField,
};
use iroha_plonk::{
    pcs::ipa::{PinnedParams, commit::msm_complete_cancellable, fold_evaluation, fold_scalars},
    transcript::{
        BasePoseidonHash, Transcript, TranscriptRead, TranscriptReader, TranscriptWrite,
        TranscriptWriter, decode_point, decode_scalar,
    },
};

use crate::{
    AccumulatorT, Error, FOLD_BODY_BYTES, FOLD_WITNESS_BYTES, FoldInput, GENERATORS, K, K_U32,
    claim::message,
};

/// Explicit local kernel policy; all clones also share the process's 64 MiB cap.
#[derive(Clone, Debug)]
pub struct FoldConfig {
    /// Scratch ceiling for an individual MSM or generator-fold chunk.
    pub kernel_budget: MemoryBudget,
    /// Shared admission for concurrently live kernel scratch.
    pub shared_budget: SharedMemoryBudget,
    /// One-way signal shared with the wallet scheduler for this operation.
    pub cancellation: Option<iroha_pasta::CancellationToken>,
}

impl Default for FoldConfig {
    fn default() -> Self {
        Self {
            kernel_budget: MemoryBudget::new(64 << 20),
            shared_budget: SharedMemoryBudget::process_default(),
            cancellation: None,
        }
    }
}

/// Canonical local fold witness: external base-field salt and the 1,088-byte IPA body.
///
/// Decoding checks all encodings, not the succinct equation or deferred decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldWitness<C: PastaCurve> {
    salt: C::Base,
    body: [u8; FOLD_BODY_BYTES],
}

impl<C: PastaCurve> FoldWitness<C> {
    /// Checks the canonical base-field salt and every body message.
    ///
    /// # Errors
    /// Wrong body length, noncanonical salt/scalars, or invalid/identity points.
    pub fn new(salt: [u8; 32], body: &[u8]) -> Result<Self, Error> {
        if body.len() != FOLD_BODY_BYTES {
            return Err(Error::Length {
                expected: FOLD_BODY_BYTES,
                actual: body.len(),
            });
        }
        let salt = decode_scalar::<C::Base>(&salt)?;
        for index in 0..2 * K {
            decode_point::<C>(&message(body, 32 * index)?)?;
        }
        decode_scalar::<C::ScalarExt>(&message(body, 64 * K)?)?;
        decode_point::<C>(&message(body, 32 * (2 * K + 1))?)?;
        let body = body.try_into().map_err(|_| Error::Length {
            expected: FOLD_BODY_BYTES,
            actual: body.len(),
        })?;
        Ok(Self { salt, body })
    }

    /// Decodes exactly `salt || body`, with no implicit salt or trailing bytes.
    ///
    /// # Errors
    /// Wrong witness length or any invalid encoding described by [`Self::new`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FOLD_WITNESS_BYTES {
            return Err(Error::Length {
                expected: FOLD_WITNESS_BYTES,
                actual: bytes.len(),
            });
        }
        Self::new(message(bytes, 0)?, &bytes[32..])
    }

    /// The exact fixed-width local witness encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; FOLD_WITNESS_BYTES] {
        let mut bytes = [0; FOLD_WITNESS_BYTES];
        bytes[..32].copy_from_slice(&self.salt.to_repr());
        bytes[32..].copy_from_slice(&self.body);
        bytes
    }

    /// The canonical external salt, unchanged from the caller's input.
    #[must_use]
    pub fn salt_bytes(&self) -> [u8; 32] {
        self.salt.to_repr()
    }

    /// Sixteen L/R pairs, c, and the unabsorbed G suffix.
    #[must_use]
    pub const fn body(&self) -> &[u8; FOLD_BODY_BYTES] {
        &self.body
    }
}

fn validate_inputs<C: PastaCurve>(inputs: &[FoldInput<C>]) -> Result<u64, Error> {
    if inputs.is_empty() {
        return Err(Error::EmptyInputs);
    }
    if !inputs.iter().any(|input| input.source_k() == K_U32) {
        return Err(Error::MissingFullLengthInput);
    }
    u64::try_from(inputs.len()).map_err(|_| Error::InputCount)
}

/// Every input, its source k and all sixteen normalized challenges precede
/// alpha, z and zeta. C is derived from those bound inputs, never reabsorbed.
pub fn prelude<C: PastaCurve, T: Transcript<C>>(
    transcript: &mut T,
    inputs: &[FoldInput<C>],
    salt: &C::Base,
) -> Result<[C::ScalarExt; 3], Error> {
    let count = validate_inputs(inputs)?;
    transcript.common_base(salt)?;
    transcript.common_base(&C::Base::from(count))?;
    for input in inputs {
        transcript.common_point(input.g())?;
        transcript.common_base(&C::Base::from(u64::from(input.source_k())))?;
        for value in input.challenges() {
            transcript.common_scalar(value);
        }
    }
    Ok([
        transcript.squeeze_challenge(),
        transcript.squeeze_challenge(),
        transcript.squeeze_challenge(),
    ])
}

/// Complete Horner joins permit equal/opposite points, identity intermediates
/// and zero scalar challenges, without exceptional-case assumptions.
pub fn combined_commitment<C: PastaCurve>(inputs: &[FoldInput<C>], alpha: C::ScalarExt) -> C {
    inputs.iter().rev().fold(C::identity(), |sum, input| {
        sum * alpha + input.g().to_curve()
    })
}

fn combined_evaluation<C: PastaCurve>(
    inputs: &[FoldInput<C>],
    alpha: C::ScalarExt,
    z: C::ScalarExt,
) -> C::ScalarExt {
    inputs
        .iter()
        .rev()
        .fold(C::ScalarExt::ZERO, |value, input| {
            value * alpha + fold_evaluation(z, input.challenges())
        })
}

/// Creates the exact non-hiding k16 fold, then checks its succinct equation.
///
/// The caller owns slot selection and salt generation. A set containing only
/// short source proofs is rejected: callers must explicitly add an authorized
/// full-length trivial slot, counted and absorbed like every other slot.
/// Canonical but false input claims cause `FoldEquation`; no proof accepts until
/// the returned accumulator also decides. Rare identity messages or zero round
/// challenges return errors; no prover salt is silently retried.
///
/// The owned coefficient, power and generator vectors total 8 MiB at k16;
/// parameters are borrowed. Generator folding processes bounded chunks, and
/// kernel scratch uses nonblocking shared admission with a complete fallback.
///
/// # Errors
/// Insufficient parameters, invalid salt, empty/short-only inputs, zero round
/// challenges, identity proof messages or a failed succinct equation.
pub fn create_fold<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    salt: [u8; 32],
    config: &FoldConfig,
) -> Result<(FoldWitness<C>, AccumulatorT<C>), Error>
where
    C::Base: PoseidonField,
{
    iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
    params.require_k(K_U32).map_err(Error::Parameters)?;
    let salt_value = decode_scalar::<C::Base>(&salt)?;
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    let [alpha, z, zeta] = prelude(&mut transcript, inputs, &salt_value)?;
    let mut coefficients = vec![C::ScalarExt::ZERO; GENERATORS];
    let mut weight = C::ScalarExt::ONE;
    for input in inputs {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
        let source = &input.challenges()[K - input.source_k() as usize..];
        let values = fold_scalars(source, weight);
        for (coefficient, value) in coefficients.iter_mut().zip(values) {
            *coefficient += value;
        }
        weight *= alpha;
    }
    // Open the shifted polynomial at zero evaluation, not unshifted h.
    coefficients[0] -= combined_evaluation(inputs, alpha, z);
    let mut powers = Vec::with_capacity(GENERATORS);
    let mut power = C::ScalarExt::ONE;
    for _ in 0..GENERATORS {
        powers.push(power);
        power *= z;
    }
    let mut generators = params.params().g()[..GENERATORS].to_vec();
    let auxiliary = params.params().u().to_curve();
    let mut challenges = [C::ScalarExt::ZERO; K];
    for (round, challenge) in challenges.iter_mut().enumerate() {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
        let half = coefficients.len() / 2;
        let left_value = inner_product(&coefficients[half..], &powers[..half]);
        let right_value = inner_product(&coefficients[..half], &powers[half..]);
        let left = (msm_public_cancellable::<C>(
            &coefficients[half..],
            &generators[..half],
            config.kernel_budget,
            &config.shared_budget,
            config.cancellation.as_ref(),
        )
        .map_err(Error::from)?
            + auxiliary * (left_value * zeta))
            .to_affine();
        let right = (msm_public_cancellable::<C>(
            &coefficients[..half],
            &generators[half..],
            config.kernel_budget,
            &config.shared_budget,
            config.cancellation.as_ref(),
        )
        .map_err(Error::from)?
            + auxiliary * (right_value * zeta))
            .to_affine();
        transcript.write_point(&left)?;
        transcript.write_point(&right)?;
        *challenge = transcript.squeeze_challenge();
        let inverse = Option::<C::ScalarExt>::from(challenge.invert())
            .ok_or(Error::ZeroChallenge { round })?;
        for index in 0..half {
            let upper = coefficients[index + half];
            coefficients[index] += upper * inverse;
            let upper = powers[index + half];
            powers[index] += upper * *challenge;
        }
        coefficients.truncate(half);
        powers.truncate(half);
        fold_generators::<C>(&mut generators, *challenge, config)?;
        generators.truncate(half);
    }
    transcript.write_scalar(&coefficients[0]);
    transcript.append_unabsorbed_point(&generators[0])?;
    let witness = FoldWitness::new(salt, &transcript.finish())?;
    let output = AccumulatorT::new(generators[0], challenges)?;
    // Catch false source claims without r separate size-2^16 decisions.
    if verify_fold(params, inputs, &witness, config)? != output {
        return Err(Error::FoldEquation);
    }
    Ok((witness, output))
}

/// Verifies the succinct equation and returns its **undecided** accumulator.
///
/// Complete Horner and the independent complete MSM kernel are used for every
/// group operation. An Ok result alone does not establish that any input
/// decides: the output claim must be decided or forwarded as a bound obligation.
///
/// # Errors
/// Insufficient parameters, empty/short-only inputs, zero round challenges,
/// malformed proof messages or a false succinct equation.
pub fn verify_fold<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    witness: &FoldWitness<C>,
    config: &FoldConfig,
) -> Result<AccumulatorT<C>, Error>
where
    C::Base: PoseidonField,
{
    iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
    params.require_k(K_U32).map_err(Error::Parameters)?;
    let mut transcript =
        TranscriptReader::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"), &witness.body);
    let [alpha, z, zeta] = prelude(&mut transcript, inputs, &witness.salt)?;
    let mut points = Vec::with_capacity(2 * K + 3);
    let mut scalars = Vec::with_capacity(2 * K + 3);
    let mut challenges = [C::ScalarExt::ZERO; K];
    for (round, challenge) in challenges.iter_mut().enumerate() {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
        let left = transcript.read_point()?;
        let right = transcript.read_point()?;
        *challenge = transcript.squeeze_challenge();
        let inverse = Option::<C::ScalarExt>::from(challenge.invert())
            .ok_or(Error::ZeroChallenge { round })?;
        points.extend([left, right]);
        scalars.extend([inverse, *challenge]);
    }
    let final_coefficient = transcript.read_scalar()?;
    let generator = transcript.read_unabsorbed_point()?;
    transcript.finish()?;
    points.extend([params.params().g()[0], params.params().u(), generator]);
    scalars.extend([
        -combined_evaluation(inputs, alpha, z),
        -(final_coefficient * fold_evaluation(z, &challenges) * zeta),
        -final_coefficient,
    ]);
    let equation = combined_commitment(inputs, alpha)
        + msm_complete_cancellable::<C>(
            &scalars,
            &points,
            config.kernel_budget,
            &config.shared_budget,
            config.cancellation.as_ref(),
        )?;
    if !bool::from(equation.is_identity()) {
        return Err(Error::FoldEquation);
    }
    AccumulatorT::new(generator, challenges)
}

fn inner_product<F: Field>(left: &[F], right: &[F]) -> F {
    left.iter()
        .zip(right)
        .fold(F::ZERO, |sum, (left, right)| sum + *left * right)
}

/// At most 2048 pairs enter the existing accelerated Pasta fold at a time.
/// Its 32 field-array lanes plus the copied affine pairs, vector headers and
/// two wNAF recodings fit within 3 MiB, independent of Rayon worker count.
///
/// # Errors
/// Returns cancellation only after the active chunk and all its workers join.
pub fn fold_generators<C: PastaCurve>(
    generators: &mut [C::AffineExt],
    challenge: C::ScalarExt,
    config: &FoldConfig,
) -> Result<(), Error> {
    const SCRATCH: usize = 3 << 20;
    iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
    let reservation = (config.kernel_budget.bytes() >= SCRATCH)
        .then(|| config.shared_budget.try_reserve(SCRATCH))
        .flatten();
    let half = generators.len() / 2;
    let (low, high) = generators.split_at_mut(half);
    if reservation.is_none() {
        for (index, (low, high)) in low.iter_mut().zip(high).enumerate() {
            if index % 256 == 0 {
                iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
            }
            *low = (low.to_curve() + high.to_curve() * challenge).to_affine();
        }
        return Ok(());
    }
    let mut chunk = Vec::with_capacity(2 * half.min(2048));
    for (low, high) in low.chunks_mut(2048).zip(high.chunks(2048)) {
        chunk.clear();
        chunk.extend_from_slice(low);
        chunk.extend_from_slice(high);
        fold_generators_cancellable::<C>(&mut chunk, &challenge, config.cancellation.as_ref())?;
        low.copy_from_slice(&chunk[..low.len()]);
    }
    iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
    Ok(())
}
