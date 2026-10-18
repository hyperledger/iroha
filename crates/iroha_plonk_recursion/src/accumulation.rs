//! Committed-mask native fold with explicit private owners; staged diagnostic.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{
    PastaCurve, PastaField,
    fold::fold_generators_cancellable,
    msm::{MemoryBudget, SharedMemoryBudget, msm_secret_cancellable},
    poseidon::{PoseidonField, Sponge},
};
use iroha_plonk::{
    pcs::ipa::{PinnedParams, commit::msm_complete_cancellable, fold_evaluation, fold_scalars},
    transcript::{
        BasePoseidonHash, Transcript, TranscriptRead, TranscriptReader, TranscriptWrite,
        decode_generator, decode_point, decode_scalar, generator_coordinates,
        pipa_r::{nonzero_challenge, scalar_elements},
    },
};

use zeroize::Zeroizing;

use crate::{
    AccumulatorT, Error, FOLD_BODY_BYTES, FOLD_WITNESS_BYTES, FoldInput, FoldPurpose, FoldTape,
    GENERATORS, K, K_U32,
    claim::message,
    fold_tape::FieldGuard,
    private::{
        AffineGuard, AffineVec, FieldArray, FieldVec, PointGuard, PrivateWitnessBytes,
        PrivateWriter,
    },
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

/// Checked private witness; no implicit clone or byte-bearing diagnostics.
///
/// This owner clears its current heap allocation on drop. A caller retaining
/// checkpoint bytes must provide an authenticated private persistence owner.
pub struct FoldWitness<C: PastaCurve> {
    bytes: Zeroizing<Box<[u8]>>,
    marker: core::marker::PhantomData<C>,
}
impl<C: PastaCurve> core::fmt::Debug for FoldWitness<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FoldWitness { private: [REDACTED] }")
    }
}
impl<C: PastaCurve> FoldWitness<C> {
    /// Checks exact canonical syntax; does not sample or refresh any randomness.
    ///
    /// # Errors
    /// Rejects any other extent or noncanonical point/scalar. Syntax alone does
    /// not authenticate a checkpoint or establish the fold equation.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FOLD_WITNESS_BYTES {
            return Err(Error::Length {
                expected: FOLD_WITNESS_BYTES,
                actual: bytes.len(),
            });
        }
        for i in 0..=2 * K {
            let word = Zeroizing::new(message(bytes, 32 * i)?);
            let _point = AffineGuard::<C>(decode_point::<C>(&word)?);
        }
        let word = Zeroizing::new(message(bytes, 32 * (2 * K + 1))?);
        let _scalar = FieldGuard(decode_scalar::<C::ScalarExt>(&word)?);
        let word = Zeroizing::new(message(bytes, 32 * (2 * K + 2))?);
        let _point = AffineGuard::<C>(decode_generator::<C>(&word)?);
        let _tape = FoldTape::<C>::from_private_bytes(&bytes[FOLD_BODY_BYTES..]).ok_or(
            Error::Encoding(iroha_plonk::transcript::TranscriptError::NonCanonicalScalar),
        )?;
        let mut owned = Zeroizing::new(vec![0; FOLD_WITNESS_BYTES].into_boxed_slice());
        owned.copy_from_slice(bytes);
        Ok(Self {
            bytes: owned,
            marker: core::marker::PhantomData,
        })
    }
    /// Explicit private serialization under a clearing owner, exact 2176 bytes.
    /// Callers must not log or convert these bytes to an unguarded container.
    pub fn to_private_bytes(&self) -> PrivateWitnessBytes {
        let mut owned = Zeroizing::new(vec![0; FOLD_WITNESS_BYTES]);
        owned.copy_from_slice(&self.bytes);
        PrivateWitnessBytes(owned)
    }
    fn tape(&self) -> Result<FoldTape<C>, Error> {
        FoldTape::from_private_bytes(&self.bytes[FOLD_BODY_BYTES..]).ok_or(Error::Encoding(
            iroha_plonk::transcript::TranscriptError::NonCanonicalScalar,
        ))
    }
}

/// Injective two-limb representation of a base-field digest in the scalar field.
pub fn digest_limbs<C: PastaCurve>(h: C::Base) -> [C::ScalarExt; 2] {
    let h = FieldGuard(h);
    let limbs = Zeroizing::new(h.0.to_canonical_limbs());
    [
        C::ScalarExt::from_raw_reduced([limbs[0], limbs[1], 0, 0]),
        C::ScalarExt::from_raw_reduced([limbs[2], limbs[3], 0, 0]),
    ]
}

/// Two canonical parameter-digest limbs, exact public profile and count.
pub fn context<C: PastaCurve>(
    params: &PinnedParams<C>,
    purpose: FoldPurpose,
    count: usize,
) -> [C::Base; 4] {
    let d = params.digest();
    [
        C::Base::from_u128(u128::from_le_bytes(d[..16].try_into().unwrap())),
        C::Base::from_u128(u128::from_le_bytes(d[16..].try_into().unwrap())),
        C::Base::from(purpose.word()),
        C::Base::from(count as u64),
    ]
}

/// Separate fresh RP57 input digest; every canonical mask and input is bound.
pub fn input_digest<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    tape: &FoldTape<C>,
    purpose: FoldPurpose,
) -> C::Base
where
    C::Base: PoseidonField,
{
    input_digest_bound(params, inputs, tape, purpose, &InputBinding::Exact)
}

/// Only the closed terminal owner can select prefix reuse.
pub(crate) enum InputBinding<C: PastaCurve> {
    Exact,
    Terminal { descriptor: [u8; 32], raw: C::Base },
}
impl<C: PastaCurve> Drop for InputBinding<C> {
    fn drop(&mut self) {
        fn clear<F: PastaField>(raw: &mut F) {
            raw.zeroize();
        }
        if let Self::Terminal { raw, .. } = self {
            clear(raw);
        }
    }
}
fn input_digest_bound<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    tape: &FoldTape<C>,
    purpose: FoldPurpose,
    binding: &InputBinding<C>,
) -> C::Base
where
    C::Base: PoseidonField,
{
    let (domain, bound_inputs) = match binding {
        InputBinding::Exact => (*b"pipa-in1", inputs),
        InputBinding::Terminal { .. } => (*b"pipa-tm1", &inputs[1..2]),
    };
    let per_scalar =
        if <C::ScalarExt as PrimeField>::MODULUS == <iroha_pasta::Fp as PrimeField>::MODULUS {
            1
        } else {
            2
        };
    let mut words = FieldVec(Vec::with_capacity(
        7 + bound_inputs.len() * (3 + K * per_scalar) + 2 * K * per_scalar,
    ));
    words.extend(context(params, purpose, inputs.len()));
    if let InputBinding::Terminal { descriptor, raw } = binding {
        words.extend(
            descriptor
                .chunks_exact(16)
                .map(|part| C::Base::from_u128(u128::from_le_bytes(part.try_into().unwrap()))),
        );
        words.push(*raw);
    }
    for input in bound_inputs {
        let (x, y) = generator_coordinates::<C>(input.g());
        words.extend([x, y, C::Base::from(u64::from(input.source_k()))]);
        for u in input.challenges() {
            let encoded = FieldVec(scalar_elements::<C>(u));
            words.extend_from_slice(&encoded);
        }
    }
    for b in tape.masks() {
        let encoded = FieldVec(scalar_elements::<C>(b));
        words.extend_from_slice(&encoded);
    }
    let mut sponge = Sponge::new();
    sponge.update(&[
        C::Base::from(u64::from_le_bytes(domain)),
        C::Base::from(words.len() as u64),
    ]);
    sponge.update(&words);
    sponge.squeeze()
}

fn opening<C: PastaCurve>(params: &PinnedParams<C>, h: C::Base, rho: C::ScalarExt) -> C {
    let h = FieldGuard(h);
    let rho = FieldGuard(rho);
    let limbs = FieldArray(digest_limbs::<C>(h.0));
    params.params().g()[0].to_curve() * limbs.0[0]
        + params.params().g()[1].to_curve() * limbs.0[1]
        + params.params().w().to_curve() * rho.0
}

fn validate_binding<C: PastaCurve>(
    purpose: FoldPurpose,
    count: usize,
    binding: &InputBinding<C>,
) -> Result<(), Error> {
    if !purpose.permits_shape::<C>(count)
        || matches!(binding, InputBinding::Terminal { .. })
            != (purpose == FoldPurpose::WrapperVesta)
    {
        return Err(Error::Purpose);
    }
    Ok(())
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

/// Challenge-only public context; the digest state and opening never enter it.
///
/// # Errors
/// Empty inputs, no full-length source, an unrepresentable input count, or a
/// transcript error while absorbing the public context.
pub fn prelude<C: PastaCurve, T: Transcript<C>>(
    transcript: &mut T,
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    purpose: FoldPurpose,
) -> Result<(), Error> {
    validate_inputs(inputs)?;
    for word in context(params, purpose, inputs.len()) {
        transcript.common_base(&word)?;
    }
    Ok(())
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

/// Consumes one private tape to create the exact committed-mask k16 fold.
///
/// The caller owns slot selection and fresh entropy sampling. A set containing only
/// short source proofs is rejected: callers must explicitly add an authorized
/// full-length trivial slot, counted and absorbed like every other slot.
/// Canonical but false input claims cause `FoldEquation`; no proof accepts until
/// the returned accumulator also decides. Identity D/L/R messages return errors;
/// only the G suffix admits identity. Actual-round challenges use the total
/// nonzero map. The consumed tape is cleared on return and unwinding.
///
/// The owned coefficient, power and generator vectors total 8 MiB at k16;
/// parameters are borrowed. Generator folding processes bounded chunks, and
/// kernel scratch uses nonblocking shared admission with a complete fallback.
/// The transcript can remain private inside an outer proof, so coefficient MSMs
/// use full-width secret planning and scratch wiping. The complete fold still
/// includes variable-time bucket and generator operations.
///
/// # Errors
/// Insufficient parameters, invalid purpose or input shape, cancellation,
/// identity D/L/R messages or a failed succinct equation.
pub fn create_fold<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    tape: FoldTape<C>,
    purpose: FoldPurpose,
    config: &FoldConfig,
) -> Result<(FoldWitness<C>, AccumulatorT<C>), Error>
where
    C::Base: PoseidonField,
{
    create_fold_bound(params, inputs, tape, purpose, config, &InputBinding::Exact)
}

pub(crate) fn create_fold_bound<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    tape: FoldTape<C>,
    purpose: FoldPurpose,
    config: &FoldConfig,
    binding: &InputBinding<C>,
) -> Result<(FoldWitness<C>, AccumulatorT<C>), Error>
where
    C::Base: PoseidonField,
{
    validate_binding(purpose, inputs.len(), binding)?;
    iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
    params.require_k(K_U32).map_err(Error::Parameters)?;
    let digest = FieldGuard(input_digest_bound(params, inputs, &tape, purpose, binding));
    let d = AffineGuard::<C>(opening(params, digest.0, *tape.rho()).to_affine());
    let mut transcript = PrivateWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    prelude(transcript.writer(), params, inputs, purpose)?;
    transcript.writer().write_point(&d.0)?;
    let [alpha, z, zeta] = core::array::from_fn(|_| transcript.writer().squeeze_challenge());
    let mut coefficients = FieldVec(vec![C::ScalarExt::ZERO; GENERATORS]);
    let mut weight = FieldGuard(C::ScalarExt::ONE);
    for input in inputs {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
        let source = &input.challenges()[K - input.source_k() as usize..];
        let values = FieldVec(fold_scalars(source, weight.0));
        for (coefficient, value) in coefficients.iter_mut().zip(values.iter()) {
            *coefficient += *value;
        }
        weight.0 *= alpha;
    }
    // Open the shifted polynomial at zero evaluation, not unshifted h.
    coefficients[0] -= combined_evaluation(inputs, alpha, z);
    let mut powers = FieldVec(Vec::with_capacity(GENERATORS));
    let mut power = FieldGuard(C::ScalarExt::ONE);
    for _ in 0..GENERATORS {
        powers.push(power.0);
        power.0 *= z;
    }
    let mut generators = AffineVec::<C>(params.params().g()[..GENERATORS].to_vec());
    let auxiliary = params.params().u().to_curve();
    let mut challenges = [C::ScalarExt::ZERO; K];
    for (round, challenge) in challenges.iter_mut().enumerate() {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
        let half = coefficients.len() / 2;
        let left_value = FieldGuard(inner_product(&coefficients[half..], &powers[..half]));
        let right_value = FieldGuard(inner_product(&coefficients[..half], &powers[half..]));
        let left = AffineGuard::<C>(
            (msm_secret_cancellable::<C>(
                &coefficients[half..],
                &generators[..half],
                config.kernel_budget,
                &config.shared_budget,
                config.cancellation.as_ref(),
            )
            .map_err(Error::from)?
                + auxiliary * (left_value.0 * zeta)
                + params.params().w().to_curve() * tape.masks()[2 * round])
                .to_affine(),
        );
        let right = AffineGuard::<C>(
            (msm_secret_cancellable::<C>(
                &coefficients[..half],
                &generators[half..],
                config.kernel_budget,
                &config.shared_budget,
                config.cancellation.as_ref(),
            )
            .map_err(Error::from)?
                + auxiliary * (right_value.0 * zeta)
                + params.params().w().to_curve() * tape.masks()[2 * round + 1])
                .to_affine(),
        );
        transcript.writer().write_point(&left.0)?;
        transcript.writer().write_point(&right.0)?;
        *challenge = nonzero_challenge(transcript.writer().squeeze_challenge());
        let inverse = Option::<C::ScalarExt>::from(challenge.invert())
            .ok_or(Error::ZeroChallenge { round })?;
        for index in 0..half {
            let upper = FieldGuard(coefficients[index + half]);
            coefficients[index] += upper.0 * inverse;
            let upper = FieldGuard(powers[index + half]);
            powers[index] += upper.0 * *challenge;
        }
        coefficients.truncate(half);
        powers.truncate(half);
        fold_generators::<C>(&mut generators, *challenge, config)?;
        generators.truncate(half);
    }
    transcript.writer().write_scalar(&coefficients[0]);
    transcript
        .writer()
        .append_unabsorbed_generator(&generators[0]);
    let body = transcript.finish();
    let coins = tape.to_private_bytes();
    // The fold attempt consumes and clears its tape after the final encoding.
    drop(tape);
    let mut bytes = Zeroizing::new(vec![0; FOLD_WITNESS_BYTES].into_boxed_slice());
    bytes[..FOLD_BODY_BYTES].copy_from_slice(&body);
    bytes[FOLD_BODY_BYTES..].copy_from_slice(&coins);
    let witness = FoldWitness::from_private_bytes(&bytes)?;
    let output = AccumulatorT::new(generators[0], challenges)?;
    // Catch false source claims without r separate size-2^16 decisions.
    if verify_fold_bound(params, inputs, &witness, purpose, config, binding)? != output {
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
/// Insufficient parameters, invalid purpose or input shape, cancellation,
/// malformed proof messages or a false succinct equation.
pub fn verify_fold<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    witness: &FoldWitness<C>,
    purpose: FoldPurpose,
    config: &FoldConfig,
) -> Result<AccumulatorT<C>, Error>
where
    C::Base: PoseidonField,
{
    verify_fold_bound(
        params,
        inputs,
        witness,
        purpose,
        config,
        &InputBinding::Exact,
    )
}

pub(crate) fn verify_fold_bound<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    witness: &FoldWitness<C>,
    purpose: FoldPurpose,
    config: &FoldConfig,
    binding: &InputBinding<C>,
) -> Result<AccumulatorT<C>, Error>
where
    C::Base: PoseidonField,
{
    validate_binding(purpose, inputs.len(), binding)?;
    iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
    params.require_k(K_U32).map_err(Error::Parameters)?;
    let mut transcript = TranscriptReader::<C, _>::new(
        BasePoseidonHash::with_domain(*b"pipa-as1"),
        &witness.bytes[..FOLD_BODY_BYTES],
    );
    let tape = witness.tape()?;
    let digest = FieldGuard(input_digest_bound(params, inputs, &tape, purpose, binding));
    prelude(&mut transcript, params, inputs, purpose)?;
    let d = AffineGuard::<C>(transcript.read_point()?);
    if d.0.to_curve() != opening(params, digest.0, *tape.rho()) {
        return Err(Error::FoldEquation);
    }
    let [alpha, z, zeta] = core::array::from_fn(|_| transcript.squeeze_challenge());
    let mut gamma = FieldGuard(C::ScalarExt::ZERO);
    let mut points = AffineVec::<C>(Vec::with_capacity(2 * K + 4));
    let mut scalars = FieldVec(Vec::with_capacity(2 * K + 4));
    let mut challenges = [C::ScalarExt::ZERO; K];
    for (round, challenge) in challenges.iter_mut().enumerate() {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())?;
        let left = AffineGuard::<C>(transcript.read_point()?);
        let right = AffineGuard::<C>(transcript.read_point()?);
        *challenge = nonzero_challenge(transcript.squeeze_challenge());
        let inverse = Option::<C::ScalarExt>::from(challenge.invert())
            .ok_or(Error::ZeroChallenge { round })?;
        gamma.0 += tape.masks()[2 * round] * inverse + tape.masks()[2 * round + 1] * *challenge;
        points.extend([left.0, right.0]);
        scalars.extend([inverse, *challenge]);
    }
    let final_coefficient = FieldGuard(transcript.read_scalar()?);
    let generator = AffineGuard::<C>(transcript.read_unabsorbed_generator()?);
    transcript.finish()?;
    points.extend([params.params().g()[0], params.params().u(), generator.0]);
    scalars.extend([
        -combined_evaluation(inputs, alpha, z),
        -(final_coefficient.0 * fold_evaluation(z, &challenges) * zeta),
        -final_coefficient.0,
    ]);
    points.push(params.params().w());
    scalars.push(-gamma.0);
    let equation = PointGuard(
        combined_commitment(inputs, alpha)
            + msm_complete_cancellable::<C>(
                &scalars,
                &points,
                config.kernel_budget,
                &config.shared_budget,
                config.cancellation.as_ref(),
            )?,
    );
    if !bool::from(equation.0.is_identity()) {
        return Err(Error::FoldEquation);
    }
    AccumulatorT::new(generator.0, challenges)
}

fn inner_product<F: PastaField>(left: &[F], right: &[F]) -> F {
    let mut sum = FieldGuard(F::ZERO);
    for (left, right) in left.iter().zip(right) {
        sum.0 += *left * right;
    }
    sum.0
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
    let mut chunk = AffineVec::<C>(Vec::with_capacity(2 * half.min(2048)));
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
