//! Complete constrained PIPA-AS-v1 succinct verification on the shared lane.
//!
//! The original source schema is circuit metadata. Incoming Trivial mode selects
//! source k16 and the pinned accumulator; Accept/Corrected retain the original k.
//! Generic folds privately hash every exact input; the closed terminal owner
//! instead binds the hard frame prefix and its own opening.
//! an all-short selected input list rejects. Soft mode
//! is total for all fixed-size witness bytes and returns a proven verdict plus
//! the pinned deciding trivial claim on failure. An accepted output remains an
//! undecided generator claim, exactly as in native [`crate::verify_fold`].
//!
//! The owning relation must enforce the global burn/no-op mode rule and close
//! the obligation ledger; this module checks each slot's selected claim.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{Fp, PastaCurve};
use iroha_plonk::{
    frontend::{Error, Region},
    pcs::ipa::PinnedParams,
    transcript::decode_point,
};
use iroha_plonk_gadgets::{
    Bit, GlueChip, Uint, Word,
    bytes::element::LeElement,
    ecc::{EccChip, ScalarLimbs},
    range::u128::UintChip,
};

use crate::{
    ACCUMULATOR_BYTES, FOLD_WITNESS_BYTES, K, K_U32, PALLAS_TRIVIAL_GENERATOR,
    VESTA_TRIVIAL_GENERATOR,
    codec::{
        GeneratorPoint, ScalarCells, decode_generator_soft, decode_point_soft, decode_scalar_soft,
    },
    obligation::ModeCells,
    transcript::{Domain, TranscriptChip},
    verifier::{GeneratorClaimCells, VerificationMode, VerifierChip, scalar::Scalar},
};

/// Original source schema of one fixed fold slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldSource {
    /// A hard slot whose source k never changes.
    Fixed(u32),
    /// Accept/Corrected retain this descriptor k; Trivial selects k16.
    Incoming(u32),
    /// A hard sigma part, with a constrained selected source k in {12, 14, 16}.
    SigmaChoice,
}

impl FoldSource {
    /// Original descriptor k, before mode-controlled trivial selection.
    /// A sigma part has no single original k and returns None.
    #[must_use]
    pub const fn original_k(self) -> Option<u32> {
        match self {
            Self::Fixed(k) | Self::Incoming(k) => Some(k),
            Self::SigmaChoice => None,
        }
    }
}

fn trivial_point<C: PastaCurve>() -> Result<C::AffineExt, crate::Error> {
    let encoded = if C::ScalarExt::MODULUS == Fp::MODULUS {
        VESTA_TRIVIAL_GENERATOR
    } else {
        PALLAS_TRIVIAL_GENERATOR
    };
    Ok(decode_point::<C>(&encoded)?)
}

/// Fixed source-slot schema and parameter points for one k16 fold.
#[derive(Clone, Debug)]
pub struct FoldPlan<C: PastaCurve> {
    sources: Vec<FoldSource>,
    g0: C::AffineExt,
    g1: C::AffineExt,
    w: C::AffineExt,
    context: [C::Base; 4],
    purpose: crate::FoldPurpose,
    auxiliary: C::AffineExt,
    trivial: C::AffineExt,
}

impl<C: PastaCurve> FoldPlan<C> {
    /// Pins hard source slots and the parameter prefix; never appends a filler.
    ///
    /// # Errors
    /// Empty slots, unsupported source k, no k16 slot, or insufficient parameters.
    pub fn new(
        params: &PinnedParams<C>,
        source_ks: Vec<u32>,
        purpose: crate::FoldPurpose,
    ) -> Result<Self, crate::Error> {
        Self::with_sources(
            params,
            source_ks.into_iter().map(FoldSource::Fixed).collect(),
            purpose,
        )
    }

    /// Pins hard and incoming slots without selecting witness modes or fillers.
    /// At least one selected source must be k16; conditional schemas enforce
    /// this in the verdict, so short-only Accept modes reject.
    ///
    /// # Errors
    /// Empty/invalid schemas, no potentially full-length slot or insufficient parameters.
    pub fn with_sources(
        params: &PinnedParams<C>,
        sources: Vec<FoldSource>,
        purpose: crate::FoldPurpose,
    ) -> Result<Self, crate::Error> {
        if !purpose.permits_shape::<C>(sources.len()) {
            return Err(crate::Error::Purpose);
        }
        params.require_k(K_U32).map_err(crate::Error::Parameters)?;
        if sources.is_empty() {
            return Err(crate::Error::EmptyInputs);
        }
        if sources.iter().any(|source| {
            source
                .original_k()
                .is_some_and(|k| !(1..=K_U32).contains(&k))
        }) {
            return Err(crate::Error::SourceK);
        }
        if !sources.iter().any(|source| {
            matches!(source, FoldSource::Incoming(_) | FoldSource::SigmaChoice)
                || source.original_k() == Some(K_U32)
        }) {
            return Err(crate::Error::MissingFullLengthInput);
        }
        u64::try_from(sources.len()).map_err(|_| crate::Error::InputCount)?;
        Ok(Self {
            context: crate::accumulation::context(params, purpose, sources.len()),
            purpose,
            sources,
            g1: params.params().g()[1],
            w: params.params().w(),
            g0: params.params().g()[0],
            auxiliary: params.params().u(),
            trivial: trivial_point::<C>()?,
        })
    }

    /// Ordered hard/incoming schemas, including every explicit filler.
    #[must_use]
    pub fn sources(&self) -> &[FoldSource] {
        &self.sources
    }
}

/// Checked source metadata and a pinned deciding dummy for total claim decoding.
/// Source k16 decodes a transported accumulator; smaller k decodes an explicitly
/// normalized forwarded claim, whose zero prefix is not an `AccumulatorT` wire value.
#[derive(Clone, Debug)]
pub struct FoldInputDecodePlan<C: PastaCurve> {
    source_k: u32,
    dummy: C::AffineExt,
}

impl<C: PastaCurve> FoldInputDecodePlan<C> {
    /// Pins `(sum_{i<2^k} g_i, zero-prefix || [1;k])` for the selected descriptor k.
    ///
    /// # Errors
    /// Invalid source k, insufficient pinned parameters or an identity dummy.
    pub fn new(params: &PinnedParams<C>, source_k: u32) -> Result<Self, crate::Error> {
        if !(1..=K_U32).contains(&source_k) {
            return Err(crate::Error::SourceK);
        }
        params
            .require_k(source_k)
            .map_err(crate::Error::Parameters)?;
        let dummy = params
            .generator_prefix_sum(source_k)
            .map_err(crate::Error::Parameters)?;
        if bool::from(dummy.is_identity()) {
            return Err(crate::Error::Encoding(
                iroha_plonk::transcript::TranscriptError::IdentityPoint,
            ));
        }
        Ok(Self { source_k, dummy })
    }

    /// Descriptor-bound source k, before any Trivial-mode replacement.
    #[must_use]
    pub const fn source_k(&self) -> u32 {
        self.source_k
    }
}

/// Exact claim-decoding verdict with a checked deciding dummy on failure.
#[must_use = "include the decode bit in soft_ok before selecting this incoming slot"]
#[derive(Clone, Debug)]
pub struct SoftFoldInputCells<C: PastaCurve> {
    /// Checked original claim, or the source-specific fixed deciding dummy.
    pub value: FoldInputCells<C>,
    /// Length, canonical full-group G, canonical scalars and exact padding/nonzero verdict.
    pub valid: Bit<C::Base>,
}

/// Checked, normalized input cells; construction proves every padding/nonzero rule.
#[must_use = "every checked slot must enter its bound fold and obligation ledger"]
#[derive(Clone, Debug)]
pub struct FoldInputCells<C: PastaCurve> {
    source: FoldSource,
    source_k: Word<C::Base>,
    g: GeneratorPoint<C::Base>,
    challenges: [ScalarCells<C>; K],
}

impl<C: PastaCurve> FoldInputCells<C> {
    /// Explicit full-k16 deciding padding slot, constrained to compiled params.
    pub fn pinned_trivial(
        chip: &mut VerifierChip<C>,
        region: &mut Region<'_, C::Base>,
    ) -> Result<Self, Error> {
        let g = trivial_point::<C>().map_err(|_| Error::Synthesis)?;
        let g = chip.ecc.constant_point(region, &g.to_curve())?;
        let g = GeneratorPoint::from_assigned(g);
        let one = chip.constant(region, C::ScalarExt::ONE)?;
        let one = chip.export(region, &one)?;
        Self::from_normalized(
            chip,
            region,
            K_U32,
            g,
            core::array::from_fn(|_| one.clone()),
        )
    }

    /// Binds A's normalized sigma part without changing Omega's fixed program.
    /// Exactly one of k12/k14/k16 is admitted; the first `16-k` challenges
    /// are exactly zero and every remaining challenge is nonzero. All sixteen
    /// canonical values and the selected k enter the fold transcript.
    ///
    /// # Errors
    /// Layout failure. Any other k, wrong prefix or zero source challenge makes
    /// the circuit unsatisfied. This hard part cannot enter incoming selection.
    pub fn from_sigma_part(
        chip: &mut VerifierChip<C>,
        region: &mut Region<'_, C::Base>,
        source_k: &Word<C::Base>,
        g: GeneratorPoint<C::Base>,
        challenges: [ScalarCells<C>; K],
    ) -> Result<Self, Error> {
        let mut choices = Vec::with_capacity(3);
        for k in [12, 14, 16] {
            let fixed = chip.glue.constant(region, C::Base::from(k))?;
            choices.push(chip.glue.is_equal(region, source_k, &fixed)?);
        }
        let short = chip
            .glue
            .add(region, choices[0].word(), choices[1].word())?;
        let all = chip.glue.add(region, &short, choices[2].word())?;
        chip.glue.enforce_constant(region, &all, C::Base::ONE)?;
        let prefix_two = chip.glue.not(region, &choices[2])?;
        for (round, challenge) in challenges.iter().enumerate() {
            let low_zero = chip.glue.is_zero(region, challenge.lo().word())?;
            let high_zero = chip.glue.is_zero(region, challenge.hi().word())?;
            let is_zero = chip.glue.and(region, &low_zero, &high_zero)?;
            if round < 2 {
                GlueChip::assert_equal(region, is_zero.word(), prefix_two.word())?;
            } else if round < 4 {
                GlueChip::assert_equal(region, is_zero.word(), choices[0].word())?;
            } else {
                chip.glue
                    .enforce_constant(region, is_zero.word(), C::Base::ZERO)?;
            }
        }
        Ok(Self {
            source: FoldSource::SigmaChoice,
            source_k: source_k.clone(),
            g,
            challenges,
        })
    }
    /// Totally decodes a fixed 544-byte normalized incoming claim.
    /// `messages` and the actual LE32 `length` must be linked to the same caller
    /// byte payload. Every malformed encoding, zero real challenge, bad prefix
    /// or length selects the source-specific deciding dummy and a false bit.
    /// The consumer must include that bit in its complete `soft_ok` predicate.
    ///
    /// # Errors
    /// A wrong fixed message-array shape or layout errors. Arbitrary byte values
    /// and arbitrary bounded actual lengths remain satisfiable.
    pub fn decode_soft(
        chip: &mut VerifierChip<C>,
        region: &mut Region<'_, C::Base>,
        plan: &FoldInputDecodePlan<C>,
        messages: &[LeElement<C::Base>],
        length: &Uint<C::Base, 32>,
    ) -> Result<SoftFoldInputCells<C>, Error> {
        if messages.len() != K + 1 {
            return Err(Error::Synthesis);
        }
        let expected = chip.glue.constant(
            region,
            C::Base::from(u64::try_from(ACCUMULATOR_BYTES).map_err(|_| Error::BoundsFailure)?),
        )?;
        let mut valid = chip.glue.is_equal(region, length.word(), &expected)?;
        let point = decode_generator_soft::<C>(
            &mut UintChip::new(&mut chip.glue, &mut chip.range),
            &mut chip.ecc,
            region,
            &messages[0],
        )?;
        chip.combine(region, &mut valid, &point.valid)?;
        let prefix = K - plan.source_k as usize;
        let mut decoded = Vec::with_capacity(K);
        for (round, element) in messages[1..].iter().enumerate() {
            let scalar = decode_scalar_soft::<C>(&mut chip.uint(), region, element)?;
            chip.combine(region, &mut valid, &scalar.valid)?;
            let low_zero = chip.glue.is_zero(region, scalar.value.lo().word())?;
            let high_zero = chip.glue.is_zero(region, scalar.value.hi().word())?;
            let zero = chip.glue.and(region, &low_zero, &high_zero)?;
            let padding = if round < prefix {
                zero
            } else {
                chip.glue.not(region, &zero)?
            };
            chip.combine(region, &mut valid, &padding)?;
            decoded.push(scalar.value);
        }
        let dummy = chip.ecc.constant_point(region, &plan.dummy.to_curve())?;
        let selected =
            EccChip::<C>::select(&mut chip.glue, region, &valid, point.value.point(), &dummy)?;
        let g = GeneratorPoint::from_assigned(selected);
        let mut challenges = Vec::with_capacity(K);
        for (round, scalar) in decoded.iter().enumerate() {
            let low = chip.glue.select_constant(
                region,
                &valid,
                scalar.lo().word(),
                if round < prefix {
                    C::Base::ZERO
                } else {
                    C::Base::ONE
                },
            )?;
            let high =
                chip.glue
                    .select_constant(region, &valid, scalar.hi().word(), C::Base::ZERO)?;
            let low = chip.uint().range_check::<128>(region, &low)?;
            let high = chip.uint().range_check::<127>(region, &high)?;
            challenges.push(ScalarCells::from_limbs(
                &mut chip.uint(),
                region,
                &low,
                &high,
            )?);
        }
        let source_k = chip
            .glue
            .constant(region, C::Base::from(u64::from(plan.source_k)))?;
        let value = Self {
            source: FoldSource::Fixed(plan.source_k),
            source_k,
            g,
            challenges: challenges.try_into().map_err(|_| Error::Synthesis)?,
        };
        Ok(SoftFoldInputCells { value, valid })
    }

    /// Decodes a transported or normalized claim from G followed by sixteen scalars.
    /// The selected descriptor supplies source k; zero-prefix normalization is
    /// checked even though transported full-length claims use no zero entries.
    ///
    /// # Errors
    /// Wrong fixed shape, unsupported k or layout failure. Invalid encodings,
    /// padding and zero real challenges make the circuit unsatisfied.
    pub fn decode(
        chip: &mut VerifierChip<C>,
        region: &mut Region<'_, C::Base>,
        source_k: u32,
        messages: &[LeElement<C::Base>],
    ) -> Result<Self, Error> {
        if messages.len() != K + 1 {
            return Err(Error::Synthesis);
        }
        let g = crate::codec::decode_generator::<C>(
            &mut UintChip::new(&mut chip.glue, &mut chip.range),
            &mut chip.ecc,
            region,
            &messages[0],
        )?;
        let challenges = messages[1..]
            .iter()
            .map(|element| crate::codec::decode_scalar::<C>(&mut chip.uint(), region, element))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_normalized(
            chip,
            region,
            source_k,
            g,
            challenges.try_into().map_err(|_| Error::Synthesis)?,
        )
    }

    /// Checks an existing normalized vector and scoped full-group generator claim.
    ///
    /// # Errors
    /// Unsupported metadata k or layout errors. Bad witness padding or a zero
    /// source challenge makes the circuit unsatisfied, matching native checked input.
    pub fn from_normalized(
        chip: &mut VerifierChip<C>,
        region: &mut Region<'_, C::Base>,
        source_k: u32,
        g: GeneratorPoint<C::Base>,
        challenges: [ScalarCells<C>; K],
    ) -> Result<Self, Error> {
        if !(1..=K_U32).contains(&source_k) {
            return Err(Error::Synthesis);
        }
        let prefix = K - source_k as usize;
        for (round, cells) in challenges.iter().enumerate() {
            if round < prefix {
                chip.glue
                    .enforce_constant(region, cells.lo().word(), C::Base::ZERO)?;
                chip.glue
                    .enforce_constant(region, cells.hi().word(), C::Base::ZERO)?;
            } else {
                let value = chip.import(region, cells)?;
                let nonzero = chip.nonzero(region, &value)?;
                chip.glue
                    .enforce_constant(region, nonzero.word(), C::Base::ONE)?;
            }
        }
        Ok(Self {
            source: FoldSource::Fixed(source_k),
            source_k: chip
                .glue
                .constant(region, C::Base::from(u64::from(source_k)))?,
            g,
            challenges,
        })
    }

    /// Selects an incoming slot from its constrained one-hot mode.
    /// Accept keeps the original; Corrected changes only G and requires it to
    /// differ; Trivial selects pinned G, all-one challenges and source k16.
    /// The owning relation must also enforce the global burn/no-op mode rule.
    ///
    /// # Errors
    /// Nested incoming selection, invalid constants or layout errors. A selected
    /// correction equal to the original makes the circuit unsatisfied.
    pub fn select_incoming(
        chip: &mut VerifierChip<C>,
        region: &mut Region<'_, C::Base>,
        original: &Self,
        corrected: &GeneratorPoint<C::Base>,
        mode: &ModeCells<C::Base>,
    ) -> Result<Self, Error> {
        let FoldSource::Fixed(k) = original.source else {
            return Err(Error::Synthesis);
        };
        let same_x = chip.glue.is_equal(region, original.g.x(), corrected.x())?;
        let same_y = chip.glue.is_equal(region, original.g.y(), corrected.y())?;
        let same = chip.glue.and(region, &same_x, &same_y)?;
        let forbidden = chip.glue.and(region, mode.corrected(), &same)?;
        chip.glue
            .enforce_constant(region, forbidden.word(), C::Base::ZERO)?;
        let selected = EccChip::<C>::select(
            &mut chip.glue,
            region,
            mode.corrected(),
            corrected.point(),
            original.g.point(),
        )?;
        let trivial = trivial_point::<C>().map_err(|_| Error::Synthesis)?;
        let trivial = chip.ecc.constant_point(region, &trivial.to_curve())?;
        let selected =
            EccChip::<C>::select(&mut chip.glue, region, mode.trivial(), &trivial, &selected)?;
        let g = GeneratorPoint::from_assigned(selected);
        let one = chip.constant(region, C::ScalarExt::ONE)?;
        let mut challenges = Vec::with_capacity(K);
        for value in &original.challenges {
            let value = chip.import(region, value)?;
            let selected = chip.arithmetic.select(
                &mut UintChip::new(&mut chip.glue, &mut chip.range),
                region,
                mode.trivial(),
                &one,
                &value,
            )?;
            challenges.push(chip.export(region, &selected)?);
        }
        let source_k = chip.glue.linear(
            region,
            &[(C::Base::from(u64::from(K_U32 - k)), mode.trivial().word())],
            C::Base::from(u64::from(k)),
        )?;
        Ok(Self {
            source: FoldSource::Incoming(k),
            source_k,
            g,
            challenges: challenges.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Pads a checked succinct-verifier output while preserving its original k.
    ///
    /// # Errors
    /// Unsupported source k, inconsistent claim shape or layout errors.
    pub fn from_claim(
        chip: &mut VerifierChip<C>,
        region: &mut Region<'_, C::Base>,
        claim: &GeneratorClaimCells<C>,
    ) -> Result<Self, Error> {
        if !(1..=K_U32).contains(&claim.k()) || claim.challenges().len() != claim.k() as usize {
            return Err(Error::Synthesis);
        }
        let zero = chip.constant(region, C::ScalarExt::ZERO)?;
        let zero = chip.export(region, &zero)?;
        let mut challenges = vec![zero; K - claim.k() as usize];
        challenges.extend_from_slice(claim.challenges());
        Self::from_normalized(
            chip,
            region,
            claim.k(),
            claim.g().clone(),
            challenges.try_into().map_err(|_| Error::Synthesis)?,
        )
    }

    /// Original descriptor schema of this slot.
    #[must_use]
    pub const fn source(&self) -> FoldSource {
        self.source
    }
    /// Constrained selected source k bound into the fold transcript.
    #[must_use]
    pub const fn source_k(&self) -> &Word<C::Base> {
        &self.source_k
    }
    /// The scoped full-group generator claim, including identity.
    #[must_use]
    pub const fn g(&self) -> &GeneratorPoint<C::Base> {
        &self.g
    }
    /// Exactly sixteen canonical cells with the checked leading zero prefix.
    #[must_use]
    pub const fn challenges(&self) -> &[ScalarCells<C>; K] {
        &self.challenges
    }
}

/// A succinct fold verdict and its undecided k16 output claim.
#[must_use = "bind the verdict and register or decide the returned claim"]
#[derive(Clone, Debug)]
pub struct FoldOutputCells<C: PastaCurve> {
    /// Exact succinct-verification verdict for the supplied bytes and checked slots.
    pub valid: Bit<C::Base>,
    /// The actual generator claim, or the pinned deciding trivial claim on failure.
    pub claim: GeneratorClaimCells<C>,
    /// Diagnostic exact native/circuit transcript comparison.
    pub prelude: [ScalarCells<C>; 3],
    /// Diagnostic private hash comparison.
    pub digest: Word<C::Base>,
    /// Diagnostic checked correction comparison.
    pub gamma: ScalarCells<C>,
}

// Only a closed frame owner can select the terminal binding. Generic folds
// always hash every exact input. This enum is not part of the public API.
enum InputBinding<C: PastaCurve> {
    Exact,
    Terminal {
        descriptor: [u8; 32],
        raw: Word<C::Base>,
    },
}

impl<C: PastaCurve> VerifierChip<C> {
    fn fold_evaluation_cells(
        &mut self,
        region: &mut Region<'_, C::Base>,
        powers: &[Scalar<C>],
        challenges: &[ScalarCells<C>],
    ) -> Result<Scalar<C>, Error> {
        let one = self.constant(region, C::ScalarExt::ONE)?;
        let mut value = one.clone();
        for (power, challenge) in powers.iter().zip(challenges.iter().rev()) {
            let challenge = self.import(region, challenge)?;
            let product = self.mul(region, power, &challenge)?;
            let factor = self.add(region, &one, &product)?;
            value = self.mul(region, &value, &factor)?;
        }
        Ok(value)
    }

    fn committed_fold_prelude(
        &mut self,
        region: &mut Region<'_, C::Base>,
        plan: &FoldPlan<C>,
        inputs: &[FoldInputCells<C>],
        messages: &[LeElement<C::Base>],
        valid: &mut Bit<C::Base>,
        binding: &InputBinding<C>,
    ) -> Result<
        (
            TranscriptChip<C::Base>,
            [ScalarCells<C>; 3],
            Vec<ScalarCells<C>>,
            Word<C::Base>,
        ),
        Error,
    > {
        let d = decode_point_soft::<C>(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            &mut self.ecc,
            region,
            &messages[0],
        )?;
        self.combine(region, valid, &d.valid)?;
        let rho = decode_scalar_soft::<C>(&mut self.uint(), region, &messages[2 * K + 3])?;
        self.combine(region, valid, &rho.valid)?;
        let mut masks = Vec::with_capacity(2 * K);
        for message in &messages[2 * K + 4..] {
            let b = decode_scalar_soft::<C>(&mut self.uint(), region, message)?;
            self.combine(region, valid, &b.valid)?;
            masks.push(b.value);
        }
        let mut words = Vec::new();
        for x in plan.context {
            words.push(self.glue.constant(region, x)?);
        }
        let bound_inputs = match binding {
            InputBinding::Exact => inputs,
            InputBinding::Terminal { descriptor, raw } => {
                for limb in descriptor.chunks_exact(16) {
                    words.push(self.glue.constant(
                        region,
                        C::Base::from_u128(u128::from_le_bytes(
                            limb.try_into().map_err(|_| Error::Synthesis)?,
                        )),
                    )?);
                }
                words.push(raw.clone());
                // The complete A own-opening claim is NOT in its first prefix.
                // The closed owner derives all other slots from the bound frame.
                &inputs[1..2]
            }
        };
        for input in bound_inputs {
            words.extend([
                input.g.x().clone(),
                input.g.y().clone(),
                input.source_k.clone(),
            ]);
            for u in &input.challenges {
                if let Some(x) = u.native_word() {
                    words.push(x.clone());
                } else {
                    words.extend([u.lo().word().clone(), u.hi().word().clone()]);
                }
            }
        }
        for b in &masks {
            if let Some(x) = b.native_word() {
                words.push(x.clone());
            } else {
                words.extend([b.lo().word().clone(), b.hi().word().clone()]);
            }
        }
        let mut duplex = self.duplex.take().ok_or(Error::Synthesis)?;
        if !duplex.is_clear() || duplex.buffered() != 0 {
            return Err(Error::Synthesis);
        }
        duplex.absorb_constant(C::Base::from(u64::from_le_bytes(match binding {
            InputBinding::Exact => *b"pipa-in1",
            InputBinding::Terminal { .. } => *b"pipa-tm1",
        })));
        duplex.absorb_constant(C::Base::from(words.len() as u64));
        for word in &words {
            duplex.absorb(word);
        }
        let digest = duplex.squeeze_and_clear(region)?;
        let limbs = iroha_plonk_gadgets::ff::CanonicalS6::from_native_word(
            &mut self.uint(),
            region,
            &digest,
        )?;
        let lo = ScalarCells::<C>::from_native_word(&mut self.uint(), region, limbs.lo().word())?;
        let hi = ScalarCells::<C>::from_native_word(&mut self.uint(), region, limbs.hi().word())?;
        let mut opening = self.ecc.constant_point(region, &C::identity())?;
        for (p, s) in [(plan.g0, &lo), (plan.g1, &hi), (plan.w, &rho.value)] {
            let point = self.ecc.constant_point(region, &p.to_curve())?;
            let scalar = self.import(region, s)?;
            let term = self.scale_point(region, &point, &scalar)?;
            opening = self.ecc.add(region, &opening, &term)?;
        }
        let neg_d = EccChip::<C>::neg(&mut self.glue, region, d.value.point())?;
        let difference = self.ecc.add(region, &opening, &neg_d)?;
        let opening_ok = EccChip::<C>::is_identity(&mut self.glue, region, &difference)?;
        self.combine(region, valid, &opening_ok)?;
        let mut transcript = TranscriptChip::from_duplex(duplex, Domain::Fold)?;
        for value in plan.context {
            transcript.common_constant(value);
        }
        transcript.common_point(&d.value);
        let prelude = [
            transcript.squeeze_scalar::<C>(&mut self.uint(), region)?,
            transcript.squeeze_scalar::<C>(&mut self.uint(), region)?,
            transcript.squeeze_scalar::<C>(&mut self.uint(), region)?,
        ];
        Ok((transcript, prelude, masks, digest))
    }

    fn fold_claim(
        &mut self,
        region: &mut Region<'_, C::Base>,
        plan: &FoldPlan<C>,
        valid: &Bit<C::Base>,
        suffix: &GeneratorPoint<C::Base>,
        rounds: &[ScalarCells<C>],
    ) -> Result<GeneratorClaimCells<C>, Error> {
        let dummy = self.ecc.constant_point(region, &plan.trivial.to_curve())?;
        let selected = EccChip::<C>::select(&mut self.glue, region, valid, suffix.point(), &dummy)?;
        let g = GeneratorPoint::from_assigned(selected);
        let one = self.constant(region, C::ScalarExt::ONE)?;
        let mut challenges = Vec::with_capacity(K);
        for cells in rounds {
            let value = self.import(region, cells)?;
            let value = self.arithmetic.select(
                &mut UintChip::new(&mut self.glue, &mut self.range),
                region,
                valid,
                &value,
                &one,
            )?;
            challenges.push(self.export(region, &value)?);
        }
        Ok(GeneratorClaimCells {
            k: K_U32,
            g,
            challenges,
        })
    }

    /// Verifies the exact 2,176-byte committed-mask witness with complete group equations.
    ///
    /// `messages` is D, sixteen masked L/R pairs, c, G′, rho and32 masks, linked to the same
    /// caller-owned byte tape as the supplied LE32 `length`. Inputs must match
    /// the fixed ordered source-k schema. No input or constant filler is inferred.
    ///
    /// # Errors
    /// Structural metadata/length-shape mismatches or layout errors. Arbitrary
    /// byte contents soft-fail; hard mode additionally requires the verdict.
    pub fn verify_fold(
        &mut self,
        region: &mut Region<'_, C::Base>,
        plan: &FoldPlan<C>,
        inputs: &[FoldInputCells<C>],
        messages: &[LeElement<C::Base>],
        length: &Uint<C::Base, 32>,
        mode: VerificationMode,
    ) -> Result<FoldOutputCells<C>, Error> {
        if plan.purpose == crate::FoldPurpose::WrapperVesta {
            return Err(Error::Synthesis);
        }
        self.verify_fold_bound(
            region,
            plan,
            inputs,
            messages,
            length,
            mode,
            InputBinding::Exact,
        )
    }

    fn verify_fold_bound(
        &mut self,
        region: &mut Region<'_, C::Base>,
        plan: &FoldPlan<C>,
        inputs: &[FoldInputCells<C>],
        messages: &[LeElement<C::Base>],
        length: &Uint<C::Base, 32>,
        mode: VerificationMode,
        binding: InputBinding<C>,
    ) -> Result<FoldOutputCells<C>, Error> {
        if messages.len() != FOLD_WITNESS_BYTES / 32
            || inputs.len() != plan.sources.len()
            || inputs
                .iter()
                .zip(&plan.sources)
                .any(|(input, source)| input.source != *source)
        {
            return Err(Error::Synthesis);
        }
        let length_constant = self.glue.constant(region, C::Base::from(2176))?;
        let mut valid = self
            .glue
            .is_equal(region, length.word(), &length_constant)?;
        let full_length = self
            .glue
            .constant(region, C::Base::from(u64::from(K_U32)))?;
        let first = inputs.first().ok_or(Error::Synthesis)?;
        let mut has_full = self.glue.is_equal(region, &first.source_k, &full_length)?;
        for input in &inputs[1..] {
            let matches = self.glue.is_equal(region, &input.source_k, &full_length)?;
            let missing_prior = self.glue.not(region, &has_full)?;
            let missing_current = self.glue.not(region, &matches)?;
            let missing = self.glue.and(region, &missing_prior, &missing_current)?;
            has_full = self.glue.not(region, &missing)?;
        }
        self.combine(region, &mut valid, &has_full)?;
        let (mut transcript, prelude, masks, digest) =
            self.committed_fold_prelude(region, plan, inputs, messages, &mut valid, &binding)?;
        let [alpha_cells, z_cells, zeta_cells] = prelude.clone();
        let mut gamma_pairs = Vec::with_capacity(2 * K);
        let alpha = self.import(region, &alpha_cells)?;
        let z = self.import(region, &z_cells)?;
        let zeta = self.import(region, &zeta_cells)?;
        let mut powers = vec![z];
        for round in 1..K {
            powers.push(self.arithmetic.square(
                &mut iroha_plonk_gadgets::range::u128::UintChip::new(
                    &mut self.glue,
                    &mut self.range,
                ),
                region,
                &powers[round - 1],
            )?);
        }
        let mut evaluation = self.constant(region, C::ScalarExt::ZERO)?;
        for input in inputs.iter().rev() {
            let value = self.fold_evaluation_cells(region, &powers, &input.challenges)?;
            evaluation = self.mul(region, &evaluation, &alpha)?;
            evaluation = self.add(region, &evaluation, &value)?;
        }
        let points = inputs
            .iter()
            .map(|input| input.g.point().clone())
            .collect::<Vec<_>>();
        let mut equation = self.ecc.horner(
            region,
            &mut self.range,
            ScalarLimbs::new(alpha_cells.lo(), alpha_cells.hi()),
            &points,
        )?;
        let mut rounds = Vec::with_capacity(K);
        for round in 0..K {
            let left = decode_point_soft::<C>(
                &mut UintChip::new(&mut self.glue, &mut self.range),
                &mut self.ecc,
                region,
                &messages[1 + 2 * round],
            )?;
            let right = decode_point_soft::<C>(
                &mut UintChip::new(&mut self.glue, &mut self.range),
                &mut self.ecc,
                region,
                &messages[2 + 2 * round],
            )?;
            self.combine(region, &mut valid, &left.valid)?;
            self.combine(region, &mut valid, &right.valid)?;
            transcript.common_point(&left.value);
            transcript.common_point(&right.value);
            let cells = transcript.squeeze_scalar::<C>(&mut self.uint(), region)?;
            let cells = cells.nonzero_or_one(&mut self.uint(), region)?;
            let challenge = self.import(region, &cells)?;
            // Exact constrained nz round cells; no zero/identity refusal is added.
            let inverse = self.arithmetic.ff.inverse(region, &challenge)?;
            let left_mask = self.import(region, &masks[2 * round])?;
            let right_mask = self.import(region, &masks[2 * round + 1])?;
            gamma_pairs.push((left_mask, inverse.clone()));
            gamma_pairs.push((right_mask, challenge.clone()));
            let left_term = self.scale_point(region, left.value.point(), &inverse)?;
            let right_term = self.scale_point(region, right.value.point(), &challenge)?;
            equation = self.ecc.add(region, &equation, &left_term)?;
            equation = self.ecc.add(region, &equation, &right_term)?;
            rounds.push(cells);
        }
        let coefficient = decode_scalar_soft::<C>(&mut self.uint(), region, &messages[1 + 2 * K])?;
        self.combine(region, &mut valid, &coefficient.valid)?;
        // Private c is never absorbed into a live continuation.
        let suffix = decode_generator_soft::<C>(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            &mut self.ecc,
            region,
            &messages[2 + 2 * K],
        )?;
        self.combine(region, &mut valid, &suffix.valid)?;
        self.duplex = Some(transcript.into_duplex());
        let c = self.import(region, &coefficient.value)?;
        let folded = self.fold_evaluation_cells(region, &powers, &rounds)?;
        let auxiliary_coefficient = self.mul(region, &c, &folded)?;
        let auxiliary_coefficient = self.mul(region, &auxiliary_coefficient, &zeta)?;
        let g0 = self.ecc.constant_point(region, &plan.g0.to_curve())?;
        let auxiliary = self
            .ecc
            .constant_point(region, &plan.auxiliary.to_curve())?;
        for (point, scalar) in [
            (&g0, &evaluation),
            (&auxiliary, &auxiliary_coefficient),
            (suffix.value.point(), &c),
        ] {
            let scalar = self.neg(region, scalar)?;
            let term = self.scale_point(region, point, &scalar)?;
            equation = self.ecc.add(region, &equation, &term)?;
        }
        // All masks and round challenges retain their original checked imports.
        // Batched unsigned dot products compute the same scalar gamma modulo Fr.
        let mut gamma = self.constant(region, C::ScalarExt::ZERO)?;
        for chunk in gamma_pairs.chunks(8) {
            let pairs = chunk.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>();
            let part = self.arithmetic.dot(
                &mut UintChip::new(&mut self.glue, &mut self.range),
                region,
                &pairs,
            )?;
            gamma = self.add(region, &gamma, &part)?;
        }
        let w = self.ecc.constant_point(region, &plan.w.to_curve())?;
        let negative_gamma = self.neg(region, &gamma)?;
        let correction = self.scale_point(region, &w, &negative_gamma)?;
        equation = self.ecc.add(region, &equation, &correction)?;
        let gamma = self.export(region, &gamma)?;
        let zero = EccChip::<C>::is_identity(&mut self.glue, region, &equation)?;
        self.combine(region, &mut valid, &zero)?;
        if mode == VerificationMode::Hard {
            self.glue
                .enforce_constant(region, valid.word(), C::Base::ONE)?;
            // This assertion includes the committed private tape, purpose/length/source
            // metadata, canonical finite D/L/R and full-group G, every mapped nonzero
            // round challenge and the complete fold equation. Forward those exact cells.
            return Ok(FoldOutputCells {
                prelude,
                digest,
                gamma,
                valid,
                claim: GeneratorClaimCells {
                    k: K_U32,
                    g: suffix.value,
                    challenges: rounds,
                },
            });
        }
        let claim = self.fold_claim(region, plan, &valid, &suffix.value, &rounds)?;
        Ok(FoldOutputCells {
            valid,
            claim,
            prelude,
            digest,
            gamma,
        })
    }
}

/// Terminal wrapper result whose lineage word and four fold slots come from the
/// same hard-verified frame. No caller-selected digest or slot list is accepted.
pub struct TerminalFoldOutputCells {
    /// A's lineage binding, from its actual first public frame word.
    pub lineage: Word<iroha_pasta::Fq>,
    /// The new complete fold verdict and undecided output claim.
    pub fold: FoldOutputCells<iroha_pasta::Eq>,
}
impl VerifierChip<iroha_pasta::Eq> {
    fn terminal_coordinate(
        chip: &mut VerifierChip<iroha_pasta::Eq>,
        region: &mut Region<'_, iroha_pasta::Fq>,
        words: &[Word<iroha_pasta::Fq>],
    ) -> Result<Word<iroha_pasta::Fq>, Error> {
        if words.len() != 2 {
            return Err(Error::Synthesis);
        }
        let lo = chip.uint().range_check::<128>(region, &words[0])?;
        let hi = chip.uint().range_check::<127>(region, &words[1])?;
        let hi = iroha_plonk_gadgets::range::u128::UintChip::widen::<127, 128>(&hi);
        iroha_plonk_gadgets::bytes::element::assert_le_max(
            &mut chip.uint(),
            region,
            lo.word(),
            &hi,
            iroha_plonk_gadgets::bytes::element::modulus_max::<iroha_pasta::Fq>(),
        )?;
        chip.uint().glue().linear(
            region,
            &[
                (iroha_pasta::Fq::ONE, lo.word()),
                (
                    iroha_pasta::Fq::from_u128(u128::MAX) + iroha_pasta::Fq::ONE,
                    hi.word(),
                ),
            ],
            iroha_pasta::Fq::ZERO,
        )
    }
    fn terminal_point(
        chip: &mut VerifierChip<iroha_pasta::Eq>,
        region: &mut Region<'_, iroha_pasta::Fq>,
        words: &[Word<iroha_pasta::Fq>],
    ) -> Result<GeneratorPoint<iroha_pasta::Fq>, Error> {
        if words.len() != 4 {
            return Err(Error::Synthesis);
        }
        let x = Self::terminal_coordinate(chip, region, &words[..2])?;
        let y = Self::terminal_coordinate(chip, region, &words[2..])?;
        chip.constrain_generator(region, &x, &y)
    }
    fn terminal_claim(
        chip: &mut VerifierChip<iroha_pasta::Eq>,
        region: &mut Region<'_, iroha_pasta::Fq>,
        words: &[Word<iroha_pasta::Fq>],
        scalars: &[ScalarCells<iroha_pasta::Eq>],
    ) -> Result<FoldInputCells<iroha_pasta::Eq>, Error> {
        let g = Self::terminal_point(chip, region, words)?;
        FoldInputCells::from_normalized(
            chip,
            region,
            16,
            g,
            scalars.to_vec().try_into().map_err(|_| Error::Synthesis)?,
        )
    }
    /// Closed terminal-only fold, binding the raw prefix of the same hard A
    /// verification and its exact own-opening claim. Derives all frame slots.
    pub fn verify_terminal_frame_fold(
        &mut self,
        region: &mut Region<'_, iroha_pasta::Fq>,
        plan: &FoldPlan<iroha_pasta::Eq>,
        frame: crate::verifier::HardVerifiedFrame<iroha_pasta::Eq>,
        messages: &[LeElement<iroha_pasta::Fq>],
        length: &Uint<iroha_pasta::Fq, 32>,
    ) -> Result<TerminalFoldOutputCells, Error> {
        let descriptor = frame.binding.descriptor();
        if plan.purpose != crate::FoldPurpose::WrapperVesta
            || descriptor.k != 16
            || descriptor.instance_lengths != [69]
            || descriptor.instance_types.as_deref()
                != Some(&[iroha_plonk::cs::InstanceType::Bounded])
            || plan.sources
                != [
                    FoldSource::SigmaChoice,
                    FoldSource::Fixed(16),
                    FoldSource::Fixed(16),
                    FoldSource::Incoming(16),
                ]
            || frame.instances.len() != 1
            || frame.instances[0].len() != 69
        {
            return Err(Error::Synthesis);
        }
        let scalars = &frame.instances[0];
        let words = scalars
            .iter()
            .map(|s| s.native_word().cloned().ok_or(Error::Synthesis))
            .collect::<Result<Vec<_>, _>>()?;
        let part_point = Self::terminal_point(self, region, &words[2..6])?;
        let part = FoldInputCells::from_sigma_part(
            self,
            region,
            &words[1],
            part_point,
            scalars[6..22]
                .to_vec()
                .try_into()
                .map_err(|_| Error::Synthesis)?,
        )?;
        let own = FoldInputCells::from_claim(self, region, &frame.own_claim)?;
        let predecessor = Self::terminal_claim(self, region, &words[22..26], &scalars[26..42])?;
        let incoming = Self::terminal_claim(self, region, &words[42..46], &scalars[46..62])?;
        let modes = words[62..65]
            .to_vec()
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let modes = ModeCells::constrain(self.uint().glue(), region, &modes)?;
        let corrected = Self::terminal_point(self, region, &words[65..69])?;
        let selected =
            FoldInputCells::select_incoming(self, region, &incoming, &corrected, &modes)?;
        let inputs = [part, own, predecessor, selected];
        let binding = InputBinding::Terminal {
            descriptor: *frame.binding.digest(),
            raw: frame.first_raw,
        };
        let fold = self.verify_fold_bound(
            region,
            plan,
            &inputs,
            messages,
            length,
            VerificationMode::Hard,
            binding,
        )?;
        Ok(TerminalFoldOutputCells {
            lineage: words[0].clone(),
            fold,
        })
    }
}
