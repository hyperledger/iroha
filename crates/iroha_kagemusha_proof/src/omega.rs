//! One fixed Omega wrapper for the uniform 69-word A frame.
//!
//! A is verified hard under one descriptor and a constant key-digest allowlist.
//! Its part, own A opening, predecessor and mode-selected incoming Vesta claims
//! enter four explicit AS slots. Absent predecessor/incoming claims are pinned
//! trivial fillers by A's variant key. Omega never omits a slot or substitutes
//! a different descriptor. Its public columns are the specified 1/2/16 values.
//!
//! TODO: compose real operation A proofs and qualify the final wrapper layout
//! against the joint Payment byte cap before freezing any artifact.

/// Original-key native final Omega producer and canonical durable restore.
pub mod native;

use crate::a_relation::AFramePlan;
use ff::{Field, PrimeField};
use iroha_pasta::{Eq, Fp, Fq, PastaCurve};
use iroha_plonk::{
    DescriptorBinding, VerifyingKey,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value},
    pcs::ipa::PinnedParams,
    transcript::TranscriptRepr,
};
use iroha_plonk_gadgets::{
    GlueChip, Uint, Word,
    bytes::element::{LeElement, assert_le_max, modulus_max},
    ecc::NonIdentityPoint,
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    FOLD_WITNESS_BYTES, K,
    accumulation_circuit::{FoldInputCells, FoldPlan, FoldSource},
    codec::ScalarCells,
    obligation::ModeCells,
    verifier::{
        CompactPublicConfig, CompactSpans, PinnedKeyCatalog, VerificationMode, VerifierChip,
        VerifierConfig, VerifierPlan,
    },
};

fn valid_allowlist(digests: &[Fq]) -> bool {
    !digests.is_empty()
        && digests.len() <= 32
        && !digests
            .iter()
            .enumerate()
            .any(|(index, value)| digests[..index].contains(value))
}

// Fq is a field: this product vanishes exactly when one fixed allowed digest
// equals the computed complete VK digest. Every factor is assigned by a fixed
// coefficient gate; no witness selector or supplied digest can choose a key.
fn constrain_allowed_key(
    glue: &mut GlueChip<Fq>,
    region: &mut Region<'_, Fq>,
    actual: &Word<Fq>,
    digests: &[Fq],
) -> Result<(), Error> {
    if !valid_allowlist(digests) {
        return Err(Error::Synthesis);
    }
    if digests.len() == 1 {
        return glue.enforce_constant(region, actual, digests[0]);
    }
    let mut product = glue.linear(region, &[(Fq::ONE, actual)], -digests[0])?;
    for digest in &digests[1..] {
        let factor = glue.linear(region, &[(Fq::ONE, actual)], -*digest)?;
        product = glue.mul(region, &product, &factor)?;
    }
    glue.enforce_constant(region, &product, Fq::ZERO)
}

/// Circuit-fixed A descriptor, admissible keys and exact four-slot fold plan.
#[derive(Clone, Debug)]
pub struct OmegaPlan {
    verifier: VerifierPlan<Eq>,
    allowlist: Vec<Fq>,
    catalog: Option<PinnedKeyCatalog<Eq>>,
    fold: FoldPlan<Eq>,
}
impl OmegaPlan {
    /// Accepts one k16 PIPA-R A descriptor with the uniform Bounded column69,
    /// and 1..=32 distinct complete key digests. Every variant uses this plan.
    ///
    /// # Errors
    /// Wrong A profile/shape, duplicate keys, or insufficient pinned parameters.
    pub fn new(
        binding: DescriptorBinding,
        params: PinnedParams<Eq>,
        allowlist: Vec<Fq>,
    ) -> Result<Self, Error> {
        let d = binding.descriptor();
        if d.k != 16
            || d.instance_lengths != [69]
            || d.instance_types.as_deref() != Some(&[InstanceType::Bounded])
            || !valid_allowlist(&allowlist)
        {
            return Err(Error::Synthesis);
        }
        let fold = FoldPlan::with_sources(
            &params,
            vec![
                FoldSource::SigmaChoice,
                FoldSource::Fixed(16),
                FoldSource::Fixed(16),
                FoldSource::Incoming(16),
            ],
        )
        .map_err(|_| Error::Synthesis)?;
        let verifier = VerifierPlan::new(binding, params).map_err(|_| Error::Synthesis)?;
        Ok(Self {
            verifier,
            allowlist,
            catalog: None,
            fold,
        })
    }
    /// Pins the complete key catalog as circuit metadata in the existing
    /// allowlist order. This explicit profile reuses its bound complete digest;
    /// it never falls back to witness-key hashing on a selection failure.
    ///
    /// # Errors
    /// Catalog keys differ from the exact descriptor or authorized digest list.
    pub fn with_key_catalog(mut self, keys: Vec<VerifyingKey<Eq>>) -> Result<Self, Error> {
        let catalog = PinnedKeyCatalog::new(&self.verifier, keys)?;
        if catalog.digests() != self.allowlist {
            return Err(Error::Synthesis);
        }
        self.catalog = Some(catalog);
        Ok(self)
    }
    /// Fixed A verifier program used by every key in the allowlist.
    pub const fn verifier(&self) -> &VerifierPlan<Eq> {
        &self.verifier
    }
    /// Homogeneous outer public columns: digest, point coordinates, challenges.
    pub const fn instance_types() -> [InstanceType; 3] {
        [
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ]
    }
    /// The exact public-column lengths required by Lambda §3.2.
    pub const fn instance_lengths() -> [usize; 3] {
        [1, 2, K]
    }
}
/// A's original proof/frame and the local four-slot accumulation witness.
#[derive(Clone, Debug)]
pub struct OmegaWitness {
    /// Witness A key, authorized by the complete digest computed in circuit.
    pub key: VerifyingKey<Eq>,
    /// Exactly69 canonical native Fp values from A's single public column.
    pub instances: Vec<Fp>,
    /// Descriptor-sized retained A proof bytes.
    pub proof: Vec<u8>,
    /// Original LE32 proof carrier length, linked to the same byte tape.
    pub length: u32,
    /// Canonical salt and non-hiding IPA body for the four explicit obligations.
    pub fold: [u8; FOLD_WITNESS_BYTES],
}
/// Shared complete verifier lanes and three fixed public columns.
#[derive(Clone, Debug)]
pub struct OmegaConfig {
    verifier: VerifierConfig<Eq>,
    public: [Column<Instance>; 3],
    compact_public: Option<CompactPublicConfig>,
}
/// The one-program Omega relation. Acceptance still requires its own Pallas
/// opening and the exported Vesta accumulator to be decided natively.
#[derive(Clone, Debug)]
pub struct OmegaCircuit {
    pub(crate) plan: OmegaPlan,
    pub(crate) witness: OmegaWitness,
    known: bool,
    compact: Option<CompactSpans>,
    secondary: Option<iroha_plonk_gadgets::range::secondary::SecondaryPlan>,
}
impl OmegaCircuit {
    /// Constructs the fixed wrapper; optional slot presence never changes shape.
    ///
    /// # Errors
    /// Proof/frame dimensions disagree with the fixed A descriptor.
    pub fn new(plan: OmegaPlan, witness: OmegaWitness) -> Result<Self, Error> {
        if witness.instances.len() != AFramePlan::instance_length()
            || witness.proof.len() != plan.verifier.proof_length()
        {
            return Err(Error::Synthesis);
        }
        Ok(Self {
            plan,
            witness,
            known: true,
            compact: None,
            secondary: None,
        })
    }
    /// Selects the explicit compact layout for artifact construction or
    /// diagnostics. Spans remain circuit-fixed; no verification fallback exists.
    /// The composed row and proof-size gates must pass before artifact freezing.
    #[must_use]
    pub fn with_compact_layout(mut self, spans: CompactSpans) -> Self {
        self.compact = Some(spans);
        self.secondary = None;
        self
    }

    /// Selects the guarded fixed secondary range program with a reserved
    /// public-prefix gap. Artifact qualification remains mandatory.
    #[must_use]
    pub fn with_secondary_layout(
        mut self,
        spans: CompactSpans,
        plan: iroha_plonk_gadgets::range::secondary::SecondaryPlan,
    ) -> Self {
        self.compact = Some(spans);
        self.secondary = Some(plan);
        self
    }

    /// Selects the explicit checked key-catalog profile for this wrapper.
    ///
    /// # Errors
    /// The catalog differs from the plan's exact descriptor or digest order.
    pub fn with_key_catalog(mut self, keys: Vec<VerifyingKey<Eq>>) -> Result<Self, Error> {
        self.plan = self.plan.with_key_catalog(keys)?;
        Ok(self)
    }

    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn messages(
        &self,
        chip: &mut VerifierChip<Eq>,
        region: &mut Region<'_, Fq>,
        raw: &[u8],
        length: u32,
    ) -> Result<ProofMessages, Error> {
        if !raw.len().is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        // These private bytes have no digest/chunk export. Their complete
        // 128/127/1 decomposition is an injective encoding of each raw message;
        // the original LE32 length has its own exact unsigned32 carrier.
        let length = chip
            .uint()
            .assign::<32>(region, self.value(u128::from(length)))?;
        let messages = raw
            .chunks_exact(32)
            .map(|chunk| {
                let message = chunk.try_into().map_err(|_| Error::Synthesis)?;
                LeElement::assign(&mut chip.uint(), region, self.value(message))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProofMessages { messages, length })
    }
    fn coordinate(
        chip: &mut VerifierChip<Eq>,
        region: &mut Region<'_, Fq>,
        words: &[Word<Fq>],
    ) -> Result<Word<Fq>, Error> {
        if words.len() != 2 {
            return Err(Error::Synthesis);
        }
        let lo = chip.uint().range_check::<128>(region, &words[0])?;
        let hi = chip.uint().range_check::<127>(region, &words[1])?;
        let hi = iroha_plonk_gadgets::range::u128::UintChip::widen::<127, 128>(&hi);
        assert_le_max(
            &mut chip.uint(),
            region,
            lo.word(),
            &hi,
            modulus_max::<Fq>(),
        )?;
        chip.uint().glue().linear(
            region,
            &[
                (Fq::ONE, lo.word()),
                (Fq::from_u128(u128::MAX) + Fq::ONE, hi.word()),
            ],
            Fq::ZERO,
        )
    }
    fn point(
        chip: &mut VerifierChip<Eq>,
        region: &mut Region<'_, Fq>,
        words: &[Word<Fq>],
    ) -> Result<NonIdentityPoint<Fq>, Error> {
        if words.len() != 4 {
            return Err(Error::Synthesis);
        }
        let x = Self::coordinate(chip, region, &words[..2])?;
        let y = Self::coordinate(chip, region, &words[2..])?;
        chip.constrain_point(region, &x, &y)
    }
    fn claim(
        chip: &mut VerifierChip<Eq>,
        region: &mut Region<'_, Fq>,
        words: &[Word<Fq>],
        scalars: &[ScalarCells<Eq>],
    ) -> Result<FoldInputCells<Eq>, Error> {
        let g = Self::point(chip, region, words)?;
        FoldInputCells::from_normalized(
            chip,
            region,
            16,
            g,
            scalars.to_vec().try_into().map_err(|_| Error::Synthesis)?,
        )
    }
}
struct ProofMessages {
    messages: Vec<LeElement<Fq>>,
    length: Uint<Fq, 32>,
}
impl Circuit<Fq> for OmegaCircuit {
    type Config = OmegaConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = (
        Option<CompactSpans>,
        Option<iroha_plonk_gadgets::range::secondary::SecondaryPlan>,
    );
    fn params(&self) -> Self::Params {
        (self.compact, self.secondary.clone())
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure_with_params(meta, (None, None))
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<Fq>,
        (spans, secondary): Self::Params,
    ) -> Self::Config {
        if let Some(spans) = spans {
            let (verifier, public) = if let Some(plan) = secondary {
                VerifierConfig::configure_compact_secondary(meta, spans, plan)
                    .expect("fixed valid secondary plan")
            } else {
                VerifierConfig::configure_compact(meta, spans)
            };
            return OmegaConfig {
                verifier,
                public: public.columns(),
                compact_public: Some(public),
            };
        }
        let verifier = VerifierConfig::configure(meta);
        let public = OmegaPlan::instance_lengths().map(|len| {
            let col = meta.instance_column(len);
            meta.enable_equality(col);
            col
        });
        OmegaConfig {
            verifier,
            public,
            compact_public: None,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        if self.witness.instances.len() != 69
            || self.witness.proof.len() != self.plan.verifier.proof_length()
        {
            return Err(Error::Synthesis);
        }
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let output = layouter.assign_region(
            || "uniform Omega wrapper",
            |mut region| {
                let proof = self.messages(
                    &mut chip,
                    &mut region,
                    &self.witness.proof,
                    self.witness.length,
                )?;
                let fold = self.messages(&mut chip, &mut region, &self.witness.fold, 1120)?;
                let mut scalars = Vec::new();
                for value in &self.witness.instances {
                    let [lo, hi] = foreign_limbs(value);
                    let lo = chip.uint().assign::<128>(&mut region, self.value(lo))?;
                    let hi = chip.uint().assign::<127>(&mut region, self.value(hi))?;
                    scalars.push(ScalarCells::from_limbs(
                        &mut chip.uint(),
                        &mut region,
                        &lo,
                        &hi,
                    )?);
                }
                let a = if let Some(catalog) = &self.plan.catalog {
                    let digest = self
                        .witness
                        .key
                        .kagemusha_digest(self.plan.verifier.binding())
                        .map_err(|_| Error::Synthesis)?;
                    let index = catalog
                        .digests()
                        .iter()
                        .position(|v| *v == digest)
                        .unwrap_or_else(|| catalog.digests().len());
                    let key = chip.select_catalog_key(
                        &mut region,
                        &self.plan.verifier,
                        catalog,
                        self.value(index),
                    )?;
                    chip.verify_pinned(
                        &mut region,
                        &self.plan.verifier,
                        &key,
                        &[scalars.clone()],
                        &proof.messages,
                        &proof.length,
                        VerificationMode::Hard,
                    )?
                } else {
                    let TranscriptRepr::Base(repr) = *self.witness.key.transcript_repr() else {
                        return Err(Error::Synthesis);
                    };
                    let points = |values: &[<Eq as PastaCurve>::AffineExt]| {
                        values
                            .iter()
                            .map(|p| self.value(Eq::from(*p)))
                            .collect::<Vec<_>>()
                    };
                    let key = chip.witness_key(
                        &mut region,
                        self.value(repr),
                        &points(self.witness.key.fixed_commitments()),
                        &points(self.witness.key.permutation_commitments()),
                    )?;
                    chip.verify(
                        &mut region,
                        &self.plan.verifier,
                        &key,
                        &[scalars.clone()],
                        &proof.messages,
                        &proof.length,
                        VerificationMode::Hard,
                    )?
                };
                constrain_allowed_key(
                    chip.uint().glue(),
                    &mut region,
                    &a.key_digest,
                    &self.plan.allowlist,
                )?;
                let words = scalars
                    .iter()
                    .map(|value| value.native_word().cloned().ok_or(Error::Synthesis))
                    .collect::<Result<Vec<_>, _>>()?;
                let part_point = Self::point(&mut chip, &mut region, &words[2..6])?;
                let part = FoldInputCells::from_sigma_part(
                    &mut chip,
                    &mut region,
                    &words[1],
                    part_point,
                    scalars[6..22]
                        .to_vec()
                        .try_into()
                        .map_err(|_| Error::Synthesis)?,
                )?;
                let a_claim = FoldInputCells::from_claim(&mut chip, &mut region, &a.claim)?;
                let predecessor =
                    Self::claim(&mut chip, &mut region, &words[22..26], &scalars[26..42])?;
                let incoming =
                    Self::claim(&mut chip, &mut region, &words[42..46], &scalars[46..62])?;
                let modes: [Word<Fq>; 3] = words[62..65]
                    .to_vec()
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let modes = ModeCells::constrain(chip.uint().glue(), &mut region, &modes)?;
                let corrected = Self::point(&mut chip, &mut region, &words[65..69])?;
                let selected = FoldInputCells::select_incoming(
                    &mut chip,
                    &mut region,
                    &incoming,
                    &corrected,
                    &modes,
                )?;
                let inputs = vec![part, a_claim, predecessor, selected];
                let output = chip.verify_fold(
                    &mut region,
                    &self.plan.fold,
                    &inputs,
                    &fold.messages,
                    &fold.length,
                    VerificationMode::Hard,
                )?;
                let challenges = output
                    .claim
                    .challenges()
                    .iter()
                    .map(|value| value.native_word().cloned().ok_or(Error::Synthesis))
                    .collect::<Result<Vec<_>, _>>()?;
                let output = [
                    vec![words[0].clone()],
                    vec![output.claim.g().x().clone(), output.claim.g().y().clone()],
                    challenges,
                ];
                chip.finish_compact(&mut region)?;
                if let Some(public) = &config.compact_public {
                    public.assign(&mut region, output.each_ref().map(Vec::as_slice))?;
                }
                Ok(output)
            },
        )?;
        if config.compact_public.is_none() {
            for (column, words) in config.public.into_iter().zip(output) {
                for (row, value) in words.into_iter().enumerate() {
                    layouter.constrain_instance(value.cell(), column, row)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "omega/membership_tests.rs"]
mod membership_tests;
