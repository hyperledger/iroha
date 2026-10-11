//! Constrained field bridges, sigma export checks and lineage digest binding.

use ff::Field;
use iroha_pasta::{Ep, Eq, Fp, PastaAffine};
use iroha_plonk::{
    cs::InstanceType,
    frontend::{Error, Region},
    transcript::decode_point,
};
use iroha_plonk_gadgets::{
    Bit, GlueChip, Uint, Word,
    bytes::{element::LeElement, variable::ActiveBytes},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    K, VESTA_TRIVIAL_GENERATOR,
    accumulation_circuit::{FoldInputCells, FoldSource},
    codec::ScalarCells,
    obligation::ModeCells,
    verifier::VerifierChip,
};

use super::{AFramePlan, LINEAGE_DOMAIN, LineagePublicCells};
use crate::{
    operation_relation::{
        incoming_statement::{IncomingStatementCells, StatementView},
        statement::StatementCells,
    },
    q_sigma::QSigmaPlan,
};

#[cfg(test)]
pub(super) mod tests;

/// Constrains a canonical Fq scalar to its injective native Fp subfield encoding.
/// This is the bridge for the Bounded and Bits columns verified by A.
///
/// # Errors
/// Layout errors; an out-of-type value is unsatisfiable, never reduced modulo p.
pub fn bounded_word(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    scalar: &ScalarCells<Ep>,
) -> Result<Word<Fp>, Error> {
    let bounded = scalar.instance_type(&mut chip.uint(), region, InstanceType::Bounded)?;
    GlueChip::assert_constant(region, bounded.word(), Fp::ONE)?;
    chip.uint().glue().linear(
        region,
        &[
            (Fp::ONE, scalar.lo().word()),
            (Fp::from(2).pow_vartime([128]), scalar.hi().word()),
        ],
        Fp::ZERO,
    )
}

/// Foreign Vesta claim carried through A, with canonical coordinates and scalars.
/// Its curve/finite check belongs to the hard Q/Omega source relation and the
/// native Vesta fold in Omega; A preserves the exact canonical coordinate limbs.
#[derive(Clone, Debug)]
pub struct VestaClaimCells {
    source_k: u32,
    coordinates: [ScalarCells<Ep>; 2],
    challenges: [Word<Fp>; K],
}
impl VestaClaimCells {
    /// Totally decodes transported incoming bytes before any soft verification.
    /// The returned bit is mandatory in the incoming branch predicate.
    ///
    /// # Errors
    /// Wrong fixed shape or layout failure.
    pub fn decode_soft(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        messages: &[LeElement<Fp>],
        length: &Uint<Fp, 32>,
    ) -> Result<(Self, Bit<Fp>), Error> {
        let decoded = chip.decode_vesta_accumulator(region, messages, length)?;
        let value = Self::constrain(chip, region, 16, decoded.coordinates, decoded.challenges)?;
        Ok((value, decoded.valid))
    }
    /// Assigns the pinned full-k16 deciding filler, never a missing obligation.
    ///
    /// # Errors
    /// Invalid pinned encoding or layout failure.
    pub fn trivial(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
    ) -> Result<Self, Error> {
        let point = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).map_err(|_| Error::Synthesis)?;
        let (x, y) = Option::from(point.coordinates()).ok_or(Error::Synthesis)?;
        let mut coordinates = Vec::with_capacity(2);
        for value in [x, y] {
            let [lo, hi] = foreign_limbs(&value);
            let lo = chip.uint().constant::<128>(region, lo)?;
            let hi = chip.uint().constant::<127>(region, hi)?;
            coordinates.push(ScalarCells::from_limbs(&mut chip.uint(), region, &lo, &hi)?);
        }
        let one = chip.uint().glue().constant(region, Fp::ONE)?;
        Ok(Self {
            source_k: 16,
            coordinates: coordinates.try_into().map_err(|_| Error::Synthesis)?,
            challenges: core::array::from_fn(|_| one.clone()),
        })
    }
    /// Checks a claim copied from an authenticated recursive public frame.
    /// No accumulator validity is asserted here; the consuming native-curve
    /// fold checks its finite point and retains its generator obligation.
    ///
    /// # Errors
    /// Invalid source metadata/layout; bad padding or zero suffix is unsatisfiable.
    pub fn constrain(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        source_k: u32,
        coordinates: [ScalarCells<Ep>; 2],
        challenges: [Word<Fp>; K],
    ) -> Result<Self, Error> {
        if !(1..=16).contains(&source_k) {
            return Err(Error::Synthesis);
        }
        let prefix = K - source_k as usize;
        for (index, challenge) in challenges.iter().enumerate() {
            if index < prefix {
                GlueChip::assert_constant(region, challenge, Fp::ZERO)?;
            } else {
                let zero = chip.uint().glue().is_zero(region, challenge)?;
                GlueChip::assert_constant(region, zero.word(), Fp::ZERO)?;
            }
        }
        Ok(Self {
            source_k,
            coordinates,
            challenges,
        })
    }
    /// Descriptor-bound source k, before any incoming mode selection.
    pub const fn source_k(&self) -> u32 {
        self.source_k
    }
    /// Canonical foreign x/y coordinate encodings.
    pub const fn coordinates(&self) -> &[ScalarCells<Ep>; 2] {
        &self.coordinates
    }
    /// Native Fp challenge cells, including checked zero prefix when short.
    pub const fn challenges(&self) -> &[Word<Fp>; K] {
        &self.challenges
    }
    /// The exact 20-word public representation, excluding fixed source k.
    pub fn words(&self) -> Vec<Word<Fp>> {
        let mut words = Vec::with_capacity(20);
        for value in &self.coordinates {
            words.extend([value.lo().word().clone(), value.hi().word().clone()]);
        }
        words.extend(self.challenges.iter().cloned());
        words
    }
}

/// One operation-derived sigma statement, key index and exact proof carrier chunks.
/// Each field must be copied from the owning operation and byte-tape relation.
#[derive(Clone, Debug)]
pub struct SigmaBindingCells {
    statement: BoundStatement,
    key_index: Word<Fp>,
    proof_chunks: Vec<Word<Fp>>,
    step_digest: Option<Word<Fp>>,
    carrier_length: Option<usize>,
    active_carrier: Option<ActiveBytes<Fp>>,
}
#[derive(Clone, Debug)]
enum BoundStatement {
    Own(Box<StatementCells>),
    Incoming(Box<IncomingStatementCells>),
}
impl SigmaBindingCells {
    pub(super) const fn key_index(&self) -> &Word<Fp> {
        &self.key_index
    }
    pub(super) fn carrier_length(&self) -> Result<usize, Error> {
        self.carrier_length.ok_or(Error::Synthesis)
    }
    pub(super) fn proof_chunks(&self) -> &[Word<Fp>] {
        &self.proof_chunks
    }
    /// Copies a validated statement, operation-derived selector and byte chunks.
    /// The caller must derive `key_index` from the authenticated operation
    /// controls and `proof_chunks` from the same supplied proof tape.
    pub fn from_statement(
        statement: &StatementCells,
        key_index: Word<Fp>,
        proof_chunks: Vec<Word<Fp>>,
    ) -> Self {
        Self {
            statement: BoundStatement::Own(Box::new(statement.clone())),
            key_index,
            proof_chunks,
            step_digest: None,
            carrier_length: None,
            active_carrier: None,
        }
    }
    /// The statement whose digest is bound to the Q slot.
    pub fn statement(&self) -> &dyn StatementView {
        match &self.statement {
            BoundStatement::Own(statement) => statement.as_ref(),
            BoundStatement::Incoming(statement) => statement.as_ref(),
        }
    }
    /// Hard own statement, unavailable for a total incoming statement.
    ///
    /// # Errors
    /// The binding belongs to an incoming slot.
    pub fn hard_statement(&self) -> Result<&StatementCells, Error> {
        match &self.statement {
            BoundStatement::Own(statement) => Ok(statement),
            BoundStatement::Incoming(_) => Err(Error::Synthesis),
        }
    }
    /// Total incoming statement, unavailable for an own hard slot.
    /// # Errors
    /// The binding belongs to an own slot.
    pub fn incoming_statement(&self) -> Result<&IncomingStatementCells, Error> {
        match &self.statement {
            BoundStatement::Incoming(statement) => Ok(statement),
            BoundStatement::Own(_) => Err(Error::Synthesis),
        }
    }
    /// Copies a total incoming statement and its original proof carrier chunks.
    /// Its semantic validity joins the incoming Q verdict during binding; it is
    /// never asserted hard and its original digest is never replaced by a dummy.
    pub fn from_incoming(
        statement: &IncomingStatementCells,
        key_index: Word<Fp>,
        proof_chunks: Vec<Word<Fp>>,
    ) -> Self {
        Self {
            statement: BoundStatement::Incoming(Box::new(statement.clone())),
            key_index,
            proof_chunks,
            step_digest: None,
            carrier_length: None,
            active_carrier: None,
        }
    }

    /// Bind the exact `LE32 length || sigma` tape and its sigma-only digest.
    /// The primary segments must be the canonical contiguous 31-byte chunks;
    /// a four-byte little-endian secondary segment carries the actual length.
    /// These are the same chunks checked against the hard Q sigma export.
    ///
    /// # Errors
    /// Wrong fixed framing, missing bounded chunks or layout failure. A wrong
    /// actual length is unsatisfiable. Send/Unload/Retiring must separately hash
    /// their complete Omega-plus-sigma carrier instead of this step digest.
    pub fn from_run(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        statement: &StatementCells,
        key_index: Word<Fp>,
        run: &iroha_plonk_gadgets::bytes::tape::ByteRun<Fp>,
    ) -> Result<Self, Error> {
        Self::from_tape(
            chip,
            region,
            BoundStatement::Own(Box::new(statement.clone())),
            key_index,
            run,
        )
    }

    /// Bind an incoming sigma's original length-prefixed tape without making
    /// malformed length or statement semantics hard requirements. The Q soft
    /// verifier and statement verdict must both join the final branch rule.
    /// # Errors
    /// Wrong fixed framing/segments or synthesis failure.
    pub fn from_incoming_run(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        statement: &IncomingStatementCells,
        key_index: Word<Fp>,
        run: &iroha_plonk_gadgets::bytes::tape::ByteRun<Fp>,
    ) -> Result<Self, Error> {
        Self::from_tape(
            chip,
            region,
            BoundStatement::Incoming(Box::new(statement.clone())),
            key_index,
            run,
        )
    }

    /// Fixed decoder segments of an unframed original sigma buffer.
    /// The buffer may be larger; only this prefix is supplied to the fixed Q
    /// verifier, whose length verdict still uses the exact original length.
    /// # Errors
    /// Zero/non-message-aligned capacity or overflow.
    pub fn incoming_segments(
        proof_bytes: usize,
    ) -> Result<Vec<iroha_plonk_gadgets::bytes::SegmentSpec>, Error> {
        use iroha_plonk_gadgets::bytes::SegmentSpec;
        if proof_bytes == 0 || !proof_bytes.is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        u32::try_from(proof_bytes).map_err(|_| Error::BoundsFailure)?;
        Ok((0..proof_bytes)
            .step_by(31)
            .map(|offset| SegmentSpec::little(offset, (proof_bytes - offset).min(31)))
            .collect())
    }

    /// Bind an exact original sigma string to its safe Q view and byte digest.
    ///
    /// Q receives `LE32(actual length)` followed by the descriptor-sized prefix.
    /// A short original is zero padded only for that view; a long original tail
    /// remains in the exact external digest. No decoded witness bit can replace
    /// this provenance. The statement and Q verifier verdicts remain soft.
    /// # Errors
    /// Invalid descriptor capacity, missing fixed segments or synthesis failure.
    pub fn from_incoming_active(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        statement: &IncomingStatementCells,
        key_index: Word<Fp>,
        raw: &ActiveBytes<Fp>,
        proof_bytes: usize,
    ) -> Result<Self, Error> {
        use iroha_plonk_gadgets::{
            UintChip,
            bytes::{BoundedBytes, PBytes},
        };
        if raw.run().len() < proof_bytes {
            return Err(Error::Synthesis);
        }
        let mut fixed = PBytes::new();
        // ActiveBytes owns this UInt32 certificate, so the LE32 bound is exact.
        fixed.push_bounded(
            BoundedBytes::trusted(raw.length().word().clone(), 4).ok_or(Error::Synthesis)?,
        )?;
        for spec in Self::incoming_segments(proof_bytes)? {
            let chunk = raw
                .run()
                .secondary_segment(spec)?
                .bounded()
                .ok_or(Error::Synthesis)?;
            fixed.push_bounded_split(&mut chip.uint(), region, &chunk)?;
        }
        let chunks = fixed
            .chunk_words(chip.uint().glue(), region)?
            .iter()
            .map(|chunk| chunk.word().clone())
            .collect();
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let digest = raw.packed().length_prefixed(&mut uint, region)?.digest(
            &mut uint,
            lanes.hash.sponge_mut()?,
            region,
            u64::from_le_bytes(*b"kgwstep1"),
        )?;
        Ok(Self {
            statement: BoundStatement::Incoming(Box::new(statement.clone())),
            key_index,
            proof_chunks: chunks,
            step_digest: Some(digest),
            carrier_length: Some(proof_bytes.checked_add(4).ok_or(Error::BoundsFailure)?),
            active_carrier: Some(raw.clone()),
        })
    }

    /// Original sigma provenance required by total variable-length consumers.
    /// # Errors
    /// The binding came from a fixed buffer or field/chunk-only constructor.
    pub fn active_carrier(&self) -> Result<&ActiveBytes<Fp>, Error> {
        self.active_carrier.as_ref().ok_or(Error::Synthesis)
    }

    fn from_tape(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        statement: BoundStatement,
        key_index: Word<Fp>,
        run: &iroha_plonk_gadgets::bytes::tape::ByteRun<Fp>,
    ) -> Result<Self, Error> {
        use iroha_plonk_gadgets::{
            UintChip,
            bytes::{PBytes, tape::SegmentSpec},
        };
        let body = run.len().checked_sub(4).ok_or(Error::Synthesis)?;
        if body == 0 || !body.is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        let length = chip.uint().range_check::<32>(
            region,
            run.secondary_segment(SegmentSpec::little(0, 4))?.word(),
        )?;
        if matches!(statement, BoundStatement::Own(_)) {
            GlueChip::assert_constant(
                region,
                length.word(),
                Fp::from(u64::try_from(body).map_err(|_| Error::BoundsFailure)?),
            )?;
        }
        let mut bytes = PBytes::new();
        let mut chunks = Vec::new();
        let mut offset = 0;
        for segment in run.primary() {
            let expected = (run.len() - offset).min(31);
            if segment.spec() != SegmentSpec::little(offset, expected) {
                return Err(Error::Synthesis);
            }
            bytes.push_bounded(segment.bounded().ok_or(Error::Synthesis)?)?;
            chunks.push(segment.word().clone());
            offset += expected;
        }
        if bytes.len() != run.len() {
            return Err(Error::Synthesis);
        }
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let digest = bytes.digest(
            uint.glue(),
            lanes.hash,
            region,
            u64::from_le_bytes(*b"kgwstep1"),
        )?;
        Ok(Self {
            statement,
            key_index,
            proof_chunks: chunks,
            step_digest: Some(digest),
            carrier_length: Some(run.len()),
            active_carrier: None,
        })
    }

    /// Same-tape sigma-only receipt digest, available after either tape constructor.
    ///
    /// # Errors
    /// The binding was constructed without an authenticated digest tape.
    pub fn step_digest(&self) -> Result<&Word<Fp>, Error> {
        self.step_digest.as_ref().ok_or(Error::Synthesis)
    }
}

/// Bound sigma leaf exports, whose own obligations remain hard.
#[derive(Clone, Debug)]
pub struct BoundSigmaCells {
    /// Authenticated Q part, forwarded unchanged to the Vesta fold in Omega.
    pub part: VestaClaimCells,
    /// Incoming sigma verification AND original statement validity, when present.
    /// Computed statement/index bindings are hard equalities, never soft failures.
    pub incoming_valid: Option<Bit<Fp>>,
    /// The same incoming mode cells committed by Q's instances.
    pub incoming_mode: Option<ModeCells<Fp>>,
}

// bind_sigma consumes the exact QSigmaPlan five-column frame. It is either
// already hard-verified, or committed in a predecessor-first A1 context whose
// mandatory A2 continuation hard-verifies these identical canonical S6 cells.
// That complete relation proves Bounded/Bits membership, so recomposition is
// injective in Fp without a duplicate comparison. A1/W alone cannot accept a
// lineage or authenticate a deferred Q frame.
fn verified_bounded_word(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    scalar: &ScalarCells<Ep>,
) -> Result<Word<Fp>, Error> {
    chip.uint().glue().linear(
        region,
        &[
            (Fp::ONE, scalar.lo().word()),
            (Fp::from(2).pow_vartime([128]), scalar.hi().word()),
        ],
        Fp::ZERO,
    )
}

/// Links every `Q_sigma` public value to its operation and supplied byte tape.
/// Private to A: callers pass cells hard-verified using the fixed five-column
/// types, or context-committed cells whose identical values must be verified by
/// the continuation before it can close. An intermediate A1/W is not accepted.
/// The statement's original semantic verdict and incoming proof verdict stay
/// soft. Computed statement digests, deterministic selectors and chunk bindings
/// are hard: selecting different verifier inputs cannot justify a burn.
///
/// # Errors
/// Fixed metadata/shape mismatch or layout errors.
pub(super) fn bind_sigma(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &QSigmaPlan,
    instances: &[Vec<ScalarCells<Ep>>],
    bindings: &[SigmaBindingCells],
) -> Result<BoundSigmaCells, Error> {
    if instances.len() != 5
        || bindings.len() != plan.slot_count()
        || instances
            .iter()
            .zip(plan.instance_lengths())
            .any(|(column, len)| column.len() != len)
    {
        return Err(Error::Synthesis);
    }
    let mut incoming_valid = None;
    for (slot, binding) in bindings.iter().enumerate() {
        if (slot == 0) != matches!(binding.statement, BoundStatement::Own(_)) {
            return Err(Error::Synthesis);
        }
        let digest = binding.statement().digest();
        let actual = verified_bounded_word(chip, region, &instances[0][slot])?;
        let digest_matches = chip.uint().glue().is_equal(region, digest, &actual)?;
        let index = verified_bounded_word(chip, region, &instances[2][slot])?;
        let index_matches = chip
            .uint()
            .glue()
            .is_equal(region, &index, &binding.key_index)?;
        let verdict = verified_bounded_word(chip, region, &instances[3][slot])?;
        let verdict = chip.uint().glue().assert_bool(region, &verdict)?;
        let both = chip
            .uint()
            .glue()
            .and(region, &digest_matches, &index_matches)?;
        let valid = chip.uint().glue().and(region, &both, &verdict)?;
        if slot == 0 {
            GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        } else {
            let BoundStatement::Incoming(statement) = &binding.statement else {
                return Err(Error::Synthesis);
            };
            // These values are derived verifier inputs, not malformed original
            // bytes. Otherwise a prover could verify a valid sigma against a
            // different digest/key and manufacture a false verdict for burn.
            GlueChip::assert_constant(region, digest_matches.word(), Fp::ONE)?;
            GlueChip::assert_constant(region, index_matches.word(), Fp::ONE)?;
            incoming_valid = Some(chip.uint().glue().and(region, &valid, statement.valid())?);
        }
        let chunks = plan.chunk_range(slot).ok_or(Error::Synthesis)?;
        if chunks.len() != binding.proof_chunks.len() {
            return Err(Error::Synthesis);
        }
        for (index, expected) in chunks.zip(&binding.proof_chunks) {
            let actual = verified_bounded_word(chip, region, &instances[0][index])?;
            GlueChip::assert_equal(region, &actual, expected)?;
        }
    }
    let incoming_mode = if plan.slot_count() == 2 {
        let mut modes = Vec::with_capacity(3);
        for scalar in &instances[3][2..5] {
            modes.push(verified_bounded_word(chip, region, scalar)?);
        }
        Some(ModeCells::constrain(
            chip.uint().glue(),
            region,
            &modes.try_into().map_err(|_| Error::Synthesis)?,
        )?)
    } else {
        None
    };
    let source = verified_bounded_word(chip, region, &instances[4][0])?;
    GlueChip::assert_constant(region, &source, Fp::from(u64::from(plan.part_source_k())))?;
    let mut challenges = Vec::with_capacity(K);
    for index in plan.challenge_range() {
        challenges.push(verified_bounded_word(chip, region, &instances[0][index])?);
    }
    let part = VestaClaimCells::constrain(
        chip,
        region,
        plan.part_source_k(),
        [instances[1][0].clone(), instances[1][1].clone()],
        challenges.try_into().map_err(|_| Error::Synthesis)?,
    )?;
    Ok(BoundSigmaCells {
        part,
        incoming_valid,
        incoming_mode,
    })
}

/// Computes the exact 52-word `D_A` from checked lineage fields and Pallas claim.
///
/// # Errors
/// Non-k16 claim metadata or layout errors.
pub fn lineage_digest(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    public: &LineagePublicCells,
    accumulator: &FoldInputCells<Ep>,
) -> Result<Word<Fp>, Error> {
    lineage_digest_fields(chip, region, public.fields(), accumulator)
}
pub(super) fn lineage_digest_fields(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    fields: &[Word<Fp>; super::LINEAGE_FIELDS],
    accumulator: &FoldInputCells<Ep>,
) -> Result<Word<Fp>, Error> {
    if accumulator.source() != FoldSource::Fixed(16) {
        return Err(Error::Synthesis);
    }
    GlueChip::assert_constant(region, accumulator.source_k(), Fp::from(16))?;
    let mut words = fields.to_vec();
    words.extend([accumulator.g().x().clone(), accumulator.g().y().clone()]);
    for scalar in accumulator.challenges() {
        words.extend([scalar.lo().word().clone(), scalar.hi().word().clone()]);
    }
    chip.hash_words(region, LINEAGE_DOMAIN, &words)
}

/// A's typed output before final public-column exposure.
#[derive(Clone, Debug)]
pub struct AOutputCells {
    /// Complete lineage digest including the output Pallas obligation.
    pub digest: Word<Fp>,
    /// Hard sigma part, retaining its source descriptor k.
    pub sigma_part: VestaClaimCells,
    /// Hard predecessor Vesta accumulator, absent exactly for Bootstrap.
    pub predecessor: Option<VestaClaimCells>,
    /// Incoming original Vesta claim and mode/correction, in gated variants only.
    pub incoming: Option<IncomingVestaCells>,
}

/// Incoming Vesta data carried unchanged to Omega's native-curve mode selector.
#[derive(Clone, Debug)]
pub struct IncomingVestaCells {
    /// Checked full-length original or total-decoder dummy.
    pub claim: VestaClaimCells,
    /// Same modes included in A's global incoming-mode constraint.
    pub mode: ModeCells<Fp>,
    /// Canonical corrected coordinates, finite/different checked by Omega.
    pub corrected: [ScalarCells<Ep>; 2],
}
impl AOutputCells {
    /// Constrains metadata and returns the exact single-column A frame.
    ///
    /// # Errors
    /// A missing/extra slot, wrong source metadata or layout failure.
    pub fn words(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: AFramePlan,
    ) -> Result<Vec<Word<Fp>>, Error> {
        self.words_with_source(chip, region, plan, plan.part_source_k())
    }
    pub(super) fn words_with_source(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: AFramePlan,
        source_k: u32,
    ) -> Result<Vec<Word<Fp>>, Error> {
        if self.sigma_part.source_k() != source_k
            || self.predecessor.is_some() != plan.has_predecessor()
            || self.incoming.is_some() != plan.has_incoming()
            || self
                .predecessor
                .as_ref()
                .is_some_and(|p| p.source_k() != 16)
            || self
                .incoming
                .as_ref()
                .is_some_and(|p| p.claim.source_k() != 16)
        {
            return Err(Error::Synthesis);
        }
        let source = chip
            .uint()
            .glue()
            .constant(region, Fp::from(u64::from(source_k)))?;
        let mut words = vec![self.digest.clone(), source];
        words.extend(self.sigma_part.words());
        let trivial = VestaClaimCells::trivial(chip, region)?;
        if let Some(pred) = &self.predecessor {
            words.extend(pred.words());
        } else {
            words.extend(trivial.words());
        }
        if let Some(incoming) = &self.incoming {
            words.extend(incoming.claim.words());
            words.extend([
                incoming.mode.accept().word().clone(),
                incoming.mode.trivial().word().clone(),
                incoming.mode.corrected().word().clone(),
            ]);
            for coordinate in &incoming.corrected {
                words.extend([
                    coordinate.lo().word().clone(),
                    coordinate.hi().word().clone(),
                ]);
            }
        } else {
            words.extend(trivial.words());
            for bit in [0, 1, 0] {
                words.push(chip.uint().glue().constant(region, Fp::from(bit))?);
            }
            for coordinate in trivial.coordinates() {
                words.extend([
                    coordinate.lo().word().clone(),
                    coordinate.hi().word().clone(),
                ]);
            }
        }
        Ok(words)
    }
}
