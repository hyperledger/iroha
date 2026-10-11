//! Total incoming lineage prefix with an exact original digest and safe view.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, Uint, UintChip, Word,
    bytes::{
        element::{LeElement, decode_le_element, scalar_bytes_canonical},
        tape::{ByteRun, SegmentSpec},
        variable::ActiveBytes,
    },
};

use super::{LINEAGE_FIELDS, LineagePublicCells};

/// Decoded incoming prefix and a fixed valid dummy for bounded operations.
///
/// The verifier hashes `fields`, never the whole-header dummy, and joins
/// `valid` internally. The byte decoder zero-selects noncanonical Fp atoms
/// before placing them in `fields`; an exact byte digest must hash its retained
/// original carrier. The lower-level field constructor carries no byte
/// provenance and cannot by itself establish an admitted incoming object.
#[derive(Clone, Debug)]
pub struct IncomingLineageCells {
    fields: [Word<Fp>; LINEAGE_FIELDS],
    checked: LineagePublicCells,
    valid: Bit<Fp>,
    carrier: Option<ByteRun<Fp>>,
}
impl IncomingLineageCells {
    /// Decode the public prefix of one exact incoming lineage carrier.
    ///
    /// `run` is `LE32 length || public320 || proof || accP || accV`, with the
    /// secondary segments from `ConsumingProofCells::omega_segments`. The
    /// whole carrier length, version, canonical Fp atoms and SEC1 prefix all
    /// join the returned validity. Invalid Fp atoms select zero before use;
    /// their original bytes remain in `run` and must enter the consumer digest.
    /// The Omega-key digest is a pinned relation input, absent from public320.
    ///
    /// This does not decode the proof or accumulators. Their total decoders
    /// must consume the remaining bytes of this same carrier before verification.
    /// # Errors
    /// Invalid fixed descriptor length/segment layout or synthesis failure.
    pub fn from_run(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        proof_bytes: usize,
        omega_key_digest: &Word<Fp>,
    ) -> Result<Self, Error> {
        use super::own::ConsumingProofCells;
        let total = proof_bytes
            .checked_add(ConsumingProofCells::PUBLIC_BYTES)
            .and_then(|n| n.checked_add(2 * iroha_plonk_recursion::ACCUMULATOR_BYTES))
            .ok_or(Error::BoundsFailure)?;
        if proof_bytes == 0
            || !proof_bytes.is_multiple_of(32)
            || total.checked_add(4) != Some(run.len())
        {
            return Err(Error::Synthesis);
        }
        let declared = uint.range_check::<32>(
            region,
            run.secondary_segment(SegmentSpec::little(0, 4))?.word(),
        )?;
        Self::from_view(uint, region, run, 4, total, &declared, omega_key_digest)
    }

    /// Decode an original unframed bounded byte string, preserving its length.
    ///
    /// The raw buffer may exceed the selected descriptor's capacity, so an
    /// overlong original remains representable and returns false. A short
    /// original uses constrained zero padding only for safe fixed-offset views.
    /// Its external digest must use `raw.packed()`, never those safe views.
    /// Secondary segments are the usual carrier segments shifted left by four.
    /// # Errors
    /// Invalid descriptor/capacity/segment layout or synthesis failure.
    pub fn from_active(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        raw: &ActiveBytes<Fp>,
        proof_bytes: usize,
        omega_key_digest: &Word<Fp>,
    ) -> Result<Self, Error> {
        let total = proof_bytes
            .checked_add(super::own::ConsumingProofCells::PUBLIC_BYTES)
            .and_then(|n| n.checked_add(2 * iroha_plonk_recursion::ACCUMULATOR_BYTES))
            .ok_or(Error::BoundsFailure)?;
        if proof_bytes == 0 || !proof_bytes.is_multiple_of(32) || raw.run().len() < total {
            return Err(Error::Synthesis);
        }
        Self::from_view(
            uint,
            region,
            raw.run(),
            0,
            total,
            raw.length(),
            omega_key_digest,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one validator serves framed diagnostics and exact active original views"
    )]
    fn from_view(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        start: usize,
        total: usize,
        declared: &Uint<Fp, 32>,
        omega_key_digest: &Word<Fp>,
    ) -> Result<Self, Error> {
        let at = |offset, bytes| {
            run.secondary_segment(SegmentSpec::little(start + offset, bytes))
                .map(iroha_plonk_gadgets::bytes::Segment::word)
        };
        let total = u32::try_from(total).map_err(|_| Error::BoundsFailure)?;
        let expected = uint.constant::<32>(region, u128::from(total))?;
        let mut valid = uint
            .glue()
            .is_equal(region, declared.word(), expected.word())?;
        let zero = uint.glue().constant(region, Fp::ZERO)?;
        let mut fields = core::array::from_fn(|_| zero.clone());
        fields[0] = at(0, 2)?.clone();
        for (offset, index) in [(2, 1), (34, 3), (98, 6)] {
            for limb in 0..2 {
                fields[index + limb] = at(offset + 16 * limb, 16)?.clone();
            }
        }
        for (offset, index) in [(66, 5), (130, 8), (256, 15), (288, 16)] {
            let element = decode_le_element(uint, region, run, start + offset)?;
            let canonical = scalar_bytes_canonical::<Fp, Fp>(uint, region, &element)?;
            valid = uint.glue().and(region, &valid, &canonical)?;
            let residue = uint.glue().linear(
                region,
                &[
                    (Fp::ONE, element.lo().word()),
                    (Fp::from(2).pow_vartime([128]), element.hi().word()),
                ],
                Fp::ZERO,
            )?;
            fields[index] = uint.glue().select(region, &canonical, &residue, &zero)?;
        }
        let prefix = uint.glue().constant(region, Fp::from(4))?;
        let prefix_valid = uint.glue().is_equal(region, at(162, 1)?, &prefix)?;
        valid = uint.glue().and(region, &valid, &prefix_valid)?;
        for (limb, index) in [10, 9, 12, 11].into_iter().enumerate() {
            fields[index] = run
                .secondary_segment(SegmentSpec::big(start + 163 + 16 * limb, 16))?
                .word()
                .clone();
        }
        fields[13] = uint.glue().linear(
            region,
            &[
                (Fp::ONE, at(227, 1)?),
                (Fp::from(2).pow_vartime([8]), at(228, 8)?),
                (Fp::from(2).pow_vartime([72]), at(236, 4)?),
            ],
            Fp::ZERO,
        )?;
        fields[14] = at(240, 16)?.clone();
        fields[17] = omega_key_digest.clone();
        let mut decoded = Self::constrain(uint, region, &fields, &valid)?;
        decoded.carrier = Some(run.clone());
        Ok(decoded)
    }

    /// Check the hard prefix's exact version/width rules as a total predicate.
    ///
    /// `encoding_valid` is the mandatory verdict of the same-tape original
    /// byte decoder, including canonical-field encoding and framing/length.
    /// The supplied decoded fields remain unchanged in every proof/context
    /// digest. This lower-level constructor does not retain or certify a byte
    /// carrier, even if the caller supplies an encoding bit equal to true.
    /// After any failure, `checked` is fixed to `[1, 0, ..., 0]` before hard
    /// range checks. This view is arithmetic-safe, not an authenticated state.
    ///
    /// # Errors
    /// Layout failure; invalid version/width/encoding returns a false bit.
    pub fn constrain(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        fields: &[Word<Fp>; LINEAGE_FIELDS],
        encoding_valid: &Bit<Fp>,
    ) -> Result<Self, Error> {
        let one = uint.glue().constant(region, Fp::ONE)?;
        let version = uint.glue().is_equal(region, &fields[0], &one)?;
        let mut valid = uint.glue().and(region, encoding_valid, &version)?;
        for index in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 13, 14] {
            let element =
                LeElement::assign(uint, region, fields[index].value().map(|v| v.to_repr()))?;
            let canonical = scalar_bytes_canonical::<Fp, Fp>(uint, region, &element)?;
            GlueChip::assert_constant(region, canonical.word(), Fp::ONE)?;
            let joined = uint.glue().linear(
                region,
                &[
                    (Fp::ONE, element.lo().word()),
                    (Fp::from(2).pow_vartime([128]), element.hi().word()),
                ],
                Fp::ZERO,
            )?;
            GlueChip::assert_equal(region, &joined, &fields[index])?;
            let mut fits = uint.glue().is_zero(region, element.hi().word())?;
            if index == 13 {
                let low = uint.assign::<104>(
                    region,
                    element.lo().value().map(|v| v & ((1u128 << 104) - 1)),
                )?;
                let high = uint.assign::<24>(region, element.lo().value().map(|v| v >> 104))?;
                let joined = uint.glue().linear(
                    region,
                    &[
                        (Fp::ONE, low.word()),
                        (Fp::from_u128(1u128 << 104), high.word()),
                    ],
                    Fp::ZERO,
                )?;
                GlueChip::assert_equal(region, &joined, element.lo().word())?;
                let clear = uint.glue().is_zero(region, high.word())?;
                fits = uint.glue().and(region, &fits, &clear)?;
            }
            valid = uint.glue().and(region, &valid, &fits)?;
        }
        let zero = uint.glue().constant(region, Fp::ZERO)?;
        let safe = fields
            .iter()
            .enumerate()
            .map(|(i, field)| {
                uint.glue()
                    .select(region, &valid, field, if i == 0 { &one } else { &zero })
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let checked = LineagePublicCells::constrain(uint, region, &safe)?;
        Ok(Self {
            fields: fields.clone(),
            checked,
            valid,
            carrier: None,
        })
    }
    /// Decoded canonical-field prefix, including on a false verdict. A malformed
    /// Fp atom from [`Self::from_run`] is zero; the original bytes remain in
    /// [`Self::carrier`] and must be used for the external byte digest.
    pub const fn fields(&self) -> &[Word<Fp>; LINEAGE_FIELDS] {
        &self.fields
    }
    /// Total encoding/version/width validity, required by the soft verifier.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
    /// Same-source padded carrier retained by either byte constructor.
    /// A typed incoming consumer must require this provenance and decode the
    /// proof/accumulators and compute its byte digest from this same run.
    /// # Errors
    /// The prefix was constructed from fields without a same-tape decoder.
    pub fn carrier(&self) -> Result<&ByteRun<Fp>, Error> {
        self.carrier.as_ref().ok_or(Error::Synthesis)
    }
    /// Hard-valid bounded arithmetic view, fixed to the dummy after failure.
    pub const fn checked(&self) -> &LineagePublicCells {
        &self.checked
    }
    /// Original carried Omega digest, not the selected dummy's digest.
    pub const fn omega_key_digest(&self) -> &Word<Fp> {
        &self.fields[17]
    }
}
