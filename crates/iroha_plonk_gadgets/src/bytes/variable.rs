//! Exact bounded variable-length byte strings, concatenation and `P_bytes`.
//!
//! Circuit-fixed capacities determine every row. Witness lengths determine
//! constrained active prefixes, never the layout. Raw tapes use canonical zero
//! padding; only active original bytes enter the digest. Concatenation shifts
//! packed words before merging, so padding never appears between sources.

use iroha_pasta::{PastaField, poseidon::PoseidonField};
use iroha_plonk::frontend::{Error, Region, Value};

use super::{
    BoundedBytes, ByteOrder, ByteRun, BytesChip, CHUNK_BYTES, SegmentSpec, byte_power,
    chunk_segments, field_le_bytes, split_bounded,
};
use crate::{
    Bit, GlueChip, SpongeChip, Uint, UintChip, Word,
    poseidon::{Absorb, AbsorbInput, raw_initial_state},
};

/// An original bounded byte tape with a constrained active length.
///
/// The tape is retained for same-source decoder projections. Its inactive
/// suffix is exactly zero, and `packed()` hashes only its active prefix.
#[derive(Clone, Debug)]
pub struct ActiveBytes<F: PastaField> {
    run: ByteRun<F>,
    packed: VariablePBytes<F>,
}

/// Packed active bytes with an exact length and fixed maximum capacity.
///
/// Private fields preserve chunk bounds and zero inactive suffixes across
/// construction, framing and concatenation. A decoder uses [`ActiveBytes`]'s
/// original tape; this type makes no claim of semantic message validity.
#[derive(Clone, Debug)]
pub struct VariablePBytes<F: PastaField> {
    length: Uint<F, 32>,
    capacity: usize,
    chunks: Vec<BoundedBytes<F>>,
}

struct LengthParts<F: PastaField> {
    whole: Uint<F, 32>,
    remainder: Uint<F, 8>,
    chunks: Uint<F, 32>,
}
fn length_parts<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    length: &Uint<F, 32>,
    capacity: usize,
) -> Result<LengthParts<F>, Error> {
    let cap = u32::try_from(capacity).map_err(|_| Error::BoundsFailure)?;
    let limit = uint.constant::<32>(region, u128::from(cap))?;
    uint.assert_le(region, length, &limit)?;
    let whole = uint.assign::<32>(region, length.value().map(|n| n / 31))?;
    let remainder = uint.assign::<8>(region, length.value().map(|n| n % 31))?;
    let radix = uint.constant::<8>(region, 31)?;
    uint.assert_lt(region, &remainder, &radix)?;
    let joined = uint.glue().linear(
        region,
        &[(F::from(31), whole.word()), (F::ONE, remainder.word())],
        F::ZERO,
    )?;
    GlueChip::assert_equal(region, &joined, length.word())?;
    let no_remainder = uint.glue().is_zero(region, remainder.word())?;
    let has_remainder = uint.glue().not(region, &no_remainder)?;
    let count = uint
        .glue()
        .add(region, whole.word(), has_remainder.word())?;
    // This addition is below 2^32 because length<=u32::MAX and radix=31.
    let chunks = Uint::new(count);
    Ok(LengthParts {
        whole,
        remainder,
        chunks,
    })
}
fn sum<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    words: &[Word<F>],
) -> Result<Word<F>, Error> {
    let mut total = glue.constant(region, F::ZERO)?;
    for pair in words.chunks(2) {
        let mut terms = vec![(F::ONE, &total)];
        terms.extend(pair.iter().map(|word| (F::ONE, word)));
        total = glue.linear(region, &terms, F::ZERO)?;
    }
    Ok(total)
}
fn prefix<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    count: &Uint<F, 32>,
    capacity: usize,
) -> Result<Vec<Bit<F>>, Error> {
    let mut bits = Vec::with_capacity(capacity);
    for index in 0..capacity {
        let bit = glue.boolean(region, count.value().map(|n| (index as u128) < n))?;
        if let Some(previous) = bits.last() {
            let linked = glue.mul(region, bit.word(), Bit::word(previous))?;
            GlueChip::assert_equal(region, &linked, bit.word())?;
        }
        bits.push(bit);
    }
    let total = sum(
        glue,
        region,
        &bits
            .iter()
            .map(|bit| bit.word().clone())
            .collect::<Vec<_>>(),
    )?;
    GlueChip::assert_equal(region, &total, count.word())?;
    Ok(bits)
}
fn bits<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    word: &Word<F>,
    value: Value<u128>,
    count: usize,
) -> Result<Vec<Bit<F>>, Error> {
    let mut result = Vec::with_capacity(count);
    let mut terms = Vec::with_capacity(count);
    for index in 0..count {
        let bit = glue.boolean(region, value.map(|n| ((n >> index) & 1) != 0))?;
        terms.push(glue.linear(
            region,
            &[(F::from_u128(1u128 << index), bit.word())],
            F::ZERO,
        )?);
        result.push(bit);
    }
    let joined = sum(glue, region, &terms)?;
    GlueChip::assert_equal(region, &joined, word)?;
    Ok(result)
}

impl<F: PastaField> ActiveBytes<F> {
    /// Assign an original byte vector into a fixed-capacity tape.
    ///
    /// Secondary segments are fixed decoder views of this same tape. A known
    /// vector longer than the capacity fails; unknown vectors keep the same
    /// layout as every admitted length, including zero.
    /// # Errors
    /// Capacity outside u32, oversized input, bad tape layout or synthesis.
    pub fn assign(
        uint: &mut UintChip<'_, F>,
        bytes: &mut BytesChip<F>,
        region: &mut Region<'_, F>,
        capacity: usize,
        raw: &Value<Vec<u8>>,
        secondary: &[SegmentSpec],
    ) -> Result<Self, Error> {
        u32::try_from(capacity).map_err(|_| Error::BoundsFailure)?;
        raw.error_if_known_and(|value| value.len() > capacity)?;
        let length = uint.assign::<32>(region, raw.as_ref().map(|value| value.len() as u128))?;
        let padded = (0..capacity)
            .map(|i| raw.as_ref().map(|v| v.get(i).copied().unwrap_or(0)))
            .collect::<Vec<_>>();
        let run = bytes.run(region, &padded, &chunk_segments(0, capacity), secondary)?;
        Self::from_run(uint, bytes, region, run, length)
    }
    /// Bind a fixed tape and a constrained actual byte length.
    ///
    /// Primary segments must be exact 31-byte chunks from offset zero. The
    /// caller binds `length` to the original carrier's framing; this method
    /// proves the bounded prefix and zero padding, not an external I/O claim.
    /// # Errors
    /// Wrong primary segmentation, over-capacity length or synthesis.
    pub fn from_run(
        uint: &mut UintChip<'_, F>,
        bytes: &mut BytesChip<F>,
        region: &mut Region<'_, F>,
        run: ByteRun<F>,
        length: Uint<F, 32>,
    ) -> Result<Self, Error> {
        let capacity = run.len();
        let expected = chunk_segments(0, capacity);
        if run.primary().len() != expected.len() {
            return Err(Error::Synthesis);
        }
        let mut start = 0;
        for (segment, len) in run.primary().iter().zip(expected) {
            if segment.spec()
                != (SegmentSpec {
                    start,
                    len,
                    order: ByteOrder::Little,
                })
            {
                return Err(Error::Synthesis);
            }
            start += len;
        }
        let parts = length_parts(uint, region, &length, capacity)?;
        let active = prefix(uint.glue(), region, &parts.chunks, run.primary().len())?;
        let zero = uint.glue().constant(region, F::ZERO)?;
        let mut selected = Vec::with_capacity(active.len());
        let mut chunks = Vec::with_capacity(active.len());
        for (index, (segment, bit)) in run.primary().iter().zip(&active).enumerate() {
            let word = segment.word();
            let kept = uint.glue().mul(region, bit.word(), word)?;
            GlueChip::assert_equal(region, &kept, word)?;
            let next = active.get(index + 1).map_or(&zero, Bit::word);
            let end = uint.glue().sub(region, bit.word(), next)?;
            selected.push(uint.glue().mul(region, &end, word)?);
            // A shorter capacity-tail segment is also bounded by31 bytes.
            chunks.push(BoundedBytes::new(word.clone(), CHUNK_BYTES));
        }
        let last = sum(uint.glue(), region, &selected)?;
        let last_bytes = (0..31)
            .map(|i| last.value().map(|v| field_le_bytes(&v)[i]))
            .collect::<Vec<_>>();
        let last_run = bytes.run(
            region,
            &last_bytes,
            &[31],
            &(0..31)
                .map(|i| SegmentSpec::little(i, 1))
                .collect::<Vec<_>>(),
        )?;
        GlueChip::assert_equal(region, last_run.primary()[0].word(), &last)?;
        let rem_zero = uint.glue().is_zero(region, parts.remainder.word())?;
        let full_tail = uint.glue().constant(region, F::from(31))?;
        let tail = uint
            .glue()
            .select_constant(region, &rem_zero, &full_tail, F::ZERO)?;
        let tail = uint.glue().add(region, &tail, parts.remainder.word())?;
        let tail = Uint::<F, 32>::new(tail);
        let suffix = prefix(uint.glue(), region, &tail, 31)?;
        for (index, bit) in suffix.iter().enumerate() {
            let byte = last_run
                .secondary_segment(SegmentSpec::little(index, 1))?
                .word();
            let kept = uint.glue().mul(region, bit.word(), byte)?;
            GlueChip::assert_equal(region, &kept, byte)?;
        }
        Ok(Self {
            run,
            packed: VariablePBytes {
                length,
                capacity,
                chunks,
            },
        })
    }
    /// Original zero-padded tape for same-source fixed-offset decoder views.
    pub const fn run(&self) -> &ByteRun<F> {
        &self.run
    }
    /// Exact active length, including when a semantic decoder returns false.
    pub const fn length(&self) -> &Uint<F, 32> {
        &self.packed.length
    }
    /// Packed active original bytes, with no decoder substitution.
    pub const fn packed(&self) -> &VariablePBytes<F> {
        &self.packed
    }
}

/// Shift a vector of full bounded chunks left by a fixed number of bytes.
/// The returned vector has the same capacity; its discarded high fragment
/// is returned separately so a caller can prove it is inactive.
fn shift_bytes<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    chunks: &[BoundedBytes<F>],
    shift: usize,
) -> Result<(Vec<BoundedBytes<F>>, Word<F>), Error> {
    if !(1..31).contains(&shift) {
        return Err(Error::Synthesis);
    }
    let mut carry = uint.glue().constant(region, F::ZERO)?;
    let mut shifted = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let (low, high) = split_bounded(uint, region, chunk, 31 - shift)?;
        let value = uint.glue().linear(
            region,
            &[(byte_power::<F>(shift), low.word()), (F::ONE, &carry)],
            F::ZERO,
        )?;
        // The two bounded pieces occupy disjoint byte positions.
        shifted.push(BoundedBytes::new(value, 31));
        carry = high.word().clone();
    }
    Ok((shifted, carry))
}
impl<F: PastaField> VariablePBytes<F> {
    /// Circuit-fixed maximum number of active bytes.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
    /// Exact constrained number of active bytes.
    pub const fn length(&self) -> &Uint<F, 32> {
        &self.length
    }
    /// Prepend the exact LE32 active byte length, excluding capacity padding.
    /// # Errors
    /// Capacity overflow, length overflow or synthesis.
    pub fn length_prefixed(
        &self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
    ) -> Result<Self, Error> {
        let capacity = self.capacity.checked_add(4).ok_or(Error::BoundsFailure)?;
        u32::try_from(capacity).map_err(|_| Error::BoundsFailure)?;
        let length = uint.checked_add_constant(region, &self.length, 4)?;
        let zero = uint.glue().constant(region, F::ZERO)?;
        let mut source = self.chunks.clone();
        source.resize(capacity.div_ceil(31), BoundedBytes::new(zero, 31));
        let (mut chunks, carry) = shift_bytes(uint, region, &source, 4)?;
        GlueChip::assert_constant(region, &carry, F::ZERO)?;
        chunks[0] = BoundedBytes::new(
            uint.glue()
                .add(region, chunks[0].word(), self.length.word())?,
            31,
        );
        Ok(Self {
            length,
            capacity,
            chunks,
        })
    }
    /// Concatenate active original bytes without an intervening padded suffix.
    /// # Errors
    /// Combined capacity/length overflow, bad layout or synthesis.
    pub fn concat(
        &self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        right: &Self,
    ) -> Result<Self, Error> {
        let capacity = self
            .capacity
            .checked_add(right.capacity)
            .ok_or(Error::BoundsFailure)?;
        u32::try_from(capacity).map_err(|_| Error::BoundsFailure)?;
        let length = uint.checked_add(region, &self.length, &right.length)?;
        let parts = length_parts(uint, region, &self.length, self.capacity)?;
        let remainder = bits(
            uint.glue(),
            region,
            parts.remainder.word(),
            parts.remainder.value(),
            5,
        )?;
        let zero = uint.glue().constant(region, F::ZERO)?;
        let mut shifted = right.chunks.clone();
        shifted.push(BoundedBytes::new(zero.clone(), 31));
        for (index, bit) in remainder.iter().enumerate() {
            let (candidate, carry) = shift_bytes(uint, region, &shifted, 1 << index)?;
            let lost = uint.glue().mul(region, bit.word(), &carry)?;
            GlueChip::assert_constant(region, &lost, F::ZERO)?;
            shifted = shifted
                .iter()
                .zip(candidate)
                .map(|(old, new)| {
                    uint.glue()
                        .select(region, bit, new.word(), old.word())
                        .map(|word| BoundedBytes::new(word, 31))
                })
                .collect::<Result<_, _>>()?;
        }
        let count = capacity.div_ceil(31);
        for extra in shifted.iter().skip(count) {
            GlueChip::assert_constant(region, extra.word(), F::ZERO)?;
        }
        shifted.truncate(count);
        shifted.resize(count, BoundedBytes::new(zero.clone(), 31));
        let max_whole = u32::try_from(self.capacity / 31).map_err(|_| Error::BoundsFailure)?;
        let count_bits = (32 - max_whole.leading_zeros()).max(1) as usize;
        let whole = bits(
            uint.glue(),
            region,
            parts.whole.word(),
            parts.whole.value(),
            count_bits,
        )?;
        for (index, bit) in whole.iter().enumerate() {
            let offset = 1usize << index;
            for lost in shifted.iter().skip(count.saturating_sub(offset)) {
                let lost = uint.glue().mul(region, bit.word(), lost.word())?;
                GlueChip::assert_constant(region, &lost, F::ZERO)?;
            }
            shifted = (0..count)
                .map(|i| {
                    let moved = i.checked_sub(offset).map_or(&zero, |j| shifted[j].word());
                    uint.glue()
                        .select(region, bit, moved, shifted[i].word())
                        .map(|word| BoundedBytes::new(word, 31))
                })
                .collect::<Result<_, _>>()?;
        }
        let chunks = (0..count)
            .map(|i| {
                let left = self.chunks.get(i).map_or(&zero, BoundedBytes::word);
                let merged = uint.glue().add(region, left, shifted[i].word())?;
                uint.range().range_check(region, &merged, 248)?;
                Ok(BoundedBytes::new(merged, 31))
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self {
            length,
            capacity,
            chunks,
        })
    }
    /// Hash the exact active string with native `P_bytes` framing and padding.
    ///
    /// Requires an ordinary (non-phased) sponge lane. The complete fixed
    /// permutation schedule runs; a constrained unique endpoint selects the
    /// digest, including empty strings and both arity parities.
    /// # Errors
    /// Compact lane, malformed capacity or synthesis.
    pub fn digest(
        &self,
        uint: &mut UintChip<'_, F>,
        sponge: &mut SpongeChip<F>,
        region: &mut Region<'_, F>,
        domain: u64,
    ) -> Result<Word<F>, Error>
    where
        F: PoseidonField,
    {
        let parts = length_parts(uint, region, &self.length, self.capacity)?;
        let active = prefix(uint.glue(), region, &parts.chunks, self.chunks.len())?;
        let zero = uint.glue().constant(region, F::ZERO)?;
        let one = uint.glue().constant(region, F::ONE)?;
        let domain = uint.glue().constant(region, F::from(domain))?;
        let arity = uint
            .glue()
            .add_constant(region, parts.chunks.word(), F::ONE)?;
        let mut elements = vec![domain, arity, self.length.word().clone()];
        let mut padding = vec![zero.clone(); 3];
        let mut previous = one;
        for (chunk, bit) in self.chunks.iter().zip(&active) {
            let kept = uint.glue().mul(region, bit.word(), chunk.word())?;
            GlueChip::assert_equal(region, &kept, chunk.word())?;
            let end = uint.glue().sub(region, &previous, bit.word())?;
            elements.push(uint.glue().add(region, chunk.word(), &end)?);
            padding.push(end);
            previous = bit.word().clone();
        }
        elements.push(previous.clone());
        padding.push(previous);
        if !elements.len().is_multiple_of(2) {
            elements.push(zero.clone());
            padding.push(zero);
        }
        let lane = sponge.lane_mut();
        let mut state = Some(lane.start(region, raw_initial_state())?);
        let mut outputs = Vec::with_capacity(elements.len() / 2);
        let last = elements.len() / 2 - 1;
        for (index, pair) in elements.chunks_exact(2).enumerate() {
            let block = Absorb::Block([AbsorbInput::Word(&pair[0]), AbsorbInput::Word(&pair[1])]);
            let current = state.take().ok_or(Error::Synthesis)?;
            let output = if index == last {
                lane.squeeze(region, current, block)?
            } else {
                let (next, output) = lane.permute_with_output(region, current, block)?;
                state = Some(next);
                output
            };
            let selected = uint
                .glue()
                .add(region, &padding[2 * index], &padding[2 * index + 1])?;
            outputs.push(uint.glue().mul(region, &selected, &output)?);
            if index == last {
                break;
            }
        }
        sum(uint.glue(), region, &outputs)
    }
}

#[cfg(test)]
#[path = "variable_tests.rs"]
mod tests;
