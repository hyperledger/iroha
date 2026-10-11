//! Constrained CRC64-XZ over assigned bytes for canonical Norito frame headers.
//!
//! The state starts at all ones, shifts least-significant bit first using the
//! reflected ECMA polynomial, and finishes with an all-ones XOR. Every input bit,
//! shift, XOR and conditional byte consumption is constrained. A CRC is framing
//! metadata and supplies no cryptographic authentication or source authority.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

use crate::{Bit, GlueChip, U64, UintChip, Word, cells::low_u128};

const POLYNOMIAL: u64 = 0xc96c_5795_d787_0f42;

/// Sixty-four constrained reflected CRC bits, before the final XOR.
#[derive(Clone, Debug)]
pub struct Crc64State<F: PastaField> {
    bits: [Bit<F>; 64],
}

fn pack<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    bits: &[Bit<F>],
) -> Result<Word<F>, Error> {
    let mut value = uint.glue().constant(region, F::ZERO)?;
    for bit in bits.iter().rev() {
        value = uint.glue().linear(
            region,
            &[(F::from(2), &value), (F::ONE, bit.word())],
            F::ZERO,
        )?;
    }
    Ok(value)
}

fn xor<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    a: &Bit<F>,
    b: &Bit<F>,
) -> Result<Bit<F>, Error> {
    let product = uint.glue().mul(region, a.word(), b.word())?;
    let value = uint.glue().linear(
        region,
        &[
            (F::ONE, a.word()),
            (F::ONE, b.word()),
            (-F::from(2), &product),
        ],
        F::ZERO,
    )?;
    Ok(Bit::new(value))
}

impl<F: PastaField> Crc64State<F> {
    /// Exact initial state of CRC64-XZ.
    /// # Errors
    /// Circuit layout errors.
    pub fn initial(uint: &mut UintChip<'_, F>, region: &mut Region<'_, F>) -> Result<Self, Error> {
        let one = Bit::new(uint.glue().constant(region, F::ONE)?);
        Ok(Self {
            bits: core::array::from_fn(|_| one.clone()),
        })
    }

    /// Import a canonical unsigned running state for a surrounding proved scan.
    /// The caller must bind its predecessor and initial state; this is not a CRC verdict.
    /// # Errors
    /// Circuit layout errors; a value outside64 bits is unsatisfiable.
    pub fn from_word(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        word: &Word<F>,
    ) -> Result<Self, Error> {
        let mut bits = Vec::with_capacity(64);
        for i in 0..64 {
            bits.push(
                uint.glue()
                    .boolean(region, word.value().map(|v| (low_u128(&v) >> i) & 1 != 0))?,
            );
        }
        let packed = pack(uint, region, &bits)?;
        GlueChip::assert_equal(region, &packed, word)?;
        Ok(Self {
            bits: bits.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Consume one ranged byte exactly when the surrounding proved schedule enables it.
    /// Disabled bytes preserve every state bit; their source byte remains range checked.
    /// # Errors
    /// Circuit layout errors; a non-byte input is unsatisfiable.
    pub fn update(
        &self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        byte: &Word<F>,
        enabled: &Bit<F>,
    ) -> Result<Self, Error> {
        let mut input = Vec::with_capacity(8);
        for i in 0..8 {
            input.push(
                uint.glue()
                    .boolean(region, byte.value().map(|v| (low_u128(&v) >> i) & 1 != 0))?,
            );
        }
        let packed = pack(uint, region, &input)?;
        GlueChip::assert_equal(region, &packed, byte)?;
        let mut state = self.bits.clone();
        for (bit, input) in state.iter_mut().zip(input.iter()) {
            *bit = xor(uint, region, bit, input)?;
        }
        let zero = Bit::new(uint.glue().constant(region, F::ZERO)?);
        for _ in 0..8 {
            let low = state[0].clone();
            let mut next = Vec::with_capacity(64);
            for i in 0..64 {
                let shifted = state.get(i + 1).unwrap_or(&zero);
                next.push(if POLYNOMIAL >> i & 1 == 1 {
                    xor(uint, region, shifted, &low)?
                } else {
                    shifted.clone()
                });
            }
            state = next.try_into().map_err(|_| Error::Synthesis)?;
        }
        let mut selected = Vec::with_capacity(64);
        for (next, previous) in state.iter().zip(&self.bits) {
            selected.push(Bit::new(uint.glue().select(
                region,
                enabled,
                next.word(),
                previous.word(),
            )?));
        }
        Ok(Self {
            bits: selected.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Export the exact unsigned running state for a recursive checkpoint.
    /// # Errors
    /// Circuit layout errors.
    pub fn word(
        &self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
    ) -> Result<U64<F>, Error> {
        let word = pack(uint, region, &self.bits)?;
        uint.range_check::<64>(region, &word)
    }

    /// Apply the fixed final XOR and return the canonical CRC64-XZ checksum.
    /// # Errors
    /// Circuit layout errors.
    pub fn checksum(
        &self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
    ) -> Result<U64<F>, Error> {
        let state = self.word(uint, region)?;
        let complement =
            uint.glue()
                .linear(region, &[(-F::ONE, state.word())], F::from(u64::MAX))?;
        uint.range_check::<64>(region, &complement)
    }
}

#[cfg(test)]
mod tests;
