//! Framed RP57 word hashing shared by stand-alone and recursive circuits.

use core::fmt::Debug;

use iroha_pasta::poseidon::PoseidonField;
use iroha_plonk::frontend::{Error, Region};

use crate::{SpongeChip, Word, poseidon::AbsorbInput, pow5_fq::DuplexChip};

mod sealed {
    use super::*;
    pub trait Sealed {}
    impl<F: PoseidonField> Sealed for SpongeChip<F> {}
    impl<F: PoseidonField> Sealed for DuplexChip<F> {}
}

/// A constrained `P(domain; words)` hash with preserved lane cursors.
///
/// Only the two repository-owned RP57 chips implement this interface. A
/// duplex must be clear at entry and is cleared after each framed hash;
/// it cannot silently replace an active proof transcript.
pub trait WordHasher<F: PoseidonField>: Debug + sealed::Sealed {
    /// Hash `[domain, inputs.len(), inputs...]` with canonical RP57 padding.
    /// Constants do not allocate unconstrained witnesses or extra glue rows.
    ///
    /// # Errors
    /// Layout failure, an unrepresentable length or an active duplex transcript.
    fn hash_inputs(
        &mut self,
        region: &mut Region<'_, F>,
        domain: u64,
        inputs: &[AbsorbInput<'_, F>],
    ) -> Result<Word<F>, Error>;

    /// Hash a message consisting entirely of constrained words.
    ///
    /// # Errors
    /// The errors of [`Self::hash_inputs`].
    fn hash_words(
        &mut self,
        region: &mut Region<'_, F>,
        domain: u64,
        words: &[Word<F>],
    ) -> Result<Word<F>, Error> {
        let inputs: Vec<_> = words.iter().map(AbsorbInput::Word).collect();
        self.hash_inputs(region, domain, &inputs)
    }
}

impl<F: PoseidonField> WordHasher<F> for SpongeChip<F> {
    fn hash_inputs(
        &mut self,
        region: &mut Region<'_, F>,
        domain: u64,
        inputs: &[AbsorbInput<'_, F>],
    ) -> Result<Word<F>, Error> {
        SpongeChip::hash(self, region, domain, inputs)
    }
}

impl<F: PoseidonField> WordHasher<F> for DuplexChip<F> {
    fn hash_inputs(
        &mut self,
        region: &mut Region<'_, F>,
        domain: u64,
        inputs: &[AbsorbInput<'_, F>],
    ) -> Result<Word<F>, Error> {
        if !self.is_clear() || self.buffered() != 0 {
            return Err(Error::Synthesis);
        }
        self.absorb_constant(F::from(domain));
        self.absorb_constant(F::from(
            u64::try_from(inputs.len()).map_err(|_| Error::BoundsFailure)?,
        ));
        for input in inputs {
            match input {
                AbsorbInput::Word(word) => self.absorb(word),
                AbsorbInput::Constant(value) => self.absorb_constant(*value),
            }
        }
        self.squeeze_and_clear(region)
    }
}
