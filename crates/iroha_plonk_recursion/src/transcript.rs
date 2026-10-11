//! Circuit-side RP57 transcript state for PIPA-R and PIPA-AS.
//!
//! Uses the existing constrained duplex lane in both Pasta base fields. Every
//! squeeze retains all three state words; empty and even buffers receive the
//! native sponge's extra padding permutation. Domain and instance framing are
//! circuit constants, while absorbed words are copied from constrained cells.
//!
//! Typed scalar/point absorption and scalar squeezes use [`crate::codec`]'s
//! canonical cells and constrained challenge map. Callers must retain soft
//! verdicts, constrain instance types and key bindings, and enforce the complete
//! verification predicate, implemented by [`crate::verifier`].

use iroha_pasta::{PastaCurve, poseidon::PoseidonField};
use iroha_plonk::{
    cs::InstanceType,
    frontend::{Error, Region},
};
use iroha_plonk_gadgets::{
    Word, WordHasher,
    ecc::NonIdentityPoint,
    pow5_fq::{DuplexChip, DuplexConfig},
    range::u128::UintChip,
};

use crate::codec::{ScalarCells, map_challenge};

impl<C: PastaCurve> crate::verifier::VerifierChip<C> {
    /// Hashes a framed native-field message on the cleared verifier sponge lane.
    /// Preserves its cursor for subsequent hashes, proofs and folds.
    ///
    /// # Errors
    /// Layout failure or an interrupted transcript that did not return a clear lane.
    pub fn hash_words(
        &mut self,
        region: &mut Region<'_, C::Base>,
        domain: u64,
        words: &[Word<C::Base>],
    ) -> Result<Word<C::Base>, Error> {
        let duplex = self.duplex.as_mut().ok_or(Error::Synthesis)?;
        duplex.hash_words(region, domain, words)
    }
}

/// Domain separation for the two base-field transcript protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    /// Recursive PLONK/IPA proof transcript.
    Proof,
    /// Local non-hiding accumulation transcript.
    Fold,
}

impl Domain {
    /// The canonical eight-byte little-endian domain tag.
    #[must_use]
    pub const fn tag(self) -> [u8; 8] {
        match self {
            Self::Proof => *b"pipa-rb1",
            Self::Fold => *b"pipa-as1",
        }
    }
}

/// A single in-circuit base-field transcript, with no reset or domain switching.
#[derive(Debug)]
pub struct TranscriptChip<F: PoseidonField> {
    duplex: DuplexChip<F>,
    domain: Domain,
    prelude_available: bool,
}

impl<F: PoseidonField> TranscriptChip<F> {
    /// Starts a transcript after an earlier digest cleared the same duplex lane.
    /// The existing row cursor is retained, so no assigned cells are overwritten.
    ///
    /// # Errors
    /// Returns [`Error::Synthesis`] unless the state and buffer are both clear.
    pub fn from_duplex(mut duplex: DuplexChip<F>, domain: Domain) -> Result<Self, Error> {
        if !duplex.is_clear() || duplex.buffered() != 0 {
            return Err(Error::Synthesis);
        }
        duplex.absorb_constant(F::from(u64::from_le_bytes(domain.tag())));
        Ok(Self {
            duplex,
            domain,
            prelude_available: true,
        })
    }

    /// Ends this transcript and returns its cleared lane at the current cursor.
    /// Pending final messages are discarded without a squeeze, as required when
    /// the fixed protocol schedule has no challenge after its final messages.
    /// The caller must have checked that complete schedule before ending it.
    #[must_use]
    pub fn into_duplex(mut self) -> DuplexChip<F> {
        self.duplex.clear();
        self.duplex
    }

    /// Starts a transcript with its domain as the first buffered element.
    #[must_use]
    pub fn new(config: DuplexConfig<F>, domain: Domain) -> Self {
        let mut duplex = DuplexChip::new(config);
        duplex.absorb_constant(F::from(u64::from_le_bytes(domain.tag())));
        Self {
            duplex,
            domain,
            prelude_available: true,
        }
    }

    /// Absorbs a constrained base-field word.
    pub fn common_word(&mut self, word: &Word<F>) {
        self.prelude_available = false;
        self.duplex.absorb(word);
    }

    /// Absorbs a canonical proof scalar using its curve's injective encoding.
    /// A soft decoder's verdict must also enter the consuming verifier's verdict.
    pub fn common_scalar<C: PastaCurve<Base = F>>(&mut self, scalar: &ScalarCells<C>) {
        if let Some(word) = scalar.native_word() {
            self.common_word(word);
        } else {
            self.common_word(scalar.lo().word());
            self.common_word(scalar.hi().word());
        }
    }

    /// Absorbs the canonical coordinates of a constrained finite point.
    /// A soft decoder's verdict must also enter the consuming verifier's verdict.
    pub fn common_point(&mut self, point: &NonIdentityPoint<F>) {
        self.common_word(point.x());
        self.common_word(point.y());
    }

    /// Squeezes and constrains the full-width proof-scalar challenge map.
    ///
    /// # Errors
    /// Returns a layout error when the sponge or range lanes lack rows.
    pub fn squeeze_scalar<C: PastaCurve<Base = F>>(
        &mut self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
    ) -> Result<ScalarCells<C>, Error> {
        let word = self.squeeze_base(region)?;
        map_challenge(uint, region, &word)
    }

    /// Absorbs a circuit-constant base-field metadata value.
    pub fn common_constant(&mut self, value: F) {
        self.prelude_available = false;
        self.duplex.absorb_constant(value);
    }

    /// Absorbs the PIPA-R key representation and complete typed instance frame.
    ///
    /// Lengths and types are descriptor constants. The caller subsequently
    /// absorbs the instance values column-major using their curve's canonical
    /// scalar encoding. This method does not itself prove type membership.
    ///
    /// # Errors
    /// Returns [`Error::Synthesis`] for a repeated/late prelude, the fold domain,
    /// mismatched column counts or a bit width above 253. Invalid metadata never
    /// partially changes the transcript.
    pub fn proof_prelude(
        &mut self,
        representation: &Word<F>,
        lengths: &[u32],
        types: &[InstanceType],
    ) -> Result<(), Error> {
        if self.domain != Domain::Proof
            || !self.prelude_available
            || self.duplex.buffered() != 1
            || lengths.len() != types.len()
            || types
                .iter()
                .any(|ty| matches!(ty, InstanceType::Bits(bits) if *bits > 253))
        {
            return Err(Error::Synthesis);
        }
        let columns = u64::try_from(lengths.len()).map_err(|_| Error::BoundsFailure)?;
        self.duplex.absorb(representation);
        self.duplex
            .absorb_constant(F::from(u64::from_le_bytes(*b"pipainst")));
        self.duplex.absorb_constant(F::from(columns));
        for length in lengths {
            self.duplex.absorb_constant(F::from(u64::from(*length)));
        }
        for ty in types {
            self.duplex.absorb_constant(F::from(ty.code()));
        }
        self.prelude_available = false;
        Ok(())
    }

    /// Squeezes a constrained base-field word, retaining the duplex state.
    ///
    /// # Errors
    /// Returns a layout error when the configured lane has insufficient rows.
    pub fn squeeze_base(&mut self, region: &mut Region<'_, F>) -> Result<Word<F>, Error> {
        self.prelude_available = false;
        self.duplex.squeeze(region)
    }

    /// Squeezes the last base-field word and consumes this transcript.
    ///
    /// The final squeeze has identical value and padding to a continuing one,
    /// but avoids reserving a state row that no later squeeze will consume.
    ///
    /// # Errors
    /// Returns a layout error when the configured lane has insufficient rows.
    pub fn finish(mut self, region: &mut Region<'_, F>) -> Result<Word<F>, Error> {
        self.duplex.squeeze_and_clear(region)
    }
}
