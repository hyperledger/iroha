//! The protocol variants of the backend and the values that select them.
//!
//! Three variants exist. Exactly one is FAEST-conformant:
//!
//! | [`Variant`] | prefix | [`Construction`] | status |
//! |---|---|---|---|
//! | [`Variant::Reference`] | empty | [`Construction::Faest`] | plain FAEST v3.0; checked against the official vectors |
//! | [`Variant::Prefixed`] | non-empty | [`Construction::Faest`] | FAEST-derived: the FAEST construction with a namespace prefix on every oracle call |
//! | [`Variant::Extended`] | non-empty | [`Construction::Extended`] | FAEST-derived: the changes below; no official vectors exist for it |
//!
//! A [`Variant`] is what a [`crate::proof::ProofContext`] carries. Below the proof
//! layer the namespace is passed on its own, so the layers distinguish only the two
//! [`Construction`]s; a [`Binding`] is a construction together with the per-proof
//! public data it adds to oracle inputs (the salt). Each layer that behaves
//! differently takes one of these values explicitly. There is no default and no
//! global state, and the salt can only be supplied as part of
//! [`Binding::Extended`], so a salted challenge cannot be combined with an unsalted
//! `H_5`, nor an extended leaf commitment with a reference-size opening.
//!
//! # The extended construction
//!
//! Defined for `lambda = 256` and three-block leaf commitments only (the geometry
//! of the FAEST-256f and FAEST-256s rows); anything else is a [`VariantError`]. It
//! differs from the FAEST construction in exactly these points:
//!
//! * **Salt.** A public salt of [`SALT_BYTES`] bytes per proof. It is appended to
//!   the first challenge's message (`mu || com || c_1 .. || c_mult || iv_pre ||
//!   salt`) and enters every `H_5` input (`iv || salt || LE32(e) || label`). It
//!   does not enter `H_4`, `H_0`, the AES generator or the leaf commitment. In the
//!   proof it follows `iv_pre` and precedes the counter.
//! * **Counter limit.** Counters `0 ..= `[`EXTENDED_LAST_COUNTER`], still encoded
//!   as four little-endian bytes. The prover never wraps; the verifier rejects a
//!   larger counter before any reconstruction.
//! * **Affine-checked leaf commitment.** `H_0` outputs `h0[96] || h1[32]`, the
//!   leaf generator expands `sd[32] || b0[96] || b1[16]`, and the leaf commitment
//!   is `c0[96] || c1[16]` with `c0` the FAEST leaf hash of `(sd, b0)` under `h0`
//!   and `c1` the low 128 polynomial coordinates of `sd * h1` in `GF(2^256)`,
//!   added (XOR) to `b1` ([`crate::bavc`]). The opening carries the 112-byte
//!   commitments.
//!
//! Everything else (the prefix on every oracle call, domain bytes, challenge
//! lengths, CRT tables, field conventions, the absence of `H_3`) is unchanged.
//!
//! Nothing here is a statement about the security of either derived variant; none
//! of them is selected or qualified.

use thiserror::Error;

use crate::params::{SecurityLevel, VoleParams};

/// Bytes of the per-proof public salt of the extended construction.
pub const SALT_BYTES: usize = 32;

/// The last counter the extended construction allows: `2^20 - 1`.
pub const EXTENDED_LAST_COUNTER: u32 = 0x000f_ffff;

/// Bytes of the affine check `c1` appended to each leaf commitment of the
/// extended construction.
pub const EXTENDED_CHECK_BYTES: usize = 16;

/// The extended construction was requested where it is not defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VariantError {
    /// The extended construction is defined for `lambda = 256` only.
    #[error("the extended construction is defined for lambda = 256, not {lambda}")]
    UnsupportedLevel {
        /// `lambda` of the level requested, in bits.
        lambda: usize,
    },
    /// The extended construction is defined for three-block leaf commitments only.
    #[error("the extended construction is defined for n_leafcom = 3, not {n_leafcom}")]
    UnsupportedLeafBlocks {
        /// `n_leafcom` of the row.
        n_leafcom: usize,
    },
}

/// The protocol variant of one proof context. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Variant {
    /// Plain FAEST v3.0: the empty prefix and the FAEST construction. The only
    /// FAEST-conformant variant.
    Reference,
    /// The FAEST construction inside a non-empty namespace prefix.
    Prefixed,
    /// The extended construction inside a non-empty namespace prefix.
    Extended,
}

impl Variant {
    /// All variants.
    pub const ALL: [Self; 3] = [Self::Reference, Self::Prefixed, Self::Extended];

    /// The construction the layers below the proof run.
    pub const fn construction(self) -> Construction {
        match self {
            Self::Reference | Self::Prefixed => Construction::Faest,
            Self::Extended => Construction::Extended,
        }
    }

    /// Whether the variant is the proof system of FAEST v3.0 byte for byte. True
    /// for [`Self::Reference`] only.
    pub const fn is_faest_conformant(self) -> bool {
        matches!(self, Self::Reference)
    }
}

/// What the hash, commitment, VOLE, transcript and codec layers compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Construction {
    /// The construction of FAEST v3.0.
    Faest,
    /// The extended construction: salt, counter limit, affine-checked leaves.
    Extended,
}

impl Construction {
    /// Both constructions.
    pub const ALL: [Self; 2] = [Self::Faest, Self::Extended];

    /// The last counter a proof may carry: `2^32 - 1` for [`Self::Faest`],
    /// [`EXTENDED_LAST_COUNTER`] for [`Self::Extended`].
    pub const fn last_counter(self) -> u32 {
        match self {
            Self::Faest => u32::MAX,
            Self::Extended => EXTENDED_LAST_COUNTER,
        }
    }

    /// Bytes of salt in a proof: none for [`Self::Faest`], [`SALT_BYTES`] for
    /// [`Self::Extended`].
    pub const fn salt_bytes(self) -> usize {
        match self {
            Self::Faest => 0,
            Self::Extended => SALT_BYTES,
        }
    }

    /// Check that the construction is defined at `level`.
    ///
    /// # Errors
    /// [`VariantError::UnsupportedLevel`] for [`Self::Extended`] at a level other
    /// than `lambda = 256`.
    pub const fn check_level(self, level: SecurityLevel) -> Result<(), VariantError> {
        match (self, level) {
            (Self::Faest, _) | (Self::Extended, SecurityLevel::L256) => Ok(()),
            (Self::Extended, _) => Err(VariantError::UnsupportedLevel {
                lambda: level.bits(),
            }),
        }
    }

    /// Check that the construction is defined on the row `params`.
    ///
    /// # Errors
    /// For [`Self::Extended`]: [`VariantError::UnsupportedLevel`] unless
    /// `lambda = 256`, then [`VariantError::UnsupportedLeafBlocks`] unless
    /// `n_leafcom = 3`.
    pub const fn check_row(self, params: &VoleParams) -> Result<(), VariantError> {
        if let Err(error) = self.check_level(params.lambda()) {
            return Err(error);
        }
        match self {
            Self::Extended if params.n_leafcom() != 3 => Err(VariantError::UnsupportedLeafBlocks {
                n_leafcom: params.n_leafcom(),
            }),
            _ => Ok(()),
        }
    }
}

/// A construction together with the per-proof public data it binds into oracle
/// inputs. Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding<'a> {
    /// The FAEST construction: nothing is added.
    Faest,
    /// The extended construction with the salt of the proof.
    Extended {
        /// The salt.
        salt: &'a [u8; SALT_BYTES],
    },
}

impl<'a> Binding<'a> {
    /// The construction.
    pub const fn construction(self) -> Construction {
        match self {
            Self::Faest => Construction::Faest,
            Self::Extended { .. } => Construction::Extended,
        }
    }

    /// The salt, if the construction has one.
    pub const fn salt(self) -> Option<&'a [u8; SALT_BYTES]> {
        match self {
            Self::Faest => None,
            Self::Extended { salt } => Some(salt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{FAEST_128F, FAEST_192S, FAEST_256F, FAEST_256S, FAEST_EM_256F};

    #[test]
    fn the_public_constants_are_those_of_the_extended_construction() {
        assert_eq!(SALT_BYTES, 32);
        assert_eq!(EXTENDED_LAST_COUNTER, 0x000f_ffff);
        assert_eq!(u64::from(EXTENDED_LAST_COUNTER) + 1, 1 << 20);
        assert_eq!(EXTENDED_CHECK_BYTES, 16);
    }

    #[test]
    fn variants_map_to_constructions_and_only_reference_is_conformant() {
        assert_eq!(Variant::Reference.construction(), Construction::Faest);
        assert_eq!(Variant::Prefixed.construction(), Construction::Faest);
        assert_eq!(Variant::Extended.construction(), Construction::Extended);
        assert_eq!(
            Variant::ALL.map(Variant::is_faest_conformant),
            [true, false, false]
        );
    }

    #[test]
    fn counter_limits_and_salt_lengths_follow_the_construction() {
        assert_eq!(Construction::Faest.last_counter(), u32::MAX);
        assert_eq!(Construction::Extended.last_counter(), 0x000f_ffff);
        assert_eq!(Construction::ALL.map(Construction::salt_bytes), [0, 32]);
    }

    #[test]
    fn the_extended_construction_is_defined_on_the_256_bit_three_block_rows_only() {
        for level in SecurityLevel::ALL {
            assert_eq!(Construction::Faest.check_level(level), Ok(()));
        }
        assert_eq!(
            Construction::Extended.check_level(SecurityLevel::L256),
            Ok(())
        );
        for level in [SecurityLevel::L128, SecurityLevel::L192] {
            assert_eq!(
                Construction::Extended.check_level(level),
                Err(VariantError::UnsupportedLevel {
                    lambda: level.bits()
                })
            );
        }
        for set in [FAEST_256F, FAEST_256S] {
            assert_eq!(Construction::Extended.check_row(set.vole()), Ok(()));
        }
        for set in [FAEST_128F, FAEST_192S, FAEST_256F, FAEST_EM_256F] {
            assert_eq!(Construction::Faest.check_row(set.vole()), Ok(()));
        }
        assert_eq!(
            Construction::Extended.check_row(FAEST_128F.vole()),
            Err(VariantError::UnsupportedLevel { lambda: 128 })
        );
        assert_eq!(
            Construction::Extended.check_row(FAEST_EM_256F.vole()),
            Err(VariantError::UnsupportedLeafBlocks { n_leafcom: 2 })
        );
        assert!(
            VariantError::UnsupportedLevel { lambda: 192 }
                .to_string()
                .contains("192")
        );
    }

    #[test]
    fn a_binding_carries_the_salt_of_its_construction_only() {
        let salt = [7u8; SALT_BYTES];
        assert_eq!(Binding::Faest.construction(), Construction::Faest);
        assert_eq!(Binding::Faest.salt(), None);
        let extended = Binding::Extended { salt: &salt };
        assert_eq!(extended.construction(), Construction::Extended);
        assert_eq!(extended.salt(), Some(&salt));
    }
}
