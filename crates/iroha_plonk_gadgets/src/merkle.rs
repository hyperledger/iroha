//! Counted application Merkle inclusion using the ordinary ledger's exact hashes.
//!
//! The caller must authenticate the root **and count** together and link the original
//! typed leaf hash to its canonical preimage. This chip proves only inclusion, not
//! validator finality, successful execution, or the meaning of a leaf. A proof owner
//! must constrain every returned state transition and call [`PathCells::finish`].
//! Hashing uses `Blake2b-256`, Iroha's final-byte low-bit marker, the exact NUL-ended
//! leaf/internal domains, ordered children, and unchanged promotion on ragged edges.
//! The number of calls is fixed by the circuit, never selected by a private witness.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

use crate::{Bit, GlueChip, U64, Uint, UintChip, Word, blake2b::Blake2bChip};

const LEAF_DOMAIN: &[u8] = b"iroha:merkle:leaf:v1\0";
const INTERNAL_DOMAIN: &[u8] = b"iroha:merkle:internal:v1\0";

/// One level of a canonical counted tree. Fields cannot be forged by callers.
#[derive(Clone, Debug)]
pub struct Geometry<F: PastaField> {
    index: U64<F>,
    width: U64<F>,
}

/// A constrained step's next level, direction and required sibling presence.
#[derive(Clone, Debug)]
pub struct GeometryStep<F: PastaField> {
    next: Geometry<F>,
    right: Bit<F>,
    sibling: Bit<F>,
}

impl<F: PastaField> Geometry<F> {
    /// Start with a native proof's `u32` leaf index and authenticated nonzero count.
    ///
    /// # Errors
    /// Returns layout errors; zero counts and out-of-range indices are unsatisfiable.
    pub fn new(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        index: &Uint<F, 32>,
        count: &U64<F>,
    ) -> Result<Self, Error> {
        let index = UintChip::widen(index);
        uint.assert_lt(region, &index, count)?;
        Ok(Self {
            index,
            width: count.clone(),
        })
    }

    /// The current node index, to bind when carrying a recursive path state.
    #[must_use]
    pub const fn index(&self) -> &U64<F> {
        &self.index
    }

    /// The current level width, to bind when carrying a recursive path state.
    #[must_use]
    pub const fn width(&self) -> &U64<F> {
        &self.width
    }

    /// Prove one actual level: `i' = floor(i/2)`, `w' = ceil(w/2)` and sibling
    /// presence exactly when `i xor 1 < w`. A terminal width cannot take a step.
    ///
    /// # Errors
    /// Returns layout errors; a step above the root is unsatisfiable.
    pub fn step(
        &self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
    ) -> Result<GeometryStep<F>, Error> {
        let one = uint.constant::<64>(region, 1)?;
        uint.assert_lt(region, &one, &self.width)?;
        let (index_half, right) = split_half(uint, region, &self.index)?;
        let (width_half, odd_width) = split_half(uint, region, &self.width)?;
        let width_sum = uint
            .glue()
            .add(region, width_half.word(), odd_width.word())?;
        let width = uint.range_check::<64>(region, &width_sum)?;
        let other = uint.glue().linear(
            region,
            &[(F::ONE, self.index.word()), (-F::from(2), right.word())],
            F::ONE,
        )?;
        // i xor 1 fits u64 even at the endpoints, so this also excludes wraparound.
        let other = uint.range_check::<64>(region, &other)?;
        let sibling = uint.lt(region, &other, &self.width)?;
        let next = Self {
            index: UintChip::widen(&index_half),
            width,
        };
        uint.assert_lt(region, &next.index, &next.width)?;
        Ok(GeometryStep {
            next,
            right,
            sibling,
        })
    }

    /// Require the exact root level: index zero and width one.
    ///
    /// # Errors
    /// Returns layout errors; a truncated path has no satisfying assignment.
    pub fn finish(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        GlueChip::assert_constant(region, self.index.word(), F::ZERO)?;
        GlueChip::assert_constant(region, self.width.word(), F::ONE)
    }
}

impl<F: PastaField> GeometryStep<F> {
    /// The next level's linked geometry.
    #[must_use]
    pub const fn next(&self) -> &Geometry<F> {
        &self.next
    }
    /// True exactly when the current node is the right child.
    #[must_use]
    pub const fn right(&self) -> &Bit<F> {
        &self.right
    }
    /// True exactly when the counted tree requires a sibling at this level.
    #[must_use]
    pub const fn sibling(&self) -> &Bit<F> {
        &self.sibling
    }
}

fn split_half<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    value: &U64<F>,
) -> Result<(Uint<F, 63>, Bit<F>), Error> {
    let half = uint.assign::<63>(region, value.value().map(|v| v >> 1))?;
    let odd = uint
        .glue()
        .boolean(region, value.value().map(|v| v & 1 == 1))?;
    let recombined = uint.glue().linear(
        region,
        &[(F::from(2), half.word()), (F::ONE, odd.word())],
        F::ZERO,
    )?;
    GlueChip::assert_equal(region, &recombined, value.word())?;
    Ok((half, odd))
}

/// Inclusion accumulator whose digest and counted geometry advance together.
#[derive(Clone, Debug)]
pub struct PathCells<F: PastaField> {
    geometry: Geometry<F>,
    digest: [Word<F>; 32],
}

impl<F: PastaField> PathCells<F> {
    /// Reopen a path continuation after the enclosing source authenticates all
    /// three fields. This checks canonical geometry and hash bytes, but conveys
    /// no inclusion authority without that original endpoint commitment.
    /// # Errors
    /// Layout errors; a zero width, out-of-range index or unmarked hash fails.
    pub fn resume(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        index: &Uint<F, 32>,
        width: &U64<F>,
        digest: &[Word<F>; 32],
    ) -> Result<Self, Error> {
        let geometry = Geometry::new(uint, region, index, width)?;
        let one = uint.glue().constant(region, F::ONE)?;
        let one = uint.glue().assert_bool(region, &one)?;
        canonical_sibling(uint, region, digest, &one)?;
        Ok(Self {
            geometry,
            digest: digest.clone(),
        })
    }

    /// Domain-separate one typed Iroha hash and bind its exact index/count.
    ///
    /// # Errors
    /// Returns layout errors; a noncanonical hash marker is unsatisfiable.
    pub fn start(
        hash: &mut Blake2bChip<'_, F>,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        index: &Uint<F, 32>,
        count: &U64<F>,
        leaf: &[Word<F>; 32],
    ) -> Result<Self, Error> {
        let geometry = Geometry::new(uint, region, index, count)?;
        let one = uint.glue().constant(region, F::ONE)?;
        let one = uint.glue().assert_bool(region, &one)?;
        canonical_sibling(uint, region, leaf, &one)?;
        let mut message = domain(uint, region, LEAF_DOMAIN)?;
        message.extend_from_slice(leaf);
        let digest = hash.hash_marked(region, &message)?.bytes().clone();
        Ok(Self { geometry, digest })
    }

    /// Hash one ordered pair, or promote the left node when the exact count requires
    /// a missing right sibling. Missing sibling bytes must all be zero; present
    /// siblings must be canonical Iroha hashes. Neither fact is a caller-supplied flag.
    ///
    /// # Errors
    /// Returns layout errors; wrong padding, marker or path geometry is unsatisfiable.
    pub fn step(
        &self,
        hash: &mut Blake2bChip<'_, F>,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        sibling: &[Word<F>; 32],
    ) -> Result<Self, Error> {
        let geometry = self.geometry.step(uint, region)?;
        canonical_sibling(uint, region, sibling, &geometry.sibling)?;
        let mut message = domain(uint, region, INTERNAL_DOMAIN)?;
        for (first, second) in [(&self.digest, sibling), (sibling, &self.digest)] {
            for (a, b) in first.iter().zip(second) {
                message.push(uint.glue().select(region, &geometry.right, b, a)?);
            }
        }
        let parent = hash.hash_marked(region, &message)?;
        let mut digest = Vec::with_capacity(32);
        for (parent, original) in parent.bytes().iter().zip(&self.digest) {
            digest.push(
                uint.glue()
                    .select(region, &geometry.sibling, parent, original)?,
            );
        }
        Ok(Self {
            geometry: geometry.next,
            digest: digest.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Advance one slot of a fixed-capacity path. An actual tree level uses
    /// [`Self::step`]; after width one, the only allowed sibling is zero and
    /// the complete path state is unchanged. Both cases have one fixed layout.
    /// The owner must constrain the number of slots and call [`Self::finish`].
    /// # Errors
    /// Layout errors; nonzero terminal padding and malformed live siblings fail.
    pub fn step_padded(
        &self,
        hash: &mut Blake2bChip<'_, F>,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        sibling: &[Word<F>; 32],
    ) -> Result<Self, Error> {
        let one = uint.constant::<64>(region, 1)?;
        let active = uint.lt(region, &one, &self.geometry.width)?;
        let zero = uint.glue().constant(region, F::ZERO)?;
        let two = uint.glue().constant(region, F::from(2))?;
        let index = uint
            .glue()
            .select(region, &active, self.geometry.index.word(), &zero)?;
        let index = uint.range_check::<32>(region, &index)?;
        let width = uint
            .glue()
            .select(region, &active, self.geometry.width.word(), &two)?;
        let width = uint.range_check::<64>(region, &width)?;
        // A fixed valid dummy pair keeps the ordinary step's constraints active
        // above the root. Its digest is discarded, never used as an authority.
        let mut selected = Vec::with_capacity(32);
        for (i, byte) in sibling.iter().enumerate() {
            uint.range_check::<8>(region, byte)?;
            let retained = uint.glue().mul(region, active.word(), byte)?;
            GlueChip::assert_equal(region, &retained, byte)?;
            let dummy = uint
                .glue()
                .constant(region, if i == 31 { F::ONE } else { F::ZERO })?;
            selected.push(uint.glue().select(region, &active, byte, &dummy)?);
        }
        let candidate = Self {
            geometry: Geometry::new(uint, region, &index, &width)?,
            digest: self.digest.clone(),
        }
        .step(
            hash,
            uint,
            region,
            &selected.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let index = uint.glue().select(
            region,
            &active,
            candidate.geometry.index.word(),
            self.geometry.index.word(),
        )?;
        let width = uint.glue().select(
            region,
            &active,
            candidate.geometry.width.word(),
            self.geometry.width.word(),
        )?;
        let mut digest = Vec::with_capacity(32);
        for (next, current) in candidate.digest.iter().zip(&self.digest) {
            digest.push(uint.glue().select(region, &active, next, current)?);
        }
        Ok(Self {
            geometry: Geometry {
                index: uint.range_check::<64>(region, &index)?,
                width: uint.range_check::<64>(region, &width)?,
            },
            digest: digest.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Counted path state that a recursive continuation must bind in its entirety.
    #[must_use]
    pub const fn geometry(&self) -> &Geometry<F> {
        &self.geometry
    }

    /// Current domain-separated node digest, to bind alongside the geometry.
    #[must_use]
    pub const fn digest(&self) -> &[Word<F>; 32] {
        &self.digest
    }

    /// Require the terminal root level and equality with the authenticated root bytes.
    ///
    /// # Errors
    /// Returns layout errors; wrong roots and truncated paths are unsatisfiable.
    pub fn finish(&self, region: &mut Region<'_, F>, root: &[Word<F>; 32]) -> Result<(), Error> {
        self.geometry.finish(region)?;
        for (computed, expected) in self.digest.iter().zip(root) {
            GlueChip::assert_equal(region, computed, expected)?;
        }
        Ok(())
    }
}

fn domain<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    bytes: &[u8],
) -> Result<Vec<Word<F>>, Error> {
    bytes
        .iter()
        .map(|b| uint.glue().constant(region, F::from(u64::from(*b))))
        .collect()
}

fn canonical_sibling<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    bytes: &[Word<F>; 32],
    present: &Bit<F>,
) -> Result<(), Error> {
    for byte in bytes {
        uint.range_check::<8>(region, byte)?;
        let active = uint.glue().mul(region, present.word(), byte)?;
        GlueChip::assert_equal(region, &active, byte)?;
    }
    // Present hashes are odd in byte 31; absent hashes are the unique zero string.
    let top = uint.assign::<7>(
        region,
        bytes[31].value().map(|v| crate::cells::low_u128(&v) >> 1),
    )?;
    let marked = uint.glue().linear(
        region,
        &[(F::from(2), top.word()), (F::ONE, present.word())],
        F::ZERO,
    )?;
    GlueChip::assert_equal(region, &marked, &bytes[31])
}

#[cfg(test)]
mod tests;
