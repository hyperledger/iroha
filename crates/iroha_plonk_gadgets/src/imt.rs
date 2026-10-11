//! Authenticated indexed Merkle map operations for KAGEMUSHA lineage.
//!
//! Leaves hash `(key, value, next_key)` under `kgwimlf1`; binary nodes use
//! `kgwimnd1`. Slot zero contains the zero-key sentinel, and an unoccupied
//! slot contains the raw field zero (not the hash of a zero leaf). Keys are
//! ordered by their full canonical field integers, never by a reduced
//! difference or only their low limbs.
//!
//! Every opening and its search route are hard: the leaf must either match
//! the queried key or bracket it. Neither a bad path nor a different valid
//! leaf can manufacture non-membership failure and select a Receive burn. Insertion first
//! relinks the authenticated low leaf and authenticates the destination as
//! empty against that intermediate root. Removal authenticates and relinks
//! the predecessor, authenticates the removed leaf against the intermediate
//! root, then clears its slot. The native wallet chooses monotonically
//! increasing free slots; its counter is not part of this proof relation.
//!
//! Production maps use [`DEPTH`]. The generic depth permits small exhaustive
//! adversarial tests of the same constraints. These gadgets preserve an
//! initially well-formed map; they do not prove global sortedness of an
//! arbitrary unauthenticated starting tree.

use iroha_pasta::{PastaField, poseidon::PoseidonField};
use iroha_plonk::frontend::{Error, Region};

use crate::{
    Bit, GlueChip, RunningSumChip, SpongeChip, Uint, UintChip, Word, WordHasher,
    statement::assign_canonical_limbs,
};

/// Depth of every production KAGEMUSHA indexed map.
pub const DEPTH: usize = 32;
/// Domain of the three-field indexed leaf.
pub const LEAF_DOMAIN: u64 = u64::from_le_bytes(*b"kgwimlf1");
/// Domain of a two-field binary node.
pub const NODE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwimnd1");

/// Cells of an indexed leaf, authenticated and validated by [`ImtChip`].
#[derive(Clone, Debug)]
pub struct LeafCells<F: PastaField> {
    key: Word<F>,
    value: Word<F>,
    next_key: Word<F>,
}

impl<F: PastaField> LeafCells<F> {
    /// Wrap existing words in `(key, value, next_key)` order.
    ///
    /// This introduces no assertion; an operation authenticates and checks
    /// the leaf before using it.
    #[must_use]
    pub fn from_words([key, value, next_key]: [Word<F>; 3]) -> Self {
        Self {
            key,
            value,
            next_key,
        }
    }

    /// Map key, zero only for the sentinel of a valid map.
    #[must_use]
    pub const fn key(&self) -> &Word<F> {
        &self.key
    }

    /// Map value commitment, zero only for the sentinel of a valid map.
    #[must_use]
    pub const fn value(&self) -> &Word<F> {
        &self.value
    }

    /// Next key in canonical integer order, or zero at the end.
    #[must_use]
    pub const fn next_key(&self) -> &Word<F> {
        &self.next_key
    }
}

/// A binary path with a range-checked index and a constrained bit decomposition.
#[derive(Clone, Debug)]
pub struct PathCells<F: PastaField, const D: usize = DEPTH> {
    index: Uint<F, D>,
    bits: [Bit<F>; D],
    siblings: [Word<F>; D],
}

impl<F: PastaField, const D: usize> PathCells<F, D> {
    /// Constrain an existing index to `D` bits and link every direction bit.
    ///
    /// All `2^D` slots are representable, including `u32::MAX` at depth 32.
    ///
    /// # Errors
    ///
    /// Returns layout errors. An out-of-range index has no satisfying witness.
    pub fn from_words(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        index: &Word<F>,
        siblings: [Word<F>; D],
    ) -> Result<Self, Error> {
        const { assert!(D >= 1 && D <= DEPTH, "indexed map depth must be 1..=32") };
        let index = uint.range_check::<D>(region, index)?;
        let mut bits = Vec::with_capacity(D);
        for height in 0..D {
            bits.push(uint.glue().boolean(
                region,
                index.value().map(|index| (index >> height) & 1 != 0),
            )?);
        }
        let mut composed = uint.glue().constant(region, F::ZERO)?;
        for bit in bits.iter().rev() {
            composed = uint.glue().linear(
                region,
                &[(F::from(2), &composed), (F::ONE, bit.word())],
                F::ZERO,
            )?;
        }
        GlueChip::assert_equal(region, &composed, index.word())?;
        Ok(Self {
            index,
            bits: bits.try_into().map_err(|_| Error::Synthesis)?,
            siblings,
        })
    }

    /// The constrained slot index.
    #[must_use]
    pub const fn index(&self) -> &Uint<F, D> {
        &self.index
    }
}

/// A leaf and its binary authentication path.
#[derive(Clone, Debug)]
pub struct OpeningCells<F: PastaField, const D: usize = DEPTH> {
    /// The opened leaf.
    pub leaf: LeafCells<F>,
    /// Its slot and siblings.
    pub path: PathCells<F, D>,
}

/// Result of an insert-only record operation.
#[derive(Clone, Debug)]
pub struct RecordCells<F: PastaField> {
    root: Word<F>,
    value: Word<F>,
    present: Bit<F>,
}

impl<F: PastaField> RecordCells<F> {
    /// Successor root, unchanged when the key was already present.
    #[must_use]
    pub const fn root(&self) -> &Word<F> {
        &self.root
    }
    /// The first stored value, or the proposed value when inserted.
    #[must_use]
    pub const fn value(&self) -> &Word<F> {
        &self.value
    }
    /// Whether the authenticated predecessor already contained the key.
    #[must_use]
    pub const fn present(&self) -> &Bit<F> {
        &self.present
    }
}

/// An indexed-map view over the shared arithmetic, range and Poseidon chips.
#[derive(Debug)]
pub struct ImtChip<'a, F: PoseidonField, H: WordHasher<F> = SpongeChip<F>> {
    uint: UintChip<'a, F>,
    sponge: &'a mut H,
}

impl<'a, F: PoseidonField, H: WordHasher<F>> ImtChip<'a, F, H> {
    /// Borrow chips whose row cursors remain shared with the caller.
    pub const fn new(
        glue: &'a mut GlueChip<F>,
        range: &'a mut RunningSumChip<F>,
        sponge: &'a mut H,
    ) -> Self {
        Self {
            uint: UintChip::new(glue, range),
            sponge,
        }
    }

    /// Compare full canonical field integers, returning `[left < right]`.
    ///
    /// # Errors
    ///
    /// Returns layout errors.
    pub fn less(
        &mut self,
        region: &mut Region<'_, F>,
        left: &Word<F>,
        right: &Word<F>,
    ) -> Result<Bit<F>, Error> {
        let left = assign_canonical_limbs(&mut self.uint, region, left)?;
        let right = assign_canonical_limbs(&mut self.uint, region, right)?;
        let high_less = self.uint.lt(region, left.hi(), right.hi())?;
        let high_equal = self
            .uint
            .glue()
            .is_equal(region, left.hi().word(), right.hi().word())?;
        let low_less = self.uint.lt(region, left.lo(), right.lo())?;
        let tied = self.uint.glue().and(region, &high_equal, &low_less)?;
        // The two terms cannot both be one, so their sum is boolean.
        let result = self
            .uint
            .glue()
            .add(region, high_less.word(), tied.word())?;
        self.uint.glue().assert_bool(region, &result)
    }

    /// Hash a leaf. Its local shape is checked when authenticated by an operation.
    ///
    /// # Errors
    ///
    /// Returns layout errors.
    pub fn leaf_hash(
        &mut self,
        region: &mut Region<'_, F>,
        leaf: &LeafCells<F>,
    ) -> Result<Word<F>, Error> {
        self.sponge.hash_words(
            region,
            LEAF_DOMAIN,
            &[leaf.key.clone(), leaf.value.clone(), leaf.next_key.clone()],
        )
    }

    /// Compute a path root over an already-hashed leaf or raw empty-slot zero.
    ///
    /// # Errors
    ///
    /// Returns layout errors.
    pub fn path_root<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        node: &Word<F>,
        path: &PathCells<F, D>,
    ) -> Result<Word<F>, Error> {
        let mut node = node.clone();
        for (bit, sibling) in path.bits.iter().zip(&path.siblings) {
            let left = self.uint.glue().select(region, bit, sibling, &node)?;
            let right = self.uint.glue().select(region, bit, &node, sibling)?;
            node = self
                .sponge
                .hash_words(region, NODE_DOMAIN, &[left, right])?;
        }
        Ok(node)
    }

    /// Authenticate a well-formed leaf, including the sentinel.
    ///
    /// A valid non-sentinel leaf has nonzero key/value and a strictly larger
    /// successor or zero. The sentinel has index/key/value zero.
    fn authenticate<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        root: &Word<F>,
        opening: &OpeningCells<F, D>,
    ) -> Result<(), Error> {
        let leaf = &opening.leaf;
        let key_zero = self.uint.glue().is_zero(region, &leaf.key)?;
        let value_zero = self.uint.glue().is_zero(region, &leaf.value)?;
        let index_zero = self
            .uint
            .glue()
            .is_zero(region, opening.path.index.word())?;
        GlueChip::assert_equal(region, key_zero.word(), index_zero.word())?;
        GlueChip::assert_equal(region, value_zero.word(), key_zero.word())?;
        let next_zero = self.uint.glue().is_zero(region, &leaf.next_key)?;
        let ordered = self.less(region, &leaf.key, &leaf.next_key)?;
        let valid = self
            .uint
            .glue()
            .add(region, next_zero.word(), ordered.word())?;
        GlueChip::assert_constant(region, &valid, F::ONE)?;
        let node = self.leaf_hash(region, leaf)?;
        let actual = self.path_root(region, &node, &opening.path)?;
        GlueChip::assert_equal(region, &actual, root)
    }

    /// Prove a nonzero key and its value are members of an authenticated map.
    ///
    /// The caller binds the opened key/value to the operation's key/value.
    ///
    /// # Errors
    ///
    /// Returns layout errors; false membership has no satisfying witness.
    pub fn membership<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        root: &Word<F>,
        opening: &OpeningCells<F, D>,
    ) -> Result<(), Error> {
        self.uint
            .glue()
            .assert_nonzero(region, opening.leaf.key())?;
        self.authenticate(region, root, opening)
    }

    /// Return whether `key` is absent, with a unique authenticated search route.
    ///
    /// The path, leaf shape and `own leaf OR bracketing low leaf` are hard
    /// constraints. The resulting soft bit is false only on authenticated
    /// membership. A prover cannot pick an unrelated valid leaf to select
    /// burn. The queried key must be nonzero; a consumer decoding a malformed
    /// key must first select a valid dummy and preserve its failure bit.
    ///
    /// # Errors
    ///
    /// Returns layout errors; a forged path, wrong search route or zero key
    /// has no satisfying witness.
    pub fn absent<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        root: &Word<F>,
        key: &Word<F>,
        low: &OpeningCells<F, D>,
    ) -> Result<Bit<F>, Error> {
        self.authenticate(region, root, low)?;
        self.uint.glue().assert_nonzero(region, key)?;
        let present = self.uint.glue().is_equal(region, &low.leaf.key, key)?;
        let absent = self.brackets(region, key, &low.leaf)?;
        let routed = self
            .uint
            .glue()
            .add(region, present.word(), absent.word())?;
        GlueChip::assert_constant(region, &routed, F::ONE)?;
        Ok(absent)
    }

    fn brackets(
        &mut self,
        region: &mut Region<'_, F>,
        key: &Word<F>,
        low: &LeafCells<F>,
    ) -> Result<Bit<F>, Error> {
        let lower = self.less(region, &low.key, key)?;
        let upper = self.less(region, key, &low.next_key)?;
        let end = self.uint.glue().is_zero(region, &low.next_key)?;
        // `key < 0` is false in canonical integer order.
        let upper_or_end = self.uint.glue().add(region, upper.word(), end.word())?;
        let upper_or_end = self.uint.glue().assert_bool(region, &upper_or_end)?;
        self.uint.glue().and(region, &lower, &upper_or_end)
    }

    /// Insert a fresh nonzero key/value, authenticating the destination as empty.
    ///
    /// `slot` authenticates zero against the root *after* updating the low
    /// leaf's link. It is not a path against the original root. No free-slot
    /// counter is exposed or incremented in the circuit.
    ///
    /// # Errors
    ///
    /// Returns layout errors; duplicates, invalid gaps and occupied slots
    /// have no satisfying witness.
    pub fn insert<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        old_root: &Word<F>,
        key: &Word<F>,
        value: &Word<F>,
        low: &OpeningCells<F, D>,
        slot: &PathCells<F, D>,
    ) -> Result<Word<F>, Error> {
        let absent = self.absent(region, old_root, key, low)?;
        GlueChip::assert_constant(region, absent.word(), F::ONE)?;
        self.uint.glue().assert_nonzero(region, value)?;
        let linked =
            LeafCells::from_words([low.leaf.key.clone(), low.leaf.value.clone(), key.clone()]);
        let linked = self.leaf_hash(region, &linked)?;
        let intermediate = self.path_root(region, &linked, &low.path)?;
        let zero = self.uint.glue().constant(region, F::ZERO)?;
        let empty_root = self.path_root(region, &zero, slot)?;
        GlueChip::assert_equal(region, &intermediate, &empty_root)?;
        let leaf = LeafCells::from_words([key.clone(), value.clone(), low.leaf.next_key.clone()]);
        let node = self.leaf_hash(region, &leaf)?;
        self.path_root(region, &node, slot)
    }

    /// Preserve an existing record or insert a fresh one, with no witness branch.
    ///
    /// `opening` must be the queried key's leaf or its bracketing low leaf.
    /// On membership, `slot` opens that same leaf against the unchanged root;
    /// the existing value remains untouched even when it differs from
    /// `proposed_value`. On absence, `slot` opens an empty slot after
    /// relinking the low leaf. This is the credit-digest update rule.
    ///
    /// # Errors
    ///
    /// Returns layout errors; false search routes, changing an existing
    /// record or inserting into an occupied slot are unsatisfiable.
    pub fn record<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        root: &Word<F>,
        key: &Word<F>,
        proposed_value: &Word<F>,
        opening: &OpeningCells<F, D>,
        slot: &PathCells<F, D>,
    ) -> Result<RecordCells<F>, Error> {
        let absent = self.absent(region, root, key, opening)?;
        let present = self.uint.glue().not(region, &absent)?;
        let new_root =
            self.selected_insert(region, [key, proposed_value], opening, slot, &absent)?;
        let value =
            self.uint
                .glue()
                .select(region, &present, opening.leaf.value(), proposed_value)?;
        Ok(RecordCells {
            root: new_root,
            value,
            present,
        })
    }

    /// Constrain a structurally valid insertion or an unchanged root.
    ///
    /// The constrained `insert` bit belongs to the operation relation. When
    /// it is one, the key must be absent and the destination empty; when it
    /// is zero, both paths authenticate the same existing leaf and the root
    /// is unchanged. Thus a no-op remains possible in a full tree. This is
    /// the OQ-3 consumed-credit root rule; the caller additionally binds an
    /// accepting Receive to insertion of its own exact key/value.
    ///
    /// # Errors
    ///
    /// Returns layout errors; a bad authentication or enabled bad insertion
    /// has no satisfying witness.
    pub fn insert_if<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        root: &Word<F>,
        entry: [&Word<F>; 2],
        low: &OpeningCells<F, D>,
        slot: &PathCells<F, D>,
        insert: &Bit<F>,
    ) -> Result<Word<F>, Error> {
        self.authenticate(region, root, low)?;
        let absent = self.brackets(region, entry[0], &low.leaf)?;
        let valid = self.uint.glue().and(region, insert, &absent)?;
        GlueChip::assert_equal(region, valid.word(), insert.word())?;
        self.selected_insert(region, entry, low, slot, insert)
    }

    /// Both branches use the same paths and gates. Callers have already
    /// authenticated the old leaf and proved the gap whenever inserting.
    fn selected_insert<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        [key, value]: [&Word<F>; 2],
        low: &OpeningCells<F, D>,
        slot: &PathCells<F, D>,
        insert: &Bit<F>,
    ) -> Result<Word<F>, Error> {
        let checked_value = self
            .uint
            .glue()
            .select_constant(region, insert, value, F::ONE)?;
        self.uint.glue().assert_nonzero(region, &checked_value)?;
        let checked_slot =
            self.uint
                .glue()
                .select_constant(region, insert, slot.index.word(), F::ONE)?;
        self.uint.glue().assert_nonzero(region, &checked_slot)?;
        let noop = self.uint.glue().not(region, insert)?;
        let slot_delta = self
            .uint
            .glue()
            .sub(region, slot.index.word(), low.path.index.word())?;
        let noop_delta = self.uint.glue().mul(region, noop.word(), &slot_delta)?;
        GlueChip::assert_constant(region, &noop_delta, F::ZERO)?;
        let next = self
            .uint
            .glue()
            .select(region, insert, key, low.leaf.next_key())?;
        let linked = LeafCells::from_words([low.leaf.key.clone(), low.leaf.value.clone(), next]);
        let linked_hash = self.leaf_hash(region, &linked)?;
        let intermediate = self.path_root(region, &linked_hash, &low.path)?;
        let low_hash = self.leaf_hash(region, &low.leaf)?;
        let old_node = self
            .uint
            .glue()
            .select_constant(region, &noop, &low_hash, F::ZERO)?;
        let authenticated = self.path_root(region, &old_node, slot)?;
        GlueChip::assert_equal(region, &authenticated, &intermediate)?;
        let leaf = LeafCells::from_words([key.clone(), value.clone(), low.leaf.next_key.clone()]);
        let leaf_hash = self.leaf_hash(region, &leaf)?;
        let new_node = self
            .uint
            .glue()
            .select(region, insert, &leaf_hash, &low_hash)?;
        self.path_root(region, &new_node, slot)
    }

    /// Remove a nonzero leaf by relinking its predecessor and clearing its slot.
    ///
    /// The removed leaf's path is relative to the root *after* relinking
    /// the predecessor. Its authenticated value remains available to the
    /// operation, which must bind the removed descriptor before archiving.
    ///
    /// # Errors
    ///
    /// Returns layout errors; invalid links, paths, sentinel removal and
    /// aliasing the two slots have no satisfying witness.
    pub fn remove<const D: usize>(
        &mut self,
        region: &mut Region<'_, F>,
        old_root: &Word<F>,
        predecessor: &OpeningCells<F, D>,
        removed: &OpeningCells<F, D>,
    ) -> Result<Word<F>, Error> {
        self.authenticate(region, old_root, predecessor)?;
        GlueChip::assert_equal(region, predecessor.leaf.next_key(), removed.leaf.key())?;
        let difference = self.uint.glue().sub(
            region,
            predecessor.path.index.word(),
            removed.path.index.word(),
        )?;
        self.uint.glue().assert_nonzero(region, &difference)?;
        let relinked = LeafCells::from_words([
            predecessor.leaf.key.clone(),
            predecessor.leaf.value.clone(),
            removed.leaf.next_key.clone(),
        ]);
        let node = self.leaf_hash(region, &relinked)?;
        let intermediate = self.path_root(region, &node, &predecessor.path)?;
        self.membership(region, &intermediate, removed)?;
        let zero = self.uint.glue().constant(region, F::ZERO)?;
        self.path_root(region, &zero, &removed.path)
    }
}
