//! The in-circuit control checks of the step relations (the circuit side of
//! [`crate::controls`]): Merkle paths over the tree domains of
//! [`crate::tree`], the blacklist gap opening, the attestation lease and the
//! quota windows and usage updates.
//!
//! Every check here is gated by a bit the circuit derives (a held list, a
//! present segment slot, a touched window), so a check that does not apply
//! constrains nothing, and every hash runs on the lane of its
//! [`HashSite`]. Each output equals the native reference of
//! [`crate::controls`] for every witness, honest or not, so the digests the
//! circuit compares with the native evaluation never diverge.

use iroha_pasta::poseidon::PoseidonField;
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{
    AbsorbInput, Bit, GlueChip, SpongeChip, U64, U128, Uint, UintChip, Word,
};

use crate::{
    circuit::{HashSite, LanePlan, UsagePath},
    controls::{
        QUOTA_CHARGES_PER_KIND, QuotaCharge, QuotaWitness, SEGMENT_BASE_MAX, SEGMENT_POSITIONS,
        WindowSegment,
    },
    tree::{
        BLACKLIST_DEPTH, BLACKLIST_LEAF_DOMAIN, BLACKLIST_NODE_DOMAIN, BlacklistGap, QUOTA_DEPTH,
        QUOTA_NODE_DOMAIN, QUOTA_USAGE_DOMAIN, QUOTA_USAGE_NODE_DOMAIN, QUOTA_WINDOW_DOMAIN,
        WINDOW_DAILY, WINDOW_KINDS,
    },
};

/// The two `u128` limbs of a 32-byte digest, low half first (the G1
/// element rule).
fn limbs_of(bytes: &[u8; 32]) -> [u128; 2] {
    let mut lo = [0_u8; 16];
    let mut hi = [0_u8; 16];
    lo.copy_from_slice(&bytes[..16]);
    hi.copy_from_slice(&bytes[16..]);
    [u128::from_le_bytes(lo), u128::from_le_bytes(hi)]
}

/// A value of the witness (unknown during key generation).
fn value<T, V>(source: Option<&T>, read: impl FnOnce(&T) -> V) -> Value<V> {
    source.map_or_else(Value::unknown, |source| Value::known(read(source)))
}

/// The sponge of `site`'s lane.
fn sponge<'s, F: PoseidonField>(
    sponges: &'s mut [SpongeChip<F>],
    plan: &LanePlan,
    site: HashSite,
) -> Result<&'s mut SpongeChip<F>, Error> {
    sponges.get_mut(plan.lane_of(site)).ok_or(Error::Synthesis)
}

/// The chips a control check lays out on.
pub struct ControlChips<'c, 'u, F: PoseidonField> {
    /// Checked arithmetic on the glue and running-sum chips.
    pub uint: &'c mut UintChip<'u, F>,
    /// One sponge per lane.
    pub sponges: &'c mut [SpongeChip<F>],
    /// The lane of every hash site.
    pub plan: &'c LanePlan,
}

impl<F: PoseidonField> ControlChips<'_, '_, F> {
    fn glue(&mut self) -> &mut GlueChip<F> {
        self.uint.glue()
    }

    /// `n` boolean witnesses: the low `n` bits of `index`.
    fn index_bits(
        &mut self,
        region: &mut Region<'_, F>,
        index: Value<u64>,
        n: usize,
    ) -> Result<Vec<Bit<F>>, Error> {
        (0..n)
            .map(|bit| {
                self.glue()
                    .boolean(region, index.map(|index| (index >> bit) & 1 == 1))
            })
            .collect()
    }

    /// Free witnesses, four per glue row.
    fn words(
        &mut self,
        region: &mut Region<'_, F>,
        values: &[Value<F>],
    ) -> Result<Vec<Word<F>>, Error> {
        self.glue().witnesses(region, values)
    }

    /// The root over `node` at the position `bits` (height 0 first) with
    /// `siblings`, nodes `P(node_domain, [left, right])` on `site`'s lane.
    fn merkle_root(
        &mut self,
        region: &mut Region<'_, F>,
        site: HashSite,
        node_domain: u64,
        node: &Word<F>,
        bits: &[Bit<F>],
        siblings: &[Word<F>],
    ) -> Result<Word<F>, Error> {
        if bits.len() != siblings.len() {
            return Err(Error::Synthesis);
        }
        let mut current = node.clone();
        for (bit, sibling) in bits.iter().zip(siblings) {
            // The running node is the right child where the bit is set.
            let left = self.glue().select(region, bit, sibling, &current)?;
            let right = self.glue().linear(
                region,
                &[(F::ONE, &current), (F::ONE, sibling), (-F::ONE, &left)],
                F::ZERO,
            )?;
            current = sponge(self.sponges, self.plan, site)?.hash(
                region,
                node_domain,
                &[AbsorbInput::Word(&left), AbsorbInput::Word(&right)],
            )?;
        }
        Ok(current)
    }

    /// `P(domain, inputs)` on `site`'s lane.
    fn hash(
        &mut self,
        region: &mut Region<'_, F>,
        site: HashSite,
        domain: u64,
        inputs: &[AbsorbInput<'_, F>],
    ) -> Result<Word<F>, Error> {
        sponge(self.sponges, self.plan, site)?.hash(region, domain, inputs)
    }

    /// Constrains `gate (x - y) = 0`.
    fn assert_gated_equal(
        &mut self,
        region: &mut Region<'_, F>,
        gate: &Bit<F>,
        x: &Word<F>,
        y: &Word<F>,
    ) -> Result<(), Error> {
        let difference = self.glue().sub(region, x, y)?;
        let gated = self.glue().mul(region, gate.word(), &difference)?;
        GlueChip::assert_constant(region, &gated, F::ZERO)
    }

    /// Constrains `gate -> bit` (`gate (1 - bit) = 0`).
    fn assert_gated_true(
        &mut self,
        region: &mut Region<'_, F>,
        gate: &Bit<F>,
        bit: &Bit<F>,
    ) -> Result<(), Error> {
        let not = self.glue().not(region, bit)?;
        let gated = self.glue().mul(region, gate.word(), not.word())?;
        GlueChip::assert_constant(region, &gated, F::ZERO)
    }

    /// The bit `a + b`, for bits that are never both set.
    fn exclusive_or(
        &mut self,
        region: &mut Region<'_, F>,
        bits: &[&Bit<F>],
    ) -> Result<Bit<F>, Error> {
        let mut terms = bits.iter();
        let first = terms.next().ok_or(Error::Synthesis)?;
        let mut sum = first.word().clone();
        for bit in terms {
            sum = self.glue().add(region, &sum, bit.word())?;
        }
        self.glue().assert_bool(region, &sum)
    }

    /// The bit `a OR b` (`a + b - a b`).
    fn or(&mut self, region: &mut Region<'_, F>, a: &Bit<F>, b: &Bit<F>) -> Result<Bit<F>, Error> {
        let product = self.glue().mul(region, a.word(), b.word())?;
        let sum = self.glue().linear(
            region,
            &[(F::ONE, a.word()), (F::ONE, b.word()), (-F::ONE, &product)],
            F::ZERO,
        )?;
        self.glue().assert_bool(region, &sum)
    }

    /// `[a < b]` in limb order for two-limb values `(lo, hi)`.
    fn limb_less(
        &mut self,
        region: &mut Region<'_, F>,
        a: &[U128<F>; 2],
        b: &[U128<F>; 2],
    ) -> Result<Bit<F>, Error> {
        let high_less = self.uint.lt(region, &a[1], &b[1])?;
        let high_equal = self.glue().is_equal(region, a[1].word(), b[1].word())?;
        let low_less = self.uint.lt(region, &a[0], &b[0])?;
        let less =
            self.glue()
                .mul_add(region, high_equal.word(), low_less.word(), high_less.word())?;
        self.glue().assert_bool(region, &less)
    }

    /// The blacklist rule: while a list is held (`version != 0`), `gap`
    /// shows `account` (two limbs, range-checked here) absent from the list
    /// `root`.
    pub fn blacklist(
        &mut self,
        region: &mut Region<'_, F>,
        version: &Word<F>,
        root: &Word<F>,
        account: [&Word<F>; 2],
        gap: Option<&BlacklistGap<F>>,
    ) -> Result<(), Error> {
        let none = self.glue().is_zero(region, version)?;
        let held = self.glue().not(region, &none)?;
        let account = [
            self.uint.range_check::<128>(region, account[0])?,
            self.uint.range_check::<128>(region, account[1])?,
        ];
        let reads: [fn(&BlacklistGap<F>) -> u128; 4] = [
            |gap| limbs_of(&gap.lower)[0],
            |gap| limbs_of(&gap.lower)[1],
            |gap| limbs_of(&gap.upper)[0],
            |gap| limbs_of(&gap.upper)[1],
        ];
        let mut limbs = Vec::with_capacity(4);
        for read in reads {
            limbs.push(self.uint.assign_u128(region, value(gap, read))?);
        }
        let [lower_lo, lower_hi, upper_lo, upper_hi]: [U128<F>; 4] =
            limbs.try_into().map_err(|_| Error::Synthesis)?;
        let lower = [lower_lo, lower_hi];
        let upper = [upper_lo, upper_hi];
        let site = HashSite::BlacklistGap;
        let leaf = self.hash(
            region,
            site,
            BLACKLIST_LEAF_DOMAIN,
            &[
                AbsorbInput::Word(lower[0].word()),
                AbsorbInput::Word(lower[1].word()),
                AbsorbInput::Word(upper[0].word()),
                AbsorbInput::Word(upper[1].word()),
            ],
        )?;
        let bits = self.index_bits(
            region,
            value(gap, |gap| u64::from(gap.leaf_index)),
            BLACKLIST_DEPTH,
        )?;
        let siblings: Vec<Value<F>> = (0..BLACKLIST_DEPTH)
            .map(|height| value(gap, |gap| gap.siblings[height]))
            .collect();
        let siblings = self.words(region, &siblings)?;
        let opened =
            self.merkle_root(region, site, BLACKLIST_NODE_DOMAIN, &leaf, &bits, &siblings)?;
        self.assert_gated_equal(region, &held, &opened, root)?;
        let above_lower = self.limb_less(region, &lower, &account)?;
        let below_upper = self.limb_less(region, &account, &upper)?;
        let inside = self.glue().and(region, &above_lower, &below_upper)?;
        self.assert_gated_true(region, &held, &inside)
    }

    /// The quota rule: every touched window of `windows_root` is charged
    /// `gross` within its limit, every defined kind is touched, and the
    /// returned word is the quota-usage root after the charges.
    #[allow(
        clippy::too_many_arguments,
        reason = "the committed roots, the accepted interval and the gross debit the rule reads"
    )]
    pub fn quota(
        &mut self,
        region: &mut Region<'_, F>,
        windows_root: &Word<F>,
        usage_root: &Word<F>,
        lower: &U64<F>,
        upper: &U64<F>,
        gross: &U128<F>,
        witness: Option<&QuotaWitness<F>>,
    ) -> Result<Word<F>, Error> {
        let mut root = usage_root.clone();
        for (kind_index, kind) in WINDOW_KINDS.into_iter().enumerate() {
            let segment = witness.map(|witness| &witness.segments[kind_index]);
            let positions = self.segment(
                region,
                kind_index,
                kind,
                windows_root,
                lower,
                upper,
                segment,
            )?;
            // Positions 1 and 2 are the charge candidates, in window order.
            let candidates = positions.iter().skip(1).take(QUOTA_CHARGES_PER_KIND);
            for (offset, position) in candidates.enumerate() {
                let charge_index = kind_index * QUOTA_CHARGES_PER_KIND + offset;
                let charge = witness.map(|witness| &witness.charges[charge_index]);
                root = self.charge(region, charge_index, kind, position, &root, gross, charge)?;
            }
        }
        Ok(root)
    }

    /// One window kind's segment: its slot openings, the boundary rules and
    /// the coverage rule; returns every position's window cells and bits.
    #[allow(
        clippy::too_many_arguments,
        reason = "the segment, its kind and the committed values the rules read"
    )]
    fn segment(
        &mut self,
        region: &mut Region<'_, F>,
        kind_index: usize,
        kind: u8,
        windows_root: &Word<F>,
        lower: &U64<F>,
        upper: &U64<F>,
        segment: Option<&WindowSegment<F>>,
    ) -> Result<Vec<Position<F>>, Error> {
        // The base (`0..=64`) and the positions it makes real.
        let base: Uint<F, 7> = self
            .uint
            .assign::<7>(region, value(segment, |segment| u128::from(segment.base)))?;
        let max = self
            .uint
            .constant::<7>(region, u128::from(SEGMENT_BASE_MAX))?;
        self.uint.assert_le(region, &base, &max)?;
        let first_virtual = self.glue().is_zero(region, base.word())?;
        let present_first = self.glue().not(region, &first_virtual)?;
        let at_max =
            self.glue()
                .add_constant(region, base.word(), -F::from(u64::from(SEGMENT_BASE_MAX)))?;
        let second_virtual = self.glue().is_zero(region, &at_max)?;
        let present_second = self.glue().not(region, &second_virtual)?;
        let below_63 = self
            .uint
            .constant::<7>(region, u128::from(SEGMENT_BASE_MAX - 1))?;
        let present_third = self.uint.lt(region, &base, &below_63)?;
        let below_62 = self
            .uint
            .constant::<7>(region, u128::from(SEGMENT_BASE_MAX - 2))?;
        let present_fourth = self.uint.lt(region, &base, &below_62)?;
        let present = [present_first, present_second, present_third, present_fourth];
        let mut positions = Vec::with_capacity(SEGMENT_POSITIONS);
        for (index, present) in present.into_iter().enumerate() {
            let slot = segment.map(|segment| &segment.slots[index]);
            let slot_index = segment.map(|segment| segment.slot(index));
            positions.push(self.position(
                region,
                HashSite::QuotaWindow(
                    u8::try_from(kind_index).map_err(|_| Error::Synthesis)?,
                    u8::try_from(index).map_err(|_| Error::Synthesis)?,
                ),
                kind,
                index,
                &base,
                present,
                windows_root,
                lower,
                upper,
                slot.map(|slot| (slot, slot_index.unwrap_or(0))),
            )?);
        }
        let [first, second, third, last] = positions.as_slice() else {
            return Err(Error::Synthesis);
        };
        // Position 0: below the kind, or of the kind and ended by `L`.
        let not_first = self.glue().not(region, &first.present)?;
        let below = if kind == WINDOW_DAILY {
            not_first
        } else {
            self.exclusive_or(region, &[&not_first, &first.kind_one])?
        };
        let lower_before_end = self.uint.lt(region, lower, &first.end)?;
        let ended = self.glue().not(region, &lower_before_end)?;
        let ended_of_kind = self.glue().and(region, &first.of_kind, &ended)?;
        let pre = self.exclusive_or(region, &[&below, &ended_of_kind])?;
        // Position 3: above the kind, or of the kind and starting after `U`.
        let last_above = self.above(region, kind, last)?;
        let starts_after = self.uint.lt(region, upper, &last.start)?;
        let late_of_kind = self.glue().and(region, &last.of_kind, &starts_after)?;
        let post = self.exclusive_or(region, &[&last_above, &late_of_kind])?;
        let bounded = self.glue().and(region, &pre, &post)?;
        GlueChip::assert_constant(region, bounded.word(), F::ONE)?;
        // Coverage: a touched window, or no window of the kind at all.
        let second_above = self.above(region, kind, second)?;
        let absent = self.glue().and(region, &below, &second_above)?;
        let touched = self.or(region, &second.touched, &third.touched)?;
        let covered = self.or(region, &touched, &absent)?;
        GlueChip::assert_constant(region, covered.word(), F::ONE)?;
        Ok(positions)
    }

    /// `[the position is above `kind`]`: a higher kind, an empty slot or
    /// the end boundary.
    fn above(
        &mut self,
        region: &mut Region<'_, F>,
        kind: u8,
        position: &Position<F>,
    ) -> Result<Bit<F>, Error> {
        let after = self.glue().not(region, &position.present)?;
        if kind == WINDOW_DAILY {
            self.exclusive_or(region, &[&position.kind_two, &position.empty, &after])
        } else {
            self.exclusive_or(region, &[&position.empty, &after])
        }
    }

    /// One segment position: the slot index, the window opening (checked
    /// when present) and the window's facts.
    #[allow(
        clippy::too_many_arguments,
        reason = "the position, its segment base and the committed values it reads"
    )]
    fn position(
        &mut self,
        region: &mut Region<'_, F>,
        site: HashSite,
        kind: u8,
        index: usize,
        base: &Uint<F, 7>,
        present: Bit<F>,
        windows_root: &Word<F>,
        lower: &U64<F>,
        upper: &U64<F>,
        slot: Option<(&crate::controls::WindowSlot<F>, u64)>,
    ) -> Result<Position<F>, Error> {
        // slot = present (base - 1 + index), decomposed into six bits.
        let offset = F::from(u64::try_from(index).map_err(|_| Error::Synthesis)?) - F::ONE;
        let shifted = self.glue().add_constant(region, base.word(), offset)?;
        let slot_index = self.glue().mul(region, present.word(), &shifted)?;
        let bits = self.index_bits(region, value(slot.as_ref(), |(_, slot)| *slot), QUOTA_DEPTH)?;
        let mut recomposed = self.glue().linear(
            region,
            &[
                (F::ONE, bits[0].word()),
                (F::from(2_u64), bits[1].word()),
                (F::from(4_u64), bits[2].word()),
            ],
            F::ZERO,
        )?;
        recomposed = self.glue().linear(
            region,
            &[
                (F::ONE, &recomposed),
                (F::from(8_u64), bits[3].word()),
                (F::from(16_u64), bits[4].word()),
            ],
            F::ZERO,
        )?;
        recomposed = self.glue().linear(
            region,
            &[(F::ONE, &recomposed), (F::from(32_u64), bits[5].word())],
            F::ZERO,
        )?;
        GlueChip::assert_equal(region, &recomposed, &slot_index)?;
        // The window: kind in {0, 1, 2}, `u64` times and a `u128` limit.
        let window = slot.as_ref().map(|(slot, _)| slot.window);
        let kind_word = self.glue().witness(
            region,
            value(window.as_ref(), |window| F::from(u64::from(window.kind))),
        )?;
        let minus_one = self.glue().add_constant(region, &kind_word, -F::ONE)?;
        let minus_two = self
            .glue()
            .add_constant(region, &kind_word, -F::from(2_u64))?;
        let product = self.glue().mul(region, &kind_word, &minus_one)?;
        let product = self.glue().mul(region, &product, &minus_two)?;
        GlueChip::assert_constant(region, &product, F::ZERO)?;
        let start = self
            .uint
            .assign_u64(region, value(window.as_ref(), |window| window.start_ms))?;
        let end = self
            .uint
            .assign_u64(region, value(window.as_ref(), |window| window.end_ms))?;
        let limit = self
            .uint
            .assign_u128(region, value(window.as_ref(), |window| window.limit))?;
        let leaf = self.hash(
            region,
            site,
            QUOTA_WINDOW_DOMAIN,
            &[
                AbsorbInput::Word(&kind_word),
                AbsorbInput::Word(start.word()),
                AbsorbInput::Word(end.word()),
                AbsorbInput::Word(limit.word()),
            ],
        )?;
        let siblings: Vec<Value<F>> = (0..QUOTA_DEPTH)
            .map(|height| value(slot.as_ref(), |(slot, _)| slot.siblings[height]))
            .collect();
        let siblings = self.words(region, &siblings)?;
        let opened = self.merkle_root(region, site, QUOTA_NODE_DOMAIN, &leaf, &bits, &siblings)?;
        self.assert_gated_equal(region, &present, &opened, windows_root)?;
        // The window's facts.
        let is_empty = self.glue().is_zero(region, &kind_word)?;
        let is_one = self.glue().is_zero(region, &minus_one)?;
        let is_two = self.glue().is_zero(region, &minus_two)?;
        let empty = self.glue().and(region, &present, &is_empty)?;
        let kind_one = self.glue().and(region, &present, &is_one)?;
        let kind_two = self.glue().and(region, &present, &is_two)?;
        let of_kind = if kind == WINDOW_DAILY {
            kind_one.clone()
        } else {
            kind_two.clone()
        };
        let starts_late = self.uint.lt(region, upper, &start)?;
        let started = self.glue().not(region, &starts_late)?;
        let not_ended = self.uint.lt(region, lower, &end)?;
        let intersects = self.glue().and(region, &started, &not_ended)?;
        let touched = self.glue().and(region, &of_kind, &intersects)?;
        Ok(Position {
            slot_index,
            present,
            kind_one,
            kind_two,
            empty,
            of_kind,
            touched,
            start,
            end,
            limit,
        })
    }

    /// One charge candidate: when `position` is touched, the usage leaf of
    /// its aligned window slot is updated with `used + gross <= limit`;
    /// returns the usage root after it.
    #[allow(
        clippy::too_many_arguments,
        reason = "the charge, its window and the running usage root"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "one straight-line layout of the aligned array update"
    )]
    fn charge(
        &mut self,
        region: &mut Region<'_, F>,
        charge_index: usize,
        kind: u8,
        position: &Position<F>,
        root: &Word<F>,
        gross: &U128<F>,
        charge: Option<&QuotaCharge<F>>,
    ) -> Result<Word<F>, Error> {
        let index = u8::try_from(charge_index).map_err(|_| Error::Synthesis)?;
        let taken = &position.touched;
        let kind_value = F::from(u64::from(kind));
        // used' = used + gross < 2^128, and taken -> used' <= limit.
        let used = self
            .uint
            .assign_u128(region, value(charge, |charge| charge.used))?;
        let used_after = self.uint.checked_add(region, &used, gross)?;
        let headroom = self
            .glue()
            .sub(region, position.limit.word(), used_after.word())?;
        let gated_headroom = self.glue().mul(region, taken.word(), &headroom)?;
        self.uint
            .range()
            .range_check(region, &gated_headroom, 128)?;
        // The old and new usage values.
        let values = HashSite::UsageValues(index);
        let old_value = self.hash(
            region,
            values,
            QUOTA_USAGE_DOMAIN,
            &[
                AbsorbInput::Constant(kind_value),
                AbsorbInput::Word(position.start.word()),
                AbsorbInput::Word(position.end.word()),
                AbsorbInput::Word(used.word()),
            ],
        )?;
        let new_value = self.hash(
            region,
            values,
            QUOTA_USAGE_DOMAIN,
            &[
                AbsorbInput::Constant(kind_value),
                AbsorbInput::Word(position.start.word()),
                AbsorbInput::Word(position.end.word()),
                AbsorbInput::Word(used_after.word()),
            ],
        )?;
        // The array index is explicitly linked to the window slot. Paths
        // use six bits and the same siblings before and after the in-place write.
        let slot = self
            .uint
            .assign::<6>(region, value(charge, |charge| u128::from(charge.slot)))?;
        self.assert_gated_equal(region, taken, slot.word(), &position.slot_index)?;
        let bits = self.index_bits(
            region,
            value(charge, |charge| u64::from(charge.slot)),
            QUOTA_DEPTH,
        )?;
        let mut recomposed = self.glue().constant(region, F::ZERO)?;
        for (height, bit) in bits.iter().enumerate() {
            recomposed = self.glue().linear(
                region,
                &[
                    (F::ONE, &recomposed),
                    (F::from(1_u64 << height), bit.word()),
                ],
                F::ZERO,
            )?;
        }
        GlueChip::assert_equal(region, &recomposed, slot.word())?;
        let siblings: Vec<_> = (0..QUOTA_DEPTH)
            .map(|height| value(charge, |charge| charge.siblings[height]))
            .collect();
        let siblings = self.words(region, &siblings)?;
        let opened = self.merkle_root(
            region,
            HashSite::UsagePath(index, UsagePath::LeafBefore),
            QUOTA_USAGE_NODE_DOMAIN,
            &old_value,
            &bits,
            &siblings,
        )?;
        let charged = self.merkle_root(
            region,
            HashSite::UsagePath(index, UsagePath::LeafAfter),
            QUOTA_USAGE_NODE_DOMAIN,
            &new_value,
            &bits,
            &siblings,
        )?;
        self.assert_gated_equal(region, taken, &opened, root)?;
        self.glue().select(region, taken, &charged, root)
    }
}

/// The cells and bits of one segment position.
struct Position<F: PoseidonField> {
    slot_index: Word<F>,
    present: Bit<F>,
    kind_one: Bit<F>,
    kind_two: Bit<F>,
    empty: Bit<F>,
    of_kind: Bit<F>,
    touched: Bit<F>,
    start: U64<F>,
    end: U64<F>,
    limit: U128<F>,
}
