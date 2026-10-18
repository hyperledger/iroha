//! Bounded private inverse windows selected only by public column geometry.
//!
//! Every factor and temporary recurrence has an explicit clearing owner.
//! This helper does not establish constant work for the surrounding private row constructors.

use super::*;

pub(super) const PAIRS: usize = 3 * BATCH;
pub(super) const GATE: usize = 0;
pub(super) const DENOMINATOR: usize = 1;
const ACTIVE: usize = 2;
const NONZERO: usize = 3;
pub(super) const NEUTRAL: usize = 4;
const PREFIX: usize = 5;
const INVERSE: usize = 6;
const ZERO: usize = 7;

/// Each gate, denominator, normalized factor, prefix and result has one owner.
/// The four working cells own product, inverse product, temporary inverse and mask.
pub(super) struct InverseWindowV1 {
    pub(super) pairs: [[F; 8]; PAIRS],
    work: [F; 4],
    pub(super) count: usize,
    pub(super) cursor: usize,
}
impl InverseWindowV1 {
    pub(super) fn new_v1() -> Self {
        Self {
            pairs: [[F::ZERO; 8]; PAIRS],
            work: [F::ZERO; 4],
            count: 0,
            cursor: 0,
        }
    }
    pub(super) fn collect_v1(&mut self, gate: F, denominator: F) -> (F, F) {
        assert!(self.count < PAIRS, "public inverse window capacity");
        let pair = &mut self.pairs[self.count];
        pair[GATE] = gate;
        pair[DENOMINATOR] = denominator;
        self.count += 1;
        // Preserve the active malformed-input panic and inactive tolerance.
        // Select into existing clearing storage before validation so the
        // admitted precondition has the same outcome for every private gate.
        // This slot is replaced by the neutralized nonzero factor in invert_v1.
        pair[ACTIVE] = F(u64::from(gate != F::ZERO));
        pair[NEUTRAL] = F(denominator.0 & 0_u64.wrapping_sub(pair[ACTIVE].0));
        assert!(
            pair[NEUTRAL].0 < crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1,
            "nonzero canonical Goldilocks value is invertible"
        );
        (F::ZERO, F::ZERO)
    }
    pub(super) fn invert_v1(&mut self) {
        // The empty-window branch is determined solely by public descriptors.
        if self.count == 0 {
            return;
        }
        self.work[0] = F::ONE;
        for pair in &mut self.pairs[..self.count] {
            pair[ACTIVE] = F(u64::from(pair[GATE] != F::ZERO));
            pair[NONZERO] = F(u64::from(pair[DENOMINATOR] != F::ZERO));
            self.work[3].0 = 0_u64.wrapping_sub(pair[ACTIVE].0 & pair[NONZERO].0);
            // A private inactive/noncanonical denominator never enters field
            // arithmetic. Every factor actually multiplied here is canonical nonzero.
            pair[NEUTRAL].0 = (pair[DENOMINATOR].0 & self.work[3].0) | (1 & !self.work[3].0);
            pair[PREFIX] = self.work[0];
            self.work[0] = self.work[0].mul(pair[NEUTRAL]);
        }
        self.work[1] = self.work[0].inverse_or_zero_canonical_v1();
        for pair in self.pairs[..self.count].iter_mut().rev() {
            self.work[2] = self.work[1].mul(pair[PREFIX]);
            self.work[1] = self.work[1].mul(pair[NEUTRAL]);
            pair[INVERSE] = self.work[2].mul(pair[ACTIVE]).mul(pair[NONZERO]);
            pair[ZERO] = pair[ACTIVE].mul(F::ONE.sub(pair[NONZERO]));
        }
    }
    pub(super) fn replay_v1(&mut self, gate: F, denominator: F) -> (F, F) {
        assert!(
            self.cursor < self.count,
            "public inverse window replay count"
        );
        let pair = &self.pairs[self.cursor];
        self.cursor += 1;
        // Invariant check only: the same immutable row and public descriptor
        // must reproduce both inputs. Never print private fields on a failure.
        assert!(
            (pair[GATE] == gate) & (pair[DENOMINATOR] == denominator),
            "inverse replay inputs changed"
        );
        (pair[ZERO], pair[INVERSE])
    }
    pub(super) fn finish_v1(&self) {
        assert_eq!(self.cursor, self.count);
    }
}
impl Drop for InverseWindowV1 {
    fn drop(&mut self) {
        for pair in &mut self.pairs {
            zeroize_fields_v1(pair);
        }
        zeroize_fields_v1(&mut self.work);
    }
}

pub(super) fn pairs_for_column_v1(column: usize) -> usize {
    if (AUX_NUMERIC_INVERSE..AUX_NUMERIC_ZERO_SUM + numeric::LOOKUP_LANES_V1).contains(&column) {
        1
    } else if profile_lookup_aux_column_descriptor_v1(column).is_some() {
        3
    } else if grammar_lookup_aux_column_descriptor_v1(column).is_some()
        || lookup_aux_column_descriptor_v1(column).is_some()
    {
        2
    } else {
        0
    }
}

/// Additional resident private storage is counted explicitly; the existing
/// output batch, row context, numeric event and recurrence values remain charged.
pub(in super::super) const fn scratch_payload_bytes_v1() -> usize {
    super::scalar_scratch_payload_bytes_v1()
        + core::mem::size_of::<InverseWindowV1>()
        + core::mem::size_of::<ColumnStateV1>()
        + core::mem::size_of::<F>()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn step_window_v1(
    states: &mut [ColumnStateV1; BATCH],
    first: usize,
    outputs: &mut [&mut [F]],
    index: usize,
    context: &RowContextV1,
    last: bool,
    der: ZkX509DerStarkChallengesV1,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    centers: &ZkX509ShaUnionCentersV1,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let mut window = InverseWindowV1::new_v1();
    for (offset, (state, target)) in states.iter_mut().zip(outputs.iter_mut()).enumerate() {
        let column = first + offset;
        if pairs_for_column_v1(column) != 0 {
            // Every temporary recurrence cell uses the same clearing owner.
            // Factors depend on the row/challenges, not these prefix sums.
            let mut copy = ColumnStateV1 {
                product: state.product,
                sums: state.sums,
            };
            let before = window.count;
            let mut discarded = copy.step_with_inverse_v1(
                column,
                context,
                last,
                der,
                challenges,
                centers,
                &mut |gate, factor| window.collect_v1(gate, factor),
            )?;
            discarded.zeroize_v1();
            assert_eq!(window.count - before, pairs_for_column_v1(column));
        } else {
            // Execute noninverse columns once, in their original order. This
            // preserves an earlier product/shape error before a later malformed
            // inverse factor. OutputGuard clears these outputs if any later step fails.
            target[index] = state.step_v1(column, context, last, der, challenges, centers)?;
        }
    }
    window.invert_v1();
    for (offset, (state, target)) in states.iter_mut().zip(outputs.iter_mut()).enumerate() {
        if pairs_for_column_v1(first + offset) != 0 {
            target[index] = state.step_with_inverse_v1(
                first + offset,
                context,
                last,
                der,
                challenges,
                centers,
                &mut |gate, factor| window.replay_v1(gate, factor),
            )?;
        }
    }
    window.finish_v1();
    Ok(())
}

/// Fill at most the existing admitted eight-column replay batch without a heap scratch matrix.
pub(in super::super) fn fill_columns_v1(
    material: &ZkX509Rfc5280StarkBaseMaterialV1,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    first: usize,
    outputs: &mut [&mut [F]],
    sha_union: &ZkX509ShaUnionCentersV1,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    fill_with_v1(
        ZK_X509_RFC5280_STARK_TRACE_SIZE_V1,
        first,
        outputs,
        der_challenges,
        challenges,
        sha_union,
        |index| {
            // Adopt the private row before another fallible source operation.
            let mut context = RowContextV1 {
                base: material.base_row(index)?,
                fixed: [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1],
                family: ZkX509Rfc5280StarkFamilyV1::Padding,
            };
            context.fixed = material.fixed_row(index)?;
            context.family = material.schedule.family_and_ordinal(index)?.0;
            Ok(context)
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn fill_with_v1(
    rows: usize,
    first: usize,
    outputs: &mut [&mut [F]],
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    sha_union: &ZkX509ShaUnionCentersV1,
    mut row_at: impl FnMut(usize) -> Result<RowContextV1, ZkX509Rfc5280StarkErrorV1>,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    der_challenges.validate()?;
    challenges.validate()?;
    sha_union.validate_v1()?;
    let end = first
        .checked_add(outputs.len())
        .filter(|&end| end <= ZK_X509_RFC5280_STARK_AUX_WIDTH_V1)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Shape)?;
    if rows == 0
        || rows > ZK_X509_RFC5280_STARK_TRACE_SIZE_V1
        || outputs.is_empty()
        || outputs.len() > BATCH
        || outputs.iter().any(|output| output.len() != rows)
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    // This branch is independent of every private row, gate, factor and recurrence.
    let has_inverse_columns = (first..end).any(|column| pairs_for_column_v1(column) != 0);
    let mut output = OutputGuardV1 {
        outputs,
        committed: false,
    };
    let mut states: [ColumnStateV1; BATCH] = core::array::from_fn(|_| ColumnStateV1::new_v1());
    if first >= AUX_SHA_UNION_CENTERS && end <= AUX_SERIAL_SOURCE_BEFORE {
        for (column, target) in (first..end).zip(output.outputs.iter_mut()) {
            let index = column - AUX_SHA_UNION_CENTERS;
            target.fill(sha_union.products[index / 4][index % 4]);
        }
    } else {
        for index in 0..rows {
            let context = row_at(index)?;
            if has_inverse_columns {
                step_window_v1(
                    &mut states,
                    first,
                    output.outputs,
                    index,
                    &context,
                    index + 1 == rows,
                    der_challenges,
                    challenges,
                    sha_union,
                )?;
            } else {
                for ((column, target), state) in (first..end)
                    .zip(output.outputs.iter_mut())
                    .zip(states.iter_mut())
                {
                    target[index] = state.step_v1(
                        column,
                        &context,
                        index + 1 == rows,
                        der_challenges,
                        challenges,
                        sha_union,
                    )?;
                }
            }
        }
    }
    for ((column, target), state) in (first..end).zip(output.outputs.iter()).zip(states.iter()) {
        state.finish_v1(column, target[rows - 1])?;
    }
    output.committed = true;
    Ok(())
}
