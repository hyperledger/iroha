//! Value-independent placement and guarded replay of exact range requests.

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use super::{SecondaryPhase, SecondaryRangeConfig};
use crate::{
    Word,
    cells::assign_word,
    range::{RangeShape, RunningSumConfig, running_sum_witness},
};
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    Primary(usize),
    Secondary(usize),
}

/// Fixed structural schedule. Construction never reads witness values. Every
/// replayed event still emits its exact range predicate and source equality;
/// cell/fixed guards reject an inaccurate spare-cell inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecondaryPlan {
    widths: Vec<usize>,
    places: Vec<Place>,
    phases: Vec<Option<SecondaryPhase>>,
    pattern: Vec<u8>,
    control: Vec<u8>,
    primary_end: usize,
}
impl SecondaryPlan {
    /// Packs a complete ordered list of noncached range events into structurally
    /// free phase rows. `None` rows are owned elsewhere. Rows before sixteen
    /// remain the direct public prefix. Every endpoint protects the next-state
    /// query; no selected check crosses into another owner.
    ///
    /// # Errors
    /// Invalid widths/phases, failure to converge, or insufficient row capacity.
    pub fn new(widths: Vec<usize>, phases: Vec<Option<SecondaryPhase>>) -> Result<Self, Error> {
        let capacity = phases.len();
        if capacity < 17
            || phases[..16].iter().any(Option::is_some)
            || widths.iter().any(|bits| *bits == 0 || *bits > 252)
        {
            return Err(Error::Synthesis);
        }
        let mut segments = Vec::new();
        let mut row = 16;
        while row < capacity {
            let Some(phase) = phases[row] else {
                row += 1;
                continue;
            };
            let start = row;
            let radix = phase.radix_bits();
            while row < capacity && phases[row].is_some_and(|p| p.radix_bits() == radix) {
                row += 1;
            }
            segments.push((radix, start, row));
        }
        let mut forbidden = vec![false; capacity];
        for (_, _, end) in &segments {
            forbidden[end - 1] = true;
        }
        let mut target = BTreeMap::<usize, usize>::new();
        for bits in &widths {
            *target.entry(*bits).or_default() += 1;
        }
        for _ in 0..128 {
            let mut discard = target.clone();
            // Oversized intermediate tapes permit convergence from the full
            // baseline; only the finalized plan must fit the declared domain.
            let tape_len = capacity.max(
                widths
                    .iter()
                    .try_fold(16_usize, |sum, b| sum.checked_add(b.div_ceil(15) + 1))
                    .ok_or(Error::BoundsFailure)?,
            );
            let mut pattern = vec![0_u8; tape_len];
            let mut control = vec![0_u8; tape_len];
            let mut places = Vec::with_capacity(widths.len());
            let mut primary_end = 16_usize;
            for bits in &widths {
                if let Some(count) = discard.get_mut(bits)
                    && *count > 0
                {
                    *count -= 1;
                    places.push(Place::Secondary(usize::MAX));
                    continue;
                }
                let rows = bits.div_ceil(15);
                let top_bits = (bits - 1) % 15 + 1;
                if top_bits >= 3 {
                    while forbidden
                        .get(
                            primary_end
                                .checked_add(rows - 1)
                                .ok_or(Error::BoundsFailure)?,
                        )
                        .copied()
                        .unwrap_or(false)
                    {
                        primary_end = primary_end.checked_add(1).ok_or(Error::BoundsFailure)?;
                    }
                }
                places.push(Place::Primary(primary_end));
                let end = primary_end.checked_add(rows).ok_or(Error::BoundsFailure)?;
                if end > pattern.len() {
                    pattern.resize(end, 0);
                    control.resize(end, 0);
                }
                pattern[primary_end..end - 1].fill(1);
                let top = end - 1;
                pattern[top] = match top_bits {
                    1 => 3,
                    2 => 4,
                    _ => 2,
                };
                if top_bits >= 3 {
                    control[top] = u8::try_from(top_bits).map_err(|_| Error::BoundsFailure)?;
                }
                primary_end = end;
            }
            let mut remaining = target.clone();
            let mut placements = BTreeMap::<usize, Vec<usize>>::new();
            for (radix, start, end) in &segments {
                let mut row = *start;
                let order: &[usize] = if *radix == 15 {
                    &[128, 87, 81]
                } else {
                    &[93, 81, 128, 87]
                };
                while row < *end {
                    let bits = order.iter().copied().find(|bits| {
                        let rows = bits.div_ceil(*radix);
                        remaining.get(bits).copied().unwrap_or(0) > 0
                            && row + rows <= *end
                            && pattern[row + rows - 1] != 2
                    });
                    if let Some(bits) = bits {
                        placements.entry(bits).or_default().push(row);
                        *remaining.get_mut(&bits).ok_or(Error::Synthesis)? -= 1;
                        row += bits.div_ceil(*radix);
                    } else {
                        row += 1;
                    }
                }
            }
            let counts = placements
                .iter()
                .map(|(bits, rows)| (*bits, rows.len()))
                .collect::<BTreeMap<_, _>>();
            if counts == target {
                if primary_end > capacity {
                    return Err(Error::BoundsFailure);
                }
                for rows in placements.values_mut() {
                    rows.reverse();
                }
                for (bits, place) in widths.iter().zip(&mut places) {
                    if matches!(place, Place::Secondary(_)) {
                        *place = Place::Secondary(
                            placements
                                .get_mut(bits)
                                .and_then(Vec::pop)
                                .ok_or(Error::Synthesis)?,
                        );
                    }
                }
                pattern.truncate(capacity);
                control.truncate(capacity);
                for (row, phase) in phases.iter().enumerate() {
                    if phase.is_some() && pattern[row] == 0 {
                        pattern[row] = 1;
                    }
                }
                for (bits, place) in widths.iter().zip(&places) {
                    if let Place::Secondary(start) = place {
                        let radix = phases[*start].ok_or(Error::Synthesis)?.radix_bits();
                        let rows = bits.div_ceil(radix);
                        for row in *start..start + rows {
                            if pattern[row] != 2 {
                                control[row] = if row + 1 < start + rows {
                                    1
                                } else {
                                    match bits {
                                        81 | 93 => 0,
                                        87 => 2,
                                        128 => 3,
                                        _ => return Err(Error::Synthesis),
                                    }
                                };
                            }
                        }
                    }
                }
                // A last-row dummy step would read a blinding row. Every
                // primary step's successor must stay in the usable domain.
                if pattern[capacity - 1] == 1 {
                    return Err(Error::BoundsFailure);
                }
                return Ok(Self {
                    widths,
                    places,
                    phases,
                    pattern,
                    control,
                    primary_end,
                });
            }
            target = counts;
        }
        Err(Error::Synthesis)
    }
    #[cfg(test)]
    pub(crate) fn real_primary_rows(&self) -> std::collections::BTreeSet<usize> {
        self.widths
            .iter()
            .zip(&self.places)
            .flat_map(|(bits, place)| match place {
                Place::Primary(start) => *start..start + bits.div_ceil(15),
                Place::Secondary(_) => 0..0,
            })
            .collect()
    }
    /// Number of real noncached range requests this program must replay.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.widths.len()
    }
    /// Highest real primary row plus one, excluding zero-only filler steps.
    #[must_use]
    pub const fn primary_end(&self) -> usize {
        self.primary_end
    }
    /// Fixed usable-domain size.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.phases.len()
    }
}

/// Shared synthesis-local replay, including all chip clones.
#[derive(Clone, Debug)]
pub struct Replay<F: PastaField>(Rc<RefCell<ReplayState<F>>>);
#[derive(Debug)]
struct ReplayState<F: PastaField> {
    plan: SecondaryPlan,
    secondary: SecondaryRangeConfig,
    primary: RunningSumConfig,
    next: usize,
    finished: bool,
    primary_values: Vec<Option<Value<F>>>,
    secondary_values: Vec<Option<Value<F>>>,
}
impl<F: PastaField> Replay<F> {
    pub(crate) fn new(
        plan: SecondaryPlan,
        secondary: SecondaryRangeConfig,
        primary: RunningSumConfig,
    ) -> Result<Self, Error> {
        if primary.compact_pattern_codes() != 4
            || primary.compact_patterns() != Some((secondary.primary, secondary.control))
        {
            return Err(Error::Synthesis);
        }
        let len = plan.capacity();
        Ok(Self(Rc::new(RefCell::new(ReplayState {
            plan,
            secondary,
            primary,
            next: 0,
            finished: false,
            primary_values: vec![None; len],
            secondary_values: vec![None; len],
        }))))
    }
    pub(crate) fn next_row(&self) -> usize {
        let state = self.0.borrow();
        state
            .plan
            .pattern
            .iter()
            .rposition(|code| *code != 0)
            .map_or(16, |row| {
                row + 1 + usize::from(state.plan.pattern[row] == 1)
            })
    }
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        value: Value<F>,
        bits: usize,
    ) -> Result<Word<F>, Error> {
        let mut state = self.0.borrow_mut();
        if state.finished || state.plan.widths.get(state.next) != Some(&bits) {
            return Err(Error::Synthesis);
        }
        let place = state.plan.places[state.next];
        state.next += 1;
        match place {
            Place::Primary(start) => {
                let mut shape =
                    RangeShape::new(bits, state.primary.limb_bits()).ok_or(Error::Synthesis)?;
                shape.rows = shape.limbs;
                let entries = value
                    .map(|v| running_sum_witness(&v, shape))
                    .transpose_vec(shape.rows)?;
                let mut root = None;
                for (offset, entry) in entries.into_iter().enumerate() {
                    let row = start + offset;
                    state.fixed(region, row)?;
                    region.reserve_advice(state.primary.column(), row)?;
                    let word = assign_word(region, state.primary.column(), row, entry)?;
                    state.primary_values[row] = Some(entry);
                    if root.is_none() {
                        root = Some(word);
                    }
                }
                root.ok_or(Error::Synthesis)
            }
            Place::Secondary(start) => {
                let radix = state.plan.phases[start]
                    .ok_or(Error::Synthesis)?
                    .radix_bits();
                let mut shape =
                    RangeShape::new(bits, super::LimbBits::new(radix).ok_or(Error::Synthesis)?)
                        .ok_or(Error::Synthesis)?;
                shape.rows = shape.limbs;
                let entries = value
                    .map(|v| running_sum_witness(&v, shape))
                    .transpose_vec(shape.rows)?;
                let mut root = None;
                for (offset, entry) in entries.into_iter().enumerate() {
                    let row = start + offset;
                    state.fixed(region, row)?;
                    let phase = state.plan.phases[row].ok_or(Error::Synthesis)?;
                    let word = state.secondary.assign_digits(
                        region,
                        row,
                        phase,
                        bits,
                        offset + 1 == shape.rows,
                        entry,
                    )?;
                    state.secondary_values[row] = Some(entry);
                    if root.is_none() {
                        root = Some(word);
                    }
                }
                root.ok_or(Error::Synthesis)
            }
        }
    }
    pub(crate) fn finish(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        if state.finished || state.next != state.plan.widths.len() {
            return Err(Error::Synthesis);
        }
        for row in (16..state.plan.capacity()).rev() {
            if let Some(phase) = state.plan.phases[row] {
                state.fixed(region, row)?;
                if state.secondary_values[row].is_none() {
                    let entry = if state.plan.pattern[row] == 2 {
                        let next = state
                            .secondary_values
                            .get(row + 1)
                            .copied()
                            .flatten()
                            .ok_or(Error::Synthesis)?;
                        next.map(|v| v * F::from(1 << phase.radix_bits()))
                    } else {
                        Value::known(F::ZERO)
                    };
                    state
                        .secondary
                        .assign_zero_digits(region, row, phase, entry)?;
                    state.secondary_values[row] = Some(entry);
                }
            }
            if state.plan.pattern[row] != 0 && state.primary_values[row].is_none() {
                if state.plan.pattern[row] != 1 {
                    return Err(Error::Synthesis);
                }
                state.fixed(region, row)?;
                let next = state
                    .primary_values
                    .get(row + 1)
                    .copied()
                    .flatten()
                    .unwrap_or(Value::known(F::ZERO));
                let entry = next.map(|v| v * F::from(1 << 15));
                region.reserve_advice(state.primary.column(), row)?;
                assign_word(region, state.primary.column(), row, entry)?;
                state.primary_values[row] = Some(entry);
                // The lookup queries the successor even when its value is
                // zero; explicitly assign that otherwise inactive cell.
                if state
                    .primary_values
                    .get(row + 1)
                    .is_some_and(Option::is_none)
                {
                    region.reserve_advice(state.primary.column(), row + 1)?;
                    assign_word(
                        region,
                        state.primary.column(),
                        row + 1,
                        Value::known(F::ZERO),
                    )?;
                    state.primary_values[row + 1] = Some(Value::known(F::ZERO));
                }
            }
        }
        state.finished = true;
        Ok(())
    }
}
impl<F: PastaField> ReplayState<F> {
    fn fixed(&self, region: &mut Region<'_, F>, row: usize) -> Result<(), Error> {
        for (col, value) in [
            (self.secondary.primary, self.plan.pattern[row]),
            (self.secondary.control, self.plan.control[row]),
        ] {
            let value = F::from(u64::from(value));
            region.expect_fixed(col, row, value)?;
            region.assign_fixed(col, row, value)?;
        }
        Ok(())
    }
}
