//! Exact fixed-array quota rebuild using a deterministic sorted merge.
//!
//! Both 64-slot inputs have canonical padding and unique sorted real keys.
//! Reversing the new half gives one bitonic sequence; 448 constrained
//! compare/swaps merge it without witness-addressed memory or a probabilistic
//! multiset check. Origin and every payload word move through the same switches.
//! Adjacent equal keys are therefore exactly the old/new matching pairs.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, Word, WordHasher};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{map_effects::MapTransition, state::rest_index as rest};
use crate::{
    tree::{QUOTA_NODE_DOMAIN, QUOTA_USAGE_DOMAIN, QUOTA_USAGE_NODE_DOMAIN, QUOTA_WINDOW_DOMAIN},
    witness::core_index as core,
};

/// The signed share's 64 window leaves and the two usage-array openings.
#[derive(Clone, Debug)]
pub struct QuotaRebuildCells {
    /// Old `(kind, start, end, used)` leaves; all-zero padding follows real leaves.
    pub old: [[Word<Fp>; 4]; 64],
    /// New signed `(kind, start, end, limit)` windows, then all-zero padding.
    pub windows: [[Word<Fp>; 4]; 64],
    /// Successor usage, aligned exactly with `windows`.
    pub used: [Word<Fp>; 64],
    /// Share issue time, bound by A's signed-object transcript.
    pub issued: Word<Fp>,
    /// Exact real-window count from the signed share, in 1..=64.
    pub window_count: Word<Fp>,
}

/// Number of canonical field words bound across the split quota owners.
pub const QUOTA_WITNESS_WORDS: usize = 578;

impl QuotaRebuildCells {
    /// Exact old/window/used arrays and signed issue/count in fixed field order.
    /// A split owner must commit these same words in its recursive context;
    /// independently assigned arrays do not establish a complete rebuild.
    pub fn commitment_words(&self) -> Vec<Word<Fp>> {
        self.old
            .iter()
            .flatten()
            .chain(self.windows.iter().flatten())
            .chain(&self.used)
            .chain([&self.issued, &self.window_count])
            .cloned()
            .collect()
    }
}

/// One fixed authenticated array root in the complete quota rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaRoot {
    /// Old usage array bound to the predecessor state.
    PreviousUsage,
    /// New windows bound to the signed share and successor state.
    ReplacementWindows,
    /// New usage array aligned with the replacement windows.
    ReplacementUsage,
}

// sort key, window key, end, used, start, origin (new=1), active.
#[derive(Clone)]
struct Entry([Word<Fp>; 7]);

fn gate_zero(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    gate: &Bit<Fp>,
    value: &Word<Fp>,
) -> Result<(), Error> {
    let product = uint.glue().mul(region, gate.word(), value)?;
    GlueChip::assert_constant(region, &product, Fp::ZERO)
}
fn gate_equal(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    gate: &Bit<Fp>,
    a: &Word<Fp>,
    b: &Word<Fp>,
) -> Result<(), Error> {
    let delta = uint.glue().sub(region, a, b)?;
    gate_zero(uint, region, gate, &delta)
}
fn gate_true(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    gate: &Bit<Fp>,
    value: &Bit<Fp>,
) -> Result<(), Error> {
    let false_bit = uint.glue().not(region, value)?;
    gate_zero(uint, region, gate, false_bit.word())
}

fn entry(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    fields: &[Word<Fp>; 4],
    used: &Word<Fp>,
    new: bool,
) -> Result<Entry, Error> {
    let kind = uint.range_check::<2>(region, &fields[0])?;
    let zero = uint.glue().is_zero(region, kind.word())?;
    let one = uint.glue().add_constant(region, kind.word(), -Fp::ONE)?;
    let two = uint
        .glue()
        .add_constant(region, kind.word(), -Fp::from(2))?;
    let product = uint.glue().mul(region, &one, &two)?;
    let product = uint.glue().mul(region, &product, kind.word())?;
    GlueChip::assert_constant(region, &product, Fp::ZERO)?;
    let active = uint.glue().not(region, &zero)?;
    let start = uint.range_check::<64>(region, &fields[1])?;
    let end = uint.range_check::<64>(region, &fields[2])?;
    uint.range_check::<128>(region, &fields[3])?;
    uint.range_check::<128>(region, used)?;
    for field in fields.iter().skip(1).chain([used]) {
        gate_zero(uint, region, &zero, field)?;
    }
    let proper = uint.lt(region, &start, &end)?;
    gate_true(uint, region, &active, &proper)?;
    let key = uint.glue().linear(
        region,
        &[
            (Fp::from_u128(1 << 64), kind.word()),
            (Fp::ONE, start.word()),
        ],
        Fp::ZERO,
    )?;
    let origin = uint.glue().constant(region, Fp::from(u64::from(new)))?;
    // Padding sorts after every legal kind/start, independent of its origin.
    let sort = uint.glue().linear(
        region,
        &[
            (Fp::from(2), &key),
            (Fp::ONE, &origin),
            (Fp::from_u128(1 << 67), zero.word()),
        ],
        Fp::ZERO,
    )?;
    Ok(Entry([
        sort,
        key,
        end.word().clone(),
        used.clone(),
        start.word().clone(),
        origin,
        active.word().clone(),
    ]))
}

fn sorted_source(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    entries: &[Entry],
) -> Result<(), Error> {
    for pair in entries.windows(2) {
        let previous = uint.glue().assert_bool(region, &pair[0].0[6])?;
        let active = uint.glue().assert_bool(region, &pair[1].0[6])?;
        gate_true(uint, region, &active, &previous)?;
        let left = uint.range_check::<66>(region, &pair[0].0[1])?;
        let right = uint.range_check::<66>(region, &pair[1].0[1])?;
        let increasing = uint.lt(region, &left, &right)?;
        gate_true(uint, region, &active, &increasing)?;
        // Within one kind, windows cannot overlap. Key-start recovers kind*2^64.
        let old_kind = uint.glue().sub(region, &pair[0].0[1], &pair[0].0[4])?;
        let new_kind = uint.glue().sub(region, &pair[1].0[1], &pair[1].0[4])?;
        let same = uint.glue().is_equal(region, &old_kind, &new_kind)?;
        let same = uint.glue().and(region, &same, &active)?;
        let end = uint.range_check::<64>(region, &pair[0].0[2])?;
        let start = uint.range_check::<64>(region, &pair[1].0[4])?;
        let overlap = uint.lt(region, &start, &end)?;
        gate_zero(uint, region, &same, overlap.word())?;
    }
    Ok(())
}

fn array_root(
    sponge: &mut impl WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    mut nodes: Vec<Word<Fp>>,
    domain: u64,
) -> Result<Word<Fp>, Error> {
    while nodes.len() > 1 {
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| sponge.hash_words(region, domain, pair))
            .collect::<Result<_, _>>()?;
    }
    nodes.pop().ok_or(Error::Synthesis)
}

/// Authenticate and rebuild the fixed usage array of a `QuotaShare` refresh.
///
/// Matches preserve end and used exactly, even when the new limit is lower
/// than carried usage. New keys start at zero; only the first share may add
/// keys starting before the monotone floor. Charged live keys cannot vanish.
/// Every new window is within the signed issue/expiry interval and longer
/// than the response bound. This composes with `refresh::constrain` and the
/// signature/transcript relation; no object is authenticated by a bare root.
///
/// # Errors
/// Wrong fixed variant or layout failure. Incorrect roots, noncanonical
/// arrays, reset consumption and changed matching ends are unsatisfiable.
pub fn constrain(
    uint: &mut UintChip<'_, Fp>,
    sponge: &mut impl WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    transition: &MapTransition<'_>,
    witness: &QuotaRebuildCells,
) -> Result<(), Error> {
    constrain_semantics(uint, region, transition, witness)?;
    for root in [
        QuotaRoot::PreviousUsage,
        QuotaRoot::ReplacementWindows,
        QuotaRoot::ReplacementUsage,
    ] {
        constrain_root(sponge, region, transition, witness, root)?;
    }
    Ok(())
}

/// Authenticate one exact fixed64 root without duplicating the matching owner.
///
/// This is one obligation of a split rebuild. The complete relation must also
/// execute the other two root owners and [`constrain_semantics`], all over the
/// same [`QuotaRebuildCells::commitment_words`] bound in the recursive context.
/// Root equality alone does not establish canonical arrays or preserve charges.
/// # Errors
/// Wrong operation variant, failed root equality or synthesis failure.
pub fn constrain_root(
    sponge: &mut impl WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    transition: &MapTransition<'_>,
    witness: &QuotaRebuildCells,
    root: QuotaRoot,
) -> Result<(), Error> {
    if transition.statement.variant() != Variant::RefreshQuotaShare {
        return Err(Error::Synthesis);
    }
    let (leaf_domain, node_domain, expected) = match root {
        QuotaRoot::PreviousUsage => (
            QUOTA_USAGE_DOMAIN,
            QUOTA_USAGE_NODE_DOMAIN,
            &transition.predecessor.state.core()[core::QUOTA_USAGE_ROOT],
        ),
        QuotaRoot::ReplacementWindows => (
            QUOTA_WINDOW_DOMAIN,
            QUOTA_NODE_DOMAIN,
            &transition.successor.state.core()[core::QUOTA_WINDOWS_ROOT],
        ),
        QuotaRoot::ReplacementUsage => (
            QUOTA_USAGE_DOMAIN,
            QUOTA_USAGE_NODE_DOMAIN,
            &transition.successor.state.core()[core::QUOTA_USAGE_ROOT],
        ),
    };
    let mut leaves = Vec::with_capacity(64);
    for i in 0..64 {
        let fields = match root {
            QuotaRoot::PreviousUsage => witness.old[i].clone(),
            QuotaRoot::ReplacementWindows => witness.windows[i].clone(),
            QuotaRoot::ReplacementUsage => [
                witness.windows[i][0].clone(),
                witness.windows[i][1].clone(),
                witness.windows[i][2].clone(),
                witness.used[i].clone(),
            ],
        };
        leaves.push(sponge.hash_words(region, leaf_domain, &fields)?);
    }
    let actual = array_root(sponge, region, leaves, node_domain)?;
    GlueChip::assert_equal(region, &actual, expected)
}

/// Constrain exact canonical arrays, window bounds and deterministic matching.
///
/// This retains all fixed64 semantic constraints, including preservation of
/// matched usage and rejection of dropped live charges. A split circuit must
/// execute all three [`constrain_root`] owners over these same context-bound
/// witness words; semantic checks alone do not authenticate a state opening.
/// # Errors
/// Wrong operation variant, invalid semantic constraints or synthesis failure.
pub fn constrain_semantics(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    transition: &MapTransition<'_>,
    witness: &QuotaRebuildCells,
) -> Result<(), Error> {
    if transition.statement.variant() != Variant::RefreshQuotaShare {
        return Err(Error::Synthesis);
    }
    let old = transition.predecessor.state;
    let new = transition.successor.state;
    let floor = uint.range_check::<64>(region, &new.core()[core::TIME_FLOOR])?;
    let issued = uint.range_check::<64>(region, &witness.issued)?;
    let expires = uint.range_check::<64>(region, &new.core()[core::QUOTA_SHARE_EXPIRY])?;
    let bound = uint.range_check::<64>(region, &old.core()[core::TIME_ANCHOR_MAX_RESPONSE])?;
    let first = uint
        .glue()
        .is_zero(region, &old.rest()[rest::QUOTA_SHARE_ID])?;
    let mut window_count = uint.glue().constant(region, Fp::ZERO)?;
    let mut previous = Vec::with_capacity(64);
    let mut replacement = Vec::with_capacity(64);
    for i in 0..64 {
        let a = entry(uint, region, &witness.old[i], &witness.old[i][3], false)?;
        gate_zero(uint, region, &first, &a.0[6])?;
        let b = entry(uint, region, &witness.windows[i], &witness.used[i], true)?;
        let active = uint.glue().assert_bool(region, &b.0[6])?;
        window_count = uint.glue().add(region, &window_count, active.word())?;
        let start = uint.range_check::<64>(region, &b.0[4])?;
        let end = uint.range_check::<64>(region, &b.0[2])?;
        let length = uint.checked_sub(region, &end, &start)?;
        let long_enough = uint.lt(region, &bound, &length)?;
        gate_true(uint, region, &active, &long_enough)?;
        let too_early = uint.lt(region, &start, &issued)?;
        let too_late = uint.lt(region, &expires, &end)?;
        gate_zero(uint, region, &active, too_early.word())?;
        gate_zero(uint, region, &active, too_late.word())?;
        previous.push(a);
        replacement.push(b);
    }
    GlueChip::assert_equal(region, &window_count, &witness.window_count)?;
    uint.glue().assert_nonzero(region, &window_count)?;
    sorted_source(uint, region, &previous)?;
    sorted_source(uint, region, &replacement)?;
    previous.extend(replacement.into_iter().rev());
    let mut distance = 64;
    while distance > 0 {
        for i in 0..128 {
            let j = i ^ distance;
            if j <= i {
                continue;
            }
            let a = previous[i].clone();
            let b = previous[j].clone();
            let left = uint.range_check::<68>(region, &a.0[0])?;
            let right = uint.range_check::<68>(region, &b.0[0])?;
            let swap = uint.lt(region, &right, &left)?;
            for k in 0..7 {
                previous[i].0[k] = uint.glue().select(region, &swap, &b.0[k], &a.0[k])?;
                previous[j].0[k] = uint.glue().select(region, &swap, &a.0[k], &b.0[k])?;
            }
        }
        distance /= 2;
    }
    let false_bit = uint
        .glue()
        .boolean(region, iroha_plonk::frontend::Value::known(false))?;
    GlueChip::assert_constant(region, false_bit.word(), Fp::ZERO)?;
    for i in 0..128 {
        let row = &previous[i].0;
        let active = uint.glue().assert_bool(region, &row[6])?;
        let fresh = uint.glue().assert_bool(region, &row[5])?;
        let old_origin = uint.glue().not(region, &fresh)?;
        let is_old = uint.glue().and(region, &active, &old_origin)?;
        let is_new = uint.glue().and(region, &active, &fresh)?;
        let follows = if i > 0 {
            uint.glue()
                .is_equal(region, &previous[i - 1].0[1], &row[1])?
        } else {
            false_bit.clone()
        };
        let precedes = if i < 127 {
            uint.glue()
                .is_equal(region, &row[1], &previous[i + 1].0[1])?
        } else {
            false_bit.clone()
        };
        let matched = uint.glue().and(region, &is_old, &precedes)?;
        if i < 127 {
            for k in [2, 3] {
                gate_equal(uint, region, &matched, &row[k], &previous[i + 1].0[k])?;
            }
        }
        let no_next = uint.glue().not(region, &precedes)?;
        let dropped = uint.glue().and(region, &is_old, &no_next)?;
        let used_zero = uint.glue().is_zero(region, &row[3])?;
        let end = uint.range_check::<64>(region, &row[2])?;
        let still_live = uint.lt(region, &floor, &end)?;
        let charged = uint.glue().not(region, &used_zero)?;
        let live_charge = uint.glue().and(region, &still_live, &charged)?;
        gate_zero(uint, region, &dropped, live_charge.word())?;
        let no_previous = uint.glue().not(region, &follows)?;
        let added = uint.glue().and(region, &is_new, &no_previous)?;
        gate_zero(uint, region, &added, &row[3])?;
        let not_first = uint.glue().not(region, &first)?;
        let bounded_add = uint.glue().and(region, &added, &not_first)?;
        let start = uint.range_check::<64>(region, &row[4])?;
        let too_early = uint.lt(region, &start, &floor)?;
        gate_zero(uint, region, &bounded_add, too_early.word())?;
    }
    Ok(())
}
