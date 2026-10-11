//! Fixed-layout state effects for the single RefreshPolicy sigma selector.
//!
//! The operation kind comes from the constrained statement. Projected fields are
//! witnesses, not authenticated facts: A must bind them and every state effect to
//! the exact signed update, credential renewal, blacklist insertion and quota
//! rebuild. Native Advance authenticates every changed root before persistence.

use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, Word};

use crate::{
    operation_relation::{
        map_effects::MapState, state::rest_index as rest, statement::RefreshStatementCells,
    },
    witness::core_index as core,
};

/// Fixed projection width: digest; scheme2; asset2; wallet2; counter; issued;
/// expiry/lease; root; controls; fee digest. Unused fields must be zero.
/// This is an internal circuit witness layout, not a new serialized artifact.
pub const UPDATE_FIELDS: usize = 13;

/// Validated single-key refresh statement and its complete state openings.
pub struct SelectedRefreshTransition<'a> {
    /// Kind selectors are derived from this statement inside the circuit.
    pub statement: &'a RefreshStatementCells,
    /// Original committed state and its lineage identity.
    pub predecessor: MapState<'a>,
    /// Successor state and its preserved lineage values.
    pub successor: MapState<'a>,
}

fn gate_equal(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    gate: &Bit<Fp>,
    left: &Word<Fp>,
    right: &Word<Fp>,
) -> Result<(), Error> {
    let difference = uint.glue().sub(region, left, right)?;
    let selected = uint.glue().mul(region, gate.word(), &difference)?;
    GlueChip::assert_constant(region, &selected, Fp::ZERO)
}
fn selected(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    kinds: &[Bit<Fp>; 5],
    indices: &[usize],
) -> Result<Bit<Fp>, Error> {
    let terms: Vec<_> = indices
        .iter()
        .map(|i| (Fp::ONE, kinds[*i].word()))
        .collect();
    let sum = uint.glue().linear(region, &terms, Fp::ZERO)?;
    let zero = uint.glue().is_zero(region, &sum)?;
    uint.glue().not(region, &zero)
}
fn projection(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    kind: &Bit<Fp>,
    old: &Word<Fp>,
    new: &Word<Fp>,
    value: &Word<Fp>,
) -> Result<(), Error> {
    let expected = uint.glue().select(region, kind, value, old)?;
    GlueChip::assert_equal(region, &expected, new)
}

/// Constrain all five refresh state effects in one witness-independent layout.
///
/// Every selector derives from the statement's kind1..5; neither Rust dispatch
/// nor a host validity bit selects source rules. Signed-object authentication,
/// credential renewal identity, blacklist-history insertion and the complete
/// quota-array rebuild remain hard obligations of A.
///
/// # Errors
/// Layout failure; bad projection padding, identities, counters, permission
/// intersection, floor/expiry/anchor rules or unrelated changes are unsatisfiable.
pub fn constrain_selected(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    transition: &SelectedRefreshTransition<'_>,
    fields: &[Word<Fp>; UPDATE_FIELDS],
) -> Result<(), Error> {
    transition.statement.bind_states(
        uint,
        region,
        (transition.predecessor.state, transition.predecessor.lineage),
        transition.successor.state,
        transition.successor.lineage,
    )?;
    let kinds = transition.statement.kinds();
    let [credential, policy, blacklist, quota, anchor] = kinds;
    let before = transition.predecessor.state.core();
    let after = transition.successor.state.core();
    let old_rest = transition.predecessor.state.rest();
    let new_rest = transition.successor.state.rest();
    let zero = uint.glue().constant(region, Fp::ZERO)?;
    let one = uint.glue().constant(region, Fp::ONE)?;
    let scheme = uint.glue().not(region, credential)?;
    let asset = selected(uint, region, kinds, &[1, 3])?;
    let wallet = selected(uint, region, kinds, &[3, 4])?;
    let counter = selected(uint, region, kinds, &[1, 2, 3])?;
    let issued = uint.glue().not(region, policy)?;
    let expires = selected(uint, region, kinds, &[0, 3])?;
    let root = selected(uint, region, kinds, &[2, 3])?;
    // Canonical inactive projections prevent hidden alternate facts in a branch.
    for (active, indices) in [
        (&scheme, &[1, 2][..]),
        (&asset, &[3, 4][..]),
        (&wallet, &[5, 6][..]),
        (&counter, &[7][..]),
        (&issued, &[8][..]),
        (&expires, &[9][..]),
        (&root, &[10][..]),
        (policy, &[11, 12][..]),
    ] {
        let inactive = uint.glue().not(region, active)?;
        for index in indices {
            gate_equal(uint, region, &inactive, &fields[*index], &zero)?;
        }
    }
    for field in &fields[1..7] {
        uint.range_check::<128>(region, field)?;
    }
    for field in &fields[7..10] {
        uint.range_check::<64>(region, field)?;
    }
    GlueChip::assert_equal(region, &fields[0], &transition.statement.fields()[18])?;
    for (active, offset, source) in [
        (&scheme, 1, core::SCHEME),
        (&asset, 3, core::ASSET),
        (&wallet, 5, core::WALLET),
    ] {
        for limb in 0..2 {
            gate_equal(
                uint,
                region,
                active,
                &fields[offset + limb],
                &before[source + limb],
            )?;
        }
    }
    // Reuse the strict counter rule; inactive kinds prove the fixed harmless 0<1.
    let old_counter = uint.glue().select(
        region,
        quota,
        &old_rest[rest::QUOTA_SHARE_ID],
        &before[core::BLACKLIST_VERSION],
    )?;
    let old_counter =
        uint.glue()
            .select(region, policy, &before[core::POLICY_EPOCH], &old_counter)?;
    let old_counter = uint.glue().select(region, &counter, &old_counter, &zero)?;
    let new_counter = uint.glue().select(region, &counter, &fields[7], &one)?;
    super::increasing(uint, region, &old_counter, &new_counter)?;
    let start = uint.range_check::<64>(region, &fields[8])?;
    let end = uint.range_check::<64>(region, &fields[9])?;
    let ordered = uint.lt(region, &start, &end)?;
    gate_equal(uint, region, quota, ordered.word(), &one)?;
    let repeated = uint
        .glue()
        .is_equal(region, &fields[0], &old_rest[rest::TIME_ANCHOR])?;
    gate_equal(uint, region, anchor, repeated.word(), &zero)?;

    let controls = super::mask(uint, region, &fields[11])?;
    let permitted = super::mask(uint, region, &old_rest[rest::PERMITTED])?;
    let mut intersection = Vec::with_capacity(3);
    for i in 0..3 {
        intersection.push(
            uint.glue()
                .mul(region, controls[i].word(), permitted[i].word())?,
        );
    }
    let enabled = uint.glue().linear(
        region,
        &[
            (Fp::ONE, &intersection[0]),
            (Fp::from(2), &intersection[1]),
            (Fp::from(4), &intersection[2]),
        ],
        Fp::ZERO,
    )?;
    let signed_time = uint
        .glue()
        .select(region, policy, &before[core::TIME_FLOOR], &fields[8])?;
    let old_floor = uint.range_check::<64>(region, &before[core::TIME_FLOOR])?;
    let signed_time = uint.range_check::<64>(region, &signed_time)?;
    let advance = uint.lt(region, &old_floor, &signed_time)?;
    let floor = uint
        .glue()
        .select(region, &advance, signed_time.word(), old_floor.word())?;
    GlueChip::assert_equal(region, &floor, &transition.statement.fields()[19])?;

    for (index, old) in before.iter().enumerate() {
        let selection = match index {
            core::SEQUENCE | core::STATE_NONCE => continue,
            core::CREDENTIAL => Some((credential, &fields[0])),
            core::LEASE_EXPIRY => Some((credential, &fields[9])),
            core::POLICY_EPOCH => Some((policy, &fields[7])),
            core::ENABLED_CONTROLS => Some((policy, &enabled)),
            core::BLACKLIST_VERSION => Some((blacklist, &fields[7])),
            core::BLACKLIST_ROOT => Some((blacklist, &fields[10])),
            core::BLACKLIST_ISSUED_AT => Some((blacklist, &fields[8])),
            core::QUOTA_WINDOWS_ROOT => Some((quota, &fields[10])),
            core::QUOTA_SHARE_EXPIRY => Some((quota, &fields[9])),
            core::QUOTA_USAGE_ROOT => {
                let unchanged = uint.glue().not(region, quota)?;
                gate_equal(uint, region, &unchanged, old, &after[index])?;
                continue;
            }
            core::TIME_FLOOR => {
                GlueChip::assert_equal(region, &floor, &after[index])?;
                continue;
            }
            _ => None,
        };
        if let Some((kind, value)) = selection {
            projection(uint, region, kind, old, &after[index], value)?;
        } else {
            GlueChip::assert_equal(region, old, &after[index])?;
        }
    }
    for (index, old) in old_rest.iter().enumerate() {
        let selection = match index {
            rest::SCHEME_POLICY => Some((policy, &fields[0])),
            rest::FEE_SCHEDULE => Some((policy, &fields[12])),
            rest::BLACKLIST => Some((blacklist, &fields[0])),
            rest::QUOTA_SHARE => Some((quota, &fields[0])),
            rest::QUOTA_SHARE_ID => Some((quota, &fields[7])),
            rest::TIME_ANCHOR => Some((anchor, &fields[0])),
            rest::BLACKLIST_HISTORY => {
                let unchanged = uint.glue().not(region, blacklist)?;
                gate_equal(uint, region, &unchanged, old, &new_rest[index])?;
                continue;
            }
            _ => None,
        };
        if let Some((kind, value)) = selection {
            projection(uint, region, kind, old, &new_rest[index], value)?;
        } else {
            GlueChip::assert_equal(region, old, &new_rest[index])?;
        }
    }
    for index in [14, 15, 16] {
        GlueChip::assert_equal(
            region,
            &transition.predecessor.lineage.fields()[index],
            &transition.successor.lineage.fields()[index],
        )?;
    }
    Ok(())
}
