//! Bootstrap, Load, `ArchiveSent`, Unload and Retiring state effects.
//!
//! These effects compose with authenticated credentials, ordinary receipts and charge quotes
//! and map transitions in A. They do not verify those signatures or finality.
//! No stand-alone monetary acceptance API is exposed here.

use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{GlueChip, UintChip, WordHasher};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{
    map_effects::MapTransition,
    state::{StateCells, rest_index as rest},
    statement::StatementCells,
};
use crate::{
    a_relation::LineagePublicCells,
    tree::{IndexedTree, QuotaUsageTree, QuotaWindowTree},
    witness::core_index as core,
};

/// Domain of the five-field scheme/wallet/redeem-ordinal nullifier.
pub const NULLIFIER_DOMAIN: u64 = u64::from_le_bytes(*b"kgwnull1");

/// Constrain the exact zero-value initial state and lineage maps.
///
/// A separately authenticates and binds the credential's scheme, asset,
/// wallet, digest, enrollment identity, payment key, permitted controls,
/// regulatory bounds and lease. The state nonce remains a nonzero witness.
///
/// # Errors
/// Wrong fixed variant or layout failure; preloaded value, maps, counters,
/// enabled controls and held objects have no satisfying witness.
pub fn bootstrap(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    statement: &StatementCells,
    state: &StateCells,
    lineage: &LineagePublicCells,
) -> Result<(), Error> {
    if statement.variant() != Variant::Bootstrap {
        return Err(Error::Synthesis);
    }
    statement.bind_states(uint, region, None, state, lineage)?;
    let empty = IndexedTree::<Fp>::new().root();
    let windows = QuotaWindowTree::new(&[]).ok_or(Error::Synthesis)?;
    let empty_usage = QuotaUsageTree::<Fp>::new(&windows).root();
    let fields = state.core();
    GlueChip::assert_constant(region, &fields[core::LIFECYCLE], Fp::ONE)?;
    for word in &fields[core::BALANCE..=core::RECEIVE_CHAIN] {
        GlueChip::assert_constant(region, word, Fp::ZERO)?;
    }
    for word in &fields[core::CONSUMED_CREDIT_ROOT..=core::FEE_CLAIM_ROOT] {
        GlueChip::assert_constant(region, word, empty)?;
    }
    GlueChip::assert_constant(region, &fields[core::QUOTA_USAGE_ROOT], empty_usage)?;
    for index in [
        core::ENABLED_CONTROLS,
        core::QUOTA_WINDOWS_ROOT,
        core::QUOTA_SHARE_EXPIRY,
        core::BLACKLIST_VERSION,
        core::BLACKLIST_ROOT,
        core::BLACKLIST_ISSUED_AT,
        core::POLICY_EPOCH,
        core::TIME_FLOOR,
    ] {
        GlueChip::assert_constant(region, &fields[index], Fp::ZERO)?;
    }
    for word in &state.rest()[rest::SCHEME_POLICY..rest::BLACKLIST_HISTORY] {
        GlueChip::assert_constant(region, word, Fp::ZERO)?;
    }
    GlueChip::assert_constant(region, &state.rest()[rest::BLACKLIST_HISTORY], empty)?;
    GlueChip::assert_constant(region, lineage.burned_total(), Fp::ZERO)?;
    GlueChip::assert_constant(region, lineage.pending_root(), empty)?;
    GlueChip::assert_constant(region, lineage.credit_root(), empty)
}

/// Constrain Load/Unload/Retiring's arithmetic and every unchanged field.
///
/// Load and Unload's recovery-map insertion is separately hard-authenticated
/// in A; only that root is left for the map relation. Unload spends the
/// requested face amount, with its online charge withheld from ledger payout,
/// and cannot spend adjusted burned value. Both lineage-consuming operations
/// resynchronize the committed core's burned/pending fields. No operation
/// restores a prior Send or changes an unrelated map or policy.
///
/// # Errors
/// Unsupported variant or layout failure; overflow, underflow, wrong ordinals,
/// nullifiers, lifecycle changes and unrelated changes are unsatisfiable.
pub fn monetary(
    uint: &mut UintChip<'_, Fp>,
    sponge: &mut impl WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    transition: &MapTransition<'_>,
) -> Result<(), Error> {
    let variant = transition.statement.variant();
    if !matches!(variant, Variant::Load | Variant::Unload | Variant::Retiring) {
        return Err(Error::Synthesis);
    }
    transition.statement.bind_states(
        uint,
        region,
        Some((transition.predecessor.state, transition.predecessor.lineage)),
        transition.successor.state,
        transition.successor.lineage,
    )?;
    let before = transition.predecessor.state.core();
    let after = transition.successor.state.core();
    let effect = &transition.statement.fields()[17..];
    if matches!(variant, Variant::Load | Variant::Unload) {
        let index = if variant == Variant::Load {
            core::NEXT_LOAD
        } else {
            core::NEXT_REDEEM
        };
        GlueChip::assert_equal(region, &before[index], &effect[1])?;
        let ordinal = uint.range_check::<128>(region, &effect[1])?;
        let next = uint.checked_add_constant(region, &ordinal, 1)?;
        GlueChip::assert_equal(region, next.word(), &after[index])?;
        let balance = uint.range_check::<128>(region, &before[core::BALANCE])?;
        let amount = uint.range_check::<128>(region, &effect[2])?;
        let new_balance = if variant == Variant::Load {
            uint.checked_add(region, &balance, &amount)?
        } else {
            let burned =
                uint.range_check::<128>(region, transition.predecessor.lineage.burned_total())?;
            let available = uint.checked_sub(region, &balance, &burned)?;
            uint.assert_le(region, &amount, &available)?;
            let nullifier = sponge.hash_words(
                region,
                NULLIFIER_DOMAIN,
                &[
                    before[core::SCHEME].clone(),
                    before[core::SCHEME + 1].clone(),
                    before[core::WALLET].clone(),
                    before[core::WALLET + 1].clone(),
                    effect[1].clone(),
                ],
            )?;
            GlueChip::assert_equal(region, &nullifier, &effect[0])?;
            uint.checked_sub(region, &balance, &amount)?
        };
        GlueChip::assert_equal(region, new_balance.word(), &after[core::BALANCE])?;
    }
    if variant == Variant::Retiring {
        GlueChip::assert_constant(region, &before[core::LIFECYCLE], Fp::ONE)?;
        GlueChip::assert_constant(region, &after[core::LIFECYCLE], Fp::from(2))?;
    }
    if matches!(variant, Variant::Unload | Variant::Retiring) {
        GlueChip::assert_equal(
            region,
            transition.predecessor.lineage.burned_total(),
            &after[core::BURNED_TOTAL],
        )?;
        GlueChip::assert_equal(
            region,
            transition.predecessor.lineage.pending_root(),
            &after[core::PENDING_OUTGOING_ROOT],
        )?;
    }
    for index in 0..before.len() {
        let changed = matches!(index, core::SEQUENCE | core::STATE_NONCE)
            || (variant == Variant::Load
                && matches!(
                    index,
                    core::BALANCE | core::NEXT_LOAD | core::LOAD_REDEEM_ROOT
                ))
            || (variant == Variant::Unload
                && matches!(
                    index,
                    core::BALANCE
                        | core::NEXT_REDEEM
                        | core::LOAD_REDEEM_ROOT
                        | core::BURNED_TOTAL
                        | core::PENDING_OUTGOING_ROOT
                ))
            || (variant == Variant::Retiring
                && matches!(
                    index,
                    core::LIFECYCLE | core::BURNED_TOTAL | core::PENDING_OUTGOING_ROOT
                ));
        if !changed {
            GlueChip::assert_equal(region, &before[index], &after[index])?;
        }
    }
    for (old, new) in transition
        .predecessor
        .state
        .rest()
        .iter()
        .zip(transition.successor.state.rest())
    {
        GlueChip::assert_equal(region, old, new)?;
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

/// Constrain `ArchiveSent`'s complete non-value state transition.
///
/// Only sequence, nonce and the committed pending root may change. The root's
/// exact removal is authenticated by Native Advance and the map relation in A,
/// which also owns the evidence-dependent adjusted pending removal/no-op. No
/// evidence bit, refund, quota restoration or Payment deletion grant is supplied
/// here. Adjusted burned value and permanent credit evidence remain unchanged.
///
/// # Errors
/// Wrong fixed variant or layout failure; any unrelated state change, malformed
/// opening or statement, sequence overflow or zero nonce is unsatisfiable.
pub fn archive(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    transition: &MapTransition<'_>,
) -> Result<(), Error> {
    if !matches!(
        transition.statement.variant(),
        Variant::ArchiveReceive | Variant::ArchiveStatus
    ) {
        return Err(Error::Synthesis);
    }
    transition.statement.bind_states(
        uint,
        region,
        Some((transition.predecessor.state, transition.predecessor.lineage)),
        transition.successor.state,
        transition.successor.lineage,
    )?;
    for (index, old) in transition.predecessor.state.core().iter().enumerate() {
        if !matches!(
            index,
            core::SEQUENCE | core::STATE_NONCE | core::PENDING_OUTGOING_ROOT
        ) {
            GlueChip::assert_equal(region, old, &transition.successor.state.core()[index])?;
        }
    }
    for (old, new) in transition
        .predecessor
        .state
        .rest()
        .iter()
        .zip(transition.successor.state.rest())
    {
        GlueChip::assert_equal(region, old, new)?;
    }
    GlueChip::assert_equal(
        region,
        transition.predecessor.lineage.burned_total(),
        transition.successor.lineage.burned_total(),
    )?;
    GlueChip::assert_equal(
        region,
        transition.predecessor.lineage.credit_root(),
        transition.successor.lineage.credit_root(),
    )
}
