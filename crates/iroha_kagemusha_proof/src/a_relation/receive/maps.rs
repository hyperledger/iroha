//! Fixed-owner Receive map predicates and terminal OQ-3 effects.
//!
//! These entry points derive their inputs from the same committed context.
//! They do not admit a stage key: the catalog must additionally establish all
//! five result producers, hard own authorization and recursive obligations.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, Word, imt::OpeningCells};
use iroha_plonk_recursion::verifier::VerifierChip;

use super::ReceiveSignedObjects;
use crate::{
    a_relation::{
        bind_modes, bounded_word,
        context::{ContextInputs, ContextPlan},
        results::ReceiveResultTag,
        schedule::{OperationTask, constrain_sigma_selector},
    },
    operation_relation::map_effects::{MapEffectsChip, MapState, MapTransition, ReceiveMapWitness},
};

fn transition<'a>(input: &'a ContextInputs<'_>) -> Result<MapTransition<'a>, Error> {
    let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
    Ok(MapTransition {
        statement: input.own_statement,
        predecessor: MapState {
            state: predecessor.state,
            lineage: predecessor.public,
        },
        successor: MapState {
            state: input.successor.state,
            lineage: input.successor.public,
        },
    })
}

pub(super) fn require_task(
    plan: &ContextPlan,
    stage: u32,
    task: OperationTask,
) -> Result<(), Error> {
    if plan.receive_results().is_none()
        || !plan
            .operation_tasks(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
            .ok_or(Error::Synthesis)?
            .contains(&task)
    {
        return Err(Error::Synthesis);
    }
    Ok(())
}

/// Derive consumed-credit absence from the exact predecessor state and own credit.
///
/// The depth32 search is hard-authenticated and must open either the requested
/// key or its unique bracketing leaf. Only actual presence returns false. The
/// complete state/statement transition is bound before the result is committed.
///
/// # Errors
/// Wrong fixed owner/schema, missing context input or layout failure. An
/// unauthenticated or wrong search route is unsatisfiable on every branch.
pub fn constrain_nonmembership(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    opening: &OpeningCells<Fp>,
) -> Result<(), Error> {
    let valid = derive_nonmembership(chip, region, plan, stage, input, opening)?;
    input.receive_results.ok_or(Error::Synthesis)?.bind_derived(
        region,
        plan.receive_results().ok_or(Error::Synthesis)?,
        stage,
        ReceiveResultTag::Nonmembership,
        &valid,
    )
}

// Same native predicate, without interpreting a proposed result as authority.
pub(crate) fn derive_nonmembership(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    opening: &OpeningCells<Fp>,
) -> Result<Bit<Fp>, Error> {
    require_task(plan, stage, OperationTask::ReceiveNonmembership)?;
    if input.own_statement.variant() != plan.operation().frame().variant() {
        return Err(Error::Synthesis);
    }
    nonmembership_predicate(chip, region, &transition(input)?, opening)
}

// Shared Q-free predicate; the staged wrapper retains exact task/context bindings.
pub(crate) fn nonmembership_predicate(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    transition: &MapTransition<'_>,
    opening: &OpeningCells<Fp>,
) -> Result<Bit<Fp>, Error> {
    let lanes = chip.operation_lanes()?;
    transition.statement.bind_states(
        &mut UintChip::new(lanes.glue, lanes.range),
        region,
        Some((transition.predecessor.state, transition.predecessor.lineage)),
        transition.successor.state,
        transition.successor.lineage,
    )?;
    let valid = MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash)
        .receive_nonmembership(region, transition, opening)?;
    Ok(valid)
}

impl ReceiveSignedObjects {
    // Native source query has no Q0 frame. Both paths call the exact shared kernel.
    pub(crate) fn blacklist_predicate(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        state: &crate::operation_relation::state::StateCells,
        lineage: &crate::a_relation::LineagePublicCells,
        opening: &OpeningCells<Fp>,
    ) -> Result<(Bit<Fp>, Word<Fp>), Error> {
        state.bind_lineage(&mut chip.uint(), region, lineage)?;
        blacklist_result(chip, region, &self.objects[0], state, opening)
    }

    /// Derive the Request-recorded history predicate and own Receive selector.
    ///
    /// The original version selects index10 or11, independently of validity.
    /// Invalid/zero pairs use the fixed valid `(1,1)` query, whose route still
    /// must authenticate; their result is determined by the original pair.
    /// Current blacklist state is never substituted for the recorded pair.
    ///
    /// # Errors
    /// Wrong fixed owner/schema, missing context input or layout failure.
    /// Spliced Requests, freely chosen selectors and forged routes fail hard.
    pub fn constrain_blacklist(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        opening: &OpeningCells<Fp>,
    ) -> Result<(), Error> {
        let valid = self.derive_blacklist(chip, region, plan, stage, input, opening)?;
        input.receive_results.ok_or(Error::Synthesis)?.bind_derived(
            region,
            plan.receive_results().ok_or(Error::Synthesis)?,
            stage,
            ReceiveResultTag::Blacklist,
            &valid,
        )
    }

    // Same production predicate for native witness preparation. This returns assigned
    // cells only; the fixed owning stage still binds and proves the result.
    pub(crate) fn derive_blacklist(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        opening: &OpeningCells<Fp>,
    ) -> Result<Bit<Fp>, Error> {
        require_task(plan, stage, OperationTask::ReceiveBlacklist)?;
        self.bind_context(region, plan, input)?;
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        predecessor
            .state
            .bind_lineage(&mut chip.uint(), region, predecessor.public)?;
        let (valid, selector) =
            blacklist_result(chip, region, &self.objects[0], predecessor.state, opening)?;
        let own_index = input
            .q_instances
            .first()
            .and_then(|columns| columns.get(2))
            .and_then(|column| column.first())
            .ok_or(Error::Synthesis)?;
        let actual = bounded_word(chip, region, own_index)?;
        GlueChip::assert_equal(region, &actual, &selector)?;
        Ok(valid)
    }
}

pub(crate) fn blacklist_result(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    request: &crate::operation_relation::objects::SignedObjectCells,
    state: &crate::operation_relation::state::StateCells,
    opening: &OpeningCells<Fp>,
) -> Result<(Bit<Fp>, Word<Fp>), Error> {
    let version = request.word(15)?;
    let root = request.word(16)?;
    let lanes = chip.operation_lanes()?;
    let mut uint = UintChip::new(lanes.glue, lanes.range);
    // U64 parsing is exact even for a structurally invalid Request;
    // canonical Fp parsing retains its separate structural verdict.
    let zero_version = uint.glue().is_zero(region, version)?;
    let nonzero_version = uint.glue().not(region, &zero_version)?;
    let zero_root = uint.glue().is_zero(region, root)?;
    let nonzero_root = uint.glue().not(region, &zero_root)?;
    let pair = uint.glue().and(region, &nonzero_version, &nonzero_root)?;
    let empty = uint.glue().and(region, &zero_version, &zero_root)?;
    let one = uint.glue().constant(region, Fp::ONE)?;
    let safe_version = uint.glue().select(region, &pair, version, &one)?;
    let safe_root = uint.glue().select(region, &pair, root, &one)?;
    let selector = constrain_sigma_selector(&mut uint, region, 4, nonzero_version.word())?;
    let found = MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).recorded_blacklist(
        region,
        state,
        &safe_version,
        &safe_root,
        opening,
    )?;
    let valid = chip.uint().glue().and(region, &pair, &found)?;
    // `empty` and `pair` are disjoint, making this an exact boolean OR.
    let valid = chip.uint().glue().add(region, valid.word(), empty.word())?;
    let valid = chip.uint().glue().assert_bool(region, &valid)?;
    let valid = chip
        .uint()
        .glue()
        .and(region, &valid, request.structural_valid())?;
    Ok((valid, selector))
}

/// Terminal mode verdict whose OQ-3 map and burn effects have been constrained.
/// This is not a standalone lineage-acceptance certificate.
#[must_use = "retain all stage proofs and pending claims through final Omega decision"]
#[derive(Clone, Debug)]
pub struct ReceiveEffectsCells {
    valid: Bit<Fp>,
}
impl ReceiveEffectsCells {
    /// The complete five-result/mode rule used by these exact map effects.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}

fn effect_verdict(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    input: &ContextInputs<'_>,
) -> Result<Bit<Fp>, Error> {
    let claims = input.receive_results.ok_or(Error::Synthesis)?;
    bind_modes(
        chip,
        region,
        plan.operation(),
        claims.values(plan.receive_results().ok_or(Error::Synthesis)?)?,
        input.modes,
    )
}

/// Authenticate one fixed consumed/credit-map owner against the same complete
/// context, all five results and all modes. Neither owner introduces a soft bit.
/// # Errors
/// Wrong/missing owner, terminal placement, wrong Payment or unsatisfied map effect.
pub fn constrain_map_effects(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    witness: &ReceiveMapWitness,
    task: OperationTask,
) -> Result<(), Error> {
    if !matches!(
        task,
        OperationTask::ReceiveConsumedEffects | OperationTask::ReceiveCreditEffects
    ) || usize::try_from(stage)
        .ok()
        .and_then(|s| s.checked_add(1))
        .is_none_or(|next| next >= plan.stage_count())
        || input.own_statement.variant() != plan.operation().frame().variant()
    {
        return Err(Error::Synthesis);
    }
    require_task(plan, stage, task)?;
    let valid = effect_verdict(chip, region, plan, input)?;
    GlueChip::assert_equal(
        region,
        &witness.payment_digest,
        input
            .objects
            .get(3)
            .ok_or(Error::Synthesis)?
            .authenticated_digest(),
    )?;
    let transition = transition(input)?;
    let lanes = chip.operation_lanes()?;
    let mut maps = MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash);
    match task {
        OperationTask::ReceiveConsumedEffects => {
            maps.receive_consumed(region, &transition, witness, &valid)
        }
        OperationTask::ReceiveCreditEffects => {
            maps.receive_credit(region, &transition, witness, &valid)
        }
        _ => Err(Error::Synthesis),
    }
}

/// Consume all five fixed results and all modes, then finalize burn and preserved state.
///
/// This runs only at the fixed terminal Effects stage. Result claims are not
/// accepted from a caller-provided shortened slice. The exact Payment digest
/// and both map roots were hard-bound by the mandatory preceding consumed/credit
/// owners. Catalog admission must establish every preceding typed result owner and hard own
/// authorization; intermediate W proofs are never final lineage proofs.
///
/// # Errors
/// Wrong stage/schema, incomplete results/modes or layout failure. Incorrect
/// map effects, Payment substitution and a discretionary burn are unsatisfiable.
pub fn constrain_effects(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
) -> Result<ReceiveEffectsCells, Error> {
    require_task(plan, stage, OperationTask::ReceiveEffects)?;
    if usize::try_from(stage).ok().and_then(|s| s.checked_add(1)) != Some(plan.stage_count())
        || input.own_statement.variant() != plan.operation().frame().variant()
    {
        return Err(Error::Synthesis);
    }
    let valid = effect_verdict(chip, region, plan, input)?;
    let transition = transition(input)?;
    let lanes = chip.operation_lanes()?;
    MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).receive_burn_and_preserve(
        region,
        &transition,
        &valid,
    )?;
    Ok(ReceiveEffectsCells { valid })
}

#[cfg(test)]
mod tests;
