//! Separate hard core and adjusted pending removals with terminal mode closure.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, Word};
use iroha_plonk_recursion::verifier::VerifierChip;

use super::{
    require_task,
    results::ArchiveResultClaims,
    retained::{DESCRIPTOR_SLOT, DESCRIPTOR_SPEC},
};
use crate::{
    a_relation::{
        context::{ContextInputs, ContextObjectCells, ContextPlan},
        schedule::OperationTask,
    },
    operation_relation::map_effects::{MapEffectsChip, MapState, MapTransition, RemoveCells},
};

/// One retained descriptor and exactly one authenticated pending-removal path.
/// Each mandatory owner binds this descriptor to the same fixed context slot.
#[derive(Clone, Debug)]
pub struct ArchivePendingWitness {
    /// Exact seven-field descriptor of the original retained outgoing Payment.
    pub descriptor: [Word<Fp>; 7],
    /// Core or adjusted-lineage removal, selected by the fixed owner task.
    pub removal: RemoveCells,
}

/// Terminal evidence mode verdict after all mandatory source and map owners.
/// It does not establish execution of the other owners or final Omega decision.
#[must_use = "close every recursive obligation and durably commit Omega before deletion"]
#[derive(Clone, Debug)]
pub struct ArchiveEffectsCells {
    valid: Bit<Fp>,
}
impl ArchiveEffectsCells {
    /// Complete three-result/mode iff verdict used by the source transition.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}

/// Close the fixed complete result/mode rule after every mandatory owner.
/// This terminal predicate accepts no map witness or independently proposed bit.
/// # Errors
/// Wrong owner, missing result/mode context, or discretionary no-op.
pub fn constrain_effects(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    claims: &ArchiveResultClaims,
) -> Result<ArchiveEffectsCells, Error> {
    let valid = claims.terminal_modes(chip, region, plan, stage, input)?;
    Ok(ArchiveEffectsCells { valid })
}

/// Authenticate the unconditional committed-core pending removal in its fixed owner.
/// The separate adjusted-lineage owner independently binds the same retained
/// descriptor and old/new context roots before selecting removal or no-op.
/// # Errors
/// Wrong task or descriptor schema, substituted descriptor, invalid removal path
/// or a changed committed successor root.
pub fn constrain_core_pending(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    witness: &ArchivePendingWitness,
) -> Result<(), Error> {
    require_task(plan, stage, OperationTask::ArchiveCorePending)?;
    bind_descriptor(chip, region, plan, input, witness)?;
    let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
    let transition = MapTransition {
        statement: input.own_statement,
        predecessor: MapState {
            state: predecessor.state,
            lineage: predecessor.public,
        },
        successor: MapState {
            state: input.successor.state,
            lineage: input.successor.public,
        },
    };
    let lanes = chip.operation_lanes()?;
    MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).archive_core_pending(
        region,
        &transition,
        &witness.descriptor,
        &witness.removal,
    )
}

/// Authenticate adjusted pending removal and unchanged administrative state.
/// The removal path is checked even on no-op; the same complete context binds
/// this owner's descriptor, roots and evidence-result claims to terminal closure.
/// # Errors
/// Wrong owner/descriptor/result schema, changed unrelated state or invalid path.
pub fn constrain_lineage_pending(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    claims: &ArchiveResultClaims,
    witness: &ArchivePendingWitness,
) -> Result<(), Error> {
    let valid = claims.lineage_verdict(chip, region, plan, stage, input)?;
    bind_descriptor(chip, region, plan, input, witness)?;
    let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
    let transition = MapTransition {
        statement: input.own_statement,
        predecessor: MapState {
            state: predecessor.state,
            lineage: predecessor.public,
        },
        successor: MapState {
            state: input.successor.state,
            lineage: input.successor.public,
        },
    };
    let lanes = chip.operation_lanes()?;
    MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).archive_lineage_pending(
        region,
        &transition,
        &witness.descriptor,
        &witness.removal,
        &valid,
    )
}

fn bind_descriptor(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    input: &ContextInputs<'_>,
    witness: &ArchivePendingWitness,
) -> Result<(), Error> {
    let spec = *plan
        .object_specs()
        .get(DESCRIPTOR_SLOT)
        .ok_or(Error::Synthesis)?;
    if spec != DESCRIPTOR_SPEC {
        return Err(Error::Synthesis);
    }
    let actual = ContextObjectCells::from_internal_words(chip, region, spec, &witness.descriptor)?;
    let expected = input.objects.get(DESCRIPTOR_SLOT).ok_or(Error::Synthesis)?;
    for (a, b) in actual
        .commitment_words()
        .iter()
        .zip(expected.commitment_words())
    {
        GlueChip::assert_equal(region, a, &b)?;
    }
    Ok(())
}
