//! Self-contained SCCP penalty continuation of an authenticated committed record.
//!
//! This module does not admit evidence. It consumes the immutable original retained
//! owner; neither live generations nor peer-key lookup can replace G6 attribution.

use super::*;
use iroha_data_model::{
    block::consensus::RecordedEvidenceV1,
    nexus::PublicLaneValidatorRecord,
    sccp::native::{SccpForgeryOffenderV1, SccpForgeryRecordV1},
};

/// A charged parent-plan row shares the original immutable record allocation.
pub(super) struct Pending {
    pub(super) key: Hash,
    pub(super) record: crate::state::RetainedEvidenceRecord,
}

/// Check the closed structural join without treating DATA as signature authority.
pub(super) fn material<'a>(
    key: &Hash,
    record: &'a crate::state::RetainedEvidenceRecord,
) -> Result<&'a SccpForgeryRecordV1> {
    use iroha_data_model::sumeragi_finality::certified_result::SccpFinalityHeaderV1;
    use iroha_sccp::v1::finality::QcFixedV1;
    let RecordedEvidenceV1::SccpForgery(material) = &record.evidence else {
        return Err(eyre!("SCCP penalty requires closed SCCP material"));
    };
    material
        .validate_shape()
        .map_err(|_| eyre!("invalid SCCP penalty record shape"))?;
    let attribution = &record.attribution;
    let x = SccpFinalityHeaderV1::parse(&material.evidence.header)
        .map_err(|_| eyre!("invalid retained SCCP header"))?;
    let qc =
        QcFixedV1::parse(&material.evidence.qc).map_err(|_| eyre!("invalid retained SCCP QC"))?;
    if attribution.scope
        != (EvidenceScope::SccpGeneration {
            generation: material.generation,
        })
        || attribution.height != material.start_height
        || !attribution.safety_violation
        || attribution.offenders.len() != material.offenders.len()
        || !x.is_active()
        || x.generation() != material.generation
        || x.committee_root() != attribution.authority_generation
        || qc.epoch != attribution.epoch
        || qc.epoch_context != attribution.context_id
        || record.sccp_evidence_id().map(Hash::prehashed).as_ref() != Some(key)
    {
        return Err(eyre!(
            "SCCP penalty differs from its original record and attribution"
        ));
    }
    for (captured, attributed) in material.offenders.iter().zip(&attribution.offenders) {
        if captured.signer != attributed.signer
            || attributed.lane_stake.is_some()
            || qc.signers & (1u32 << captured.signer) == 0
        {
            return Err(eyre!(
                "SCCP penalty differs from its captured signer attribution"
            ));
        }
    }
    Ok(material)
}

/// Borrow the original registration by G6 tuple, never by its current peer key.
/// Missing or replaced registration is an invariant failure, not an empty slash.
pub(super) fn registration<'a>(
    world: &'a impl WorldReadOnly,
    offender: &SccpForgeryOffenderV1,
    start_height: u64,
) -> Result<&'a PublicLaneValidatorRecord> {
    let (key, current) = world
        .public_lane_validators()
        .iter()
        .find(|((lane, validator), _)| {
            *lane == offender.lane_id && validator == &offender.validator
        })
        .ok_or_else(|| eyre!("SCCP penalty lost its captured registration"))?;
    if !public_lane_validator_record_matches_key(key, current)
        || current.activation_height != offender.activation_height
        || !validator_tenure_contains_height(current, start_height)?
    {
        return Err(eyre!("SCCP penalty captured registration was substituted"));
    }
    Ok(current)
}

/// Recheck the exact action target against its immutable record before any movement.
pub(super) fn action_liability(
    world: &impl WorldReadOnly,
    record: &crate::state::RetainedEvidenceRecord,
    action: &NposConsensusSlashAction,
) -> Result<ConsensusSlashLiability> {
    let material = material(&action.evidence_key, record)?;
    let offender = material
        .offenders
        .iter()
        .find(|row| row.signer == action.signer)
        .ok_or_else(|| eyre!("SCCP slash does not name a captured G6 offender"))?;
    if action.slash_id != action.evidence_key
        || offender.lane_id != action.lane_id
        || offender.validator != action.validator
        || !record
            .attribution
            .offenders
            .iter()
            .any(|row| row.signer == action.signer && row.peer_id == action.peer_id)
    {
        return Err(eyre!(
            "SCCP slash target differs from captured G6 attribution"
        ));
    }
    registration(world, offender, material.start_height)?;
    Ok(ConsensusSlashLiability::Root(liability_height(material)))
}

fn liability_height(material: &SccpForgeryRecordV1) -> u64 {
    #[cfg(all(test, sumeragi_core_mutation = "HC318"))]
    {
        return iroha_data_model::sumeragi_finality::certified_result::SccpFinalityHeaderV1::parse(
            &material.evidence.header,
        )
        .expect("validated material")
        .height();
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC318")))]
    {
        material.start_height
    }
}

/// Plan all captured offenders in the same disposable ordered monetary overlay.
/// Any error drops the enclosing plan; the original record remains Pending.
pub(super) fn plan(
    original: &Pending,
    scratch: &mut crate::state::StateBlock<'_>,
    index: &PublicLaneStakeIndex,
    max_slash_bps: u16,
    header: &BlockHeader,
    actions: &mut funded_actions::ActionBuilder,
) -> Result<()> {
    let material = material(&original.key, &original.record)?;
    let liability = ConsensusSlashLiability::Root(liability_height(material));
    for (offender, attributed) in material
        .offenders
        .iter()
        .zip(&original.record.attribution.offenders)
    {
        #[cfg(all(test, sumeragi_core_mutation = "HC319"))]
        let current = scratch
            .world
            .public_lane_validators()
            .iter()
            .find(|(_, row)| row.peer_id == attributed.peer_id)
            .map(|(_, row)| row)
            .ok_or_else(|| eyre!("late peer map has no registration"))?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC319")))]
        let current = registration(&scratch.world, offender, material.start_height)?;
        let share_keys = index.share_keys(offender.lane_id, &offender.validator);
        let exposure = indexed_slashable_validator_exposure(
            &scratch.world,
            offender.lane_id,
            &offender.validator,
            current,
            &liability,
            share_keys,
        )
        .wrap_err("failed to compute original SCCP liable exposure")?;
        if &exposure > original_slashable_exposure(index, offender.lane_id, &offender.validator)? {
            return Err(eyre!(
                "SCCP exposure increased during ordered penalty planning"
            ));
        }
        let amount = funded_actions::slash_amount(&exposure, max_slash_bps, actions.budget())?;
        if amount.get().is_zero() {
            continue;
        }
        let mut transaction = scratch.consensus_effects_transaction()?;
        apply_indexed_slash_to_validator_without_observability(
            &mut transaction,
            offender.lane_id,
            &offender.validator,
            original.key,
            amount.get(),
            header.creation_time_ms,
            &liability,
            share_keys,
        )
        .wrap_err("failed to plan original SCCP custody slash")?;
        transaction.apply_consensus_effects();
        actions.slash(
            funded_actions::SlashFields {
                evidence_key: original.key,
                signer: offender.signer,
                peer_id: &attributed.peer_id,
                lane_id: offender.lane_id,
                validator: &offender.validator,
                slash_id: original.key,
            },
            amount,
        )?;
    }
    // Only after every captured registration and movement was successfully planned.
    actions.marker(original.key, header.height().get())?;
    Ok(())
}
