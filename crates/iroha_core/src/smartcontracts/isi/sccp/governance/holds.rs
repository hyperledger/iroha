//! Parliament-only progress and quarantine effects over original retained route state.

use super::{Error, controls::ControlCauseV1, refuse, store};
use crate::state::StateTransaction;
use iroha_data_model::sccp::{
    events::{SccpEvent, SccpRevisionForgeryReleasedV1, SccpRevisionQuarantinedV1},
    governance::{
        SccpAttestDeploymentProgressActionV1, SccpDeploymentProgressV1, SccpRouteRevisionActionV1,
    },
    native::SccpQuarantineV1,
};

pub(super) fn attest(
    stx: &mut StateTransaction<'_, '_>,
    action: &SccpAttestDeploymentProgressActionV1,
) -> Result<(), Error> {
    let world = &*stx.world;
    let floor = match action.at {
        SccpDeploymentProgressV1::Frozen => u64::MAX,
        SccpDeploymentProgressV1::Generation {
            generation,
            committee_root,
        } => {
            if generation == 0 || generation > *store::committee_current::get(world) {
                return Err(refuse(
                    "attested generation is not a current or past generation",
                ));
            }
            let record = store::committee_generations::get(world, &generation)
                .ok_or_else(|| refuse("attested generation is not retained"))?;
            if record.committee_root != committee_root || !record.is_well_formed() {
                return Err(refuse(
                    "attested committee root differs from the retained generation",
                ));
            }
            generation
        }
    };
    let maximum = store::forgery_max_generation(world);
    let mut route = store::routes::get(world, &action.network)
        .cloned()
        .ok_or_else(|| refuse("attested route does not exist"))?;
    let revision = route
        .revisions
        .get_mut(&action.revision)
        .ok_or_else(|| refuse("attested revision does not exist"))?;
    let was_held = revision.forgery_held(maximum);
    revision.forgery_floor = if cfg!(all(test, sumeragi_core_mutation = "HC285")) {
        floor
    } else {
        revision.forgery_floor.max(floor)
    };
    let released = was_held && !revision.forgery_held(maximum);
    let floor = revision.forgery_floor;
    store::routes::insert(stx, action.network, route)?;
    if released {
        stx.world
            .emit_events(Some(SccpEvent::RevisionForgeryReleased(
                SccpRevisionForgeryReleasedV1 {
                    network: action.network,
                    revision: action.revision,
                    forgery_floor: floor,
                },
            )));
    }
    Ok(())
}

pub(super) fn quarantine(
    stx: &mut StateTransaction<'_, '_>,
    action: SccpRouteRevisionActionV1,
    cause: ControlCauseV1,
) -> Result<(), Error> {
    let mut route = store::routes::get(&*stx.world, &action.network)
        .cloned()
        .ok_or_else(|| refuse("quarantined route does not exist"))?;
    let revision = route
        .revisions
        .get_mut(&action.revision)
        .ok_or_else(|| refuse("quarantined revision does not exist"))?;
    if !cfg!(all(test, sumeragi_core_mutation = "HC286")) && revision.quarantine.is_some() {
        return Ok(());
    }
    let quarantine = SccpQuarantineV1 {
        certificate_id: cause.certificate_id,
        since_height: stx.block_height(),
    };
    revision.quarantine = Some(quarantine);
    store::routes::insert(stx, action.network, route)?;
    stx.world.emit_events(Some(SccpEvent::RevisionQuarantined(
        SccpRevisionQuarantinedV1 {
            network: action.network,
            revision: action.revision,
            certificate_id: quarantine.certificate_id,
            since_height: quarantine.since_height,
        },
    )));
    Ok(())
}

#[cfg(test)]
#[path = "holds/tests.rs"]
mod tests;
