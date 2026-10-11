//! Bind startup execution geometry to the independently authenticated original genesis scope.

use iroha_config::parameters::actual::Nexus;
use iroha_data_model::block::consensus::{ConsensusMode, SumeragiRootScope};

#[cfg(test)]
use iroha_config::parameters::actual::LaneConfig;
#[cfg(test)]
use iroha_data_model::nexus::{
    AUTOSCALE_META_COMMITTEE, AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_DRAIN_STATE,
    AUTOSCALE_META_MANAGED, LaneStorageProfile, LaneVisibility,
};
#[cfg(test)]
use iroha_model_base::topology::LaneId;

/// Check geometry only after the caller has authenticated the original signed genesis context.
pub(super) fn validate(
    nexus: &Nexus,
    mode: ConsensusMode,
    scope: SumeragiRootScope,
) -> Result<(), &'static str> {
    scope.validate().map_err(|_| "invalid signed root scope")?;
    let SumeragiRootScope::Dataspace { dataspace_id, .. } = scope else {
        return if nexus.uses_multilane_catalogs() && mode != ConsensusMode::Npos {
            Err("custom Nexus lane topology requires the authenticated consensus mode to be NPoS")
        } else {
            Ok(())
        };
    };
    if mode != ConsensusMode::Permissioned {
        return Err("private root requires the authenticated consensus mode to be Permissioned");
    }
    nexus.validate_private_root_geometry(dataspace_id)
}

#[cfg(test)]
mod tests;
