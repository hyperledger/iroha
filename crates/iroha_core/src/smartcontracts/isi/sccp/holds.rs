//! Exact forgery and quarantine gates shared by SCCP value paths (§4.10).
//!
//! This predicate reads current committed/executing state; it does not authenticate evidence
//! or governance, and a false result grants no permission. Other activation, pause, finality,
//! supply and recipient checks remain with their owners.

use super::store;
use crate::state::WorldReadOnly;
use iroha_data_model::sccp::registry::SccpRouteRevisionV1;

/// Whether a recorded forgery or permanent quarantine blocks this revision's value paths.
///
/// TODO: settlement may lift the quarantine/forgery leg only through the authenticated
/// reconciliation result and its exact payout owner (§4.10 R3–R4). That state does not exist
/// yet, so this function never infers reconciliation from an activation, pause or floor.
/// Outbound recording must continue to refuse every quarantined revision permanently.
#[must_use]
pub(super) fn forgery_or_quarantine(
    world: &(impl WorldReadOnly + ?Sized),
    revision: &SccpRouteRevisionV1,
) -> bool {
    revision.forgery_held(store::forgery_max_generation(world)) || revision.quarantine.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_route};
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::{native::SccpQuarantineV1, registry::SccpRouteActivationV1},
    };

    #[test]
    fn forgery_floor_is_inclusive_and_u64_max_is_not_a_release_sentinel() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let mut route = sample_route(SccpNetworkV1::EthereumMainnet);
        let revision = route.revisions.get_mut(&1).unwrap();
        // Injected DATA exercises the predicate only, not evidence/governance authority.
        for (floor, maximum, expected) in [
            (1, None, false),
            (2, Some(1), false),
            (2, Some(2), true),
            (2, Some(3), true),
            (u64::MAX, Some(u64::MAX - 1), false),
            (u64::MAX, Some(u64::MAX), true),
        ] {
            revision.forgery_floor = floor;
            *stx.world.sccp_forgery_max_generation.get_mut() = maximum;
            assert_eq!(forgery_or_quarantine(&*stx.world, revision), expected);
        }
    }

    #[test]
    fn quarantine_is_independent_of_activation_floor_and_forgery_absence() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let stx = block.transaction();
        let mut route = sample_route(SccpNetworkV1::EthereumMainnet);
        let revision = route.revisions.get_mut(&1).unwrap();
        revision.forgery_floor = u64::MAX;
        revision.quarantine = Some(SccpQuarantineV1 {
            certificate_id: [0x81; 32],
            since_height: 1,
        });
        for activation in [
            SccpRouteActivationV1::Staged,
            SccpRouteActivationV1::Bidirectional,
            SccpRouteActivationV1::Paused,
            SccpRouteActivationV1::InboundOnly,
            SccpRouteActivationV1::Retired,
        ] {
            revision.activation = activation;
            assert!(forgery_or_quarantine(&*stx.world, revision));
            assert_eq!(
                revision.quarantine.as_ref().unwrap().certificate_id,
                [0x81; 32]
            );
        }
    }
}
