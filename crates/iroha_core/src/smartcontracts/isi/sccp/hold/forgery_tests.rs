//! Forgery/quarantine hold controls.

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
        assert_eq!(
            forgery_or_quarantine(&*stx.world, revision),
            expected,
            "SC25 must hold every revision whose original forgery floor is not above the maximum offence"
        );
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

#[test]
fn fast_pause_expiry_cannot_release_forgery_or_permanent_quarantine() {
    use crate::smartcontracts::isi::sccp::test_support::install_consumer_fast_pause;
    use iroha_data_model::sccp::params::SccpParametersV1;

    let state = blank_state();
    let mut block = state.block(header(2));
    let mut stx = block.transaction();
    let network = SccpNetworkV1::EthereumMainnet;
    let mut route = sample_route(network);
    route.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::Bidirectional;
    route.revisions.get_mut(&1).unwrap().forgery_floor = 2;
    store::routes::insert(&mut stx, network, route.clone()).unwrap();
    let mut parameters = SccpParametersV1::taira_default();
    parameters.enabled = true;
    store::parameters::set(&mut stx, Some(parameters));
    install_consumer_fast_pause(&mut stx, network, true, vec![1], 10_000);
    assert!(taira(&*stx.world, network, 1, Some(9_999)));
    assert!(!taira(&*stx.world, network, 1, Some(10_000)));

    *stx.world.sccp_forgery_max_generation.get_mut() = Some(2);
    assert!(taira(&*stx.world, network, 1, Some(10_000)));
    assert!(taira(&*stx.world, network, 1, Some(u64::MAX)));
    // Test DATA changes one independent gate at a time; this grants no reconciliation.
    *stx.world.sccp_forgery_max_generation.get_mut() = None;
    route.revisions.get_mut(&1).unwrap().quarantine = Some(SccpQuarantineV1 {
        certificate_id: [0x81; 32],
        since_height: 1,
    });
    store::routes::insert(&mut stx, network, route).unwrap();
    assert!(taira(&*stx.world, network, 1, Some(u64::MAX)));
}
