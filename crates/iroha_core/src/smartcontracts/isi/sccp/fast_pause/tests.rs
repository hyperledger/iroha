//! Component rules use explicit prestate; they issue no Parliament authority.
use super::*;
use crate::smartcontracts::isi::sccp::test_support::{
    authority, blank_state, header, sample_fast_pause, sample_pause_panel, sample_route,
};

fn panel(accepted: &[usize]) -> RetainedSccpPausePanel {
    let mut source = sample_pause_panel(1);
    source.drawn = (1..=15).map(authority).collect();
    source.accepted = accepted
        .iter()
        .map(|index| source.drawn[*index].clone())
        .collect();
    RetainedSccpPausePanel::admit(&source, &iroha_allocation::AllocationBudget::new(1 << 20))
        .unwrap()
}
#[test]
fn sccp_pause_seats_replace_only_unaccepted_in_primary_then_backup_order_at_deadline() {
    let panel = panel(&[1, 5, 10, 11, 12, 13, 14]);
    let before = seats(&panel, 5, panel.accept_until_ms - 1, u32::MAX).unwrap();
    assert_eq!(
        &before[..10],
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        "reserve replacement must wait until the exact acceptance deadline"
    );
    let at = seats(
        &panel,
        5,
        panel.accept_until_ms,
        u32::MAX & !(1 << 11) & !(1 << 1),
    )
    .unwrap();
    assert_eq!(
        &at[..10],
        &[10, 1, 12, 13, 14, 5, 6, 7, 8, 9],
        "reserve replacement must be disjoint, eligible and primary-first"
    );
    assert!(!counts(
        &panel,
        &at,
        SccpPanelRoleV1::Primary,
        5,
        u32::MAX & !(1 << 1),
        &panel.drawn[1]
    ));
    assert!(!counts(
        &panel,
        &at,
        SccpPanelRoleV1::Primary,
        5,
        u32::MAX,
        &panel.drawn[11]
    ));
}
#[test]
fn sccp_pause_acceptance_is_original_funded_and_preserves_draw_and_term() {
    let original = panel(&[10]);
    let source = &original.drawn[2];
    assert!(matches!(
        accepted_panel(
            &original,
            source,
            &iroha_allocation::AllocationBudget::new(0)
        ),
        Err(PauseRecordError::Admission(_))
    ));
    let budget = iroha_allocation::AllocationBudget::new(1 << 20);
    let accepted = accepted_panel(&original, source, &budget).unwrap();
    assert_eq!(accepted.drawn, original.drawn);
    assert_eq!(
        (accepted.accept_until_ms, accepted.term_ends_at_ms),
        (original.accept_until_ms, original.term_ends_at_ms)
    );
    assert!(accepted.accepted.binary_search(source).is_ok());
    assert!(original.accepted.binary_search(source).is_err());
    let occupied = budget.reserved_bytes();
    let same = accepted_panel(&accepted, source, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), occupied);
    drop(accepted);
    assert!(budget.reserved_bytes() > 0);
    drop(same);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn sccp_pause_conditions_bind_live_route_head_suspension_and_renewal_boundary() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let network = SccpNetworkV1::EthereumMainnet;
    let parameters = SccpParametersV1::taira_default();
    assert_eq!(
        conditions(&*tx.world, network, 0, 100, &parameters),
        Err(NoResult::NoLiveRevision)
    );
    let mut route = sample_route(network);
    route.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::InboundOnly;
    store::routes::insert(&mut tx, network, route).unwrap();
    assert!(conditions(&*tx.world, network, 0, 100, &parameters).is_ok());
    store::set_governance_revision(&mut tx, SccpGovernanceSubjectV1::FastHold(network), 1);
    assert_eq!(
        conditions(&*tx.world, network, 0, 100, &parameters),
        Err(NoResult::HeadChanged)
    );
    store::fast_pause_suspended_until_ms::insert(&mut tx, network, 101).unwrap();
    assert_eq!(
        conditions(&*tx.world, network, 1, 100, &parameters),
        Err(NoResult::Suspended)
    );
    let mut pause = sample_fast_pause(1);
    pause.until_ms = 1000 + parameters.fast_pause_renew_lead_ms;
    let retained = super::super::pause_record::RetainedSccpFastPause::admit(
        &pause,
        tx.sccp_evidence_preparation_budget(),
    )
    .unwrap();
    store::fast_pauses::insert(&mut tx, network, retained).unwrap();
    assert_eq!(
        conditions(&*tx.world, network, 1, 999, &parameters),
        Err(NoResult::RenewalWindowClosed)
    );
    assert!(conditions(&*tx.world, network, 1, 1000, &parameters).is_ok());
}
#[test]
fn sccp_pause_suspension_never_clears_active_parts_and_zero_removes_only_suspension() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let network = SccpNetworkV1::TonMainnet;
    let original = super::super::pause_record::RetainedSccpFastPause::admit(
        &sample_fast_pause(1),
        tx.sccp_evidence_preparation_budget(),
    )
    .unwrap();
    store::fast_pauses::insert(&mut tx, network, original.clone()).unwrap();
    suspend(&mut tx, network, 30).unwrap();
    assert_eq!(
        store::fast_pause_suspended_until_ms::get(&*tx.world, &network),
        Some(&8030)
    );
    assert_eq!(
        store::fast_pauses::get(&*tx.world, &network),
        Some(&original),
        "suspension must preserve every active fast-pause part"
    );
    suspend(&mut tx, network, 0).unwrap();
    assert!(store::fast_pause_suspended_until_ms::get(&*tx.world, &network).is_none());
    assert_eq!(
        store::fast_pauses::get(&*tx.world, &network),
        Some(&original)
    );
    assert!(
        suspend(
            &mut tx,
            network,
            3 * iroha_data_model::sccp::params::SCCP_MAX_FAST_PAUSE_MS_V1 + 1
        )
        .is_err()
    );
}

#[test]
fn sccp_pause_lift_compares_original_height_position_and_removes_only_the_matching_part() {
    use iroha_data_model::{
        governance::GovernanceAnchorV1,
        sccp::{events::SccpFastPausePartV1 as Part, fast_pause::SccpPassPositionV1},
    };
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let network = SccpNetworkV1::TonMainnet;
    let mut source = sample_fast_pause(1);
    source.enacted_at = SccpPassPositionV1 {
        height: 2,
        position: 5,
    };
    let original = super::super::pause_record::RetainedSccpFastPause::admit(
        &source,
        tx.sccp_evidence_preparation_budget(),
    )
    .unwrap();
    store::fast_pauses::insert(&mut tx, network, original.clone()).unwrap();
    for (height, position) in [(1, 99), (2, 4), (2, 5)] {
        lift_at(
            &mut tx,
            network,
            Part::Taira,
            GovernanceAnchorV1 {
                height,
                position,
                timestamp_ms: u64::MAX,
            },
        )
        .unwrap();
        assert_eq!(
            store::fast_pauses::get(&*tx.world, &network),
            Some(&original),
            "a resume cannot lift a pause enacted at or after its original casting-open position"
        );
        assert_eq!(
            store::governance_revision(&*tx.world, &SccpGovernanceSubjectV1::FastHold(network)),
            0
        );
    }
    let newer = GovernanceAnchorV1 {
        height: 2,
        position: 6,
        timestamp_ms: 0,
    };
    lift_at(&mut tx, network, Part::Destination { revision: 1 }, newer).unwrap();
    let remaining = store::fast_pauses::get(&*tx.world, &network).unwrap();
    assert!(remaining.taira);
    assert_eq!(remaining.revisions, [3]);
    lift_at(&mut tx, network, Part::Taira, newer).unwrap();
    assert_eq!(
        store::fast_pauses::get(&*tx.world, &network)
            .unwrap()
            .revisions,
        [3]
    );
    lift_at(&mut tx, network, Part::Destination { revision: 3 }, newer).unwrap();
    assert!(store::fast_pauses::get(&*tx.world, &network).is_none());
    assert_eq!(
        store::governance_revision(&*tx.world, &SccpGovernanceSubjectV1::FastHold(network)),
        3
    );
}
