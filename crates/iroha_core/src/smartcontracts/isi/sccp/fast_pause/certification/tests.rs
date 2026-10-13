//! Independent component checks for current-state quorum and streamed certificate identities.
use super::*;
use crate::smartcontracts::isi::sccp::test_support::{
    blank_state, header, sample_fast_pause_round, sample_pause_panel, sample_route,
};
use norito::codec::Encode;

#[test]
fn sccp_pause_controls_preflight_capacity_nonce_and_every_live_part_before_effects() {
    let mut route = sample_route(SccpNetworkV1::EthereumMainnet);
    let prototype = route.revisions[&1].clone();
    route.revisions.clear();
    for (index, activation) in [
        SccpRouteActivationV1::Staged,
        SccpRouteActivationV1::Bidirectional,
        SccpRouteActivationV1::Paused,
        SccpRouteActivationV1::InboundOnly,
        SccpRouteActivationV1::Retired,
    ]
    .into_iter()
    .enumerate()
    {
        let mut revision = prototype.clone();
        revision.revision = u32::try_from(index).expect("fixture value fits u32") + 1;
        revision.activation = activation;
        route.revisions.insert(revision.revision, revision);
    }
    let before = route.clone();
    let (parts, count) = control_parts(&route, 509).unwrap();
    assert_eq!(&parts[..count], &[2, 3, 4]);
    assert_eq!(
        control_parts(&route, 510),
        Err(NoResult::ControlCapacity),
        "every fast-pause control must fit the remaining original block leaf capacity"
    );
    assert_eq!(route, before);
    route.revisions.get_mut(&4).unwrap().next_control_nonce = u64::MAX;
    assert_eq!(control_parts(&route, 0), Err(NoResult::CounterExhausted));
    route.revisions.retain(|key, _| *key == 1 || *key == 5);
    assert_eq!(control_parts(&route, 0), Err(NoResult::NoLiveRevision));
}
#[test]
fn sccp_pause_fingerprint_stream_matches_canonical_effect_bytes() {
    let state = blank_state();
    let network = *state.network_id_ref();
    let preimage = (network, SccpNetworkV1::TonMainnet, 17u64);
    assert_eq!(
        fingerprint(
            iroha_data_model::sccp::fast_pause::SCCP_FAST_PAUSE_EFFECT_V1,
            &preimage
        )
        .unwrap(),
        SccpFastPauseCertificateV1::effect_hash(network, SccpNetworkV1::TonMainnet, 17)
    );
}
#[test]
fn sccp_pause_certification_rechecks_revoked_members_and_exact_close_after_halt() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let network = SccpNetworkV1::EthereumMainnet;
    store::parameters::set(&mut tx, Some(SccpParametersV1::taira_default()));
    let mut route = sample_route(network);
    route.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::Bidirectional;
    store::routes::insert(&mut tx, network, route).unwrap();
    let mut panel = sample_pause_panel(1);
    panel.accepted = panel.drawn.iter().cloned().collect();
    let mut round = sample_fast_pause_round(1);
    round.panel_id = panel.primary_id;
    round.head = 0;
    round.endorsers = panel.drawn[..6]
        .iter()
        .cloned()
        .map(|account| {
            (
                account,
                SccpFastPauseEndorsementV1 {
                    incident_digest: [9; 32],
                    recorded_at_height: 2,
                },
            )
        })
        .collect();
    let panel =
        RetainedSccpPausePanel::admit(&panel, tx.sccp_evidence_preparation_budget()).unwrap();
    let round =
        RetainedSccpFastPauseRound::admit(&round, tx.sccp_evidence_preparation_budget()).unwrap();
    let time = round.closes_at_ms - 1;
    assert_eq!(
        recheck(
            &*tx.world,
            &panel,
            &round,
            network,
            SccpPanelRoleV1::Primary,
            time,
            u32::MAX
        )
        .unwrap()
        .1,
        6
    );
    assert_eq!(
        recheck(
            &*tx.world,
            &panel,
            &round,
            network,
            SccpPanelRoleV1::Primary,
            time,
            u32::MAX & !1
        ),
        Err(NoResult::InsufficientEligibleEndorsements),
        "revoked endorsers must not count toward certification quorum"
    );
    assert_eq!(
        recheck(
            &*tx.world,
            &panel,
            &round,
            network,
            SccpPanelRoleV1::Primary,
            time + 1,
            u32::MAX
        ),
        Err(NoResult::Expired),
        "endorsement windows must expire at the exact close even after a halt"
    );
    let (selected, count) = recheck(
        &*tx.world,
        &panel,
        &round,
        network,
        SccpPanelRoleV1::Primary,
        time,
        u32::MAX,
    )
    .unwrap();
    let (root, incident) = roots(&round, &selected, count).unwrap();
    let mut bytes = b"sccp/pause-endorsements/v1".to_vec();
    bytes.extend(count.to_be_bytes());
    let mut incidents = b"sccp/pause-incidents/v1".to_vec();
    incidents.extend(count.to_be_bytes());
    for (account, fact) in &round.endorsers {
        let encoded = account.encode();
        bytes.extend((encoded.len() as u64).to_be_bytes());
        bytes.extend(encoded);
        bytes.extend(fact.incident_digest);
        bytes.extend(fact.recorded_at_height.to_be_bytes());
        incidents.extend(fact.incident_digest);
    }
    assert_eq!(root, *Hash::new(bytes).as_ref());
    assert_eq!(incident, *Hash::new(incidents).as_ref());
}
