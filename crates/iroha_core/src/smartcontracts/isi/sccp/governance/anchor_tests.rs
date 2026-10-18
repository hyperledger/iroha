//! The authenticated Parliament casting-open anchor reaches each SCCP resume consumer.

use super::{enact, store};
use crate::{
    smartcontracts::isi::sccp::{
        pause_record::RetainedSccpFastPause,
        test_support::{blank_state, header, sample_fast_pause, sample_route},
    },
    state::StateReadOnly,
};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    governance::GovernanceAnchorV1,
    sccp::{
        events::SccpFastPausePartV1 as Part,
        fast_pause::SccpPassPositionV1,
        governance::{
            SccpGovernanceActionV1 as Action, SccpGovernanceProposalV1,
            SccpGovernanceSubjectV1 as Subject, SccpSetDestinationPausedActionV1,
            SccpSetTairaPausedActionV1,
        },
        params::SccpParametersV1,
        registry::SccpRouteActivationV1,
    },
};

#[test]
fn enactment_preserves_casting_open_anchor_for_each_pause_part() {
    const CERTIFICATE_ID: [u8; 32] = [0x43; 32];
    const EFFECT_HASH: [u8; 32] = [0x45; 32];
    let network = SccpNetworkV1::EthereumMainnet;
    for part in [Part::Taira, Part::Destination { revision: 1 }] {
        for (height, position, lifted) in [
            (1, u32::MAX, false),
            (2, 4, false),
            (2, 5, false),
            (2, 6, true),
            (3, 0, true),
        ] {
            for timestamp_ms in [0, 8_000, u64::MAX] {
                let state = blank_state();
                let mut block = state.block(header(4));
                let mut stx = block.transaction();
                store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
                let mut route = sample_route(network);
                let revision = route.revisions.get_mut(&1).unwrap();
                revision.activation = SccpRouteActivationV1::Paused;
                revision.ever_activated = true;
                revision.destination_paused = true;
                store::routes::insert(&mut stx, network, route).unwrap();
                let mut source = sample_fast_pause(1);
                source.enacted_at = SccpPassPositionV1 {
                    height: 2,
                    position: 5,
                };
                source.enacted_at_ms = 8_000;
                source.until_ms = stx.block_unix_timestamp_ms() + 1_000;
                let original =
                    RetainedSccpFastPause::admit(&source, stx.sccp_evidence_preparation_budget())
                        .unwrap();
                store::fast_pauses::insert(&mut stx, network, original).unwrap();
                let (subject, action) = match part {
                    Part::Taira => (
                        Subject::Route(network),
                        Action::SetTairaPaused(SccpSetTairaPausedActionV1 {
                            network,
                            paused: false,
                        }),
                    ),
                    Part::Destination { revision } => (
                        Subject::RouteControl(network),
                        Action::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
                            network,
                            revision,
                            paused: false,
                        }),
                    ),
                };
                let proposal = SccpGovernanceProposalV1 {
                    network_id: *stx.network_id(),
                    base_revisions: vec![(subject, 0).into()],
                    actions: vec![action],
                };
                // This component supplies authenticated interface DATA, not a synthetic
                // Parliament certificate or evidence that the production ballot is ready.
                enact(
                    &mut stx,
                    CERTIFICATE_ID,
                    EFFECT_HASH,
                    GovernanceAnchorV1 {
                        height,
                        position,
                        timestamp_ms,
                    },
                    &proposal,
                )
                .unwrap();

                let remaining = store::fast_pauses::get(&*stx.world, &network).unwrap();
                let part_is_held = match part {
                    Part::Taira => remaining.taira,
                    Part::Destination { revision } => remaining.revisions.contains(&revision),
                };
                assert_eq!(
                    part_is_held, !lifted,
                    "SCCP enactment must preserve the authenticated casting-open anchor for the requested pause part"
                );
                assert_eq!(remaining.certificate_id, source.certificate_id);
                assert_eq!(remaining.effect_hash, source.effect_hash);
                assert_eq!(remaining.enacted_at, source.enacted_at);
                assert_eq!(remaining.until_ms, source.until_ms);
                assert_eq!(
                    store::governance_revision(&*stx.world, &Subject::FastHold(network)),
                    u64::from(lifted)
                );
                assert_eq!(store::governance_revision(&*stx.world, &subject), 1);
                let revision = &store::routes::get(&*stx.world, &network).unwrap().revisions[&1];
                match part {
                    Part::Taira => {
                        assert_eq!(remaining.revisions, [1, 3]);
                        assert_eq!(revision.activation, SccpRouteActivationV1::Bidirectional);
                        assert!(revision.destination_paused);
                        assert!(store::control_messages::is_empty(&*stx.world));
                    }
                    Part::Destination { revision: number } => {
                        assert!(remaining.taira);
                        assert!(remaining.revisions.contains(&3));
                        assert!(!revision.destination_paused);
                        assert_eq!(revision.activation, SccpRouteActivationV1::Paused);
                        let control =
                            store::control_messages::get(&*stx.world, &(network, number, 1))
                                .unwrap();
                        assert_eq!(control.certificate_id, CERTIFICATE_ID);
                        assert_eq!(control.effect_hash, EFFECT_HASH);
                        assert!(!control.parliament_paused);
                        assert_eq!(
                            control.fast_pause_until_ms,
                            if lifted { 0 } else { source.until_ms }
                        );
                    }
                }
            }
        }
    }
}
