//! ZK referenda auto-close should not emit decisions without a finalized tally.

use core::num::NonZeroU64;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        ElectionState, GovernanceReferendumMode, GovernanceReferendumRecord,
        GovernanceReferendumStatus, State, World, WorldReadOnly,
    },
};
use iroha_data_model::{
    block::BlockHeader,
    events::data::{DataEvent, governance::GovernanceEvent},
};
use mv::storage::StorageReadOnly;
#[test]
fn zk_referendum_auto_close_defers_decision_without_tally() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    let rid = hex::encode([0x11_u8; 32]);
    let header1 = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock1 = state.block(header1);
    let mut stx1 = sblock1.transaction();
    stx1.world.governance_referenda_mut().insert(
        rid.clone(),
        GovernanceReferendumRecord {
            h_start: 1,
            h_end: 2,
            status: GovernanceReferendumStatus::Open,
            mode: GovernanceReferendumMode::Zk,
            plain_context:
                iroha_data_model::governance::conviction::PlainVotingContextV1::NotApplicable,
            plain_result:
                iroha_data_model::governance::conviction::PlainVotingResultV1::NotApplicable,
        },
    );
    stx1.world.elections_mut().insert(
        rid.clone(),
        ElectionState {
            options: 2,
            eligible_root: [0u8; 32],
            start_ts: 0,
            end_ts: 0,
            finalized: false,
            tally: vec![0, 0],
            accepted_ballots: Vec::new(),
            vk_ballot: None,
            vk_ballot_commitment: None,
            vk_tally: None,
            vk_tally_commitment: None,
            domain_tag: "gov:ballot:v1".to_string(),
        },
    );
    stx1.apply();
    sblock1.commit_empty_block_for_testing().unwrap();
    let header2 = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut sblock2 = state.block(header2);
    let events_at_end = sblock2.world.take_external_events();
    assert!(
        !events_at_end.iter().any(|event| {
            matches!(
                event.as_data_event(),
                Some(DataEvent::Governance(GovernanceEvent::ReferendumClosed(_)))
            )
        }),
        "inclusive h_end must remain open for ballots"
    );
    sblock2.commit_empty_block_for_testing().unwrap();
    let header3 = BlockHeader::new(NonZeroU64::new(3).unwrap(), None, None, 0, 0);
    let mut sblock3 = state.block(header3);
    let events = sblock3.world.take_external_events();
    let has_closed = events.iter().any(|event| {
        matches!(
            event.as_data_event(),
            Some(DataEvent::Governance(GovernanceEvent::ReferendumClosed(_)))
        )
    });
    assert!(has_closed, "expected ReferendumClosed at h_end + 1");
    let has_decision = events.iter().any(|event| {
        matches!(
            event.as_data_event(),
            Some(DataEvent::Governance(
                GovernanceEvent::ReferendumDecided(_) | GovernanceEvent::ProposalRejected(_)
            ))
        )
    });
    assert!(
        !has_decision,
        "unexpected decision without finalized zk tally"
    );
    sblock3.commit_empty_block_for_testing().unwrap();
    assert!(
        state
            .view()
            .world()
            .governance_referenda()
            .get(&rid)
            .is_some_and(|record| record.status == GovernanceReferendumStatus::Closed),
        "a ZK referendum awaiting its tally remains durably closed"
    );
}
