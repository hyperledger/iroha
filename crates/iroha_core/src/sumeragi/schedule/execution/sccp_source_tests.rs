//! SCCP initialization borrows only the original signed-genesis capture.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::blank_state;
use iroha_data_model::parameter::system::SumeragiConsensusMode;

#[test]
fn signed_genesis_capture_survives_mutable_peer_substitution_and_child_rollback() {
    let signed =
        crate::sumeragi::epoch::tests::genesis_fixture(SumeragiConsensusMode::Npos, 10, false);
    let expected = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .unwrap()
        .into_parts()
        .0;
    let state = blank_state();
    let mut block = state.block(signed.header());
    assert!(block.sumeragi_schedule.sccp_genesis_source().is_none());
    block
        .request_sumeragi_schedule(1, &signed, None, None)
        .unwrap();
    {
        let mut transaction = block.transaction();
        transaction.world.peers.clear();
        let original = transaction.sccp_genesis_source.as_ref().unwrap();
        assert_eq!(original.epoch(), &expected);
        assert_eq!(
            original.root_scope(),
            iroha_data_model::block::consensus::SumeragiRootScope::Global
        );
        assert!(
            transaction.world.consensus_schedule().entries().is_empty(),
            "genesis authority is captured before the finalizer installs World schedule"
        );
    }
    assert_eq!(
        block
            .sumeragi_schedule
            .sccp_genesis_source()
            .unwrap()
            .epoch(),
        &expected,
        "child rollback cannot replace the original capture"
    );
}

#[test]
fn absent_native_capture_cannot_be_replaced_with_staged_world_peers() {
    assert!(ScheduleStep::Off.sccp_genesis_source().is_none());
    let signed =
        crate::sumeragi::epoch::tests::genesis_fixture(SumeragiConsensusMode::Npos, 10, false);
    let state = blank_state();
    let mut block = state.block(signed.header());
    let transaction = block.transaction();
    assert!(transaction.sccp_genesis_source.is_none());
}
