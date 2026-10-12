//! Read API proofs over genuine executed SCCP blocks and original Kura/State custody.

use super::*;
use crate::{
    smartcontracts::isi::sccp::native_tests::native_chain_config,
    sumeragi::test_chain::CertifiedTestChain,
};

#[test]
fn native_finality_api_uses_executed_header_original_committee_and_same_committed_cut() {
    let mut chain = CertifiedTestChain::start(native_chain_config()).unwrap();
    {
        let view = chain.state().view();
        assert!(matches!(
            finality_certificate(&view, 1),
            Err(SccpReadError::Unavailable(_))
        ));
        let capabilities = capabilities(&view).unwrap();
        assert_eq!(capabilities.committed_height, 1);
        assert_eq!(capabilities.current_generation.unwrap().generation, 1);
    }
    chain.commit_at(2_000, Vec::new());
    let view = chain.state().view();
    let certificate = finality_certificate(&view, 2).unwrap();
    let generation = view.world().sccp_committee_generations().get(&1).unwrap();
    let instance = CertifiedChain::new(&view).unwrap().instance();
    let verified = verify_native_certificate(
        &certificate,
        view.network_id().as_bytes(),
        &instance.0,
        generation.record(),
    )
    .unwrap();
    assert_eq!(verified.header.height(), 2);
    let original_block = chain.committed(2);
    assert_eq!(
        verified.header.timestamp_ms(),
        original_block.block_time_ms()
    );
    assert!(verified.header.timestamp_ms() >= 2_000);
    assert_eq!(
        verified.result,
        view.native_execution_tip().unwrap().result().0
    );
    assert_eq!(certificate.committee, generation.keys);
    assert!(matches!(
        finality_certificate(&view, 0),
        Err(SccpReadError::NotFound(_))
    ));
    assert!(matches!(
        finality_certificate(&view, 3),
        Err(SccpReadError::NotFound(_))
    ));
    let before = view.native_execution_tip().unwrap();
    let json = norito::json::to_json(&certificate).unwrap();
    let decoded = norito::json::from_str::<SccpCertificateV1>(&json).unwrap();
    assert_eq!(decoded, certificate);
    let mut changed = decoded;
    changed.header[56] ^= 1;
    assert!(
        verify_native_certificate(
            &changed,
            view.network_id().as_bytes(),
            &instance.0,
            generation.record()
        )
        .is_err()
    );
    assert_eq!(
        view.native_execution_tip().unwrap().result(),
        before.result()
    );
}

#[test]
fn native_rotation_api_exports_the_exact_executed_heartbeat_handoff() {
    let mut chain = CertifiedTestChain::start(native_chain_config()).unwrap();
    let rotation_time = {
        let view = chain.state().view();
        let generation = view.world().sccp_committee_generations().get(&1).unwrap();
        generation.start_timestamp_ms
            + store::parameters::get(view.world())
                .as_ref()
                .unwrap()
                .committee_heartbeat_ms
    };
    chain.commit_at(rotation_time, Vec::new());
    let view = chain.state().view();
    assert_eq!(view.world().sccp_committee_current(), 2);
    let handoffs = rotation_chain(&view, 1, MAX_ROTATION_STEPS).unwrap();
    assert_eq!(handoffs.len(), 1);
    let current = view.world().sccp_committee_generations().get(&2).unwrap();
    let outgoing = view.world().sccp_committee_generations().get(&1).unwrap();
    let instance = CertifiedChain::new(&view).unwrap().instance();
    let verified = verify_native_certificate(
        &handoffs[0].certificate,
        view.network_id().as_bytes(),
        &instance.0,
        outgoing.record(),
    )
    .unwrap();
    assert!(verified.header.is_rotation());
    assert_eq!(verified.header.generation(), 1);
    assert_eq!(
        verified.header.next_committee_root(),
        current.committee_root
    );
    assert_eq!(handoffs[0].next_committee, current.keys);
    assert_eq!(outgoing.end.unwrap().end_height, 2);
    assert_eq!(current.start_height, 3);
    assert!(rotation_chain(&view, 2, 1).unwrap().is_empty());
    assert!(matches!(
        rotation_chain(&view, 1, 0),
        Err(SccpReadError::Invalid(_))
    ));
}
