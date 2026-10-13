//! Current control ordering, cause binding, destination identity and expiry controls.

use super::*;
use crate::pure::test_support::{Fixture, INSTANCE, NETWORK, NOW};
use iroha_sccp::v1::{
    control::{MAX_FAST_PAUSE_MS, control_leaf},
    destination::DestinationFlavor,
    finality::SccpFinalityHeaderFieldsV1,
    merkle::PromoteOddTree,
    proof::ProofError,
};

fn context(f: &Fixture) -> DestinationContextV1<'_> {
    DestinationContextV1 {
        taira_network_id: NETWORK,
        consensus_instance: INSTANCE,
        destination: f.destination,
        flavor: DestinationFlavor::Evm,
        committee_state: f.state,
        ton_keys: None,
        checkpoints: &f.checkpoints,
        now_ms: NOW,
    }
}

#[test]
fn newest_control_prefers_the_higher_nonce() {
    let destination = DestinationControlStateV1 {
        control_nonce: 3,
        ..Default::default()
    };
    let newer = TairaControlV1 {
        control_nonce: 4,
        parliament_paused: true,
        fast_pause_until_ms: 0,
    };
    let older = TairaControlV1 {
        control_nonce: 3,
        ..newer
    };
    assert_eq!(
        newest_control(&destination, Some(&newer), NOW),
        NewestControlV1 {
            control_nonce: 4,
            paused: true,
            source: ControlSourceV1::Taira,
        }
    );
    assert_eq!(
        newest_control(&destination, Some(&older), NOW).source,
        ControlSourceV1::Destination
    );
    assert_eq!(
        newest_control(&destination, None, NOW).source,
        ControlSourceV1::Destination
    );
}

#[test]
fn recording_is_refused_only_behind_a_newest_pause() {
    let running = DestinationControlStateV1 {
        control_nonce: 1,
        ..Default::default()
    };
    let paused = DestinationControlStateV1 {
        parliament_paused: true,
        ..running
    };
    let pending_pause = TairaControlV1 {
        control_nonce: 2,
        parliament_paused: true,
        fast_pause_until_ms: 0,
    };
    let pending_resume = TairaControlV1 {
        parliament_paused: false,
        ..pending_pause
    };
    assert!(check_may_record(&running, None, NOW).is_ok());
    assert!(check_may_record(&running, Some(&pending_pause), NOW).is_err());
    assert!(check_may_record(&paused, None, NOW).is_err());
    assert!(check_may_record(&paused, Some(&pending_resume), NOW).is_ok());
    assert!(
        check_may_record(&paused, None, NOW)
            .unwrap_err()
            .to_string()
            .contains("nonce 1")
    );
    let fast = DestinationControlStateV1 {
        fast_pause_until_ms: NOW + 1,
        ..running
    };
    assert!(check_may_record(&fast, None, NOW).is_err());
    assert!(check_may_record(&fast, None, NOW + 1).is_ok());
    assert!(
        check_may_record(
            &DestinationControlStateV1 {
                parliament_paused: true,
                ..fast
            },
            None,
            NOW + 1
        )
        .is_err()
    );
}

#[test]
fn finalization_applies_newer_controls_first() {
    let running = DestinationControlStateV1 {
        control_nonce: 1,
        ..Default::default()
    };
    let paused = DestinationControlStateV1 {
        parliament_paused: true,
        ..running
    };
    let resume = TairaControlV1 {
        control_nonce: 3,
        parliament_paused: false,
        fast_pause_until_ms: 0,
    };
    let pause = TairaControlV1 {
        parliament_paused: true,
        ..resume
    };
    let stale = TairaControlV1 {
        control_nonce: 1,
        ..resume
    };
    assert_eq!(
        plan_before_finalize(&running, None, NOW),
        PreFinalizeActionV1::Finalize
    );
    assert_eq!(
        plan_before_finalize(&paused, None, NOW),
        PreFinalizeActionV1::Paused
    );
    assert_eq!(
        plan_before_finalize(&paused, Some(&resume), NOW),
        PreFinalizeActionV1::ApplyControl {
            control_nonce: 3,
            paused: false
        }
    );
    // An unavailable candidate proof never changes this required action to Finalize.
    assert_eq!(
        plan_before_finalize(&running, Some(&pause), NOW),
        PreFinalizeActionV1::ApplyControl {
            control_nonce: 3,
            paused: true
        }
    );
    assert_eq!(
        plan_before_finalize(&paused, Some(&stale), NOW),
        PreFinalizeActionV1::Paused
    );
    let expired = TairaControlV1 {
        fast_pause_until_ms: NOW,
        ..resume
    };
    assert_eq!(
        plan_before_finalize(&running, Some(&expired), NOW),
        PreFinalizeActionV1::ApplyControl {
            control_nonce: 3,
            paused: false
        }
    );
}

#[test]
fn control_bundles_verify_for_their_own_deployment_only() {
    let fixture = Fixture::new();
    let bundle = fixture.control();
    let context = context(&fixture);
    let applied = DestinationControlStateV1::default();
    let verified =
        verify_control_bundle(&bundle, &context, &applied, CertificateUseV1::Inline).unwrap();
    assert!(!verified.is_historical());
    assert!(!verified.is_checkpoint());
    assert!(!verified.finalize_allowed_after_apply(NOW));
    assert_eq!(verified.control_nonce(), 4);
    assert_eq!(verified.control.certificate_id, [7; 32]);
    assert_eq!(verified.control.effect_hash, [8; 32]);
    let mut other_revision = bundle.clone();
    other_revision.revision += 1;
    assert_eq!(
        verify_control_bundle(
            &other_revision,
            &context,
            &applied,
            CertificateUseV1::Inline
        ),
        Err(ControlBundleError::WrongDeployment)
    );
    let mut foreign = context;
    foreign.destination.route_revision += 1;
    assert_eq!(
        verify_control_bundle(
            &other_revision,
            &foreign,
            &applied,
            CertificateUseV1::Inline
        ),
        Err(ControlBundleError::Bundle(BundleError::Proof(
            ProofError::BadBlockPath
        )))
    );
    for mutate in [
        |b: &mut SccpControlProofBundleV1| b.parliament_paused = false,
        |b: &mut SccpControlProofBundleV1| b.certificate_id[0] ^= 1,
        |b: &mut SccpControlProofBundleV1| b.effect_hash[0] ^= 1,
        |b: &mut SccpControlProofBundleV1| b.fast_pause_until_ms = NOW,
        |b: &mut SccpControlProofBundleV1| b.track = 2,
    ] {
        let mut changed = bundle.clone();
        mutate(&mut changed);
        assert_eq!(
            verify_control_bundle(&changed, &context, &applied, CertificateUseV1::Inline),
            Err(ControlBundleError::Bundle(BundleError::Proof(
                ProofError::BadBlockPath
            )))
        );
    }
    let stale = DestinationControlStateV1 {
        control_nonce: 4,
        ..Default::default()
    };
    assert_eq!(
        verify_control_bundle(&bundle, &context, &stale, CertificateUseV1::Inline),
        Err(ControlBundleError::Stale)
    );
    let mut wrong_count = bundle;
    wrong_count.block.message_count += 1;
    assert_eq!(
        verify_control_bundle(&wrong_count, &context, &applied, CertificateUseV1::Inline),
        Err(ControlBundleError::Bundle(BundleError::Proof(
            ProofError::BadBlockReference
        )))
    );
    assert!(
        ControlBundleError::WrongDeployment
            .to_string()
            .contains("revision")
    );
}

#[test]
fn verified_fast_pause_uses_destination_time_clamp_and_expiry() {
    let fixture = Fixture::new();
    let mut bundle = fixture.control();
    bundle.track = 2;
    bundle.parliament_paused = false;
    bundle.fast_pause_until_ms = u64::MAX;
    let fields = bundle.control_proof().fields(bundle.revision);
    let leaf = control_leaf(
        &NETWORK,
        bundle.network,
        &fixture.destination.destination_word,
        &fields,
    )
    .unwrap();
    let tree = PromoteOddTree::block(&[[5; 32], leaf]).unwrap();
    bundle.path = tree.path(1).unwrap();
    bundle.block.sccp_root = tree.root();
    bundle.certificate = fixture.certify(SccpFinalityHeaderFieldsV1 {
        message_count: 2,
        sccp_root: tree.root(),
        ..fixture.fields(9)
    });
    let verified = verify_control_bundle(
        &bundle,
        &context(&fixture),
        &DestinationControlStateV1::default(),
        CertificateUseV1::Inline,
    )
    .unwrap();
    let applied = verified.applied_state(NOW);
    assert_eq!(applied.fast_pause_until_ms, NOW + MAX_FAST_PAUSE_MS);
    assert!(!verified.finalize_allowed_after_apply(NOW));
    assert!(applied.paused_at(NOW + MAX_FAST_PAUSE_MS - 1));
    assert!(!applied.paused_at(NOW + MAX_FAST_PAUSE_MS));
    assert_eq!(
        verified.applied_state(u64::MAX - 1).fast_pause_until_ms,
        u64::MAX
    );
}
