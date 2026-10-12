//! Signed handoff ordering, key binding, trust bounds, latch and checkpoint retention controls.

use super::*;
use crate::pure::test_support::{Fixture, INSTANCE, NETWORK, NOW, T0, VALIDITY};
use iroha_sccp::{
    api::ApiShapeError,
    v1::{
        committee::LatchReasonV1,
        finality::{MAX_VALIDITY_MS, QcFixedV1, SccpFinalityHeaderV1, checkpoint_id},
    },
};

fn context(f: &Fixture, flavor: DestinationFlavor) -> DestinationContextV1<'_> {
    DestinationContextV1 {
        taira_network_id: NETWORK,
        consensus_instance: INSTANCE,
        destination: f.destination,
        flavor,
        committee_state: f.state,
        ton_keys: (flavor == DestinationFlavor::Ton).then_some(f.keys.as_slice()),
        checkpoints: &f.checkpoints,
        now_ms: NOW,
    }
}

#[test]
fn a_long_chain_verifies_and_splits_into_batches_of_16() {
    let fixture = Fixture::new();
    let steps: Vec<_> = (1..=17)
        .map(|generation| fixture.rotation(generation, 100 + generation, &fixture))
        .collect();
    for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
        let plan = verify_rotation_steps(&steps, &context(&fixture, flavor), 18).unwrap();
        assert_eq!(plan.steps().len(), 17);
        assert_eq!(plan.final_state().generation, 18);
        assert_eq!(plan.final_state().start, 118);
        assert_eq!(plan.final_state().high, 117);
        assert_eq!(plan.final_state().root, fixture.state.root);
        assert_eq!(plan.final_state().until_ms, T0 + 117 + VALIDITY);
        assert_eq!(plan.minimum_until_ms(), fixture.state.until_ms);
        assert_eq!(
            plan.batches()
                .map(<[VerifiedRotationV1]>::len)
                .collect::<Vec<_>>(),
            vec![16, 1]
        );
        assert!(plan.steps().iter().all(|step| {
            QcFixedV1::parse(&step.certificate().qc)
                .unwrap()
                .signers
                .count_ones()
                == 3
        }));
        assert!(plan.steps().iter().all(|step| step.next_keys().is_none()));
        assert!(!plan.is_empty());
    }
}

#[test]
fn the_chain_stops_at_the_target_and_reports_breaks() {
    let fixture = Fixture::new();
    let steps: Vec<_> = (1..=3)
        .map(|generation| fixture.rotation(generation, 100 + generation, &fixture))
        .collect();
    let selected = context(&fixture, DestinationFlavor::Evm);
    let plan = verify_rotation_steps(&steps, &selected, 2).unwrap();
    assert_eq!(plan.steps().len(), 1);
    let empty = verify_rotation_steps(&steps, &selected, 1).unwrap();
    assert!(empty.is_empty());
    assert_eq!(*empty.final_state(), fixture.state);
    assert_eq!(
        verify_rotation_steps(&steps[..1], &selected, 3),
        Err(RotationChainError::ChainTooShort {
            reached: 2,
            target: 3
        })
    );
    assert_eq!(
        verify_rotation_steps(&steps, &selected, 6),
        Err(RotationChainError::ChainTooShort {
            reached: 4,
            target: 6
        })
    );
    let mut beyond_target = steps.clone();
    beyond_target[1].certificate.aggregate_signature = [0; 96];
    assert!(verify_rotation_steps(&beyond_target, &selected, 2).is_ok());
    assert!(verify_rotation_steps(&beyond_target, &selected, 3).is_err());
    assert_eq!(selected.committee_state, fixture.state);
}

#[test]
fn rotation_bounds_signatures_and_successor_keys_are_enforced() {
    let first = Fixture::new();
    let second = Fixture::with_tag(1);
    let third = Fixture::with_tag(2);
    let steps = [
        first.rotation(1, 101, &second),
        second.rotation(2, 102, &third),
    ];
    for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
        let selected = context(&first, flavor);
        let plan = verify_rotation_steps(&steps, &selected, 3).unwrap();
        assert_eq!(plan.final_state().root, third.state.root);
        assert_eq!(plan.final_state().generation, 3);
        if flavor == DestinationFlavor::Ton {
            assert_eq!(plan.steps()[0].next_keys(), Some(second.keys.as_slice()));
            assert_eq!(plan.steps()[1].next_keys(), Some(third.keys.as_slice()));
        } else {
            assert!(plan.steps().iter().all(|step| step.next_keys().is_none()));
        }
        assert!(matches!(
            verify_rotation_steps(&steps[1..], &selected, 3),
            Err(RotationChainError::Step { index: 0, .. })
        ));
        let mut expired = selected;
        expired.now_ms = first.state.until_ms + 1;
        assert_eq!(
            verify_rotation_steps(&steps, &expired, 3),
            Err(RotationChainError::Step {
                index: 0,
                error: BundleError::Certificate(DestinationError::CommitteeNotAccepted)
            })
        );
        let skip = first.rotation(2, 101, &second);
        assert!(matches!(
            verify_rotation_steps(&[skip], &selected, 3),
            Err(RotationChainError::Step { index: 0, .. })
        ));
        let mut bad_successor = steps[0].clone();
        bad_successor.next_committee = third.keys.clone();
        assert_eq!(
            verify_rotation_steps(&[bad_successor], &selected, 2),
            Err(RotationChainError::Step {
                index: 0,
                error: BundleError::Shape(ApiShapeError::BadRotation)
            })
        );
        let mut bad_signature = steps[0].clone();
        bad_signature.certificate.aggregate_signature = second
            .rotation(1, 101, &second)
            .certificate
            .aggregate_signature;
        assert_eq!(
            verify_rotation_steps(&[bad_signature], &selected, 2),
            Err(RotationChainError::Step {
                index: 0,
                error: BundleError::Certificate(DestinationError::BadSignature)
            })
        );
        let mut plain = steps[0].clone();
        plain.certificate = first.certify(first.fields(101));
        assert_eq!(
            verify_rotation_steps(&[plain], &selected, 2),
            Err(RotationChainError::Step {
                index: 0,
                error: BundleError::Shape(ApiShapeError::BadRotation)
            })
        );
        let mut long = steps[0].clone();
        let mut fields = SccpFinalityHeaderV1::parse(&long.certificate.header)
            .unwrap()
            .fields();
        fields.validity_ms = MAX_VALIDITY_MS + 1;
        long.certificate.header = fields.to_bytes();
        assert_eq!(
            verify_rotation_steps(&[long], &selected, 2),
            Err(RotationChainError::Step {
                index: 0,
                error: BundleError::Shape(ApiShapeError::BadFinalityHeader)
            })
        );
    }
}

#[test]
fn authenticated_latch_precedes_successor_checks_and_never_yields_a_plan() {
    let mut fixture = Fixture::new();
    let next = Fixture::with_tag(1);
    let original = fixture.rotation(1, 101, &next);
    for reason in [
        LatchReasonV1::ConflictingCheckpoint,
        LatchReasonV1::BelowStart,
        LatchReasonV1::RotationBelowHigh,
    ] {
        fixture.checkpoints.clear();
        if reason == LatchReasonV1::ConflictingCheckpoint {
            fixture.checkpoints.insert(101, [0xaa; 32]);
        }
        let mut selected = context(&fixture, DestinationFlavor::Ton);
        if reason == LatchReasonV1::BelowStart {
            selected.committee_state.start = 102;
        }
        if reason == LatchReasonV1::RotationBelowHigh {
            selected.committee_state.high = 102;
        }
        let original_state = selected.committee_state;
        let mut malformed_successor = original.clone();
        malformed_successor.next_committee.clear();
        match verify_rotation_steps(&[malformed_successor], &selected, 2) {
            Err(RotationChainError::Latch {
                index: 0,
                violation,
            }) => {
                assert_eq!(violation.reason, reason);
                assert_eq!(violation.generation, 1);
                assert_eq!(violation.height, 101);
                assert_eq!(violation.b, checkpoint_id(&original.certificate.header));
            }
            other => panic!("expected authenticated {reason:?}, got {other:?}"),
        }
        assert_eq!(selected.committee_state, original_state);
    }
}

#[test]
fn expired_successor_and_original_trust_horizon_cannot_be_bypassed() {
    let fixture = Fixture::new();
    let mut fields = fixture.fields(101);
    fields.flags |= iroha_sccp::v1::finality::FLAG_ROTATION;
    fields.validity_ms = 1;
    fields.next_committee_root = fixture.state.root;
    let expired = SccpRotationV1 {
        certificate: fixture.certify(fields),
        next_committee: fixture.keys.clone(),
    };
    let selected = context(&fixture, DestinationFlavor::Evm);
    assert_eq!(
        verify_rotation_steps(&[expired], &selected, 2),
        Err(RotationChainError::Frozen { index: 0 })
    );
    let steps = [fixture.rotation(1, 101, &fixture)];
    let plan = verify_rotation_steps(&steps, &selected, 2).unwrap();
    let remaining = fixture.state.until_ms - NOW;
    assert_eq!(
        check_committee_horizon(&fixture.state, &plan, NOW, remaining - 10, 10),
        Ok(())
    );
    assert_eq!(
        check_committee_horizon(&fixture.state, &plan, NOW, remaining - 10, 11),
        Err(CommitteeHorizonError::ExpiresTooSoon {
            until_ms: fixture.state.until_ms,
            required_until_ms: fixture.state.until_ms + 1
        })
    );
    assert_eq!(
        check_committee_horizon(&fixture.state, &plan, fixture.state.until_ms + 1, 0, 0),
        Err(CommitteeHorizonError::Frozen)
    );
    let mut changed = fixture.state;
    changed.high += 1;
    assert_eq!(
        check_committee_horizon(&changed, &plan, NOW, 0, 0),
        Err(CommitteeHorizonError::ContextChanged)
    );
}

#[test]
fn checkpoint_recording_matches_eviction_and_never_replaces_an_original_id() {
    let mut checkpoints = BTreeMap::from([(5, [5; 32]), (8, [8; 32]), (10, [10; 32])]);
    record_checkpoint(&mut checkpoints, DestinationFlavor::Ton, 4, [4; 32]);
    assert_eq!(checkpoints.len(), 3);
    assert!(!checkpoints.contains_key(&4));
    record_checkpoint(&mut checkpoints, DestinationFlavor::Ton, 8, [0; 32]);
    assert_eq!(checkpoints[&8], [8; 32]);
    record_checkpoint(&mut checkpoints, DestinationFlavor::Ton, 9, [9; 32]);
    assert_eq!(
        checkpoints.keys().copied().collect::<Vec<_>>(),
        vec![8, 9, 10]
    );
    record_checkpoint(&mut checkpoints, DestinationFlavor::Evm, 4, [4; 32]);
    assert_eq!(
        checkpoints.keys().copied().collect::<Vec<_>>(),
        vec![4, 8, 9, 10]
    );
}

#[test]
fn trust_horizon_rejects_overflow_without_shortening_the_requested_interval() {
    let mut fixture = Fixture::new();
    fixture.state.until_ms = u64::MAX;
    for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
        let plan = verify_rotation_steps(&[], &context(&fixture, flavor), fixture.state.generation)
            .expect("unchanged live destination needs no rotations");
        assert_eq!(
            check_committee_horizon(&fixture.state, &plan, u64::MAX - 5, 3, 2),
            Ok(()),
            "the exact representable endpoint remains valid"
        );
        for (ttl, margin) in [(6, 0), (3, 3), (u64::MAX, u64::MAX)] {
            assert!(
                check_committee_horizon(&fixture.state, &plan, u64::MAX - 5, ttl, margin).is_err(),
                "overflow must not shorten TTL {ttl} and margin {margin} to fit the committee"
            );
        }
    }
}
