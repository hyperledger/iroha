//! Both-source transcript order and exact supplemental wire adversaries.

use super::*;
use crate::privacy_engines::transparent_stark::{GOLDILOCKS_MODULUS_V1, GoldilocksFieldV1 as F};
use crate::privacy_engines::zk_x509::credential_pre_aux::{
    ZkX509CredentialMainPreAuxV1, derive_zk_x509_credential_pre_aux_binding_v1,
};
use crate::privacy_engines::zk_x509::proof_instance::TEST_PROOF_INSTANCE_V1;
fn digest(n: u8) -> Digest {
    Digest::from_bytes([n; 48])
}
fn binding() -> ZkX509CredentialPreAuxBindingV1 {
    derive_zk_x509_credential_pre_aux_binding_v1(
        ZkX509CredentialMainPreAuxV1::fixture_for_test_v1([1; 32], [2; 32], [digest(3)]),
        digest(4),
        digest(5),
        digest(6),
    )
    .unwrap()
}
fn transcript(n: u8, family: JointSubproofV1) -> Transcript {
    Transcript::new(
        match family {
            JointSubproofV1::Main => TEST_PROOF_INSTANCE_V1.main_context_v1(),
            JointSubproofV1::Ca => TEST_PROOF_INSTANCE_V1.ca_context_v1(),
        },
        b"joint-fixture",
        &digest(n),
        &digest(n + 1),
    )
    .unwrap()
}
fn values() -> JointOriginalOpeningsV1 {
    JointOriginalOpeningsV1 {
        main: core::array::from_fn(|i| E::canonical([i as u64 + 1, 2, 3, 4]).unwrap()),
        ca: core::array::from_fn(|i| E::canonical([i as u64 + 101, 7, 11, 13]).unwrap()),
    }
}

#[test]
fn joint_auxiliary_binding_preserves_both_original_roots_and_context() {
    let original = JointAuxiliaryBindingV1::new_v1(&binding(), [digest(8), digest(9)]).unwrap();
    assert!(original.matches_v1(&binding(), JointSubproofV1::Main, digest(8)));
    assert!(original.matches_v1(&binding(), JointSubproofV1::Ca, digest(9)));
    assert!(!original.matches_v1(&binding(), JointSubproofV1::Ca, digest(8)));
    let mut baseline = transcript(10, JointSubproofV1::Main);
    original.absorb_v1(&mut baseline).unwrap();
    for roots in [
        [digest(7), digest(9)],
        [digest(8), digest(7)],
        [digest(9), digest(8)],
    ] {
        let changed = JointAuxiliaryBindingV1::new_v1(&binding(), roots).unwrap();
        let mut actual = transcript(10, JointSubproofV1::Main);
        changed.absorb_v1(&mut actual).unwrap();
        assert_ne!(actual.state(), baseline.state());
    }
    let foreign = derive_zk_x509_credential_pre_aux_binding_v1(
        ZkX509CredentialMainPreAuxV1::fixture_for_test_v1([21; 32], [2; 32], [digest(3)]),
        digest(4),
        digest(5),
        digest(6),
    )
    .unwrap();
    assert!(!original.matches_v1(&foreign, JointSubproofV1::Main, digest(8)));
    let changed = JointAuxiliaryBindingV1::new_v1(&foreign, [digest(8), digest(9)]).unwrap();
    assert_ne!(changed.digest, original.digest);
}

#[test]
fn shared_point_binds_every_oracle_and_both_complete_local_transcript_states() {
    let auxiliary = JointAuxiliaryBindingV1::new_v1(&binding(), [digest(8), digest(9)]).unwrap();
    let main = transcript(10, JointSubproofV1::Main);
    let ca = transcript(12, JointSubproofV1::Ca);
    let checkpoints = JointOracleCheckpointsV1 {
        transcript_states: [main.state(), ca.state()],
        composition_roots: [digest(14), digest(15)],
        fri_mask_roots: [digest(16), digest(17)],
    };
    let original = checkpoints
        .derive_point_v1(auxiliary, |z| z != E::ZERO)
        .unwrap();
    for changed_index in 0..6 {
        let mut changed = checkpoints;
        match changed_index {
            0..=1 => changed.transcript_states[changed_index] = digest(90),
            2..=3 => changed.composition_roots[changed_index - 2] = digest(90),
            _ => changed.fri_mask_roots[changed_index - 4] = digest(90),
        }
        assert_ne!(
            changed
                .derive_point_v1(auxiliary, |z| z != E::ZERO)
                .unwrap()
                .point_v1(),
            original.point_v1()
        );
    }
    let mut main_bound = main;
    let mut ca_bound = ca;
    original
        .absorb_v1(JointSubproofV1::Main, &mut main_bound)
        .unwrap();
    original
        .absorb_v1(JointSubproofV1::Ca, &mut ca_bound)
        .unwrap();
    assert_ne!(main_bound.state(), main.state());
    assert_ne!(ca_bound.state(), ca.state());
    assert!(
        original
            .absorb_v1(JointSubproofV1::Ca, &mut main.clone())
            .is_err()
    );
    assert!(
        original
            .absorb_v1(JointSubproofV1::Main, &mut main_bound)
            .is_err()
    );
    let mut rejected = 0;
    let next = checkpoints
        .derive_point_v1(auxiliary, |z| {
            rejected += 1;
            z != original.point_v1()
        })
        .unwrap();
    assert_eq!(rejected, 2);
    assert_ne!(next.point_v1(), original.point_v1());
}

#[test]
fn original_opening_wire_rejects_every_extent_and_noncanonical_coordinate() {
    let values = values();
    let wire = values.encode_v1().unwrap();
    assert_eq!(wire.len(), 4224);
    assert_eq!(JointOriginalOpeningsV1::decode_v1(&wire).unwrap(), values);
    for len in 0..wire.len() {
        assert!(JointOriginalOpeningsV1::decode_v1(&wire[..len]).is_err());
    }
    let mut extra = wire.to_vec();
    extra.push(0);
    assert!(JointOriginalOpeningsV1::decode_v1(&extra).is_err());
    for coordinate in 0..132 * 4 {
        let mut changed = wire;
        changed[coordinate * 8..coordinate * 8 + 8]
            .copy_from_slice(&GOLDILOCKS_MODULUS_V1.to_be_bytes());
        assert!(JointOriginalOpeningsV1::decode_v1(&changed).is_err());
    }
}

#[test]
fn both_complete_deep_states_and_each_original_opening_precede_each_local_mix() {
    let values = values();
    let main = transcript(31, JointSubproofV1::Main);
    let ca = transcript(41, JointSubproofV1::Ca);
    let mut expected_main = main;
    let mut expected_ca = ca;
    values
        .bind_both_v1(TEST_PROOF_INSTANCE_V1, &mut expected_main, &mut expected_ca)
        .unwrap();
    for coordinate in 0..132 {
        let mut changed = values;
        let target = if coordinate < 24 {
            &mut changed.main[coordinate]
        } else {
            &mut changed.ca[coordinate - 24]
        };
        *target = target.add(E::from_base(F::ONE));
        let mut actual_main = main;
        let mut actual_ca = ca;
        changed
            .bind_both_v1(TEST_PROOF_INSTANCE_V1, &mut actual_main, &mut actual_ca)
            .unwrap();
        assert_ne!(actual_main.state(), expected_main.state());
        assert_ne!(actual_ca.state(), expected_ca.state());
    }
    for family in [JointSubproofV1::Main, JointSubproofV1::Ca] {
        let mut actual_main = main;
        let mut actual_ca = ca;
        match family {
            JointSubproofV1::Main => actual_main
                .absorb(b"changed-complete-deep", &[b"one-field"])
                .unwrap(),
            JointSubproofV1::Ca => actual_ca
                .absorb(b"changed-complete-deep", &[b"one-field"])
                .unwrap(),
        }
        values
            .bind_both_v1(TEST_PROOF_INSTANCE_V1, &mut actual_main, &mut actual_ca)
            .unwrap();
        assert_ne!(actual_main.state(), expected_main.state());
        assert_ne!(actual_ca.state(), expected_ca.state());
    }
}

#[test]
fn original_joint_capabilities_reject_foreign_nonce_and_swapped_families_before_mutation() {
    let instance = TEST_PROOF_INSTANCE_V1;
    let foreign = ZkX509ProofInstanceV1::new_v1([0xa7; 32]);
    let auxiliary = JointAuxiliaryBindingV1::new_v1(&binding(), [digest(8), digest(9)]).unwrap();
    for context in [
        foreign.main_context_v1(),
        foreign.ca_context_v1(),
        instance.joint_context_v1(),
    ] {
        let mut candidate =
            Transcript::new(context, b"joint-fixture", &digest(10), &digest(11)).unwrap();
        let before = candidate.state();
        assert!(auxiliary.absorb_v1(&mut candidate).is_err());
        assert_eq!(candidate.state(), before);
    }
    let original_main = transcript(10, JointSubproofV1::Main);
    let original_ca = transcript(12, JointSubproofV1::Ca);
    for (mut main, mut ca) in [(original_main, original_ca), (original_ca, original_main)] {
        let states = [main.state(), ca.state()];
        assert!(values().bind_both_v1(foreign, &mut main, &mut ca).is_err());
        assert_eq!([main.state(), ca.state()], states);
    }
    let mut main = original_ca;
    let mut ca = original_main;
    assert!(values().bind_both_v1(instance, &mut main, &mut ca).is_err());
    assert_eq!(
        [main.state(), ca.state()],
        [original_ca.state(), original_main.state()]
    );
    let mut main = original_main;
    let mut ca = original_ca;
    let bound = values().bind_both_v1(instance, &mut main, &mut ca).unwrap();
    assert!(bound.matches_v1(JointSubproofV1::Main, &main));
    assert!(bound.matches_v1(JointSubproofV1::Ca, &ca));
    assert!(!bound.matches_v1(JointSubproofV1::Main, &ca));
    assert!(!bound.matches_v1(JointSubproofV1::Ca, &main));
}
