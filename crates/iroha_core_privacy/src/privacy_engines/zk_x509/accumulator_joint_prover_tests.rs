//! Real CA polynomial/Merkle/FRI coverage under a paired transcript fixture.
//! The MAIN checkpoint is an explicit component fixture, not a credential proof.

use super::super::super::tests::{credential_main_pre_aux_v1, fixture};
use super::*;
use crate::privacy_engines::zk_x509::proof_instance::TEST_PROOF_INSTANCE_V1;
use crate::privacy_engines::zk_x509::{
    accumulator_stark::joint_verifier::CaJointVerifierOraclesV1,
    credential_joint::JointOracleCheckpointsV1,
};
use rand::{SeedableRng, rngs::StdRng};

fn main_component_transcript_v1(auxiliary: JointAuxiliaryBindingV1) -> TransparentTranscriptV1 {
    let mut main = TransparentTranscriptV1::new(
        TEST_PROOF_INSTANCE_V1.main_context_v1(),
        b"ca-test-only-main-component-placeholder",
        &PrivacyOuterDigestV1::from_bytes([3; 48]),
        &PrivacyOuterDigestV1::from_bytes([5; 48]),
    )
    .unwrap();
    auxiliary.absorb_v1(&mut main).unwrap();
    main
}
fn point_v1(
    main: &TransparentTranscriptV1,
    auxiliary: JointAuxiliaryBindingV1,
    ca: [PrivacyOuterDigestV1; 3],
    plan: &CaMainPrivateLinkPlanV1,
) -> JointPointV1 {
    JointOracleCheckpointsV1 {
        transcript_states: [main.state(), ca[0]],
        composition_roots: [PrivacyOuterDigestV1::from_bytes([7; 48]), ca[1]],
        fri_mask_roots: [PrivacyOuterDigestV1::from_bytes([11; 48]), ca[2]],
    }
    .derive_point_v1(auxiliary, |point| {
        plan.admissible_v1(point).unwrap_or(false)
    })
    .unwrap()
}

/// Actual CA proof plus explicit synthetic MAIN transcript context for component tests.
pub struct CaJointComponentFixtureV1 {
    pub(crate) evidence: (
        ZkX509CaAccumulatorStarkPublicV1,
        ZkX509ShaCallScheduleV1,
        Vec<u8>,
    ),
    auxiliary: JointAuxiliaryBindingV1,
    pub(crate) openings: JointOriginalOpeningsV1,
}
impl CaJointComponentFixtureV1 {
    pub(crate) fn verify_v1(
        &self,
        public: ZkX509CaAccumulatorStarkPublicV1,
        schedule: &ZkX509ShaCallScheduleV1,
        pre_aux: ZkX509CredentialMainPreAuxV1,
        encoded: &[u8],
        openings: JointOriginalOpeningsV1,
    ) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        let oracle =
            CaJointVerifierOraclesV1::new_v1(public, schedule, pre_aux, self.auxiliary, encoded)?;
        let plan = CaMainPrivateLinkPlanV1::new_v1(
            schedule,
            derive_zk_x509_credential_pre_aux_binding_v1(
                pre_aux,
                ca_profile_digest_v1()?,
                ca_public_digest_v1(TEST_PROOF_INSTANCE_V1, public, schedule)?,
                ca_accumulator_base_root_from_proof_v1(encoded)?,
            )
            .map_err(map_credential_pre_aux_error_v1)?
            .sha(),
        )?;
        let mut main = main_component_transcript_v1(self.auxiliary);
        let point = point_v1(&main, self.auxiliary, oracle.checkpoint_v1(), &plan);
        point
            .absorb_v1(JointSubproofV1::Main, &mut main)
            .map_err(map_transparent_proof_error_v1)?;
        main.absorb(
            b"test-only-main-local-deep-record",
            &[b"fixed-component-fixture"],
        )
        .map_err(map_transparent_proof_error_v1)?;
        let mut opened = oracle.open_joint_point_v1(point)?;
        let binding = opened.bind_with_main_v1(&mut main, openings)?;
        opened.finish_v1(binding)
    }
}
/// Share one genuine CA Merkle/FRI construction across all hostile component tests.
pub fn fixture_v1() -> &'static CaJointComponentFixtureV1 {
    static FIXTURE: std::sync::OnceLock<CaJointComponentFixtureV1> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (trace, schedule, _, _) = fixture();
        let public = ca_accumulator_stark_public_v1(&trace, &schedule).unwrap();
        let mut rng = StdRng::seed_from_u64(0xCA10_0101);
        let original = commit_ca_through_auxiliary_v1(
            &trace,
            &schedule,
            credential_main_pre_aux_v1(),
            &mut rng,
        )
        .unwrap();
        let auxiliary = JointAuxiliaryBindingV1::new_v1(
            &original.binding_v1(),
            [
                PrivacyOuterDigestV1::from_bytes([13; 48]),
                original.auxiliary_root_v1(),
            ],
        )
        .unwrap();
        let plan = CaMainPrivateLinkPlanV1::new_v1(&schedule, original.binding_v1().sha()).unwrap();
        let oracle = original
            .commit_joint_oracles_v1(auxiliary, &mut rng)
            .unwrap();
        let mut main = main_component_transcript_v1(auxiliary);
        let point = point_v1(&main, auxiliary, oracle.checkpoint_v1(), &plan);
        point.absorb_v1(JointSubproofV1::Main, &mut main).unwrap();
        main.absorb(
            b"test-only-main-local-deep-record",
            &[b"fixed-component-fixture"],
        )
        .unwrap();
        let mut opened = oracle.open_joint_point_v1(point).unwrap();
        let binding = opened.bind_with_main_v1(&mut main, [E::ONE; 24]).unwrap();
        let openings = binding.openings_v1();
        let encoded = opened.finish_v1(binding).unwrap();
        CaJointComponentFixtureV1 {
            evidence: (public, schedule, encoded),
            auxiliary,
            openings,
        }
    })
}
#[test]
fn actual_ca_joint_fri_binds_every_original_supplemental_opening_and_paired_main_record() {
    let fixture = fixture_v1();
    let (public, schedule, encoded) = &fixture.evidence;
    let verify = |openings| {
        fixture.verify_v1(
            *public,
            schedule,
            credential_main_pre_aux_v1(),
            encoded,
            openings,
        )
    };
    assert!(encoded.len() <= ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1);
    assert!(verify(fixture.openings).is_ok());
    for index in 0..108 {
        let mut changed = fixture.openings;
        changed.ca[index] = changed.ca[index].add(E::ONE);
        assert!(verify(changed).is_err(), "CA original opening {index}");
    }
    for index in 0..24 {
        let mut changed = fixture.openings;
        changed.main[index] = changed.main[index].add(E::ONE);
        assert!(verify(changed).is_err(), "paired MAIN opening {index}");
    }
}
