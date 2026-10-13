//! Role-16 signed Check binding and failed finalized execution; no topology authority is issued.

use super::*;
use iroha_data_model::{
    isi::{Log, sorafs::MutateSorafsTopologyAuthority},
    sorafs::topology_authority::{
        TopologyActionV1, TopologyCheckPhaseV1, TopologyCheckV1, TopologyFloorClaimV1,
        TopologyHeadV1, TopologyReserveV1, TopologyRevocationV1, TopologyTransitionV1,
    },
};
use sorafs_manifest::signer::{
    protocol::{
        SignerOperationActionV1, SignerOperationAuditHeadV1, SignerOperationCustodyV1,
        SignerOperationIntentV1,
    },
    topology::{SignerTopologyRequestV1, subject::TopologyApprovalSubjectV1},
};

fn check_instruction(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
    floor: NativeCheckFloorV1,
) -> MutateSorafsTopologyAuthority {
    let audit = SignerOperationAuditHeadV1 {
        sequence: 0,
        digest: [0; 32],
    };
    let request = SignerTopologyRequestV1 {
        operation_id: [1; 32],
        binding_digest: [2; 32],
        original_custody: SignerOperationCustodyV1 {
            record_digest: [3; 32],
            control_state_digest: [4; 32],
        },
        subject_digest: [5; 32],
    };
    // These syntactic values confer no current custody. Core remains closed even for Check.
    let reviewed = TopologyReserveV1 {
        subject: TopologyApprovalSubjectV1 {
            deployment_id: "topology-primary".into(),
            network_id: *state.network_id_ref().as_bytes(),
            chain_id: state.view().chain_id().to_string(),
            chain_discriminant: 1,
            release_manifest_sha256: [6; 32],
            qualification_summary_sha256: [7; 32],
            manifest_sha256: [8; 32],
            canonical_manifest_sha256: [9; 32],
            validator_ids_sha256: [10; 32],
            reviewed_at_unix_ms: 1_000,
            expires_at_unix_ms: 10_000,
        },
        request,
        intent: SignerOperationIntentV1 {
            action: SignerOperationActionV1::Sign,
            operation_id: request.operation_id,
            request_digest: [11; 32],
            previous_audit: audit,
        },
    };
    MutateSorafsTopologyAuthority {
        transition: TopologyTransitionV1 {
            deployment_id: "topology-primary".into(),
            control: TopologyHeadV1::EMPTY,
            operations: TopologyHeadV1::EMPTY,
            action: TopologyActionV1::Check(Box::new(TopologyCheckV1 {
                challenge: round.issue_challenge().unwrap(),
                network_id: *state.network_id_ref().as_bytes(),
                floor: TopologyFloorClaimV1 {
                    height: floor.height,
                    block_hash: floor.block_hash,
                },
                expected_operator: AccountId::new(key(4).public_key().clone()),
                reviewed,
                phase: TopologyCheckPhaseV1::Current(Box::new(audit)),
            })),
        },
    }
}

fn bind(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
    instruction: &MutateSorafsTopologyAuthority,
    floor: NativeCheckFloorV1,
) -> Result<BoundNativeCheckV1, Error> {
    bind_fixture(
        state,
        round,
        NativeCustodyCheckRefV1::Topology(instruction),
        &state.view().chain_id().to_string(),
        *state.network_id_ref().as_bytes(),
        &AccountId::new(key(2).public_key().clone()),
        floor,
        sign(state, instruction.clone().into(), 2, 3_000),
    )
}

#[test]
fn role16_binding_rejects_substituted_floor_action_and_purpose() {
    let state = state();
    let floor = floor();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = check_instruction(&mut round, &state, floor);
    let bound = bind(&mut round, &state, &instruction, floor).unwrap();
    assert_eq!(bound.purpose, NativeCustodyCheckPurposeV1::Topology);
    assert_eq!(
        authenticate_applied_check_v1(
            &state,
            NativeCustodyCheckPurposeV1::FinalPromotion,
            &mut Some(bound),
            &round,
        )
        .err()
        .map(crate::execution_attempt::expect_completed_rejection),
        Some(Error::Invalid),
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = check_instruction(&mut round, &state, floor);
    let mut different_floor = floor;
    different_floor.block_hash[0] ^= 1;
    assert_eq!(
        bind(&mut round, &state, &instruction, different_floor).err(),
        Some(Error::Transaction),
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    round.issue_challenge().unwrap();
    let non_check = MutateSorafsTopologyAuthority {
        transition: TopologyTransitionV1 {
            deployment_id: "topology-primary".into(),
            control: TopologyHeadV1::EMPTY,
            operations: TopologyHeadV1::EMPTY,
            action: TopologyActionV1::Revoke(TopologyRevocationV1 {
                signer: true,
                attester: false,
            }),
        },
    };
    assert_eq!(
        bind(&mut round, &state, &non_check, floor).err(),
        Some(Error::Transaction),
    );
}

#[test]
fn finalized_role16_check_with_closed_core_result_cannot_authenticate() {
    let mut fixture =
        crate::query::signer_check_test_fixture::NativeCheckTestFixtureV1::new(World::new());
    let state = Arc::clone(fixture.state());
    let anchor = sign(
        &state,
        Log::new(iroha_logger::Level::INFO, "topology floor".into()).into(),
        2,
        1_000,
    );
    fixture.commit(1_000, vec![anchor]);
    let (height, block_hash, context_id) = fixture.finalized_floor();
    let floor = NativeCheckFloorV1 {
        height,
        block_hash,
        context_id,
    };
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = check_instruction(&mut round, &state, floor);
    let bound = bind(&mut round, &state, &instruction, floor).unwrap();
    let signed = bound.signed_transaction().clone();
    assert_eq!(
        fixture.commit(2_000, vec![signed]),
        vec![false],
        "the registered topology ISI must remain closed",
    );
    assert_eq!(
        authenticate_applied_check_v1(
            &state,
            NativeCustodyCheckPurposeV1::Topology,
            &mut Some(bound),
            &round,
        )
        .err()
        .map(crate::execution_attempt::expect_completed_rejection),
        Some(Error::Execution),
        "a finalized failed output cannot be a topology approval",
    );
}
