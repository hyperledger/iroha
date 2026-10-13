//! Role-13 signed Check binding and failed finalized execution; no release signer authority.

use super::*;
use crate::state::WorldReadOnly;
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::Account,
    executor::ValidationFail,
    isi::{Log, sorafs::MutateSorafsReleaseManifestAuthority},
    permission::{Permission, Permissions},
    sorafs::release_manifest_authority::{
        ReleaseManifestActionV1, ReleaseManifestCheckPhaseV1, ReleaseManifestCheckV1,
        ReleaseManifestFloorV1, ReleaseManifestReserveV1,
    },
    transaction::error::TransactionRejectionReason,
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsReleaseManifest, CanOperateSorafsReleaseManifest,
};
use mv::storage::StorageReadOnly;
use sorafs_manifest::signer::{
    protocol::{
        SignerOperationActionV1, SignerOperationAuditHeadV1, SignerOperationCustodyV1,
        SignerOperationIntentV1,
    },
    receipt::SignerReleaseManifestRequestV1,
};
use std::num::NonZeroUsize;

fn check_instruction(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
    floor: NativeCheckFloorV1,
) -> MutateSorafsReleaseManifestAuthority {
    let audit = SignerOperationAuditHeadV1 {
        sequence: 0,
        digest: [0; 32],
    };
    let request = SignerReleaseManifestRequestV1 {
        operation_id: [0x31; 32],
        binding_digest: [0x32; 32],
        original_custody: SignerOperationCustodyV1 {
            record_digest: [0x33; 32],
            control_state_digest: [0x34; 32],
        },
        manifest_digest: [0x35; 32],
        manifest_size: 256,
    };
    let reviewed = ReleaseManifestReserveV1 {
        request,
        intent: SignerOperationIntentV1 {
            action: SignerOperationActionV1::Sign,
            operation_id: request.operation_id,
            request_digest: request.digest().unwrap(),
            previous_audit: audit,
        },
    };
    MutateSorafsReleaseManifestAuthority {
        deployment_id: "release-primary".into(),
        expected_control_revision: 1,
        expected_control_digest: request.original_custody.control_state_digest,
        action: ReleaseManifestActionV1::Check(ReleaseManifestCheckV1 {
            challenge: round.issue_challenge().unwrap(),
            network_id: *state.network_id_ref().as_bytes(),
            expected_operator: AccountId::new(key(4).public_key().clone()),
            floor: ReleaseManifestFloorV1 {
                height: floor.height,
                block_hash: floor.block_hash,
            },
            reviewed,
            phase: ReleaseManifestCheckPhaseV1::Current(audit),
        }),
    }
}

fn bind(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
    instruction: &MutateSorafsReleaseManifestAuthority,
    floor: NativeCheckFloorV1,
) -> Result<BoundNativeCheckV1, Error> {
    bind_fixture(
        state,
        round,
        NativeCustodyCheckRefV1::ReleaseManifest(instruction),
        state.view().chain_id().as_ref(),
        *state.network_id_ref().as_bytes(),
        &AccountId::new(key(2).public_key().clone()),
        floor,
        sign(state, instruction.clone().into(), 2, 3_000),
    )
}

#[test]
fn role13_check_binding_rejects_purpose_floor_signed_body_and_non_check_substitution() {
    let state = state();
    let floor = floor();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = check_instruction(&mut round, &state, floor);
    let bound = bind(&mut round, &state, &instruction, floor).unwrap();
    assert_eq!(bound.purpose, NativeCustodyCheckPurposeV1::ReleaseManifest);
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
    let mut wrong_floor = floor;
    wrong_floor.block_hash[0] ^= 1;
    assert_eq!(
        bind(&mut round, &state, &instruction, wrong_floor).err(),
        Some(Error::Transaction),
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = check_instruction(&mut round, &state, floor);
    let mut substituted = instruction.clone();
    substituted.expected_control_digest = [0x99; 32];
    assert_eq!(
        bind_fixture(
            &state,
            &mut round,
            NativeCustodyCheckRefV1::ReleaseManifest(&instruction),
            state.view().chain_id().as_ref(),
            *state.network_id_ref().as_bytes(),
            &AccountId::new(key(2).public_key().clone()),
            floor,
            sign(&state, substituted.into(), 2, 3_000),
        )
        .err(),
        Some(Error::Transaction),
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let mut non_check = check_instruction(&mut round, &state, floor);
    let ReleaseManifestActionV1::Check(check) = &non_check.action else {
        panic!("Check fixture");
    };
    non_check.action = ReleaseManifestActionV1::Reserve(check.reviewed);
    assert_eq!(
        bind(&mut round, &state, &non_check, floor).err(),
        Some(Error::Transaction),
    );
}

#[test]
fn finalized_role13_check_with_exact_grants_still_cannot_authenticate() {
    let observer = AccountId::new(key(2).public_key().clone());
    let operator = AccountId::new(key(4).public_key().clone());
    let mut world = World::new();
    for id in [&observer, &operator] {
        let (key, value) = Account::new(id.clone()).build(&observer).into_key_value();
        world.accounts.insert(key, value);
    }
    for (id, permission) in [
        (
            &observer,
            Permission::from(CanCheckSorafsReleaseManifest {
                deployment_id: "release-primary".into(),
            }),
        ),
        (
            &operator,
            Permission::from(CanOperateSorafsReleaseManifest {
                deployment_id: "release-primary".into(),
            }),
        ),
    ] {
        let mut grants = Permissions::new();
        grants.insert(permission);
        world.account_permissions.insert(id.clone(), grants);
    }
    let mut fixture = crate::query::signer_check_test_fixture::NativeCheckTestFixtureV1::new(world);
    let state = Arc::clone(fixture.state());
    {
        let view = state.view();
        let world = view.world();
        assert!(world.accounts().get(&observer).is_some());
        assert!(world.accounts().get(&operator).is_some());
        assert!(
            world.account_contains_inherent_permission(
                &observer,
                &CanCheckSorafsReleaseManifest {
                    deployment_id: "release-primary".into(),
                }
                .into(),
            )
        );
        assert!(
            world.account_contains_inherent_permission(
                &operator,
                &CanOperateSorafsReleaseManifest {
                    deployment_id: "release-primary".into(),
                }
                .into(),
            )
        );
    }
    let anchor = sign(
        &state,
        Log::new(iroha_logger::Level::INFO, "release-manifest floor".into()).into(),
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
        "the registered role-13 ISI must remain closed",
    );
    let block = state
        .block_by_height(NonZeroUsize::new(3).unwrap())
        .expect("committed history read completes")
        .expect("committed execution is retained");
    let (_, output) = block.network_output_at(0).unwrap();
    assert!(matches!(
        &output.result.0,
        Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(reason)
        )) if reason == crate::smartcontracts::isi::INITIAL_NATIVE_INSTRUCTION_CLOSED_REASON
    ));
    assert_eq!(
        authenticate_applied_check_v1(
            &state,
            NativeCustodyCheckPurposeV1::ReleaseManifest,
            &mut Some(bound),
            &round,
        )
        .err()
        .map(crate::execution_attempt::expect_completed_rejection),
        Some(Error::Execution),
        "a finalized failed output cannot authorize release-manifest signing",
    );
}
