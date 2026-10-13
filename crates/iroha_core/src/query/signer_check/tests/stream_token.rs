//! Closed role-11 signed Check binding before any native execution or finality authority.

use super::*;
use iroha_data_model::{
    isi::sorafs::MutateSorafsStreamTokenAuthority,
    sorafs::{
        capacity::ProviderId,
        stream_token_authority::{
            StreamTokenAuthorityActionV1, StreamTokenAuthorityRequestV1, StreamTokenCheckPhaseV1,
            StreamTokenCheckV1, StreamTokenFinalityFloorV1, StreamTokenReviewedV1,
        },
    },
};
use sorafs_manifest::signer::{
    protocol::{
        SignerOperationActionV1, SignerOperationAuditHeadV1, SignerOperationCustodyV1,
        SignerOperationIntentV1,
    },
    stream_token::SignerStreamTokenRequestV1,
};

fn instruction(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
) -> MutateSorafsStreamTokenAuthority {
    let request = SignerStreamTokenRequestV1 {
        operation_id: [0x31; 32],
        binding_digest: [0x32; 32],
        original_custody: SignerOperationCustodyV1 {
            record_digest: [0x33; 32],
            control_state_digest: [0x34; 32],
        },
        signing_payload_digest: [0x35; 32],
        signing_payload_size: 256,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 10_000,
    };
    let audit = SignerOperationAuditHeadV1 {
        sequence: 0,
        digest: [0; 32],
    };
    let reviewed = StreamTokenReviewedV1 {
        request,
        intent: SignerOperationIntentV1 {
            action: SignerOperationActionV1::Sign,
            operation_id: request.operation_id,
            request_digest: request.digest().unwrap(),
            previous_audit: audit,
        },
    };
    let floor = floor();
    MutateSorafsStreamTokenAuthority {
        request: StreamTokenAuthorityRequestV1 {
            network_id: *state.network_id_ref().as_bytes(),
            provider_id: ProviderId::new([0x36; 32]),
            expected_control_revision: 1,
            expected_control_digest: request.original_custody.control_state_digest,
            action: StreamTokenAuthorityActionV1::Check(StreamTokenCheckV1 {
                challenge: round.issue_challenge().unwrap(),
                expected_operator: AccountId::new(key(4).public_key().clone()),
                expected_observer: AccountId::new(key(2).public_key().clone()),
                floor: StreamTokenFinalityFloorV1 {
                    height: floor.height,
                    block_hash: floor.block_hash,
                    context_id: floor.context_id,
                },
                reviewed,
                phase: StreamTokenCheckPhaseV1::Current(audit),
            }),
        },
    }
}

fn bind(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
    instruction: &MutateSorafsStreamTokenAuthority,
) -> Result<BoundNativeCheckV1, Error> {
    bind_fixture(
        state,
        round,
        NativeCustodyCheckRefV1::StreamToken(instruction),
        &state.view().chain_id().to_string(),
        *state.network_id_ref().as_bytes(),
        &AccountId::new(key(2).public_key().clone()),
        floor(),
        sign(state, instruction.clone().into(), 2, 3_000),
    )
}

#[test]
fn role11_check_binding_is_exact_and_cannot_cross_purpose() {
    let state = state();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let check = instruction(&mut round, &state);
    let signed = sign(&state, check.clone().into(), 2, 3_000);
    let bound = bind(&mut round, &state, &check).unwrap();
    assert_eq!(bound.signed_transaction(), &signed);
    assert_eq!(bound.purpose, NativeCustodyCheckPurposeV1::StreamToken);
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
    let check = instruction(&mut round, &state);
    let bound = bind(&mut round, &state, &check).unwrap();
    assert_eq!(
        authenticate_applied_check_v1(
            &state,
            NativeCustodyCheckPurposeV1::StreamToken,
            &mut Some(bound),
            &round,
        )
        .err()
        .map(crate::execution_attempt::expect_completed_rejection),
        Some(Error::NotApplied),
    );
}

#[test]
fn role11_check_binding_rejects_substitutions_and_non_check_actions() {
    let state = state();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let check = instruction(&mut round, &state);
    let mut changed = check.clone();
    changed.request.expected_control_digest = [0x99; 32];
    assert_eq!(
        bind_fixture(
            &state,
            &mut round,
            NativeCustodyCheckRefV1::StreamToken(&check),
            &state.view().chain_id().to_string(),
            *state.network_id_ref().as_bytes(),
            &AccountId::new(key(2).public_key().clone()),
            floor(),
            sign(&state, changed.into(), 2, 3_000),
        )
        .err(),
        Some(Error::Transaction),
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let check = instruction(&mut round, &state);
    let mut wrong_floor = floor();
    wrong_floor.height += 1;
    assert_eq!(
        bind_fixture(
            &state,
            &mut round,
            NativeCustodyCheckRefV1::StreamToken(&check),
            &state.view().chain_id().to_string(),
            *state.network_id_ref().as_bytes(),
            &AccountId::new(key(2).public_key().clone()),
            wrong_floor,
            sign(&state, check.clone().into(), 2, 3_000),
        )
        .err(),
        Some(Error::Transaction),
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let mut changed_context = instruction(&mut round, &state);
    let StreamTokenAuthorityActionV1::Check(check) = &mut changed_context.request.action else {
        panic!("Check fixture");
    };
    check.floor.context_id = HeightContextId(HashOf::from_untyped_unchecked(Hash::new(
        b"different signed role-11 floor context",
    )));
    assert_eq!(
        bind(&mut round, &state, &changed_context).err(),
        Some(Error::Transaction),
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let mut non_check = instruction(&mut round, &state);
    let StreamTokenAuthorityActionV1::Check(check) = &non_check.request.action else {
        panic!("Check fixture");
    };
    non_check.request.action = StreamTokenAuthorityActionV1::Reserve(check.reviewed);
    assert_eq!(
        bind(&mut round, &state, &non_check).err(),
        Some(Error::Transaction),
    );
}
