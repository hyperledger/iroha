//! Closed-purpose binding and move-only round invariants; these are not finality qualification.
use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
use fixture::{key, sign};
use iroha_crypto::{Hash, Signature, SignatureOf};
use iroha_data_model::{
    sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyCheckV1,
    transaction::TransactionSignature,
};

fn state() -> Arc<State> {
    Arc::new(State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ))
}
fn floor() -> NativeCheckFloorV1 {
    NativeCheckFloorV1 {
        height: 1,
        block_hash: [7; 32],
        context_id: HeightContextId(HashOf::from_untyped_unchecked(Hash::new(
            b"independently retained context",
        ))),
    }
}
fn instruction(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
) -> MutateSorafsFinalPromotionAccountCustody {
    MutateSorafsFinalPromotionAccountCustody {
        deployment_id: "promotion-primary".into(),
        expected_control_revision: 2,
        expected_control_digest: [8; 32],
        action: FinalPromotionAccountCustodyActionV1::Check(FinalPromotionAccountCustodyCheckV1 {
            challenge: round.issue_challenge().unwrap(),
            network_id: *state.network_id_ref().as_bytes(),
            minimum_height: floor().height,
            minimum_block_hash: floor().block_hash,
            expected_account: AccountId::new(key(4).public_key().clone()),
            transaction_payload_digest: [9; 32],
        }),
    }
}
fn bind(
    round: &mut NativeCheckRoundV1,
    state: &Arc<State>,
    instruction: &MutateSorafsFinalPromotionAccountCustody,
) -> Result<BoundNativeCheckV1, Error> {
    let signed = sign(state, instruction.clone().into(), 2, 3_000);
    bind_fixture(
        state,
        round,
        NativeCustodyCheckRefV1::FinalPromotionAccount(instruction),
        &state.view().chain_id().to_string(),
        *state.network_id_ref().as_bytes(),
        &AccountId::new(key(2).public_key().clone()),
        floor(),
        signed,
    )
}

// Existing closed-purpose tests borrow their independent fixture inputs. The production binder
// still owns its signed attempt; no production wrapper exposes this fixture-only projection.
fn test_scope<'a>(scope: &'a mut BindingScope<'_>) -> Result<BindingScope<'a>, Error> {
    Ok(BindingScope {
        state: scope.state,
        round: scope.round,
        instruction: scope.instruction,
        chain_id: scope.chain_id,
        network_id: scope.network_id,
        authority: scope.authority,
        floor: scope.floor,
    })
}
fn bind_fixture(
    state: &State,
    round: &mut NativeCheckRoundV1,
    instruction: NativeCustodyCheckRefV1<'_>,
    chain_id: &str,
    network_id: [u8; 32],
    authority: &AccountId,
    floor: NativeCheckFloorV1,
    signed: SignedTransaction,
) -> Result<BoundNativeCheckV1, Error> {
    bind_signed_check_v1(
        BindingScope {
            state,
            round,
            instruction,
            chain_id,
            network_id,
            authority,
            floor,
        },
        SignedCheckAttempt::new(signed),
        test_scope,
    )
    .map(|(_, bound)| bound)
    .map_err(|failure| match failure.error {
        NativeCheckBindingErrorV1::Rejected(error) => error,
        other => panic!("unexpected local fixture refusal: {other:?}"),
    })
}

#[test]
fn bound_check_cannot_cross_native_purpose_or_replace_its_original_round() {
    let state = state();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = instruction(&mut round, &state);
    let bound = bind(&mut round, &state, &instruction).unwrap();
    assert_eq!(
        authenticate_applied_check_v1(
            &state,
            NativeCustodyCheckPurposeV1::FinalPromotion,
            &mut Some(bound),
            &round
        )
        .err()
        .map(crate::execution_attempt::expect_completed_rejection),
        Some(Error::Invalid)
    );

    let mut original = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = self::instruction(&mut original, &state);
    let bound = bind(&mut original, &state, &instruction).unwrap();
    let mut replacement = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    replacement.issue_challenge().unwrap();
    assert_eq!(
        authenticate_applied_check_v1(
            &state,
            NativeCustodyCheckPurposeV1::FinalPromotionAccount,
            &mut Some(bound),
            &replacement
        )
        .err()
        .map(crate::execution_attempt::expect_completed_rejection),
        Some(Error::Invalid)
    );
}

#[test]
fn one_round_issues_and_binds_only_once_and_failure_cannot_be_retried() {
    let state = state();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = instruction(&mut round, &state);
    assert_eq!(round.issue_challenge(), Err(Error::Invalid));
    let bound = bind(&mut round, &state, &instruction).unwrap();
    assert_eq!(
        bind(&mut round, &state, &instruction).err(),
        Some(Error::Invalid)
    );
    assert_eq!(
        authenticate_applied_check_v1(
            &state,
            NativeCustodyCheckPurposeV1::FinalPromotionAccount,
            &mut Some(bound),
            &round
        )
        .err()
        .map(crate::execution_attempt::expect_completed_rejection),
        Some(Error::NotApplied)
    );

    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let mut changed = self::instruction(&mut round, &state);
    let FinalPromotionAccountCustodyActionV1::Check(check) = &mut changed.action else {
        panic!("Check");
    };
    check.challenge = [99; 32];
    assert_eq!(
        bind(&mut round, &state, &changed).err(),
        Some(Error::Transaction)
    );
    assert_eq!(
        bind(&mut round, &state, &changed).err(),
        Some(Error::Invalid)
    );
}

#[test]
fn common_binding_rejects_non_check_actions_for_both_closed_purposes() {
    let state = state();
    let account = MutateSorafsFinalPromotionAccountCustody {
        deployment_id: "promotion-primary".into(),
        expected_control_revision: 0,
        expected_control_digest: [0; 32],
        action: FinalPromotionAccountCustodyActionV1::Configure(vec![1]),
    };
    let promotion = MutateSorafsFinalPromotionAuthority {
        deployment_id: "promotion-primary".into(),
        expected_control_revision: 0,
        expected_control_digest: [0; 32],
        action: FinalPromotionAuthorityActionV1::Configure(vec![1]),
    };
    for instruction in [
        NativeCustodyCheckRefV1::FinalPromotionAccount(&account),
        NativeCustodyCheckRefV1::FinalPromotion(&promotion),
    ] {
        let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
        round.issue_challenge().unwrap();
        let signed = sign(&state, instruction.instruction(), 2, 3_000);
        assert_eq!(
            bind_fixture(
                &state,
                &mut round,
                instruction,
                &state.view().chain_id().to_string(),
                *state.network_id_ref().as_bytes(),
                &AccountId::new(key(2).public_key().clone()),
                floor(),
                signed
            )
            .err(),
            Some(Error::Transaction)
        );
    }
}

#[test]
fn complete_external_bytes_and_signature_are_retained_by_the_single_owner() {
    let state = state();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = instruction(&mut round, &state);
    let signed = sign(&state, instruction.clone().into(), 2, 3_000);
    let bytes = bounded_entry(&TransactionEntrypoint::External(signed.clone())).unwrap();
    let bound = bind(&mut round, &state, &instruction).unwrap();
    assert_eq!(bound.entry_bytes.as_slice(), bytes);
    assert_eq!(bound.signed_transaction(), &signed);
    let mut changed = signed.clone();
    changed.set_signature(TransactionSignature(SignatureOf::from_signature(
        Signature::try_new(key(3).private_key(), b"other authorization").unwrap(),
    )));
    assert_eq!(changed.hash_as_entrypoint(), signed.hash_as_entrypoint());
    assert_ne!(
        bounded_entry(&TransactionEntrypoint::External(changed.clone())).unwrap(),
        bytes
    );
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let exact = self::instruction(&mut round, &state);
    let mut forged = sign(&state, exact.clone().into(), 2, 3_000);
    forged.set_signature(changed.signature().clone());
    assert_eq!(
        bind_fixture(
            &state,
            &mut round,
            NativeCustodyCheckRefV1::FinalPromotionAccount(&exact),
            &state.view().chain_id().to_string(),
            *state.network_id_ref().as_bytes(),
            &AccountId::new(key(2).public_key().clone()),
            floor(),
            forged
        )
        .err(),
        Some(Error::Transaction)
    );
}

mod account_envelope;
mod release_manifest;
mod stream_token;
mod topology;

#[test]
fn shared_check_replay_span_rejects_overlong_history_before_finality_io() {
    let floor = 7_u64;
    assert_eq!(check_history_span_v1(floor, floor), Ok(()));
    assert_eq!(
        check_history_span_v1(floor, floor + MAX_NATIVE_CHECK_HISTORY_BLOCKS_V1 - 1),
        Ok(())
    );
    assert_eq!(
        check_history_span_v1(floor, floor + MAX_NATIVE_CHECK_HISTORY_BLOCKS_V1),
        Err(Error::Finality)
    );
    assert_eq!(
        check_history_span_v1(floor, floor - 1),
        Err(Error::Finality)
    );
    assert_eq!(check_history_span_v1(1, u64::MAX), Err(Error::Finality));
    assert_eq!(
        check_history_span_v1(u64::MAX - 1, u64::MAX),
        Ok(()),
        "only relative work, never absolute height, is bounded"
    );
}

#[test]
fn canonical_check_frames_preserve_wire_and_charge_one_original_allocation_scope() {
    let value = vec![7_u8; 64];
    let canonical = norito::encode_canonical(&value).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, canonical.len(), 32);
    norito::core::with_decode_limits_scope(limits, || {
        assert_eq!(bounded_frame(&value).unwrap(), canonical);
        assert_eq!(
            bounded_frame(&value),
            Err(Error::Transaction),
            "second retained frame cannot renew the original allowance"
        );
    });
    norito::core::with_decode_limits_scope(limits, || {
        assert_eq!(
            bounded_frame(&vec![0_u8; FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1]),
            Err(Error::Transaction)
        );
        assert_eq!(
            bounded_frame(&value).unwrap(),
            canonical,
            "oversized input refuses before charging its nonexistent owned frame"
        );
    });
}

#[test]
fn refused_signed_binding_retains_original_attempt_and_spends_round() {
    let state = state();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = instruction(&mut round, &state);
    let signed = sign(&state, instruction.clone().into(), 2, 3_000);
    let chain_id = state.view().chain_id().to_string();
    let authority = AccountId::new(key(2).public_key().clone());
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let scope = BindingScope {
        state: &state,
        round: &mut round,
        instruction: NativeCustodyCheckRefV1::FinalPromotionAccount(&instruction),
        chain_id: &chain_id,
        network_id: *state.network_id_ref().as_bytes(),
        authority: &authority,
        floor: floor(),
    };
    let failure: BindingFailure<_, Error> =
        match norito::core::with_decode_limits_scope(limits, || {
            bind_signed_check_v1(scope, SignedCheckAttempt::new(signed), test_scope)
        }) {
            Err(failure) => failure,
            Ok(_) => panic!("original caller ceiling must refuse"),
        };
    assert!(matches!(
        &failure.error,
        NativeCheckBindingErrorV1::Codec { local: Some(_), .. }
    ));
    assert!(failure.prepared.round.bound);
    drop(failure);
    assert_eq!(
        bind(&mut round, &state, &instruction).err(),
        Some(Error::Invalid)
    );
}
