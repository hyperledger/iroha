//! Actual configured-root genesis selection and unpublished original-State controls.

use super::*;
use crate::{
    block::authenticate_genesis_block_intents,
    state::{State, StateBlockStartError, World, WorldReadOnly},
};
use iroha_crypto::Algorithm;
use iroha_data_model::{
    isi::{InstructionBox, Log},
    prelude::*,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};

fn policy(algorithm: Algorithm) -> CryptoAdmissionPolicyV1 {
    CryptoAdmissionPolicyV1::new(vec![algorithm]).unwrap()
}

fn instruction(algorithm: Algorithm) -> InstructionBox {
    SetParameter::new(policy(algorithm).into_parameter().unwrap()).into()
}

fn source(batches: Vec<Vec<InstructionBox>>) -> SignedBlock {
    let transactions = batches
        .into_iter()
        .map(|instructions| {
            TransactionBuilder::new_genesis(
                SAMPLE_GENESIS_ACCOUNT_ID.clone(),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions(instructions)
            .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key())
        })
        .collect();
    SignedBlock::genesis(
        transactions,
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    )
    .canonical_resultless_proposal()
    .unwrap()
}

fn state() -> State {
    State::new_for_testing(
        World::new(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    )
}

#[test]
fn configured_root_selects_policy_from_later_input_without_ordinary_root_exemption() {
    let block = source(vec![
        vec![Log::new(Level::INFO, "before policy".into()).into()],
        vec![instruction(Algorithm::Secp256k1)],
    ]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let initial = original.initial_crypto_policy(&block).unwrap();
    assert_eq!(initial.coordinate, (1, 0));
    assert_eq!(initial.policy, policy(Algorithm::Secp256k1));
    assert!(!initial.policy.allows(Algorithm::Ed25519));
    for transaction in block.external_transactions() {
        crate::tx::AcceptedTransaction::validate_genesis_with_now(
            transaction,
            std::time::Duration::from_secs(1),
            &SAMPLE_GENESIS_ACCOUNT_ID,
            block.header().creation_time(),
        )
        .unwrap();
    }
}

#[test]
fn initial_policy_rejects_missing_and_equal_or_conflicting_duplicates_across_all_inputs() {
    for batches in [
        vec![vec![Log::new(Level::INFO, "missing".into()).into()]],
        vec![vec![
            instruction(Algorithm::Ed25519),
            instruction(Algorithm::Ed25519),
        ]],
        vec![
            vec![instruction(Algorithm::Ed25519)],
            vec![instruction(Algorithm::Ed25519)],
        ],
        vec![
            vec![instruction(Algorithm::Ed25519)],
            vec![instruction(Algorithm::Secp256k1)],
        ],
    ] {
        let block = source(batches);
        let original =
            authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
        assert!(matches!(
            original.initial_crypto_policy(&block),
            Err(BlockValidationError::InvalidGenesis(
                InvalidGenesisError::CryptoPolicy(_)
            ))
        ));
    }
}

#[test]
fn policy_capability_cannot_switch_original_source_or_configured_root() {
    let block = source(vec![vec![instruction(Algorithm::Ed25519)]]);
    let other = source(vec![vec![instruction(Algorithm::Secp256k1)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    assert!(original.initial_crypto_policy(&other).is_err());
    assert!(authenticate_genesis_block_intents(&block, &iroha_test_samples::ALICE_ID).is_err());
}

#[test]
fn initial_policy_decoder_refusal_retains_original_and_retries_same_source() {
    let block = source(vec![vec![instruction(Algorithm::Ed25519)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let before = block.canonical_wire().unwrap();
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let error = zero
        .with(|| original.initial_crypto_policy(&block))
        .unwrap_err();
    let BlockValidationError::ExecutionDeferred(original_error) = error else {
        panic!("original decoder refusal required")
    };
    assert!(original_error.decode_refusal().is_some());
    assert_eq!(
        block.canonical_wire().unwrap().as_framed(),
        before.as_framed()
    );
    let retry = original.initial_crypto_policy(&block).unwrap();
    assert_eq!(retry.policy, policy(Algorithm::Ed25519));
}

#[test]
fn pristine_initialization_is_recorded_and_failed_bootstrap_leaves_full_original_state_unchanged() {
    let state = state();
    let block = source(vec![vec![instruction(Algorithm::Ed25519)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_crypto_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            GenesisCryptoPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            overlay.require_original_execution_recorder().unwrap();
            assert!(initial.is_none());
            assert!(overlay.genesis_crypto_policy.is_some());
            assert_eq!(
                overlay.crypto_admission_policy().unwrap(),
                &policy(Algorithm::Ed25519)
            );
            assert_eq!(
                overlay.world.parameters.get().crypto_policy(),
                Some(&policy(Algorithm::Ed25519))
            );
            overlay
                .genesis_crypto_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            // A failed later bootstrap step cannot publish this already initialized overlay.
            Err::<(), BlockValidationError>(invalid("deliberate later bootstrap refusal"))
        },
        invalid,
    );
    assert!(matches!(
        result,
        Err(StateBlockStartError::Stage(
            BlockValidationError::InvalidGenesis(InvalidGenesisError::CryptoPolicy(_))
        ))
    ));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
    assert_eq!(state.state_view_generation(), generation);
    assert!(
        state
            .world
            .view()
            .transaction_admission_parameters()
            .crypto_policy()
            .is_none()
    );
}

#[test]
fn installation_decoder_refusal_keeps_original_state_and_changed_overlay_cannot_finalize() {
    let state = state();
    let block = source(vec![vec![instruction(Algorithm::Ed25519)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_crypto_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            let error = zero
                .with(|| {
                    GenesisCryptoPolicy::install(&mut initial, &block, overlay, &state, generation)
                })
                .unwrap_err();
            let BlockValidationError::ExecutionDeferred(original_error) = error else {
                panic!("original initialization decoder refusal required")
            };
            assert!(original_error.decode_refusal().is_some());
            assert!(overlay.world.parameters.get().crypto_policy().is_none());
            assert!(initial.is_some());
            assert!(overlay.genesis_crypto_policy.is_none());
            GenesisCryptoPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            overlay
                .world
                .parameters
                .get_mut()
                .set_parameter(policy(Algorithm::Secp256k1).into_parameter().unwrap())
                .unwrap();
            assert!(overlay.crypto_admission_policy().is_err());
            {
                let transaction = overlay.transaction();
                assert!(transaction.crypto_admission_policy().is_err());
            }
            overlay
                .genesis_crypto_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)
        },
        invalid,
    );
    assert!(matches!(
        result,
        Err(StateBlockStartError::Stage(
            BlockValidationError::InvalidGenesis(InvalidGenesisError::CryptoPolicy(_))
        ))
    ));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
    assert_eq!(state.state_view_generation(), generation);
}

#[test]
fn initial_policy_installation_rejects_another_owner_generation_and_source_without_effects() {
    let different_state = state();
    let state = state();
    let block = source(vec![vec![instruction(Algorithm::Ed25519)]]);
    let different_source = source(vec![vec![instruction(Algorithm::Secp256k1)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_crypto_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            assert!(
                GenesisCryptoPolicy::install(
                    &mut initial,
                    &block,
                    overlay,
                    &different_state,
                    generation
                )
                .is_err()
            );
            assert!(
                GenesisCryptoPolicy::install(&mut initial, &block, overlay, &state, generation + 1)
                    .is_err()
            );
            assert!(
                GenesisCryptoPolicy::install(
                    &mut initial,
                    &different_source,
                    overlay,
                    &state,
                    generation
                )
                .is_err()
            );
            assert!(overlay.world.parameters.get().crypto_policy().is_none());
            assert!(initial.is_some());
            assert!(overlay.genesis_crypto_policy.is_none());
            GenesisCryptoPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            overlay
                .genesis_crypto_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            Err::<(), BlockValidationError>(invalid("end unpublished ownership control"))
        },
        invalid,
    );
    assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn actual_genesis_parameter_instruction_only_repeats_the_authenticated_initial_policy() {
    use crate::smartcontracts::Execute as _;
    let state = state();
    let block = source(vec![vec![instruction(Algorithm::Ed25519)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_crypto_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            GenesisCryptoPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            {
                let mut transaction = overlay.transaction();
                assert_eq!(
                    transaction.crypto_admission_policy().unwrap(),
                    &policy(Algorithm::Ed25519)
                );
                let parameters_before = transaction.world.parameters.get().clone();
                let changed =
                    SetParameter::new(policy(Algorithm::Secp256k1).into_parameter().unwrap());
                assert!(
                    changed
                        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut transaction)
                        .is_err()
                );
                assert_eq!(transaction.world.parameters.get(), &parameters_before);
                let same = SetParameter::new(policy(Algorithm::Ed25519).into_parameter().unwrap());
                same.execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut transaction)
                    .unwrap();
                assert_eq!(
                    transaction.world.parameters.get().crypto_policy(),
                    Some(&policy(Algorithm::Ed25519))
                );
                // This is an unpublished instruction boundary control; dropping the
                // transaction also rolls back its configuration event.
            }
            overlay
                .genesis_crypto_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            Err::<(), BlockValidationError>(invalid("end unpublished instruction control"))
        },
        invalid,
    );
    assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn installation_rejects_changed_nonpolicy_body_and_da_with_same_original_header() {
    let block = source(vec![vec![
        instruction(Algorithm::Ed25519),
        Log::new(Level::INFO, "original non-policy input".into()).into(),
    ]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut changed_body = source(vec![vec![
        instruction(Algorithm::Ed25519),
        Log::new(Level::INFO, "substituted non-policy input".into()).into(),
    ]]);
    changed_body.replace_header_for_testing(block.header());
    let mut changed_da = block.clone();
    changed_da.set_da_proof_policies(Some(
        iroha_data_model::da::commitment::DaProofPolicyBundle::new(Vec::new()),
    ));
    changed_da.replace_header_for_testing(block.header());
    for substituted in [changed_body, changed_da] {
        let mut initial = Some(original.initial_crypto_policy(&block).unwrap());
        assert_eq!(substituted.header(), block.header());
        assert!(substituted.validate_proposal_commitments().is_err());
        let state = state();
        let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
        let generation = state.state_view_generation();
        let result = state.block_with_recorded_pristine_carrier_stage(
            &block,
            |overlay| {
                let error = GenesisCryptoPolicy::install(
                    &mut initial,
                    &substituted,
                    overlay,
                    &state,
                    generation,
                )
                .unwrap_err();
                assert!(matches!(
                    error,
                    BlockValidationError::InvalidGenesis(InvalidGenesisError::CryptoPolicy(_))
                ));
                assert!(overlay.world.parameters.get().crypto_policy().is_none());
                GenesisCryptoPolicy::install(&mut initial, &block, overlay, &state, generation)?;
                overlay
                    .genesis_crypto_policy
                    .as_ref()
                    .unwrap()
                    .require_unchanged(overlay)?;
                Err::<(), BlockValidationError>(invalid(
                    "end unpublished source substitution control",
                ))
            },
            invalid,
        );
        assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
        assert_eq!(state.state_view_generation(), generation);
    }
}

#[test]
fn header_and_unpublished_current_policy_cannot_replace_retained_genesis_authority() {
    let state = state();
    let block = source(vec![vec![instruction(Algorithm::Ed25519)]]);
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    {
        let mut overlay = state.block(block.header());
        overlay
            .world
            .parameters
            .get_mut()
            .set_parameter(policy(Algorithm::Ed25519).into_parameter().unwrap())
            .unwrap();
        assert!(overlay.genesis_crypto_policy.is_none());
        assert!(overlay.world.parameters.get().crypto_policy().is_some());
        assert!(overlay.crypto_admission_policy().is_err());
        let transaction = overlay.transaction();
        assert!(transaction.crypto_admission_policy().is_err());
    }
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn ordinary_policy_borrows_original_preimage_across_pending_applied_and_rolled_back_changes() {
    let state = state();
    let expected = policy(Algorithm::Ed25519);
    let mut parameters = state.world.parameters.block();
    parameters
        .get_mut()
        .set_parameter(expected.clone().into_parameter().unwrap())
        .unwrap();
    parameters.commit();
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    // Structural owner control only: these headers grant no native publication authority.
    let header = BlockHeader::new(std::num::NonZeroU64::new(2).unwrap(), None, None, 1, 0);
    {
        let mut overlay = state.block(header);
        assert!(overlay.genesis_crypto_policy.is_none());
        assert!(std::ptr::eq(
            overlay.crypto_admission_policy().unwrap(),
            overlay
                .world
                .parameters
                .get_before_block()
                .require_crypto_policy()
                .unwrap(),
        ));
        {
            let mut transaction = overlay.transaction();
            transaction
                .world
                .parameters
                .get_mut()
                .set_parameter(policy(Algorithm::Secp256k1).into_parameter().unwrap())
                .unwrap();
            assert_eq!(transaction.crypto_admission_policy().unwrap(), &expected);
            transaction.apply();
        }
        assert_eq!(
            overlay.world.parameters.get().crypto_policy(),
            Some(&policy(Algorithm::Secp256k1))
        );
        assert_eq!(overlay.crypto_admission_policy().unwrap(), &expected);
        {
            let mut sibling = overlay.transaction();
            assert_eq!(sibling.crypto_admission_policy().unwrap(), &expected);
            sibling
                .world
                .parameters
                .get_mut()
                .set_parameter(policy(Algorithm::Ed25519).into_parameter().unwrap())
                .unwrap();
            assert_eq!(sibling.crypto_admission_policy().unwrap(), &expected);
        }
        assert_eq!(
            overlay.world.parameters.get().crypto_policy(),
            Some(&policy(Algorithm::Secp256k1))
        );
        assert_eq!(overlay.crypto_admission_policy().unwrap(), &expected);
    }
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn replacement_policy_borrows_original_undo_and_rejects_current_only_signed_algorithm() {
    let state = state();
    let older = policy(Algorithm::Ed25519);
    let mut initial = state.world.parameters.block();
    initial
        .get_mut()
        .set_parameter(older.clone().into_parameter().unwrap())
        .unwrap();
    initial.commit();
    let retained_old = state.query_view();
    let wider =
        CryptoAdmissionPolicyV1::new(vec![Algorithm::Ed25519, Algorithm::Secp256k1]).unwrap();
    let mut update = state.world.parameters.block();
    update
        .get_mut()
        .set_parameter(wider.clone().into_parameter().unwrap())
        .unwrap();
    update.commit();
    // A structural cell publication control: the same-height selector must use its
    // retained undo. No fabricated header or this test grants native history authority.
    let view = state.query_view();
    assert_eq!(
        view.crypto_admission_policy_for_validation(false).unwrap(),
        &wider
    );
    assert_eq!(
        view.crypto_admission_policy_for_validation(true).unwrap(),
        &older
    );
    assert_eq!(
        retained_old
            .crypto_admission_policy_for_validation(false)
            .unwrap(),
        &older
    );
    let key = iroha_crypto::KeyPair::try_from_seed(vec![0xDA; 32], Algorithm::Secp256k1).unwrap();
    let transaction = TransactionBuilder::new(
        *state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "replacement policy source".into())])
    .try_sign(key.private_key())
    .unwrap();
    let validate = |selected| {
        crate::tx::AcceptedTransaction::validate_with_now(
            &transaction,
            state.network_id_ref(),
            std::time::Duration::ZERO,
            view.world.parameters().transaction(),
            selected,
            transaction.creation_time(),
        )
    };
    validate(view.crypto_admission_policy_for_validation(false).unwrap()).unwrap();
    let rejected =
        validate(view.crypto_admission_policy_for_validation(true).unwrap()).unwrap_err();
    assert!(
        matches!(rejected, crate::tx::AcceptTransactionFail::SignatureVerification(ref failure)
        if failure.code() == crate::tx::SignatureRejectionCode::AlgorithmNotPermitted)
    );
    drop(view);
    // An unchanged next cell commit has no distinct undo and legitimately uses current.
    state.world.parameters.block().commit();
    let unchanged = state.query_view();
    assert_eq!(
        unchanged
            .crypto_admission_policy_for_validation(true)
            .unwrap(),
        &wider
    );
    assert_eq!(
        retained_old
            .crypto_admission_policy_for_validation(false)
            .unwrap(),
        &older
    );
}

#[test]
fn public_genesis_policy_inspection_authenticates_original_and_keeps_callback_result() {
    let state = state();
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let block = source(vec![vec![instruction(Algorithm::Secp256k1)]]);
    let source_before = block.canonical_wire().unwrap();
    let calls = std::cell::Cell::new(0);
    let marker = Box::new(41_u64);
    let identity = std::ptr::from_ref(&*marker);
    let retained: Result<(), Box<u64>> = crate::with_authenticated_genesis_crypto_policy(
        &block,
        &SAMPLE_GENESIS_ACCOUNT_ID,
        |selected| {
            calls.set(calls.get() + 1);
            assert_eq!(selected, &policy(Algorithm::Secp256k1));
            assert!(!selected.allows(Algorithm::Ed25519));
            Err(marker)
        },
    )
    .unwrap();
    let retained = retained.unwrap_err();
    assert_eq!(
        std::ptr::from_ref(&*retained),
        identity,
        "callback result is moved without translation"
    );
    assert_eq!(calls.get(), 1);
    assert!(
        crate::with_authenticated_genesis_crypto_policy(
            &block,
            &iroha_test_samples::ALICE_ID,
            |_| calls.set(calls.get() + 1)
        )
        .is_err()
    );
    let duplicate = source(vec![vec![
        instruction(Algorithm::Ed25519),
        instruction(Algorithm::Ed25519),
    ]]);
    assert!(
        crate::with_authenticated_genesis_crypto_policy(
            &duplicate,
            &SAMPLE_GENESIS_ACCOUNT_ID,
            |_| calls.set(calls.get() + 1)
        )
        .is_err()
    );
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let error = zero
        .with(|| {
            crate::with_authenticated_genesis_crypto_policy(
                &block,
                &SAMPLE_GENESIS_ACCOUNT_ID,
                |_| calls.set(calls.get() + 1),
            )
        })
        .unwrap_err();
    assert!(
        matches!(error, BlockValidationError::ExecutionDeferred(original) if original.decode_refusal().is_some())
    );
    assert_eq!(
        calls.get(),
        1,
        "authentication and decode failure cannot reach callback"
    );
    crate::with_authenticated_genesis_crypto_policy(&block, &SAMPLE_GENESIS_ACCOUNT_ID, |_| {
        calls.set(calls.get() + 1)
    })
    .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(
        block.canonical_wire().unwrap().as_framed(),
        source_before.as_framed()
    );
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn local_crypto_settings_do_not_change_original_policy_or_execution_digest() {
    let state = state();
    let mut parameters = state.world.parameters.block();
    parameters
        .get_mut()
        .set_parameter(policy(Algorithm::Secp256k1).into_parameter().unwrap())
        .unwrap();
    parameters.commit();
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&std::sync::Arc::new(
        crate::governance::manifest::LaneManifestRegistry::empty()
            .rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    let before_digest = state.execution_policy_digest_v1().unwrap();
    let key = iroha_crypto::KeyPair::try_from_seed(vec![0xDB; 32], Algorithm::Secp256k1).unwrap();
    let transaction = TransactionBuilder::new(
        *state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(
        Level::INFO,
        "local crypto has no admission authority".into(),
    )])
    .try_sign(key.private_key())
    .unwrap();
    let validate = || {
        let original = state.transaction_admission_parameters();
        crate::tx::AcceptedTransaction::validate_with_now(
            &transaction,
            state.network_id_ref(),
            std::time::Duration::ZERO,
            original.transaction(),
            original.require_crypto_policy().unwrap(),
            transaction.creation_time(),
        )
        .unwrap();
        assert_eq!(
            original.require_crypto_policy().unwrap(),
            &policy(Algorithm::Secp256k1)
        );
    };
    validate();
    let mut local = state.crypto().as_ref().clone();
    local.default_hash = "sm3-256".into();
    local.sm2_distid_default = "local generation identity".into();
    local.enable_sm_openssl_preview = !local.enable_sm_openssl_preview;
    local.sm_intrinsics = iroha_config::parameters::actual::SmIntrinsicsPolicy::ForceDisable;
    state.set_crypto(local);
    assert_eq!(state.execution_policy_digest_v1().unwrap(), before_digest);
    validate();
}
