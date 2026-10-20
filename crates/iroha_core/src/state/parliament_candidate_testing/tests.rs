//! Genuine genesis installation, direct-origin refusal and certified replay controls.

use super::*;
use crate::{
    block::authenticate_genesis_block_intents,
    smartcontracts::Execute,
    state::{StateBlockStartError, World},
    sumeragi::test_chain::{CertifiedTestChain, PreparedTestChainConfig, TestChainConfig},
};
use iroha_data_model::{
    NetworkId, governance::anonymous_ballot::authenticate_parliament_candidate_genesis_v1,
    transaction::TransactionEntrypoint,
};
use iroha_primitives::json::Json;
use iroha_test_samples::BOB_ID;

fn parameter() -> Parameter {
    Parameter::Custom(
        ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
            .to_custom_parameter()
            .unwrap(),
    )
}

fn config(selected: bool) -> TestChainConfig {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    if selected {
        config
            .genesis_instructions
            .push(SetParameter::new(parameter()).into());
    }
    config
}

fn committed_parameter(chain: &CertifiedTestChain) -> Option<CustomParameter> {
    chain
        .state()
        .view()
        .world()
        .parameters()
        .custom()
        .get(ParliamentCandidateTestingPolicyV1::parameter_id())
        .cloned()
}

#[tokio::test]
async fn candidate_testing_native_genesis_and_certified_replay_preserve_the_original_selection() {
    let mut original = CertifiedTestChain::start(config(true)).unwrap();
    let mut replay = CertifiedTestChain::start(config(true)).unwrap();
    assert_eq!(
        original.validated_genesis().canonical_wire(),
        replay.validated_genesis().canonical_wire(),
    );
    let expected = parameter();
    let Parameter::Custom(expected) = expected else {
        unreachable!()
    };
    assert_eq!(committed_parameter(&original), Some(expected.clone()));
    assert_eq!(committed_parameter(&replay), Some(expected.clone()));

    original.commit_at(1_002, Vec::new());
    replay.replay_from(&original).unwrap();
    assert_eq!(replay.height(), original.height());
    assert_eq!(committed_parameter(&replay), Some(expected));
}

#[tokio::test]
async fn candidate_testing_cannot_be_installed_or_replaced_after_genesis() {
    for selected in [false, true] {
        let cfg = config(selected);
        let key = cfg.genesis_key.clone();
        let mut chain = CertifiedTestChain::start(cfg).unwrap();
        let before = committed_parameter(&chain);
        let transaction = chain.sign(&key, [SetParameter::new(parameter()).into()], 1_002);
        assert_eq!(chain.commit(vec![transaction]), vec![false]);
        assert_eq!(committed_parameter(&chain), before);

        // Also exercise the native handler directly: privilege or a restored raw slot
        // cannot replace the required original signed instruction capability.
        let header = iroha_data_model::block::BlockHeader::new(
            3_u64.try_into().unwrap(),
            None,
            None,
            1_003,
            0,
        );
        let mut block = chain.state().block(header);
        let mut tx = block.transaction();
        assert!(
            SetParameter::new(parameter())
                .execute(chain.genesis_account(), &mut tx)
                .is_err()
        );
    }
}

#[tokio::test]
async fn candidate_testing_duplicate_and_unsupported_signed_genesis_leave_no_committed_slot() {
    let mut duplicate = config(true);
    duplicate
        .genesis_instructions
        .push(SetParameter::new(parameter()).into());
    let mut unsupported = config(false);
    unsupported.genesis_instructions.push(
        SetParameter::new(Parameter::Custom(CustomParameter::new(
            ParliamentCandidateTestingPolicyV1::parameter_id().clone(),
            Json::new(ParliamentCandidateTestingPolicyV1 {
                version: 2,
                ..ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
            }),
        )))
        .into(),
    );
    for config in [duplicate, unsupported] {
        let failure = CertifiedTestChain::prepare(config).unwrap_err();
        let view = failure.state.view();
        assert_eq!(view.height(), 0);
        assert!(
            view.world()
                .parameters()
                .custom()
                .get(ParliamentCandidateTestingPolicyV1::parameter_id())
                .is_none()
        );
        assert_eq!(failure.state.kura().blocks_count(), 0);
    }
}

/// Inspect one real original source before effects; no test creates a capability.
fn with_original(
    prepared: &PreparedTestChainConfig,
    inspect: impl FnOnce(
        &mut StateBlock<'_>,
        super::super::network_policy_routes::CapturedNetworkPolicyRoute,
        &crate::block::AuthenticatedGenesisTransaction,
        &SignedTransaction,
        &InstructionBox,
        usize,
        usize,
    ),
) {
    let original = prepared.genesis.block();
    let (_, selection) =
        authenticate_parliament_candidate_genesis_v1(original, &prepared.state.network_id).unwrap();
    let selection = selection.unwrap();
    let (input_index, instruction_index) = selection.source_position();
    let TransactionEntrypoint::External(signed) =
        original.network_entrypoint_at(input_index).unwrap()
    else {
        unreachable!()
    };
    let Executable::Instructions(instructions) = signed.instructions() else {
        unreachable!()
    };
    let authority = signed.authority();
    let authenticated = authenticate_genesis_block_intents(original, authority).unwrap();
    let input = authenticated
        .transaction_for(original, input_index)
        .unwrap();
    let result = prepared
        .state
        .block_with_owned_start_stages_with_carrier(
            original.header(),
            Some(original),
            |block| {
                let (_, route) = block
                    .network_policy_routes
                    .as_ref()
                    .unwrap()
                    .get(original, input_index)
                    .unwrap();
                inspect(
                    block,
                    route,
                    &input,
                    signed,
                    &instructions[instruction_index],
                    input_index,
                    instruction_index,
                );
                Err::<(), _>("candidate origin inspected")
            },
            |_, ()| Ok(()),
        )
        .map(|_| ());
    assert!(matches!(
        result,
        Err(StateBlockStartError::Stage("candidate origin inspected"))
    ));
}

fn bind_input(
    tx: &mut StateTransaction<'_, '_>,
    route: super::super::network_policy_routes::CapturedNetworkPolicyRoute,
    authenticated: &crate::block::AuthenticatedGenesisTransaction,
    signed: &SignedTransaction,
    input_index: usize,
) {
    tx.current_network_entrypoint_hash = Some(signed.hash_as_entrypoint());
    tx.current_entrypoint_index = Some(input_index.try_into().unwrap());
    tx.current_tx_hash = Some(signed.hash());
    tx.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
    tx.genesis_execution_scope = route
        .genesis_execution_scope(signed, tx, Some(authenticated))
        .unwrap();
}

#[tokio::test]
async fn candidate_testing_only_exact_direct_original_instruction_can_install() {
    let prepared = CertifiedTestChain::prepare(config(true)).unwrap();
    with_original(
        &prepared,
        |block, route, original, signed, instruction, input, ordinal| {
            for case in 0..11 {
                let mut tx = block.transaction();
                bind_input(&mut tx, route, original, signed, input);
                let authority = signed.authority();
                match case {
                    3 => tx.current_entrypoint_index = Some(input as u64 + 1),
                    6 => {
                        tx.network_id = NetworkId::from_genesis_hash(
                            HashOf::from_untyped_unchecked(Hash::new(b"foreign candidate network")),
                        )
                    }
                    7 => tx.current_tx_hash = None,
                    _ => {}
                }
                if case != 1 {
                    tx.arm_direct_parliament_candidate_testing(
                        signed,
                        if case == 5 { &BOB_ID } else { authority },
                        instruction,
                        if case == 4 { ordinal + 1 } else { ordinal },
                        case != 2,
                    );
                }
                match case {
                    8 => tx.tx_call_hash = None,
                    9 => tx.clear_direct_parliament_candidate_testing(),
                    _ => {}
                }
                let supplied = if case == 10 {
                    Parameter::Custom(CustomParameter::new(
                        ParliamentCandidateTestingPolicyV1::parameter_id().clone(),
                        Json::new("altered after original authentication"),
                    ))
                } else {
                    parameter()
                };
                let result = SetParameter::new(supplied).execute(authority, &mut tx);
                assert_eq!(result.is_ok(), case == 0, "case {case}: {result:?}");
                assert_eq!(
                    tx.world
                        .parameters
                        .get()
                        .custom()
                        .contains_key(ParliamentCandidateTestingPolicyV1::parameter_id()),
                    case == 0
                );
            }
        },
    );
}

#[tokio::test]
async fn candidate_testing_consumption_is_one_use_including_rejected_consumption() {
    let prepared = CertifiedTestChain::prepare(config(true)).unwrap();
    with_original(
        &prepared,
        |block, route, original, signed, instruction, input, ordinal| {
            for wrong_authority in [false, true] {
                let mut tx = block.transaction();
                bind_input(&mut tx, route, original, signed, input);
                tx.arm_direct_parliament_candidate_testing(
                    signed,
                    signed.authority(),
                    instruction,
                    ordinal,
                    true,
                );
                assert_eq!(
                    tx.consume_parliament_candidate_testing_parameter(
                        &parameter(),
                        if wrong_authority {
                            &BOB_ID
                        } else {
                            signed.authority()
                        }
                    )
                    .is_ok(),
                    !wrong_authority
                );
                tx.arm_direct_parliament_candidate_testing(
                    signed,
                    signed.authority(),
                    instruction,
                    ordinal,
                    true,
                );
                assert!(
                    tx.consume_parliament_candidate_testing_parameter(
                        &parameter(),
                        signed.authority()
                    )
                    .is_err()
                );
            }
        },
    );
}

#[tokio::test]
async fn candidate_testing_genesis_output_seal_rejects_omission_injection_and_change() {
    let prepared = CertifiedTestChain::prepare(config(true)).unwrap();
    let original = prepared.genesis.block();
    let mut block = prepared.state.block(original.header());
    assert!(validate_genesis_output(original, &block).is_err());
    block
        .world
        .parameters
        .get_mut()
        .set_parameter(parameter())
        .unwrap();
    assert!(validate_genesis_output(original, &block).is_ok());
    block
        .world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(CustomParameter::new(
            ParliamentCandidateTestingPolicyV1::parameter_id().clone(),
            Json::new("substitution"),
        )))
        .unwrap();
    assert!(validate_genesis_output(original, &block).is_err());

    let absent = CertifiedTestChain::prepare(config(false)).unwrap();
    let source = absent.genesis.block();
    let mut block = absent.state.block(source.header());
    assert!(validate_genesis_output(source, &block).is_ok());
    block
        .world
        .parameters
        .get_mut()
        .set_parameter(parameter())
        .unwrap();
    assert!(validate_genesis_output(source, &block).is_err());
}

#[test]
fn candidate_testing_codec_refusals_stay_deferred_and_invalid_policy_stays_rejected() {
    let error = ParliamentCandidateTestingErrorV1::Json(norito::json::Error::AllocationFailed);
    assert!(matches!(
        candidate_policy_attempt_error(error),
        ExecutionAttemptError::Deferred(_)
    ));
    assert!(matches!(
        candidate_policy_attempt_error(ParliamentCandidateTestingErrorV1::DuplicatePolicy),
        ExecutionAttemptError::Rejected(_)
    ));
}

#[tokio::test]
async fn candidate_testing_preseeded_same_value_never_replaces_original_installation() {
    for selected in [false, true] {
        let mut cfg = config(selected);
        let mut parameters = cfg.world.parameters.view().get().clone();
        parameters.set_parameter(parameter()).unwrap();
        cfg.world.parameters = mv::cell::Cell::new(parameters);
        // The real preparation owner executes original native genesis, even though it
        // discards the overlay while deriving signed policy commitments.
        let failure = CertifiedTestChain::prepare(cfg).unwrap_err();
        let view = failure.state.view();
        assert_eq!(view.height(), 0);
        assert_eq!(failure.state.kura().blocks_count(), 0);
        let Parameter::Custom(expected) = parameter() else {
            unreachable!()
        };
        assert_eq!(
            view.world()
                .parameters()
                .custom()
                .get(ParliamentCandidateTestingPolicyV1::parameter_id()),
            Some(&expected),
            "failed original execution must preserve the untouched preseeded owner",
        );
    }
}

#[tokio::test]
async fn candidate_testing_borrowed_and_user_executor_dispatch_cannot_inherit_direct_authority() {
    let prepared = CertifiedTestChain::prepare(config(true)).unwrap();
    let denying =
        crate::executor::denying_executor_for_testing("candidate marker dispatch control");
    with_original(
        &prepared,
        |block, route, original, signed, instruction, input, ordinal| {
            for dispatch in 0..3 {
                let mut tx = block.transaction();
                bind_input(&mut tx, route, original, signed, input);
                tx.arm_direct_parliament_candidate_testing(
                    signed,
                    signed.authority(),
                    instruction,
                    ordinal,
                    true,
                );
                assert!(tx.direct_parliament_candidate_testing.is_some());
                let result = match dispatch {
                    0 => crate::executor::Executor::Initial.execute_instruction(
                        &mut tx,
                        signed.authority(),
                        instruction.clone(),
                    ),
                    1 => crate::executor::Executor::Initial.execute_borrowed_overlay_instruction(
                        &mut tx,
                        signed.authority(),
                        instruction,
                        None,
                    ),
                    _ => denying.execute_instruction(
                        &mut tx,
                        signed.authority(),
                        instruction.clone(),
                    ),
                };
                if dispatch == 2 {
                    assert!(matches!(
                        result,
                        Err(iroha_data_model::ValidationFail::NotPermitted(message))
                            if message == "candidate marker dispatch control"
                    ));
                } else {
                    assert_eq!(result.is_ok(), dispatch == 0, "{result:?}");
                }
                assert!(tx.direct_parliament_candidate_testing.is_none());
                assert_eq!(
                    tx.world
                        .parameters
                        .get()
                        .custom()
                        .contains_key(ParliamentCandidateTestingPolicyV1::parameter_id()),
                    dispatch == 0,
                );
                // A caught executor error cannot hand the old direct authority to a
                // native host invocation of the same original SetParameter value.
                assert!(
                    SetParameter::new(parameter())
                        .execute(signed.authority(), &mut tx)
                        .is_err()
                );
            }
        },
    );
}
