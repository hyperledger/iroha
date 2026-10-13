//! Final candidate, signed genesis batch, schedule, and rollback regressions.

use std::num::NonZeroU64;

use iroha_data_model::{
    Level, Registrable as _,
    account::Account,
    isi::{InstructionBox, Log, SetParameter, privacy::SchedulePrivacyConsensusPolicyTighteningV1},
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiParameter, TransactionParameter},
    },
    privacy::{
        PrivacyConsensusLimitsV1, PrivacyConsensusPolicyTighteningV1, PrivacyConsensusPolicyV1,
    },
    transaction::Executable,
};
use iroha_executor_data_model::permission::{
    governance::CanEnactGovernance, parameter::CanSetParameters,
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};

use super::*;
use crate::{
    state::World,
    sumeragi::{
        schedule::{
            ChainParamsRecord, ConsensusSchedule, RetainedConsensusSchedule, ScheduledConfig,
            ScheduledSlot,
        },
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};

const MIB: u32 = 1024 * 1024;

fn lower_limits(action: u32, block: u32) -> PrivacyConsensusLimitsV1 {
    PrivacyConsensusLimitsV1 {
        max_proof_bytes_per_action: action,
        max_action_bytes: action,
        max_privacy_bytes_per_transaction: action,
        max_privacy_bytes_per_block: block,
        ..PrivacyConsensusLimitsV1::taira_default()
    }
}

fn set_caps(world: &World, transaction: u64, block: u32) {
    let mut parameters = world.parameters.block();
    parameters
        .set_parameter(Parameter::Transaction(TransactionParameter::MaxTxBytes(
            NonZeroU64::new(transaction).unwrap(),
        )))
        .unwrap();
    parameters
        .set_parameter(Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
            NonZeroU32::new(block).unwrap(),
        )))
        .unwrap();
    parameters.commit();
}

fn set_privacy(world: &World, policy: PrivacyConsensusPolicyV1) {
    let mut privacy = world.privacy_consensus_policy.block();
    *privacy.get_mut() = policy;
    privacy.commit();
}

fn scheduled_world(caps: [u32; 3]) -> World {
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(
        SumeragiConsensusMode::Permissioned,
        10,
        false,
    );
    let epoch = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .unwrap()
        .into_parts()
        .0;
    let graph = ConsensusSchedule::from_owned_entries(
        caps.into_iter()
            .enumerate()
            .map(|(index, cap)| {
                let mut params = ChainParamsRecord::from_parameters(
                    &iroha_data_model::parameter::system::SumeragiParameters::default(),
                );
                params.max_block_bytes = cap;
                ScheduledSlot::Ready(ScheduledConfig {
                    height: index as u64 + 2,
                    epoch: epoch.clone(),
                    params,
                })
            })
            .collect(),
    )
    .unwrap();
    let world = World::new();
    let budget = iroha_allocation::AllocationBudget::new(1024 * 1024);
    let mut schedule = world.consensus_schedule.block();
    *schedule.get_mut() = RetainedConsensusSchedule::admit(&graph, &budget).unwrap();
    schedule.commit();
    world
}

#[test]
fn original_successor_slots_control_final_candidates_and_restores() {
    let world = scheduled_world([16 * MIB; 3]);
    validate_final_policy(&world.view(), 2).unwrap();
    validate_restored_policy(&world.view(), 2).unwrap();
    set_caps(&world, u64::from(10 * MIB), 15 * MIB);
    assert_eq!(
        validate_restored_policy(&world.view(), 2),
        Err(PolicyCoherenceError::RestoredBlockCapMismatch {
            height: 4,
            parameter_max_block_bytes: 15 * MIB,
            scheduled_max_block_bytes: 16 * MIB,
        })
    );
    assert!(matches!(
        validate_final_policy(&world.view(), 2),
        Err(PolicyCoherenceError::Effective(
            SuccessorResourceCoherenceError::AtHeight {
                effective_height: 4,
                ..
            }
        ))
    ));
}

#[test]
fn missing_authenticated_successor_never_uses_local_or_default_caps() {
    let world = World::new();
    validate_restored_policy(&world.view(), 0).unwrap();
    assert_eq!(
        validate_final_policy(&world.view(), 2),
        Err(PolicyCoherenceError::MissingScheduledParameters { height: 3 })
    );
    assert_eq!(
        validate_restored_policy(&world.view(), 2),
        Err(PolicyCoherenceError::MissingScheduledParameters { height: 4 })
    );
    assert_eq!(
        validate_final_policy(&world.view(), u64::MAX),
        Err(PolicyCoherenceError::HeightOverflow {
            committed_height: u64::MAX
        })
    );
}

#[test]
fn lower_genesis_caps_require_privacy_tightening_at_height_two() {
    let world = World::new();
    set_caps(&world, u64::from(3 * MIB), 4 * MIB);
    let mut policy = PrivacyConsensusPolicyV1 {
        current_limits: PrivacyConsensusLimitsV1::taira_default(),
        pending_tightening: Some(PrivacyConsensusPolicyTighteningV1 {
            scheduled_at_height: 1,
            effective_at_height: 2,
            next_limits: lower_limits(2 * MIB, 3 * MIB),
        }),
    };
    set_privacy(&world, policy);
    validate_final_policy(&world.view(), 1).unwrap();
    policy
        .pending_tightening
        .as_mut()
        .unwrap()
        .effective_at_height = 3;
    set_privacy(&world, policy);
    assert!(matches!(
        validate_final_policy(&world.view(), 1),
        Err(PolicyCoherenceError::Effective(
            SuccessorResourceCoherenceError::AtHeight {
                effective_height: 2,
                ..
            }
        ))
    ));
}

#[test]
fn invocation_rejection_retains_exact_height_and_numeric_diagnostic() {
    let error = PolicyCoherenceError::RestoredBlockCapMismatch {
        height: 9,
        parameter_max_block_bytes: 123,
        scheduled_max_block_bytes: 456,
    };
    let expected = format!("incoherent final resource policy: {error}");
    assert_eq!(
        error.into_transaction_rejection(),
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted(expected),
        )
    );
}

fn genesis_config(effective_at_height: Option<u64>) -> TestChainConfig {
    let mut world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    world.account_permissions.insert(
        ALICE_ID.clone(),
        [CanSetParameters.into(), CanEnactGovernance.into()]
            .into_iter()
            .collect(),
    );
    let mut config = TestChainConfig::new(world, 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.genesis_parameters = vec![
        Parameter::Transaction(TransactionParameter::MaxTxBytes(
            NonZeroU64::new(u64::from(3 * MIB)).unwrap(),
        )),
        Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
            NonZeroU32::new(4 * MIB).unwrap(),
        )),
    ];
    if let Some(height) = effective_at_height {
        config.genesis_instructions.push(
            SchedulePrivacyConsensusPolicyTighteningV1::new(height, lower_limits(2 * MIB, 3 * MIB))
                .into(),
        );
    }
    config
}

#[test]
fn split_signed_genesis_transactions_may_be_temporarily_incoherent() {
    let chain = CertifiedTestChain::start(genesis_config(Some(2)))
        .expect("complete signed genesis is coherent");
    let mut parameter_index = None;
    let mut privacy_index = None;
    for (index, transaction) in chain.genesis().external_transactions().enumerate() {
        if let Executable::Instructions(instructions) = transaction.instructions() {
            for instruction in instructions {
                if instruction.as_any().downcast_ref::<SetParameter>().is_some_and(|set| matches!(set.inner(), Parameter::Transaction(TransactionParameter::MaxTxBytes(value)) if value.get() == u64::from(3 * MIB))) {
                    parameter_index = Some(index);
                }
                if instruction
                    .as_any()
                    .is::<SchedulePrivacyConsensusPolicyTighteningV1>()
                {
                    privacy_index = Some(index);
                }
            }
        }
    }
    assert!(
        parameter_index.unwrap() < privacy_index.unwrap(),
        "the temporary inconsistency spans distinct authenticated transactions"
    );
    validate_restored_policy(chain.state().view().world(), 1).unwrap();
}

#[test]
fn executed_genesis_rejects_final_incoherence_and_an_uncovered_intervening_height() {
    for activation in [None, Some(3)] {
        let error = CertifiedTestChain::start(genesis_config(activation))
            .expect_err("final genesis must reject incoherent height two");
        assert!(
            format!("{error:?}").contains("incoherent resource policy at height 2"),
            "{error:?}"
        );
        assert_eq!(
            error.state.view().height(),
            0,
            "rejected genesis publishes no state"
        );
    }
}

#[test]
fn atomic_governance_transaction_checks_final_policy_in_either_instruction_order() {
    for reverse in [false, true] {
        let mut chain = CertifiedTestChain::start(genesis_config(Some(2))).unwrap();
        let mut instructions: Vec<InstructionBox> = vec![
            SetParameter::new(Parameter::Transaction(TransactionParameter::MaxTxBytes(
                NonZeroU64::new(u64::from(MIB)).unwrap(),
            )))
            .into(),
            SchedulePrivacyConsensusPolicyTighteningV1::new(3, lower_limits(MIB, 2 * MIB)).into(),
        ];
        if reverse {
            instructions.reverse();
        }
        let transaction = chain.sign(&ALICE_KEYPAIR, instructions, 1);
        assert_eq!(chain.commit(vec![transaction]), vec![true]);
        validate_restored_policy(chain.state().view().world(), 2).unwrap();
        assert_eq!(
            chain
                .state()
                .view()
                .world()
                .parameters()
                .transaction()
                .max_tx_bytes()
                .get(),
            u64::from(MIB)
        );
    }
}

#[test]
fn invalid_final_governance_transaction_rolls_back_without_poisoning_block() {
    let mut chain = CertifiedTestChain::start(genesis_config(Some(2))).unwrap();
    let invalid = chain.sign(
        &ALICE_KEYPAIR,
        [
            SetParameter::new(Parameter::Transaction(TransactionParameter::MaxTxBytes(
                NonZeroU64::new(u64::from(MIB)).unwrap(),
            )))
            .into(),
        ],
        1,
    );
    let work = chain.sign(
        &ALICE_KEYPAIR,
        [Log::new(Level::INFO, "same block still executes".into()).into()],
        2,
    );
    assert_eq!(chain.commit(vec![invalid, work]), vec![false, true]);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .parameters()
            .transaction()
            .max_tx_bytes()
            .get(),
        u64::from(3 * MIB)
    );
    assert!(
        format!("{:?}", chain.committed(2).block().output_error(0))
            .contains("incoherent final resource policy")
    );
    let next = chain.sign(
        &ALICE_KEYPAIR,
        [Log::new(Level::INFO, "next block still executes".into()).into()],
        1_001,
    );
    assert_eq!(chain.commit(vec![next]), vec![true]);
}

#[test]
fn internal_pipeline_candidate_rolls_back_incoherent_policy_before_publication() {
    use iroha_data_model::{
        block::execution_output::ExecutionOutputV1,
        events::pipeline::{BlockEventFilter, BlockStatus},
        isi::Register,
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    let mut config = genesis_config(Some(2));
    let invalid = SetParameter::new(Parameter::Transaction(TransactionParameter::MaxTxBytes(
        NonZeroU64::new(u64::from(MIB)).unwrap(),
    )));
    config.genesis_instructions.push(
        Register::trigger(Trigger::new(
            "incoherent_resource_callback".parse().unwrap(),
            Action::new(
                vec![InstructionBox::from(invalid)],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                BlockEventFilter::new()
                    .for_status(BlockStatus::Approved)
                    .for_height(NonZeroU64::new(2).unwrap()),
            )
            .unwrap(),
        ))
        .into(),
    );
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let work = chain.sign(
        &ALICE_KEYPAIR,
        [Log::new(Level::INFO, "invoke pipeline".into()).into()],
        1,
    );
    assert_eq!(chain.commit(vec![work]), vec![true]);
    let committed = chain.committed(2);
    let failure = committed
        .block()
        .execution_outputs()
        .iter()
        .find_map(|output| match output {
            ExecutionOutputV1::Pipeline(output) => output.result.as_ref().err(),
            _ => None,
        })
        .expect("actual pipeline callback is deterministically rejected");
    assert!(format!("{failure:?}").contains("incoherent final resource policy"));
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .parameters()
            .transaction()
            .max_tx_bytes()
            .get(),
        u64::from(3 * MIB)
    );
    validate_restored_policy(chain.state().view().world(), 2).unwrap();
}
