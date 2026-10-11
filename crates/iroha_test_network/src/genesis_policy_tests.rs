//! Regression tests for staged policy discovery and strict final genesis validation.

use super::*;
use crate::config::{self, StagedGenesisPolicyHashes};
use iroha_crypto::{Algorithm, Hash};
use iroha_data_model::account::{AccountId, address::ChainDiscriminantGuard};
use iroha_genesis::GenesisTopologyEntry;
use iroha_model_base::peer::PeerId;
use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;

fn fixture() -> (
    GenesisBlock,
    AccountId,
    Vec<PeerId>,
    KeyPair,
    RawGenesisTransaction,
) {
    fixture_with_instructions(Vec::new())
}

fn fixture_with_instructions(
    instructions: Vec<iroha_data_model::isi::InstructionBox>,
) -> (
    GenesisBlock,
    AccountId,
    Vec<PeerId>,
    KeyPair,
    RawGenesisTransaction,
) {
    crate::init_instruction_registry();
    let mut entries = (0xD0..=0xD3)
        .map(|seed| {
            let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic genesis validator");
            GenesisTopologyEntry::new(
                PeerId::new(key.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("validator PoP"),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.peer.cmp(&right.peer));
    config::build_minimal_genesis_unexecuted_with_post_topology(
        vec![instructions],
        Vec::new(),
        entries.iter().map(|entry| entry.peer.clone()).collect(),
        entries,
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
        config::chain_id(),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(iroha_core::state::default_genesis_confidential_policy_hash()),
    )
}

fn mismatch_report(hashes: StagedGenesisPolicyHashes) -> Report {
    Report::new(Box::new(BlockValidationError::GenesisPolicyMismatch {
        expected_execution: Hash::new(b"provisional execution policy"),
        actual_execution: hashes.execution_policy,
        expected_nexus: Hash::new(b"provisional Nexus policy"),
        actual_nexus: hashes.nexus_amx,
    }))
    .wrap_err("genesis pre-execution failed before transaction results were recorded")
}

#[test]
fn discovery_uses_only_the_retained_typed_policy_mismatch() {
    let hashes = StagedGenesisPolicyHashes {
        execution_policy: Hash::new(b"derived execution"),
        nexus_amx: Hash::new(b"derived Nexus"),
    };
    assert_eq!(
        discover_generated_policy_hashes(Ok(hashes)).unwrap(),
        hashes
    );
    assert_eq!(
        discover_generated_policy_hashes(Err(mismatch_report(hashes))).unwrap(),
        hashes
    );
    let text_only = eyre!(format!("{:#}", mismatch_report(hashes)));
    assert!(discover_generated_policy_hashes(Err(text_only)).is_err());
    let other = Report::new(Box::new(BlockValidationError::ExecutionContextInvalid(
        "invalid original instruction".to_owned(),
    )))
    .wrap_err("native validation failed");
    let error = discover_generated_policy_hashes(Err(other)).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<Box<BlockValidationError>>().map(Box::as_ref),
        Some(BlockValidationError::ExecutionContextInvalid(message))
            if message == "invalid original instruction"
    ));
}

#[test]
fn generated_policy_binding_executes_strictly_and_preserves_original_manifest_inputs() {
    let _profile = ChainDiscriminantGuard::enter(
        iroha_config::parameters::defaults::common::chain_discriminant(),
    );
    let (proposal, account, topology, key, manifest) = fixture();
    assert_eq!(topology.len(), 4);
    let original_manifest = norito::json::to_value(&manifest).unwrap();
    let original_times = proposal
        .0
        .external_transactions()
        .map(|tx| tx.creation_time())
        .collect::<Vec<_>>();
    let original_header = proposal.0.header();
    let original_policies = proposal.0.da_proof_policies().cloned();
    let mut calls = 0;
    let (executed, staged, bound_manifest) =
        execute_generated_genesis(proposal, manifest, &key, true, |candidate| {
            calls += 1;
            config::preexecute_genesis_with_runtime_config(
                candidate, &account, &topology, &key, None, None, None, None,
            )
        })
        .expect("new fixture must bind the actual policies and pass strict native execution");
    assert_eq!(
        calls, 2,
        "provisional policy mismatch requires one strict re-execution"
    );
    assert!(config::genesis_results_are_canonical(&executed.0));
    assert!(config::genesis_signature_is_canonical(&executed.0, &key));
    assert_eq!(
        executed
            .0
            .external_transactions()
            .map(|tx| tx.creation_time())
            .collect::<Vec<_>>(),
        original_times
    );
    assert_eq!(
        executed.0.header().creation_time(),
        original_header.creation_time()
    );
    assert_eq!(
        executed.0.header().confidential_features(),
        original_header.confidential_features()
    );
    assert_eq!(executed.0.da_proof_policies(), original_policies.as_ref());
    let context = bound_manifest.sumeragi_context_parameters();
    assert_eq!(
        Hash::prehashed(context.execution_policy_hash),
        staged.execution_policy
    );
    assert_eq!(
        Hash::prehashed(context.nexus_amx_context_hash),
        staged.nexus_amx
    );
    let parameters = crate::consensus_parameters_from_genesis(&executed);
    let carrier = parameters
        .custom()
        .get(&iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id())
        .expect("one signed policy carrier");
    let metadata: iroha_data_model::parameter::system::ConsensusHandshakeMetadata =
        norito::json::from_str(carrier.payload().get()).unwrap();
    assert_eq!(metadata.sumeragi_context, context);
    let norito::json::Value::Object(mut before) = original_manifest else {
        panic!("original manifest must be an object");
    };
    let norito::json::Value::Object(mut after) = norito::json::to_value(&bound_manifest).unwrap()
    else {
        panic!("bound manifest must be an object");
    };
    for field in ["sumeragi_context", "consensus_fingerprint"] {
        before.remove(field);
        after.remove(field);
    }
    assert_eq!(
        after, before,
        "rebinding must preserve every other manifest field"
    );
    let (_, replayed) = config::preexecute_genesis_with_runtime_config(
        &executed, &account, &topology, &key, None, None, None, None,
    )
    .expect("the complete signed result must independently validate");
    assert_eq!(replayed, staged);
}

#[test]
fn supplied_policy_commitments_are_never_rebound() {
    let _profile = ChainDiscriminantGuard::enter(
        iroha_config::parameters::defaults::common::chain_discriminant(),
    );
    let (proposal, account, topology, key, manifest) = fixture();
    let original = proposal.0.encode_wire().unwrap();
    let mut calls = 0;
    let error = execute_generated_genesis(proposal, manifest, &key, false, |candidate| {
        calls += 1;
        assert_eq!(candidate.0.encode_wire().unwrap(), original);
        config::preexecute_genesis_with_runtime_config(
            candidate, &account, &topology, &key, None, None, None, None,
        )
    })
    .expect_err("explicit signed commitments must be validated without rebinding");
    assert_eq!(calls, 1);
    assert!(policy_mismatch_hashes(&error).is_some());
}

#[test]
fn generated_policy_binding_stops_after_the_second_typed_mismatch() {
    let _profile = ChainDiscriminantGuard::enter(
        iroha_config::parameters::defaults::common::chain_discriminant(),
    );
    let (proposal, _, _, key, manifest) = fixture();
    let hashes = StagedGenesisPolicyHashes {
        execution_policy: Hash::new(b"derived execution"),
        nexus_amx: Hash::new(b"derived Nexus"),
    };
    let mut calls = 0;
    let error = execute_generated_genesis(proposal, manifest, &key, true, |_| {
        calls += 1;
        Err(mismatch_report(hashes))
    })
    .expect_err("a failed strict final execution must never trigger another rewrite");
    assert_eq!(calls, 2);
    assert_eq!(policy_mismatch_hashes(&error), Some(hashes));
}

#[test]
fn strict_genesis_rejection_preserves_actual_output_index_and_cause() {
    use iroha_data_model::{
        Identifiable as _,
        isi::{Register, RegisterBox, error::InstructionExecutionError},
        prelude::Domain,
        transaction::{Executable, error::TransactionRejectionReason},
    };
    let _profile = ChainDiscriminantGuard::enter(
        iroha_config::parameters::defaults::common::chain_discriminant(),
    );
    let domain =
        iroha_model_base::domain::DomainId::try_new("rejected-genesis", "universal").unwrap();
    let (proposal, account, topology, key, _) = fixture_with_instructions(vec![
        Register::domain(Domain::new(domain.clone())).into(),
        Register::domain(Domain::new(domain.clone())).into(),
    ]);
    let expected_index = proposal
        .0
        .external_transactions()
        .position(|transaction| {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                return false;
            };
            instructions.iter().any(|instruction| {
                matches!(
                    instruction.as_any().downcast_ref::<RegisterBox>(),
                    Some(RegisterBox::Domain(register)) if register.object().id() == &domain
                )
            })
        })
        .expect("the signed inputs contain the rejected domain transaction");
    let original_wire = proposal.0.encode_wire().unwrap();
    let before = config::genesis_preexecution_count();
    let report = config::preexecute_genesis_with_runtime_config(
        &proposal, &account, &topology, &key, None, None, None, None,
    )
    .expect_err("a duplicate domain must fail original execution before policy discovery");
    assert_eq!(config::genesis_preexecution_count(), before + 1);
    let error = report
        .downcast_ref::<Box<BlockValidationError>>()
        .expect("the wrapped report retains the original native error");
    let BlockValidationError::InvalidGenesis(
        iroha_core::block::InvalidGenesisError::RejectedOutput(rejection),
    ) = error.as_ref()
    else {
        panic!("lost actual rejection cause: {report:#}");
    };
    assert_eq!(rejection.output_index, expected_index);
    assert!(matches!(
        rejection.reason.as_ref(),
        TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::InstructionFailed(
                InstructionExecutionError::Repetition(_)
            )
        )
    ));
    assert!(
        report
            .chain()
            .any(|cause| cause.is::<TransactionRejectionReason>())
    );
    assert!(
        !proposal.0.has_results(),
        "failed outputs remain unpublished"
    );
    assert_eq!(proposal.0.encode_wire().unwrap(), original_wire);
    assert_startup_retains_rejection_and_rolls_back(&proposal, &account, &domain, rejection);
    assert!(
        discover_generated_policy_hashes(Err(report)).is_err(),
        "a real instruction rejection cannot supply policy-binding authority"
    );
}

/// Exercise the public startup boundary through the dependency's production code.
fn assert_startup_retains_rejection_and_rolls_back(
    proposal: &GenesisBlock,
    account: &AccountId,
    duplicate: &iroha_model_base::domain::DomainId,
    expected: &iroha_core::block::GenesisOutputRejection,
) {
    use iroha_core::{
        block::InvalidGenesisError,
        query::store::LiveQueryStore,
        state::{State, StateReadOnly, World, WorldReadOnly},
        sumeragi::startup::{StartupError, apply_genesis},
    };
    use iroha_data_model::{Registrable as _, account::Account, prelude::Domain};
    use std::error::Error as _;

    let nexus = iroha_config::parameters::actual::Nexus::default();
    let mut world = World::with(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(account)],
        [Account::new(account.clone()).build(account)],
        [],
    );
    iroha_core::sns::seed_genesis_alias_bootstrap(
        &mut world,
        &proposal.0,
        &nexus.dataspace_catalog,
    )
    .expect("authenticated genesis SNS bootstrap");
    let state =
        State::new_with_pre_genesis_nexus_for_testing(world, nexus, LiveQueryStore::start_test());
    config::install_preexec_lane_manifests(&state, None).unwrap();
    let original_wire = proposal.0.encode_wire().unwrap();
    let startup = apply_genesis(
        &state,
        proposal.0.clone(),
        account,
        iroha_data_model::parameter::system::ConsensusMode::Permissioned,
        None,
    )
    .expect_err("startup must retain the actual failed original genesis execution");
    let StartupError::InvalidGenesis(error) = &startup else {
        panic!("startup erased the native validation error: {startup:?}");
    };
    assert!(matches!(
        error.as_ref(),
        BlockValidationError::InvalidGenesis(InvalidGenesisError::RejectedOutput(actual))
            if actual == expected
    ));
    assert!(
        startup
            .source()
            .unwrap()
            .downcast_ref::<Box<BlockValidationError>>()
            .is_some_and(|source| std::ptr::eq(source, error)),
        "the source chain retains the exact boxed native validation error"
    );
    assert_eq!(state.view().height(), 0, "genesis was not published");
    assert!(
        state.world_view().domain(duplicate).is_err(),
        "failed batch rolled back"
    );
    assert_eq!(
        state.view().kura().blocks_count(),
        0,
        "failed genesis was not persisted"
    );
    assert!(
        !proposal.0.has_results(),
        "failed outputs remain unpublished"
    );
    assert_eq!(proposal.0.encode_wire().unwrap(), original_wire);
}
