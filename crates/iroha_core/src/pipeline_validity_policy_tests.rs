//! Tests of the committed execution-limit policy.
//!
//! Field coverage is generated from the policy's own field list. The parity
//! tests execute the same transactions on nodes that differ only in their own
//! pipeline settings: certified results, roots and block wires must be
//! identical, and only a committed policy may change a decision.

use std::{num::NonZeroU64, sync::Arc};

use iroha_config::parameters::actual::{Pipeline, QueryCursorMode};
use iroha_data_model::{
    Level, Registrable as _,
    account::Account,
    block::BlockHeader,
    domain::Domain,
    executor::ExecutorDataModel,
    isi::{InstructionBox, Log, SetParameter},
    parameter::{CustomParameter, Parameter},
    permission::Permission,
};
use iroha_executor_data_model::permission::parameter::CanSetParameters;
use iroha_primitives::json::Json;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, StateReadOnly as _, World, WorldReadOnly as _},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

/// The local resource settings of `pipeline`, for comparison. Exhaustive like
/// [`policy_of`]: every field is either a local resource listed here or a
/// validity value named as ignored.
fn local_resources_of(pipeline: &Pipeline) -> String {
    let Pipeline {
        dynamic_prepass: _,
        access_set_cache_enabled,
        parallel_overlay,
        workers,
        stateless_cache_cap,
        parallel_apply,
        ready_queue_heap,
        gpu_key_bucket,
        debug_trace_scheduler_inputs,
        debug_trace_tx_eval,
        signature_batch_max_ed25519,
        signature_batch_max_secp256k1,
        signature_batch_max_pqc,
        signature_batch_max_bls,
        cache_size,
        ivm_cache_max_decoded_ops,
        ivm_cache_max_bytes,
        ivm_execution_max_bytes,
        ivm_prover_threads,
        overlay_max_instructions: _,
        overlay_max_bytes: _,
        overlay_chunk_instructions: _,
        gas,
        ivm_max_cycles_upper_bound: _,
        ivm_max_decoded_instructions: _,
        ivm_max_decoded_bytes: _,
        quarantine_max_txs_per_block: _,
        quarantine_tx_max_cycles: _,
        query_default_cursor_mode,
        query_max_fetch_size: _,
        query_stored_min_gas_units: _,
        amx_per_dataspace_budget_ms: _,
        amx_group_budget_ms: _,
        amx_per_instruction_ns: _,
        amx_per_memory_access_ns: _,
        amx_per_syscall_ns: _,
    } = pipeline;
    format!(
        "{access_set_cache_enabled} {parallel_overlay} {workers} {stateless_cache_cap} \
         {parallel_apply} {ready_queue_heap} {gpu_key_bucket} {debug_trace_scheduler_inputs} \
         {debug_trace_tx_eval} {signature_batch_max_ed25519} {signature_batch_max_secp256k1} \
         {signature_batch_max_pqc} {signature_batch_max_bls} {cache_size} \
         {ivm_cache_max_decoded_ops} {ivm_cache_max_bytes} {ivm_execution_max_bytes} \
         {ivm_prover_threads} {gas:?} {query_default_cursor_mode:?}"
    )
}

/// Settings whose every local resource differs from `base`.
fn scarce_local_resources(base: &Pipeline) -> Pipeline {
    let mut node = base.clone();
    node.access_set_cache_enabled = !node.access_set_cache_enabled;
    node.debug_trace_tx_eval = !node.debug_trace_tx_eval;
    node.debug_trace_scheduler_inputs = !node.debug_trace_scheduler_inputs;
    node.stateless_cache_cap += 7;
    node.signature_batch_max_ed25519 += 3;
    node.signature_batch_max_secp256k1 += 3;
    node.signature_batch_max_pqc += 3;
    node.signature_batch_max_bls += 3;
    node.cache_size += 5;
    node.ivm_cache_max_decoded_ops += 11;
    node.ivm_cache_max_bytes += 13;
    node.ivm_prover_threads += 1;
    node.query_default_cursor_mode = match node.query_default_cursor_mode {
        QueryCursorMode::Ephemeral => QueryCursorMode::Stored,
        QueryCursorMode::Stored => QueryCursorMode::Ephemeral,
    };
    node
}

/// Settings whose validity values would change decisions if a node could
/// decide them, with scarce local resources.
fn divergent_node_pipeline(base: &Pipeline) -> Pipeline {
    let mut node = scarce_local_resources(base);
    node.dynamic_prepass = !node.dynamic_prepass;
    node.overlay_max_instructions = 1;
    node.overlay_max_bytes = 1;
    node.overlay_chunk_instructions = 1;
    node.ivm_max_cycles_upper_bound = NonZeroU64::new(1).expect("nonzero");
    node.ivm_max_decoded_instructions = 1;
    node.ivm_max_decoded_bytes = 1;
    node.quarantine_max_txs_per_block = 9;
    node.quarantine_tx_max_cycles = 9;
    node.query_max_fetch_size = 1;
    node.query_stored_min_gas_units = 77;
    node.amx_per_dataspace_budget_ms = 1;
    node.amx_group_budget_ms = 1;
    node.amx_per_instruction_ns = 999;
    node.amx_per_memory_access_ns = 999;
    node.amx_per_syscall_ns = 999;
    node
}

fn changed_policy() -> PipelineValidityPolicyV1 {
    let mut policy = PipelineValidityPolicyV1::protocol_default();
    for (index, name) in PipelineValidityPolicyV1::FIELD_NAMES.iter().enumerate() {
        let salt = u32::try_from(index).expect("field count fits") + 1;
        assert!(policy.perturb_field(name, salt), "{name}");
    }
    policy
}

/// A committed policy that differs from the protocol default in limits the
/// chain tests exercise.
fn committed_policy() -> PipelineValidityPolicyV1 {
    let mut policy = PipelineValidityPolicyV1::protocol_default();
    policy.overlay_max_instructions = 2;
    policy.ivm_max_cycles_upper_bound = 4_321;
    policy.query_max_fetch_size = 55;
    policy
}

fn parameters_with(policy: &PipelineValidityPolicyV1) -> Parameters {
    let mut parameters = Parameters::default();
    parameters.set_parameter(Parameter::Custom(policy.into_custom_parameter()));
    parameters
}

fn state_with(policy: Option<&PipelineValidityPolicyV1>) -> State {
    let world = World::default();
    if let Some(policy) = policy {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(policy.into_custom_parameter()));
        block.commit();
    }
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn header(height: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("nonzero height"),
        None,
        None,
        0,
        0,
    )
}

#[test]
fn protocol_default_is_the_default_of_the_settings_value() {
    // One default: the data-model protocol default and the default of the
    // State-owned settings value never drift apart.
    assert_eq!(
        policy_of(&Pipeline::default()),
        PipelineValidityPolicyV1::protocol_default()
    );
    assert!(node_validity_overrides(&Pipeline::default()).is_empty());
    assert_eq!(count(7), 7);
    assert_eq!(size(7, "field"), Ok(7));
}

#[test]
fn every_policy_field_reaches_the_settings_and_the_execution_policy_digest() {
    let default = PipelineValidityPolicyV1::protocol_default();
    let default_digest = state_with(None)
        .execution_policy_digest_v1()
        .expect("execution policy digest");
    let mut seen = std::collections::BTreeSet::from([default_digest]);
    assert_eq!(PipelineValidityPolicyV1::FIELD_NAMES.len(), 16);
    for (index, name) in PipelineValidityPolicyV1::FIELD_NAMES.iter().enumerate() {
        let salt = u32::try_from(index).expect("field count fits") + 1;
        let mut policy = default;
        assert!(policy.perturb_field(name, salt), "{name}");
        // The value reaches the settings and is read back unchanged, so the
        // field is neither dropped nor wired to another one.
        let mut pipeline = Pipeline::default();
        apply_policy(&policy, &mut pipeline).expect("a valid policy applies");
        assert_eq!(policy_of(&pipeline), policy, "{name}");
        // A node that holds the value reports it and does not install it.
        assert_eq!(node_validity_overrides(&pipeline), [*name]);
        let installed = node_local_resources(pipeline);
        assert!(node_validity_overrides(&installed).is_empty(), "{name}");
        // The committed value overrides whatever a node installed.
        let effective = effective_pipeline(
            divergent_node_pipeline(&Pipeline::default()),
            &parameters_with(&policy),
        );
        assert_eq!(policy_of(&effective), policy, "{name}");
        // It is part of the execution-policy identity of a State that commits it.
        let digest = state_with(Some(&policy))
            .execution_policy_digest_v1()
            .expect("execution policy digest");
        assert!(seen.insert(digest), "{name} moves the digest uniquely");
    }
}

#[test]
fn local_resources_survive_and_validity_values_are_stripped_from_a_node() {
    let default = Pipeline::default();
    let scarce = scarce_local_resources(&default);
    assert_ne!(local_resources_of(&scarce), local_resources_of(&default));
    assert!(node_validity_overrides(&scarce).is_empty());
    // A committed policy keeps the node's local resources.
    let all_changed = changed_policy();
    assert_eq!(
        all_changed
            .differing_fields(&PipelineValidityPolicyV1::protocol_default())
            .len(),
        16
    );
    let mut node = scarce.clone();
    apply_policy(&all_changed, &mut node).expect("valid policy");
    assert_eq!(local_resources_of(&node), local_resources_of(&scarce));
    assert_eq!(policy_of(&node), all_changed);
    assert_eq!(node_validity_overrides(&node).len(), 16);
    // Installing a node strips every validity value and keeps the resources.
    let installed = node_local_resources(node);
    assert_eq!(local_resources_of(&installed), local_resources_of(&scarce));
    assert_eq!(
        policy_of(&installed),
        PipelineValidityPolicyV1::protocol_default()
    );
    let effective = effective_pipeline(installed, &parameters_with(&all_changed));
    assert_eq!(local_resources_of(&effective), local_resources_of(&scarce));
    assert_eq!(policy_of(&effective), all_changed);
}

#[test]
fn effective_pipeline_reads_the_committed_policy() {
    let policy = changed_policy();
    assert_eq!(committed(&Parameters::default()), Ok(None));
    let parameters = parameters_with(&policy);
    assert_eq!(committed(&parameters), Ok(Some(policy)));
    // Two nodes with different installed settings read the same policy.
    let first = effective_pipeline(Pipeline::default(), &parameters);
    let second = effective_pipeline(divergent_node_pipeline(&Pipeline::default()), &parameters);
    assert_eq!(policy_of(&first), policy);
    assert_eq!(policy_of(&second), policy);
    // A different committed payload is decoded afresh, not served from the memo.
    let other = committed_policy();
    assert_eq!(
        policy_of(&effective_pipeline(
            Pipeline::default(),
            &parameters_with(&other)
        )),
        other
    );
    assert_eq!(
        policy_of(&effective_pipeline(Pipeline::default(), &parameters)),
        policy
    );
    // Without a committed policy the installed value is returned as is.
    assert_eq!(
        policy_of(&effective_pipeline(
            Pipeline::default(),
            &Parameters::default()
        )),
        PipelineValidityPolicyV1::protocol_default()
    );
    // A payload no valid transition commits leaves the installed value and is
    // reported by `committed`.
    let mut malformed = Parameters::default();
    malformed.set_parameter(Parameter::Custom(CustomParameter::new(
        PipelineValidityPolicyV1::parameter_id(),
        Json::new("not a policy"),
    )));
    assert!(matches!(
        committed(&malformed),
        Err(PipelineValidityPolicyError::Malformed(_))
    ));
    assert_eq!(
        policy_of(&effective_pipeline(Pipeline::default(), &malformed)),
        PipelineValidityPolicyV1::protocol_default()
    );
}

#[test]
fn set_parameter_validation_uses_the_instruction_bytes_only() {
    let other = CustomParameter::new(
        "another_parameter".parse().expect("valid name"),
        Json::new(1_u32),
    );
    assert_eq!(validate_set_parameter(&other), Ok(false));
    assert_eq!(
        validate_set_parameter(&changed_policy().into_custom_parameter()),
        Ok(true)
    );
    let not_a_policy = CustomParameter::new(
        PipelineValidityPolicyV1::parameter_id(),
        Json::new("not a policy"),
    );
    assert!(matches!(
        validate_set_parameter(&not_a_policy),
        Err(PipelineValidityPolicyError::Malformed(_))
    ));
    let mut zero = PipelineValidityPolicyV1::protocol_default();
    zero.ivm_max_cycles_upper_bound = 0;
    assert_eq!(
        validate_set_parameter(&zero.into_custom_parameter()),
        Err(PipelineValidityPolicyError::Zero(
            "ivm_max_cycles_upper_bound"
        ))
    );
}

#[test]
fn a_failed_application_leaves_the_settings_untouched() {
    let mut untouched = scarce_local_resources(&Pipeline::default());
    let before = format!("{untouched:?}");
    let mut invalid = changed_policy();
    invalid.overlay_chunk_instructions = 0;
    assert_eq!(
        apply_policy(&invalid, &mut untouched),
        Err(PipelineValidityPolicyError::Zero(
            "overlay_chunk_instructions"
        ))
    );
    assert_eq!(format!("{untouched:?}"), before);
}

#[test]
fn install_node_pipeline_keeps_local_resources_and_ignores_validity_values() {
    let mut state = state_with(None);
    let base = state.installed_pipeline().clone();
    let node = divergent_node_pipeline(&base);
    let ignored = state
        .install_node_pipeline(node.clone())
        .expect("node pipeline resources install");
    assert_eq!(ignored.len(), 16, "every validity value is reported");
    assert_eq!(
        local_resources_of(&state.installed_pipeline()),
        local_resources_of(&node)
    );
    assert_eq!(
        policy_of(&state.pipeline_snapshot()),
        PipelineValidityPolicyV1::protocol_default()
    );
    assert_eq!(
        state.ivm_admission_cycle_limit().get(),
        PipelineValidityPolicyV1::protocol_default()
            .ivm_max_cycles_upper_bound
            .min(
                state
                    .view()
                    .world()
                    .parameters()
                    .smart_contract()
                    .fuel()
                    .get()
            )
    );
    // The stateless cache follows the node's own setting.
    assert_eq!(
        state.installed_pipeline().stateless_cache_cap,
        node.stateless_cache_cap
    );
    // A node that holds only local resources ignores nothing.
    assert!(
        state
            .install_node_pipeline(scarce_local_resources(&base))
            .expect("install")
            .is_empty()
    );
}

#[test]
fn committed_policy_decides_every_view_and_block_under_divergent_node_configuration() {
    let policy = committed_policy();
    let default_node = state_with(Some(&policy));
    let mut divergent_node = state_with(Some(&policy));
    let node = divergent_node_pipeline(&divergent_node.installed_pipeline().clone());
    divergent_node
        .install_node_pipeline(node)
        .expect("node pipeline resources install");
    for state in [&default_node, &divergent_node] {
        assert_eq!(policy_of(state.view().pipeline()), policy);
        assert_eq!(policy_of(&state.query_view().pipeline), policy);
        assert_eq!(policy_of(&state.pipeline_snapshot()), policy);
        let block = state.block(header(2));
        assert_eq!(policy_of(&block.pipeline), policy);
        // A State and the blocks built on it report one execution-policy identity.
        assert_eq!(
            block
                .execution_policy_digest_v1()
                .expect("execution policy digest"),
            state
                .execution_policy_digest_v1()
                .expect("execution policy digest")
        );
        drop(block);
        assert_eq!(
            state.ivm_admission_cycle_limit().get(),
            policy.ivm_max_cycles_upper_bound.min(
                state
                    .view()
                    .world()
                    .parameters()
                    .smart_contract()
                    .fuel()
                    .get()
            )
        );
    }
    assert_eq!(
        default_node
            .execution_policy_digest_v1()
            .expect("execution policy digest"),
        divergent_node
            .execution_policy_digest_v1()
            .expect("execution policy digest")
    );
    // The committed policy is visible in the identity: a chain without it differs.
    assert_ne!(
        state_with(None)
            .execution_policy_digest_v1()
            .expect("execution policy digest"),
        default_node
            .execution_policy_digest_v1()
            .expect("execution policy digest")
    );
}

#[test]
fn install_node_pipeline_refuses_a_malformed_committed_policy() {
    let world = World::default();
    {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(CustomParameter::new(
                PipelineValidityPolicyV1::parameter_id(),
                Json::new("not a policy"),
            )));
        block.commit();
    }
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let before = format!("{:?}", state.installed_pipeline());
    assert!(matches!(
        state.install_node_pipeline(divergent_node_pipeline(&Pipeline::default())),
        Err(PipelineValidityPolicyError::Malformed(_))
    ));
    assert_eq!(
        format!("{:?}", state.installed_pipeline()),
        before,
        "nothing is installed"
    );
}

#[test]
fn set_parameter_installs_the_policy_and_rejects_invalid_payloads() {
    let set = |policy: PipelineValidityPolicyV1| {
        SetParameter::new(Parameter::Custom(policy.into_custom_parameter()))
    };
    let mut zero = committed_policy();
    zero.overlay_chunk_instructions = 0;
    let mut outcomes = Vec::new();
    for divergent in [false, true] {
        let mut state = state_with(None);
        if divergent {
            let node = divergent_node_pipeline(&state.installed_pipeline().clone());
            state.install_node_pipeline(node).expect("install");
        }
        let mut observed = Vec::new();
        // The policy is an ordinary parameter: genesis and later blocks both set it.
        for height in [1, 2] {
            let mut block = state.block(header(height));
            let mut transaction = block.transaction();
            let malformed = SetParameter::new(Parameter::Custom(CustomParameter::new(
                PipelineValidityPolicyV1::parameter_id(),
                Json::new("not a policy"),
            )))
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("a malformed policy payload is rejected");
            observed.push(format!("{malformed:?}"));
            let structural = set(zero)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("a structurally invalid policy is rejected");
            observed.push(format!("{structural:?}"));
            assert_eq!(
                committed(transaction.world.parameters.get()),
                Ok(None),
                "a rejected policy leaves State unchanged"
            );
            set(committed_policy())
                .execute(&ALICE_ID, &mut transaction)
                .expect("a valid policy is installed");
            assert_eq!(
                committed(transaction.world.parameters.get()),
                Ok(Some(committed_policy()))
            );
            // The block that commits a policy still runs under the one frozen
            // at its construction.
            assert_eq!(
                policy_of(&transaction.pipeline),
                PipelineValidityPolicyV1::protocol_default()
            );
        }
        outcomes.push(observed);
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert!(
        outcomes[0][0].contains("not a canonical V1 policy"),
        "{outcomes:?}"
    );
    assert!(
        outcomes[0][1].contains("overlay_chunk_instructions"),
        "{outcomes:?}"
    );
}

#[test]
fn executor_reconciliation_cannot_replace_or_remove_the_committed_policy() {
    let installed = committed_policy();
    let mut attacker_value = PipelineValidityPolicyV1::protocol_default();
    attacker_value.ivm_max_cycles_upper_bound = u64::MAX;
    for attacker in [
        attacker_value.into_custom_parameter(),
        CustomParameter::new(
            PipelineValidityPolicyV1::parameter_id(),
            Json::new("not a policy"),
        ),
    ] {
        let state = state_with(Some(&installed));
        let mut block = state.block(header(2));
        let mut transaction = block.transaction();
        let mut declares = ExecutorDataModel::default();
        declares
            .parameters
            .insert(PipelineValidityPolicyV1::parameter_id(), attacker);
        transaction.world.apply_executor_data_model(declares);
        assert_eq!(
            committed(transaction.world.parameters.get()),
            Ok(Some(installed)),
            "an executor data model cannot overwrite the committed policy"
        );
        assert!(
            transaction
                .world
                .executor_data_model
                .get()
                .parameters()
                .get(&PipelineValidityPolicyV1::parameter_id())
                .is_none(),
            "executor-owned schemas must not acquire the consensus-owned parameter"
        );
        transaction
            .world
            .apply_executor_data_model(ExecutorDataModel::default());
        assert_eq!(
            committed(transaction.world.parameters.get()),
            Ok(Some(installed)),
            "an executor data model cannot remove the committed policy"
        );
    }
    // A chain without the policy does not acquire one from an executor either.
    let state = state_with(None);
    let mut block = state.block(header(2));
    let mut transaction = block.transaction();
    let mut declares = ExecutorDataModel::default();
    declares.parameters.insert(
        PipelineValidityPolicyV1::parameter_id(),
        committed_policy().into_custom_parameter(),
    );
    transaction.world.apply_executor_data_model(declares);
    assert_eq!(committed(transaction.world.parameters.get()), Ok(None));
    assert!(
        crate::state::consensus_owned_custom_parameter_ids()
            .contains(&PipelineValidityPolicyV1::parameter_id())
    );
}

fn alice_world(permissions: impl IntoIterator<Item = Permission>) -> World {
    let domain_id = iroha_model_base::domain::DomainId::try_new("wonderland", "universal")
        .expect("valid domain");
    let domain = Domain::new(domain_id).build(&ALICE_ID);
    let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
    let mut world = World::with([domain], [alice, bob], []);
    world
        .account_permissions
        .insert(ALICE_ID.clone(), permissions.into_iter().collect());
    world
}

fn alice_chain(
    divergent_node: bool,
    policy: Option<&PipelineValidityPolicyV1>,
) -> CertifiedTestChain {
    let mut config = TestChainConfig::new(alice_world([Permission::from(CanSetParameters)]), 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    if let Some(policy) = policy {
        config
            .genesis_parameters
            .push(Parameter::Custom(policy.into_custom_parameter()));
    }
    let mut prepared = CertifiedTestChain::prepare(config).expect("fixture genesis is prepared");
    if divergent_node {
        // As a node does before it applies genesis: local resources only.
        let state = Arc::get_mut(&mut prepared.state).expect("the unapplied State has one owner");
        let node = divergent_node_pipeline(&state.installed_pipeline().clone());
        let ignored = state
            .install_node_pipeline(node)
            .expect("node pipeline resources install");
        assert!(!ignored.is_empty());
    }
    CertifiedTestChain::from_prepared(prepared).expect("genesis applies")
}

/// What consensus certifies for every committed height.
fn certified_history(chain: &CertifiedTestChain) -> Vec<(Vec<u8>, Vec<u8>, String, Vec<u8>)> {
    (1..=chain.height())
        .map(|height| {
            let committed = chain.committed(height);
            (
                committed.result().0.to_vec(),
                committed.core_hash().0.to_vec(),
                format!("{:?}", committed.commitment()),
                committed
                    .block()
                    .encode_wire()
                    .expect("committed block encodes"),
            )
        })
        .collect()
}

fn logs(count: usize) -> Vec<InstructionBox> {
    (0..count)
        .map(|index| Log::new(Level::INFO, format!("limit-{index}")).into())
        .collect()
}

#[test]
fn authorized_change_governs_the_next_block_identically_on_every_node() {
    // The committed overlay limit is two instructions. A transaction of
    // exactly two is accepted and one of three is rejected, on a node with
    // default settings and on one whose own settings name a limit of one.
    let policy = committed_policy();
    let set: InstructionBox =
        SetParameter::new(Parameter::Custom(policy.into_custom_parameter())).into();
    let mut histories = Vec::new();
    for divergent in [false, true] {
        let mut chain = alice_chain(divergent, None);
        // An account without the parameter permission cannot install the policy.
        let unauthorized = chain.sign(&BOB_KEYPAIR, [set.clone()], 1);
        assert_eq!(chain.commit(vec![unauthorized]), vec![false]);
        // Before the change three instructions fit: the default is unlimited
        // and the divergent node's own limit of one does not apply.
        let before = chain.sign(&ALICE_KEYPAIR, logs(3), 1_001);
        assert_eq!(chain.commit(vec![before]), vec![true]);
        // The authorized change commits in block N together with a
        // three-instruction transaction: block N still runs under the old policy.
        let change = chain.sign(&ALICE_KEYPAIR, [set.clone()], 2_001);
        let same_block = chain.sign(&ALICE_KEYPAIR, logs(3), 2_002);
        assert_eq!(chain.commit(vec![change, same_block]), vec![true, true]);
        assert_eq!(policy_of(chain.state().view().pipeline()), policy);
        // Block N + 1: exactly the committed limit is accepted, one more is rejected.
        let at_limit = chain.sign(&ALICE_KEYPAIR, logs(2), 3_001);
        let over_limit = chain.sign(&ALICE_KEYPAIR, logs(3), 3_002);
        assert_eq!(chain.commit(vec![at_limit, over_limit]), vec![true, false]);
        let rejection = format!(
            "{:?}",
            chain.committed(chain.height()).block().output_error(1)
        );
        histories.push((certified_history(&chain), rejection));
    }
    assert_eq!(histories[0], histories[1]);
    // A chain whose genesis commits the policy enforces it from block two on
    // both nodes as well.
    let mut from_genesis = Vec::new();
    for divergent in [false, true] {
        let mut chain = alice_chain(divergent, Some(&policy));
        let at_limit = chain.sign(&ALICE_KEYPAIR, logs(2), 1);
        let over_limit = chain.sign(&ALICE_KEYPAIR, logs(3), 2);
        assert_eq!(chain.commit(vec![at_limit, over_limit]), vec![true, false]);
        from_genesis.push(certified_history(&chain));
    }
    assert_eq!(from_genesis[0], from_genesis[1]);
}

/// An IVM program of `syscalls` system calls and `loads` 64-bit loads, then `HALT`.
fn amx_program(syscalls: usize, loads: usize) -> Vec<u8> {
    use ivm::{encoding::wide as encode, instruction::wide};
    let mut program = ivm::ProgramMetadata::default_for(1, 1, 1).encode();
    for _ in 0..syscalls {
        program.extend_from_slice(&encode::encode_sys(wide::system::SCALL, 0).to_le_bytes());
    }
    for _ in 0..loads {
        program
            .extend_from_slice(&encode::encode_load(wide::memory::LOAD64, 5, 6, 0).to_le_bytes());
    }
    program.extend_from_slice(&encode::encode_halt().to_le_bytes());
    program
}

// TODO: drive the same boundary through the host's `AXT_COMMIT` syscall. This test
// runs the budget check the host calls (`ivm::analysis::enforce_amx_budget`) with the
// limits a block freezes from the committed policy; an AXT group fixture that reaches
// the syscall with a chosen analysis does not exist yet.
#[test]
fn amx_budgets_accept_exactly_the_committed_budget_and_reject_one_unit_above() {
    use std::num::NonZeroUsize;

    use ivm::analysis::{AmxBudgetError, analyze_program, enforce_amx_budget};

    use crate::smartcontracts::ivm::host::CoreHost;

    // A real program fixes the memory-access and syscall counts; the instruction
    // count is then chosen so the modelled cost is exactly one millisecond.
    let mut analysis = analyze_program(&amx_program(3, 5)).expect("the program analyses");
    let loads = analysis.memory.load64;
    let syscalls: u64 = analysis.syscalls.iter().map(|usage| usage.count).sum();
    assert_eq!((loads, syscalls), (5, 3));
    let mut policy = PipelineValidityPolicyV1::protocol_default();
    policy.amx_per_dataspace_budget_ms = 1;
    policy.amx_group_budget_ms = 3;
    policy.amx_per_instruction_ns = 6;
    policy.amx_per_memory_access_ns = 11;
    policy.amx_per_syscall_ns = 13;
    let budget_ns = 1_000_000_u64;
    let fixed = loads * 11 + syscalls * 13;
    assert_eq!((budget_ns - fixed) % 6, 0, "the instruction count is exact");
    let instructions = (budget_ns - fixed) / 6;
    analysis.instruction_count = usize::try_from(instructions).expect("fits usize");
    let one = NonZeroUsize::new(1).expect("nonzero");
    let three = NonZeroUsize::new(3).expect("nonzero");
    let four = NonZeroUsize::new(4).expect("nonzero");

    let default_node = Pipeline::default();
    for node in [None, Some(divergent_node_pipeline(&default_node))] {
        // The limits the host of a block enforces come from the committed policy.
        let limits_of = |policy: &PipelineValidityPolicyV1| {
            let mut state = state_with(Some(policy));
            if let Some(node) = node.clone() {
                state
                    .install_node_pipeline(node)
                    .expect("node pipeline resources install");
            }
            let block = state.block(header(2));
            CoreHost::amx_limits_from_config(&block.pipeline)
        };
        let limits = limits_of(&policy);
        assert_eq!(limits.per_dataspace_budget_ms, 1);
        assert_eq!(limits.group_budget_ms, 3);
        assert_eq!(
            (
                limits.per_instruction_ns,
                limits.per_memory_access_ns,
                limits.per_syscall_ns
            ),
            (6, 11, 13)
        );

        // Per-dataspace budget: exactly the budget is accepted, one more
        // instruction is refused.
        let cost = enforce_amx_budget(&analysis, one, &limits).expect("exactly the budget");
        assert_eq!(cost.estimated_ns_per_dataspace, budget_ns);
        let mut over = analysis.clone();
        over.instruction_count += 1;
        assert_eq!(
            enforce_amx_budget(&over, one, &limits),
            Err(AmxBudgetError::PerDataspaceBudgetExceeded {
                estimated_ns: budget_ns + 6,
                limit_ns: budget_ns,
            })
        );

        // Group budget: three dataspaces cost exactly three milliseconds; a
        // fourth dataspace, or a committed group budget one millisecond lower,
        // is refused.
        let cost = enforce_amx_budget(&analysis, three, &limits).expect("exactly the group budget");
        assert_eq!(cost.estimated_group_ns, 3 * budget_ns);
        assert_eq!(
            enforce_amx_budget(&analysis, four, &limits),
            Err(AmxBudgetError::GroupBudgetExceeded {
                estimated_ns: 4 * budget_ns,
                limit_ns: 3 * budget_ns,
            })
        );
        let mut lower_group = policy;
        lower_group.amx_group_budget_ms = 2;
        assert_eq!(
            enforce_amx_budget(&analysis, three, &limits_of(&lower_group)),
            Err(AmxBudgetError::GroupBudgetExceeded {
                estimated_ns: 3 * budget_ns,
                limit_ns: 2 * budget_ns,
            })
        );
        let mut lower_dataspace = policy;
        lower_dataspace.amx_per_dataspace_budget_ms = 0;
        assert!(matches!(
            enforce_amx_budget(&analysis, one, &limits_of(&lower_dataspace)),
            Err(AmxBudgetError::PerDataspaceBudgetExceeded { limit_ns: 0, .. })
        ));

        // Each unit cost: one nanosecond more per instruction, per memory
        // access or per syscall moves the same program over the budget by
        // exactly its count of that unit.
        type Edit = fn(&mut PipelineValidityPolicyV1);
        let unit_costs: [(Edit, u64); 3] = [
            (|policy| policy.amx_per_instruction_ns += 1, instructions),
            (|policy| policy.amx_per_memory_access_ns += 1, loads),
            (|policy| policy.amx_per_syscall_ns += 1, syscalls),
        ];
        for (edit, count) in unit_costs {
            let mut dearer = policy;
            edit(&mut dearer);
            assert_eq!(
                enforce_amx_budget(&analysis, one, &limits_of(&dearer)),
                Err(AmxBudgetError::PerDataspaceBudgetExceeded {
                    estimated_ns: budget_ns + count,
                    limit_ns: budget_ns,
                })
            );
        }
    }
}

#[test]
fn installed_settings_are_read_through_accessors_and_edited_through_the_installers() {
    let mut state = state_with(Some(&committed_policy()));
    // The accessor borrows the installed value: the committed policy is not in it.
    let installed = state.installed_pipeline().clone();
    assert!(node_validity_overrides(&installed).is_empty());
    assert_ne!(
        policy_of(&state.pipeline_snapshot()),
        policy_of(&installed),
        "validation reads the committed policy, not the installed value"
    );
    // A fixture edit goes through the installer, which stores the value.
    state.edit_pipeline_for_testing(|pipeline| {
        pipeline.stateless_cache_cap = 7;
        pipeline.workers = 3;
    });
    assert_eq!(state.installed_pipeline().stateless_cache_cap, 7);
    assert_eq!(state.installed_pipeline().workers, 3);
    assert_eq!(state.pipeline_snapshot().workers, 3);
    // The committed policy still decides every view and block.
    assert_eq!(policy_of(&state.view().pipeline), committed_policy());

    // The ZK settings follow the same rule.
    let default_gas = state.installed_zk().gas.proof_base;
    state
        .edit_zk_for_testing(|zk| zk.verify_timeout = std::time::Duration::from_millis(9))
        .expect("a fixture ZK edit installs");
    assert_eq!(
        state.installed_zk().verify_timeout,
        std::time::Duration::from_millis(9)
    );
    assert_eq!(state.installed_zk().gas.proof_base, default_gas);
    assert_eq!(
        state.zk_snapshot().verify_timeout,
        std::time::Duration::from_millis(9),
        "a local resource of the installed value reaches the snapshot"
    );
}
