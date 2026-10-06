//! Parity and negative tests of the committed ZK validity policy.
//!
//! The same transactions are executed by nodes that differ only in their own
//! ZK settings. Certified results, World roots, events, executed block wires
//! (every transaction result), proof records and the verification gas charged
//! must be identical; only a committed policy may change them.

use std::{collections::BTreeSet, num::NonZeroU64, sync::Arc};

use iroha_config::parameters::actual::Zk;
use iroha_data_model::{
    Registrable as _,
    account::Account,
    block::BlockHeader,
    confidential::ConfidentialStatus,
    domain::Domain,
    executor::ExecutorDataModel,
    isi::{InstructionBox, SetParameter, verifying_keys::RegisterVerifyingKey, zk::VerifyProof},
    parameter::{CustomParameter, Parameter},
    permission::Permission,
    proof::{ProofAttachment, ProofBox, ProofId, ProofStatus, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use iroha_executor_data_model::permission::{
    governance::{CanManageVerifyingKeys, CanSubmitGovernanceBallot},
    parameter::CanSetParameters,
};
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};
use mv::storage::StorageReadOnly as _;

use super::{
    ZkValidityPolicyV1, committed, node_local_resources, node_validity_overrides, policy_of,
};
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{
        State, World, WorldReadOnly as _, compute_zk_consensus_policy_hash, default_zk_config,
    },
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

/// The five rates of a verification gas schedule, for comparison.
fn rates(gas: &iroha_config::parameters::actual::ConfidentialGas) -> [u64; 5] {
    [
        gas.proof_base,
        gas.per_public_input,
        gas.per_proof_byte,
        gas.per_nullifier,
        gas.per_commitment,
    ]
}

/// The verification gas schedule the next block of `state` freezes and charges.
fn next_block_gas(state: &State) -> iroha_config::parameters::actual::ConfidentialGas {
    state.block(next_header(state)).zk.gas
}

/// Settings whose every kind of value differs from the default: validity
/// values a node must not decide, and local resources it may.
fn divergent_node_zk() -> Zk {
    let mut node = default_zk_config();
    node.halo2.enabled = false;
    node.halo2.max_k = 5;
    node.halo2.max_proof_bytes = 17;
    node.stark.enabled = false;
    node.stark.max_proof_bytes = 19;
    node.sccp.max_proofs_per_block = core::num::NonZeroU32::new(1).expect("nonzero");
    node.ballot_history_cap = 1;
    node.preverify_max_bytes = 1;
    node.preverify_budget_bytes = 1;
    node.bridge_proof_max_past_age_blocks = 3;
    node.bridge_proof_max_future_drift_blocks = 4;
    node.max_proof_size_bytes = 1;
    node.max_nullifiers_per_tx = 1;
    node.max_commitments_per_tx = 1;
    node.max_anchor_age_blocks = 2;
    node.max_verify_calls_per_tx = 1;
    node.max_verify_calls_per_block = 1;
    node.max_confidential_ops_per_block = 1;
    node.max_proof_bytes_block = 1;
    node.policy_transition_delay_blocks = 9;
    node.gas.proof_base = 1;
    node.gas.per_proof_byte = 1_000;
    node.kaigi_authorization_vk = Some(iroha_config::parameters::actual::VerifyingKeyRef {
        backend: "halo2/ipa".to_owned(),
        name: "node-local-kaigi".to_owned(),
    });
    // Local resources: scarce on purpose.
    node.halo2.verifier_worker_threads = 1;
    node.halo2.verifier_queue_cap = 1;
    node.halo2.verifier_budget_ms = 1;
    node.halo2.verifier_enqueue_wait_ms = 1;
    node.verify_timeout = core::time::Duration::from_nanos(1);
    node
}

/// A committed policy that differs from the protocol default in limits,
/// windows and the verification gas schedule. The schedule is State-owned and
/// frozen per block, so chains with different schedules run side by side in
/// one process.
fn committed_policy() -> ZkValidityPolicyV1 {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.confidential.max_proof_size_bytes = 2;
    policy.confidential.max_anchor_age_blocks = 4_321;
    policy.proofs.bridge_proof_max_past_age_blocks = 55;
    policy.gas.per_proof_byte += 7;
    policy.gas.proof_base += 11;
    policy
}

fn install_node(prepared: &mut crate::sumeragi::test_chain::PreparedTestChainConfig, node: Zk) {
    // As a node does before it applies genesis: local resources only.
    let ignored = Arc::get_mut(&mut prepared.state)
        .expect("the unapplied State has one owner")
        .install_node_zk(node)
        .expect("node ZK resources install");
    assert!(
        !ignored.is_empty(),
        "the settings hold validity values and they are reported as ignored"
    );
}

fn chain(node: Option<Zk>, policy: Option<ZkValidityPolicyV1>) -> CertifiedTestChain {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    if let Some(policy) = policy {
        config
            .genesis_parameters
            .push(Parameter::Custom(policy.into_custom_parameter()));
    }
    let mut prepared = CertifiedTestChain::prepare(config).expect("fixture genesis is prepared");
    if let Some(node) = node {
        install_node(&mut prepared, node);
    }
    CertifiedTestChain::from_prepared(prepared).expect("genesis applies")
}

/// What consensus certifies for every committed height: the result `R`, the
/// core block hash, the complete execution commitment and the canonical
/// result-bearing block wire.
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

/// Commit two blocks of ordinary work (the fixture's own signed `Log`
/// transactions) and return the certified history.
fn ordinary_history(chain: &mut CertifiedTestChain) -> Vec<(Vec<u8>, Vec<u8>, String, Vec<u8>)> {
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    certified_history(chain)
}

#[test]
fn node_local_zk_configuration_cannot_change_roots_effects_or_gas() {
    let mut reference = chain(None, None);
    let reference_history = ordinary_history(&mut reference);
    let reference_zk = reference.state().view().zk.clone();

    let mut divergent = chain(Some(divergent_node_zk()), None);
    let divergent_history = ordinary_history(&mut divergent);
    let divergent_zk = divergent.state().view().zk.clone();

    // Certified result, core hash, complete execution commitment (World roots,
    // event commitment, executed block wire hash) and the block wire itself,
    // which carries every transaction result and the confidential feature digest.
    assert_eq!(reference_history, divergent_history);
    assert_eq!(reference.height(), 3);
    // Verification gas is the consensus schedule on both nodes: the divergent
    // node held a different one (base 1, 1000 per byte) and its blocks do not
    // charge it.
    assert_eq!(rates(&reference_zk.gas), rates(&crate::gas::DEFAULT_ZK_GAS));
    assert_eq!(rates(&divergent_zk.gas), rates(&crate::gas::DEFAULT_ZK_GAS));
    assert_eq!(
        rates(&next_block_gas(divergent.state())),
        rates(&crate::gas::DEFAULT_ZK_GAS)
    );
    // The validity view is identical; the scarce local resources are kept.
    assert_eq!(
        compute_zk_consensus_policy_hash(&reference_zk),
        compute_zk_consensus_policy_hash(&divergent_zk)
    );
    assert!(node_validity_overrides(&divergent_zk).is_empty());
    assert_eq!(divergent_zk.halo2.verifier_worker_threads, 1);
    assert_eq!(divergent_zk.halo2.verifier_queue_cap, 1);
    assert_eq!(
        divergent_zk.verify_timeout,
        core::time::Duration::from_nanos(1)
    );
    // The execution-policy identity a State reports is the one its blocks
    // freeze, for both nodes.
    assert_eq!(
        reference
            .state()
            .execution_policy_digest_v1()
            .expect("execution policy digest"),
        divergent
            .state()
            .execution_policy_digest_v1()
            .expect("execution policy digest")
    );
}

#[test]
fn committed_policy_decides_validity_identically_under_different_node_configuration() {
    let policy = committed_policy();
    let mut first = chain(None, Some(policy.clone()));
    let first_history = ordinary_history(&mut first);
    let mut second = chain(Some(divergent_node_zk()), Some(policy.clone()));
    let second_history = ordinary_history(&mut second);

    // Same committed policy, different node settings: identical history.
    assert_eq!(first_history, second_history);
    for chain in [&first, &second] {
        let view = chain.state().view();
        assert_eq!(policy_of(&view.zk), policy);
        assert_eq!(policy_of(&chain.state().zk_snapshot()), policy);
        assert_eq!(policy_of(&chain.state().query_view().zk), policy);
        // A State and the blocks built on it report one execution-policy identity.
        drop(view);
        let block = chain.state().block(next_header(chain.state()));
        assert_eq!(policy_of(&block.zk), policy);
        assert_eq!(
            block
                .execution_policy_digest_v1()
                .expect("execution policy digest"),
            chain
                .state()
                .execution_policy_digest_v1()
                .expect("execution policy digest")
        );
    }
    assert_eq!(
        first
            .state()
            .execution_policy_digest_v1()
            .expect("execution policy digest"),
        second
            .state()
            .execution_policy_digest_v1()
            .expect("execution policy digest")
    );
    // The divergent node held another gas schedule; the committed one is what
    // the blocks of both nodes freeze and charge, while a chain without the
    // policy keeps the protocol default in the same process.
    let committed_rates = [
        policy.gas.proof_base,
        policy.gas.per_public_input,
        policy.gas.per_proof_byte,
        policy.gas.per_nullifier,
        policy.gas.per_commitment,
    ];
    assert_eq!(rates(&next_block_gas(first.state())), committed_rates);
    assert_eq!(rates(&next_block_gas(second.state())), committed_rates);
    assert_ne!(committed_rates, rates(&crate::gas::DEFAULT_ZK_GAS));

    // The comparison is sensitive: a chain without the committed policy
    // certifies a different history (its genesis and its confidential feature
    // digests differ), so equality above is not vacuous.
    let mut default_chain = chain(None, None);
    assert_ne!(ordinary_history(&mut default_chain), first_history);
    let default_header = default_chain.committed(3).block().header().clone();
    let policy_header = first.committed(3).block().header().clone();
    assert_ne!(
        default_header.confidential_features(),
        policy_header.confidential_features(),
        "a committed policy change is visible in the certified block header"
    );
    assert_ne!(
        default_chain
            .state()
            .execution_policy_digest_v1()
            .expect("execution policy digest"),
        first
            .state()
            .execution_policy_digest_v1()
            .expect("execution policy digest")
    );
}

fn state_with(node: Option<Zk>, policy: Option<&ZkValidityPolicyV1>) -> State {
    let world = World::default();
    if let Some(policy) = policy {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(policy.clone().into_custom_parameter()));
        block.commit();
    }
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    if let Some(node) = node {
        state
            .install_node_zk(node)
            .expect("node ZK resources install");
    }
    state
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

/// The outcome of a ballot whose four-byte proof passes or fails the committed
/// per-proof size limit before any cryptography runs.
fn four_byte_ballot_outcome(transaction: &mut crate::state::StateTransaction<'_, '_>) -> String {
    transaction.gov.citizenship_bond_amount = Quantity::zero();
    let election_id = "election-1".to_owned();
    transaction.world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([Permission::from(CanSubmitGovernanceBallot {
            referendum_id: election_id.clone(),
        })]),
    );
    let error = iroha_data_model::isi::governance::CastZkBallot {
        election_id,
        proof_b64: "AAECAw==".to_owned(),
        public_inputs_json: "{}".to_owned(),
    }
    .execute(&ALICE_ID, transaction)
    .expect_err("a ballot without an election or a real proof never succeeds");
    format!("{error:?}")
}

fn four_byte_ballot_outcome_at(state: &State, height: u64) -> String {
    let mut block = state.block(header(height));
    let mut transaction = block.transaction();
    four_byte_ballot_outcome(&mut transaction)
}

/// The header of the block after the committed tip of `state`.
fn next_header(state: &State) -> BlockHeader {
    let view = state.view();
    BlockHeader::new(
        NonZeroU64::new(u64::try_from(view.height()).expect("height fits") + 1)
            .expect("nonzero height"),
        view.latest_block_hash(),
        None,
        0,
        0,
    )
}

fn four_byte_ballot_outcome_on_tip(state: &State) -> String {
    let mut block = state.block(next_header(state));
    let mut transaction = block.transaction();
    four_byte_ballot_outcome(&mut transaction)
}

#[test]
fn node_local_setting_cannot_change_a_validation_outcome() {
    // Protocol default (1 MiB per proof): the four-byte proof passes the size
    // limit on a default node and on a node holding a one-byte limit.
    let default_outcome = four_byte_ballot_outcome_at(&state_with(None, None), 2);
    let divergent_outcome =
        four_byte_ballot_outcome_at(&state_with(Some(divergent_node_zk()), None), 2);
    assert_eq!(default_outcome, divergent_outcome);
    assert!(
        !default_outcome.contains("max_proof_size_bytes"),
        "the node-held one-byte limit must not apply: {default_outcome}"
    );
    let divergent_default_state = state_with(Some(divergent_node_zk()), None);
    assert_eq!(
        rates(&divergent_default_state.block(header(2)).zk.gas),
        rates(&crate::gas::DEFAULT_ZK_GAS),
        "block construction froze the protocol-default schedule on the divergent node"
    );

    // Committed limit of two bytes: both nodes reject by the committed limit.
    let policy = committed_policy();
    let committed_default = four_byte_ballot_outcome_at(&state_with(None, Some(&policy)), 2);
    let committed_divergent =
        four_byte_ballot_outcome_at(&state_with(Some(divergent_node_zk()), Some(&policy)), 2);
    assert_eq!(committed_default, committed_divergent);
    assert!(
        committed_default.contains("confidential proof exceeds max_proof_size_bytes"),
        "the committed limit decides: {committed_default}"
    );
    assert_ne!(committed_default, default_outcome);
    // Gas follows the committed schedule frozen at block construction, not the
    // one either node held.
    let committed_state = state_with(Some(divergent_node_zk()), Some(&policy));
    let committed_gas = committed_state.block(header(2)).zk.gas;
    assert_eq!(committed_gas.per_proof_byte, policy.gas.per_proof_byte);
    assert_eq!(committed_gas.proof_base, policy.gas.proof_base);
    assert_ne!(committed_gas.proof_base, divergent_node_zk().gas.proof_base);
    // The schedule belongs to the State that committed it: a State without a
    // committed policy, alive in the same process, still freezes the default.
    assert_eq!(
        rates(&divergent_default_state.block(header(2)).zk.gas),
        rates(&crate::gas::DEFAULT_ZK_GAS)
    );
}

#[test]
fn set_parameter_installs_and_changes_the_policy_and_rejects_invalid_payloads() {
    let set = |policy: ZkValidityPolicyV1| {
        SetParameter::new(Parameter::Custom(policy.into_custom_parameter()))
    };
    let malformed = || {
        SetParameter::new(Parameter::Custom(CustomParameter::new(
            ZkValidityPolicyV1::parameter_id(),
            Json::new("not a policy"),
        )))
    };
    let mut zero = committed_policy();
    zero.confidential.policy_transition_max_per_height = 0;
    let mut incoherent = committed_policy();
    incoherent.confidential.tree_roots_history_len = 7;
    let mut tight = committed_policy();
    tight.confidential.policy_transition_max_per_height = 1;

    // Two nodes with different settings reach the same decision on every input.
    let mut outcomes = Vec::new();
    for node in [None, Some(divergent_node_zk())] {
        let state = state_with(node, None);
        let mut observed = Vec::new();
        // The policy is an ordinary parameter: genesis and later blocks both set it.
        for height in [1, 2] {
            let mut block = state.block(header(height));
            let mut transaction = block.transaction();
            let rejected = malformed()
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("a malformed policy payload is rejected");
            observed.push(format!("{rejected:?}"));
            let structural = set(zero.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("a structurally invalid policy is rejected");
            observed.push(format!("{structural:?}"));
            let contradiction = set(incoherent.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("an incoherent policy is rejected");
            observed.push(format!("{contradiction:?}"));
            assert!(
                committed(transaction.world.parameters.get())
                    .expect("no malformed policy is stored")
                    .is_none(),
                "a rejected policy leaves State unchanged"
            );
            // Two committed transitions at one height are an obligation the
            // new per-height limit must cover.
            transaction
                .world
                .confidential_policy_transition_counts
                .insert(90, 2);
            let stranded = set(tight.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("a limit below a committed pending count is rejected");
            observed.push(format!("{stranded:?}"));
            transaction
                .world
                .confidential_policy_transition_counts
                .insert(90, 1);
            set(tight.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect("the limit covers the committed pending count");
            set(committed_policy())
                .execute(&ALICE_ID, &mut transaction)
                .expect("a valid policy replaces the previous one");
            assert_eq!(
                committed(transaction.world.parameters.get()),
                Ok(Some(committed_policy()))
            );
            // The block that commits a policy still runs under the one frozen
            // at its construction.
            assert_eq!(
                policy_of(&transaction.zk),
                ZkValidityPolicyV1::protocol_default()
            );
        }
        outcomes.push(observed);
    }
    assert_eq!(outcomes[0], outcomes[1]);
    let observed = &outcomes[0];
    assert_eq!(
        observed[..4],
        observed[4..],
        "genesis and later blocks agree"
    );
    assert!(
        observed[0].contains("not a canonical V1 policy"),
        "{observed:?}"
    );
    assert!(
        observed[1].contains("confidential.policy_transition_max_per_height"),
        "{observed:?}"
    );
    assert!(observed[2].contains("incoherent"), "{observed:?}");
    assert!(
        observed[3].contains("committed confidential-policy transitions at height 90"),
        "{observed:?}"
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
    world: World,
    node: Option<Zk>,
    policy: Option<&ZkValidityPolicyV1>,
) -> CertifiedTestChain {
    let mut config = TestChainConfig::new(world, 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    if let Some(policy) = policy {
        config
            .genesis_parameters
            .push(Parameter::Custom(policy.clone().into_custom_parameter()));
    }
    let mut prepared = CertifiedTestChain::prepare(config).expect("fixture genesis is prepared");
    if let Some(node) = node {
        install_node(&mut prepared, node);
    }
    CertifiedTestChain::from_prepared(prepared).expect("genesis applies")
}

#[test]
fn authorized_change_governs_the_next_block_without_grandfathering() {
    // A chain that started without the parameter installs it with an ordinary
    // authorized `SetParameter`. Two nodes that differ in their own settings
    // certify the same history before, at and after the change.
    let policy = committed_policy();
    let mut histories = Vec::new();
    for node in [None, Some(divergent_node_zk())] {
        let mut chain = alice_chain(
            alice_world([Permission::from(CanSetParameters)]),
            node,
            None,
        );
        let set = |policy: &ZkValidityPolicyV1| -> InstructionBox {
            SetParameter::new(Parameter::Custom(policy.clone().into_custom_parameter())).into()
        };
        // An account without the parameter permission cannot install it.
        let unauthorized = chain.sign(&BOB_KEYPAIR, [set(&policy)], 1);
        assert_eq!(chain.commit(vec![unauthorized]), vec![false]);
        assert_eq!(
            policy_of(&chain.state().view().zk),
            ZkValidityPolicyV1::protocol_default()
        );
        // Before the change a four-byte proof passes the default size limit.
        let before = four_byte_ballot_outcome_on_tip(chain.state());
        assert!(!before.contains("max_proof_size_bytes"), "{before}");

        // The authorized change commits in block N.
        let authorized = chain.sign(&ALICE_KEYPAIR, [set(&policy)], 1_001);
        assert_eq!(chain.commit(vec![authorized]), vec![true]);
        // Block N + 1 and every view of the committed State read the new policy.
        assert_eq!(policy_of(&chain.state().view().zk), policy);
        assert_eq!(policy_of(&chain.state().zk_snapshot()), policy);
        // No grandfathering: the same proof is now over the committed
        // two-byte limit, on both nodes.
        let after = four_byte_ballot_outcome_on_tip(chain.state());
        assert!(
            after.contains("confidential proof exceeds max_proof_size_bytes"),
            "{after}"
        );

        // A coherent smaller policy is an ordinary change too: limits shrink.
        let mut smaller = policy.clone();
        smaller.confidential.max_anchor_age_blocks = 10;
        smaller.confidential.tree_roots_history_len = 10;
        smaller.proofs.proof_history_cap = 1;
        smaller.proofs.proof_retention_grace_blocks = 0;
        let shrink = chain.sign(&ALICE_KEYPAIR, [set(&smaller)], 2_001);
        assert_eq!(chain.commit(vec![shrink]), vec![true]);
        assert_eq!(policy_of(&chain.state().view().zk), smaller);
        // An incoherent one is rejected and the committed policy stays.
        let mut incoherent = smaller.clone();
        incoherent.confidential.tree_roots_history_len = 9;
        let rejected = chain.sign(&ALICE_KEYPAIR, [set(&incoherent)], 3_001);
        assert_eq!(chain.commit(vec![rejected]), vec![false]);
        assert_eq!(policy_of(&chain.state().view().zk), smaller);
        // The node kept only its local resources throughout.
        assert!(
            node_validity_overrides(&node_local_resources(chain.state().installed_zk().clone())).is_empty()
        );
        histories.push((certified_history(&chain), before, after));
    }
    assert_eq!(histories[0], histories[1]);
    // The headers before and after the change commit to different policies.
    let mut chain = alice_chain(
        alice_world([Permission::from(CanSetParameters)]),
        None,
        None,
    );
    chain.commit(Vec::new());
    let before = chain.committed(2).block().header().confidential_features();
    let set: InstructionBox =
        SetParameter::new(Parameter::Custom(policy.into_custom_parameter())).into();
    let tx = chain.sign(&ALICE_KEYPAIR, [set], 1_001);
    assert_eq!(chain.commit(vec![tx]), vec![true]);
    let at = chain.committed(3).block().header().confidential_features();
    chain.commit(Vec::new());
    let after = chain.committed(4).block().header().confidential_features();
    assert_eq!(
        before, at,
        "the block that commits the change runs under the old policy"
    );
    assert_ne!(
        at, after,
        "the next block is certified under the new policy"
    );
}

#[test]
fn executor_reconciliation_cannot_replace_or_remove_the_committed_policy() {
    let installed = committed_policy();
    let mut attacker_value = ZkValidityPolicyV1::protocol_default();
    attacker_value.confidential.max_proof_size_bytes = 1;
    attacker_value.gas.proof_base = 1;
    let attacker_models = [
        // A valid replacement policy.
        attacker_value.into_custom_parameter(),
        // A malformed payload, which would silently drop every committed limit.
        CustomParameter::new(
            ZkValidityPolicyV1::parameter_id(),
            Json::new("not a policy"),
        ),
    ];
    for attacker in attacker_models {
        let state = state_with(None, Some(&installed));
        let mut block = state.block(header(2));
        let mut transaction = block.transaction();
        // The migrated executor declares the parameter.
        let mut declares = ExecutorDataModel::default();
        declares
            .parameters
            .insert(ZkValidityPolicyV1::parameter_id(), attacker.clone());
        transaction.world.apply_executor_data_model(declares);
        assert_eq!(
            committed(transaction.world.parameters.get()),
            Ok(Some(installed.clone())),
            "an executor data model cannot overwrite the committed policy"
        );
        assert!(
            transaction
                .world
                .executor_data_model
                .get()
                .parameters()
                .get(&ZkValidityPolicyV1::parameter_id())
                .is_none(),
            "executor-owned schemas must not acquire the consensus-owned parameter"
        );
        // A later migration stops declaring it.
        transaction
            .world
            .apply_executor_data_model(ExecutorDataModel::default());
        assert_eq!(
            committed(transaction.world.parameters.get()),
            Ok(Some(installed.clone())),
            "an executor data model cannot remove the committed policy"
        );
    }
    // A chain without the policy does not acquire one from an executor either.
    let state = state_with(None, None);
    let mut block = state.block(header(2));
    let mut transaction = block.transaction();
    let mut declares = ExecutorDataModel::default();
    declares.parameters.insert(
        ZkValidityPolicyV1::parameter_id(),
        committed_policy().into_custom_parameter(),
    );
    transaction.world.apply_executor_data_model(declares);
    assert_eq!(committed(transaction.world.parameters.get()), Ok(None));
    assert!(
        crate::state::consensus_owned_custom_parameter_ids()
            .contains(&ZkValidityPolicyV1::parameter_id())
    );
}

/// An executor that admits every instruction, so Core's own proof rules decide.
fn admit_all_executor() -> crate::executor::Executor {
    let verdict = norito::codec::Encode::encode(&Ok::<(), iroha_data_model::ValidationFail>(()));
    let program = crate::executor::build_program_from_encoded_result(&verdict);
    let loaded = crate::executor::LoadedExecutor::load(iroha_data_model::executor::Executor::new(
        iroha_data_model::transaction::IvmBytecode::from_compiled(program),
    ))
    .expect("load the admit-all executor");
    crate::executor::Executor::UserProvided(loaded)
}

/// A committed policy whose per-proof limit is exactly the size of the real
/// fixture proof, with a verification gas schedule that differs from the
/// protocol default in its base and per-byte rates.
fn proof_policy(proof_bytes: usize) -> ZkValidityPolicyV1 {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    let limit = u32::try_from(proof_bytes).expect("fixture proof length fits u32");
    policy.confidential.max_proof_size_bytes = limit;
    policy.confidential.max_verify_calls_per_tx = 2;
    policy.confidential.max_verify_calls_per_block = 2;
    // A lower per-byte rate than the default, so that the base rate can place
    // the price of the fixture proof exactly at a block gas limit.
    policy.gas.per_proof_byte -= 1;
    policy.gas.proof_base += 11;
    policy
}

/// `policy` with the verification base rate chosen so that one proof of
/// `proof_bytes` bytes on a backend without public-input pricing costs
/// exactly `total` gas.
fn priced_at(policy: &ZkValidityPolicyV1, proof_bytes: u64, total: u64) -> ZkValidityPolicyV1 {
    let mut priced = policy.clone();
    let per_byte = priced
        .gas
        .per_proof_byte
        .checked_mul(proof_bytes)
        .expect("per-byte charge fits u64");
    priced.gas.proof_base = total
        .checked_sub(per_byte)
        .expect("the per-byte charge alone stays below the target");
    priced
}

/// Gas the State's next block charges for `instruction`: the block freezes
/// the committed schedule and the production meter is given it.
fn gas_charged_by_next_block(state: &State, instruction: &InstructionBox) -> (u64, u64) {
    let block = state.block(next_header(state));
    (
        crate::gas::meter_instructions(core::slice::from_ref(instruction), &block.zk.gas),
        crate::gas::confidential_gas_cost(instruction, &block.zk.gas),
    )
}

#[cfg(feature = "zk-stark")]
#[test]
fn proof_bearing_history_is_identical_under_divergent_node_configuration() {
    let backend = crate::zk::ZK_BACKEND_STARK_FRI_V1;
    // A real native STARK proof and its verifying key.
    let fixture = crate::zk::test_utils::stark_public_binding_fixture_envelope();
    let proof = fixture.proof_box(backend);
    let key = fixture
        .vk_box(backend)
        .expect("the fixture carries its key");
    let key_id = VerifyingKeyId::new(backend, "parity-public-binding");
    let mut record = VerifyingKeyRecord::new_with_owner(
        1,
        format!("{backend}:public-binding-demo"),
        None,
        "test",
        BackendTag::Stark,
        "goldilocks",
        fixture.schema_hash,
        crate::zk::hash_vk(&key),
    );
    record.vk_len = u32::try_from(key.bytes.len()).expect("key length fits u32");
    record.status = ConfidentialStatus::Active;
    record.key = Some(key);
    record.gas_schedule_id = Some("stark_default".to_owned());
    let register: InstructionBox = RegisterVerifyingKey {
        id: key_id.clone(),
        record,
    }
    .into();
    let verify = |proof: ProofBox| -> InstructionBox {
        VerifyProof::new(ProofAttachment::new_ref(
            backend.into(),
            proof,
            key_id.clone(),
        ))
        .into()
    };
    // The same envelope with one flipped byte: carried evidence that is malformed.
    let mut tampered = proof.clone();
    let last = tampered.bytes.len() - 1;
    tampered.bytes[last] ^= 0x01;
    // The same proof padded past the committed per-proof limit.
    let mut oversized = proof.clone();
    oversized.bytes.extend_from_slice(&[0_u8; 8]);
    let policy = proof_policy(proof.bytes.len());
    let proof_id = |proof: &ProofBox| ProofId {
        backend: backend.into(),
        proof_hash: crate::zk::hash_proof(proof),
    };

    let proof_len = u64::try_from(proof.bytes.len()).expect("length fits");
    let set = |policy: &ZkValidityPolicyV1| -> InstructionBox {
        SetParameter::new(Parameter::Custom(policy.clone().into_custom_parameter())).into()
    };

    let mut observed = Vec::new();
    for node in [None, Some(divergent_node_zk())] {
        let mut world = alice_world([
            Permission::from(CanManageVerifyingKeys),
            Permission::from(CanSetParameters),
        ]);
        world.executor = mv::cell::Cell::new(admit_all_executor());
        let mut chain = alice_chain(world, node, Some(&policy));
        let block_gas_limit =
            crate::state::gas_limit_from_parameters(chain.state().view().world().parameters());
        // Two committed schedules around the block gas limit: under `over` the
        // real proof costs one unit more than a block holds, under `exact`
        // exactly what it holds.
        let over = priced_at(&policy, proof_len, block_gas_limit + 1);
        let exact = priced_at(&policy, proof_len, block_gas_limit);
        let register_tx = chain.sign(&ALICE_KEYPAIR, [register.clone()], 1);
        let registered = chain.commit(vec![register_tx]);
        let set_over = chain.sign(&ALICE_KEYPAIR, [set(&over)], 501);
        assert_eq!(chain.commit(vec![set_over]), vec![true]);
        let unaffordable_tx = chain.sign(&ALICE_KEYPAIR, [verify(proof.clone())], 701);
        let unaffordable = chain.commit(vec![unaffordable_tx]);
        let unaffordable_error = format!(
            "{:?}",
            chain.committed(chain.height()).block().output_error(0)
        );
        let set_exact = chain.sign(&ALICE_KEYPAIR, [set(&exact)], 801);
        assert_eq!(chain.commit(vec![set_exact]), vec![true]);
        let accepted_tx = chain.sign(&ALICE_KEYPAIR, [verify(proof.clone())], 1_001);
        let accepted = chain.commit(vec![accepted_tx]);
        let tampered_tx = chain.sign(&ALICE_KEYPAIR, [verify(tampered.clone())], 2_001);
        let tampered_result = chain.commit(vec![tampered_tx]);
        let oversized_tx = chain.sign(&ALICE_KEYPAIR, [verify(oversized.clone())], 3_001);
        let oversized_result = chain.commit(vec![oversized_tx]);
        let errors: Vec<String> = (3..=chain.height())
            .map(|height| format!("{:?}", chain.committed(height).block().output_error(0)))
            .collect();
        let view = chain.state().view();
        let statuses: Vec<Option<ProofStatus>> = [&proof, &tampered, &oversized]
            .into_iter()
            .map(|proof| {
                view.world()
                    .proofs()
                    .get(&proof_id(proof))
                    .map(|record| record.status)
            })
            .collect();
        assert_eq!(policy_of(&view.zk), exact);
        drop(view);
        // Gas the next block of this node charges for the accepted proof.
        let charged = gas_charged_by_next_block(chain.state(), &verify(proof.clone()));
        observed.push((
            registered,
            unaffordable,
            unaffordable_error,
            accepted,
            tampered_result,
            oversized_result,
            errors,
            statuses,
            charged,
            block_gas_limit,
            certified_history(&chain),
        ));
    }
    assert_eq!(observed[0], observed[1]);
    let (
        registered,
        unaffordable,
        unaffordable_error,
        accepted,
        tampered_result,
        oversized_result,
        errors,
        statuses,
        charged,
        block_gas_limit,
        _,
    ) = &observed[0];
    assert_eq!(
        registered,
        &vec![true],
        "the verifying key registers: {errors:?}"
    );
    // The committed schedule is what the certified block charged: one gas unit
    // over the block limit rejects the real proof, exactly the limit accepts
    // it. The divergent node held base 1 and 1000 per byte and decides the same.
    assert_eq!(unaffordable, &vec![false], "{errors:?}");
    assert!(
        unaffordable_error.contains(&format!(
            "block gas limit exceeded: {} > {block_gas_limit}",
            block_gas_limit + 1
        )),
        "{unaffordable_error}"
    );
    assert_eq!(
        accepted,
        &vec![true],
        "the real proof is accepted at exactly the block gas limit: {errors:?}"
    );
    assert_eq!(
        statuses[0],
        Some(ProofStatus::Verified),
        "the accepted proof is recorded as verified: {errors:?}"
    );
    assert_ne!(
        statuses[1],
        Some(ProofStatus::Verified),
        "a tampered proof is never recorded as verified: {tampered_result:?} {errors:?}"
    );
    assert_eq!(
        oversized_result,
        &vec![false],
        "the committed per-proof limit rejects one byte class over it: {errors:?}"
    );
    assert_eq!(statuses[2], None);
    // The charge follows the committed schedule, not the protocol default and
    // not the one the divergent node held.
    let (total, confidential) = *charged;
    assert_eq!(total, *block_gas_limit);
    assert_eq!(confidential, *block_gas_limit);
    assert_ne!(
        total,
        crate::gas::meter_instructions(
            core::slice::from_ref(&verify(proof.clone())),
            &crate::gas::DEFAULT_ZK_GAS
        )
    );
}

#[cfg(feature = "zk-stark")]
#[test]
fn committed_gas_schedule_prices_a_real_proof_identically_on_every_node() {
    let backend = crate::zk::ZK_BACKEND_STARK_FRI_V1;
    let fixture = crate::zk::test_utils::stark_public_binding_fixture_envelope();
    let proof = fixture.proof_box(backend);
    let proof_len = u64::try_from(proof.bytes.len()).expect("length fits");
    let instruction: InstructionBox = VerifyProof::new(ProofAttachment::new_ref(
        backend.into(),
        proof,
        VerifyingKeyId::new(backend, "priced-proof"),
    ))
    .into();
    let policy = committed_policy();
    let default_node = gas_charged_by_next_block(&state_with(None, Some(&policy)), &instruction);
    let divergent_node = gas_charged_by_next_block(
        &state_with(Some(divergent_node_zk()), Some(&policy)),
        &instruction,
    );
    assert_eq!(default_node, divergent_node);
    // Without a committed policy both nodes charge the protocol default.
    let default_chain = gas_charged_by_next_block(&state_with(None, None), &instruction);
    let divergent_default_chain =
        gas_charged_by_next_block(&state_with(Some(divergent_node_zk()), None), &instruction);
    assert_eq!(default_chain, divergent_default_chain);
    // The two committed schedules price the proof differently, by exactly the
    // difference of their base and per-byte charges.
    let default_gas = ZkValidityPolicyV1::protocol_default().gas;
    assert_eq!(
        default_node.1 - default_chain.1,
        (policy.gas.proof_base - default_gas.proof_base)
            + (policy.gas.per_proof_byte - default_gas.per_proof_byte) * proof_len
    );
    assert_eq!(
        default_node.0 - default_chain.0,
        default_node.1 - default_chain.1
    );
}

/// The feature-parity record `scripts/check_zk_feature_parity.py` compares
/// across Cargo feature selections.
#[path = "zk_validity_policy_feature_parity_tests.rs"]
mod feature_parity;
