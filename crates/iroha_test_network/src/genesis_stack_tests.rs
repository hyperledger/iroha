//! Default-stack execution of the actual native genesis pre-execution owner.

use super::*;
use crate::{NetworkBuilder, NetworkPeer, resolve_final_actual_config};
use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
use std::borrow::Cow;

#[test]
fn genesis_preexecution_uses_ordinary_stack_with_exact_runtime_profile() {
    let _caller_profile = ChainDiscriminantGuard::enter(777);
    let before_build = genesis_preexecution_count();
    let network = crate::tests::build_with_isolated_permit(
        NetworkBuilder::new()
            .with_peers(4)
            .with_npos_consensus()
            .with_config_layer(|layer| {
                layer
                    .write("chain", "fc56984b-2be7-431d-840e-21514d1883f0")
                    .write("chain_discriminant", 369_i64);
            }),
    );
    assert!(
        genesis_preexecution_count() > before_build,
        "fixture construction must perform native pre-execution"
    );
    assert_eq!(chain_discriminant(), 777, "builder leaked its profile");
    let original = network.genesis();
    let original_wire = original
        .0
        .encode_wire()
        .expect("original signed genesis wire");
    assert!(
        original.0.has_results(),
        "fixture has actual execution results"
    );
    assert!(genesis_results_are_canonical(&original.0));
    let layers = network
        .config_layers()
        .map(Cow::into_owned)
        .collect::<Vec<_>>();
    let actual = resolve_final_actual_config(&network.peers()[0], &layers);
    assert_eq!(*actual.common.chain_discriminant.value(), 369);
    let topology = network
        .peers()
        .iter()
        .map(NetworkPeer::id)
        .collect::<Vec<_>>();
    assert_eq!(topology.len(), 4, "the native committee is exactly 3f+1");
    assert_eq!(network.validators().len(), 4);
    let genesis_key_pair = network
        .genesis_key_pair
        .as_ref()
        .expect("generated genesis must retain its signing owner");
    let genesis_account = AccountId::new(genesis_key_pair.public_key().clone());
    let expected_nexus = Hash::prehashed(
        network
            .consensus_profile
            .params
            .sumeragi_context
            .nexus_amx_context_hash,
    );
    let expected_execution = Hash::prehashed(
        network
            .consensus_profile
            .params
            .sumeragi_context
            .execution_policy_hash,
    );

    // Pin the ordinary libtest stack explicitly regardless of the process
    // environment. The canonical entry executes on this calling thread. Stack
    // overflow aborts normally; there is no skip or larger-stack retry.
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("genesis-preexecution-ordinary-stack".to_owned())
            .stack_size(2 * 1024 * 1024)
            .spawn_scoped(scope, || {
                let _foreign_profile = ChainDiscriminantGuard::enter(888);
                assert_eq!(genesis_preexecution_count(), 0);
                {
                    eprintln!("entering actual genesis pre-execution on a fixed 2 MiB stack");
                    let (executed, staged) = preexecute_genesis_with_runtime_config(
                        &original,
                        &genesis_account,
                        &topology,
                        genesis_key_pair,
                        None,
                        None,
                        None,
                        Some(&actual),
                    )
                    .expect("native genesis must execute on the ordinary stack");
                    assert_eq!(chain_discriminant(), 888, "runtime scope leaked");
                    assert!(
                        executed
                            .output_results()
                            .all(|result| result.as_ref().is_ok())
                    );
                    assert!(genesis_results_are_canonical(&executed));
                    assert!(genesis_signature_is_canonical(&executed, genesis_key_pair));
                    assert_eq!(executed.header(), original.0.header());
                    assert_eq!(executed.hash(), original.0.hash());
                    assert_eq!(
                        executed
                            .encode_wire()
                            .expect("re-executed canonical signed genesis"),
                        original_wire,
                        "ordinary-stack execution must retain the exact signed output frame"
                    );
                    assert_eq!(staged.nexus_amx, expected_nexus);
                    assert_eq!(staged.execution_policy, expected_execution);
                }
                assert_eq!(chain_discriminant(), 888, "runtime scope leaked");
                assert_eq!(
                    genesis_preexecution_count(),
                    1,
                    "the canonical executor must run on this ordinary-stack thread"
                );
            })
            .expect("spawn ordinary-stack genesis regression");
        if let Err(panic) = worker.join() {
            std::panic::resume_unwind(panic);
        }
    });
    assert_eq!(chain_discriminant(), 777, "worker changed caller profile");
}

#[test]
fn blocking_builder_reexecutes_genesis_on_its_default_runtime_worker() {
    let (network, runtime) = crate::tests::build_blocking_with_isolated_permit(
        NetworkBuilder::new().with_peers(4).with_npos_consensus(),
    );
    let layers = network
        .config_layers()
        .map(Cow::into_owned)
        .collect::<Vec<_>>();
    let actual = resolve_final_actual_config(&network.peers()[0], &layers);
    let topology = network
        .peers()
        .iter()
        .map(NetworkPeer::id)
        .collect::<Vec<_>>();
    let genesis = network.genesis();
    let original_wire = genesis.0.encode_wire().expect("signed genesis wire");
    let key = network
        .genesis_key_pair
        .clone()
        .expect("generated genesis must retain its signing owner");
    let account = AccountId::new(key.public_key().clone());
    let worker = runtime.spawn(async move {
        let _profile = ChainDiscriminantGuard::enter(888);
        let before = genesis_preexecution_count();
        let (executed, _) = preexecute_genesis_with_runtime_config(
            &genesis,
            &account,
            &topology,
            &key,
            None,
            None,
            None,
            Some(&actual),
        )
        .expect("the owned runtime executes strict genesis with its default worker stack");
        assert_eq!(genesis_preexecution_count(), before + 1);
        assert_eq!(
            chain_discriminant(),
            888,
            "execution must restore the worker profile"
        );
        assert_eq!(
            executed.encode_wire().expect("executed genesis wire"),
            original_wire
        );
    });
    runtime
        .block_on(worker)
        .expect("ordinary runtime worker must complete");
}
