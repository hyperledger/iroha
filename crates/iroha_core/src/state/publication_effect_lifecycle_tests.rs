//! Signed physical catalog additions retain publication custody across index refusal.

use super::*;
use crate::sumeragi::test_chain::Signers;
use iroha_executor_data_model::permission::parameter::CanSetParameters;
use std::sync::mpsc;

#[derive(Debug)]
struct LifecycleAttempt {
    result: Result<HashOf<BlockHeader>, String>,
    original: Option<(usize, u64, Hash)>,
}

fn prepared_lifecycle_identity(state: &StateBlock<'_>) -> Option<(usize, u64, Hash)> {
    state.pending_autoscale_lifecycle.as_ref().map(|pending| {
        (
            std::ptr::from_ref(state) as usize,
            pending.transition_height,
            pending.expected_incarnation_root,
        )
    })
}

#[test]
fn signed_lifecycle_index_refusal_precedes_geometry_and_replays_final_cursor_journal() {
    let (authority, signer) = gen_account_in("universal");
    let world = || {
        let domain = Domain::new(sample_domain_id()).build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let mut world = World::with([domain], [account], []);
        world.account_permissions.insert(
            authority.clone(),
            BTreeSet::from([Permission::from(CanSetParameters)]),
        );
        world
    };
    let mut chain = manual_lane_lifecycle_test_chain(world());
    let state = Arc::clone(chain.state());
    let original_height = chain.height();
    let generation = state.state_view_generation();
    let original_catalog = state.nexus_snapshot().lane_catalog;
    let original_geometry = state.kura.lane_geometry_journal_state_for_test().unwrap();
    let budget = state.ivm_execution_budget();
    let transaction = chain.sign(
        &signer,
        [iroha_data_model::isi::SetParameter::new(Parameter::Custom(
            manual_lane_lifecycle_payload().into_custom_parameter(),
        ))
        .into()],
        1,
    );
    let proposal = chain.proposal(None, vec![transaction]);
    let expected_hash = proposal.hash();
    let mut pending = chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .unwrap();
    let original = pending
        .inspect(|view| prepared_lifecycle_identity(view.state))
        .unwrap()
        .expect("the actual signed instruction stages a physical lane addition");
    pending.prepare(Signers::Quorum).unwrap();
    assert_eq!(original.1, original_height + 1);
    let mut attempts = Vec::new();
    let mut unchanged = Vec::new();
    let mut returned_before_release = true;
    let mut joined = false;
    std::thread::scope(|scope| {
        let (commands, command_rx) = mpsc::channel();
        let (responses, response_rx) = mpsc::channel();
        let worker = scope.spawn(move || {
            while command_rx.recv() == Ok(()) {
                let result = pending
                    .publish(Signers::Quorum)
                    .map(|block| block.block_hash());
                let original = result
                    .is_err()
                    .then(|| {
                        pending
                            .inspect_prepared(|view| prepared_lifecycle_identity(view.state))
                            .ok()
                            .flatten()
                    })
                    .flatten();
                if responses
                    .send(LifecycleAttempt { result, original })
                    .is_err()
                {
                    break;
                }
            }
        });
        // This is the last real effect index. Acquisition must refuse before
        // applying any raw/tiered geometry or choosing an irreversible direction.
        let blocker = state.da_indexes_hydrated.write();
        for _ in 0..3 {
            if commands.send(()).is_err() {
                break;
            }
            match response_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(attempt) => {
                    attempts.push(attempt);
                    let fences_free = state.state_write_lock.try_lock().is_some()
                        && state.state_commit_lock.try_lock().is_some()
                        && state.lane_lifecycle_lock.try_lock().is_some();
                    let original_fields_free = state.world.try_block(&budget).is_ok()
                        && state
                            .canonical_runtime
                            .probe_original_writers_for_testing()
                            .iter()
                            .all(|probe| probe.acquired && !probe.poisoned);
                    let indexes_free = state.da_shard_cursors.try_write().is_some()
                        && state.lane_manifests.try_write().is_some()
                        && state.lane_privacy_registry.try_write().is_some();
                    unchanged.push(
                        fences_free
                            && original_fields_free
                            && indexes_free
                            && state.state_view_generation() == generation
                            && state.transactions.latest_height()
                                == usize::try_from(original_height)
                                    .expect("fixture height fits usize")
                            && state.nexus_snapshot().lane_catalog == original_catalog
                            && state.geometry_publication.lock().is_none()
                            && state
                                .kura
                                .lane_geometry_journal_state_for_test()
                                .ok()
                                .as_ref()
                                == Some(&original_geometry)
                            && budget.same_pool(&state.ivm_execution_budget()),
                    );
                }
                Err(_) => {
                    returned_before_release = false;
                    break;
                }
            }
        }
        // Release before any assertion, including when the old publisher blocks.
        drop(blocker);
        if returned_before_release {
            for _ in 0..2 {
                if commands.send(()).is_err() {
                    break;
                }
                if let Ok(attempt) = response_rx.recv_timeout(Duration::from_secs(5)) {
                    attempts.push(attempt);
                }
            }
        } else if let Ok(attempt) = response_rx.recv_timeout(Duration::from_secs(5)) {
            attempts.push(attempt);
        }
        drop(commands);
        joined = worker.join().is_ok();
    });
    assert!(joined, "the original native owner must retire naturally");
    assert!(
        attempts.first().is_some_and(|attempt| attempt.result.as_ref().is_err_and(|error|
            error == "deferred original publication: original State publication participant is busy")),
        "the signed lifecycle index blocker must defer before geometry\nattempts: {attempts:?}"
    );
    assert!(
        returned_before_release,
        "the signed lifecycle must not block under fences"
    );
    assert_eq!(attempts.len(), 5);
    assert_eq!(unchanged, vec![true; 3]);
    assert!(
        attempts[..3]
            .iter()
            .all(|attempt| attempt.original == Some(original))
    );
    assert!(
        attempts[3..]
            .iter()
            .all(|attempt| attempt.result == Ok(expected_hash))
    );
    assert_eq!(chain.height(), original_height + 1);
    assert_eq!(state.state_view_generation(), generation + 2);
    assert_eq!(state.latest_block_hash_fast(), Some(expected_hash));
    assert!(state.geometry_publication.lock().is_none());
    let geometry = state.kura.lane_geometry_journal_state_for_test().unwrap();
    assert_eq!(geometry.1, vec!["catalog_published"]);
    assert!(!geometry.2);
    let nexus = state.nexus_snapshot();
    assert!(nexus.lane_config.entry(LaneId::new(1)).is_some());
    let path = state.da_shard_cursor_journal_path();
    assert!(
        path.is_file(),
        "the final publication must durably write its real journal"
    );
    let journal = DaShardCursorJournal::load(&nexus.lane_config, &path).unwrap();
    assert_eq!(journal.mapping(), &nexus.lane_config.shard_mapping());
    assert_eq!(
        journal.canonical_reset_height_for_lane(LaneId::new(1)),
        Some(chain.height())
    );
    assert_eq!(
        journal.canonical_reset_heights(),
        state.da_shard_cursors.read().canonical_reset_heights()
    );
    // Reuse the original native frames and certificates through startup's replay
    // owner; never synthesize another certificate to stand in for restart.
    let mut replay = manual_lane_lifecycle_test_chain(world());
    replay
        .replay_from(&chain)
        .expect("authenticated original suffix replays");
    let restored = replay.state();
    assert_eq!(
        restored.latest_block_hash_fast(),
        state.latest_block_hash_fast()
    );
    let restored_nexus = restored.nexus_snapshot();
    assert_eq!(restored_nexus.lane_catalog, nexus.lane_catalog);
    assert!(lane_config_entries_match(
        &restored_nexus.lane_config,
        &nexus.lane_config
    ));
    assert_eq!(
        restored.da_shard_cursors.read().canonical_reset_heights(),
        journal.canonical_reset_heights()
    );
    let restored_path = restored.da_shard_cursor_journal_path();
    assert!(
        restored_path.is_file(),
        "replay must persist its actual final cursor image"
    );
    let restored_journal = DaShardCursorJournal::load(&restored_nexus.lane_config, &restored_path)
        .expect("reopen the authenticated replay's durable cursor image");
    assert_eq!(
        restored_journal.canonical_reset_heights(),
        journal.canonical_reset_heights()
    );
}
