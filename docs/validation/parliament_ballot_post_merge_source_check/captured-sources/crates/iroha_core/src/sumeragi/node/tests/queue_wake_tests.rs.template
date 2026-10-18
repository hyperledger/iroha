//! Native enqueue-only root/lane liveness and exact binding lifecycle controls.
//!
//! A signed long EMPTY retry interval is a fixture precondition; test deadlines remain the
//! existing 30/60 second bounds. Admission alone must wake the actual existing node owners.

use super::*;

fn accepted_log(chain: &Chain, message: &str) -> AcceptedTransaction<'static> {
    let network = NetworkId::from_genesis_hash(chain.genesis.hash());
    let signed = TransactionBuilder::new(
        network,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, message.to_owned())])
    .sign(ALICE_KEYPAIR.private_key());
    AcceptedTransaction::accept(
        signed,
        &network,
        Duration::from_secs(10),
        TransactionParameters::default(),
        &iroha_config::parameters::actual::Crypto::default(),
    )
    .expect("original accepted native input")
}

fn enqueue_only(
    chain: &Chain,
    validators: &[Validator],
    message: &str,
) -> HashOf<TransactionEntrypoint> {
    let accepted = accepted_log(chain, message);
    let hash = accepted.hash_as_entrypoint();
    for validator in validators {
        validator
            .queue
            .push(accepted.clone(), validator.state.view())
            .expect("native enqueue");
    }
    hash
}

#[test]
fn native_queue_admission_wakes_original_global_driver_after_empty() {
    let chain = chain(4, 600_000);
    let disks = disks(&chain);
    let validators = start_all(&chain, &disks, true);
    wait_until(
        &validators,
        Duration::from_secs(30),
        "actual root EMPTY answer",
        || {
            validators
                .iter()
                .map(|v| v.queue.empty_payload_answers_for_test().0)
                .sum::<usize>()
                > 0
                && validators
                    .iter()
                    .any(|v| v.node.driver.handle().waiting_after_empty_for_test())
        },
    );
    let hash = enqueue_only(&chain, &validators, "admission after original root EMPTY");
    wait_until(
        &validators,
        Duration::from_secs(30),
        "native queue admission must wake the original global driver after EMPTY",
        || committed_everywhere(&validators, hash),
    );
    assert_same_certified_blocks(&disks, validators[0].state.view().height());
    assert_idle_height_unchanged(&validators, Duration::from_millis(250));
    shutdown(validators);
}

#[test]
fn native_queue_admission_wakes_original_live_lane_after_empty() {
    let chain = chain_with(4, 600_000, |keys| {
        fixed_lane_policy_with_retry(keys, 600_000)
    });
    let disks = disks(&chain);
    let validators = start_all(&chain, &disks, true);
    // Real global commits activate the signed fixed lane at height 3. These warmups are
    // setup only; the causal input below calls native Queue admission without a manual wake.
    for message in ["activate lane 1", "activate lane 2"] {
        let hash = submit(&chain, &validators, message);
        wait_until(&validators, Duration::from_secs(30), message, || {
            committed_everywhere(&validators, hash)
        });
    }
    wait_until(
        &validators,
        Duration::from_secs(30),
        "actual live lane EMPTY answer",
        || {
            validators
                .iter()
                .all(|v| v.node.lanes.instances().len() == 1)
                && validators
                    .iter()
                    .map(|v| v.queue.empty_payload_answers_for_test().1)
                    .sum::<usize>()
                    > 0
                && validators
                    .iter()
                    .any(|v| v.node.lanes.waiting_after_empty_for_test())
        },
    );
    let hash = enqueue_only(&chain, &validators, "admission after original lane EMPTY");
    wait_until(
        &validators,
        Duration::from_secs(60),
        "native queue admission must wake the original live lane after EMPTY",
        || committed_everywhere(&validators, hash),
    );
    assert_eq!(
        merged_everywhere(&validators, &disks),
        vec![1; 4],
        "original live lane execution"
    );
    assert_idle_height_unchanged(&validators, Duration::from_millis(250));
    shutdown(validators);
}

/// A separately prepared real State reaches the original startup seam without launching
/// another signer. Its attempted files must remain absent on exclusive Queue refusal.
fn duplicate_prepared_start(chain: &Chain, queue: &Arc<Queue>) -> (NodeError, tempfile::TempDir) {
    let disk = Disk {
        kura: Kura::blank_kura_for_testing(),
        dir: tempfile::tempdir().unwrap(),
    };
    let state = empty_state(&chain.chain_id, &chain.genesis, &disk.kura);
    let prepared = prepare(PrepareInputs {
        state,
        events: tokio::sync::broadcast::channel(1024).0,
        genesis: Some(chain.genesis.clone()),
        genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        consensus_mode: ConsensusMode::Permissioned,
    })
    .expect("real duplicate preparation");
    let key_pair = chain.keys[0].clone();
    let attempted = prepared.start(StartInputs {
        net: Arc::new(MemNet {
            from: core_key(key_pair.public_key()).unwrap(),
            registry: Arc::new(Registry::default()),
        }),
        queue: Arc::clone(queue),
        key_pair,
        beacon_signer: None,
        config: NodeConfig {
            records_dir: disk.dir.path().join("records"),
            installation_log: disk.dir.path().join("keys").join("installation.log"),
            bodies_dir: disk.dir.path().join("bodies"),
            local: SumeragiLocalOverrides::default(),
            assert_fresh_key: true,
            retired_keys: Vec::new(),
        },
        observer: Arc::new(PrintObserver(99)),
        driver: DriverConfig::default(),
    });
    let error = match attempted {
        Err(error) => error,
        Ok(node) => {
            drop(node.queue_wake);
            node.lanes.shutdown();
            node.driver.shutdown();
            panic!("duplicate native startup must refuse before launching a second signer")
        }
    };
    assert!(
        !disk.dir.path().join("records").exists(),
        "duplicate native startup must refuse before launching a second signer"
    );
    assert!(
        !disk.dir.path().join("keys").exists(),
        "duplicate native startup must refuse before launching a second signer"
    );
    assert!(
        !disk.dir.path().join("bodies").exists(),
        "duplicate native startup must refuse before launching a second signer"
    );
    (error, disk.dir)
}

#[test]
fn native_queue_owner_refuses_duplicate_prepared_start_and_requires_fresh_queue_restart() {
    let chain = chain(4, 600_000);
    let disks = disks(&chain);
    let validators = start_all(&chain, &disks, true);
    let original = validators
        .iter()
        .map(|v| Arc::clone(&v.queue))
        .collect::<Vec<_>>();
    let (error, attempted_files) = duplicate_prepared_start(&chain, &original[0]);
    assert!(
        matches!(error, NodeError::Input(ref message)
        if message == "transaction queue already has an original native owner; restart with a fresh Queue"),
        "duplicate native startup must refuse before launching a second signer"
    );
    drop(attempted_files);
    wait_until(
        &validators,
        Duration::from_secs(30),
        "original root EMPTY after duplicate refusal",
        || {
            validators
                .iter()
                .any(|v| v.node.driver.handle().waiting_after_empty_for_test())
        },
    );
    let first = enqueue_only(
        &chain,
        &validators,
        "original queue remains live after duplicate refusal",
    );
    wait_until(
        &validators,
        Duration::from_secs(30),
        "original queue remains usable",
        || committed_everywhere(&validators, first),
    );
    let retired_state = Arc::clone(&validators[0].state);
    shutdown(validators);
    let retired_pool = retired_state.ivm_execution_budget();
    let retired_bytes = retired_pool.reserved_bytes();
    let retained_bytes = original[0].retained_bytes();
    let queued = original[0].queued_len();
    let retired_input = accepted_log(&chain, "retired native Queue cannot accept new work");
    let retired_hash = retired_input.hash_as_entrypoint();
    let refusal = original[0]
        .push(retired_input, retired_state.view())
        .expect_err("retired native Queue must refuse new admission");
    assert!(
        matches!(refusal.err, crate::queue::Error::AdmissionInvariant { ref reason }
        if reason == "transaction queue native owner has retired; restart with a fresh Queue")
    );
    assert_eq!(retired_pool.reserved_bytes(), retired_bytes);
    assert_eq!(original[0].retained_bytes(), retained_bytes);
    assert_eq!(original[0].queued_len(), queued);
    assert!(!original[0].contains_entrypoint_hash(retired_hash));
    drop(retired_state);
    // Notification retirement is permanent even while callback-owned physical joins could
    // still be running. Starting a retired Queue must not reconstruct another native owner.
    let (error, attempted_files) = duplicate_prepared_start(&chain, &original[0]);
    assert!(
        matches!(error, NodeError::Input(ref message)
        if message == "transaction queue already has an original native owner; restart with a fresh Queue"),
        "duplicate native startup must refuse before launching a second signer"
    );
    drop(attempted_files);
    let validators = start_all(&chain, &disks, false);
    for (validator, old) in validators.iter().zip(&original) {
        assert!(
            !Arc::ptr_eq(&validator.queue, old),
            "ordinary restart creates a fresh Queue"
        );
    }
    assert!(
        committed_everywhere(&validators, first),
        "original certified replay"
    );
    wait_until(
        &validators,
        Duration::from_secs(30),
        "restarted actual root EMPTY",
        || {
            validators
                .iter()
                .any(|v| v.node.driver.handle().waiting_after_empty_for_test())
        },
    );
    let second = enqueue_only(
        &chain,
        &validators,
        "fresh queue after original certified restart",
    );
    wait_until(
        &validators,
        Duration::from_secs(30),
        "fresh queue admission after restart",
        || committed_everywhere(&validators, second),
    );
    assert_same_certified_blocks(&disks, validators[0].state.view().height());
    shutdown(validators);
}

#[test]
fn native_queue_reservation_refuses_foreign_funded_pool_without_changing_original_pending() {
    let chain = chain(4, 600_000);
    let disk = Disk {
        kura: Kura::blank_kura_for_testing(),
        dir: tempfile::tempdir().unwrap(),
    };
    let state = empty_state(&chain.chain_id, &chain.genesis, &disk.kura);
    let _prepared = prepare(PrepareInputs {
        state: Arc::clone(&state),
        events: tokio::sync::broadcast::channel(1024).0,
        genesis: Some(chain.genesis.clone()),
        genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        consensus_mode: ConsensusMode::Permissioned,
    })
    .expect("original prepared State");
    let (_, time) = TimeSource::new_mock(Duration::ZERO);
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    let accepted = accepted_log(&chain, "original pending funding before startup");
    let hash = accepted.hash_as_entrypoint();
    queue
        .push(accepted, state.view())
        .expect("original actual native admission");
    let original_pool = state.ivm_execution_budget();
    let original_bytes = original_pool.reserved_bytes();
    let retained = queue.retained_bytes();
    let view = state.view();
    let pending = queue
        .bounded_pending_snapshot_for_testing(&view, std::num::NonZeroUsize::new(1).unwrap())
        .unwrap();
    let wire = pending[0]
        .signed_bytes()
        .expect("original canonical signed source");
    drop(pending);
    drop(view);
    let foreign = iroha_allocation::AllocationBudget::new(original_pool.limit_bytes());
    assert!(
        matches!(
            queue.reserve_sumeragi_start(&foreign),
            Err("transaction queue resident custody belongs to a different original State pool")
        ),
        "existing resident Queue must retain its original State pool at startup"
    );
    assert_eq!(original_pool.reserved_bytes(), original_bytes);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(queue.retained_bytes(), retained);
    assert_eq!(queue.queued_len(), 1);
    assert!(queue.contains_entrypoint_hash(hash));
    let view = state.view();
    let pending = queue
        .bounded_pending_snapshot_for_testing(&view, std::num::NonZeroUsize::new(1).unwrap())
        .unwrap();
    assert!(Arc::ptr_eq(&wire, &pending[0].signed_bytes().unwrap()));
    drop(pending);
    drop(view);
    let reservation = queue
        .reserve_sumeragi_start(&original_pool)
        .expect("exact original pool");
    drop(reservation);
    assert_eq!(queue.queued_len(), 1);
    assert_eq!(original_pool.reserved_bytes(), original_bytes);
}

#[test]
fn native_queue_admission_before_start_retains_original_prepared_state_and_commits() {
    let chain = chain(4, 600_000);
    let disks = disks(&chain);
    let registry = Arc::new(Registry::default());
    let accepted = accepted_log(&chain, "original admission before node binding");
    let hash = accepted.hash_as_entrypoint();
    let mut validators = Vec::new();
    for (index, disk) in disks.iter().enumerate() {
        let state = empty_state(&chain.chain_id, &chain.genesis, &disk.kura);
        let prepared = prepare(PrepareInputs {
            state: Arc::clone(&state),
            events: tokio::sync::broadcast::channel(1024).0,
            genesis: Some(chain.genesis.clone()),
            genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
            consensus_mode: ConsensusMode::Permissioned,
        })
        .expect("original prepared State");
        let (_, time) = TimeSource::new_mock(Duration::ZERO);
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        ));
        queue
            .push(accepted.clone(), state.view())
            .expect("actual pre-binding admission");
        let original_pool = state.ivm_execution_budget();
        assert!(queue.contains_entrypoint_hash(hash));
        let key_pair = chain.keys[index].clone();
        let node = prepared
            .start(StartInputs {
                net: Arc::new(MemNet {
                    from: core_key(key_pair.public_key()).expect("BLS key"),
                    registry: Arc::clone(&registry),
                }),
                queue: Arc::clone(&queue),
                key_pair,
                beacon_signer: None,
                config: NodeConfig {
                    records_dir: disk.dir.path().join("records"),
                    installation_log: disk.dir.path().join("keys").join("installation.log"),
                    bodies_dir: disk.dir.path().join("bodies"),
                    local: SumeragiLocalOverrides::default(),
                    assert_fresh_key: true,
                    retired_keys: Vec::new(),
                },
                observer: Arc::new(PrintObserver(index)),
                driver: DriverConfig::default(),
            })
            .expect("start the original prepared node");
        assert!(original_pool.same_pool(&state.ivm_execution_budget()));
        assert!(
            queue.contains_entrypoint_hash(hash),
            "original pre-start admission remains resident"
        );
        validators.push(Validator { node, state, queue });
    }
    for (key, validator) in chain.keys.iter().zip(&validators) {
        registry.0.lock().insert(
            core_key(key.public_key()).unwrap(),
            Arc::clone(&validator.node.ingress),
        );
    }
    wait_until(
        &validators,
        Duration::from_secs(30),
        "original admission before binding must commit",
        || committed_everywhere(&validators, hash),
    );
    assert_same_certified_blocks(&disks, validators[0].state.view().height());
    shutdown(validators);
}

#[test]
fn native_queue_admission_never_waits_for_original_live_lane_map() {
    let chain = chain_with(4, 600_000, |keys| {
        fixed_lane_policy_with_retry(keys, 600_000)
    });
    let disks = disks(&chain);
    let validators = start_all(&chain, &disks, true);
    for message in ["live map activation 1", "live map activation 2"] {
        let hash = submit(&chain, &validators, message);
        wait_until(&validators, Duration::from_secs(30), message, || {
            committed_everywhere(&validators, hash)
        });
    }
    wait_until(
        &validators,
        Duration::from_secs(30),
        "original live lane map",
        || {
            validators
                .iter()
                .all(|v| v.node.lanes.instances().len() == 1)
        },
    );
    let accepted = accepted_log(&chain, "native enqueue under held original lane map");
    let hash = accepted.hash_as_entrypoint();
    for validator in &validators {
        let (entered, enqueue) = std::sync::mpsc::sync_channel(0);
        let (completed, completion) = std::sync::mpsc::sync_channel(1);
        let queue = Arc::clone(&validator.queue);
        let state = Arc::clone(&validator.state);
        let input = accepted.clone();
        let producer = std::thread::spawn(move || {
            enqueue.recv().unwrap();
            let result = queue.push(input, state.view());
            completed.send(result.is_ok()).unwrap();
        });
        // The existing runner may wait on this map, but the admission thread must not.
        // Always release the map and join the original test producer before asserting.
        let mut received = None;
        validator.node.lanes.with_live_lane_map_for_test(|| {
            entered.send(()).unwrap();
            received = Some(completion.recv_timeout(Duration::from_secs(5)));
        });
        producer.join().expect("original finite enqueue producer");
        assert!(
            matches!(received, Some(Ok(true))),
            "native queue admission cannot block on a live lane map"
        );
    }
    wait_until(
        &validators,
        Duration::from_secs(60),
        "admitted original lane work must merge",
        || committed_everywhere(&validators, hash),
    );
    assert_eq!(merged_everywhere(&validators, &disks), vec![1; 4]);
    shutdown(validators);
}
