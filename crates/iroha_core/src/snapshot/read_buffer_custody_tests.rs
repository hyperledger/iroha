// Exercise both production consumers of the original charged payload buffer.

#[test]
fn snapshot_read_buffer_refusal_preserves_descriptor_position_and_allows_retry() {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Waker},
    };
    let root = tempdir().unwrap();
    let path = root.path().join(SNAPSHOT_FILE_NAME);
    let source = b"exact original snapshot bytes";
    std::fs::write(&path, source).unwrap();
    let binding = bind_snapshot_file_handle(&path, source.len() as u64)
        .unwrap()
        .unwrap();
    let mut reader = binding.handle.as_ref();
    reader.seek(std::io::SeekFrom::Start(3)).unwrap();
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(source.len() + waiter_bytes);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget.try_reserve_bytes(source.len()).unwrap();
    let Err(TryReadError::PayloadAllocation(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    })) = read_bound_snapshot_payload(&binding, &budget)
    else {
        panic!("the original read-buffer pool must refuse before seeking or reading");
    };
    assert_eq!(
        (requested_bytes, reserved_bytes, limit_bytes),
        (
            source.len(),
            source.len() + waiter_bytes,
            source.len() + waiter_bytes
        )
    );
    assert_eq!(reader.stream_position().unwrap(), 3);
    assert_eq!(std::fs::read(&path).unwrap(), source);
    let mut released = pin!(release.wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert!(released.as_mut().poll(&mut context).is_pending());
    drop(occupied);
    assert!(released.as_mut().poll(&mut context).is_ready());
    let (bytes, digest) = read_bound_snapshot_payload(&binding, &budget).unwrap();
    assert_eq!(bytes.as_slice(), source);
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(source)));
    assert_eq!((budget.reserved_bytes() - waiter_bytes), source.len());
    assert_eq!(reader.stream_position().unwrap(), 0);
    drop(bytes);
    assert_eq!((budget.reserved_bytes() - waiter_bytes), 0);
}

#[test]
fn snapshot_read_buffer_changed_source_refunds_the_allocated_owner() {
    let root = tempdir().unwrap();
    let path = root.path().join(SNAPSHOT_FILE_NAME);
    std::fs::write(&path, b"original").unwrap();
    let binding = bind_snapshot_file_handle(&path, 8).unwrap().unwrap();
    std::fs::write(&path, b"modified").unwrap();
    let budget = AllocationBudget::new(8);
    assert!(matches!(
        read_bound_snapshot_payload(&binding, &budget),
        Err(TryReadError::SnapshotBindingChanged(changed)) if changed == path
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[tokio::test]
async fn snapshot_read_buffer_strict_restore_retains_charge_through_initialization() {
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let state = state_factory();
    let key = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store, &key, TEST_CHUNK_SIZE).unwrap();
    let payload_len = usize::try_from(
        std::fs::metadata(current_generation_artifact(&store, SNAPSHOT_FILE_NAME))
            .unwrap()
            .len(),
    )
    .unwrap();
    let pointer = std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap();
    let budget = AllocationBudget::new(payload_len);
    let occupied = budget.try_reserve_bytes(payload_len).unwrap();
    let calls = std::cell::Cell::new(0);
    let kura = Kura::blank_kura_for_testing();
    let initialize = |restored: &mut State| {
        assert_eq!(
            budget.reserved_bytes(),
            payload_len,
            "decoded State must not outlive an early buffer refund"
        );
        calls.set(calls.get() + 1);
        restored
            .set_zk(crate::state::default_zk_config())
            .map_err(TryReadError::ZkConfigInstall)
    };
    let restore = || {
        try_read_snapshot_with_initializer(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            &store,
            &kura,
            &state.lane_manifests.read().clone(),
            &state.nexus_snapshot(),
            LiveQueryStore::start_test,
            BlockCount(state.view().height()),
            TEST_CHUNK_SIZE,
            defaults::snapshot::MAX_PAYLOAD_BYTES,
            SnapshotResourcePolicy::default(),
            key.public_key(),
            &state.chain_id,
            &state.network_id,
            &initialize,
            #[cfg(feature = "telemetry")]
            StateTelemetry::new(<_>::default(), true),
            &budget,
        )
    };
    assert!(matches!(
        restore(),
        Err(TryReadError::PayloadAllocation(
            iroha_allocation::AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(calls.get(), 0);
    assert_eq!(
        std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
        pointer
    );
    drop(occupied);
    let restored = restore().unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        canonical_state_snapshot_bytes_for_tests(&restored),
        canonical_state_snapshot_bytes_for_tests(&state)
    );
}

#[test]
fn snapshot_read_buffer_gc_refusal_preserves_pointer_and_both_retained_generations() {
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let key = checked_random_snapshot_keypair();
    write_snapshot_bundle_from_bytes(&store, b"rollback generation", &key);
    let rollback = current_generation_dir(&store);
    write_snapshot_bundle_from_bytes(&store, b"current generation", &key);
    let current = current_generation_dir(&store);
    let pointer = std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap();
    let (identity, next) = publish_test_snapshot_generation(&store, b"next generation", &key);
    let budget = AllocationBudget::new(64);
    let occupied = budget.try_reserve_bytes(64).unwrap();
    let publish = || {
        budget.with_deferred_refund_notifications(|_| {
            let _guard = SNAPSHOT_PUBLICATION_LOCK.lock();
            publish_snapshot_current_pointer(
                &store,
                identity,
                &next,
                defaults::snapshot::MAX_PAYLOAD_BYTES,
                TEST_CHUNK_SIZE,
                key.public_key(),
                &budget,
            )
        })
    };
    assert!(matches!(
        publish(),
        Err(TryWriteError::PayloadAllocation(
            iroha_allocation::AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(
        std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
        pointer
    );
    for directory in [&rollback, &current, &next.generation_dir] {
        assert!(
            directory.is_dir(),
            "capacity is not invalidity and must preserve every generation"
        );
    }
    drop(occupied);
    publish().unwrap();
    assert_eq!(current_generation_name(&store), next.name);
    assert!(!rollback.exists());
    assert!(current.is_dir());
    assert!(next.generation_dir.is_dir());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn snapshot_read_buffer_gc_fallback_cannot_filter_out_a_capacity_refusal() {
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let key = checked_random_snapshot_keypair();
    write_snapshot_bundle_from_bytes(&store, b"retained rollback", &key);
    let rollback = current_generation_dir(&store);
    write_snapshot_bundle_from_bytes(&store, b"retained current", &key);
    let (_, current) = publish_test_snapshot_generation(&store, b"retained current", &key);
    let pointer = std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap();
    let budget = AllocationBudget::new(64);
    let occupied = budget.try_reserve_bytes(64).unwrap();
    let planned = plan_snapshot_generation_gc(
        &current,
        Some(&current.name),
        defaults::snapshot::MAX_PAYLOAD_BYTES,
        TEST_CHUNK_SIZE,
        key.public_key(),
        &budget,
    );
    assert!(matches!(
        planned,
        Err(TryWriteError::PayloadAllocation(
            iroha_allocation::AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(
        std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
        pointer
    );
    assert!(rollback.is_dir());
    assert!(current.generation_dir.is_dir());
    drop(occupied);
    let plan = plan_snapshot_generation_gc(
        &current,
        Some(&current.name),
        defaults::snapshot::MAX_PAYLOAD_BYTES,
        TEST_CHUNK_SIZE,
        key.public_key(),
        &budget,
    )
    .unwrap();
    assert!(
        plan.removals.is_empty(),
        "the original valid rollback must be retained on retry"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

struct SnapshotRefundAfterUnlock {
    budget: AllocationBudget,
    waiter_bytes: usize,
    wakes: std::sync::atomic::AtomicUsize,
}
impl std::task::Wake for SnapshotRefundAfterUnlock {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        // Other parallel snapshot tests can briefly own the global lock; allow
        // their publication to complete, but fail rather than deadlock if this
        // same synchronous call still owns its guard at notification time.
        let _guard = SNAPSHOT_PUBLICATION_LOCK
            .try_lock_for(std::time::Duration::from_secs(10))
            .expect("snapshot refund must notify only after publication guards release");
        assert_eq!(
            self.budget.reserved_bytes() - self.waiter_bytes,
            1,
            "only the fixture's prepaid sentinel may remain"
        );
        self.wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn snapshot_read_buffer_writer_notifies_after_unlock_on_success_and_error() {
    use std::{
        future::Future,
        pin::pin,
        sync::atomic::Ordering::SeqCst,
        task::{Context, Waker},
    };
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let state = state_factory();
    let key = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store, &key, TEST_CHUNK_SIZE).unwrap();
    let payload_len = usize::try_from(
        std::fs::metadata(current_generation_artifact(&store, SNAPSHOT_FILE_NAME))
            .unwrap()
            .len(),
    )
    .unwrap();
    let pointer = std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap();
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(payload_len + 1 + waiter_bytes);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let _sentinel = budget.try_reserve_bytes(1).unwrap();
    let observer = Arc::new(SnapshotRefundAfterUnlock {
        budget: budget.clone(),
        waiter_bytes,
        wakes: Default::default(),
    });
    let waker = Waker::from(Arc::clone(&observer));
    for expect_error in [false, true] {
        let Err(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
            budget.try_reserve_bytes(payload_len + 1)
        else {
            panic!("fixture sentinel must provide a real original-pool refusal");
        };
        let mut released = pin!(release.wait_for_release(&mut registration));
        assert!(
            released
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let extras = if expect_error {
            // Two authenticated extras make rollback chronology ambiguous.
            // The writer reads/refunds both, then fails before pointer mutation.
            Some((
                publish_test_snapshot_generation(&store, b"extra one", &key).1,
                publish_test_snapshot_generation(&store, b"extra two", &key).1,
            ))
        } else {
            None
        };
        let result = try_write_snapshot_with_limit_and_policy(
            &state,
            &store,
            &key,
            TEST_CHUNK_SIZE,
            defaults::snapshot::MAX_PAYLOAD_BYTES,
            SnapshotResourcePolicy::default(),
            &budget,
        );
        if let Some((first, second)) = extras {
            assert!(
                matches!(result, Err(TryWriteError::PublicationIntegrity(ref reason)) if reason.contains("ambiguous"))
            );
            assert!(first.generation_dir.is_dir());
            assert!(second.generation_dir.is_dir());
        } else {
            result.unwrap();
        }
        assert!(
            released
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
        );
        assert_eq!(observer.wakes.load(SeqCst), usize::from(expect_error) + 1);
        assert_eq!(
            std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
            pointer
        );
        assert_eq!((budget.reserved_bytes() - waiter_bytes), 1);
    }
}

#[tokio::test]
async fn snapshot_read_buffer_maker_retains_the_original_startup_pool() {
    let root = tempdir().unwrap();
    let config = Config {
        mode: Mode::ReadWrite,
        create_every_ms: defaults::snapshot::CREATE_EVERY.into(),
        store_dir: WithOrigin::inline(root.path().to_path_buf()),
        merkle_chunk_size_bytes: TEST_CHUNK_SIZE,
        max_payload_bytes: nonzero!(64_usize),
        max_read_buffer_bytes: nonzero!(64_usize),
        resources: SnapshotResourcePolicy::default(),
        verification_public_key: None,
        signing_private_key: None,
    };
    let startup_pool = AllocationBudget::new(config.max_read_buffer_bytes.get());
    let occupied = startup_pool.try_reserve_bytes(64).unwrap();
    let state = Arc::new(state_factory());
    let key = checked_random_snapshot_keypair();
    let maker = SnapshotMaker::from_config(
        &config,
        Arc::clone(&state),
        key.clone(),
        startup_pool.clone(),
    )
    .unwrap();
    assert_eq!(maker.read_buffer_budget.reserved_bytes(), 64);
    assert!(matches!(
        maker.read_buffer_budget.try_reserve_bytes(1),
        Err(iroha_allocation::AllocationRefusal::Capacity { .. })
    ));
    drop(occupied);
    let writer_owns = maker.read_buffer_budget.try_reserve_bytes(64).unwrap();
    assert_eq!(startup_pool.reserved_bytes(), 64);
    drop(writer_owns);
    assert_eq!(startup_pool.reserved_bytes(), 0);
    let disabled = Config {
        mode: Mode::Disabled,
        ..config
    };
    assert!(SnapshotMaker::from_config(&disabled, state, key, startup_pool).is_none());
}

#[test]
fn snapshot_read_buffer_operation_unwind_notifies_after_unlock() {
    use std::{
        future::Future,
        panic::{AssertUnwindSafe, catch_unwind},
        pin::pin,
        sync::atomic::Ordering::SeqCst,
        task::{Context, Waker},
    };
    let root = tempdir().unwrap();
    let path = root.path().join(SNAPSHOT_FILE_NAME);
    std::fs::write(&path, b"unwind").unwrap();
    let binding = bind_snapshot_file_handle(&path, 6).unwrap().unwrap();
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(7 + waiter_bytes);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let _sentinel = budget.try_reserve_bytes(1).unwrap();
    let Err(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
        budget.try_reserve_bytes(7)
    else {
        panic!("fixture sentinel must provide an original-pool refusal");
    };
    let observer = Arc::new(SnapshotRefundAfterUnlock {
        budget: budget.clone(),
        waiter_bytes,
        wakes: Default::default(),
    });
    let waker = Waker::from(Arc::clone(&observer));
    let mut released = pin!(release.wait_for_release(&mut registration));
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let unwind =
        catch_unwind(AssertUnwindSafe(|| {
            budget.with_deferred_refund_notifications(|_| {
        let _guard = SNAPSHOT_PUBLICATION_LOCK.lock();
        let (buffer, _) = read_bound_snapshot_payload(&binding, &budget).unwrap();
        assert_eq!(buffer.as_slice(), b"unwind");
        panic!("injected failure while an original charged buffer and publication lock are held");
    })
        }));
    assert!(unwind.is_err());
    assert_eq!(observer.wakes.load(SeqCst), 1);
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert_eq!((budget.reserved_bytes() - waiter_bytes), 1);
}

// Composed entrypoint controls: all snapshots below use the canonical signed
// writer, the normal Strict decoder, and the original allocation pool.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_maker_first_tick_exports_recovered_state_without_new_work() {
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let chain = native_snapshot_chain();
    let state = Arc::clone(chain.state());
    let tip = state.latest_block_hash_fast().expect("native executed tip");
    let payload = exact_snapshot_payload_bytes(&state);
    let key = checked_random_snapshot_keypair();
    let config = Config {
        mode: Mode::ReadWrite,
        create_every_ms: defaults::snapshot::CREATE_EVERY.into(),
        store_dir: WithOrigin::inline(store.clone()),
        merkle_chunk_size_bytes: TEST_CHUNK_SIZE,
        max_payload_bytes: defaults::snapshot::MAX_PAYLOAD_BYTES,
        max_read_buffer_bytes: NonZeroUsize::new(payload.len()).unwrap(),
        resources: SnapshotResourcePolicy::default(),
        verification_public_key: None,
        signing_private_key: None,
    };
    let budget = AllocationBudget::new(config.max_read_buffer_bytes.get());
    let mut maker = SnapshotMaker::from_config(&config, state, key, budget.clone()).unwrap();
    assert_eq!(maker.latest_block_hash, None);
    assert_snapshot_bundle_absent(&store);
    let (owner, readiness) = startup_recovery::channel();
    owner.ready();
    let shutdown = ShutdownSignal::new();
    let stop = shutdown.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        SnapshotMaker::run_snapshot_loop(Duration::from_secs(3600), readiness, shutdown, || {
            maker.create_snapshot();
            stop.send();
        }),
    )
    .await
    .expect("the immediate first tick publishes without a new block");
    assert_eq!(maker.latest_block_hash, Some(tip));
    assert_eq!(maker.state.latest_block_hash_fast(), Some(tip));
    assert_eq!(
        std::fs::read(current_generation_artifact(&store, SNAPSHOT_FILE_NAME)).unwrap(),
        payload
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_read_buffer_maker_gc_refusal_retries_the_same_pending_state() {
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let mut chain = native_snapshot_chain();
    let state = Arc::clone(chain.state());
    let key = checked_random_snapshot_keypair();

    // GC retains the current generation and its immediate predecessor. A
    // third, genuinely written generation is needed to exercise its reader.
    try_write_snapshot(&state, &store, &key, TEST_CHUNK_SIZE).unwrap();
    let rollback = current_generation_dir(&store);
    let rollback_name = current_generation_name(&store);
    let rollback_bytes = std::fs::read(rollback.join(SNAPSHOT_FILE_NAME)).unwrap();
    chain.commit(Vec::new());
    let block_one = state.latest_block_hash_fast().unwrap();
    try_write_snapshot(&state, &store, &key, TEST_CHUNK_SIZE).unwrap();
    let current = current_generation_dir(&store);
    let current_bytes = std::fs::read(current.join(SNAPSHOT_FILE_NAME)).unwrap();
    let pointer = std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap();
    // Publication authenticates the current snapshot before planning rollback
    // GC. Either real payload must fit after the competing reader is released.
    let (occupied_generation, occupied_bytes) = if current_bytes.len() >= rollback_bytes.len() {
        (&current, &current_bytes)
    } else {
        (&rollback, &rollback_bytes)
    };
    let config = Config {
        mode: Mode::ReadWrite,
        create_every_ms: defaults::snapshot::CREATE_EVERY.into(),
        store_dir: WithOrigin::inline(store.clone()),
        merkle_chunk_size_bytes: TEST_CHUNK_SIZE,
        max_payload_bytes: defaults::snapshot::MAX_PAYLOAD_BYTES,
        max_read_buffer_bytes: NonZeroUsize::new(occupied_bytes.len()).unwrap(),
        resources: SnapshotResourcePolicy::default(),
        verification_public_key: None,
        signing_private_key: None,
    };
    let budget = AllocationBudget::new(config.max_read_buffer_bytes.get());
    let mut maker =
        SnapshotMaker::from_config(&config, state, key.clone(), budget.clone()).unwrap();
    assert_eq!(maker.latest_block_hash, None);
    maker.create_snapshot();
    assert_eq!(maker.latest_block_hash, Some(block_one));
    let state_owner = Arc::as_ptr(&maker.state);
    // Execute the next block in the same State owner retained by SnapshotMaker.
    chain.commit(Vec::new());
    let block_two = maker.state.latest_block_hash_fast().unwrap();
    let pending_bytes = exact_snapshot_payload_bytes(&maker.state);
    let pending_name = hex::encode(Sha256::digest(&pending_bytes));
    let pending = store
        .join(SNAPSHOT_GENERATIONS_DIR_NAME)
        .join(&pending_name);
    let binding = bind_snapshot_file_handle(
        &occupied_generation.join(SNAPSHOT_FILE_NAME),
        u64::try_from(occupied_bytes.len()).unwrap(),
    )
    .unwrap()
    .unwrap();
    let (occupied, _) = read_bound_snapshot_payload(&binding, &budget).unwrap();
    assert_eq!(occupied.as_slice(), occupied_bytes);
    assert!(matches!(
        snapshot_generation_is_canonical_for_gc(
            &rollback,
            &rollback_name,
            config.max_payload_bytes,
            TEST_CHUNK_SIZE,
            key.public_key(),
            &budget,
        ),
        Err(TryWriteError::PayloadAllocation(
            iroha_allocation::AllocationRefusal::Capacity { .. }
        ))
    ));

    maker.create_snapshot();
    assert_eq!(maker.latest_block_hash, Some(block_one));
    assert_eq!(maker.state.latest_block_hash_fast(), Some(block_two));
    assert_eq!(Arc::as_ptr(&maker.state), state_owner);
    assert_eq!(exact_snapshot_payload_bytes(&maker.state), pending_bytes);
    assert_eq!(
        std::fs::read(pending.join(SNAPSHOT_FILE_NAME)).unwrap(),
        pending_bytes
    );
    assert_eq!(
        std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
        pointer
    );
    assert_eq!(
        std::fs::read(rollback.join(SNAPSHOT_FILE_NAME)).unwrap(),
        rollback_bytes
    );
    assert_eq!(
        std::fs::read(current.join(SNAPSHOT_FILE_NAME)).unwrap(),
        current_bytes
    );
    assert_eq!(budget.reserved_bytes(), occupied_bytes.len());

    // Only destruction of the real charged reader changes between attempts.
    drop(occupied);
    assert_eq!(budget.reserved_bytes(), 0);
    maker.create_snapshot();
    assert_eq!(maker.latest_block_hash, Some(block_two));
    assert_eq!(Arc::as_ptr(&maker.state), state_owner);
    assert_eq!(exact_snapshot_payload_bytes(&maker.state), pending_bytes);
    assert_eq!(current_generation_name(&store), pending_name);
    assert!(!rollback.exists());
    assert!(current.is_dir());
    assert_eq!(
        std::fs::read(current.join(SNAPSHOT_FILE_NAME)).unwrap(),
        current_bytes
    );
    assert_eq!(
        std::fs::read(pending.join(SNAPSHOT_FILE_NAME)).unwrap(),
        pending_bytes
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

fn strict_snapshot_read_for_custody_test<F>(
    store: &Path,
    source: &State,
    kura: &Arc<Kura>,
    key: &KeyPair,
    budget: &AllocationBudget,
    initialize: &F,
) -> Result<Box<State>, TryReadError>
where
    F: Fn(&mut State) -> Result<(), TryReadError>,
{
    assert!(!kura.emergency_fast_startup_enabled());
    let block_count = BlockCount(source.view().height());
    let lane_manifests = source.lane_manifests.read().clone();
    try_read_snapshot_with_initializer(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        store,
        kura,
        &lane_manifests,
        &source.nexus_snapshot(),
        LiveQueryStore::start_test,
        block_count,
        TEST_CHUNK_SIZE,
        defaults::snapshot::MAX_PAYLOAD_BYTES,
        SnapshotResourcePolicy::default(),
        key.public_key(),
        &source.chain_id,
        &source.network_id,
        initialize,
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        budget,
    )
}

struct StrictInitializerRefundObserver {
    budget: AllocationBudget,
    waiter_bytes: usize,
    kura: Arc<Kura>,
    original_kura_owners: usize,
    decoded_crypto:
        parking_lot::Mutex<Option<std::sync::Weak<iroha_config::parameters::actual::Crypto>>>,
    wakes: std::sync::atomic::AtomicUsize,
    saw_payload_refunded: std::sync::atomic::AtomicBool,
    saw_decoded_state_released: std::sync::atomic::AtomicBool,
}

impl std::task::Wake for StrictInitializerRefundObserver {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        use std::sync::atomic::Ordering::SeqCst;
        // Record without panicking: the unwind test must remain catchable even
        // if refund ordering regresses. These are actual decoded-State owners,
        // not a test-only replacement Drop token installed into State.
        let decoded_crypto_released = self
            .decoded_crypto
            .lock()
            .as_ref()
            .is_some_and(|crypto| crypto.strong_count() == 0);
        self.saw_payload_refunded.fetch_and(
            self.budget.reserved_bytes() == self.waiter_bytes + 1,
            SeqCst,
        );
        self.saw_decoded_state_released.fetch_and(
            decoded_crypto_released && Arc::strong_count(&self.kura) == self.original_kura_owners,
            SeqCst,
        );
        self.wakes.fetch_add(1, SeqCst);
    }
}

fn assert_strict_initializer_failure_refunds_before_notification(unwind: bool) {
    use std::{
        future::Future,
        panic::{AssertUnwindSafe, catch_unwind},
        pin::pin,
        sync::atomic::Ordering::SeqCst,
        task::{Context, Waker},
    };
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let kura = Kura::blank_kura_for_testing();
    // Strict decoding admits height zero. Nonzero caches require original replay
    // before a typed State can be restored.
    let state = state_factory_with_kura(Arc::clone(&kura));
    let key = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store, &key, TEST_CHUNK_SIZE).unwrap();
    let payload_path = current_generation_artifact(&store, SNAPSHOT_FILE_NAME);
    let payload = std::fs::read(&payload_path).unwrap();
    let pointer = std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap();
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(payload.len() + 1 + waiter_bytes);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let _sentinel = budget.try_reserve_bytes(1).unwrap();
    let Err(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
        budget.try_reserve_bytes(payload.len() + 1)
    else {
        panic!("sentinel must produce an original-pool release observation");
    };
    let observer = Arc::new(StrictInitializerRefundObserver {
        budget: budget.clone(),
        waiter_bytes,
        original_kura_owners: Arc::strong_count(&kura) + 1,
        kura: Arc::clone(&kura),
        decoded_crypto: Default::default(),
        wakes: Default::default(),
        saw_payload_refunded: true.into(),
        saw_decoded_state_released: true.into(),
    });
    let waker = Waker::from(Arc::clone(&observer));
    let mut released = pin!(release.wait_for_release(&mut registration));
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let calls = std::cell::Cell::new(0);
    let initialize = |restored: &mut State| {
        calls.set(calls.get() + 1);
        assert_eq!((budget.reserved_bytes() - waiter_bytes), payload.len() + 1);
        let crypto = restored.crypto.read();
        assert_eq!(Arc::strong_count(&crypto), 1);
        *observer.decoded_crypto.lock() = Some(Arc::downgrade(&crypto));
        drop(crypto);
        assert!(Arc::strong_count(&kura) > observer.original_kura_owners);
        if unwind {
            panic!("injected Strict initializer unwind after actual payload/State acquisition");
        }
        // The refusal happens after the authenticated payload was decoded into
        // the restored State; the snapshot seal itself is never bypassed.
        Err(TryReadError::SnapshotResourceLimit(
            "strict initializer refused the restored State".to_owned(),
        ))
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        strict_snapshot_read_for_custody_test(&store, &state, &kura, &key, &budget, &initialize)
    }));
    if unwind {
        let Err(panic) = result else {
            panic!("the Strict initializer must reach its deliberate unwind");
        };
        assert_eq!(
            panic.downcast_ref::<&str>().copied(),
            Some("injected Strict initializer unwind after actual payload/State acquisition")
        );
    } else {
        assert!(matches!(
            result.unwrap(),
            Err(TryReadError::SnapshotResourceLimit(message))
                if message == "strict initializer refused the restored State"
        ));
    }
    assert_eq!(calls.get(), 1);
    assert_eq!(observer.wakes.load(SeqCst), 1);
    assert!(observer.saw_payload_refunded.load(SeqCst));
    assert!(observer.saw_decoded_state_released.load(SeqCst));
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert_eq!((budget.reserved_bytes() - waiter_bytes), 1);
    assert_eq!(std::fs::read(&payload_path).unwrap(), payload);
    assert_eq!(
        std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
        pointer
    );
    assert_eq!(kura.blocks_count(), 0);
    assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
    assert!(
        kura.get_block(nonzero!(1_usize), &state.ivm_execution_budget())
            .expect("empty canonical history read completes")
            .is_none()
    );

    let restored =
        strict_snapshot_read_for_custody_test(&store, &state, &kura, &key, &budget, &|restored| {
            restored
                .set_zk(state.zk_snapshot())
                .map_err(TryReadError::ZkConfigInstall)
        })
        .expect("the same pool and authenticated source remain usable after initializer failure");
    assert_eq!((budget.reserved_bytes() - waiter_bytes), 1);
    assert_eq!(
        canonical_state_snapshot_bytes_for_tests(&restored),
        canonical_state_snapshot_bytes_for_tests(&state)
    );
}

#[tokio::test]
async fn snapshot_read_buffer_strict_initializer_error_refunds_state_before_notification() {
    assert_strict_initializer_failure_refunds_before_notification(false);
}

#[tokio::test]
async fn snapshot_read_buffer_strict_initializer_unwind_refunds_state_before_notification() {
    assert_strict_initializer_failure_refunds_before_notification(true);
}

#[tokio::test]
async fn snapshot_read_buffer_concurrent_strict_and_gc_retry_after_actual_reader_release() {
    use std::{
        future::Future,
        pin::pin,
        sync::mpsc,
        task::{Context, Waker},
    };
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let state = state_factory();
    let key = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store, &key, TEST_CHUNK_SIZE).unwrap();
    let generation = current_generation_dir(&store);
    let generation_name = current_generation_name(&store);
    let payload = std::fs::read(generation.join(SNAPSHOT_FILE_NAME)).unwrap();
    let pointer = std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap();
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(payload.len() + waiter_bytes);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let kura = Kura::blank_kura_for_testing();
    let runtime = tokio::runtime::Handle::current();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (finish_tx, finish_rx) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        // An ordinary worker retains the real Strict payload in its initializer;
        // channels establish ordering without timing-dependent sleeps.
        let reader_store = &store;
        let reader_state = &state;
        let reader_kura = &kura;
        let reader_key = &key;
        let reader_budget = &budget;
        let payload_len = payload.len();
        let reader = scope.spawn(move || {
            let _runtime = runtime.enter();
            strict_snapshot_read_for_custody_test(
                reader_store,
                reader_state,
                reader_kura,
                reader_key,
                reader_budget,
                &|restored| {
                    assert_eq!((reader_budget.reserved_bytes() - waiter_bytes), payload_len);
                    entered_tx.send(()).unwrap();
                    finish_rx
                        .recv_timeout(Duration::from_secs(30))
                        .expect("release Strict initializer");
                    restored
                        .set_zk(crate::state::default_zk_config())
                        .map_err(TryReadError::ZkConfigInstall)
                },
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("Strict initializer owns the charged payload");
        assert_eq!((budget.reserved_bytes() - waiter_bytes), payload.len());
        let Err(TryWriteError::PayloadAllocation(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        })) = snapshot_generation_is_canonical_for_gc(
            &generation,
            &generation_name,
            defaults::snapshot::MAX_PAYLOAD_BYTES,
            TEST_CHUNK_SIZE,
            key.public_key(),
            &budget,
        )
        else {
            panic!("concurrent generation validation must refuse the same occupied pool");
        };
        assert_eq!(
            (requested_bytes, reserved_bytes, limit_bytes),
            (
                payload.len(),
                payload.len() + waiter_bytes,
                payload.len() + waiter_bytes
            )
        );
        let mut released = pin!(release.wait_for_release(&mut registration));
        assert!(
            released
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(
            std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
            pointer
        );
        assert_eq!(
            std::fs::read(generation.join(SNAPSHOT_FILE_NAME)).unwrap(),
            payload
        );
        assert_eq!((budget.reserved_bytes() - waiter_bytes), payload.len());
        finish_tx.send(()).unwrap();
        let restored = reader
            .join()
            .expect("ordinary Strict reader worker")
            .unwrap();
        assert_eq!((budget.reserved_bytes() - waiter_bytes), 0);
        assert!(
            released
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert!(
            snapshot_generation_is_canonical_for_gc(
                &generation,
                &generation_name,
                defaults::snapshot::MAX_PAYLOAD_BYTES,
                TEST_CHUNK_SIZE,
                key.public_key(),
                &budget,
            )
            .unwrap()
        );
        assert_eq!((budget.reserved_bytes() - waiter_bytes), 0);
        assert_eq!(
            std::fs::read(store.join(SNAPSHOT_CURRENT_FILE_NAME)).unwrap(),
            pointer
        );
        assert_eq!(
            std::fs::read(generation.join(SNAPSHOT_FILE_NAME)).unwrap(),
            payload
        );
        assert_eq!(
            canonical_state_snapshot_bytes_for_tests(&restored),
            canonical_state_snapshot_bytes_for_tests(&state)
        );
    });
}
