// Connected controls for the actual original Queue owner and State allocation pool.

fn resident_signed_input(time: &TimeSource, message_len: usize) -> AcceptedTransaction<'static> {
    resource_contract_accept(
        resource_contract_signed_log(time, message_len),
        TransactionParameters::default(), time,
    ).expect("the original signed Log input is accepted")
}

fn resident_instructions_pointer(transaction: &AcceptedTransaction<'_>) -> *const InstructionBox {
    let Executable::Instructions(instructions) = transaction.external().unwrap().instructions() else {
        panic!("the real signed input owns its nonempty instruction graph")
    };
    assert!(!instructions.is_empty());
    instructions.as_ptr()
}

/// Run the actual routing, checked-State and fee/manifest preparation before pressure.
fn resident_prepare(
    queue: &Queue, state: &State, transaction: AcceptedTransaction<'static>,
) -> PreparedQueueAdmission {
    let view = state.view();
    queue.sync_nexus_routing_with_view(&view);
    let plan = queue.router.read().try_route_plan_with_view(&transaction, &view)
        .and_then(|plan| Queue::resolve_view_routing_plan(plan, &view))
        .expect("the actual committed route");
    let checked = transaction.into_checked(&view).expect("the original input is not applied");
    let height = state_view_height_for_routing(&view).checked_add(1).unwrap();
    let mut access = EagerAdmissionStateAccess::new(
        view.world(), &view.nexus, &view.pipeline, &view, height, view.query_ledger_time_ms(),
    );
    queue.prepare_checked_for_enqueue(checked, plan, &mut access, None,
        #[cfg(feature = "telemetry")] view.telemetry,
    ).expect("original authority, fee and manifest preparation completes before pressure")
}

fn resident_fixture() -> (State, TimeSource) {
    let (state, time) = current_admission_queue_fixture();
    assert_eq!(state.view().commit_topology().len(), 4, "genuine f=1 validator authority");
    (state, time)
}

fn resident_shell_layout() -> std::alloc::Layout {
    iroha_allocation::shared::Shared::<CheckedTransaction<'static>, resident_owner::QueueResidentCharge>::layout()
}

#[test]
fn removed_pending_owner_retains_original_resident_credit_until_last_reader() {
    let (mut state, time) = resident_fixture();
    let first = resident_signed_input(&time, 256);
    let second = resident_signed_input(&time, 257);
    register_accepted_tx_authority_for_queue_test(&mut state, &first);
    let hash = first.hash_as_entrypoint();
    let canonical = first.entrypoint_bytes();
    let graph = resident_instructions_pointer(&first);
    let cost = Queue::retained_byte_cost(canonical.len());
    let mut config = config_factory();
    config.capacity = nonzero!(16_usize);
    config.capacity_per_user = nonzero!(16_usize);
    let next_cost = Queue::retained_byte_cost(second.entrypoint_bytes().len());
    config.max_retained_bytes = NonZeroU64::new(cost.max(next_cost)).unwrap();
    let queue = Queue::test(config, &time);
    let mut backpressure = queue.backpressure_handle().subscribe();
    queue.push(first, state.view()).expect("the actual first input fits residence");
    let original = queue.txs.get(&hash).unwrap().value().clone();
    let last = original.clone();
    assert!(QueuedTransaction::ptr_eq(&original, &last));
    assert_eq!(resident_instructions_pointer(original.as_accepted()), graph);
    assert!(Arc::ptr_eq(&original.entrypoint_bytes(), &canonical));
    let budget = state.ivm_execution_budget();
    let occupied = budget.reserved_bytes();
    assert!(queue.resident_accounting.get().unwrap().belongs_to(&budget));
    assert_eq!(queue.retained_bytes(), cost);
    assert!(backpressure.borrow_and_update().is_saturated());
    assert_eq!(queue.remove_committed_hashes([hash], None), 1);
    assert_eq!((queue.active_len(), queue.queued_len()), (0, 0));
    assert!(queue.tx_encoded_len.is_empty(), "the Queue metadata is genuinely retired");
    assert_eq!(queue.retained_bytes(), cost, "last readers retain the original resident credit");
    assert_eq!(budget.reserved_bytes(), occupied, "removing a slot cannot refund its live shell");
    assert!(backpressure.borrow_and_update().is_saturated());
    let refusal = queue.push(second, state.view()).expect_err("retained residence still refuses admission");
    assert!(matches!(refusal.err, Error::Full));
    assert_eq!(queue.retained_bytes(), cost);
    drop(original);
    assert_eq!(queue.retained_bytes(), cost);
    assert_eq!(budget.reserved_bytes(), occupied);
    assert!(!backpressure.has_changed().unwrap());
    assert_eq!(resident_instructions_pointer(last.as_accepted()), graph);
    assert!(Arc::ptr_eq(&last.entrypoint_bytes(), &canonical));
    drop(last);
    assert_eq!(queue.retained_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), occupied - resident_shell_layout().size());
    assert!(backpressure.has_changed().unwrap(), "the actual last refund wakes pressure observers");
    assert!(!backpressure.borrow_and_update().is_saturated());
    queue.push(*refusal.tx, state.view()).expect("same original Queue and State retry after refund");
    queue.clear_all();
    assert_eq!(queue.retained_bytes(), 0);
}

#[test]
fn original_queue_shell_refusal_preserves_graph_and_exact_release_then_retries() {
    let (mut state, time) = resident_fixture();
    let queue = Queue::test(config_factory(), &time);
    let warm = resident_signed_input(&time, 256);
    register_accepted_tx_authority_for_queue_test(&mut state, &warm);
    let warm_hash = warm.hash_as_entrypoint();
    queue.push(warm, state.view()).unwrap();
    queue.remove_committed_hashes([warm_hash], None);
    let original = resident_signed_input(&time, 257);
    let graph = resident_instructions_pointer(&original);
    let canonical = original.entrypoint_bytes();
    let hash = original.hash_as_entrypoint();
    let prepared = resident_prepare(&queue, &state, original);
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let baseline = budget.reserved_bytes();
    let held = budget.try_reserve_bytes(budget.limit_bytes() - baseline).unwrap();
    let expected = budget.try_reserve(resident_shell_layout()).unwrap_err();
    let (notifications, failure) = match queue.enqueue_prepared_admissions(vec![prepared], None, &budget) {
        Err(refused) => refused,
        Ok(_) => panic!("the actual Queue shared shell refuses the occupied original pool"),
    };
    assert!(notifications.is_empty());
    let Error::Deferred(reason) = &failure.err else { panic!("original pool refusal: {:?}", failure.err) };
    assert_eq!(reason.allocation_refusal(), Some(&expected));
    let iroha_allocation::AllocationRefusal::Capacity { release, .. } = expected else {
        panic!("actual occupied finite pool, not policy size or allocator failure")
    };
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    assert_eq!(resident_instructions_pointer(&failure.tx), graph, "the refused producer returns its original graph");
    assert!(Arc::ptr_eq(&failure.tx.entrypoint_bytes(), &canonical));
    assert_eq!(failure.tx.hash_as_entrypoint(), hash);
    assert_eq!((queue.active_len(), queue.retained_bytes()), (0, 0));
    assert!(queue.txs.is_empty());
    assert!(queue.fee_admission_reservations.lock().live_by_entrypoint.is_empty());
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(held);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    assert_eq!(budget.reserved_bytes(), baseline);
    queue.push(*failure.tx, state.view()).expect("retry uses the same released original State pool");
    let retained = queue.txs.get(&hash).unwrap();
    assert_eq!(resident_instructions_pointer(retained.as_accepted()), graph);
    assert!(Arc::ptr_eq(&retained.entrypoint_bytes(), &canonical));
    drop(retained);
    queue.clear_all();
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn first_queue_resident_ledger_refusal_keeps_original_input_and_retry_pool() {
    let (mut state, time) = resident_fixture();
    let queue = Queue::test(config_factory(), &time);
    let original = resident_signed_input(&time, 256);
    register_accepted_tx_authority_for_queue_test(&mut state, &original);
    let graph = resident_instructions_pointer(&original);
    let canonical = original.entrypoint_bytes();
    let prepared = resident_prepare(&queue, &state, original);
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let baseline = budget.reserved_bytes();
    let held = budget.try_reserve_bytes(budget.limit_bytes() - baseline).unwrap();
    let layout = iroha_allocation::ChargedShared::<QueueResidentLedger>::allocation_layout();
    let expected = budget.try_reserve(layout).unwrap_err();
    let (notifications, failure) = match queue.enqueue_prepared_admissions(vec![prepared], None, &budget) {
        Err(refused) => refused,
        Ok(_) => panic!("first counter control cannot allocate before original admission"),
    };
    assert!(notifications.is_empty());
    let Error::Deferred(reason) = &failure.err else { panic!("original ledger refusal: {:?}", failure.err) };
    assert_eq!(reason.allocation_refusal(), Some(&expected));
    let iroha_allocation::AllocationRefusal::Capacity { release, .. } = expected else {
        panic!("the actual original State pool is occupied")
    };
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    assert!(queue.resident_accounting.get().is_none());
    assert_eq!((queue.active_len(), queue.retained_bytes()), (0, 0));
    assert_eq!(resident_instructions_pointer(&failure.tx), graph);
    assert!(Arc::ptr_eq(&failure.tx.entrypoint_bytes(), &canonical));
    drop(held);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    assert_eq!(budget.reserved_bytes(), baseline);
    queue.push(*failure.tx, state.view()).expect("the same original pool admits after release");
    assert!(queue.resident_accounting.get().unwrap().belongs_to(&budget));
    queue.clear_all();
    assert_eq!(budget.reserved_bytes(), baseline + layout.size());
    drop(queue);
    assert_eq!(budget.reserved_bytes(), baseline);
}

struct ResidentFenceWake {
    queue: Arc<Queue>,
    wakes: AtomicUsize,
}

impl std::task::Wake for ResidentFenceWake {
    fn wake(self: Arc<Self>) {
        let _guard = self.queue.push_remove_lock.try_lock()
            .expect("the genuine pool refund callback follows the original Queue fence");
        let _revalidation = self.queue.nexus_revalidation_lock.try_lock()
            .expect("the same refund callback follows the original Nexus revalidation owner");
        assert_eq!(self.queue.active_len(), 0);
        assert_eq!(self.queue.retained_bytes(), 0);
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn every_queue_retirement_defers_original_refund_until_its_mutation_fence_releases() {
    for boundary in 0..4 {
        let (mut state, _) = resident_fixture();
        let (clock, time) = TimeSource::new_mock(Duration::default());
        let mut config = config_factory();
        config.transaction_time_to_live = Duration::from_secs(1);
        let queue = Arc::new(Queue::test(config, &time));
        let original = resident_signed_input(&time, 256);
        register_accepted_tx_authority_for_queue_test(&mut state, &original);
        let hash = original.hash_as_entrypoint();
        queue.push(original, state.view()).unwrap();
        let budget = state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let occupied = budget.reserved_bytes();
        let held = budget.try_reserve_bytes(budget.limit_bytes() - occupied).unwrap();
        let iroha_allocation::AllocationRefusal::Capacity { release, .. } =
            budget.try_reserve_bytes(1).unwrap_err() else { panic!("real original-pool pressure") };
        let observed = Arc::new(ResidentFenceWake { queue: Arc::clone(&queue), wakes: AtomicUsize::new(0) });
        let waker = std::task::Waker::from(Arc::clone(&observed));
        let mut context = std::task::Context::from_waker(&waker);
        assert!(registration.poll_wait(&release, &mut context).is_pending());
        match boundary {
            0 => queue.clear_all(),
            1 => { assert_eq!(queue.remove_committed_hashes([hash], None), 1); },
            2 => {
                clock.advance(Duration::from_secs(2));
                assert_eq!(queue.cull_expired_entries(time.get_unix_time()), 1);
            }
            _ => {
                clock.advance(Duration::from_secs(2));
                let router = queue.router.read().clone();
                let view = state.view();
                queue.revalidate_pending_transactions(
                    &router, &view, &view.nexus().lane_catalog, &view.nexus().dataspace_catalog, true,
                );
            }
        }
        assert_eq!(observed.wakes.load(Ordering::Relaxed), 1, "actual final shell refund wakes once");
        assert!(registration.poll_wait(&release, &mut context).is_ready());
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes() - resident_shell_layout().size());
        assert_eq!((queue.active_len(), queue.queued_len(), queue.retained_bytes()), (0, 0, 0));
        drop(held);
        assert_eq!(budget.reserved_bytes(), occupied - resident_shell_layout().size());
    }
}

#[test]
fn equal_limit_foreign_state_cannot_replace_original_queue_resident_pool() {
    let (mut original_state, time) = resident_fixture();
    let (mut foreign_state, _) = resident_fixture();
    let first = resident_signed_input(&time, 256);
    register_accepted_tx_authority_for_queue_test(&mut original_state, &first);
    let hash = first.hash_as_entrypoint();
    let queue = Queue::test(config_factory(), &time);
    queue.push(first, original_state.view()).unwrap();
    let original_owner = queue.txs.get(&hash).unwrap().value().clone();
    let original_pool = original_state.ivm_execution_budget();
    let foreign_pool = foreign_state.ivm_execution_budget();
    assert_eq!(original_pool.limit_bytes(), foreign_pool.limit_bytes());
    assert!(!original_pool.same_pool(&foreign_pool));
    let second = resident_signed_input(&time, 257);
    register_accepted_tx_authority_for_queue_test(&mut foreign_state, &second);
    let graph = resident_instructions_pointer(&second);
    let prepared = resident_prepare(&queue, &foreign_state, second);
    let original_residence = queue.retained_bytes();
    let original_physical = original_pool.reserved_bytes();
    let foreign_physical = foreign_pool.reserved_bytes();
    let (notifications, failure) = match queue.enqueue_prepared_admissions(vec![prepared], None, &foreign_pool) {
        Err(refused) => refused,
        Ok(_) => panic!("equal limits do not manufacture the original resident pool"),
    };
    assert!(notifications.is_empty());
    assert!(matches!(failure.err, Error::AdmissionInvariant { .. }));
    assert_eq!(resident_instructions_pointer(&failure.tx), graph);
    assert_eq!(queue.retained_bytes(), original_residence);
    assert_eq!(original_pool.reserved_bytes(), original_physical);
    assert_eq!(foreign_pool.reserved_bytes(), foreign_physical);
    assert!(QueuedTransaction::ptr_eq(queue.txs.get(&hash).unwrap().value(), &original_owner));
    drop(original_owner);
    queue.clear_all();
}

#[test]
fn queue_drop_keeps_original_shell_and_ledger_charges_until_detached_last_owner() {
    let (mut state, time) = resident_fixture();
    let original = resident_signed_input(&time, 256);
    register_accepted_tx_authority_for_queue_test(&mut state, &original);
    let hash = original.hash_as_entrypoint();
    let queue = Queue::test(config_factory(), &time);
    let budget = state.ivm_execution_budget();
    let prepared = resident_prepare(&queue, &state, original);
    let baseline = budget.reserved_bytes();
    queue.enqueue_prepared_admissions(vec![prepared], None, &budget)
        .unwrap_or_else(|(_, failure)| panic!("original prepared producer failed: {:?}", failure.err));
    let retained = queue.txs.get(&hash).unwrap().value().clone();
    let graph = resident_instructions_pointer(retained.as_accepted());
    let canonical = retained.entrypoint_bytes();
    let layout = iroha_allocation::ChargedShared::<QueueResidentLedger>::allocation_layout();
    assert_eq!(budget.reserved_bytes(), baseline + layout.size() + resident_shell_layout().size());
    drop(queue);
    assert_eq!(budget.reserved_bytes(), baseline + layout.size() + resident_shell_layout().size());
    assert_eq!(resident_instructions_pointer(retained.as_accepted()), graph);
    assert!(Arc::ptr_eq(&retained.entrypoint_bytes(), &canonical));
    drop(retained);
    assert_eq!(budget.reserved_bytes(), baseline, "all actual control layouts refund after last owner destruction");
}

#[test]
fn cold_queue_retirement_holds_original_fence_until_first_admission_can_publish() {
    let (mut state, time) = resident_fixture();
    let original = resident_signed_input(&time, 256);
    register_accepted_tx_authority_for_queue_test(&mut state, &original);
    let hash = original.hash_as_entrypoint();
    let graph = resident_instructions_pointer(&original);
    let canonical = original.entrypoint_bytes();
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let prepared = resident_prepare(&queue, &state, original);
    let budget = state.ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    assert!(queue.resident_accounting.get().is_none());
    std::thread::scope(|scope| {
        // Every handshake is over an actual event, with no timing assumption.
        // Channels are local to this scope so panic closes them before child join.
        let (start, started) = std::sync::mpsc::sync_channel(0);
        let (observed, observation) = std::sync::mpsc::sync_channel(0);
        let (release, released) = std::sync::mpsc::sync_channel(0);
        let admitting_queue = Arc::clone(&queue);
        let admitting_budget = budget.clone();
        let admission = scope.spawn(move || {
            if started.recv().is_err() { return; }
            let writer_available = admitting_queue.push_remove_lock.try_lock().is_some();
            if observed.send(writer_available).is_err() || released.recv().is_err() { return; }
            match admitting_queue.enqueue_prepared_admissions(vec![prepared], None, &admitting_budget) {
                Ok(notifications) => drop(notifications),
                Err((_, refusal)) => panic!("same original prepared admission failed: {:?}", refusal.err),
            }
        });
        queue.with_resident_refunds(
            || {
                start.send(()).unwrap();
                assert!(!observation.recv().unwrap(), "the independent admission thread observes the actual cold Queue fence");
                assert!(queue.resident_accounting.get().is_none());
                assert!(queue.remove_pending_hash_locked(hash, None).is_none());
                assert_eq!((queue.active_len(), queue.queued_len(), queue.retained_bytes()), (0, 0, 0));
            },
            |()| {
                assert!(queue.push_remove_lock.try_lock().is_some(), "after-unlock actions run after the original writer");
                release.send(()).unwrap();
                admission.join().expect("actual prepared admission completes after the real fence releases");
            },
        );
    });
    let retained = queue.txs.get(&hash).unwrap().value().clone();
    assert_eq!(resident_instructions_pointer(retained.as_accepted()), graph);
    assert!(Arc::ptr_eq(&retained.entrypoint_bytes(), &canonical));
    assert!(queue.resident_accounting.get().unwrap().belongs_to(&budget));
    let cost = Queue::retained_byte_cost(canonical.len());
    assert_eq!((queue.active_len(), queue.queued_len(), queue.retained_bytes()), (1, 1, cost));
    let ledger_layout = iroha_allocation::ChargedShared::<QueueResidentLedger>::allocation_layout();
    assert_eq!(budget.reserved_bytes(), baseline + ledger_layout.size() + resident_shell_layout().size());
    drop(retained);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget.reserved_bytes();
    let pressure = budget.try_reserve_bytes(budget.limit_bytes() - occupied).unwrap();
    let iroha_allocation::AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err() else {
        panic!("the first actual producer uses the original occupied finite pool")
    };
    let observed = Arc::new(ResidentFenceWake { queue: Arc::clone(&queue), wakes: AtomicUsize::new(0) });
    let waker = std::task::Waker::from(Arc::clone(&observed));
    let mut context = std::task::Context::from_waker(&waker);
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    queue.clear_all();
    assert_eq!(observed.wakes.load(Ordering::Relaxed), 1);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    assert_eq!((queue.active_len(), queue.queued_len(), queue.retained_bytes()), (0, 0, 0));
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes() - resident_shell_layout().size());
    drop(pressure);
    assert_eq!(budget.reserved_bytes(), occupied - resident_shell_layout().size());
}
