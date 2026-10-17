//! Original remote availability-row ownership under actual pool pressure and bounded driver retry.

use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_sumeragi::{availability::RowBytes, message::PayloadChunk};

fn wake_bytes() -> usize {
    iroha_allocation::ChargedShared::<ThreadWake>::allocation_layout().size()
        + ReleaseRegistration::allocation_layout().size()
}

fn fixture(
    budget: &AllocationBudget,
) -> (DriverHandle, mpsc::Receiver<Input>, PublicKey, WireMessage) {
    let block = tests::block(
        2,
        Hash32([1; 32]),
        Hash32([2; 32]),
        iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
    );
    let chunk = PayloadChunk {
        instance: block.header().instance,
        height: block.header().height,
        block_hash: block.hash(&iroha_sumeragi::testing::FakeCrypto::new()),
        index: 0,
        bytes: RowBytes::from_untrusted(vec![7; 200]).unwrap(),
    };
    let shared = Arc::new(Shared {
        node_gate: Arc::new(NodeGate::new()),
        allocation_budget: budget.clone(),
        pending_admission: Mutex::new(PendingAdmission::admit(budget, Backoff::default()).unwrap()),
        instance: block.header().instance,
        own: Vec::new(),
        ingress: Arc::new(Mutex::new(Ingress::new(IngressLimits::default()))),
        frame_limit: 1 << 20,
        status: Mutex::new(None),
        backlog: Mutex::new(Backlog::default()),
        wake: ThreadWake::admit(budget).unwrap(),
        transactions_pending: AtomicBool::new(false),
        empty_waiting: std::sync::atomic::AtomicBool::new(false),
        empty_epoch: std::sync::atomic::AtomicU64::new(0),
        alive: AtomicBool::new(true),
        stopped: Mutex::new(None),
        metrics: None,
    });
    let (sender, rx) = mpsc::channel();
    let inputs = DriverInputs {
        sender,
        wake: shared.wake.clone(),
    };
    (
        DriverHandle { shared, inputs },
        rx,
        PublicKey::new(vec![9; 48]).unwrap(),
        WireMessage::PayloadChunk(chunk),
    )
}

fn witness(message: &WireMessage) -> &RowBytes {
    let WireMessage::PayloadChunk(chunk) = message else {
        panic!("fixture row")
    };
    &chunk.bytes
}

#[test]
fn pending_remote_frame_preserves_original_backing_and_never_enters_core_early() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, message) = fixture(&budget);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    let another = message.clone();
    let canonical = message.encode().unwrap();
    assert!(handle.deliver_message(peer.clone(), message));
    assert!(handle.shared.ingress.lock().is_empty());
    let pointer = {
        let slot = handle.shared.pending_admission.lock();
        let pending = slot.message.as_ref().unwrap();
        assert_eq!(pending.message.encode().unwrap(), canonical);
        assert!(!witness(&pending.message).admitted_to(&budget));
        witness(&pending.message).as_slice().as_ptr()
    };
    assert_eq!(budget.reserved_bytes(), 4096 + wake_bytes());
    assert!(!handle.deliver_message(peer.clone(), another));
    assert!(!handle.shared.retry_pending_message(0));
    assert!(handle.shared.ingress.lock().is_empty());
    assert_eq!(budget.reserved_bytes(), 4096 + wake_bytes());
    {
        let slot = handle.shared.pending_admission.lock();
        assert_eq!(
            witness(&slot.message.as_ref().unwrap().message)
                .as_slice()
                .as_ptr(),
            pointer
        );
    }
    // Source-independent control traffic continues while the one admission slot is occupied.
    let block = tests::block(
        2,
        Hash32([1; 32]),
        Hash32([2; 32]),
        iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
    );
    let ordinary = WireMessage::Qc(tests::commit_qc(&block, Hash32([3; 32])));
    assert!(ordinary.owned_bytes_admitted_to(&budget));
    assert!(handle.deliver_message(peer, ordinary));
    assert_eq!(handle.shared.ingress.lock().len(), 1);
    handle.shared.ingress.lock().pop();
    drop(occupied);
    assert!(handle.shared.retry_pending_message(0));
    assert!(handle.shared.pending_admission.lock().message.is_none());
    let (_, admitted) = handle.shared.ingress.lock().pop().unwrap();
    assert!(witness(&admitted).admitted_to(&budget));
    assert_eq!(witness(&admitted).as_slice().as_ptr(), pointer);
    assert_eq!(admitted.encode().unwrap(), canonical);
    assert!(!handle.shared.retry_pending_message(0));
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), wake_bytes());
    drop(handle);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pending_slot_rejects_foreign_owners_and_retained_handle_cannot_revive_stopped_instance() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let foreign = AllocationBudget::new(4096);
    let (handle, _rx, peer, mut message) = fixture(&budget);
    message.admit_owned_bytes(&foreign).unwrap();
    assert!(!handle.deliver_message(peer.clone(), message));
    assert_eq!(foreign.reserved_bytes(), 0);
    assert!(handle.shared.pending_admission.lock().message.is_none());
    let (_, _, _, message) = fixture(&budget);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    assert!(handle.deliver_message(peer.clone(), message.clone()));
    assert_eq!(budget.reserved_bytes(), 4096 + wake_bytes());
    assert!(handle.shared.pending_admission.lock().message.is_some());
    drop(LoopGuard {
        shared: Arc::clone(&handle.shared),
        observer: Arc::new(tests::fakes::RecordingObserver::default()),
    });
    assert!(!handle.shared.alive.load(Ordering::Acquire));
    assert_eq!(budget.reserved_bytes(), 3896 + wake_bytes());
    assert!(!handle.deliver_message(peer, message));
    assert!(handle.shared.pending_admission.lock().message.is_none());
    assert!(handle.shared.ingress.lock().is_empty());
    drop(occupied);
    assert_eq!(budget.reserved_bytes(), wake_bytes());
    drop(handle);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn closed_instance_releases_original_witnesses_even_with_a_retained_handle() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, message) = fixture(&budget);
    assert!(handle.deliver_message(peer.clone(), message));
    assert!(budget.reserved_bytes() > wake_bytes());
    handle.shared.node_gate.close();
    let loop_owner = LoopGuard {
        shared: Arc::clone(&handle.shared),
        observer: Arc::new(traits::NoObserver),
    };
    drop(loop_owner);
    assert!(handle.shared.ingress.lock().is_empty());
    assert!(handle.shared.pending_admission.lock().message.is_none());
    assert_eq!(budget.reserved_bytes(), wake_bytes());
    let block = tests::block(
        2,
        Hash32([1; 32]),
        Hash32([2; 32]),
        iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
    );
    assert!(!handle.deliver_message(
        peer,
        WireMessage::Qc(tests::commit_qc(&block, Hash32([3; 32])))
    ));
    assert_eq!(budget.reserved_bytes(), wake_bytes());
    drop(handle);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pending_capacity_requires_original_release_despite_foreign_wake_and_huge_clock() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, message) = fixture(&budget);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    assert!(handle.deliver_message(peer, message));
    assert!(handle.shared.wake.take_pending());
    let original = {
        let slot = handle.shared.pending_admission.lock();
        let pending = slot.message.as_ref().unwrap();
        assert!(matches!(
            pending.refusal,
            ByteAdmissionError::ControlAdmission(AllocationRefusal::Capacity { .. })
        ));
        byte_admission_release(&pending.refusal).unwrap().clone()
    };
    assert_eq!(handle.shared.pending_message_wakeup(), Millis::MAX);
    let unrelated = AllocationBudget::new(1);
    drop(unrelated.try_reserve_bytes(1).unwrap());
    assert!(!handle.shared.wake.take_pending());
    handle.shared.wake.notify();
    assert!(!handle.shared.retry_pending_message(Millis::MAX));
    {
        let slot = handle.shared.pending_admission.lock();
        let pending = slot.message.as_ref().unwrap();
        assert_eq!(
            pending.failures, 1,
            "clock and foreign wake cannot attempt admission"
        );
        assert_eq!(byte_admission_release(&pending.refusal), Some(&original));
    }
    handle.shared.wake.take_pending();
    drop(occupied);
    assert!(
        handle.shared.wake.take_pending(),
        "the actual pool wakes the charged original ThreadWake"
    );
    assert!(handle.shared.retry_pending_message(0));
    handle.shared.wake.take_pending();
    drop(handle.shared.ingress.lock().pop());
    assert!(
        !handle.shared.wake.take_pending(),
        "successful admission canceled its registration"
    );
    assert_eq!(budget.reserved_bytes(), wake_bytes());
    drop(handle);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pending_buffer_to_control_refusal_keeps_exact_owner_and_replaces_source() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, message) = fixture(&budget);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    let first_relief = ChargedBuffer::<u8>::new(100, &budget).unwrap();
    let canonical = message.encode().unwrap();
    assert!(handle.deliver_message(peer, message));
    let first = {
        let slot = handle.shared.pending_admission.lock();
        let pending = slot.message.as_ref().unwrap();
        assert!(matches!(
            pending.refusal,
            ByteAdmissionError::Buffer(ChargedBufferError::Admission(
                AllocationRefusal::Capacity {
                    requested_bytes: 200,
                    ..
                }
            ))
        ));
        byte_admission_release(&pending.refusal).unwrap().clone()
    };
    drop(first_relief);
    assert!(!handle.shared.retry_pending_message(0));
    let (second, backing) = {
        let slot = handle.shared.pending_admission.lock();
        let pending = slot.message.as_ref().unwrap();
        assert!(matches!(
            pending.refusal,
            ByteAdmissionError::ControlAdmission(AllocationRefusal::Capacity { .. })
        ));
        assert_eq!(pending.failures, 2);
        assert_eq!(pending.message.encode().unwrap(), canonical);
        (
            byte_admission_release(&pending.refusal).unwrap().clone(),
            witness(&pending.message).as_slice().as_ptr(),
        )
    };
    assert_ne!(
        first, second,
        "a newer original-pool observation replaces the completed one"
    );
    assert!(!handle.shared.retry_pending_message(Millis::MAX));
    assert_eq!(
        handle
            .shared
            .pending_admission
            .lock()
            .message
            .as_ref()
            .unwrap()
            .failures,
        2
    );
    drop(occupied);
    assert!(handle.shared.retry_pending_message(0));
    let (_, admitted) = handle.shared.ingress.lock().pop().unwrap();
    assert_eq!(witness(&admitted).as_slice().as_ptr(), backing);
    assert_eq!(admitted.encode().unwrap(), canonical);
    drop((first, second, admitted, handle));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_pool_release_before_ingress_registration_is_not_lost() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, mut message) = fixture(&budget);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    let refusal = message.admit_owned_bytes(&budget).unwrap_err();
    assert!(byte_admission_release(&refusal).is_some());
    let backing = witness(&message).as_slice().as_ptr();
    // The real source changes between the actual failed admission and arming;
    // the same slot/arming method is used by decoded-message delivery.
    drop(occupied);
    {
        let mut slot = handle.shared.pending_admission.lock();
        slot.message = Some(PendingMessage {
            from: peer,
            message,
            refusal,
            failures: 1,
            retry_at: None,
        });
        slot.arm_source(&handle.shared.wake.clone().into_waker());
    }
    assert!(handle.shared.wake.take_pending());
    assert!(handle.shared.retry_pending_message(0));
    let (_, admitted) = handle.shared.ingress.lock().pop().unwrap();
    assert_eq!(witness(&admitted).as_slice().as_ptr(), backing);
    drop((admitted, handle));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn source_less_ingress_admission_retains_typed_error_and_bounded_deadline() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, mut message) = fixture(&budget);
    let WireMessage::PayloadChunk(chunk) = &mut message else {
        unreachable!()
    };
    let length = budget.limit_bytes() + 1;
    chunk.bytes = RowBytes::from_untrusted(vec![7; length]).unwrap();
    assert!(handle.deliver_message(peer, message));
    assert!(!handle.shared.retry_pending_message(100));
    assert_eq!(handle.shared.pending_message_wakeup(), 110);
    {
        let slot = handle.shared.pending_admission.lock();
        let pending = slot.message.as_ref().unwrap();
        assert!(matches!(pending.refusal, ByteAdmissionError::Buffer(
            ChargedBufferError::Admission(AllocationRefusal::ExceedsLimit { requested_bytes, .. })
        ) if requested_bytes == length));
        assert!(byte_admission_release(&pending.refusal).is_none());
    }
    assert!(!handle.shared.retry_pending_message(110));
    assert_eq!(handle.shared.pending_message_wakeup(), 130);
    budget.set_limit_bytes(2 * length + wake_bytes());
    assert!(!handle.shared.retry_pending_message(129));
    assert!(handle.shared.ingress.lock().is_empty());
    assert!(handle.shared.retry_pending_message(130));
    assert_eq!(handle.shared.pending_message_wakeup(), Millis::MAX);
    drop(handle.shared.ingress.lock().pop());
    drop(handle);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pending_shutdown_cancels_source_before_retained_handle_and_last_owner_refund() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, message) = fixture(&budget);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    assert!(handle.deliver_message(peer, message));
    let retained = handle.clone();
    handle.shared.wake.take_pending();
    drop(LoopGuard {
        shared: Arc::clone(&handle.shared),
        observer: Arc::new(traits::NoObserver),
    });
    assert!(
        !handle.shared.wake.take_pending(),
        "partial byte retirement cannot wake a canceled ingress waiter"
    );
    assert!(handle.shared.pending_admission.lock().message.is_none());
    drop(occupied);
    assert!(!handle.shared.wake.take_pending());
    drop(handle);
    assert_eq!(budget.reserved_bytes(), wake_bytes());
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn ingress_waiter_one_byte_short_refuses_spawn_before_any_worker() {
    use iroha_sumeragi::{testing::FakeValidators, types::ChainParams};
    use tests::fakes::{
        FakeBlocks, FakeBodies, FakeClock, FakeExecutor, FakeNet, FakeRecords, RecordingObserver,
    };
    let bytes = ReleaseRegistration::allocation_layout().size();
    let wake = iroha_allocation::ChargedShared::<ThreadWake>::allocation_layout().size();
    let budget = AllocationBudget::new(wake + bytes - 1);
    let validators = FakeValidators::new(4, 7, None);
    let config = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: validators.committee.clone(),
        params: ChainParams::default(),
    };
    let instance = Hash32([5; 32]);
    let key = validators.key(0);
    let record = iroha_sumeragi::safety::SafetyRecord::fresh(
        instance,
        iroha_sumeragi::testing::TEST_EPOCH.id,
        key.clone(),
        0,
        None,
    )
    .encode(&validators.crypto)
    .unwrap();
    let tip = CommittedTip {
        height: 0,
        block_hash: Hash32([1; 32]),
        result: Hash32([2; 32]),
        header: None,
        commit_qc: None,
    };
    let observer = Arc::new(RecordingObserver::default());
    let driver = Driver::new(
        Arc::new(FakeNet::default()),
        Arc::new(FakeRecords::default()),
        Arc::new(FakeBodies::default()),
        Arc::new(FakeBlocks::default()),
        Arc::new(FakeClock::default()),
        FakeExecutor::new(tip.block_hash, tip.result, config.clone()),
        observer,
    );
    let result = driver.spawn(
        DriverConfig::default(),
        DriverStart {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: budget.clone(),
            local: LocalParams::default(),
            init: Init {
                instance,
                records: vec![(key, RecordState::Present(record), false)],
                genesis_height: 0,
                demotion_window: 128,
                nonce: 1,
                tip,
                configs: vec![
                    (1, ConfigSlot::Ready(config.clone())),
                    (2, ConfigSlot::Ready(config)),
                ],
                recent_headers: Vec::new(),
            },
            signers: vec![Arc::new(validators.signer(0).clone())],
            crypto: Arc::new(validators.crypto),
        },
    );
    assert!(
        matches!(result, Err(DriverError::Admission(AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. }))
        if requested_bytes == bytes && reserved_bytes == wake && limit_bytes == wake + bytes - 1)
    );
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "startup failure retires the original wake; no worker retains it"
    );
}

#[test]
fn pending_last_handle_drop_cancels_before_original_message_refunds() {
    let budget = AllocationBudget::new(4096 + wake_bytes());
    let (handle, _rx, peer, message) = fixture(&budget);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    assert!(handle.deliver_message(peer, message));
    let wake = handle.shared.wake.clone();
    wake.take_pending();
    drop(handle);
    assert!(!wake.take_pending());
    assert_eq!(
        budget.reserved_bytes(),
        3896 + iroha_allocation::ChargedShared::<ThreadWake>::allocation_layout().size()
    );
    drop(occupied);
    assert!(!wake.take_pending());
    drop(wake);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_ingress_eviction_refunds_only_after_pending_and_ingress_mutexes_release() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
    };
    struct Probe {
        shared: Arc<Shared>,
        calls: AtomicUsize,
        blocked: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Probe independently and retain both guards through observation.
            let pending = self.shared.pending_admission.try_lock();
            let ingress = self.shared.ingress.try_lock();
            if pending.is_none() || ingress.is_none() {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    let budget = AllocationBudget::new(8192 + wake_bytes());
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let (handle, _rx, peer, first) = fixture(&budget);
    *handle.shared.ingress.lock() = Ingress::new(IngressLimits {
        per_peer: [1; 3],
        ..IngressLimits::default()
    });
    let mut second = first.clone();
    let pending = first.clone();
    assert!(handle.deliver_message(peer.clone(), first));
    second.admit_owned_bytes(&budget).unwrap();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(handle.deliver_message(peer.clone(), pending));
    let original_source = {
        let slot = handle.shared.pending_admission.lock();
        byte_admission_release(&slot.message.as_ref().unwrap().refusal)
            .unwrap()
            .clone()
    };
    let probe = Arc::new(Probe {
        shared: Arc::clone(&handle.shared),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    assert!(
        registration
            .poll_wait(&original_source, &mut context)
            .is_pending()
    );
    handle.shared.wake.take_pending();
    // The fully admitted second frame evicts the first actual owned witness.
    // The pressure owner stays live; only real ingress retirement can wake us.
    assert!(handle.deliver_message(peer, second));
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
    assert!(
        registration
            .poll_wait(&original_source, &mut context)
            .is_ready()
    );
    assert!(handle.shared.wake.take_pending());
    assert_eq!(handle.shared.ingress.lock().dropped(), 1);
    {
        let slot = handle.shared.pending_admission.lock();
        let pending = slot.message.as_ref().unwrap();
        assert_eq!(pending.failures, 1);
        assert_eq!(
            byte_admission_release(&pending.refusal),
            Some(&original_source)
        );
    }
    {
        let ingress = handle.shared.ingress.lock();
        assert_eq!(ingress.len(), 1);
    }
    registration.cancel();
    let observe = || {
        let AllocationRefusal::Capacity { release, .. } =
            budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
        else {
            panic!("actual original ingress owners occupy capacity")
        };
        release
    };
    let retry_source = observe();
    assert!(
        registration
            .poll_wait(&retry_source, &mut context)
            .is_pending()
    );
    assert!(handle.shared.retry_pending_message(0));
    assert!(handle.shared.pending_admission.lock().message.is_none());
    assert_eq!(handle.shared.ingress.lock().dropped(), 2);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
    assert!(
        registration
            .poll_wait(&retry_source, &mut context)
            .is_ready()
    );
    registration.cancel();
    let shutdown_source = observe();
    assert!(
        registration
            .poll_wait(&shutdown_source, &mut context)
            .is_pending()
    );
    drop(LoopGuard {
        shared: Arc::clone(&handle.shared),
        observer: Arc::new(traits::NoObserver),
    });
    assert_eq!(probe.calls.load(Ordering::SeqCst), 3);
    assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
    assert!(
        registration
            .poll_wait(&shutdown_source, &mut context)
            .is_ready()
    );
    assert!(handle.shared.ingress.lock().is_empty());
    assert!(handle.shared.pending_admission.lock().message.is_none());
    registration.cancel();
    drop((
        original_source,
        retry_source,
        shutdown_source,
        registration,
        waker,
        probe,
    ));
    drop(occupied);
    drop(handle);
    assert_eq!(budget.reserved_bytes(), 0);
}
