//! Executor progress, exact ownership, and natural shutdown of the production gossip loop.
use super::*;
use crate::gossiper::GossipPlane;
use iroha_futures::supervisor::{Error as SupervisorError, Supervisor};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc as blocking_mpsc,
};
use tokio::{sync::oneshot, time::timeout};

// Existing completed-work controls use a test adapter; the production handler
// API separates infallible periodic work from typed incoming attempts.
enum Work<'a> {
    Tick,
    Incoming(&'a RetainedGossip<Arc<TransactionGossip>>),
}
struct CompletedHandler<F>(F);
impl<F> Handler for CompletedHandler<F>
where
    F: for<'a> FnMut(Work<'a>) + Send + 'static,
{
    fn tick(&mut self) {
        (self.0)(Work::Tick);
    }
    fn incoming(
        &mut self,
        message: &RetainedGossip<Arc<TransactionGossip>>,
    ) -> Result<(), ExecutionDeferred> {
        (self.0)(Work::Incoming(message));
        Ok(())
    }
}
fn start<F>(
    period: Duration,
    messages: mpsc::Receiver<RetainedGossip<Arc<TransactionGossip>>>,
    shutdown: ShutdownSignal,
    handle: F,
) -> Result<Child, TransactionGossiperStartError>
where
    F: for<'a> FnMut(Work<'a>) + Send + 'static,
{
    super::start(period, messages, shutdown, CompletedHandler(handle))
}

// Every physical executor control invokes the production worker directly.

fn message() -> RetainedGossip<Arc<TransactionGossip>> {
    RetainedGossip::synthetic_for_test(Arc::new(TransactionGossip {
        txs: Vec::new(),
        routes: Vec::new(),
        plans: Vec::new(),
        plane: GossipPlane::Public,
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn blocked_incoming_work_allows_executor_progress() {
    let mut supervisor = Supervisor::new();
    let shutdown = supervisor.shutdown_signal();
    let (sender, receiver) = mpsc::channel(1);
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = blocking_mpsc::channel();
    let mut entered_tx = Some(entered_tx);
    let stop = shutdown.clone();
    supervisor.monitor(
        start(Duration::from_secs(60), receiver, shutdown, move |work| {
            if let Work::Incoming(_message) = work {
                entered_tx
                    .take()
                    .expect("one incoming work item")
                    .send(())
                    .unwrap();
                release_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("another Tokio task must run while gossip work blocks");
                stop.send();
            }
        })
        .expect("valid multithreaded gossip worker"),
    );
    sender.send(message()).await.unwrap();
    // This task must run on the sole executor worker, not the test's block_on thread.
    let release = tokio::spawn(async move {
        entered_rx.await.unwrap();
        tokio::task::yield_now().await;
        release_tx.send(()).unwrap();
    });
    timeout(Duration::from_secs(5), supervisor.start())
        .await
        .unwrap()
        .unwrap();
    release.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn blocked_periodic_work_allows_executor_progress() {
    let mut supervisor = Supervisor::new();
    let shutdown = supervisor.shutdown_signal();
    let (_sender, receiver) = mpsc::channel(1);
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = blocking_mpsc::channel();
    let mut entered_tx = Some(entered_tx);
    let stop = shutdown.clone();
    supervisor.monitor(
        start(Duration::from_secs(60), receiver, shutdown, move |work| {
            assert!(matches!(work, Work::Tick));
            entered_tx
                .take()
                .expect("one periodic work item")
                .send(())
                .unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("executor must make progress");
            stop.send();
        })
        .expect("valid multithreaded gossip worker"),
    );
    let release = tokio::spawn(async move {
        entered_rx.await.unwrap();
        tokio::task::yield_now().await;
        release_tx.send(()).unwrap();
    });
    timeout(Duration::from_secs(5), supervisor.start())
        .await
        .unwrap()
        .unwrap();
    release.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn cooperative_shutdown_waits_for_owned_message_and_skips_pending_work() {
    let mut supervisor = Supervisor::new();
    let shutdown = supervisor.shutdown_signal();
    let (sender, receiver) = mpsc::channel(1);
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = blocking_mpsc::channel();
    let mut entered_tx = Some(entered_tx);
    let handled = Arc::new(AtomicUsize::new(0));
    let handled_worker = handled.clone();
    supervisor.monitor(
        start(
            Duration::from_secs(60),
            receiver,
            shutdown.clone(),
            move |work| {
                if let Work::Incoming(owned_message) = work {
                    handled_worker.fetch_add(1, Ordering::SeqCst);
                    entered_tx
                        .take()
                        .expect("shutdown must prevent a second work item")
                        .send(())
                        .unwrap();
                    release_rx
                        .recv_timeout(Duration::from_secs(2))
                        .expect("test releases physical work");
                    assert!(Arc::strong_count(owned_message.payload()) >= 1);
                }
            },
        )
        .expect("valid multithreaded gossip worker"),
    );
    let (first, transport_count) =
        RetainedGossip::with_count_for_test(Arc::clone(message().payload()));
    let first_weak = Arc::downgrade(first.payload());
    sender.send(first).await.unwrap();
    let mut supervision = tokio::spawn(supervisor.start());
    timeout(Duration::from_secs(1), entered_rx)
        .await
        .unwrap()
        .unwrap();
    sender.send(message()).await.unwrap();
    shutdown.send();
    assert!(
        timeout(Duration::from_millis(50), &mut supervision)
            .await
            .is_err(),
        "supervision must not finish while its physical operation runs"
    );
    assert!(
        first_weak.upgrade().is_some(),
        "message owner survives shutdown"
    );
    assert_eq!(
        transport_count.available_permits(),
        0,
        "transport credit survives queued and active work"
    );
    release_tx.send(()).unwrap();
    timeout(Duration::from_secs(3), supervision)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(first_weak.upgrade().is_none());
    assert_eq!(
        transport_count.available_permits(),
        1,
        "physical return releases exact credit"
    );
    assert_eq!(handled.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn already_signalled_shutdown_wins_over_ready_tick_and_message() {
    let mut supervisor = Supervisor::new();
    let shutdown = supervisor.shutdown_signal();
    let (sender, receiver) = mpsc::channel(1);
    sender.send(message()).await.unwrap();
    shutdown.send();
    supervisor.monitor(
        start(Duration::from_secs(60), receiver, shutdown, |_| {
            panic!("ready work must not start after cooperative shutdown");
        })
        .expect("valid multithreaded gossip worker"),
    );
    timeout(Duration::from_secs(1), supervisor.start())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn physical_worker_panic_remains_visible_to_supervisor() {
    let mut supervisor = Supervisor::new();
    let shutdown = supervisor.shutdown_signal();
    let (_sender, receiver) = mpsc::channel(1);
    supervisor.monitor(
        start(Duration::from_secs(60), receiver, shutdown.clone(), |_| {
            // The deadline covers unwind propagation and supervision. Inject the
            // unwind directly so process-global panic-hook I/O and backtrace
            // symbolization cannot consume that protocol-observation budget.
            std::panic::resume_unwind(Box::new("deliberate physical gossip worker failure"));
        })
        .expect("valid multithreaded gossip worker"),
    );
    let result = timeout(Duration::from_secs(1), supervisor.start())
        .await
        .unwrap();
    let report = result.expect_err("the physical worker panic must reach supervision");
    let mut contexts = report.current_contexts();
    assert!(matches!(
        contexts.next(),
        Some(SupervisorError::ChildPanicked)
    ));
    assert!(
        contexts.next().is_none(),
        "only the deliberate panic is reported"
    );
    assert!(shutdown.is_sent());
}

#[tokio::test(flavor = "current_thread")]
async fn unsupported_runtime_returns_error_before_publishing_actor() {
    let (_sender, receiver) = mpsc::channel(1);
    let result = start(
        Duration::from_secs(60),
        receiver,
        ShutdownSignal::new(),
        |_| {},
    );
    assert!(matches!(
        result,
        Err(TransactionGossiperStartError::UnsupportedRuntime)
    ));
}

#[test]
fn missing_runtime_returns_error_before_publishing_actor() {
    let (_sender, receiver) = mpsc::channel(1);
    let result = start(
        Duration::from_secs(60),
        receiver,
        ShutdownSignal::new(),
        |_| {},
    );
    assert!(matches!(
        result,
        Err(TransactionGossiperStartError::MissingRuntime)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn zero_period_returns_error_before_publishing_actor() {
    let (_sender, receiver) = mpsc::channel(1);
    let result = start(Duration::ZERO, receiver, ShutdownSignal::new(), |_| {});
    assert!(matches!(
        result,
        Err(TransactionGossiperStartError::ZeroPeriod)
    ));
}

fn actual_message(
    with_attachment: bool,
    lazy: bool,
) -> (
    RetainedGossip<Arc<TransactionGossip>>,
    Arc<tokio::sync::Semaphore>,
) {
    use crate::gossiper::{GossipRoute, GossipTransaction};
    use crate::queue::{RoutingDecision, RoutingPlan};
    use iroha_data_model::{
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        transaction::TransactionBuilder,
    };
    static NEXT_SOURCE: AtomicUsize = AtomicUsize::new(0);
    let nonce = NEXT_SOURCE.fetch_add(1, Ordering::Relaxed);
    let (signed, _) = crate::gossiper::tests::build_transaction(&format!(
        "retained original gossip retry {nonce}"
    ));
    let signed = if with_attachment {
        TransactionBuilder::from_payload(signed.payload().clone())
            .unwrap()
            .with_proof_attachments([ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("halo2/ipa", "gossip_original"),
            )])
            .unwrap()
            .sign(iroha_test_samples::ALICE_KEYPAIR.private_key())
    } else {
        signed
    };
    let mut item = GossipTransaction::from(signed);
    if lazy {
        item = GossipTransaction::lazy_from_encoded(
            item.payload(),
            item.hash().expect("locally signed fixture identity"),
        );
    }
    RetainedGossip::with_count_for_test(Arc::new(TransactionGossip {
        txs: vec![item],
        routes: vec![GossipRoute {
            lane_id: iroha_model_base::topology::LaneId::SINGLE,
            dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        }],
        plans: vec![RoutingPlan::single(RoutingDecision::default())],
        plane: GossipPlane::Public,
    }))
}

/// Check the actual post-pressure admission branch on the retained original.
fn assert_original_admission_after_pressure(
    message: &TransactionGossip,
    gossiper: &crate::gossiper::TransactionGossiper,
    with_attachment: bool,
) {
    let entrypoint = message.txs[0]
        .clone()
        .into_entrypoint_with_payload()
        .expect("retained original entrypoint decodes after pressure retires")
        .0;
    let iroha_data_model::transaction::TransactionEntrypoint::External(original) = &entrypoint
    else {
        panic!("original fixture is an external signed transaction");
    };
    let parameters = gossiper.state.transaction_admission_parameters();
    let admitted = crate::tx::AcceptedTransaction::validate_with_now(
        original,
        gossiper.state.network_id_ref(),
        Duration::ZERO,
        iroha_data_model::parameter::system::TransactionParameters::default(),
        parameters.require_crypto_policy().unwrap(),
        original.creation_time(),
    );
    assert_eq!(original.attachments().is_some(), with_attachment);
    if let Some(attachments) = original.attachments() {
        assert_eq!(attachments.actions().len(), 1);
        assert!(attachments.actions().iter().all(|action| matches!(
            &action.operation,
            iroha_data_model::transaction::signed_attachments::ActionOperationV1::TransactionProof
        )));
    }
    if with_attachment {
        // TODO(I.1, P.1, F.4): acceptance remains blocked until a complete
        // consuming route verifies the original TransactionProof relation.
        // Retrying the retained frame establishes custody, not that missing route.
        assert_eq!(
            admitted,
            Err(crate::tx::AcceptTransactionFail::SignedAttachments(
                iroha_data_model::transaction::signed_attachments::SignedAttachmentErrorV1::UnsupportedOperation {
                    action_index: 0,
                },
            )),
        );
    } else {
        assert_eq!(admitted, Ok(()), "plain original reaches current admission");
    }
}

#[test]
fn actual_gossip_reader_refusal_retains_frame_credit_and_original_until_retry() {
    for (with_attachment, lazy) in [(true, false), (true, true), (false, true)] {
        let mut gossiper =
            crate::gossiper::tests::closed_test_gossiper(std::num::NonZeroU32::new(1).unwrap());
        let (message, credit) = actual_message(with_attachment, lazy);
        let source = Arc::downgrade(message.payload());
        let frame = message.payload().txs[0].payload();
        let frame_pointer = frame.as_ptr();
        let hash = message.payload().txs[0].hash();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let pending = norito::with_decode_limits_scope(limits, || attempt(message, &mut gossiper))
            .expect("actual canonical frame/carrier reader is refused");
        let original = pending
            .original
            .decode_refusal()
            .expect("original codec owner")
            .clone();
        assert_eq!(
            original.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert!(
            matches!(original.resource_error(), norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 } if attempted > 0)
        );
        assert!(pending.original.allocation_refusal().is_none());
        assert_eq!(credit.available_permits(), 0);
        assert!(Arc::ptr_eq(
            pending.message.payload(),
            &source.upgrade().unwrap()
        ));
        assert_eq!(
            pending.message.payload().txs[0].payload().as_ptr(),
            frame_pointer
        );
        assert_eq!(pending.message.payload().txs[0].hash(), hash);
        assert_eq!(gossiper.queue.queued_len(), 0);
        assert_eq!(pending.original.decode_refusal(), Some(&original));
        let observed = Arc::clone(pending.message.payload());
        let PendingIncoming { message, original } = pending;
        drop(original);
        assert!(
            attempt(message, &mut gossiper).is_none(),
            "same original retries after pressure retires"
        );
        assert_eq!(gossiper.queue.queued_len(), usize::from(!with_attachment));
        assert_eq!(
            gossiper
                .queue
                .contains_entrypoint_hash(hash.expect("locally authored original identity")),
            !with_attachment,
        );
        assert_eq!(
            gossiper
                .queue
                .holds_entrypoint_frame(&iroha_crypto::Hash::new(frame.as_slice())),
            !with_attachment,
        );
        assert_eq!(credit.available_permits(), 1);
        assert_original_admission_after_pressure(&observed, &gossiper, with_attachment);
        drop(observed);
        assert!(source.upgrade().is_none());
        assert_eq!(frame.as_ptr(), frame_pointer);
    }
}

#[test]
fn actual_queue_deferred_retains_gossip_source_and_original_pool_until_retry() {
    let mut gossiper =
        crate::gossiper::tests::closed_test_gossiper(std::num::NonZeroU32::new(1).unwrap());
    let (message, credit) = actual_message(false, false);
    let source = Arc::downgrade(message.payload());
    let frame = message.payload().txs[0].payload();
    let hash = message.payload().txs[0].hash();
    let budget = gossiper.state.ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - baseline)
        .unwrap();
    // Observe the actual Queue producer before the gossiper maps that same
    // occupied-pool channel; no synthetic Queue::Deferred is constructed.
    let accepted = {
        let entrypoint = message.payload().txs[0]
            .clone()
            .into_entrypoint_with_payload()
            .expect("cached original entrypoint")
            .0;
        let iroha_data_model::transaction::TransactionEntrypoint::External(original) = &entrypoint
        else {
            panic!("original fixture is an external signed transaction");
        };
        crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(original.clone()))
    };
    let failure = gossiper
        .queue
        .push(accepted, gossiper.state.view())
        .expect_err("actual Queue refuses the occupied State pool");
    let crate::queue::Error::Deferred(expected) = failure.err else {
        panic!("Queue must return its local owner")
    };
    let pending =
        attempt(message, &mut gossiper).expect("actual Queue refusal propagates through gossip");
    assert_eq!(
        pending.original.allocation_refusal(),
        expected.allocation_refusal()
    );
    assert!(pending.original.allocation_refusal().is_some());
    assert!(pending.original.decode_refusal().is_none());
    assert!(Arc::ptr_eq(
        pending.message.payload(),
        &source.upgrade().unwrap()
    ));
    assert!(Arc::ptr_eq(
        &pending.message.payload().txs[0].payload(),
        &frame
    ));
    assert_eq!(pending.message.payload().txs[0].hash(), hash);
    assert_eq!(gossiper.queue.queued_len(), 0);
    assert_eq!(credit.available_permits(), 0);
    drop(occupied);
    let PendingIncoming { message, original } = pending;
    drop(original);
    assert!(attempt(message, &mut gossiper).is_none());
    assert_eq!(gossiper.queue.queued_len(), 1);
    assert_eq!(credit.available_permits(), 1);
    assert!(source.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn shutdown_cancels_actual_refused_source_without_retry_or_rejection() {
    struct RefuseAndStop {
        gossiper: crate::gossiper::TransactionGossiper,
        stop: ShutdownSignal,
        calls: Arc<AtomicUsize>,
        credit: Arc<tokio::sync::Semaphore>,
    }
    impl Handler for RefuseAndStop {
        fn tick(&mut self) {}
        fn incoming(
            &mut self,
            message: &RetainedGossip<Arc<TransactionGossip>>,
        ) -> Result<(), ExecutionDeferred> {
            assert_eq!(
                self.calls.fetch_add(1, Ordering::SeqCst),
                0,
                "shutdown never retries the pending source"
            );
            assert_eq!(self.credit.available_permits(), 0);
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
            let original = norito::with_decode_limits_scope(limits, || {
                self.gossiper.handle_retained_gossip(message)
            })
            .unwrap_err();
            assert!(original.decode_refusal().is_some());
            assert_eq!(self.gossiper.queue.queued_len(), 0);
            self.stop.send();
            Err(original)
        }
    }
    let mut supervisor = Supervisor::new();
    let stop = supervisor.shutdown_signal();
    let (sender, receiver) = mpsc::channel(1);
    let (message, credit) = actual_message(true, true);
    let source = Arc::downgrade(message.payload());
    let calls = Arc::new(AtomicUsize::new(0));
    sender.send(message).await.unwrap();
    supervisor.monitor(
        super::start(
            Duration::from_secs(60),
            receiver,
            stop.clone(),
            RefuseAndStop {
                gossiper: crate::gossiper::tests::closed_test_gossiper(
                    std::num::NonZeroU32::new(1).unwrap(),
                ),
                stop,
                calls: calls.clone(),
                credit: credit.clone(),
            },
        )
        .unwrap(),
    );
    timeout(Duration::from_secs(5), supervisor.start())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(credit.available_permits(), 1);
    assert!(source.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn periodic_retry_keeps_same_actual_source_ahead_of_waiting_incoming_work() {
    for (with_attachment, lazy) in [(true, false), (false, true)] {
        assert_periodic_retry_keeps_original_source(with_attachment, lazy).await;
    }
}

/// Exercise real worker retry for plain admission and fail-closed proof-carrier rejection.
/// The attached branch checks original-source custody; its consuming relation is still pending.
async fn assert_periodic_retry_keeps_original_source(with_attachment: bool, lazy: bool) {
    struct RetryOriginal {
        gossiper: crate::gossiper::TransactionGossiper,
        stop: ShutdownSignal,
        first: Option<oneshot::Sender<()>>,
        resume: blocking_mpsc::Receiver<()>,
        calls: Arc<AtomicUsize>,
        source: std::sync::Weak<TransactionGossip>,
        credit: Arc<tokio::sync::Semaphore>,
        with_attachment: bool,
        original_hash: iroha_crypto::HashOf<iroha_data_model::transaction::TransactionEntrypoint>,
        original_frame: Arc<Vec<u8>>,
    }
    impl Handler for RetryOriginal {
        fn tick(&mut self) {}
        fn incoming(
            &mut self,
            message: &RetainedGossip<Arc<TransactionGossip>>,
        ) -> Result<(), ExecutionDeferred> {
            assert!(
                Arc::ptr_eq(message.payload(), &self.source.upgrade().unwrap()),
                "a waiting envelope cannot replace the pending original"
            );
            assert_eq!(self.credit.available_permits(), 0);
            assert_eq!(message.payload().txs[0].hash(), Some(self.original_hash));
            assert!(Arc::ptr_eq(
                &message.payload().txs[0].payload(),
                &self.original_frame
            ));
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                let limits =
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
                let original = norito::with_decode_limits_scope(limits, || {
                    self.gossiper.handle_retained_gossip(message)
                })
                .unwrap_err();
                assert!(original.decode_refusal().is_some());
                assert_eq!(self.gossiper.queue.queued_len(), 0);
                self.first.take().unwrap().send(()).unwrap();
                return Err(original);
            }
            assert_eq!(call, 1);
            self.resume
                .recv_timeout(Duration::from_secs(5))
                .expect("test queued the waiting original before allowing retry completion");
            self.gossiper.handle_retained_gossip(message)?;
            assert_original_admission_after_pressure(
                message.payload(),
                &self.gossiper,
                self.with_attachment,
            );
            assert_eq!(
                self.gossiper.queue.queued_len(),
                usize::from(!self.with_attachment)
            );
            assert_eq!(
                self.gossiper
                    .queue
                    .contains_entrypoint_hash(self.original_hash),
                !self.with_attachment,
            );
            assert_eq!(
                self.gossiper
                    .queue
                    .holds_entrypoint_frame(&iroha_crypto::Hash::new(
                        self.original_frame.as_slice()
                    )),
                !self.with_attachment,
            );
            self.stop.send();
            Ok(())
        }
    }
    let mut supervisor = Supervisor::new();
    let stop = supervisor.shutdown_signal();
    let (sender, receiver) = mpsc::channel(1);
    let (first_sender, first_receiver) = oneshot::channel();
    let (resume_sender, resume_receiver) = blocking_mpsc::channel();
    let (message, credit) = actual_message(with_attachment, lazy);
    let source = Arc::downgrade(message.payload());
    let original_hash = message.payload().txs[0]
        .hash()
        .expect("locally authored original identity");
    let original_frame = message.payload().txs[0].payload();
    let (waiting, waiting_credit) = actual_message(false, false);
    let waiting_source = Arc::downgrade(waiting.payload());
    let calls = Arc::new(AtomicUsize::new(0));
    sender.send(message).await.unwrap();
    supervisor.monitor(
        super::start(
            Duration::from_millis(250),
            receiver,
            stop.clone(),
            RetryOriginal {
                gossiper: crate::gossiper::tests::closed_test_gossiper(
                    std::num::NonZeroU32::new(1).unwrap(),
                ),
                stop,
                first: Some(first_sender),
                resume: resume_receiver,
                calls: calls.clone(),
                source: source.clone(),
                credit: credit.clone(),
                with_attachment,
                original_hash,
                original_frame,
            },
        )
        .unwrap(),
    );
    let supervision = tokio::spawn(supervisor.start());
    timeout(Duration::from_secs(5), first_receiver)
        .await
        .unwrap()
        .unwrap();
    // The channel has room, but the worker must not start this new source while
    // the original source owns its inline retry slot. Shutdown cancels it later.
    sender.send(waiting).await.unwrap();
    resume_sender.send(()).unwrap();
    timeout(Duration::from_secs(5), supervision)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(credit.available_permits(), 1);
    assert_eq!(waiting_credit.available_permits(), 1);
    assert!(source.upgrade().is_none());
    assert!(waiting_source.upgrade().is_none());
}

#[test]
fn actual_lazy_gost_decode_preserves_capability_outcome_and_source_ownership() {
    use crate::gossiper::{GossipRoute, GossipTransaction};
    use crate::queue::{RoutingDecision, RoutingPlan};
    use iroha_crypto::{Algorithm, CryptoOperation};
    use iroha_data_model::transaction::TransactionEntrypoint;
    use norito::{codec::Encode as _, core as ncore};

    let (signed, _) = crate::gossiper::tests::build_transaction("unavailable gossip key parser");
    let item = GossipTransaction::from(signed);
    let original_frame = item.payload();
    let view = ncore::from_bytes_view(&original_frame).unwrap();
    let flags = view.flags();
    assert_eq!(flags, ncore::default_encode_flags());
    let key = iroha_test_samples::ALICE_KEYPAIR.public_key();
    let encoded_key = key.encode();
    let (_, key_payload) = key.try_to_bytes().unwrap();
    let mut algorithm_offset = None;
    ncore::visit_binary_sequence_with_count(&encoded_key, flags, key_payload.len() + 1, |span| {
        algorithm_offset.get_or_insert(span.start);
        Ok(())
    })
    .unwrap();
    let algorithm_offset = algorithm_offset.unwrap();
    let matches = view
        .as_bytes()
        .windows(encoded_key.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == encoded_key).then_some(offset))
        .collect::<Vec<_>>();
    assert!(
        !matches.is_empty(),
        "fixture must reach the actual authority key decoder"
    );
    let reframe = |tag| {
        let mut payload = view.as_bytes().to_vec();
        for &offset in &matches {
            payload[offset + algorithm_offset] = tag;
        }
        ncore::frame_bare_with_header_flags::<TransactionEntrypoint>(&payload, flags).unwrap()
    };
    // The unchanged lengths and fresh checksum form an actual canonical codec input.
    // Parser availability precedes cryptographic key validation; no validity of the
    // deliberately retagged key or its signature is claimed by this readiness test.
    let frame = reframe(Algorithm::Gost3410_2012_256ParamSetA as u8);
    let algorithm = Algorithm::Gost3410_2012_256ParamSetA;
    let capability = algorithm.require_implementation(CryptoOperation::ParsePublicKey);
    let decoded = norito::decode_canonical::<TransactionEntrypoint>(&frame);
    let error = decoded.expect_err("retagged 32-byte Ed25519 key is not a valid GOST key");
    match capability {
        Ok(()) => {
            assert!(crate::execution_attempt::crypto_public_key_decode_deferred(&error).is_none())
        }
        Err(original) => assert_eq!(
            crate::execution_attempt::crypto_public_key_decode_deferred(&error)
                .unwrap()
                .reason(),
            ivm::error::ExecutionDeferral::CryptoImplementationUnavailable(original)
        ),
    }
    let frame = Arc::new(frame);
    let frame_pointer = frame.as_ptr();
    let message = Arc::new(TransactionGossip {
        txs: vec![GossipTransaction::undecoded_frame(Arc::clone(&frame))],
        routes: vec![GossipRoute {
            lane_id: iroha_model_base::topology::LaneId::SINGLE,
            dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        }],
        plans: vec![RoutingPlan::single(RoutingDecision::default())],
        plane: GossipPlane::Public,
    });
    let source = Arc::downgrade(&message);
    let (retained, credit) = RetainedGossip::with_count_for_test(message);
    let mut gossiper =
        crate::gossiper::tests::closed_test_gossiper(std::num::NonZeroU32::new(1).unwrap());
    match capability {
        Ok(()) => {
            assert!(attempt(retained, &mut gossiper).is_none());
            assert_eq!(credit.available_permits(), 1);
            assert_eq!(gossiper.queue.queued_len(), 0);
            assert!(source.upgrade().is_none());
            eprintln!("actual GOST parser: available; malformed key rejected and source released");
        }
        Err(original) => {
            let pending =
                attempt(retained, &mut gossiper).expect("missing parser retains original source");
            let expected = ivm::error::ExecutionDeferral::CryptoImplementationUnavailable(original);
            assert_eq!(pending.original.reason(), expected);
            assert!(pending.original.decode_refusal().is_none());
            assert!(pending.original.allocation_refusal().is_none());
            assert_eq!(credit.available_permits(), 0);
            assert_eq!(gossiper.queue.queued_len(), 0);
            assert!(Arc::ptr_eq(
                pending.message.payload(),
                &source.upgrade().unwrap()
            ));
            assert_eq!(
                pending.message.payload().txs[0].payload().as_ptr(),
                frame_pointer
            );
            let PendingIncoming { message, original } = pending;
            drop(original);
            let pending = attempt(message, &mut gossiper)
                .expect("unchanged missing parser cannot become rejection");
            assert_eq!(pending.original.reason(), expected);
            assert_eq!(
                pending.message.payload().txs[0].payload().as_ptr(),
                frame_pointer
            );
            assert_eq!(gossiper.queue.queued_len(), 0);
            drop(pending);
            assert_eq!(credit.available_permits(), 1);
            assert!(source.upgrade().is_none());
            eprintln!(
                "actual GOST parser: absent; exact source retained through retry and cancellation"
            );
        }
    }
    let unknown = reframe(u8::MAX);
    let error = norito::decode_canonical::<TransactionEntrypoint>(&unknown).unwrap_err();
    assert!(crate::execution_attempt::crypto_public_key_decode_deferred(&error).is_none());
}
