//! One retained autonomous source at a time inside the existing FASTPQ worker.
//!
//! The authenticated prefix is rebuilt from pinned signed genesis after restart.
//! Disk artifacts are advertisements and never advance a statement without fresh verification.
//! A local attempt budget is not a customer payment deadline or evidence of settlement.

use super::*;
use crate::{
    query::native_context_archive::{
        NativeContextArchiveError,
        fastpq_source::{NativeFastpqSourceRead, SourceReadError, SourceReadLimits},
    },
    state::{State, StateReadOnly, StateViewError},
    sumeragi::finality::{NativeFinalityCursorErrorV1, NativeFinalityCursorV1, ProofError},
};
use iroha_allocation::{AllocationRefusal, ChargedBufferError};
use iroha_config::parameters::actual::FastpqProducer;
use std::{io::ErrorKind, num::NonZeroU64};

/// Original causal operation failure; no diagnostic text is used for retry policy.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProducerError {
    #[error("FASTPQ producer attempt deadline expired")]
    Deadline,
    #[error(transparent)]
    View(#[from] StateViewError),
    #[error(transparent)]
    Finality(#[from] NativeFinalityCursorErrorV1),
    #[error(transparent)]
    Source(#[from] SourceReadError),
    #[error(transparent)]
    Durable(#[from] durable::DurableError),
    #[error(transparent)]
    Work(#[from] FastpqWorkRefusal),
    #[error("FASTPQ producer original source: {0}")]
    Identity(&'static str),
}
impl ProducerError {
    fn retryable(&self) -> bool {
        match self {
            Self::Deadline | Self::View(StateViewError::Busy(_)) => true,
            Self::Finality(NativeFinalityCursorErrorV1::Deadline) => true,
            Self::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(error))) => {
                deferred_retryable(error)
            }
            Self::Source(error) => source_retryable(error),
            Self::Durable(durable::DurableError::Storage(error)) => storage_retryable(error),
            Self::Durable(durable::DurableError::Verification(error)) => {
                verification_retryable(error)
            }
            Self::Durable(durable::DurableError::Source(error)) => work_source_retryable(error),
            Self::Work(FastpqWorkRefusal::Source(error)) => work_source_retryable(error),
            Self::Work(FastpqWorkRefusal::Prove(ProvingError::Busy)) => true,
            Self::Work(FastpqWorkRefusal::Prove(ProvingError::Verify(error))) => {
                verification_retryable(error)
            }
            Self::Work(FastpqWorkRefusal::Prove(ProvingError::Prove(error))) => {
                backend_retryable(error)
            }
            _ => false,
        }
    }
}
// Classify the original owner before its lossy VM-facing category. This is a
// worker scheduling decision, never a proof verdict or a ledger rejection.
fn deferred_retryable(error: &crate::execution_attempt::ExecutionDeferred) -> bool {
    if let Some(original) = error.allocation_refusal() {
        return allocation_retryable(original);
    }
    if error.allocator_refusal().is_some() || error.decode_refusal().is_some() {
        return true;
    }
    // No verification/history/invariant category is sufficient evidence of a
    // retryable read. The cursor explicitly owns this physical allocator case.
    matches!(
        error.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    )
}
fn allocation_retryable(error: &AllocationRefusal) -> bool {
    matches!(error, AllocationRefusal::Capacity { .. })
}
fn buffer_retryable(error: &ChargedBufferError) -> bool {
    match error {
        ChargedBufferError::Admission(error) => allocation_retryable(error),
        ChargedBufferError::Allocator { .. } => true,
    }
}
fn storage_retryable(error: &crate::kura::Error) -> bool {
    matches!(error, crate::kura::Error::FastpqArtifactQuota { .. })
        || matches!(error, crate::kura::Error::IO(error, _) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::NotFound))
}
fn backend_retryable(error: &fastpq_prover::Error) -> bool {
    match error {
        fastpq_prover::Error::ProducerBusy
        | fastpq_prover::Error::LocalAllocationUnavailable { .. } => true,
        fastpq_prover::Error::AllocationAdmission(error) => allocation_retryable(error),
        fastpq_prover::Error::AllocationBacking(
            iroha_allocation::PrepaidBufferError::Allocation(error),
        ) => buffer_retryable(error),
        _ => false,
    }
}
fn verification_retryable(error: &offline_compact::VerificationError) -> bool {
    match error {
        offline_compact::VerificationError::Verify(error) => backend_retryable(error),
        _ => false,
    }
}
fn work_source_retryable(error: &source::SourceWorkError) -> bool {
    match error {
        source::SourceWorkError::Allocation(error) => allocation_retryable(error),
        source::SourceWorkError::Preparation(error) => backend_retryable(error),
        _ => false,
    }
}
fn source_retryable(error: &SourceReadError) -> bool {
    match error {
        SourceReadError::Allocation(error) => allocation_retryable(error),
        SourceReadError::Writes(
            crate::query::native_receipts::ordinary_writes::WriteDecodeError::Admission(error),
        ) => allocation_retryable(error),
        SourceReadError::Writes(
            crate::query::native_receipts::ordinary_writes::WriteDecodeError::Materialization(
                iroha_allocation::PrepaidBufferError::Allocation(error),
            ),
        ) => buffer_retryable(error),
        SourceReadError::Lane(error)
        | SourceReadError::Archive(NativeContextArchiveError::Proof(error)) => {
            error.is_local_refusal()
        }
        SourceReadError::Workspace(norito::core::PreparedDecodeScopeError::Allocation(
            iroha_allocation::PrepaidSharedError::Allocator { .. },
        )) => true,
        SourceReadError::Buffer(error)
        | SourceReadError::Effects(
            iroha_data_model::fastpq::FastpqEffectsDecodeError::Allocation(error),
        )
        | SourceReadError::Archive(NativeContextArchiveError::Allocation(error)) => {
            buffer_retryable(error)
        }
        SourceReadError::Decode(error) => error.local_refusal().is_some(),
        SourceReadError::Archive(NativeContextArchiveError::Io(error)) => matches!(
            error.kind(),
            ErrorKind::NotFound | ErrorKind::Interrupted | ErrorKind::WouldBlock
        ),
        SourceReadError::Archive(NativeContextArchiveError::Storage(error)) => {
            storage_retryable(error)
        }
        _ => false,
    }
}

/// Retained progress of the existing worker, not a second dispatch queue or workflow.
pub(super) struct Producer {
    state: Arc<State>,
    policy: FastpqProducer,
    cursor: Option<NativeFinalityCursorV1>,
    height: u64,
    h2: Option<crate::sumeragi::certified_chain::AuthenticatedExecutionBlock>,
    source: Option<NativeFastpqSourceRead>,
    job: Option<FastpqWitnessJob>,
    completed: Option<FastpqCompletedEntry>,
    // A terminal proof/source failure stops dispatch but retains its original work owner.
    stopped: bool,
    cause: Option<ProducerError>,
}
impl Producer {
    pub(super) fn new(state: Arc<State>, policy: FastpqProducer) -> Self {
        Self {
            state,
            policy,
            cursor: None,
            height: 1,
            h2: None,
            source: None,
            job: None,
            completed: None,
            stopped: false,
            cause: None,
        }
    }
    pub(super) fn poll_interval(&self) -> std::time::Duration {
        self.policy.poll_interval
    }

    pub(super) fn attempt(
        &mut self,
        engine: &Arc<dyn FastpqProofEngine>,
        generation: u64,
        shutdown: &ShutdownSignal,
        external_shutdown: Option<&ShutdownSignal>,
    ) {
        if self.stopped || shutdown_requested(shutdown, external_shutdown) {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(self.policy.step_timeout) else {
            self.cause = Some(ProducerError::Identity(
                "attempt duration is not representable",
            ));
            self.stopped = true;
            return;
        };
        let result = self.step(engine, generation, shutdown, external_shutdown, deadline);
        if let Err(error) = result {
            let retryable = error.retryable();
            warn!(height = self.height, retryable, %error, "FASTPQ producer retains unresolved exact source");
            self.stopped = !retryable;
            self.cause = Some(error);
        } else {
            self.cause = None;
        }
    }

    fn step(
        &mut self,
        engine: &Arc<dyn FastpqProofEngine>,
        generation: u64,
        shutdown: &ShutdownSignal,
        external_shutdown: Option<&ShutdownSignal>,
        deadline: Instant,
    ) -> Result<(), ProducerError> {
        check(deadline)?;
        if let Some(completed) = self.completed.take() {
            // The generation lease held by the worker spans this exact-byte barrier.
            // Cancellation checks precede persistence; a completed barrier remains a fact.
            if shutdown_requested(shutdown, external_shutdown) {
                self.completed = Some(completed);
                return Ok(());
            }
            match completed.persist(self.state.kura()) {
                Ok(job) => self.job = Some(job),
                Err((completed, error)) => {
                    self.completed = Some(completed);
                    return Err(error.into());
                }
            }
            return check(deadline);
        }
        if let Some(job) = self.job.as_mut() {
            if job.next_statement == job.source.leaves().len() {
                // Empty manifests advance only after the complete native D7 and source
                // inventory were actually authenticated by NativeFastpqSourceRead.
                self.height = self
                    .height
                    .checked_add(1)
                    .ok_or(ProducerError::Identity("height exhausted"))?;
                self.job = None;
                return Ok(());
            }
            let (proving, verification) = engine.limits();
            if job.recover_next(self.state.kura(), proving, &verification)? {
                return check(deadline);
            }
            check(deadline)?;
            let job = self.job.take().expect("retained exact job");
            match process_job(engine, job, generation, shutdown, external_shutdown) {
                FastpqJobOutcome::Complete(completed) => self.completed = Some(completed),
                FastpqJobOutcome::Exhausted(job) => self.job = Some(job),
                FastpqJobOutcome::Deferred { job, error } => {
                    self.job = Some(job);
                    return Err(error.into());
                }
            }
            // A synchronous proof cannot be preempted. The same absolute budget is
            // checked after it, preserving the produced owner for a later finite turn.
            return check(deadline);
        }
        if let Some(read) = self.source.as_mut() {
            if let Some(source) = read.poll()? {
                self.job = Some(FastpqWitnessJob::from_recovered(source));
                self.source = None;
            }
            return check(deadline);
        }
        if u64::try_from(self.state.committed_height())
            .map_err(|_| ProducerError::Identity("committed height is not representable"))?
            < self.height.max(2)
        {
            return Ok(());
        }
        let native = if self.height == 2 {
            self.h2
                .take()
                .ok_or(ProducerError::Identity("original H2 output is missing"))?
        } else {
            let view = self.state.try_view_once()?;
            let selected = view
                .native_execution_tip()
                .ok_or(ProducerError::Identity("applied native tip is missing"))?
                .root_scope();
            let cursor = self
                .cursor
                .get_or_insert_with(|| NativeFinalityCursorV1::new(selected));
            let target = NonZeroU64::new(self.height.max(2))
                .ok_or(ProducerError::Identity("zero target"))?;
            let Some(output) = cursor.advance_to_height(
                &view,
                target,
                &self.state.ivm_execution_budget(),
                deadline,
                self.policy.max_native_steps,
            )?
            else {
                return Ok(());
            };
            if self.height == 1 {
                let genesis = cursor
                    .take_genesis_execution()
                    .ok_or(ProducerError::Identity(
                        "verified H2 omitted original genesis anchor",
                    ))?;
                self.h2 = Some(output.into_authenticated_execution());
                genesis.into_authenticated_execution()
            } else {
                output.into_authenticated_execution()
            }
        };
        let (_, verification) = engine.limits();
        self.source = Some(NativeFastpqSourceRead::new(
            self.state.kura_handle(),
            native,
            self.state.ivm_execution_budget(),
            SourceReadLimits {
                max_entries: self.policy.max_source_entries.get(),
                max_statements: self.policy.max_source_statements.get(),
                max_effects_per_statement: verification.public_statement.max_effects,
            },
        ));
        check(deadline)
    }
}
fn check(deadline: Instant) -> Result<(), ProducerError> {
    if Instant::now() >= deadline {
        Err(ProducerError::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct BusyEngine(Arc<AtomicUsize>);
    impl FastpqProofEngine for BusyEngine {
        fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
            (
                ProvingLimits::default(),
                ExecutionEffectVerificationLimits::default(),
            )
        }
        fn prove(
            &self,
            _: &SourceExecutionEffectStatement<'_>,
            _: ExpectedExecutionEffects<'_>,
            _: &AllocationBudget,
            _: &mut AllocationReservation,
        ) -> Result<FastpqProofOutput, ProvingError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ProvingError::Busy)
        }
    }

    #[test]
    fn idle_final_source_retains_original_job_across_typed_prover_capacity() {
        let (chain, original) = crate::fastpq::finalized_source::test_fixture::original_source(
            iroha_primitives::numeric::Quantity::from(100_u32),
            &[3],
        );
        drop(original);
        chain
            .state()
            .ivm_execution_budget()
            .set_limit_bytes(2 * 1024 * 1024 * 1024);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(BusyEngine(Arc::clone(&calls)));
        let mut producer = Producer::new(Arc::clone(chain.state()), FastpqProducer::default());
        let shutdown = ShutdownSignal::new();
        for _ in 0..256 {
            producer.attempt(&engine, 0, &shutdown, None);
            if calls.load(Ordering::SeqCst) >= 2 {
                break;
            }
            assert!(!producer.stopped, "{:?}", producer.cause);
        }
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "finite unchanged-source retries need no unrelated traffic"
        );
        assert_eq!(chain.state().committed_height(), 2);
        let retained = producer
            .job
            .as_ref()
            .expect("original typed capacity returns the source");
        assert_eq!(retained.next_statement, 0);
        let height = retained.height();
        let pointer = std::ptr::from_ref(retained.source.entry(0).unwrap().effects());
        producer.attempt(&engine, 0, &shutdown, None);
        assert_eq!(producer.job.as_ref().unwrap().height(), height);
        assert_eq!(
            std::ptr::from_ref(
                producer
                    .job
                    .as_ref()
                    .unwrap()
                    .source
                    .entry(0)
                    .unwrap()
                    .effects()
            ),
            pointer
        );
        assert!(matches!(
            producer.cause,
            Some(ProducerError::Work(FastpqWorkRefusal::Prove(
                ProvingError::Busy
            )))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn existing_worker_polls_final_native_tip_without_queue_or_new_block() {
        let (chain, source) = crate::fastpq::finalized_source::test_fixture::original_source(
            iroha_primitives::numeric::Quantity::from(100_u32),
            &[3],
        );
        drop(source);
        chain
            .state()
            .ivm_execution_budget()
            .set_limit_bytes(2 * 1024 * 1024 * 1024);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut policy = FastpqProducer::default();
        policy.poll_interval = std::time::Duration::from_millis(1);
        let producer = Producer::new(Arc::clone(chain.state()), policy);
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        let shutdown = ShutdownSignal::new();
        let callback_calls = Arc::clone(&calls);
        let task = spawn_worker(
            receiver,
            Arc::new(AtomicBool::new(false)),
            Some(producer),
            Arc::new(FastpqLaneGenerationLease { generation: 0 }),
            shutdown.clone(),
            None,
            move || Some(Arc::new(BusyEngine(callback_calls))),
        );
        let observed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while calls.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        shutdown.send();
        task.await.unwrap();
        assert!(
            observed.is_ok(),
            "finite original source must retry on the existing idle worker"
        );
        assert_eq!(
            chain.state().committed_height(),
            2,
            "no unrelated transaction or empty block was produced"
        );
    }

    #[test]
    fn malformed_source_and_proof_failures_are_terminal_without_text_classification() {
        assert!(!ProducerError::Source(SourceReadError::Source("capacity")).retryable());
        assert!(!ProducerError::Durable(durable::DurableError::Identity("busy")).retryable());
        assert!(
            !ProducerError::Work(FastpqWorkRefusal::Prove(ProvingError::Prove(
                fastpq_prover::Error::CommitmentMismatch
            )))
            .retryable()
        );
        assert!(!ProducerError::View(StateViewError::Changed).retryable());
        assert!(!ProducerError::View(StateViewError::Poisoned).retryable());
        assert!(ProducerError::Work(FastpqWorkRefusal::Prove(ProvingError::Busy)).retryable());
        assert!(
            ProducerError::Source(SourceReadError::Archive(NativeContextArchiveError::Io(
                std::io::Error::new(ErrorKind::NotFound, "original tape missing"),
            )))
            .retryable()
        );
    }

    #[test]
    fn expired_original_attempt_deadline_does_not_acquire_or_dispatch_source() {
        let (chain, source) = crate::fastpq::finalized_source::test_fixture::original_source(
            iroha_primitives::numeric::Quantity::from(100_u32),
            &[3],
        );
        drop(source);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(BusyEngine(Arc::clone(&calls)));
        let mut producer = Producer::new(Arc::clone(chain.state()), FastpqProducer::default());
        assert!(matches!(
            producer.step(&engine, 0, &ShutdownSignal::new(), None, Instant::now()),
            Err(ProducerError::Deadline)
        ));
        assert!(producer.cursor.is_none() && producer.source.is_none() && producer.job.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(producer.height, 1);
    }
    #[test]
    fn finality_retry_requires_original_capacity_not_its_lossy_vm_category() {
        use crate::execution_attempt::ExecutionDeferred;
        use ivm::error::ExecutionDeferral;

        fn finality(original: ExecutionDeferred) -> ProducerError {
            ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
                original,
            )))
        }
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let capacity = budget.try_reserve_bytes(1).unwrap_err();
        let error = finality(capacity.clone().into());
        assert!(error.retryable());
        let ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
            retained,
        ))) = &error
        else {
            panic!("original finality owner lost")
        };
        assert_eq!(retained.allocation_refusal(), Some(&capacity));
        drop(occupied);
        assert!(budget.try_reserve_bytes(1).is_ok());

        for original in [
            iroha_allocation::AllocationBudget::new(0)
                .try_reserve_bytes(1)
                .unwrap_err(),
            AllocationRefusal::DemandOverflow,
        ] {
            let error = finality(original.clone().into());
            assert!(
                !error.retryable(),
                "permanent original geometry cannot improve on an idle tick"
            );
            let ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
                retained,
            ))) = error
            else {
                unreachable!()
            };
            assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert_eq!(retained.allocation_refusal(), Some(&original));
        }
        for kind in [
            ExecutionDeferral::LocalInvariantViolation,
            ExecutionDeferral::ActiveMemoryCapacity,
            ExecutionDeferral::VerifierArtifactsUnavailable,
            ExecutionDeferral::VerificationCancelled,
            ExecutionDeferral::NativeVerificationMemoryUnavailable,
            ExecutionDeferral::VerifierInitializationUnavailable,
            ExecutionDeferral::CanonicalHistoryUnavailable,
            ExecutionDeferral::CanonicalHistoryCapacity,
            ExecutionDeferral::TraceOwnerUnavailable,
        ] {
            assert!(
                !finality(kind.into()).retryable(),
                "unowned or permanent kind: {kind:?}"
            );
        }
        // This exact physical allocator category is constructed by the cursor's
        // fallible buffer/key destination owners; it does not imply a pool wake.
        assert!(finality(ExecutionDeferral::AllocationUnavailable.into()).retryable());
    }

    #[test]
    fn finality_retry_preserves_original_enclosing_decoder_refusal() {
        use norito::core::{DecodeLimits, with_decode_limits_scope};
        let bytes = norito::encode_canonical(&vec![19_u8; 32]).unwrap();
        let cause = with_decode_limits_scope(
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                norito::decode_canonical_for_admission::<Vec<u8>>(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
            },
        )
        .unwrap_err();
        let original = cause.local_refusal().unwrap();
        let error = ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(
            ProofError::Deferred(original.clone().into()),
        ));
        assert!(error.retryable());
        let ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
            retained,
        ))) = error
        else {
            unreachable!()
        };
        assert_eq!(retained.decode_refusal(), Some(&original));
        assert!(
            retained.allocation_refusal().is_none(),
            "decoder cause cannot invent a pool release source"
        );
    }
}
