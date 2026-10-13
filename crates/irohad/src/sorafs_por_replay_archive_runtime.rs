//! Supervised finalized-PoR reputation reconciliation and optional archive compaction.
//!
//! The worker never owns archive credentials or signing material. It operates
//! through the committed reputation runtime's durable native-outcome admission
//! boundary. When finalized replay archival is configured, the same bounded
//! worker also uses the archive already qualified and installed in
//! [`sorafs_node::NodeHandle`].
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use sorafs_node::{
    NodeHandle, PorReputationReconcileOutcomeV1,
    reputation::runtime::{
        PorTerminalReputationAdmissionStateV1, PorTerminalReputationAdmissionV1,
    },
};
use std::{sync::Arc, time::Duration};
const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
/// Payload-free worker failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PorReplayArchiveWorkerErrorV1 {
    /// The selected worker mode has no valid bounded policy.
    InvalidConfiguration,
    /// Durable PoR-to-reputation admission or acknowledgement failed.
    ReputationReconciliation,
    /// Authenticated archive compaction or checkpointing failed.
    ArchiveCompaction,
}
impl std::fmt::Display for PorReplayArchiveWorkerErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => {
                "finalized PoR reputation worker configuration is invalid"
            }
            Self::ReputationReconciliation => {
                "finalized PoR reputation reconciliation failed closed"
            }
            Self::ArchiveCompaction => "finalized PoR archive compaction failed closed",
        })
    }
}
impl std::error::Error for PorReplayArchiveWorkerErrorV1 {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PorReputationWorkerModeV1 {
    ReputationOnly,
    ReputationAndArchive,
}
/// Payload-free result of one bounded worker tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PorReplayArchiveTickOutcomeV1 {
    /// Whether reconciliation is intentionally idle until runtime activation.
    pub reputation_deferred: bool,
    /// Number of exact `PoR` terminals admitted and acknowledged.
    pub reconciled_records: u32,
    /// Number of acknowledged finalized records durably archived and compacted.
    pub compacted_records: u32,
}
/// Reconcile one bounded retained PoR-terminal batch into reputation.
pub(crate) fn reconcile_reputation_once(
    node: &NodeHandle,
    admission: &dyn PorTerminalReputationAdmissionV1,
    maximum_records: u32,
) -> Result<PorReplayArchiveTickOutcomeV1, PorReplayArchiveWorkerErrorV1> {
    if maximum_records == 0 {
        return Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration);
    }
    match admission
        .activation_state()
        .map_err(|_| PorReplayArchiveWorkerErrorV1::ReputationReconciliation)?
    {
        PorTerminalReputationAdmissionStateV1::Deferred => {
            return Ok(PorReplayArchiveTickOutcomeV1 {
                reputation_deferred: true,
                reconciled_records: 0,
                compacted_records: 0,
            });
        }
        PorTerminalReputationAdmissionStateV1::Active => {}
    }
    let mut reconciled_records = 0_u32;
    for _ in 0..maximum_records {
        match node
            .reconcile_next_por_reputation_terminal(admission)
            .map_err(|_| PorReplayArchiveWorkerErrorV1::ReputationReconciliation)?
        {
            PorReputationReconcileOutcomeV1::Idle => break,
            PorReputationReconcileOutcomeV1::Reconciled { .. } => {
                reconciled_records = reconciled_records.saturating_add(1);
            }
        }
    }
    Ok(PorReplayArchiveTickOutcomeV1 {
        reputation_deferred: false,
        reconciled_records,
        compacted_records: 0,
    })
}
/// Run one bounded reconciliation and compaction tick.
pub(crate) fn reconcile_and_compact_once(
    node: &NodeHandle,
    admission: &dyn PorTerminalReputationAdmissionV1,
    maximum_records: u32,
) -> Result<PorReplayArchiveTickOutcomeV1, PorReplayArchiveWorkerErrorV1> {
    if maximum_records == 0
        || node
            .config()
            .por_replay_archive_policy()
            .is_none_or(|policy| policy.max_records_per_tick() != maximum_records)
    {
        return Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration);
    }
    let mut outcome = reconcile_reputation_once(node, admission, maximum_records)?;
    if outcome.reputation_deferred {
        return Ok(outcome);
    }
    outcome.compacted_records = node
        .compact_configured_por_replay_archive()
        .map_err(|_| PorReplayArchiveWorkerErrorV1::ArchiveCompaction)?;
    Ok(outcome)
}
fn start_supervised(
    node: NodeHandle,
    admission: Arc<dyn PorTerminalReputationAdmissionV1>,
    mode: PorReputationWorkerModeV1,
    poll_interval: Duration,
    maximum_records: u32,
    shutdown_signal: ShutdownSignal,
) -> Child {
    let task = tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let tick_node = node.clone();
                    let tick_admission = Arc::clone(&admission);
                    let result = tokio::task::spawn_blocking(move || {
                        match mode {
                            PorReputationWorkerModeV1::ReputationOnly => {
                                reconcile_reputation_once(
                                    &tick_node,
                                    tick_admission.as_ref(),
                                    maximum_records,
                                )
                            }
                            PorReputationWorkerModeV1::ReputationAndArchive => {
                                reconcile_and_compact_once(
                                    &tick_node,
                                    tick_admission.as_ref(),
                                    maximum_records,
                                )
                            }
                        }
                    })
                    .await;
                    if !matches!(result, Ok(Ok(_))) {
                        iroha_logger::error!(
                            ?mode,
                            "supervised finalized PoR reputation worker failed closed"
                        );
                        shutdown_signal.send();
                        return;
                    }
                }
                () = shutdown_signal.receive() => return,
                else => return,
            }
        }
    });
    Child::new(task, OnShutdown::Wait(SHUTDOWN_WAIT))
}
/// Start bounded durable PoR-to-reputation reconciliation without requiring
/// optional finalized replay archival.
///
/// # Errors
///
/// Returns an error for an inert cadence or record bound.
pub(crate) fn start_reputation_reconciliation(
    node: NodeHandle,
    admission: Arc<dyn PorTerminalReputationAdmissionV1>,
    poll_interval: Duration,
    maximum_records: u32,
    shutdown_signal: ShutdownSignal,
) -> Result<Child, PorReplayArchiveWorkerErrorV1> {
    if poll_interval.is_zero() || maximum_records == 0 {
        return Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration);
    }
    Ok(start_supervised(
        node,
        admission,
        PorReputationWorkerModeV1::ReputationOnly,
        poll_interval,
        maximum_records,
        shutdown_signal,
    ))
}
/// Start the bounded supervised reconciliation and compaction worker from the
/// node's exact configured archive policy.
///
/// # Errors
///
/// Returns an error when no valid archive policy is installed.
pub(crate) fn start(
    node: NodeHandle,
    admission: Arc<dyn PorTerminalReputationAdmissionV1>,
    shutdown_signal: ShutdownSignal,
) -> Result<Child, PorReplayArchiveWorkerErrorV1> {
    let policy = node
        .config()
        .por_replay_archive_policy()
        .ok_or(PorReplayArchiveWorkerErrorV1::InvalidConfiguration)?;
    let poll_interval = policy.poll_interval();
    let maximum_records = policy.max_records_per_tick();
    if poll_interval.is_zero() || maximum_records == 0 {
        return Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration);
    }
    Ok(start_supervised(
        node,
        admission,
        PorReputationWorkerModeV1::ReputationAndArchive,
        poll_interval,
        maximum_records,
        shutdown_signal,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::sorafs::{capacity::ProviderId, reputation::PorTerminalOutcomeV1};
    use sorafs_node::{
        NodeRuntimeDeps, PorFinalizedReplayArchiveBindingV1,
        PorFinalizedReplayArchiveExternalErrorV1, PorFinalizedReplayArchiveLookupV1,
        PorFinalizedReplayArchiveReceiptV1, PorFinalizedReplayArchiveRecordV1,
        PorFinalizedReplayArchiveV1,
        config::{GcConfig, PorReplayArchivePolicyV1, RepairConfig, StorageConfig},
        reputation::runtime::{ReputationJournalEnqueueOutcomeV1, ReputationRuntimeError},
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tempfile::TempDir;
    #[derive(Debug)]
    struct RejectingAdmission;
    impl PorTerminalReputationAdmissionV1 for RejectingAdmission {
        fn activation_state(
            &self,
        ) -> Result<PorTerminalReputationAdmissionStateV1, ReputationRuntimeError> {
            Ok(PorTerminalReputationAdmissionStateV1::Active)
        }
        fn record_por_terminal(
            &self,
            _provider_id: ProviderId,
            _outcome: PorTerminalOutcomeV1,
        ) -> Result<ReputationJournalEnqueueOutcomeV1, ReputationRuntimeError> {
            Err(ReputationRuntimeError::RuntimeBindingMismatch)
        }
    }
    #[derive(Debug)]
    struct DeferredAdmission {
        calls: AtomicU64,
        active: AtomicBool,
        state_error: AtomicBool,
    }
    impl PorTerminalReputationAdmissionV1 for DeferredAdmission {
        fn activation_state(
            &self,
        ) -> Result<PorTerminalReputationAdmissionStateV1, ReputationRuntimeError> {
            if self.state_error.load(Ordering::Relaxed) {
                Err(ReputationRuntimeError::RuntimeBindingMismatch)
            } else if self.active.load(Ordering::Relaxed) {
                Ok(PorTerminalReputationAdmissionStateV1::Active)
            } else {
                Ok(PorTerminalReputationAdmissionStateV1::Deferred)
            }
        }
        fn record_por_terminal(
            &self,
            _provider_id: ProviderId,
            _outcome: PorTerminalOutcomeV1,
        ) -> Result<ReputationJournalEnqueueOutcomeV1, ReputationRuntimeError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(ReputationRuntimeError::RuntimeBindingMismatch)
        }
    }
    #[derive(Debug)]
    struct IdleReplayArchive {
        binding: PorFinalizedReplayArchiveBindingV1,
    }
    impl PorFinalizedReplayArchiveV1 for IdleReplayArchive {
        fn runtime_handle(&self) -> &'static str {
            "provider://sorafs/por-replay-archive/worker"
        }
        fn binding(
            &self,
        ) -> Result<PorFinalizedReplayArchiveBindingV1, PorFinalizedReplayArchiveExternalErrorV1>
        {
            Ok(self.binding)
        }
        fn check_readiness(&self) -> Result<(), PorFinalizedReplayArchiveExternalErrorV1> {
            Ok(())
        }
        fn current_head(
            &self,
        ) -> Result<
            Option<PorFinalizedReplayArchiveReceiptV1>,
            PorFinalizedReplayArchiveExternalErrorV1,
        > {
            Ok(None)
        }
        fn append(
            &self,
            _record: &PorFinalizedReplayArchiveRecordV1,
            _expected_previous_head: Option<[u8; 32]>,
        ) -> Result<PorFinalizedReplayArchiveReceiptV1, PorFinalizedReplayArchiveExternalErrorV1>
        {
            Err(PorFinalizedReplayArchiveExternalErrorV1::Rejected)
        }
        fn lookup(
            &self,
            _challenge_id: [u8; 32],
            _expected_checkpoint_head: PorFinalizedReplayArchiveReceiptV1,
            _proof_bounds: sorafs_node::PorFinalizedReplayArchiveProofBoundsV1,
        ) -> Result<PorFinalizedReplayArchiveLookupV1, PorFinalizedReplayArchiveExternalErrorV1>
        {
            Err(PorFinalizedReplayArchiveExternalErrorV1::Rejected)
        }
    }
    fn configured_idle_node() -> (NodeHandle, TempDir) {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve the worker temp root without symlink ancestors");
        let temp = TempDir::new_in(temp_root).expect("worker tempdir");
        let key_pair =
            KeyPair::try_from_seed(vec![0xA4; 32], Algorithm::Ed25519).expect("archive key");
        let public_key = key_pair.public_key().to_bytes().1;
        let mut signing_public_key = [0_u8; 32];
        signing_public_key.copy_from_slice(public_key);
        let binding = PorFinalizedReplayArchiveBindingV1::try_new(
            [0xA1; 32],
            1,
            [0xA2; 32],
            signing_public_key,
        )
        .expect("archive binding");
        let policy = PorReplayArchivePolicyV1::try_new(
            "provider://sorafs/por-replay-archive/worker",
            binding,
            Duration::from_secs(1),
            1,
            8,
            8_192,
        )
        .expect("archive policy");
        let config = StorageConfig::builder()
            .enabled(true)
            .data_dir(temp.path().join("storage"))
            .por_replay_archive_policy(Some(policy))
            .build();
        let node = NodeHandle::try_new_with_policies_and_runtime_deps(
            config,
            RepairConfig::default(),
            GcConfig::default(),
            NodeRuntimeDeps::default()
                .with_por_finalized_replay_archive(Arc::new(IdleReplayArchive { binding })),
        )
        .expect("configured worker node");
        (node, temp)
    }
    #[test]
    fn reputation_reconciliation_does_not_require_an_archive_policy() {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical node fixture parent");
        let storage = TempDir::new_in(root).expect("private node fixture storage");
        let node = NodeHandle::new(
            StorageConfig::builder()
                .data_dir(storage.path().join("storage"))
                .build(),
        );
        assert_eq!(
            reconcile_reputation_once(&node, &RejectingAdmission, 1),
            Ok(PorReplayArchiveTickOutcomeV1 {
                reputation_deferred: false,
                reconciled_records: 0,
                compacted_records: 0,
            })
        );
        assert_eq!(
            reconcile_reputation_once(&node, &RejectingAdmission, 0),
            Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration)
        );
        assert_eq!(
            reconcile_and_compact_once(&node, &RejectingAdmission, 1),
            Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration)
        );
        let admission: Arc<dyn PorTerminalReputationAdmissionV1> = Arc::new(RejectingAdmission);
        assert!(matches!(
            start_reputation_reconciliation(
                node.clone(),
                Arc::clone(&admission),
                Duration::ZERO,
                1,
                ShutdownSignal::new(),
            ),
            Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration)
        ));
        assert!(matches!(
            start_reputation_reconciliation(
                node.clone(),
                Arc::clone(&admission),
                Duration::from_secs(1),
                0,
                ShutdownSignal::new(),
            ),
            Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration)
        ));
        assert!(matches!(
            start(node, admission, ShutdownSignal::new()),
            Err(PorReplayArchiveWorkerErrorV1::InvalidConfiguration)
        ));
    }
    #[test]
    fn worker_idles_while_reputation_is_deferred_and_fails_closed_on_state_error() {
        let (node, _temp) = configured_idle_node();
        let deferred = DeferredAdmission {
            calls: AtomicU64::new(0),
            active: AtomicBool::new(false),
            state_error: AtomicBool::new(false),
        };
        assert_eq!(
            reconcile_and_compact_once(&node, &deferred, 1),
            Ok(PorReplayArchiveTickOutcomeV1 {
                reputation_deferred: true,
                reconciled_records: 0,
                compacted_records: 0,
            })
        );
        assert_eq!(deferred.calls.load(Ordering::Relaxed), 0);
        deferred.active.store(true, Ordering::Relaxed);
        assert_eq!(
            reconcile_and_compact_once(&node, &deferred, 1),
            Ok(PorReplayArchiveTickOutcomeV1 {
                reputation_deferred: false,
                reconciled_records: 0,
                compacted_records: 0,
            })
        );
        deferred.state_error.store(true, Ordering::Relaxed);
        assert_eq!(
            reconcile_and_compact_once(&node, &deferred, 1),
            Err(PorReplayArchiveWorkerErrorV1::ReputationReconciliation)
        );
    }
}
