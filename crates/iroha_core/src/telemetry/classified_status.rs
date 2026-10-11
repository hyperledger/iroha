//! Actor-owned classified status, with bounded journal work and immutable replies.

use super::{
    Actor, BlockCommitReport, block_counts_as_non_empty, reconcile_last_reported_block_with_kura,
};
use crate::state::{
    TelemetryStatusSourceError, TelemetryStatusTarget, write_telemetry_journal_prefix,
    write_telemetry_journal_row,
};
use iroha_crypto::Hash;
use std::num::NonZeroUsize;

/// A status response owned by the actor that classified its exact applied prefix.
#[cfg(feature = "telemetry")]
#[derive(Debug)]
pub struct OwnedStatus {
    status: iroha_torii_shared::status::Status,
    classified_height: u64,
}

#[cfg(feature = "telemetry")]
impl OwnedStatus {
    /// Consume the immutable response together with its classified State height.
    /// Runtime gauges are sampled observables; block counters and Nexus share the target.
    pub fn into_parts(self) -> (iroha_torii_shared::status::Status, u64) {
        (self.status, self.classified_height)
    }
}

/// Failure to assemble a complete, exactly bound status snapshot.
#[derive(Clone, Debug, thiserror::Error)]
pub enum StatusSnapshotError {
    /// Telemetry is not enabled for this owner.
    #[error("telemetry is disabled")]
    Disabled,
    /// The existing bounded actor mailbox cannot admit another status request.
    #[error("telemetry mailbox is unavailable")]
    MailboxUnavailable,
    /// The actor ended without a response.
    #[error("telemetry actor closed")]
    ActorClosed,
    /// The original service deadline expired; no late response is accepted.
    #[error("telemetry status deadline elapsed")]
    DeadlineElapsed,
    /// State publication or a journal read was busy; no snapshot was published.
    #[error("State publication is busy")]
    StateBusy,
    /// The captured journal target, position, or witness could not be used.
    #[error("State journal snapshot is unavailable")]
    StateUnavailable,
    /// A previously classified State checkpoint changed.
    #[error("classified State journal checkpoint changed")]
    CheckpointChanged,
    /// A canonical history read could not finish under its original allocation budget.
    #[error("status history read deferred: {0}")]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// A canonical history read completed with a storage or decoding error.
    #[error("status history read failed: {0}")]
    HistoryRead(String),
    /// Kura omitted an applied block from the required prefix.
    #[error("an applied block is missing from Kura")]
    MissingBlock,
    /// The actual block sequence differs from the captured State journal.
    #[error("Kura block sequence differs from State journal")]
    JournalMismatch,
    /// A counter cannot represent the fully classified prefix.
    #[error("classified status counter overflow")]
    CounterOverflow,
    /// The shared counters or complete Network output projection are inconsistent.
    #[error("classified status counters differ from the owned prefix")]
    CounterMismatch,
}

impl From<TelemetryStatusSourceError> for StatusSnapshotError {
    fn from(error: TelemetryStatusSourceError) -> Self {
        match error {
            TelemetryStatusSourceError::Busy => Self::StateBusy,
            TelemetryStatusSourceError::Poisoned
            | TelemetryStatusSourceError::TargetChanged
            | TelemetryStatusSourceError::InvalidPosition
            | TelemetryStatusSourceError::Encoding => Self::StateUnavailable,
        }
    }
}

impl From<crate::state::StateViewError> for StatusSnapshotError {
    fn from(error: crate::state::StateViewError) -> Self {
        match error {
            crate::state::StateViewError::Busy(_) => Self::StateBusy,
            crate::state::StateViewError::Changed
            | crate::state::StateViewError::Poisoned
            | crate::state::StateViewError::Runtime(_) => Self::StateUnavailable,
        }
    }
}

#[derive(Default)]
struct ClassifiedDelta {
    accepted: u64,
    rejected: u64,
    non_empty: u64,
    latest: Option<BlockCommitReport>,
    last_non_empty_observed_at_ms: Option<u64>,
}

fn add(total: &mut u64, value: u64) -> Result<(), StatusSnapshotError> {
    *total = total
        .checked_add(value)
        .ok_or(StatusSnapshotError::CounterOverflow)?;
    Ok(())
}

/// Classify complete Network inputs only, after validating every typed output
/// and its cache. Pipeline/Time rows remain part of the executed body but never
/// add submitted-transaction counts. This check grants no execution authority.
fn network_result_counts(
    block: &iroha_data_model::block::SignedBlock,
) -> Result<(u64, u64), StatusSnapshotError> {
    block
        .validate_output_merkle_cache()
        .map_err(|_| StatusSnapshotError::CounterMismatch)?;
    let mut accepted = 0;
    let mut rejected = 0;
    for index in 0..block.network_entrypoint_count() {
        let index = u32::try_from(index).map_err(|_| StatusSnapshotError::CounterOverflow)?;
        let (_, output) = block
            .network_output_at(index)
            .ok_or(StatusSnapshotError::CounterMismatch)?;
        if output.result.is_err() {
            add(&mut rejected, 1)?;
        } else {
            add(&mut accepted, 1)?;
        }
    }
    Ok((accepted, rejected))
}

impl Actor {
    /// Read canonical history using the original State pool, retaining local retry ownership
    /// in the actor even when the waiting status request expires or is dropped.
    pub(super) fn read_status_block(
        &mut self,
        height: NonZeroUsize,
    ) -> Result<Option<iroha_data_model::block::SharedSignedBlock>, StatusSnapshotError> {
        use crate::execution_attempt::ExecutionAttemptError;
        self.status_read_refusal = None;
        match self
            .kura
            .get_block(height, &self.state.ivm_execution_budget())
        {
            Ok(block) => Ok(block),
            Err(ExecutionAttemptError::Deferred(reason)) => {
                self.status_read_refusal = Some(reason.clone());
                Err(StatusSnapshotError::Deferred(reason))
            }
            Err(ExecutionAttemptError::Rejected(error)) => {
                Err(StatusSnapshotError::HistoryRead(error.to_string()))
            }
        }
    }

    /// Finish one finite captured target even when its original HTTP waiter expires.
    /// Verified chunk progress survives; unverified chunk counters never publish.
    pub(super) async fn classify_status_target(
        &mut self,
        target: &TelemetryStatusTarget,
    ) -> Result<(), StatusSnapshotError> {
        loop {
            let chunk = self
                .state
                .telemetry_journal_chunk(target, self.last_sync_block)
                .map_err(StatusSnapshotError::from)?;
            if chunk.checkpoint != self.last_sync_hash {
                return Err(StatusSnapshotError::CheckpointChanged);
            }
            if self.metrics.block_height.get()
                != u64::try_from(self.last_sync_block)
                    .map_err(|_| StatusSnapshotError::CounterOverflow)?
            {
                return Err(StatusSnapshotError::CounterMismatch);
            }
            if chunk.start == chunk.end {
                return Ok(());
            }
            // Copy and release the report lock before any Kura access.
            let reported = *self.last_reported_block.read().await;
            let mut delta = ClassifiedDelta::default();
            let mut failure = None;
            let digest = Hash::new_from_writer(|writer| {
                write_telemetry_journal_prefix(writer, chunk.start, chunk.end)?;
                for height in chunk.start + 1..=chunk.end {
                    let mut classify = || -> Result<_, StatusSnapshotError> {
                        let block = self
                            .read_status_block(
                                NonZeroUsize::new(height)
                                    .ok_or(StatusSnapshotError::JournalMismatch)?,
                            )?
                            .ok_or(StatusSnapshotError::MissingBlock)?;
                        let header = block.header();
                        if header.height().get()
                            != u64::try_from(height)
                                .map_err(|_| StatusSnapshotError::CounterOverflow)?
                        {
                            return Err(StatusSnapshotError::JournalMismatch);
                        }
                        // TODO: authenticate exact finalized output provenance and fund
                        // complete decode/work, beyond the original shared-control charge.
                        // The journal authenticates proposal hashes, not output bytes.
                        let (approved, rejected) = network_result_counts(&block)?;
                        let mut report = reported
                            .filter(|r| r.height == height)
                            .unwrap_or_else(|| BlockCommitReport::new(&header, &self.time_source));
                        reconcile_last_reported_block_with_kura(
                            &mut report,
                            &header,
                            &self.time_source,
                        );
                        Ok((
                            header.hash(),
                            approved,
                            rejected,
                            block_counts_as_non_empty(block.as_ref()),
                            report,
                        ))
                    };
                    let outcome =
                        classify().and_then(|(hash, accepted, rejected, non_empty, report)| {
                            add(&mut delta.accepted, accepted)?;
                            add(&mut delta.rejected, rejected)?;
                            add(&mut delta.non_empty, u64::from(non_empty))?;
                            if non_empty {
                                delta.last_non_empty_observed_at_ms = Some(report.observed_at_ms);
                            }
                            delta.latest = Some(report);
                            Ok(hash)
                        });
                    match outcome {
                        Ok(hash) => write_telemetry_journal_row(writer, height, hash)?,
                        Err(error) => {
                            failure = Some(error);
                            return Err(std::io::Error::other(
                                "classified Kura chunk is unavailable",
                            ));
                        }
                    }
                }
                Ok(())
            });
            if let Some(error) = failure {
                return Err(error);
            }
            if digest.map_err(|_| StatusSnapshotError::JournalMismatch)? != chunk.digest {
                return Err(StatusSnapshotError::JournalMismatch);
            }
            let blocks = u64::try_from(chunk.end - chunk.start)
                .map_err(|_| StatusSnapshotError::CounterOverflow)?;
            self.metrics
                .block_height
                .get()
                .checked_add(blocks)
                .ok_or(StatusSnapshotError::CounterOverflow)?;
            let total = delta
                .accepted
                .checked_add(delta.rejected)
                .ok_or(StatusSnapshotError::CounterOverflow)?;
            for (label, increment) in [
                ("accepted", delta.accepted),
                ("rejected", delta.rejected),
                ("total", total),
            ] {
                self.metrics
                    .txs
                    .with_label_values(&[label])
                    .get()
                    .checked_add(increment)
                    .ok_or(StatusSnapshotError::CounterOverflow)?;
            }
            self.metrics
                .block_height_non_empty
                .get()
                .checked_add(delta.non_empty)
                .ok_or(StatusSnapshotError::CounterOverflow)?;
            let latest = delta.latest.ok_or(StatusSnapshotError::JournalMismatch)?;
            let commit_time_ms = u64::try_from(latest.commit_time.as_millis())
                .map_err(|_| StatusSnapshotError::CounterOverflow)?;
            // Preserve an authentic notification ahead of the captured State target.
            // This is the final await before publishing a fully verified chunk.
            {
                let mut report = self.last_reported_block.write().await;
                if report.is_none_or(|old| {
                    old.height < latest.height
                        || old.height == latest.height && old.hash != latest.hash
                }) {
                    *report = Some(latest);
                }
            }
            self.metrics
                .txs
                .with_label_values(&["accepted"])
                .inc_by(delta.accepted);
            self.metrics
                .txs
                .with_label_values(&["rejected"])
                .inc_by(delta.rejected);
            self.metrics.txs.with_label_values(&["total"]).inc_by(total);
            if delta.rejected != 0 {
                let now =
                    u64::try_from(self.time_source.get_unix_time().as_millis()).unwrap_or(u64::MAX);
                self.metrics
                    .record_rejected_transactions(delta.rejected, now);
            }
            self.metrics.block_height.inc_by(blocks);
            self.metrics.block_height_non_empty.inc_by(delta.non_empty);
            self.metrics
                .last_block_committed_at_ms
                .set(latest.observed_at_ms);
            self.metrics.last_commit_time_ms.set(commit_time_ms);
            if let Some(observed) = delta.last_non_empty_observed_at_ms {
                self.metrics
                    .last_non_empty_block_committed_at_ms
                    .set(observed);
            }
            self.last_sync_block = chunk.end;
            self.last_sync_hash = chunk.tip;
            #[cfg(test)]
            if let Some((entered, resume)) = self.status_chunk_barrier.take() {
                let _ = entered.send(chunk.end);
                let _ = resume.await;
            }
            if chunk.end == target.height {
                return Ok(());
            }
            // No State or report guard, block body, or detached worker is retained.
            tokio::task::yield_now().await;
        }
    }

    #[cfg(feature = "telemetry")]
    pub(super) fn owned_status(
        &self,
        target: TelemetryStatusTarget,
        build: &iroha_torii_shared::status::BuildStatus,
    ) -> Result<OwnedStatus, StatusSnapshotError> {
        let height =
            u64::try_from(target.height).map_err(|_| StatusSnapshotError::CounterOverflow)?;
        let mut status = self.metrics.status_snapshot(build);
        if self.last_sync_block != target.height
            || self.last_sync_hash != target.tip
            || status.blocks != height
        {
            return Err(StatusSnapshotError::CounterMismatch);
        }
        status.nexus = Some(iroha_torii_shared::status::NexusStatus::from(
            &target.routing_policy,
        ));
        Ok(OwnedStatus {
            status,
            classified_height: height,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staged_counter_overflow_preserves_the_previous_value() {
        let mut value = u64::MAX - 1;
        add(&mut value, 1).unwrap();
        assert!(matches!(
            add(&mut value, 1),
            Err(StatusSnapshotError::CounterOverflow)
        ));
        assert_eq!(value, u64::MAX);
    }

    // Structural output fixture only; no producer, State policy or finality claim.
    fn classified_fixture() -> iroha_data_model::block::SignedBlock {
        use iroha_crypto::HashOf;
        use iroha_data_model::{
            Level, NetworkId,
            block::{BlockHeader, builder::BlockBuilder, execution_output::*},
            events::time::{TimeEvent, TimeInterval},
            isi::Log,
            transaction::{
                FeePaymentIntent, TransactionBuilder,
                signed::{
                    SealedTransactionCommitmentPayload, SealedTransactionReveal,
                    SignedSealedTransactionCommitment, TransactionResult,
                    compute_sealed_transaction_commitment,
                },
            },
        };
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        use std::num::NonZeroU64;
        let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"classified output fixture genesis",
        )));
        let signed = |message: &str| {
            TransactionBuilder::new(
                network,
                ALICE_ID.clone(),
                FeePaymentIntent::authority(vec![], None),
            )
            .with_instructions([Log::new(Level::INFO, message.to_owned())])
            .sign(ALICE_KEYPAIR.private_key())
        };
        let reveal = signed("sealed classified source");
        let salt = [0x45; 32];
        let commitment = compute_sealed_transaction_commitment(&network, &reveal, salt, 5);
        let commitment = SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload {
                network_id: network,
                authority: ALICE_ID.clone(),
                commitment,
                reveal_after_height: 2,
                reveal_deadline_height: 5,
                nonce: None,
            },
            ALICE_KEYPAIR.private_key(),
        );
        let mut builder = BlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            Some(HashOf::from_untyped_unchecked(Hash::new(b"parent"))),
            None,
            10,
            0,
        ));
        builder.push_sealed_transaction_commitment(commitment);
        builder.push_transaction(signed("external classified source"));
        builder.push_sealed_transaction_reveal(SealedTransactionReveal::new(
            compute_sealed_transaction_commitment(&network, &reveal, salt, 5),
            reveal,
            salt,
        ));
        let mut block = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
        let trigger = |name: &str| TriggerUseV1 {
            trigger_id: name.parse().unwrap(),
            registered_at_height: 0,
            action_hash: Hash::new(name.as_bytes()),
        };
        let rows = vec![
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 0,
                result: TransactionResult::new(Ok(vec![])),
                completions: vec![],
            }),
            ExecutionOutputV1::network_output_limit_rejection(1),
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 2,
                result: TransactionResult::new(Ok(vec![])),
                completions: vec![],
            }),
            ExecutionOutputV1::pipeline_output_limit_rejection(PipelineInvocationV1 {
                event: PipelineEventPositionV1::BlockApproved,
                candidate_index: 0,
                trigger: trigger("classified_pipeline"),
            }),
            ExecutionOutputV1::time_output_limit_rejection(TimeInvocationV1 {
                schedule_index: 0,
                event: TimeEvent {
                    interval: TimeInterval {
                        since_ms: 9,
                        length_ms: 1,
                    },
                },
                trigger: trigger("classified_time"),
            }),
        ];
        attach_classified_rows(&mut block, rows);
        block
    }

    fn attach_classified_rows(
        block: &mut iroha_data_model::block::SignedBlock,
        rows: Vec<iroha_data_model::block::execution_output::ExecutionOutputV1>,
    ) {
        block
            .set_execution_outputs(
                rows,
                0,
                Default::default(),
                vec![],
                Default::default(),
                Default::default(),
                &iroha_data_model::parameter::ExecutionOutputPolicyV1::bootstrap().limits(),
            )
            .unwrap();
    }

    #[test]
    fn network_counters_include_sealed_sources_and_exclude_all_internal_failures() {
        use iroha_data_model::block::execution_output::{ExecutionOutputV1, TimeExecutionOutputV1};
        use iroha_data_model::transaction::{ExecutionStep, TransactionResult};
        use iroha_data_model::trigger::DataTriggerStep;
        let mut block = classified_fixture();
        assert_eq!(block.external_transactions().len(), 2);
        assert_eq!(block.network_entrypoint_count(), 3);
        assert_eq!(block.execution_outputs().len(), 5);
        assert_eq!(network_result_counts(&block).unwrap(), (2, 1));
        // Internal success and failure are equally excluded from transaction counters.
        let mut rows = block.execution_outputs().to_vec();
        let ExecutionOutputV1::Time(time) = &rows[4] else {
            unreachable!()
        };
        rows[4] = ExecutionOutputV1::Time(TimeExecutionOutputV1 {
            invocation: time.invocation.clone(),
            result: TransactionResult::new(Ok(vec![DataTriggerStep {
                id: time.invocation.trigger.trigger_id.clone(),
                instructions: ExecutionStep(vec![].into()),
            }])),
            failure_root: None,
            completions: vec![],
        });
        attach_classified_rows(&mut block, rows);
        assert_eq!(network_result_counts(&block).unwrap(), (2, 1));
        assert!(block_counts_as_non_empty(&block));
    }

    #[test]
    fn internal_only_activity_has_zero_network_transaction_counters() {
        let mut block = classified_fixture();
        let rows = block.execution_outputs()[3..].to_vec();
        block.set_external_entrypoints(vec![]);
        attach_classified_rows(&mut block, rows);
        assert_eq!(network_result_counts(&block).unwrap(), (0, 0));
        assert!(block_counts_as_non_empty(&block));
    }

    #[derive(norito::NoritoSchema, norito::codec::Decode, norito::codec::Encode)]
    #[norito_schema(
        name = "iroha_core::telemetry::classified_status::tests::MutableClassifiedBlock"
    )]
    struct MutableClassifiedBlock {
        signatures: iroha_data_model::block::BlockSignatures,
        payload: iroha_data_model::block::BlockPayload,
        result: Option<iroha_data_model::block::BlockResult>,
        commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
    }

    #[test]
    fn counters_refuse_missing_outputs_stale_cache_and_foreign_complete_projection() {
        use iroha_crypto::HashOf;
        use iroha_data_model::block::{SignedBlock, execution_output::ExecutionOutputV1};
        use norito::codec::{DecodeAll as _, Encode as _};
        let original = classified_fixture();
        for mutation in 0..6 {
            let mut encoded =
                MutableClassifiedBlock::decode_all(&mut original.encode().as_slice()).unwrap();
            if mutation == 0 {
                encoded.result = None;
            } else {
                let result = encoded.result.as_mut().unwrap();
                match mutation {
                    1 => result.output_merkle = Default::default(),
                    2 => {
                        result.outputs.remove(0);
                    }
                    3 => {
                        let ExecutionOutputV1::Network(row) = &mut result.outputs[1] else {
                            unreachable!()
                        };
                        row.input_index = 2;
                    }
                    4 => {
                        let ExecutionOutputV1::Time(row) = &mut result.outputs[4] else {
                            unreachable!()
                        };
                        row.invocation.trigger.registered_at_height =
                            original.header().height().get();
                    }
                    5 => {
                        encoded.payload.header.set_execution_context_hash(Some(
                            HashOf::from_untyped_unchecked(Hash::new(
                                b"foreign classified context",
                            )),
                        ));
                    }
                    _ => unreachable!(),
                }
                if mutation != 1 {
                    result.output_merkle = result.outputs.iter().map(HashOf::new).collect();
                }
            }
            let malformed = SignedBlock::decode_all(&mut encoded.encode().as_slice()).unwrap();
            let before = malformed.encode_wire().unwrap();
            assert!(
                matches!(
                    network_result_counts(&malformed),
                    Err(StatusSnapshotError::CounterMismatch)
                ),
                "mutation {mutation}"
            );
            assert_eq!(malformed.encode_wire().unwrap(), before);
        }
        assert_eq!(network_result_counts(&original).unwrap(), (2, 1));
    }
}
