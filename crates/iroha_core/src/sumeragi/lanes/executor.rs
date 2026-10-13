//! The executor of a lane instance (`specs/sumeragi_lanes.md` §3): lane execute-before-vote is
//! admission ([`super::admit`]); commit makes a block's chain facts the applied lane state; the
//! payload builder anchors a batch at the global chain's applied tip.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    sync::Arc,
    time::Duration,
};

use iroha_crypto::HashOf;
use iroha_data_model::{
    block::BlockHeader,
    sumeragi_lanes::SumeragiLaneRecord,
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use iroha_sumeragi::{
    api::ExecOutcome,
    availability::{AvailableBody, PayloadBytes},
    message::Qc,
    prepare_admission::{ExecutionAdmission, PrepareAdmission, PrepareSigningRequest},
    types::{AppliedConfig, ConfigSlot, EpochId, Hash32, HeightConfig},
};

#[cfg(test)]
use super::{Admission, admit};
use super::{
    AdmissionAttemptError, AnchorView, LANE_DEDUP_WINDOW, LaneBatch, LaneChainView,
    TransactionCheck, admit_decoded,
};
use crate::sumeragi::driver::{
    SharedCrypto,
    acquisition::{StoredAcquisition, StoredProgress},
    payload_build::PayloadBuild,
    traits::{BlockStore, Executor, PublicationError},
};
use iroha_allocation::{AllocationBudget, ChargedShared};

/// The global chain as a lane executor sees it: anchors, and a way to wait for one.
pub trait AnchorSource: AnchorView + Send + Sync {
    /// Block until the node has applied global height `height` or `timeout` passes; whether it
    /// has.
    fn wait_for(&self, height: u64, timeout: Duration) -> bool;
    /// The applied global tip: its height and block hash.
    fn tip(&self) -> (u64, HashOf<BlockHeader>);
}

/// Local reasons why a lane must retry selection instead of reporting an empty queue.
#[derive(Debug, thiserror::Error)]
pub enum LaneSelectionError {
    /// An original State/routing resource remains unavailable, with its release source.
    #[error(transparent)]
    Deferred(#[from] crate::execution_attempt::ExecutionDeferred),
    /// Pending signed inputs become eligible after the injected proposer clock advances.
    #[error("ClockAhead")]
    ClockAhead,
    /// Selection lost its original Queue or State cut and must be retried.
    #[error("lane Queue admission changed during selection")]
    Changed,
    /// Original State publication or read refusal; never an empty selection.
    #[error(transparent)]
    Publication(#[from] PublicationError),
}

/// Transactions the lane's payload builder may propose.
pub trait LaneTransactions: Send + Sync {
    /// Move-only original admission retained beside the selected payload.
    type Lease: Send;

    /// Observe only the completed actual EMPTY selection in native unit controls.
    #[cfg(test)]
    fn empty_payload_answer(&self) {}

    /// Queued transactions routed to the lane at global height `height`, oldest first, at most
    /// `max_bytes` of encoded transactions, skipping `skip`. Future-only work returns
    /// [`LaneSelectionError::ClockAhead`] so the driver retries without unrelated traffic.
    fn candidates(
        &self,
        height: u64,
        max_bytes: usize,
        skip: &BTreeSet<HashOf<TransactionEntrypoint>>,
        budget: &AllocationBudget,
    ) -> Result<(Vec<SignedTransaction>, Self::Lease), LaneSelectionError>;

    /// Retain only the prefix selected by canonical payload sizing.
    fn retain_prefix(&self, lease: &mut Self::Lease, count: usize);

    /// Recheck the original admission before encoding and every completed output lend.
    /// A false result withdraws this selected source; a local refusal retains it for retry.
    fn lease_is_current(
        &self,
        lease: &Self::Lease,
        budget: &AllocationBudget,
    ) -> Result<bool, PublicationError>;
}

/// The chain facts after a lane block: its anchor and the anchored transactions of the last
/// [`LANE_DEDUP_WINDOW`] blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ChainState {
    anchor: u64,
    window: VecDeque<(u64, Vec<HashOf<TransactionEntrypoint>>)>,
}

impl ChainState {
    fn view(&self) -> LaneChainView {
        let mut recent = BTreeMap::new();
        for (anchor, hashes) in &self.window {
            for hash in hashes {
                // Anchors never regress along the chain: later blocks overwrite.
                recent.insert(*hash, *anchor);
            }
        }
        LaneChainView {
            previous_anchor: self.anchor,
            recent,
        }
    }

    fn after(&self, anchor: u64, txs: Vec<HashOf<TransactionEntrypoint>>) -> Self {
        let mut window = self.window.clone();
        window.push_back((anchor, txs));
        while window.len() > LANE_DEDUP_WINDOW {
            window.pop_front();
        }
        Self { anchor, window }
    }
}

#[derive(Clone, Debug)]
struct Executed {
    height: u64,
    parent: Hash32,
    result: Hash32,
    admission: ExecutionAdmission,
    state: ChainState,
}

// A routing lane admits a batch; it does not execute Global AMX due-work effects.
// Only successful native lane admission constructs these immutable source facts.
// The concrete owner itself remains charged to that original lane's execution pool.
#[derive(Debug)]
struct LanePrepareAdmission {
    instance: Hash32,
    epoch: EpochId,
    height: u64,
    block_hash: Hash32,
    result: Hash32,
}

impl PrepareAdmission for LanePrepareAdmission {
    fn result(&self) -> Hash32 {
        self.result
    }
    fn check(
        &self,
        request: &PrepareSigningRequest,
    ) -> Result<(), iroha_sumeragi::crypto::SigningError> {
        if !cfg!(all(test, sumeragi_core_mutation = "HC278"))
            && (request.instance() != self.instance
                || request.epoch() != self.epoch
                || request.height() != self.height
                || request.block_hash() != self.block_hash
                || request.result() != self.result)
        {
            return Err(iroha_sumeragi::crypto::SigningError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Applied {
    height: u64,
    block_hash: Hash32,
    state: ChainState,
}

/// The executor of one lane instance.
pub struct LaneExecutor<A, C, T: LaneTransactions> {
    record: SumeragiLaneRecord,
    instance: Hash32,
    config: HeightConfig,
    anchors: Arc<A>,
    checks: C,
    transactions: Option<Arc<T>>,
    anchor_wait: Duration,
    applied: Applied,
    cache: BTreeMap<Hash32, Executed>,
    budget: AllocationBudget,
    time_source: iroha_primitives::time::TimeSource,
    admission: Option<LaneAdmission>,
    payload_build: Option<LanePayloadBuild<T::Lease>>,
    /// Exact latest local routing refusal, retained by the original lane builder.
    routing_refusal: Option<crate::execution_attempt::ExecutionDeferred>,
    /// The exact original anchor history refusal while the driver retains the lane body.
    anchor_refusal: Option<crate::execution_attempt::ExecutionDeferred>,
}

/// Keep the exact authenticated source and its one canonical decoded graph across local waits.
struct LaneAdmission {
    block_hash: Hash32,
    body: AvailableBody,
    batch: LaneBatch,
    admitted: Option<super::AdmittedLane>,
}

/// The selected source, original admission and funded encoding remain one local owner.
/// The lease grants no monetary validity: Global merge still checks expiry and duplicates.
struct LanePayloadBuild<L> {
    height: u64,
    view: u64,
    max_bytes: u32,
    job: PayloadBuild<LaneBatch>,
    lease: L,
}

/// Retained lane startup. A local refusal returns this exact prefix/read/restoration owner.
/// Only verified available bodies supply the recovered deduplication facts.
pub struct LaneRecovery<A, C, T: LaneTransactions> {
    executor: LaneExecutor<A, C, T>,
    store: Arc<dyn BlockStore>,
    crypto: SharedCrypto,
    tip: u64,
    next: u64,
    pending: Option<RecoveryRead>,
    refusal: Option<crate::execution_attempt::ExecutionDeferred>,
}

enum RecoveryRead {
    Acquiring(Qc, StoredAcquisition),
    Decoding(Qc, AvailableBody),
}

impl<A, C, T: LaneTransactions> core::fmt::Debug for LaneExecutor<A, C, T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LaneExecutor")
            .field("lane", &self.record.lane)
            .field("applied", &self.applied.height)
            .field("cached", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl<A: AnchorSource, C: TransactionCheck + Send, T: LaneTransactions> LaneExecutor<A, C, T> {
    /// The executor of `record`'s instance over the lane blocks `store` holds: the applied state
    /// is rebuilt from the stored tip and its last [`LANE_DEDUP_WINDOW`] blocks.
    ///
    /// # Errors
    /// A stored block that is missing or whose payload is not a lane batch.
    pub fn begin_recover(
        record: SumeragiLaneRecord,
        config: HeightConfig,
        instance: Hash32,
        anchors: Arc<A>,
        checks: C,
        transactions: Option<Arc<T>>,
        genesis_hash: Hash32,
        store: Arc<dyn BlockStore>,
        crypto: SharedCrypto,
        budget: AllocationBudget,
        time_source: iroha_primitives::time::TimeSource,
    ) -> LaneRecovery<A, C, T> {
        let tip = store.height();
        let next = tip
            .saturating_sub(LANE_DEDUP_WINDOW as u64)
            .saturating_add(1)
            .max(1);
        LaneRecovery {
            executor: Self {
                anchor_wait: Duration::from_millis(config.params.e_max.into()),
                record,
                config,
                instance,
                anchors,
                checks,
                transactions,
                applied: Applied {
                    height: tip,
                    block_hash: genesis_hash,
                    state: ChainState::default(),
                },
                cache: BTreeMap::new(),
                budget,
                time_source,
                admission: None,
                payload_build: None,
                routing_refusal: None,
                anchor_refusal: None,
            },
            store,
            crypto,
            tip,
            next,
            pending: None,
            refusal: None,
        }
    }

    fn finish_payload(&mut self) -> Result<Option<PayloadBytes>, PublicationError> {
        self.finish_payload_with_encoder(|batch, mut writer| {
            norito::codec::encode_adaptive_into(batch, &mut writer).map(|_| ())
        })
    }

    fn retained_payload_is_current(&self) -> Result<bool, PublicationError> {
        if cfg!(all(test, sumeragi_core_mutation = "HC272")) {
            return Ok(true);
        }
        match (&self.payload_build, &self.transactions) {
            (Some(build), Some(transactions)) => {
                transactions.lease_is_current(&build.lease, &self.budget)
            }
            _ => Ok(false),
        }
    }

    fn finish_payload_with_encoder(
        &mut self,
        encode: impl FnOnce(&LaneBatch, &mut dyn io::Write) -> Result<(), norito::Error>,
    ) -> Result<Option<PayloadBytes>, PublicationError> {
        if !self.retained_payload_is_current()? {
            self.payload_build = None;
            return Err(PublicationError::Retryable(
                "lane Queue admission retired".into(),
            ));
        }
        let build = self
            .payload_build
            .as_mut()
            .expect("retained lane payload source");
        let batch = build.job.source();
        match self.anchors.applied_hash(batch.anchor_height) {
            Some(hash) if hash == batch.anchor_hash => {}
            None => {
                return Err(PublicationError::Retryable(
                    "lane payload anchor is unavailable".into(),
                ));
            }
            Some(_) => {
                return Err(PublicationError::RecoveryRequired(
                    "lane payload anchor changed its original identity".into(),
                ));
            }
        }
        let anchor_time = self
            .anchors
            .creation_time_ms(batch.anchor_height)
            .map_err(|error| match error {
                Attempt::Deferred(original) => PublicationError::Deferred(original.into()),
                Attempt::Rejected(error) => PublicationError::RecoveryRequired(error.to_string()),
            })?
            .ok_or_else(|| {
                PublicationError::Retryable("lane payload anchor is unavailable".into())
            })?;
        let effective_time = batch.effective_time(anchor_time);
        if !cfg!(all(test, sumeragi_core_mutation = "HC269"))
            && effective_time > self.time_source.now()
        {
            return Err(PublicationError::Retryable("ClockAhead".into()));
        }
        let encoded = build.job.finish_retained(
            |batch| norito::codec::encode_adaptive_into(batch, &mut io::sink()),
            encode,
        );
        // Queue removal, expiry or publication can occur during encoding too. Recheck
        // the same original lease before returning any shared output bytes.
        if encoded.is_ok() && !self.retained_payload_is_current()? {
            self.payload_build = None;
            return Err(PublicationError::Retryable(
                "lane Queue admission retired".into(),
            ));
        }
        match encoded {
            Ok(_)
                if !cfg!(all(test, sumeragi_core_mutation = "HC269"))
                    && effective_time > self.time_source.now() =>
            {
                // Encoding may run across a local clock adjustment. Keep the completed
                // original output and withhold publication until its clock boundary returns.
                Err(PublicationError::Retryable("ClockAhead".into()))
            }
            Ok(payload) => Ok(Some(payload)),
            Err(error) if error.is_local_refusal() => Err(PublicationError::Retryable(format!(
                "lane payload admission: {error:?}"
            ))),
            Err(error) => Err(PublicationError::RecoveryRequired(format!(
                "lane payload encoding: {error:?}"
            ))),
        }
    }

    fn parent_state(&self, block: &AvailableBody) -> Option<ChainState> {
        let parent = block.header().parent_hash;
        if parent == self.applied.block_hash && block.header().height == self.applied.height + 1 {
            return Some(self.applied.state.clone());
        }
        self.cache
            .get(&parent)
            .filter(|executed| executed.height + 1 == block.header().height)
            .map(|executed| executed.state.clone())
    }

    fn run(
        &mut self,
        block: &AvailableBody,
        block_hash: &Hash32,
        parent: ChainState,
        certified: bool,
    ) -> Result<ExecOutcome, AdmissionAttemptError> {
        self.anchor_refusal = None;
        if !block.admitted_to(&self.budget)
            || block.source().instance() != self.instance
            || block.source().config() != &self.config
            || !block.header().control_witness.is_empty()
        {
            return Ok(ExecOutcome::Invalid);
        }
        if !self
            .admission
            .as_ref()
            .is_some_and(|original| original.block_hash == *block_hash && original.body == *block)
        {
            self.admission = None;
            let batch = match LaneBatch::from_payload(block.payload().as_slice()) {
                Ok(batch) => batch,
                Err(AdmissionAttemptError::Rejected(_)) => return Ok(ExecOutcome::Invalid),
                Err(error) => return Err(error),
            };
            self.admission = Some(LaneAdmission {
                block_hash: *block_hash,
                body: block.clone(),
                batch,
                admitted: None,
            });
        }
        let original = self.admission.as_mut().expect("original lane admission");
        // Applied anchor identity is permanent protocol state. Rejoin it even after an
        // earlier successful history read; local clock waits grant no new source authority.
        if original.admitted.is_some() {
            match self.anchors.applied_hash(original.batch.anchor_height) {
                Some(hash) if hash == original.batch.anchor_hash => {}
                None => {
                    return Ok(ExecOutcome::Failed(
                        "the lane block's anchor is not applied yet".into(),
                    ));
                }
                Some(_) => {
                    self.admission = None;
                    return Ok(ExecOutcome::Invalid);
                }
            }
        }
        if original.admitted.is_none() {
            let admit_original = || {
                admit_decoded(
                    &self.record,
                    &*self.anchors,
                    &parent.view(),
                    &self.checks,
                    &self.config,
                    &original.batch,
                    original.body.payload().as_slice().len(),
                )
            };
            let mut outcome = admit_original();
            if matches!(outcome, Ok(None))
                && self
                    .anchors
                    .wait_for(original.batch.anchor_height, self.anchor_wait)
            {
                outcome = admit_original();
            }
            match outcome {
                Ok(Some(admitted)) => original.admitted = Some(admitted),
                Ok(None) => {
                    return Ok(ExecOutcome::Failed(
                        "the lane block's anchor is not applied yet".into(),
                    ));
                }
                Err(AdmissionAttemptError::Rejected(error)) => {
                    iroha_logger::debug!(lane = %self.record.lane, %error, "lane block is not admissible");
                    self.admission = None;
                    return Ok(ExecOutcome::Invalid);
                }
                Err(AdmissionAttemptError::ResourceDeferred(reason)) => {
                    self.anchor_refusal = Some(reason.clone());
                    return Err(AdmissionAttemptError::ResourceDeferred(reason));
                }
                Err(error) => return Err(error),
            }
        }
        if !certified
            && !cfg!(all(test, sumeragi_core_mutation = "HC268"))
            && original
                .admitted
                .as_ref()
                .expect("original admitted lane")
                .effective_time
                .saturating_sub(self.time_source.now())
                > self.record.params.max_clock_drift()
        {
            return Ok(ExecOutcome::Failed("ClockAhead".into()));
        }
        // Reserve before consuming the retained decoded admission. A local shortage
        // leaves the same original available body and admitted batch ready to retry.
        let mut reservation = self
            .budget
            .try_reserve_bytes(ChargedShared::<LanePrepareAdmission>::allocation_layout().size())
            .map_err(|error| {
                let reason = crate::execution_attempt::ExecutionDeferred::from(error);
                self.anchor_refusal = Some(reason.clone());
                AdmissionAttemptError::ResourceDeferred(reason)
            })?;
        let shell = ChargedShared::<LanePrepareAdmission>::reserve_from(&mut reservation).map_err(
            |error| {
                let reason: crate::execution_attempt::ExecutionDeferred = match error {
                    iroha_allocation::PrepaidSharedError::Allocator { .. } => {
                        ivm::ExecutionDeferral::AllocationUnavailable.into()
                    }
                    iroha_allocation::PrepaidSharedError::Reservation(_) => {
                        ivm::ExecutionDeferral::ActiveMemoryCapacity.into()
                    }
                };
                self.anchor_refusal = Some(reason.clone());
                AdmissionAttemptError::ResourceDeferred(reason)
            },
        )?;
        let original = self
            .admission
            .take()
            .expect("original completed lane admission");
        let result = original.admitted.expect("original admitted lane").result;
        let r = result.hash();
        let admission = ExecutionAdmission::from_owner(
            shell
                .initialize(LanePrepareAdmission {
                    instance: self.instance,
                    epoch: self.config.epoch.id,
                    height: block.header().height,
                    block_hash: *block_hash,
                    result: r,
                })
                .project::<dyn PrepareAdmission>(|value| value),
        );
        let state = parent.after(result.anchor_height, result.tx_hashes);
        self.cache.insert(
            *block_hash,
            Executed {
                height: block.header().height,
                parent: block.header().parent_hash,
                result: r,
                admission: admission.clone(),
                state,
            },
        );
        Ok(ExecOutcome::Valid {
            result: r,
            admission,
        })
    }
}

impl<A: AnchorSource, C: TransactionCheck + Send, T: LaneTransactions> LaneRecovery<A, C, T> {
    /// Continue the same startup owner, preserving every completed prefix and partial read.
    ///
    /// # Errors
    /// Returns this exact job on temporary refusal or corrupt historical data. Only WouldBlock
    /// is retryable; the caller reports other errors instead of starting from an empty state.
    #[allow(
        clippy::result_large_err,
        reason = "retain exact lane recovery ownership"
    )]
    pub fn complete(mut self) -> Result<LaneExecutor<A, C, T>, (Self, io::Error)> {
        match self.advance() {
            Ok(()) => Ok(self.executor),
            Err(error) => {
                let error = crate::sumeragi::storage_attempt::retained_io(error, &mut self.refusal);
                Err((self, error))
            }
        }
    }
    fn advance(&mut self) -> Result<(), Attempt<io::Error>> {
        while self.next <= self.tip {
            if self.pending.is_none() {
                let entry = self.store.entry(self.next)?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "committed lane entry missing")
                })?;
                let source = self
                    .store
                    .availability_source(self.next, entry.commit_qc.block_hash)?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "lane recovery authority unresolved",
                        )
                    })?;
                if source.config() != &self.executor.config {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "lane recovery authority differs from activated incarnation",
                    )
                    .into());
                }
                let job = StoredAcquisition::begin(&*self.store, source).map_err(recovery_error)?;
                self.pending = Some(RecoveryRead::Acquiring(entry.commit_qc, job));
            }
            if let Some(RecoveryRead::Acquiring(_, job)) = self.pending.as_mut() {
                let progress = job
                    .poll(&self.executor.budget, &*self.crypto)
                    .map_err(recovery_error)?;
                match progress {
                    StoredProgress::Pending(error) => {
                        return Err(crate::sumeragi::storage_attempt::byte(error));
                    }
                    StoredProgress::Absent => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "committed lane body missing",
                        )
                        .into());
                    }
                    StoredProgress::Available(body) => {
                        let Some(RecoveryRead::Acquiring(qc, _)) = self.pending.take() else {
                            unreachable!("retained original lane restoration");
                        };
                        self.pending = Some(RecoveryRead::Decoding(qc, body));
                    }
                }
            }
            let Some(RecoveryRead::Decoding(qc, body)) = self.pending.as_ref() else {
                unreachable!("original authenticated body remains owned through decode");
            };
            let batch = match LaneBatch::from_payload(body.payload().as_slice()) {
                Ok(batch) => batch,
                Err(AdmissionAttemptError::Deferred(_)) => {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock).into());
                }
                Err(AdmissionAttemptError::ResourceDeferred(reason)) => {
                    return Err(Attempt::Deferred(reason));
                }
                Err(AdmissionAttemptError::Rejected(error)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error).into());
                }
            };
            self.executor.applied.state = self.executor.applied.state.after(
                batch.anchor_height,
                batch
                    .transactions
                    .iter()
                    .map(SignedTransaction::hash_as_entrypoint)
                    .collect(),
            );
            self.executor.applied.block_hash = qc.block_hash;
            self.pending = None;
            self.next = self.next.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "lane height overflow")
            })?;
        }
        Ok(())
    }
}
fn recovery_error(error: crate::sumeragi::driver::acquisition::StoredError) -> Attempt<io::Error> {
    use crate::sumeragi::driver::acquisition::StoredError;
    match error {
        StoredError::Read(error) => error.into_attempt(),
        StoredError::Restoration(error) => crate::sumeragi::storage_attempt::restoration(error),
        error => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("lane recovery: {error:?}"),
        )
        .into(),
    }
}

impl<A: AnchorSource, C: TransactionCheck + Send, T: LaneTransactions> Executor
    for LaneExecutor<A, C, T>
{
    fn build_control_witness(
        &mut self,
        _: &iroha_sumeragi::api::ControlWitnessContext,
    ) -> Result<iroha_sumeragi::types::ControlWitness, PublicationError> {
        // Lane validity requires EMPTY; no global control producer exists in this instance.
        Ok(iroha_sumeragi::types::ControlWitness::empty())
    }

    fn drive_control(
        &mut self,
        _: &iroha_sumeragi::api::ApplicationControlContext,
    ) -> Result<Option<iroha_sumeragi::message::ApplicationControl>, PublicationError> {
        Ok(None)
    }

    fn receive_application_control(
        &mut self,
        _: &iroha_sumeragi::types::PublicKey,
        _: &iroha_sumeragi::message::ApplicationControl,
    ) -> Result<(), PublicationError> {
        // Discard unsolicited sideframes. They cannot create state or authorize lane work.
        Ok(())
    }

    fn execute(
        &mut self,
        block: &AvailableBody,
        block_hash: &Hash32,
        certified: bool,
    ) -> Option<ExecOutcome> {
        if !block.admitted_to(&self.budget)
            || block.source().instance() != self.instance
            || block.source().config() != &self.config
        {
            return Some(ExecOutcome::Invalid);
        }
        if let Some(executed) = self.cache.get(block_hash) {
            return Some(ExecOutcome::Valid {
                result: executed.result,
                admission: executed.admission.clone(),
            });
        }
        let parent = self.parent_state(block)?;
        match self.run(block, block_hash, parent, certified) {
            Ok(outcome) => Some(outcome),
            Err(_) => None,
        }
    }

    fn discard(&mut self, height: u64, keep: &[Hash32]) {
        if self.admission.as_ref().is_some_and(|original| {
            original.body.header().height == height && !keep.contains(&original.block_hash)
        }) {
            self.admission = None;
        }
        self.cache
            .retain(|hash, executed| executed.height != height || keep.contains(hash));
    }

    fn prepare(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<Option<Hash32>, PublicationError> {
        if !block.admitted_to(&self.budget)
            || block.source().instance() != self.instance
            || block.source().config() != &self.config
        {
            return Err(PublicationError::RecoveryRequired(
                "lane publication changed its original custody authority".into(),
            ));
        }
        let hash = commit_qc.block_hash;
        if let Some(executed) = self.cache.get(&hash)
            && executed.parent == self.applied.block_hash
        {
            return Ok((executed.result == commit_qc.result).then_some(executed.result));
        }
        let Some(parent) = self.parent_state(block) else {
            return Err(PublicationError::Retryable(
                "the committed lane block's parent is not applied".into(),
            ));
        };
        match self.run(block, &hash, parent, true) {
            Ok(ExecOutcome::Valid { result, .. }) => {
                Ok((result == commit_qc.result).then_some(result))
            }
            Ok(ExecOutcome::Invalid | ExecOutcome::Cancelled) => Ok(None),
            Ok(ExecOutcome::Failed(reason)) => Err(PublicationError::Retryable(reason)),
            Err(AdmissionAttemptError::ResourceDeferred(reason)) => {
                Err(PublicationError::Deferred(reason.into()))
            }
            // Allocate no diagnostic while the driver retains its original body for retry.
            Err(AdmissionAttemptError::Deferred(_)) => {
                Err(PublicationError::Retryable(String::new()))
            }
            Err(AdmissionAttemptError::Rejected(_)) => {
                unreachable!("completed rejection is Invalid")
            }
        }
    }

    fn commit(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<AppliedConfig, PublicationError> {
        if !block.admitted_to(&self.budget)
            || block.source().instance() != self.instance
            || block.source().config() != &self.config
        {
            return Err(PublicationError::RecoveryRequired(
                "lane apply changed its original custody authority".into(),
            ));
        }
        let executed = self.cache.remove(&commit_qc.block_hash).ok_or_else(|| {
            PublicationError::Retryable("the committed lane block is not prepared".into())
        })?;
        self.applied = Applied {
            height: block.header().height,
            block_hash: commit_qc.block_hash,
            state: executed.state,
        };
        let height = self.applied.height;
        self.cache.retain(|_, executed| executed.height > height);
        Ok(AppliedConfig::Continuation {
            after_next: ConfigSlot::Ready(self.config.clone()),
        })
    }

    fn build(
        &mut self,
        height: u64,
        view: u64,
        max_bytes: u32,
        _exec_budget_ms: u32,
    ) -> Result<Option<PayloadBytes>, PublicationError> {
        if self
            .payload_build
            .as_ref()
            .is_some_and(|p| p.height == height && p.view == view && p.max_bytes == max_bytes)
            && self.retained_payload_is_current()?
        {
            return self.finish_payload();
        }
        self.payload_build = None;
        let Some(transactions) = self.transactions.as_ref() else {
            return Ok(None);
        };
        let (anchor_height, anchor_hash) = self.anchors.tip();
        if !self.record.admits_anchor(anchor_height) || anchor_height < self.applied.state.anchor {
            return Ok(None);
        }
        // Skip what the lane still carries: recent blocks the global chain may merge fresh, and
        // executed, uncommitted blocks.
        let chain_view = self.applied.state.view();
        let mut skip = chain_view
            .recent
            .keys()
            .filter(|hash| chain_view.repeats(hash, anchor_height, self.record.anchor_freshness))
            .copied()
            .collect::<BTreeSet<_>>();
        for executed in self.cache.values() {
            if let Some((_, hashes)) = executed.state.window.back() {
                skip.extend(hashes.iter().copied());
            }
        }
        // Leave room for the batch framing; the data model owns the reserve so queue
        // admission and SDK preflight use the same value.
        let budget = usize::try_from(max_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(
                iroha_data_model::parameter::system::LANE_BATCH_FRAMING_RESERVE_BYTES as usize,
            );
        // The batch merges after the anchor: route as of the next global height.
        let (selected, mut lease) = match transactions.candidates(
            anchor_height.saturating_add(1),
            budget,
            &skip,
            &self.budget,
        ) {
            Ok(selected) => {
                self.routing_refusal = None;
                selected
            }
            Err(LaneSelectionError::Deferred(reason)) => {
                let message = reason.to_string();
                self.routing_refusal = Some(reason);
                return Err(PublicationError::Retryable(message));
            }
            Err(LaneSelectionError::ClockAhead) => {
                self.routing_refusal = None;
                if cfg!(all(test, sumeragi_core_mutation = "HC264")) {
                    return Ok(None);
                }
                return Err(PublicationError::Retryable("ClockAhead".into()));
            }
            Err(LaneSelectionError::Changed) => {
                self.routing_refusal = None;
                return Err(PublicationError::Retryable(
                    "lane Queue admission changed".into(),
                ));
            }
            Err(LaneSelectionError::Publication(error)) => {
                self.routing_refusal = None;
                return Err(error);
            }
        };
        if selected.is_empty() {
            #[cfg(test)]
            transactions.empty_payload_answer();
            return Ok(None);
        }
        // Canonical framing is part of the payload limit. Trim the selected source before
        // creating its retained encoding job; allocator refusal never changes selection.
        let mut batch = LaneBatch {
            anchor_height,
            anchor_hash,
            transactions: selected,
        };
        loop {
            let length =
                norito::codec::encode_adaptive_into(&batch, &mut io::sink()).map_err(|error| {
                    PublicationError::RecoveryRequired(format!("lane payload length: {error}"))
                })?;
            if length <= max_bytes as usize {
                break;
            }
            batch.transactions.pop();
            if batch.transactions.is_empty() {
                return Ok(None);
            }
        }
        transactions.retain_prefix(&mut lease, batch.transactions.len());
        self.payload_build = Some(LanePayloadBuild {
            height,
            view,
            max_bytes,
            job: PayloadBuild::new(batch, self.budget.clone(), max_bytes as usize),
            lease,
        });
        self.finish_payload()
    }

    fn reject(&mut self, height: u64, view: u64, block_hash: &Hash32) {
        iroha_logger::debug!(
            lane = %self.record.lane,
            height,
            view,
            block = %hex::encode(block_hash.0),
            "a lane block was not admissible"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        isi::{InstructionBox, Log},
        parameter::system::SumeragiParameters,
        sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember},
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_model_base::{
        peer::PeerId,
        topology::{DataSpaceId, LaneId},
    };
    use iroha_sumeragi::{
        availability::{AvailabilitySource, PayloadAuthoring},
        message::{BlockHeader as CoreHeader, VoteKind},
        preimage::payload_hash,
        types::{AggregateSignature, Bitmap, SIGNATURE_LEN},
    };
    use parking_lot::Mutex;

    use super::*;
    use crate::sumeragi::{
        body_read::{BodyReadError, BodyReadJob, BodyReader},
        crypto::{BlsCrypto, KeyPairSigner},
        lanes::lane_height_config,
    };

    fn anchor_hash(height: u64) -> HashOf<BlockHeader> {
        HashOf::from_untyped_unchecked(Hash::prehashed([u8::try_from(height).unwrap(); 32]))
    }

    /// The global chain: applied up to `applied`.
    pub(super) struct Global {
        pub(super) applied: AtomicU64,
    }

    impl AnchorView for Global {
        fn applied_hash(&self, height: u64) -> Option<HashOf<BlockHeader>> {
            (height <= self.applied.load(Ordering::SeqCst)).then(|| anchor_hash(height))
        }
        fn creation_time_ms(&self, height: u64) -> Result<Option<u64>, Attempt<io::Error>> {
            Ok((height <= self.applied.load(Ordering::SeqCst)).then_some(height * 1000))
        }
    }

    impl AnchorSource for Global {
        fn wait_for(&self, height: u64, _timeout: Duration) -> bool {
            height <= self.applied.load(Ordering::SeqCst)
        }
        fn tip(&self) -> (u64, HashOf<BlockHeader>) {
            let height = self.applied.load(Ordering::SeqCst);
            (height, anchor_hash(height))
        }
    }

    pub(super) struct Accept;
    impl TransactionCheck for Accept {
        fn check(&self, _tx: &SignedTransaction, _time: u64) -> Result<(), String> {
            Ok(())
        }
    }

    struct Queue(Mutex<Vec<SignedTransaction>>);
    impl LaneTransactions for Queue {
        type Lease = ();

        fn candidates(
            &self,
            _height: u64,
            _max_bytes: usize,
            skip: &BTreeSet<HashOf<TransactionEntrypoint>>,
            _: &iroha_allocation::AllocationBudget,
        ) -> Result<
            (Vec<SignedTransaction>, Self::Lease),
            crate::sumeragi::lanes::executor::LaneSelectionError,
        > {
            Ok((
                self.0
                    .lock()
                    .iter()
                    .filter(|tx| !skip.contains(&tx.hash_as_entrypoint()))
                    .cloned()
                    .collect(),
                (),
            ))
        }

        fn retain_prefix(&self, _: &mut Self::Lease, _: usize) {}
        fn lease_is_current(
            &self,
            _: &Self::Lease,
            _: &iroha_allocation::AllocationBudget,
        ) -> Result<bool, crate::sumeragi::driver::traits::PublicationError> {
            Ok(true)
        }
    }

    struct NoStore;
    impl BodyReader for NoStore {
        fn begin_read(&self, _: AvailabilitySource) -> Result<Box<dyn BodyReadJob>, BodyReadError> {
            panic!("the empty committed store must never be read during height-zero recovery");
        }
    }
    impl BlockStore for NoStore {
        fn committed_body(
            &self,
            _: u64,
        ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
            Ok(None)
        }
        fn height(&self) -> u64 {
            0
        }
        fn entry(
            &self,
            _height: u64,
        ) -> Result<Option<iroha_sumeragi::message::SyncEntry>, Attempt<io::Error>> {
            Ok(None)
        }
        fn availability_source(
            &self,
            _: u64,
            _: Hash32,
        ) -> Result<Option<AvailabilitySource>, Attempt<io::Error>> {
            Ok(None)
        }
        fn append(&self, _block: &AvailableBody, _qc: &Qc) -> Result<(), Attempt<io::Error>> {
            Ok(())
        }
    }

    fn member(seed: u8) -> SumeragiLaneMember {
        let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
        SumeragiLaneMember {
            peer: PeerId::new(pair.public_key().clone()),
            pop: iroha_crypto::bls_normal_pop_prove(pair.private_key()).expect("pop"),
        }
    }

    fn record() -> SumeragiLaneRecord {
        SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(16),
            dataspace: DataSpaceId::new(0),
            incarnation: [4; 32],
            params: SumeragiParameters::default(),
            committee: vec![member(1)],
            created_at: 1,
            active_from: 3,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 3,
            rescued: 0,
        }
    }

    fn tx(seed: u8) -> SignedTransaction {
        tx_at(seed, 1_000)
    }

    fn tx_at(seed: u8, created_ms: u64) -> SignedTransaction {
        let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        let mut builder = TransactionBuilder::new(
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"lane"))),
            AccountId::new(pair.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            format!("{seed}"),
        ))]);
        builder.set_creation_time(Duration::from_millis(created_ms));
        builder.sign(pair.private_key())
    }

    fn funded(lane: &LaneExecutor<Global, Accept, Queue>, bytes: Vec<u8>) -> PayloadBytes {
        let mut payload = PayloadBytes::from_untrusted(bytes).expect("nonempty fixture work");
        payload.admit(&lane.budget).expect("original fixture pool");
        payload
    }

    fn authored(
        lane: &LaneExecutor<Global, Accept, Queue>,
        header: CoreHeader,
        payload: PayloadBytes,
    ) -> AvailableBody {
        let pair = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
        let signer = KeyPairSigner::new(&pair).expect("actual lane signer");
        PayloadAuthoring::new(header, payload)
            .complete(
                lane.instance,
                &lane.config,
                &lane.budget,
                &BlsCrypto::new(),
                &signer,
            )
            .unwrap_or_else(|_| panic!("actual original signed lane availability"))
            .body
    }

    fn block(
        lane: &LaneExecutor<Global, Accept, Queue>,
        height: u64,
        parent: Hash32,
        payload: PayloadBytes,
    ) -> AvailableBody {
        let header = CoreHeader {
            instance: lane.instance,
            epoch: lane.config.epoch.id,
            height,
            origin_view: 0,
            parent_hash: parent,
            parent_result: Hash32::ZERO,
            payload_hash: payload_hash(&BlsCrypto::new(), payload.as_slice()),
            availability_digest: Hash32::ZERO,
            payload_len: u32::try_from(payload.as_slice().len()).unwrap(),
            proposer: 0,
            skipped_leaders: Vec::new(),
            control_witness: Default::default(),
        };
        authored(lane, header, payload)
    }

    fn qc(block: &AvailableBody, result: Hash32) -> Qc {
        Qc {
            kind: VoteKind::Commit,
            instance: block.header().instance,
            epoch: block.header().epoch,
            height: block.header().height,
            view: 0,
            block_hash: block.header().hash(&BlsCrypto::new()),
            result,
            signers: Bitmap::from_indices(1, [0]).unwrap(),
            agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
        }
    }

    fn executor(
        global: &Arc<Global>,
        queue: Option<Arc<Queue>>,
    ) -> LaneExecutor<Global, Accept, Queue> {
        executor_with(global, queue)
    }

    fn executor_with<T: LaneTransactions>(
        global: &Arc<Global>,
        queue: Option<Arc<T>>,
    ) -> LaneExecutor<Global, Accept, T> {
        executor_with_clock(
            global,
            queue,
            iroha_primitives::time::TimeSource::new_system(),
        )
    }

    pub(super) fn executor_with_clock<T: LaneTransactions>(
        global: &Arc<Global>,
        queue: Option<Arc<T>>,
        time_source: iroha_primitives::time::TimeSource,
    ) -> LaneExecutor<Global, Accept, T> {
        let record = record();
        let config = lane_height_config(&record).expect("config");
        LaneExecutor::begin_recover(
            record,
            config,
            Hash32([1; 32]),
            Arc::clone(global),
            Accept,
            queue,
            Hash32::ZERO,
            Arc::new(NoStore),
            Arc::new(BlsCrypto::new()),
            AllocationBudget::new(1 << 20),
            time_source,
        )
        .complete()
        .unwrap_or_else(|_| panic!("empty lane store recovery"))
    }

    #[test]
    fn lane_effective_timestamp_saturates_native_milliseconds() {
        for (created, expected) in [(0, 1), (1, 2), (u64::MAX, u64::MAX)] {
            let batch = LaneBatch {
                anchor_height: 5,
                anchor_hash: anchor_hash(5),
                transactions: vec![tx_at(25, created)],
            };
            assert_eq!(batch.effective_time(0), Duration::from_millis(expected));
            assert_eq!(
                batch.effective_time(u64::MAX),
                Duration::from_millis(u64::MAX)
            );
        }
    }

    #[test]
    fn lane_builder_effective_clock_retains_original_payload_across_clock_rewind() {
        for created_ms in [1_000, 6_500] {
            let global = Arc::new(Global {
                applied: AtomicU64::new(5),
            });
            let transaction = tx_at(24, created_ms);
            let effective = Duration::from_millis(5_000.max(created_ms + 1));
            let (clock, time) =
                iroha_primitives::time::TimeSource::new_mock(effective - Duration::from_millis(1));
            let queue = Arc::new(Queue(Mutex::new(vec![transaction.clone()])));
            let mut lane = executor_with_clock(&global, Some(queue.clone()), time);
            assert!(
                matches!(lane.build(1, 0, 1 << 20, 1_000),
                Err(PublicationError::Retryable(reason)) if reason == "ClockAhead"),
                "lane builder must retain its original effective timestamp before publication"
            );
            let source = lane
                .payload_build
                .as_ref()
                .unwrap()
                .job
                .source()
                .transactions
                .as_ptr();
            assert!(lane.cache.is_empty());
            assert_eq!(queue.0.lock().len(), 1);
            clock.set(effective);
            assert!(
                matches!(lane.finish_payload_with_encoder(|batch, mut writer| {
                norito::codec::encode_adaptive_into(batch, &mut writer)?;
                clock.rewind(Duration::from_millis(1));
                Ok(())
            }), Err(PublicationError::Retryable(reason)) if reason == "ClockAhead"),
                "lane encoding must recheck its clock before lending completed bytes"
            );
            assert!(lane.payload_build.as_ref().unwrap().job.is_completed());
            clock.set(effective);
            let payload = lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
            assert_eq!(
                LaneBatch::from_payload(payload.as_slice())
                    .unwrap()
                    .transactions,
                vec![transaction]
            );
            let original = payload.as_slice().as_ptr();
            clock.rewind(Duration::from_millis(1));
            assert!(
                matches!(lane.build(1, 0, 1 << 20, 1_000), Err(PublicationError::Retryable(reason)) if reason == "ClockAhead")
            );
            assert_eq!(
                lane.payload_build
                    .as_ref()
                    .unwrap()
                    .job
                    .source()
                    .transactions
                    .as_ptr(),
                source
            );
            assert!(lane.payload_build.as_ref().unwrap().job.is_completed());
            clock.set(effective);
            assert_eq!(
                lane.build(1, 0, 1 << 20, 1_000)
                    .unwrap()
                    .unwrap()
                    .as_slice()
                    .as_ptr(),
                original
            );
            assert_eq!(queue.0.lock().len(), 1);
        }
    }

    #[test]
    fn future_only_lane_work_retries_without_an_empty_answer_or_new_traffic() {
        struct FutureQueue {
            time: iroha_primitives::time::TimeSource,
            due: Duration,
            transaction: SignedTransaction,
            empty: AtomicU64,
        }
        impl LaneTransactions for FutureQueue {
            type Lease = ();

            fn empty_payload_answer(&self) {
                self.empty.fetch_add(1, Ordering::SeqCst);
            }
            fn candidates(
                &self,
                _: u64,
                _: usize,
                _: &BTreeSet<HashOf<TransactionEntrypoint>>,
                _: &iroha_allocation::AllocationBudget,
            ) -> Result<(Vec<SignedTransaction>, Self::Lease), LaneSelectionError> {
                if self.time.now() < self.due {
                    Err(LaneSelectionError::ClockAhead)
                } else {
                    Ok((vec![self.transaction.clone()], ()))
                }
            }

            fn retain_prefix(&self, _: &mut Self::Lease, _: usize) {}
            fn lease_is_current(
                &self,
                _: &Self::Lease,
                _: &iroha_allocation::AllocationBudget,
            ) -> Result<bool, crate::sumeragi::driver::traits::PublicationError> {
                Ok(true)
            }
        }
        let global = Arc::new(Global {
            applied: AtomicU64::new(5),
        });
        let (clock, time) = iroha_primitives::time::TimeSource::new_mock(Duration::ZERO);
        let source = Arc::new(FutureQueue {
            time,
            due: Duration::from_millis(1),
            transaction: tx(23),
            empty: AtomicU64::new(0),
        });
        let original = source.transaction.hash();
        let mut lane = executor_with(&global, Some(source.clone()));
        assert!(
            matches!(
                lane.build(1, 0, 1 << 20, 1_000),
                Err(PublicationError::Retryable(reason)) if reason == "ClockAhead"
            ),
            "future-only lane work must retry instead of reporting an empty payload"
        );
        assert_eq!(source.empty.load(Ordering::SeqCst), 0);
        assert!(
            lane.routing_refusal.is_none(),
            "time wait is not a resource refusal"
        );
        clock.advance(Duration::from_millis(1));
        let payload = lane
            .build(1, 0, 1 << 20, 1_000)
            .unwrap()
            .expect("same queued work wakes on retry");
        let batch = LaneBatch::from_payload(payload.as_slice()).unwrap();
        assert_eq!(batch.transactions.len(), 1);
        assert_eq!(batch.transactions[0].hash(), original);
        assert_eq!(source.empty.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn lanes_discard_global_control_and_refuse_control_bearing_admission() {
        use iroha_sumeragi::{
            api::{ApplicationControlContext, ControlWitnessContext},
            message::ApplicationControl,
            types::{ControlWitness, PublicKey},
        };
        let global = Arc::new(Global {
            applied: AtomicU64::new(5),
        });
        let queue = Arc::new(Queue(Mutex::new(vec![tx(1)])));
        let mut lane = executor(&global, Some(queue));
        let context = ApplicationControlContext {
            instance: Hash32([1; 32]),
            epoch: lane.config.epoch.id,
            height: 1,
            parent_hash: lane.applied.block_hash,
            parent_result: Hash32([0; 32]),
        };
        let witness = ControlWitnessContext {
            height: context.height,
            view: 0,
            epoch: context.epoch,
            parent_hash: context.parent_hash,
            parent_result: context.parent_result,
        };
        assert_eq!(
            lane.build_control_witness(&witness),
            Ok(ControlWitness::empty())
        );
        assert_eq!(lane.drive_control(&context), Ok(None));
        let control = ControlWitness::try_from_slice(b"unsolicited global control").unwrap();
        let sender = PublicKey::new(
            record().committee[0]
                .peer
                .public_key()
                .to_bytes()
                .1
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            lane.receive_application_control(
                &sender,
                &ApplicationControl {
                    context,
                    bytes: control
                }
            ),
            Ok(())
        );
        assert!(lane.cache.is_empty());
        assert_eq!(lane.applied.height, 0);
        let payload = lane.build(1, 0, 1 << 20, 100).unwrap().unwrap();
        let valid = block(&lane, 1, lane.applied.block_hash, payload);
        let mut header = valid.header().clone();
        header.control_witness = control;
        let foreign = authored(&lane, header, valid.payload().clone());
        let foreign_hash = foreign.hash(&BlsCrypto::new());
        assert_eq!(
            lane.execute(&foreign, &foreign_hash, false),
            Some(ExecOutcome::Invalid)
        );
        assert_eq!(
            lane.prepare(&foreign, &qc(&foreign, Hash32([0; 32]))),
            Ok(None)
        );
        assert!(lane.cache.is_empty());
        assert!(matches!(
            lane.execute(&valid, &valid.hash(&BlsCrypto::new()), false),
            Some(ExecOutcome::Valid { .. })
        ));
    }

    #[test]
    fn builds_executes_commits_and_deduplicates() {
        let global = Arc::new(Global {
            applied: AtomicU64::new(5),
        });
        let first = tx(1);
        let queue = Arc::new(Queue(Mutex::new(vec![first.clone()])));
        let mut lane = executor(&global, Some(Arc::clone(&queue)));
        let payload = lane.build(1, 0, 1 << 20, 100).unwrap();
        let payload = payload.expect("selected transaction work");

        let batch = LaneBatch::from_payload(payload.as_slice()).expect("batch");
        assert_eq!(batch.anchor_height, 5);
        assert_eq!(batch.transactions, vec![first.clone()]);
        let b1 = block(&lane, 1, Hash32::ZERO, payload);
        let h1 = b1.hash(&BlsCrypto::new());
        let Some(ExecOutcome::Valid { result: r1, .. }) = lane.execute(&b1, &h1, false) else {
            panic!("valid");
        };
        assert_eq!(lane.prepare(&b1, &qc(&b1, r1)), Ok(Some(r1)));
        lane.commit(&b1, &qc(&b1, r1)).expect("commit");
        // The committed transaction is not proposed again, and a block repeating it is invalid.
        assert!(lane.build(2, 0, 1 << 20, 100).unwrap().is_none());
        let repeat = LaneBatch {
            anchor_height: 5,
            anchor_hash: anchor_hash(5),
            transactions: vec![first],
        }
        .to_payload();
        let b2 = block(&lane, 2, h1, funded(&lane, repeat));
        assert_eq!(
            lane.execute(&b2, &b2.hash(&BlsCrypto::new()), false),
            Some(ExecOutcome::Invalid)
        );
        // A block whose parent is neither applied nor executed is parked.
        let orphan = block(&lane, 3, Hash32([9; 32]), b1.payload().clone());
        assert_eq!(lane.execute(&orphan, &Hash32([8; 32]), false), None);
    }

    /// The framed length queue admission and the queue-backed source measure.
    fn framed_len(transaction: &SignedTransaction) -> usize {
        crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Borrowed(transaction))
            .encoded_len()
    }

    /// A transaction source that applies the byte budget the builder passes, as the
    /// queue-backed source does, and records each budget it was given.
    struct Budgeted {
        transactions: Vec<SignedTransaction>,
        budgets: Mutex<Vec<usize>>,
    }
    impl LaneTransactions for Budgeted {
        type Lease = ();

        fn candidates(
            &self,
            _height: u64,
            max_bytes: usize,
            skip: &BTreeSet<HashOf<TransactionEntrypoint>>,
            _: &iroha_allocation::AllocationBudget,
        ) -> Result<
            (Vec<SignedTransaction>, Self::Lease),
            crate::sumeragi::lanes::executor::LaneSelectionError,
        > {
            self.budgets.lock().push(max_bytes);
            let mut bytes = 0usize;
            let mut selected = Vec::new();
            for transaction in &self.transactions {
                let next = bytes.saturating_add(framed_len(transaction));
                if skip.contains(&transaction.hash_as_entrypoint()) || next > max_bytes {
                    continue;
                }
                bytes = next;
                selected.push(transaction.clone());
            }
            Ok((selected, ()))
        }

        fn retain_prefix(&self, _: &mut Self::Lease, _: usize) {}
        fn lease_is_current(
            &self,
            _: &Self::Lease,
            _: &iroha_allocation::AllocationBudget,
        ) -> Result<bool, crate::sumeragi::driver::traits::PublicationError> {
            Ok(true)
        }
    }

    /// The lane builder selects within the lane payload limit less the batch framing reserve
    /// the data model owns, which is the budget queue admission grants a lane-routed
    /// transaction. A transaction of exactly that length is built into a batch that fits the
    /// payload limit; with one byte less payload it is not selected and nothing is proposed.
    #[test]
    fn build_carries_a_transaction_of_the_payload_limit_less_the_framing_reserve() {
        let reserve =
            iroha_data_model::parameter::system::LANE_BATCH_FRAMING_RESERVE_BYTES as usize;
        let global = Arc::new(Global {
            applied: AtomicU64::new(5),
        });
        let transaction = tx(7);
        let length = framed_len(&transaction);
        let source = Arc::new(Budgeted {
            transactions: vec![transaction.clone()],
            budgets: Mutex::new(Vec::new()),
        });
        let mut lane = executor_with(&global, Some(Arc::clone(&source)));
        let exact = u32::try_from(length + reserve).unwrap();
        // One byte over the lane budget: the builder's budget is one byte short.
        let payload = lane.build(1, 0, exact - 1, 100).unwrap();
        assert!(payload.is_none(), "nothing fits: no empty batch");
        // Exactly the lane budget.
        let payload = lane.build(1, 0, exact, 100).unwrap();
        let payload = payload.expect("the lane budget carries the transaction");

        assert!(
            payload.as_slice().len() <= exact as usize,
            "the batch framing fits the reserve: {} of {exact} bytes",
            payload.as_slice().len()
        );
        let batch = LaneBatch::from_payload(payload.as_slice()).expect("batch");
        assert_eq!(batch.transactions, vec![transaction]);
        assert_eq!(*source.budgets.lock(), vec![length - 1, length]);
        // The same budget is what the data model grants the lane route at admission (the
        // global payload here leaves no room, so the lane budget alone decides).
        assert_eq!(
            iroha_data_model::parameter::system::max_includable_transaction_bytes(
                iroha_data_model::parameter::Parameters::default()
                    .transaction()
                    .max_tx_bytes(),
                std::num::NonZeroU32::new(1).unwrap(),
                iroha_data_model::parameter::system::TransactionInclusionRoute::NativeLane {
                    max_block_bytes: std::num::NonZeroU32::new(exact).unwrap(),
                },
            ),
            u64::try_from(length).unwrap()
        );
    }

    /// A transaction source that ignores the byte budget, so the builder's own comparison of
    /// the encoded batch with the payload limit decides what is proposed.
    struct Unbudgeted(Vec<SignedTransaction>);
    impl LaneTransactions for Unbudgeted {
        type Lease = ();

        fn candidates(
            &self,
            _height: u64,
            _max_bytes: usize,
            skip: &BTreeSet<HashOf<TransactionEntrypoint>>,
            _: &iroha_allocation::AllocationBudget,
        ) -> Result<
            (Vec<SignedTransaction>, Self::Lease),
            crate::sumeragi::lanes::executor::LaneSelectionError,
        > {
            Ok((
                self.0
                    .iter()
                    .filter(|transaction| !skip.contains(&transaction.hash_as_entrypoint()))
                    .cloned()
                    .collect(),
                (),
            ))
        }

        fn retain_prefix(&self, _: &mut Self::Lease, _: usize) {}
        fn lease_is_current(
            &self,
            _: &Self::Lease,
            _: &iroha_allocation::AllocationBudget,
        ) -> Result<bool, crate::sumeragi::driver::traits::PublicationError> {
            Ok(true)
        }
    }

    /// The encoded batch, framing included, is compared with the lane payload limit itself.
    /// A batch of exactly the limit is proposed whole; with one byte less the builder drops
    /// the last transaction instead of proposing an oversized payload; below the batch of one
    /// transaction it proposes nothing.
    #[test]
    fn build_trims_the_batch_to_the_lane_payload_limit() {
        let global = Arc::new(Global {
            applied: AtomicU64::new(5),
        });
        let (first, second) = (tx(11), tx(12));
        let source = Arc::new(Unbudgeted(vec![first.clone(), second.clone()]));
        let mut lane = executor_with(&global, Some(Arc::clone(&source)));
        let encoded = |transactions: Vec<SignedTransaction>| {
            let batch = LaneBatch {
                anchor_height: 5,
                anchor_hash: anchor_hash(5),
                transactions,
            };
            norito::codec::encode_adaptive_into(&batch, &mut io::sink()).expect("batch length")
        };
        let both = encoded(vec![first.clone(), second.clone()]);
        let one = encoded(vec![first.clone()]);
        assert!(one < both);
        let carried = |payload: &PayloadBytes| {
            LaneBatch::from_payload(payload.as_slice())
                .expect("batch")
                .transactions
        };
        // Exactly the limit: both transactions, and the payload is the limit to the byte.
        let payload = lane.build(1, 0, u32::try_from(both).unwrap(), 100).unwrap();
        let payload = payload.expect("a batch of exactly the limit is proposed");

        assert_eq!(payload.as_slice().len(), both);
        assert_eq!(carried(&payload), vec![first.clone(), second]);
        // One byte less: the last transaction is dropped, never an oversized payload.
        let payload = lane
            .build(1, 0, u32::try_from(both - 1).unwrap(), 100)
            .unwrap();
        let payload = payload.expect("the first transaction still fits");
        assert_eq!(payload.as_slice().len(), one);
        assert_eq!(carried(&payload), vec![first]);
        // The batch of one transaction is itself exact at its own length and refused below it.
        let payload = lane.build(1, 0, u32::try_from(one).unwrap(), 100).unwrap();
        assert_eq!(payload.expect("exactly one batch").as_slice().len(), one);
        let payload = lane
            .build(1, 0, u32::try_from(one - 1).unwrap(), 100)
            .unwrap();
        assert!(payload.is_none(), "nothing fits: no empty batch");
    }

    #[test]
    fn payload_refusal_retains_selected_work_and_anchor_for_retry() {
        let global = Arc::new(Global {
            applied: AtomicU64::new(5),
        });
        let first = tx(1);
        let queue = Arc::new(Queue(Mutex::new(vec![first.clone()])));
        let mut lane = executor(&global, Some(Arc::clone(&queue)));
        lane.budget.set_limit_bytes(lane.budget.reserved_bytes());
        assert!(matches!(
            lane.build(1, 0, 1 << 20, 100),
            Err(PublicationError::Retryable(_))
        ));
        // New ambient work must not replace the source already selected by this job.
        *queue.0.lock() = vec![tx(2)];
        global.applied.store(6, Ordering::SeqCst);
        lane.budget.set_limit_bytes(1 << 20);
        let payload = lane.build(1, 0, 1 << 20, 100).unwrap();
        let payload = payload.expect("refusal must not manufacture an empty proposal");

        assert!(payload.admitted_to(&lane.budget));
        let batch = LaneBatch::from_payload(payload.as_slice()).expect("retained batch");
        assert_eq!(batch.anchor_height, 5);
        assert_eq!(batch.anchor_hash, anchor_hash(5));
        assert_eq!(batch.transactions, vec![first]);
        let body = block(&lane, 1, Hash32::ZERO, payload);
        assert!(matches!(
            lane.execute(&body, &body.hash(&BlsCrypto::new()), false),
            Some(ExecOutcome::Valid { .. })
        ));
    }

    #[test]
    fn an_anchor_the_node_has_not_applied_is_never_a_verdict() {
        let global = Arc::new(Global {
            applied: AtomicU64::new(4),
        });
        let mut lane = executor(&global, None);
        let ahead = LaneBatch {
            anchor_height: 6,
            anchor_hash: anchor_hash(6),
            transactions: vec![tx(2)],
        }
        .to_payload();
        let b1 = block(&lane, 1, Hash32::ZERO, funded(&lane, ahead));
        let h1 = b1.hash(&BlsCrypto::new());
        assert!(matches!(
            lane.execute(&b1, &h1, false),
            Some(ExecOutcome::Failed(_))
        ));
        global.applied.store(6, Ordering::SeqCst);
        assert!(matches!(
            lane.execute(&b1, &h1, false),
            Some(ExecOutcome::Valid { .. })
        ));
        // A lane without a transaction source builds nothing.
        assert!(lane.build(1, 0, 1 << 20, 100).unwrap().is_none());
    }
}

#[cfg(test)]
#[path = "executor/native_decode_tests.rs"]
mod native_decode_tests;

#[cfg(test)]
#[path = "executor/queue_lease_tests.rs"]
mod queue_lease_tests;
