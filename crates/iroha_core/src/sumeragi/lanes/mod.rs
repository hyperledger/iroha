//! Lanes of the global chain (`specs/sumeragi_lanes.md`): the identity and pinned configuration
//! of a lane instance, the lane block payload ([`LaneBatch`]), its result `R` ([`LaneResult`]) and
//! lane admission (§3.2).
//!
//! A lane never changes world state. Its execute-before-vote step is [`admit`]: a pure function of
//! the lane block, the lane's own committed chain and permanent facts of the global chain (the
//! anchor block's hash and creation time, and the lane record's immutable fields), so every
//! honest member computes the same `R` whenever it executes.

pub(crate) mod custody;

/// Authentication of original lane certificates and reproduced admission evidence.
pub mod evidence;
/// The executor of a lane instance.
pub mod executor;
/// The global chain as lane instances use it: applied tip, anchors, checks and the queue.
pub mod global;
/// The global chain's merge of certified lane blocks.
pub mod merge;
mod proposal_reads;
pub use proposal_reads::ProposalReadScope;

/// Canonical durable lane certificate and original payload records.
pub(crate) mod record;
/// The node's lane block stores.
pub mod registry;
/// Routing transactions to lanes from committed state.
pub mod routing;
/// The node's lane instances.
pub mod runner;
/// The lane step of a global block: frontiers, samples, lifecycle and autoscale.
pub mod step;
/// The durable block store of a lane instance.
pub mod store;

use std::collections::{BTreeMap, BTreeSet};

use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    sumeragi_lanes::{SumeragiLanePolicy, SumeragiLaneRecord},
    transaction::TransactionEntrypoint,
};
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::{
    crypto::Crypto,
    preimage::{InstanceKind, committee_digest_preimage, instance_id},
    types::{Committee, EpochConfig, EpochId, Hash32, HeightConfig},
};
use norito::codec::{Decode, Encode};
use thiserror::Error;

use super::{
    commitment::chain_hash,
    schedule::{ChainParamsRecord, ScheduleError, consensus_key},
};
use crate::state::WorldReadOnly;

/// Domain tag of a lane incarnation's genesis block hash.
pub const LANE_GENESIS_TAG: &[u8] = b"iroha/sumeragi/lane/genesis/v1";
/// Domain tag of a lane incarnation's genesis result.
pub const LANE_GENESIS_RESULT_TAG: &[u8] = b"iroha/sumeragi/lane/genesis-result/v1";
/// Domain tag of a lane block's result `R`.
pub const LANE_RESULT_TAG: &[u8] = b"iroha/sumeragi/lane/result/v1";

/// The committed lane policy of `world`, preserving an unfinished original JSON read.
/// Missing or completed malformed parameters retain their existing absent-policy outcome.
///
/// # Errors
///
/// Returns the original resource deferral if decoding the committed lane
/// policy cannot complete.
pub fn lane_policy(
    world: &impl WorldReadOnly,
) -> Result<Option<SumeragiLanePolicy>, crate::execution_attempt::ExecutionDeferred> {
    let Some(custom) = world
        .parameters()
        .custom()
        .get(&SumeragiLanePolicy::parameter_id())
    else {
        return Ok(None);
    };
    let decoded = norito::core::classify_decode_attempt(|| {
        norito::json::from_str(custom.payload().get()).map_err(norito::json::Error::into_core_error)
    });
    let policy: SumeragiLanePolicy = match decoded {
        Ok(policy) => policy,
        Err(error) => {
            return match crate::execution_attempt::canonical_decode_attempt_error(error, |_| ()) {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    if cfg!(all(test, sumeragi_core_mutation = "HC39")) {
                        return Ok(None);
                    }
                    Err(reason)
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(()) => Ok(None),
            };
        }
    };
    Ok(policy.validate().is_ok().then_some(policy))
}

/// Genesis block hash of a lane incarnation: `H(TAG ‖ network ‖ be32(lane) ‖ incarnation)`.
///
/// Every incarnation has its own genesis hash, hence its own instance id: a recreated lane never
/// shares safety records or signatures with an earlier incarnation.
#[must_use]
pub fn lane_genesis_hash(network: &NetworkId, record: &SumeragiLaneRecord) -> Hash32 {
    incarnation_genesis_hash(network, record.lane, &record.incarnation)
}

/// [`lane_genesis_hash`] of incarnation `incarnation` of `lane`.
#[must_use]
pub fn incarnation_genesis_hash(
    network: &NetworkId,
    lane: LaneId,
    incarnation: &[u8; 32],
) -> Hash32 {
    let mut bytes = Vec::with_capacity(LANE_GENESIS_TAG.len() + 32 + 4 + 32);
    bytes.extend_from_slice(LANE_GENESIS_TAG);
    bytes.extend_from_slice(network.as_bytes());
    bytes.extend_from_slice(&lane.as_u32().to_be_bytes());
    bytes.extend_from_slice(incarnation);
    chain_hash(&bytes)
}

/// Instance id `I` of a lane incarnation (`sumeragi.md` §3.5 with kind `Lane`).
#[must_use]
pub fn lane_instance(
    crypto: &dyn Crypto,
    network: &NetworkId,
    chain_id: &str,
    record: &SumeragiLaneRecord,
) -> Hash32 {
    incarnation_instance(crypto, network, chain_id, record.lane, &record.incarnation)
}

/// [`lane_instance`] of incarnation `incarnation` of `lane`.
#[must_use]
pub fn incarnation_instance(
    crypto: &dyn Crypto,
    network: &NetworkId,
    chain_id: &str,
    lane: LaneId,
    incarnation: &[u8; 32],
) -> Hash32 {
    instance_id(
        crypto,
        &incarnation_genesis_hash(network, lane, incarnation),
        chain_id.as_bytes(),
        InstanceKind::Lane,
        lane.as_u32(),
    )
}

/// Genesis result `R_0` of a lane incarnation: binds the fields fixed at creation.
#[must_use]
pub fn lane_genesis_result(record: &SumeragiLaneRecord) -> Hash32 {
    let created = (
        record.lane,
        record.dataspace,
        record.incarnation,
        record.params.clone(),
        record.da_layout,
        record.committee.clone(),
        record.created_at,
        record.active_from,
    );
    let mut bytes = LANE_GENESIS_RESULT_TAG.to_vec();
    bytes.extend_from_slice(&created.encode());
    chain_hash(&bytes)
}

/// The height configuration of every height of a lane incarnation: its pinned committee and
/// chain parameters (§2.3).
///
/// # Errors
/// A pinned member whose key is not BLS-normal, an empty or oversized committee, or chain
/// parameters that fail §9.4 validation.
pub fn lane_height_config(record: &SumeragiLaneRecord) -> Result<HeightConfig, LaneError> {
    record
        .params
        .validate_clock_policy()
        .map_err(|error| LaneError::Schedule(ScheduleError::Epoch(error.to_string())))?;
    record
        .da_layout
        .validate()
        .map_err(|error| LaneError::Schedule(ScheduleError::Epoch(error.to_string())))?;
    let keys = record
        .committee
        .iter()
        .map(|member| consensus_key(&member.peer))
        .collect::<Result<Vec<_>, _>>()
        .map_err(LaneError::Schedule)?;
    let committee = Committee::new(keys)
        .map_err(|error| LaneError::Schedule(ScheduleError::Committee(error)))?;
    let params = ChainParamsRecord::from_parameters(&record.params);
    params
        .validate()
        .map_err(|error| LaneError::Schedule(ScheduleError::Params(error)))?;
    if u64::from(params.to_core().max_block_bytes) > record.da_layout.max_payload_size_bytes {
        return Err(LaneError::Schedule(ScheduleError::Params(
            iroha_sumeragi::api::ConfigError::PayloadAboveAvailabilityLimit,
        )));
    }
    let context = lane_genesis_result(record);
    Ok(HeightConfig {
        epoch: Box::new(EpochConfig {
            da_layout: record.da_layout,
            id: EpochId { epoch: 0, context },
            authority_generation: context,
            first_height: 0,
            last_height: u64::MAX,
            leader_seed: context,
        }),
        committee,
        params: params.to_core(),
    })
}

/// A lane block's payload: an ordered transaction batch anchored at a committed global block.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LaneBatch {
    /// Global height of the anchor.
    pub anchor_height: u64,
    /// Global block hash of the anchor.
    pub anchor_hash: HashOf<iroha_data_model::block::BlockHeader>,
    /// The transactions, in lane order.
    pub transactions: Vec<TransactionEntrypoint>,
}

impl LaneBatch {
    /// Local clock reference implied by the authenticated anchor and signed inputs.
    /// This is application pacing only and is absent from the lane result preimage.
    pub(super) fn effective_time(&self, anchor_time_ms: u64) -> std::time::Duration {
        let input_floor = self
            .transactions
            .iter()
            .filter_map(TransactionEntrypoint::creation_time_ms)
            .map(|created| created.saturating_add(1))
            .max()
            .unwrap_or_default();
        std::time::Duration::from_millis(anchor_time_ms.max(input_floor))
    }

    /// The canonical payload bytes.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        self.encode()
    }

    /// Decode canonical payload bytes; non-canonical bytes are rejected.
    ///
    /// # Errors
    /// Non-canonical bytes, or an incomplete local attempt under the inherited decode budget.
    pub fn from_payload(payload: &[u8]) -> Result<Self, AdmissionAttemptError> {
        norito::core::classify_decode_attempt(|| {
            let batch = if cfg!(all(test, sumeragi_core_mutation = "HC31")) {
                <Self as norito::codec::DecodeAll>::decode_all(&mut &payload[..])
            } else {
                norito::codec::decode_adaptive::<Self>(payload)
            }?;
            if cfg!(all(test, sumeragi_core_mutation = "HC31")) {
                if batch.encode() != payload {
                    return Err(norito::Error::Message("non-canonical batch".into()));
                }
            } else {
                norito::codec::verify_exact_payload(&batch, payload)?;
            }
            Ok(batch)
        })
        .map_err(|error| {
            if cfg!(all(test, sumeragi_core_mutation = "HC29")) {
                return AdmissionAttemptError::Rejected(AdmissionError::Encoding(
                    error.to_string(),
                ));
            }
            match error.into_local_refusal() {
                Ok(original) => AdmissionAttemptError::Deferred(original),
                Err(error) => {
                    AdmissionAttemptError::Rejected(AdmissionError::Encoding(error.to_string()))
                }
            }
        })
    }
}

/// What a lane block certifies (its result preimage): the anchor, the admitted transactions, the
/// payload size and the pinned next configuration (the core's lag-2 rule, §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LaneResult {
    /// Global height of the anchor.
    pub anchor_height: u64,
    /// Global block hash of the anchor.
    pub anchor_hash: HashOf<iroha_data_model::block::BlockHeader>,
    /// Entrypoint hashes of the admitted transactions, in batch order.
    pub tx_hashes: Vec<HashOf<TransactionEntrypoint>>,
    /// Payload length in bytes.
    pub payload_bytes: u64,
    /// `committee_digest(C_{x+2})`: the pinned committee.
    pub next_committee_digest: [u8; 32],
    /// `ChainParams_{x+2}`: the pinned parameters.
    pub next_params: ChainParamsRecord,
}

impl LaneResult {
    /// `R = H(LANE_RESULT_TAG ‖ norito(self))`.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        let mut bytes = LANE_RESULT_TAG.to_vec();
        bytes.extend_from_slice(&self.encode());
        chain_hash(&bytes)
    }
}

/// The facts of the global chain that admission reads (§3.2): all permanent once committed.
pub trait AnchorView {
    /// Hash of the global block at `height`, if this node has applied it.
    fn applied_hash(&self, height: u64) -> Option<HashOf<iroha_data_model::block::BlockHeader>>;
    /// Creation time (ms since the Unix epoch) of the applied global block at `height`.
    ///
    /// # Errors
    /// Retains original local history refusal separately from completed read failures.
    fn creation_time_ms(
        &self,
        height: u64,
    ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>>;
}

/// Blocks of the lane chain that admission deduplicates against at most (§3.2 step 5).
pub const LANE_DEDUP_WINDOW: usize = 64;

/// The lane chain that admission reads: the previous block's anchor and the transactions of the
/// last [`LANE_DEDUP_WINDOW`] lane blocks with the latest anchor each appeared under (§3.2 steps
/// 2 and 5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaneChainView {
    /// Anchor height of the lane's previous block (`0` before the first block).
    pub previous_anchor: u64,
    /// Transactions of the last [`LANE_DEDUP_WINDOW`] lane blocks and their latest anchor.
    pub recent: BTreeMap<HashOf<TransactionEntrypoint>, u64>,
}

impl LaneChainView {
    /// Whether a block anchored at `anchor` repeats `hash` from a recent block that the global
    /// chain may still merge fresh (anchored at or after `anchor - A`). Once every earlier
    /// carrier is stale for such a block, the transaction may be carried again: a stale carrier
    /// never executes it.
    #[must_use]
    pub fn repeats(
        &self,
        hash: &HashOf<TransactionEntrypoint>,
        anchor: u64,
        freshness: u64,
    ) -> bool {
        self.recent
            .get(hash)
            .is_some_and(|previous| previous.saturating_add(freshness) >= anchor)
    }
}

/// The outcome of admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The block is admissible; its result preimage.
    Valid(LaneResult),
    /// The node has not applied the anchor yet: execution waits (never a verdict).
    Pending,
}

/// An incomplete local admission or a completed deterministic rejection.
///
/// This has no wire codec. Cumulative decode budgets and physical allocator refusals
/// retain their exact native category and counters without allocating a diagnostic.
#[derive(Debug, Error)]
pub enum AdmissionAttemptError {
    /// Admission completed and found that the lane block is invalid.
    #[error(transparent)]
    Rejected(#[from] AdmissionError),
    /// The original authenticated payload must be retried locally.
    #[error("lane decode attempt deferred: {0:?}")]
    Deferred(norito::core::DecodeLocalRefusal),
    /// Original anchor history or execution admission must retry with its allocation owner.
    #[error("lane resource admission deferred: {0}")]
    ResourceDeferred(crate::execution_attempt::ExecutionDeferred),
}

/// Why a lane block is not admissible (`Invalid`).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AdmissionError {
    /// The payload is not a canonical [`LaneBatch`].
    #[error("lane payload encoding: {0}")]
    Encoding(String),
    /// The anchor's hash differs from the applied global block at its height.
    #[error("anchor {height} is not the committed global block")]
    AnchorMismatch {
        /// Anchor height.
        height: u64,
    },
    /// The applied global anchor body could not be read coherently.
    #[error("anchor {height} history: {reason}")]
    AnchorRead {
        /// Anchor height.
        height: u64,
        /// Completed read failure.
        reason: String,
    },
    /// The anchor height regressed below the previous lane block's.
    #[error("anchor {height} is below the previous anchor {previous}")]
    AnchorRegressed {
        /// Anchor height.
        height: u64,
        /// Previous anchor height.
        previous: u64,
    },
    /// The lane is not active at the anchor (before activation, or at or after closing).
    #[error("the lane is not active at anchor {0}")]
    Inactive(u64),
    /// A transaction fails its intrinsic checks.
    #[error("transaction {index}: {reason}")]
    Transaction {
        /// Index in the batch.
        index: usize,
        /// Why.
        reason: String,
    },
    /// A transaction repeats one of this block or of the lane's recent blocks.
    #[error("transaction {0} is a duplicate")]
    Duplicate(usize),
}

/// Why a lane configuration cannot be formed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum LaneError {
    /// The pinned committee or parameters are not a valid core configuration.
    #[error("lane configuration: {0}")]
    Schedule(ScheduleError),
}

/// Intrinsic checks of one transaction (chain id, signature, limits), supplied by the caller so
/// admission stays independent of node configuration plumbing.
pub trait TransactionCheck {
    /// Check `tx` as of `anchor_time_ms`, preserving unfinished local verification.
    ///
    /// # Errors
    /// The transaction fails an intrinsic check or its verifier is locally unavailable.
    fn check(
        &self,
        tx: &TransactionEntrypoint,
        anchor_time_ms: u64,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<String>>;
}

/// Lane admission (§3.2): the result of a lane block with `payload`, or why it is invalid.
///
/// # Errors
/// A completed [`AdmissionError`] or an unfinished local decode attempt.
pub fn admit(
    record: &SumeragiLaneRecord,
    anchors: &impl AnchorView,
    chain: &LaneChainView,
    checks: &impl TransactionCheck,
    config: &HeightConfig,
    payload: &[u8],
) -> Result<Admission, AdmissionAttemptError> {
    let batch = LaneBatch::from_payload(payload)?;
    admit_decoded(
        record,
        anchors,
        chain,
        checks,
        config,
        &batch,
        payload.len(),
    )
    .map(|admitted| {
        admitted.map_or(Admission::Pending, |admitted| {
            Admission::Valid(admitted.result)
        })
    })
}

/// Original deterministic admission facts and their clock reference, retained together.
struct AdmittedLane {
    result: LaneResult,
    effective_time: std::time::Duration,
}

/// Admit the original canonical decoded batch without another decoder or transaction graph.
fn admit_decoded(
    record: &SumeragiLaneRecord,
    anchors: &impl AnchorView,
    chain: &LaneChainView,
    checks: &impl TransactionCheck,
    config: &HeightConfig,
    batch: &LaneBatch,
    payload_len: usize,
) -> Result<Option<AdmittedLane>, AdmissionAttemptError> {
    let Some(applied) = anchors.applied_hash(batch.anchor_height) else {
        return Ok(None);
    };
    if applied != batch.anchor_hash {
        return Err(AdmissionError::AnchorMismatch {
            height: batch.anchor_height,
        }
        .into());
    }
    if batch.anchor_height < chain.previous_anchor {
        return Err(AdmissionError::AnchorRegressed {
            height: batch.anchor_height,
            previous: chain.previous_anchor,
        }
        .into());
    }
    if !record.admits_anchor(batch.anchor_height) {
        return Err(AdmissionError::Inactive(batch.anchor_height).into());
    }
    let anchor_time_ms = anchors
        .creation_time_ms(batch.anchor_height)
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                if cfg!(all(test, sumeragi_core_mutation = "HC61")) {
                    AdmissionError::AnchorMismatch {
                        height: batch.anchor_height,
                    }
                    .into()
                } else {
                    AdmissionAttemptError::ResourceDeferred(reason)
                }
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                AdmissionError::AnchorRead {
                    height: batch.anchor_height,
                    reason: error.to_string(),
                }
                .into()
            }
        })?
        .ok_or(AdmissionError::AnchorMismatch {
            height: batch.anchor_height,
        })?;
    let mut seen = BTreeSet::new();
    let mut tx_hashes = Vec::with_capacity(batch.transactions.len());
    for (index, tx) in batch.transactions.iter().enumerate() {
        checks
            .check(tx, anchor_time_ms)
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
                    AdmissionAttemptError::Rejected(AdmissionError::Transaction { index, reason })
                }
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    AdmissionAttemptError::ResourceDeferred(reason)
                }
            })?;
        let hash = tx.hash();
        if chain.repeats(&hash, batch.anchor_height, record.anchor_freshness) || !seen.insert(hash)
        {
            return Err(AdmissionError::Duplicate(index).into());
        }
        tx_hashes.push(hash);
    }
    Ok(Some(AdmittedLane {
        effective_time: batch.effective_time(anchor_time_ms),
        result: LaneResult {
            anchor_height: batch.anchor_height,
            anchor_hash: batch.anchor_hash,
            tx_hashes,
            payload_bytes: u64::try_from(payload_len).unwrap_or(u64::MAX),
            next_committee_digest: chain_hash(&committee_digest_preimage(&config.committee)).0,
            next_params: ChainParamsRecord::from_core(&config.params),
        },
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        isi::{InstructionBox, Log},
        parameter::system::SumeragiParameters,
        sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember},
        transaction::{SignedTransaction, TransactionBuilder},
    };
    use iroha_model_base::{
        peer::PeerId,
        topology::{DataSpaceId, LaneId},
    };

    use super::*;
    use crate::sumeragi::crypto::BlsCrypto;

    struct Anchors(BTreeMap<u64, (HashOf<iroha_data_model::block::BlockHeader>, u64)>);

    impl AnchorView for Anchors {
        fn applied_hash(
            &self,
            height: u64,
        ) -> Option<HashOf<iroha_data_model::block::BlockHeader>> {
            self.0.get(&height).map(|(hash, _)| *hash)
        }
        fn creation_time_ms(
            &self,
            height: u64,
        ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>>
        {
            Ok(self.0.get(&height).map(|(_, time)| *time))
        }
    }

    struct AcceptAll;
    impl TransactionCheck for AcceptAll {
        fn check(
            &self,
            _tx: &TransactionEntrypoint,
            _anchor_time_ms: u64,
        ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<String>> {
            Ok(())
        }
    }

    fn block_hash(seed: u8) -> HashOf<iroha_data_model::block::BlockHeader> {
        HashOf::from_untyped_unchecked(Hash::prehashed([seed; 32]))
    }

    fn member(seed: u8) -> SumeragiLaneMember {
        let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
        SumeragiLaneMember {
            peer: PeerId::new(pair.public_key().clone()),
            pop: iroha_crypto::bls_normal_pop_prove(pair.private_key()).expect("pop"),
        }
    }

    fn record(closing: Option<u64>) -> SumeragiLaneRecord {
        SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(2),
            dataspace: DataSpaceId::new(0),
            incarnation: [9; 32],
            params: SumeragiParameters::default(),
            committee: vec![member(1), member(2), member(3), member(4)],
            created_at: 5,
            active_from: 7,
            closing,
            anchor_freshness: 2,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 7,
            rescued: 0,
        }
    }

    #[test]
    fn lane_height_config_clock_drift_bound_rejects_unbounded_original_records() {
        use iroha_data_model::parameter::system::MAX_CLOCK_DRIFT_BOUND_MS;
        let mut record = record(None);
        record.params.due_work_max_lag_ms = std::num::NonZeroU64::new(124_000).unwrap();
        for value in [0, MAX_CLOCK_DRIFT_BOUND_MS] {
            record.params.max_clock_drift_ms = value;
            assert!(lane_height_config(&record).is_ok());
        }
        record.params.max_clock_drift_ms = 1_000;
        record.params.due_work_max_lag_ms = std::num::NonZeroU64::new(5_999).unwrap();
        assert!(
            lane_height_config(&record)
                .unwrap_err()
                .to_string()
                .contains("due_work_max_lag_ms")
        );
        for value in [MAX_CLOCK_DRIFT_BOUND_MS + 1, u64::MAX] {
            record.params.max_clock_drift_ms = value;
            assert!(
                lane_height_config(&record)
                    .unwrap_err()
                    .to_string()
                    .contains("exceeds the protocol bound")
            );
        }
    }

    #[test]
    fn lane_availability_is_pinned_in_context_and_validated() {
        let original = record(None);
        let config = lane_height_config(&original).unwrap();
        assert_eq!(config.epoch.da_layout, original.da_layout);
        let mut changed = original.clone();
        changed.da_layout.chunk_size_bytes /= 2;
        assert_ne!(
            lane_genesis_result(&original),
            lane_genesis_result(&changed)
        );
        changed.da_layout.parity_shards = 0;
        assert!(lane_height_config(&changed).is_err());
        let mut too_small = original;
        too_small.da_layout.max_payload_size_bytes = 1;
        assert!(lane_height_config(&too_small).is_err());
    }

    fn tx(seed: u8) -> SignedTransaction {
        let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        TransactionBuilder::new(
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"lane-test"))),
            AccountId::new(pair.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            format!("tx {seed}"),
        ))])
        .sign(pair.private_key())
    }

    fn payload(anchor: u64, txs: Vec<SignedTransaction>) -> Vec<u8> {
        LaneBatch {
            anchor_height: anchor,
            anchor_hash: block_hash(u8::try_from(anchor).expect("small")),
            transactions: txs
                .into_iter()
                .map(TransactionEntrypoint::External)
                .collect(),
        }
        .to_payload()
    }

    fn anchors() -> Anchors {
        Anchors(
            (1..=10)
                .map(|h| (h, (block_hash(u8::try_from(h).unwrap()), h * 1000)))
                .collect(),
        )
    }

    fn admit_open(
        record: &SumeragiLaneRecord,
        config: &HeightConfig,
        payload: &[u8],
        chain: &LaneChainView,
    ) -> Result<Admission, AdmissionAttemptError> {
        admit(record, &anchors(), chain, &AcceptAll, config, payload)
    }

    #[test]
    fn signed_lane_batch_canonical_validation_preserves_original_bytes_without_new_allocations() {
        // Genuine signed transactions and their exact source are prepared before
        // the observation. This checks the canonicalization seam only; decoded
        // graph funding and complete native finality remain separate obligations.
        let bytes = payload(8, vec![tx(0x71), tx(0x72)]);
        let source = (bytes.as_ptr(), bytes.len(), bytes.capacity());
        let control = norito::codec::decode_adaptive::<LaneBatch>(&bytes)
            .expect("original signed batch decode");
        assert_eq!(control.to_payload(), bytes);
        assert_eq!(LaneBatch::from_payload(&bytes).unwrap(), control);
        let mut decoded = None;
        let original_decode_allocations = crate::test_allocations::allocations_during(|| {
            decoded = Some(norito::codec::decode_adaptive::<LaneBatch>(&bytes));
        });
        let mut validated = None;
        let canonical_validation_allocations = crate::test_allocations::allocations_during(|| {
            validated = Some(LaneBatch::from_payload(&bytes));
        });
        assert_eq!(decoded.unwrap().unwrap(), control);
        assert_eq!(validated.unwrap().unwrap(), control);
        assert_eq!((bytes.as_ptr(), bytes.len(), bytes.capacity()), source);
        assert_eq!(
            canonical_validation_allocations, original_decode_allocations,
            "canonical validation must borrow the original bytes and must not allocate another payload"
        );
    }

    #[test]
    fn original_signed_batch_decode_preserves_exact_local_refusal_and_terminal_limits() {
        use norito::core::DecodeResourceError;
        let signed = tx(0x61);
        let bytes = payload(8, vec![signed.clone()]);
        let control = LaneBatch::from_payload(&bytes).expect("original canonical signed batch");
        assert_eq!(
            control.transactions,
            vec![TransactionEntrypoint::External(signed)]
        );
        for limits in [
            norito::DecodeLimits::new(96, 1 << 25, usize::MAX, 0, 32),
            norito::DecodeLimits::new(96, 1 << 25, 0, usize::MAX, 32),
        ] {
            let original = norito::with_decode_limits_scope(limits, || {
                <LaneBatch as norito::codec::DecodeAll>::decode_all(&mut bytes.as_slice())
            })
            .expect_err("inherited native decode scope refuses locally");
            let category = original
                .decode_resource_error()
                .expect("exact typed native refusal");
            assert!(matches!(
                category,
                DecodeResourceError::TotalElementsExceeded { .. }
                    | DecodeResourceError::TotalAllocationExceeded { .. }
            ));
            let attempt =
                norito::with_decode_limits_scope(limits, || LaneBatch::from_payload(&bytes));
            assert!(
                matches!(attempt, Err(AdmissionAttemptError::Deferred(original)) if original.resource_error() == category)
            );
            assert_eq!(LaneBatch::from_payload(&bytes).unwrap(), control);
            let (record, chain) = (record(None), LaneChainView::default());
            let config = lane_height_config(&record).unwrap();
            assert!(matches!(
                norito::with_decode_limits_scope(limits, || {
                    admit(&record, &anchors(), &chain, &AcceptAll, &config, &bytes)
                }),
                Err(AdmissionAttemptError::Deferred(_))
            ));
        }
        // Caller-owned structural/depth limits are local; malformed source remains terminal.
        for limits in [
            norito::DecodeLimits::new(0, 1 << 25, usize::MAX, usize::MAX, 32),
            norito::DecodeLimits::new(96, 1 << 25, usize::MAX, usize::MAX, 0),
        ] {
            assert!(matches!(
                norito::with_decode_limits_scope(limits, || LaneBatch::from_payload(&bytes)),
                Err(AdmissionAttemptError::Deferred(_))
            ));
        }
        assert!(matches!(
            LaneBatch::from_payload(&[0xFF]),
            Err(AdmissionAttemptError::Rejected(AdmissionError::Encoding(_)))
        ));
    }

    #[test]
    fn identities_differ_per_incarnation_and_bind_the_record() {
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::prehashed([3; 32])));
        let crypto = BlsCrypto::new();
        let a = record(None);
        let b = SumeragiLaneRecord {
            incarnation: [10; 32],
            ..a.clone()
        };
        assert_ne!(
            lane_genesis_hash(&network, &a),
            lane_genesis_hash(&network, &b)
        );
        assert_ne!(
            lane_instance(&crypto, &network, "chain", &a),
            lane_instance(&crypto, &network, "chain", &b)
        );
        // Closing and merging do not change the genesis result.
        let later = SumeragiLaneRecord {
            closing: Some(40),
            merged: SumeragiLaneFrontier {
                height: 3,
                block_hash: [1; 32],
                result: [2; 32],
            },
            ..a.clone()
        };
        assert_eq!(lane_genesis_result(&a), lane_genesis_result(&later));
        assert_ne!(lane_genesis_result(&a), lane_genesis_result(&b));
    }

    #[test]
    fn the_pinned_committee_forms_the_configuration() {
        let config = lane_height_config(&record(None)).expect("config");
        assert_eq!(config.committee.n(), 4);
        assert_eq!(config.epoch.id.context, lane_genesis_result(&record(None)));
        assert!(config.epoch.contains(0));
        assert!(config.epoch.contains(u64::MAX));
        let changed = SumeragiLaneRecord {
            incarnation: [0x91; 32],
            ..record(None)
        };
        assert_ne!(
            config.epoch.id,
            lane_height_config(&changed).unwrap().epoch.id
        );
        let closed = SumeragiLaneRecord {
            closing: Some(40),
            ..record(None)
        };
        assert_eq!(config.epoch, lane_height_config(&closed).unwrap().epoch);
        let empty = SumeragiLaneRecord {
            committee: Vec::new(),
            ..record(None)
        };
        assert!(lane_height_config(&empty).is_err());
    }

    #[test]
    fn anonymous_ballot_lane_admission_retains_unavailable_without_a_verdict() {
        let record = record(Some(9));
        let config = lane_height_config(&record).expect("configuration");
        let chain = LaneChainView::default();
        let batch = LaneBatch {
            anchor_height: 8,
            anchor_hash: block_hash(8),
            transactions: vec![crate::tx::anonymous_ballot_tests::entrypoint()],
        };
        let bytes = batch.to_payload();
        let checks = global::StatelessChecks::new(crate::unit_test_support::synthetic_network_id(
            "anonymous representation",
        ));
        assert!(
            matches!(admit(&record, &anchors(), &chain, &checks, &config, &bytes),
            Err(AdmissionAttemptError::ResourceDeferred(reason))
                if reason.reason() == ivm::error::ExecutionDeferral::VerifierInitializationUnavailable)
        );
        assert!(chain.recent.is_empty());
    }

    #[test]
    fn admission_checks_anchor_activity_and_duplicates() {
        let record = record(Some(9));
        let config = lane_height_config(&record).expect("config");
        let unmerged_tx = tx(50);
        let chain = LaneChainView {
            previous_anchor: 7,
            recent: BTreeMap::from([(unmerged_tx.hash_as_entrypoint(), 7)]),
        };
        let admit = |payload: &[u8], chain: &LaneChainView| {
            admit(&record, &anchors(), chain, &AcceptAll, &config, payload)
        };
        let batch = payload(8, vec![tx(1), tx(2)]);
        // Valid at anchor 8.
        let valid = admit(&batch, &chain).expect("valid");
        let Admission::Valid(result) = valid else {
            panic!("expected a verdict");
        };
        assert_eq!(result.tx_hashes.len(), 2);
        assert_eq!(result.anchor_height, 8);
        // Deterministic: the same inputs give the same R.
        let again = admit(&batch, &chain).expect("valid");
        assert_eq!(Admission::Valid(result.clone()), again);
        // An anchor this node has not applied: pending, not a verdict.
        assert_eq!(
            (admit(&payload(11, vec![tx(1)]), &chain)).expect("completed fixture operation"),
            Admission::Pending
        );
        // A wrong anchor hash, a regressing anchor, an inactive anchor.
        let wrong = LaneBatch {
            anchor_height: 8,
            anchor_hash: block_hash(99),
            transactions: vec![TransactionEntrypoint::External(tx(1))],
        }
        .to_payload();
        assert!(matches!(
            admit(&wrong, &chain),
            Err(AdmissionAttemptError::Rejected(
                AdmissionError::AnchorMismatch { .. }
            ))
        ));
        assert!(matches!(
            admit(&payload(6, vec![tx(1)]), &LaneChainView::default()),
            Err(AdmissionAttemptError::Rejected(AdmissionError::Inactive(6)))
        ));
        assert!(matches!(
            admit(&payload(9, vec![tx(1)]), &chain),
            Err(AdmissionAttemptError::Rejected(AdmissionError::Inactive(9)))
        ));
        let regressed = LaneChainView {
            previous_anchor: 8,
            ..chain.clone()
        };
        assert!(matches!(
            admit(&payload(7, vec![tx(1)]), &regressed),
            Err(AdmissionAttemptError::Rejected(
                AdmissionError::AnchorRegressed { .. }
            ))
        ));
        // Duplicates within the block and against unmerged lane blocks.
        let repeated = tx(1);
        assert!(matches!(
            admit(&payload(8, vec![repeated.clone(), repeated]), &chain),
            Err(AdmissionAttemptError::Rejected(AdmissionError::Duplicate(
                1
            )))
        ));
        assert!(matches!(
            admit(&payload(8, vec![unmerged_tx.clone()]), &chain),
            Err(AdmissionAttemptError::Rejected(AdmissionError::Duplicate(
                0
            )))
        ));
        // Once the earlier carrier (anchor 7) is stale for the new block (7 + A < 10), the
        // transaction may be carried again.
        let open = SumeragiLaneRecord {
            closing: None,
            ..record.clone()
        };
        assert!(matches!(
            admit_open(
                &open,
                &config,
                &payload(10, vec![unmerged_tx.clone()]),
                &chain
            ),
            Ok(Admission::Valid(_))
        ));
        // A non-canonical payload.
        let mut bytes = payload(8, vec![tx(1)]);
        bytes.push(0);
        assert!(matches!(
            admit(&bytes, &chain),
            Err(AdmissionAttemptError::Rejected(AdmissionError::Encoding(_)))
        ));
    }
}
