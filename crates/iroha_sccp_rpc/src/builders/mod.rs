//! Evidence builders for SCCP v1 (spec §4.13.3–§4.13.5, §7.2, §7.3).
//!
//! Builders fetch raw source-chain data from public RPC and assemble light-client advances,
//! backfills, bootstraps, inbound proofs and void proofs. Their output is untrusted until
//! `iroha_sccp` verifies it.
//!
//! [`SourceChainBuilder`] is the chain-independent entry point the irohad keeper (advances) and
//! the CLI and wallets (bootstraps, advances and evidence) share:
//!
//! - **Advances** are stepped to an [`AdvanceBudgetV1`]: at most `max_updates_per_advance`
//!   items, and the longest prefix of them whose frame fits the byte budget. A light client far
//!   behind therefore catches up over several advances instead of being dropped.
//! - **Evidence** ([`SourceEvidenceV1`]) of one source event picks its anchor from what Taira
//!   stores ([`TairaLightClientView`]): a finality point under a signing set that is still
//!   fresh [`FRESHNESS_MARGIN_MS`] from now, otherwise the nearest retained checkpoint at or
//!   above the event block. When that checkpoint lies beyond one proof's ancestry bound, the
//!   evidence carries `Backfill` segments (at most [`MAX_BACKFILL_SEGMENTS`]) that walk a
//!   checkpoint down to the event first (§4.13.5).
//!
//! [`LightClientReplayV1`] replays a light client locally, so a wallet verifies the evidence with
//! the verifier Taira runs before it pays for a submission (§7.2 step 5).
//!
//! Every builder has a `rotate_endpoints` method that moves each of its clients to its next
//! endpoint. A caller whose build failed on the data it was served (malformed, inconsistent or
//! incomplete), or whose verification rejected what was built, calls it so the next build starts
//! elsewhere; the transports already move on by themselves after failover errors and after
//! answers that discredit an endpoint.
//!
//! Builders and local replay require the profiles selected by committed Taira state.
//! Callers resolve those identities against the compiled catalog before construction.

use std::collections::BTreeSet;

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceProofBytesV1,
        light_client::{
            SccpLcAdvanceBytesV1, SccpLcBootstrapV1, SccpLcCheckpointV1, SccpLcConsensusSetV1,
            SccpLightClientParamsV1, SccpLightClientV1,
        },
    },
};
use iroha_sccp::light_client::{
    self, SccpLcError,
    profile::SccpChainProfilesV1,
    proof::{SccpLcAdvanceV1, SccpLcSegmentV1, SccpVerifiedProofV1},
    state::{
        SccpLcDeltaV1, SccpLcInitialStateV1, SccpLcMemoryStateV1, SccpLcStateView, is_set_fresh,
    },
};

use crate::RpcError;

pub mod bsc;
pub mod ethereum;
pub mod ton;
mod verified;
pub use verified::{VerifiedBuildError, build_verified};

/// Clients over endpoint lists that are never contacted, for unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::{EndpointSet, FailoverPolicy, HttpConfig, HttpTransport};

    /// An HTTP transport over two loopback endpoints, starting at the first.
    pub fn two_endpoint_transport() -> HttpTransport {
        let endpoints = EndpointSet::parse(&["http://127.0.0.1:1", "http://127.0.0.1:2"], &[])
            .expect("loopback endpoints");
        HttpTransport::new(endpoints, HttpConfig::default(), FailoverPolicy::default())
            .expect("transport")
    }
}

/// Margin by which a signing set must outlive the build time before a builder anchors evidence
/// at it, because the submission lands later than it is built (one hour).
pub const FRESHNESS_MARGIN_MS: u64 = 3_600_000;

/// Most `Backfill` segments one piece of evidence carries. Ethereum and BSC segments of 256
/// headers walk 16 320 blocks down; a burn farther below the nearest checkpoint needs a nearer
/// one (`InstallTrustedCheckpoint`, §4.13.2).
pub const MAX_BACKFILL_SEGMENTS: usize = 64;

/// Why a build failed.
#[derive(Debug)]
pub enum BuildError {
    /// An endpoint failed.
    Rpc(RpcError),
    /// A response is not the expected JSON.
    Json(String),
    /// A response contradicts itself (hash, root or linkage mismatch).
    Inconsistent(String),
    /// The requested evidence cannot be built from the available data.
    Unavailable(String),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rpc(error) => write!(formatter, "RPC: {error}"),
            Self::Json(detail) => write!(formatter, "malformed JSON: {detail}"),
            Self::Inconsistent(detail) => write!(formatter, "inconsistent response: {detail}"),
            Self::Unavailable(detail) => write!(formatter, "unavailable: {detail}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<RpcError> for BuildError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

/// Bounds of one advance: the item count Taira accepts and the submitter's byte budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvanceBudgetV1 {
    /// Most items: Ethereum updates, BSC steps or TON hops.
    pub max_items: usize,
    /// Most canonical bytes of the advance frame.
    pub max_bytes: usize,
}

impl AdvanceBudgetV1 {
    /// The budget of a light client with `params` (`max_updates_per_advance` and
    /// `max_advance_bytes`), with the byte bound lowered to `local_max_bytes` (the keeper's
    /// `max_advance_bytes`, §4.13.4).
    #[must_use]
    pub fn for_params(params: &SccpLightClientParamsV1, local_max_bytes: usize) -> Self {
        Self {
            max_items: usize::try_from(params.max_updates_per_advance).unwrap_or(usize::MAX),
            max_bytes: usize::try_from(params.max_advance_bytes)
                .unwrap_or(usize::MAX)
                .min(local_max_bytes),
        }
    }
}

/// Frame the longest prefix of `items` (at most `budget.max_items` of them) whose advance fits
/// `budget.max_bytes`. Every advance kind is valid on any prefix of its items, because each item
/// is verified only against stored data and the items before it.
///
/// # Errors
///
/// [`BuildError::Unavailable`] when there is nothing to advance or not even the first item fits.
pub fn fit_advance<T: Clone>(
    mut items: Vec<T>,
    budget: AdvanceBudgetV1,
    frame: impl Fn(Vec<T>) -> SccpLcAdvanceV1,
) -> Result<SccpLcAdvanceBytesV1, BuildError> {
    items.truncate(budget.max_items);
    let mut last_error = None;
    while !items.is_empty() {
        match frame(items.clone()).to_bytes() {
            Ok(bytes) if bytes.len() <= budget.max_bytes => return Ok(bytes),
            Ok(bytes) => last_error = Some(format!("{} bytes", bytes.len())),
            Err(error) => last_error = Some(error.to_string()),
        }
        items.pop();
    }
    Err(BuildError::Unavailable(last_error.map_or_else(
        || "nothing to advance".into(),
        |detail| {
            format!(
                "not even one advance item fits {} bytes ({detail})",
                budget.max_bytes
            )
        },
    )))
}

/// Whether a signing set superseded at source time `expiry_ms` (`None`: current) is still fresh
/// [`FRESHNESS_MARGIN_MS`] after `now_ms` under `ws_bound_ms` (§4.13.2).
#[must_use]
pub fn fresh_with_margin(expiry_ms: Option<u64>, ws_bound_ms: u64, now_ms: u64) -> bool {
    is_set_fresh(
        expiry_ms,
        ws_bound_ms,
        now_ms.saturating_add(FRESHNESS_MARGIN_MS),
    )
}

/// `Backfill` segments that bring a stored checkpoint within one proof's reach of an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackfillPlanV1 {
    /// Segments `(first, last)` in submission order: the first ends at the stored checkpoint,
    /// each later one at the checkpoint the previous one records (its first header).
    pub segments: Vec<(u64, u64)>,
    /// The checkpoint the proof anchors at, at most `reach` blocks above the event.
    pub anchor: u64,
}

/// Plan `Backfill` segments of at most `segment_headers` headers from the stored checkpoint
/// `checkpoint` down until it lies at most `reach` blocks above `event` (the proof's ancestry
/// bound: Ethereum 256 and BSC 255 with the default parameters).
///
/// # Errors
///
/// [`BuildError::Inconsistent`] for a checkpoint below the event or segments shorter than two
/// headers; [`BuildError::Unavailable`] when more than [`MAX_BACKFILL_SEGMENTS`] are needed.
pub fn plan_backfill(
    event: u64,
    checkpoint: u64,
    reach: u64,
    segment_headers: u64,
) -> Result<BackfillPlanV1, BuildError> {
    if checkpoint < event {
        return Err(BuildError::Inconsistent(format!(
            "checkpoint {checkpoint} lies below event block {event}"
        )));
    }
    if segment_headers < 2 {
        return Err(BuildError::Inconsistent(
            "a backfill segment needs at least two headers".into(),
        ));
    }
    let step = segment_headers - 1;
    let needed = (checkpoint - event).saturating_sub(reach).div_ceil(step);
    if needed > MAX_BACKFILL_SEGMENTS as u64 {
        return Err(BuildError::Unavailable(format!(
            "event block {event} lies {} blocks below the nearest stored checkpoint {checkpoint}: \
             {needed} backfill segments exceed {MAX_BACKFILL_SEGMENTS}; a Parliament \
             InstallTrustedCheckpoint nearer the event recovers it",
            checkpoint - event
        )));
    }
    let mut segments = Vec::new();
    let mut anchor = checkpoint;
    while anchor - event > reach {
        let first = anchor.saturating_sub(step).max(event);
        segments.push((first, anchor));
        anchor = first;
    }
    Ok(BackfillPlanV1 { segments, anchor })
}

/// Frame one `Backfill` advance.
///
/// # Errors
///
/// [`BuildError::Inconsistent`] when the frame exceeds the advance wrapper.
pub fn backfill_bytes(segment: SccpLcSegmentV1) -> Result<SccpLcAdvanceBytesV1, BuildError> {
    SccpLcAdvanceV1::Backfill { segment }
        .to_bytes()
        .map_err(|error| BuildError::Inconsistent(format!("backfill frame: {error}")))
}

/// What Taira stores about one light client, as evidence builders read it: from Torii
/// (`GET /v1/sccp/light-clients/{network}`, `/sets` and `/checkpoints?covering=N`, §6) or from a
/// local [`LightClientReplayV1`].
pub trait TairaLightClientView {
    /// The stored light client.
    ///
    /// # Errors
    ///
    /// The read failed.
    fn light_client(&self) -> Result<SccpLightClientV1, BuildError>;

    /// The stored signing sets.
    ///
    /// # Errors
    ///
    /// The read failed.
    fn sets(&self) -> Result<Vec<SccpLcConsensusSetV1>, BuildError>;

    /// The lowest retained checkpoint at or above `source_height`; `None` when there is none
    /// (the head is below it, or retention pruned every checkpoint above it).
    ///
    /// # Errors
    ///
    /// The read failed.
    fn checkpoint_covering(
        &self,
        source_height: u64,
    ) -> Result<Option<SccpLcCheckpointV1>, BuildError>;
}

/// One source event to prove (§4.12.2, §4.16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceEventRefV1 {
    /// An Ethereum or BSC receipt's `SccpTransferToTaira` log or run of `SccpVoided` logs.
    Evm {
        /// Transaction hash.
        tx_hash: [u8; 32],
        /// Selected logs.
        event: ethereum::EthereumEventV1,
    },
    /// A TON minter transaction's `sccp_transfer_to_taira` or `sccp_voided` external-out
    /// message.
    Ton {
        /// Minter account (workchain 0).
        minter: [u8; 32],
        /// Logical time of the transaction.
        lt: u64,
        /// Transaction hash.
        hash: [u8; 32],
        /// Index of the external-out message.
        message_index: u16,
    },
}

/// Evidence of one source event, ready to submit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEvidenceV1 {
    /// `Backfill` advances to submit first, in order, each as its own
    /// `AdvanceSccpLightClientV1` (a backfill does not move the head).
    pub backfills: Vec<SccpLcAdvanceBytesV1>,
    /// The inbound or void proof.
    pub proof: SccpSourceProofBytesV1,
}

/// The chain-independent builder entry points shared by the irohad keeper, the CLI and wallets.
pub trait SourceChainBuilder {
    /// The source network.
    fn network(&self) -> SccpNetworkV1;

    /// Finite source selections covering the configured endpoint lists.
    fn source_attempts(&self) -> usize;

    /// Move to the next source selection after completed invalid-data verification.
    fn rotate_endpoints(&self);

    /// Build the `InitializeLightClient` bootstrap of the latest finalized source block.
    ///
    /// # Errors
    ///
    /// Any endpoint failure or inconsistent response.
    fn bootstrap(&self) -> Result<SccpLcBootstrapV1, BuildError>;

    /// Build the next advance from the newest stored set `latest_set_id`, stepped to `budget`.
    ///
    /// # Errors
    ///
    /// Any endpoint failure, an inconsistent response, or nothing to advance.
    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError>;

    /// Build the evidence of `event` against the light client Taira stores, anchored where the
    /// signing set is still fresh [`FRESHNESS_MARGIN_MS`] after `now_ms` (§4.13.5).
    ///
    /// # Errors
    ///
    /// Any endpoint failure, an inconsistent response, an event of another chain, or an event
    /// that no stored set or checkpoint can anchor.
    fn evidence(
        &self,
        event: &SourceEventRefV1,
        light_client: &dyn TairaLightClientView,
        now_ms: u64,
    ) -> Result<SourceEvidenceV1, BuildError>;
}

/// A local replay of one Taira light client.
///
/// It holds what Taira stores (seeded from Torii, or from a bootstrap and advances) and indexes
/// its sets and checkpoints, so it answers [`TairaLightClientView`] and verifies evidence with
/// the verifier Taira runs before anything is submitted.
#[derive(Clone, Debug)]
pub struct LightClientReplayV1 {
    profiles: SccpChainProfilesV1,
    network: SccpNetworkV1,
    state: SccpLcMemoryStateV1,
    set_ids: BTreeSet<u64>,
    checkpoints: BTreeSet<u64>,
}

impl LightClientReplayV1 {
    /// A replay of `light_client` with its stored `sets` and the known `checkpoints`.
    #[must_use]
    pub fn new(
        profiles: &SccpChainProfilesV1,
        network: SccpNetworkV1,
        light_client: SccpLightClientV1,
        sets: Vec<SccpLcConsensusSetV1>,
        checkpoints: Vec<SccpLcCheckpointV1>,
    ) -> Self {
        let mut replay = Self::empty(profiles, network);
        replay.state.set_light_client(network, light_client);
        replay.apply(&SccpLcDeltaV1 {
            new_sets: sets,
            checkpoints,
            ..SccpLcDeltaV1::default()
        });
        replay
    }

    /// A replay of a light client installed from `initial`.
    #[must_use]
    pub fn installed(
        profiles: &SccpChainProfilesV1,
        network: SccpNetworkV1,
        initial: &SccpLcInitialStateV1,
    ) -> Self {
        let mut replay = Self::empty(profiles, network);
        replay.state.install(network, initial);
        replay
            .set_ids
            .extend(initial.sets.iter().map(|set| set.set_id));
        replay.checkpoints.extend(
            initial
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.data.source_height),
        );
        replay
    }

    fn empty(profiles: &SccpChainProfilesV1, network: SccpNetworkV1) -> Self {
        Self {
            profiles: *profiles,
            network,
            state: SccpLcMemoryStateV1::new(),
            set_ids: BTreeSet::new(),
            checkpoints: BTreeSet::new(),
        }
    }

    /// The source network.
    #[must_use]
    pub const fn network(&self) -> SccpNetworkV1 {
        self.network
    }

    /// The replayed storage.
    #[must_use]
    pub const fn state(&self) -> &SccpLcMemoryStateV1 {
        &self.state
    }

    /// Apply an accepted advance's delta.
    pub fn apply(&mut self, delta: &SccpLcDeltaV1) {
        self.state.apply(self.network, delta);
        self.set_ids
            .extend(delta.new_sets.iter().map(|set| set.set_id));
        self.checkpoints.extend(
            delta
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.data.source_height),
        );
    }

    /// Record the checkpoints of an accepted proof.
    pub fn record_checkpoints(&mut self, checkpoints: &[SccpLcCheckpointV1]) {
        self.state.record_checkpoints(self.network, checkpoints);
        self.checkpoints.extend(
            checkpoints
                .iter()
                .map(|checkpoint| checkpoint.data.source_height),
        );
    }

    /// Verify `advance` at Taira time `taira_now_ms` and apply it.
    ///
    /// # Errors
    ///
    /// The verifier's rejection.
    pub fn advance(
        &mut self,
        advance: &SccpLcAdvanceBytesV1,
        taira_now_ms: u64,
    ) -> Result<SccpLcDeltaV1, SccpLcError> {
        let delta = light_client::apply_advance_with_profiles(
            &self.profiles,
            &self.state,
            self.network,
            advance,
            taira_now_ms,
        )?;
        self.apply(&delta);
        Ok(delta)
    }

    /// Apply `evidence`'s backfills to a copy of the replay in order, then verify its proof, all
    /// at Taira time `taira_now_ms`, as Taira executes the submissions.
    ///
    /// # Errors
    ///
    /// The verifier's first rejection.
    pub fn verify_evidence(
        &self,
        evidence: &SourceEvidenceV1,
        taira_now_ms: u64,
    ) -> Result<SccpVerifiedProofV1, SccpLcError> {
        let mut replay = self.clone();
        for backfill in &evidence.backfills {
            replay.advance(backfill, taira_now_ms)?;
        }
        light_client::verify_proof_with_profiles(
            &self.profiles,
            &replay.state,
            self.network,
            &evidence.proof,
            taira_now_ms,
        )
    }
}

impl TairaLightClientView for LightClientReplayV1 {
    fn light_client(&self) -> Result<SccpLightClientV1, BuildError> {
        self.state.light_client(self.network).ok_or_else(|| {
            BuildError::Unavailable(format!(
                "no {} light client is installed",
                self.network.profile_key()
            ))
        })
    }

    fn sets(&self) -> Result<Vec<SccpLcConsensusSetV1>, BuildError> {
        Ok(self
            .set_ids
            .iter()
            .filter_map(|set_id| self.state.consensus_set(self.network, *set_id))
            // This off-chain RPC builder returns detached response records;
            // the consensus verifier itself keeps the original borrowed view.
            .map(|set| SccpLcConsensusSetV1 {
                set_id: set.set_id,
                valid_from_source_height: set.valid_from_source_height,
                superseded_at_source_ms: set.superseded_at_source_ms,
                set_bytes: set.set_bytes.to_vec(),
            })
            .collect())
    }

    fn checkpoint_covering(
        &self,
        source_height: u64,
    ) -> Result<Option<SccpLcCheckpointV1>, BuildError> {
        Ok(self
            .checkpoints
            .range(source_height..)
            .find_map(|height| self.state.checkpoint(self.network, *height)))
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::sccp::light_client::{
        SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcHeadV1, SccpLcPointV1,
    };
    use iroha_sccp::light_client::{ethereum::EthereumHeaderSegmentV1, proof::SccpLcSegmentV1};

    use super::*;

    #[test]
    fn budgets_take_the_lower_byte_bound() {
        let params = SccpLightClientParamsV1::defaults_for(SccpNetworkV1::EthereumMainnet)
            .expect("external network");
        let budget = AdvanceBudgetV1::for_params(&params, 262_144);
        assert_eq!(budget.max_items, 16);
        assert_eq!(budget.max_bytes, 262_144);
        let wide = AdvanceBudgetV1::for_params(&params, usize::MAX);
        assert_eq!(wide.max_bytes, 1_048_576);
    }

    fn segment_frame(headers: Vec<Vec<u8>>) -> SccpLcAdvanceV1 {
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 { headers }),
        }
    }

    #[test]
    fn advances_keep_the_longest_prefix_that_fits() {
        let items: Vec<Vec<u8>> = (0..10_u8).map(|byte| vec![byte; 1_000]).collect();
        let frame_len = |count: usize| {
            segment_frame(items[..count].to_vec())
                .to_bytes()
                .expect("frame")
                .len()
        };
        let budget = AdvanceBudgetV1 {
            max_items: 16,
            max_bytes: frame_len(4),
        };
        let fitted = fit_advance(items.clone(), budget, segment_frame).expect("fits");
        assert_eq!(fitted.len(), frame_len(4));
        let capped = AdvanceBudgetV1 {
            max_items: 2,
            max_bytes: usize::MAX,
        };
        assert_eq!(
            fit_advance(items.clone(), capped, segment_frame).expect("fits"),
            segment_frame(items[..2].to_vec())
                .to_bytes()
                .expect("frame")
        );
        let tiny = AdvanceBudgetV1 {
            max_items: 16,
            max_bytes: frame_len(1) - 1,
        };
        assert!(matches!(
            fit_advance(items, tiny, segment_frame),
            Err(BuildError::Unavailable(_))
        ));
        assert!(matches!(
            fit_advance(Vec::<Vec<u8>>::new(), capped, segment_frame),
            Err(BuildError::Unavailable(_))
        ));
    }

    #[test]
    fn backfill_plans_stop_within_reach_of_the_event() {
        // Within reach: no segment.
        assert_eq!(
            plan_backfill(1_000, 1_256, 256, 256).expect("plan"),
            BackfillPlanV1 {
                segments: Vec::new(),
                anchor: 1_256,
            }
        );
        // One block beyond reach: one segment of 256 headers, then a two-header chain.
        assert_eq!(
            plan_backfill(1_000, 1_257, 256, 256).expect("plan"),
            BackfillPlanV1 {
                segments: vec![(1_002, 1_257)],
                anchor: 1_002,
            }
        );
        // 8 192 blocks: 32 segments.
        let plan = plan_backfill(10_000, 18_192, 256, 256).expect("plan");
        assert_eq!(plan.segments.len(), 32);
        assert!(plan.anchor - 10_000 <= 256);
        assert_eq!(plan.segments[0].1, 18_192);
        for pair in plan.segments.windows(2) {
            assert_eq!(
                pair[1].1, pair[0].0,
                "each segment ends at the last checkpoint"
            );
        }
        // A segment never starts below the event.
        assert_eq!(
            plan_backfill(1_000, 1_300, 0, 256).expect("plan"),
            BackfillPlanV1 {
                segments: vec![(1_045, 1_300), (1_000, 1_045)],
                anchor: 1_000,
            }
        );
        assert!(matches!(
            plan_backfill(10, 5, 256, 256),
            Err(BuildError::Inconsistent(_))
        ));
        assert!(matches!(
            plan_backfill(0, 5, 0, 1),
            Err(BuildError::Inconsistent(_))
        ));
        assert!(matches!(
            plan_backfill(0, 255 * 65 + 256, 256, 256),
            Err(BuildError::Unavailable(_))
        ));
        assert_eq!(
            plan_backfill(0, 255 * 64 + 256, 256, 256)
                .expect("plan")
                .segments
                .len(),
            MAX_BACKFILL_SEGMENTS
        );
    }

    #[test]
    fn freshness_keeps_a_margin() {
        let ws = 1_000_000;
        assert!(fresh_with_margin(None, ws, u64::MAX));
        let expiry = 10_000_000;
        let edge = expiry + ws - FRESHNESS_MARGIN_MS;
        assert!(fresh_with_margin(Some(expiry), ws, edge - 1));
        assert!(!fresh_with_margin(Some(expiry), ws, edge));
    }

    fn checkpoint(source_height: u64) -> SccpLcCheckpointV1 {
        SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height,
                block_hash: [1; 32],
                state_root: None,
                receipts_or_tx_root: [2; 32],
                source_time_ms: source_height,
            },
            recorded_at_taira_ms: 0,
            origin: SccpLcCheckpointOriginV1::Advance,
        }
    }

    #[test]
    fn replays_answer_covering_checkpoints_and_sets() {
        let network = SccpNetworkV1::BscMainnet;
        let params = SccpLightClientParamsV1::defaults_for(network).expect("external network");
        let head = SccpLcHeadV1 {
            latest_set_id: 7,
            latest_finalized: SccpLcPointV1 {
                source_height: 900,
                block_hash: [1; 32],
                source_time_ms: 900,
            },
            last_progress_taira_ms: 0,
        };
        let light_client = SccpLightClientV1 {
            params,
            head,
            frozen: None,
            state_hash: [0; 32],
        };
        let set = SccpLcConsensusSetV1 {
            set_id: 7,
            valid_from_source_height: 1,
            superseded_at_source_ms: None,
            set_bytes: vec![1],
        };
        let mut replay = LightClientReplayV1::new(
            iroha_sccp::light_client::profile::SccpChainProfilesV1::latest(),
            network,
            light_client,
            vec![set.clone()],
            vec![checkpoint(500), checkpoint(900)],
        );
        assert_eq!(replay.network(), network);
        assert_eq!(replay.light_client().expect("installed").head, head);
        assert_eq!(replay.sets().expect("sets"), vec![set]);
        let covering = |replay: &LightClientReplayV1, height| {
            replay
                .checkpoint_covering(height)
                .expect("read")
                .map(|checkpoint| checkpoint.data.source_height)
        };
        assert_eq!(covering(&replay, 100), Some(500));
        assert_eq!(covering(&replay, 500), Some(500));
        assert_eq!(covering(&replay, 501), Some(900));
        assert_eq!(covering(&replay, 901), None);
        replay.record_checkpoints(&[checkpoint(700)]);
        assert_eq!(covering(&replay, 501), Some(700));
        assert!(
            replay
                .state()
                .checkpoint(network, 700)
                .is_some_and(|stored| stored.data.source_height == 700)
        );
        assert!(
            LightClientReplayV1::new(
                iroha_sccp::light_client::profile::SccpChainProfilesV1::latest(),
                SccpNetworkV1::TonMainnet,
                light_client,
                Vec::new(),
                Vec::new()
            )
            .light_client()
            .is_ok()
        );
    }
}
