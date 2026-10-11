//! Light-client state rules (`specs/sccp.md` §4.13.1, §4.13.2).
//!
//! The verifier reads stored light-client data through [`SccpLcStateView`] and returns what to
//! write as a [`SccpLcDeltaV1`] (or, for `InitializeLightClient`, a [`SccpLcInitialStateV1`]);
//! it never writes itself. This module also holds the chain-independent rules: weak-subjectivity
//! freshness of signing sets, stride retention and pruning of checkpoints and sets, and the
//! `state_hash` compare-and-swap handle wallets pass as `expected_state_hash`.

use std::collections::BTreeMap;

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::light_client::{
        SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcConsensusSetV1,
        SccpLcFreezeReasonV1, SccpLcHeadV1, SccpLightClientParamsV1, SccpLightClientV1,
    },
};

use crate::v1::hashes::keccak256;

/// Read-only view of stored light-client data.
pub trait SccpLcStateView {
    /// The installed light client of `network`.
    fn light_client(&self, network: SccpNetworkV1) -> Option<SccpLightClientV1>;
    /// The stored consensus set `set_id` of `network`.
    fn consensus_set(&self, network: SccpNetworkV1, set_id: u64) -> Option<SccpLcConsensusSetV1>;
    /// The stored checkpoint of `network` at `source_height`.
    fn checkpoint(&self, network: SccpNetworkV1, source_height: u64) -> Option<SccpLcCheckpointV1>;
}

/// A signing set's supersession by a successor, recorded by source time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpLcSupersessionV1 {
    /// Superseded set.
    pub set_id: u64,
    /// Source time at which its successor took over.
    pub superseded_at_source_ms: u64,
}

/// What an accepted advance writes (§4.13.2).
///
/// An idempotent re-proof of stored data yields an empty delta.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SccpLcDeltaV1 {
    /// Newly learned consensus sets.
    pub new_sets: Vec<SccpLcConsensusSetV1>,
    /// Stored sets that the new sets supersede.
    pub superseded_sets: Vec<SccpLcSupersessionV1>,
    /// Newly recorded checkpoints (origin `Advance` or `Backfill`).
    pub checkpoints: Vec<SccpLcCheckpointV1>,
    /// The new head, when the advance moved it.
    pub head: Option<SccpLcHeadV1>,
}

impl SccpLcDeltaV1 {
    /// Whether the advance changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.new_sets.is_empty()
            && self.superseded_sets.is_empty()
            && self.checkpoints.is_empty()
            && self.head.is_none()
    }

    /// Whether the advance moved the head (the keeper fee exemption applies only then, §4.19).
    #[must_use]
    pub const fn moves_head(&self) -> bool {
        self.head.is_some()
    }

    /// The stored light client after this delta: the new head and its state hash.
    #[must_use]
    pub fn next_light_client(&self, current: &SccpLightClientV1) -> SccpLightClientV1 {
        let mut next = *current;
        if let Some(head) = self.head {
            next.head = head;
            next.state_hash = state_hash(&next.params, &next.head, next.frozen.as_ref());
        }
        next
    }
}

/// Stored data of the network that `InitializeLightClient` deletes before it installs
/// (§4.13.2, §4.14.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SccpLcPurgeV1 {
    /// Keep every stored set and checkpoint. Used when the installed light client only aged
    /// beyond its weak-subjectivity bound: its data was accepted under fresh sets and was never
    /// proven to conflict, and its retained checkpoints keep old burns provable.
    KeepStored,
    /// Delete every stored set and every checkpoint whose origin is not `Parliament`. Used for a
    /// first installation (nothing, or only orphaned data, is stored) and for re-initializing a
    /// frozen light client, whose committees and checkpoints learned from advances, proofs and
    /// backfills may come from an equivocating quorum and must not survive: a forged checkpoint
    /// would otherwise stay a `StoredCheckpoint` anchor and a forged next set would keep
    /// signing and block the honest one.
    DiscardUnvetted,
}

/// What `InitializeLightClient` writes (§4.13.2, §4.14.3), in order: apply [`Self::purge`],
/// record [`Self::superseded_sets`], then write the light client, [`Self::sets`] and
/// [`Self::checkpoints`] (replacing any same-key entry).
///
/// [`super::initialize_light_client`] builds it from the stored state and the expectation;
/// [`super::verify_bootstrap`] alone, which sees no stored state, returns the safe
/// [`SccpLcPurgeV1::DiscardUnvetted`] with no supersessions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SccpLcInitialStateV1 {
    /// The light client record, with its state hash.
    pub light_client: SccpLightClientV1,
    /// Stored data deleted before the install.
    pub purge: SccpLcPurgeV1,
    /// Kept stored sets that the bootstrap set supersedes (aged re-initialization only).
    pub superseded_sets: Vec<SccpLcSupersessionV1>,
    /// The bootstrap signing set.
    pub sets: Vec<SccpLcConsensusSetV1>,
    /// The bootstrap checkpoint (origin `Parliament`).
    pub checkpoints: Vec<SccpLcCheckpointV1>,
}

/// Whether two records of one source height describe the same block: equal block hash, receipts
/// or transaction root and source time, and equal state roots when both carry one (a Parliament
/// checkpoint may omit it).
///
/// A record that disagrees in any of these fields conflicts with stored data even when the block
/// hash matches, because proofs read the roots from the stored record.
#[must_use]
pub fn same_checkpoint_block(a: &SccpLcCheckpointDataV1, b: &SccpLcCheckpointDataV1) -> bool {
    a.source_height == b.source_height
        && a.block_hash == b.block_hash
        && a.receipts_or_tx_root == b.receipts_or_tx_root
        && a.source_time_ms == b.source_time_ms
        && match (a.state_root, b.state_root) {
            (Some(x), Some(y)) => x == y,
            _ => true,
        }
}

/// Collects the checkpoints an advance, proof or backfill records for one network, idempotent
/// against stored ones and conflict-checked by content ([`same_checkpoint_block`]).
pub(super) struct CheckpointRecorder<'a, V: SccpLcStateView + ?Sized> {
    view: &'a V,
    network: SccpNetworkV1,
    origin: SccpLcCheckpointOriginV1,
    now: u64,
    pending: BTreeMap<u64, SccpLcCheckpointV1>,
}

impl<'a, V: SccpLcStateView + ?Sized> CheckpointRecorder<'a, V> {
    pub(super) const fn new(
        view: &'a V,
        network: SccpNetworkV1,
        origin: SccpLcCheckpointOriginV1,
        now: u64,
    ) -> Self {
        Self {
            view,
            network,
            origin,
            now,
            pending: BTreeMap::new(),
        }
    }

    /// Record `data` unless an identical record exists; a different record at the same height
    /// is a conflict.
    pub(super) fn record(
        &mut self,
        data: SccpLcCheckpointDataV1,
    ) -> Result<(), super::SccpLcError> {
        let height = data.source_height;
        let existing = self
            .pending
            .get(&height)
            .map(|checkpoint| checkpoint.data)
            .or_else(|| {
                self.view
                    .checkpoint(self.network, height)
                    .map(|checkpoint| checkpoint.data)
            });
        match existing {
            Some(existing) if !same_checkpoint_block(&existing, &data) => Err(
                super::SccpLcError::ConflictsWithStoredData(super::SccpLcConflictV1::Checkpoint {
                    source_height: height,
                }),
            ),
            Some(_) => Ok(()),
            None => {
                self.pending.insert(
                    height,
                    SccpLcCheckpointV1 {
                        data,
                        recorded_at_taira_ms: self.now,
                        origin: self.origin,
                    },
                );
                Ok(())
            }
        }
    }

    /// The new checkpoints in height order.
    pub(super) fn into_vec(self) -> Vec<SccpLcCheckpointV1> {
        self.pending.into_values().collect()
    }
}

/// Canonical light-client state bytes hashed into `state_hash`.
#[derive(
    Debug, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::state::StateHashInputV1")]
struct StateHashInputV1 {
    params: SccpLightClientParamsV1,
    head: SccpLcHeadV1,
    frozen: Option<SccpLcFreezeReasonV1>,
}

/// `state_hash = keccak256("SCCP/LC/STATE/V1" ‖ frame)` over the headered Norito frame of the
/// params, head and freeze reason.
///
/// Every head move changes it (the head carries `last_progress_taira_ms`), so it serves as the
/// compare-and-swap handle of `AdvanceSccpLightClientV1`.
#[must_use]
pub fn state_hash(
    params: &SccpLightClientParamsV1,
    head: &SccpLcHeadV1,
    frozen: Option<&SccpLcFreezeReasonV1>,
) -> [u8; 32] {
    let input = StateHashInputV1 {
        params: *params,
        head: *head,
        frozen: frozen.copied(),
    };
    // Encoding a fixed-shape value of `Copy` fields cannot fail; an empty frame would still hash
    // deterministically on every peer.
    let frame = norito::encode_canonical(&input).unwrap_or_default();
    keccak256(&[b"SCCP/LC/STATE/V1", &frame])
}

/// Whether a signing set is fresh at `taira_now_ms` (§4.13.2).
///
/// `expiry_ms` is the source time at which the set was (or is scheduled to be) superseded;
/// `None` means current. A set is fresh while it is current or was superseded less than
/// `ws_bound_ms` before `taira_now_ms`.
#[must_use]
pub const fn is_set_fresh(expiry_ms: Option<u64>, ws_bound_ms: u64, taira_now_ms: u64) -> bool {
    match expiry_ms {
        None => true,
        Some(expiry) => expiry.saturating_add(ws_bound_ms) > taira_now_ms,
    }
}

/// Retention class of a checkpoint (§4.13.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SccpLcRetentionClassV1 {
    /// Parliament-installed: kept permanently.
    Permanent,
    /// Kept permanently iff it is the lowest checkpoint recorded in stride bucket `bucket`,
    /// otherwise pruned after `checkpoint_prune_after_ms`.
    StrideCandidate {
        /// `source_height / stride`.
        bucket: u64,
    },
    /// Pruned after `checkpoint_prune_after_ms` (TON keeps no stride checkpoints).
    Prunable,
}

/// Classify a checkpoint at `height` recorded with `origin` under `stride` (§4.13.1).
#[must_use]
pub const fn retention_class(
    network: SccpNetworkV1,
    height: u64,
    stride: u64,
    origin: SccpLcCheckpointOriginV1,
) -> SccpLcRetentionClassV1 {
    if matches!(origin, SccpLcCheckpointOriginV1::Parliament) {
        return SccpLcRetentionClassV1::Permanent;
    }
    if stride == 0
        || matches!(
            network,
            SccpNetworkV1::TonMainnet | SccpNetworkV1::SoraTaira
        )
    {
        return SccpLcRetentionClassV1::Prunable;
    }
    SccpLcRetentionClassV1::StrideCandidate {
        bucket: height / stride,
    }
}

/// Whether a checkpoint is kept permanently, given the lowest height recorded in its bucket.
#[must_use]
pub fn is_permanent_checkpoint(
    network: SccpNetworkV1,
    checkpoint: &SccpLcCheckpointV1,
    stride: u64,
    lowest_in_bucket: Option<u64>,
) -> bool {
    match retention_class(
        network,
        checkpoint.data.source_height,
        stride,
        checkpoint.origin,
    ) {
        SccpLcRetentionClassV1::Permanent => true,
        SccpLcRetentionClassV1::StrideCandidate { .. } => {
            lowest_in_bucket.is_none_or(|lowest| lowest >= checkpoint.data.source_height)
        }
        SccpLcRetentionClassV1::Prunable => false,
    }
}

/// Whether a checkpoint may be pruned at `taira_now_ms`.
#[must_use]
pub fn checkpoint_prune_due(
    network: SccpNetworkV1,
    checkpoint: &SccpLcCheckpointV1,
    params: &SccpLightClientParamsV1,
    lowest_in_bucket: Option<u64>,
    taira_now_ms: u64,
) -> bool {
    !is_permanent_checkpoint(
        network,
        checkpoint,
        params.checkpoint_stride,
        lowest_in_bucket,
    ) && checkpoint
        .recorded_at_taira_ms
        .saturating_add(params.checkpoint_prune_after_ms)
        <= taira_now_ms
}

/// Whether a superseded set may be pruned at `now_ms` (retained `set_retention_ms` after
/// supersession; a current set is never pruned).
#[must_use]
pub fn set_prune_due(
    set: &SccpLcConsensusSetV1,
    params: &SccpLightClientParamsV1,
    now_ms: u64,
) -> bool {
    set.superseded_at_source_ms
        .is_some_and(|at| at.saturating_add(params.set_retention_ms) <= now_ms)
}

/// In-memory light-client storage.
///
/// Wallets and tools use it to replay advances locally before submitting them; tests use it as
/// world state. It applies initial states and deltas exactly as core writes them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SccpLcMemoryStateV1 {
    light_clients: BTreeMap<SccpNetworkV1, SccpLightClientV1>,
    sets: BTreeMap<(SccpNetworkV1, u64), SccpLcConsensusSetV1>,
    checkpoints: BTreeMap<(SccpNetworkV1, u64), SccpLcCheckpointV1>,
}

impl SccpLcMemoryStateV1 {
    /// Empty storage.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install an initial state exactly as core applies `InitializeLightClient`: apply the
    /// purge, record the supersessions, then write the light client (replacing any previous
    /// one), its sets and its checkpoints.
    pub fn install(&mut self, network: SccpNetworkV1, initial: &SccpLcInitialStateV1) {
        if initial.purge == SccpLcPurgeV1::DiscardUnvetted {
            self.sets.retain(|(stored, _), _| *stored != network);
            self.checkpoints.retain(|(stored, _), checkpoint| {
                *stored != network || checkpoint.origin == SccpLcCheckpointOriginV1::Parliament
            });
        }
        for supersession in &initial.superseded_sets {
            if let Some(set) = self.sets.get_mut(&(network, supersession.set_id)) {
                set.superseded_at_source_ms = Some(supersession.superseded_at_source_ms);
            }
        }
        self.light_clients.insert(network, initial.light_client);
        for set in &initial.sets {
            self.sets.insert((network, set.set_id), set.clone());
        }
        for checkpoint in &initial.checkpoints {
            self.checkpoints
                .insert((network, checkpoint.data.source_height), *checkpoint);
        }
    }

    /// Apply an advance's delta (sets, supersessions, checkpoints, head and state hash).
    pub fn apply(&mut self, network: SccpNetworkV1, delta: &SccpLcDeltaV1) {
        for set in &delta.new_sets {
            self.sets.insert((network, set.set_id), set.clone());
        }
        for supersession in &delta.superseded_sets {
            if let Some(set) = self.sets.get_mut(&(network, supersession.set_id)) {
                set.superseded_at_source_ms = Some(supersession.superseded_at_source_ms);
            }
        }
        for checkpoint in &delta.checkpoints {
            self.checkpoints
                .entry((network, checkpoint.data.source_height))
                .or_insert(*checkpoint);
        }
        if let Some(current) = self.light_clients.get(&network).copied() {
            self.light_clients
                .insert(network, delta.next_light_client(&current));
        }
    }

    /// Record checkpoints returned by an accepted proof (first write wins).
    pub fn record_checkpoints(
        &mut self,
        network: SccpNetworkV1,
        checkpoints: &[SccpLcCheckpointV1],
    ) {
        for checkpoint in checkpoints {
            self.checkpoints
                .entry((network, checkpoint.data.source_height))
                .or_insert(*checkpoint);
        }
    }

    /// Replace a light client record (for example to freeze it).
    pub fn set_light_client(&mut self, network: SccpNetworkV1, light_client: SccpLightClientV1) {
        self.light_clients.insert(network, light_client);
    }

    /// Remove a stored checkpoint (pruning).
    pub fn remove_checkpoint(&mut self, network: SccpNetworkV1, source_height: u64) {
        self.checkpoints.remove(&(network, source_height));
    }

    /// Number of stored consensus sets of `network`.
    #[must_use]
    pub fn set_count(&self, network: SccpNetworkV1) -> usize {
        self.sets.range((network, 0)..=(network, u64::MAX)).count()
    }

    /// Number of stored checkpoints of `network`.
    #[must_use]
    pub fn checkpoint_count(&self, network: SccpNetworkV1) -> usize {
        self.checkpoints
            .range((network, 0)..=(network, u64::MAX))
            .count()
    }
}

impl SccpLcStateView for SccpLcMemoryStateV1 {
    fn light_client(&self, network: SccpNetworkV1) -> Option<SccpLightClientV1> {
        self.light_clients.get(&network).copied()
    }

    fn consensus_set(&self, network: SccpNetworkV1, set_id: u64) -> Option<SccpLcConsensusSetV1> {
        self.sets.get(&(network, set_id)).cloned()
    }

    fn checkpoint(&self, network: SccpNetworkV1, source_height: u64) -> Option<SccpLcCheckpointV1> {
        self.checkpoints.get(&(network, source_height)).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sccp::light_client::{
        SccpLcCheckpointDataV1, SccpLcEquivocationFreezeV1, SccpLcPointV1,
    };

    const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;

    fn params() -> SccpLightClientParamsV1 {
        SccpLightClientParamsV1::defaults_for(ETH).expect("external")
    }

    fn head(height: u64, progress: u64) -> SccpLcHeadV1 {
        SccpLcHeadV1 {
            latest_set_id: 7,
            latest_finalized: SccpLcPointV1 {
                source_height: height,
                block_hash: [1; 32],
                source_time_ms: 5,
            },
            last_progress_taira_ms: progress,
        }
    }

    fn checkpoint(height: u64, origin: SccpLcCheckpointOriginV1, at: u64) -> SccpLcCheckpointV1 {
        SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height: height,
                block_hash: [u8::try_from(height % 251).unwrap_or(0); 32],
                state_root: None,
                receipts_or_tx_root: [2; 32],
                source_time_ms: 3,
            },
            recorded_at_taira_ms: at,
            origin,
        }
    }

    #[test]
    fn freshness_is_strict_at_the_bound() {
        assert!(is_set_fresh(None, 10, u64::MAX));
        assert!(is_set_fresh(Some(100), 10, 109));
        assert!(!is_set_fresh(Some(100), 10, 110));
        assert!(is_set_fresh(Some(u64::MAX), 10, u64::MAX - 1));
    }

    #[test]
    fn state_hash_changes_with_head_params_and_freeze() {
        let base = state_hash(&params(), &head(10, 1), None);
        assert_eq!(base, state_hash(&params(), &head(10, 1), None));
        assert_ne!(base, state_hash(&params(), &head(10, 2), None));
        assert_ne!(base, state_hash(&params(), &head(11, 1), None));
        let mut other = params();
        other.ws_bound_ms += 1;
        assert_ne!(base, state_hash(&other, &head(10, 1), None));
        let frozen = SccpLcFreezeReasonV1::Equivocation(SccpLcEquivocationFreezeV1 {
            evidence_hash: [9; 32],
        });
        assert_ne!(base, state_hash(&params(), &head(10, 1), Some(&frozen)));
    }

    #[test]
    fn retention_classes_follow_the_stride_rule() {
        assert_eq!(
            retention_class(ETH, 8_192 * 3 + 5, 8_192, SccpLcCheckpointOriginV1::Advance),
            SccpLcRetentionClassV1::StrideCandidate { bucket: 3 }
        );
        assert_eq!(
            retention_class(ETH, 5, 8_192, SccpLcCheckpointOriginV1::Parliament),
            SccpLcRetentionClassV1::Permanent
        );
        assert_eq!(
            retention_class(
                SccpNetworkV1::TonMainnet,
                5,
                0,
                SccpLcCheckpointOriginV1::Proof
            ),
            SccpLcRetentionClassV1::Prunable
        );
        assert_eq!(
            retention_class(
                SccpNetworkV1::BscMainnet,
                16_384,
                8_192,
                SccpLcCheckpointOriginV1::Backfill
            ),
            SccpLcRetentionClassV1::StrideCandidate { bucket: 2 }
        );
        let lowest = checkpoint(8_192 * 3 + 5, SccpLcCheckpointOriginV1::Backfill, 0);
        let higher = checkpoint(8_192 * 3 + 9, SccpLcCheckpointOriginV1::Advance, 0);
        assert!(is_permanent_checkpoint(
            ETH,
            &lowest,
            8_192,
            Some(lowest.data.source_height)
        ));
        assert!(is_permanent_checkpoint(ETH, &lowest, 8_192, None));
        assert!(!is_permanent_checkpoint(
            ETH,
            &higher,
            8_192,
            Some(lowest.data.source_height)
        ));
        let parliament = checkpoint(8_192 * 3 + 9, SccpLcCheckpointOriginV1::Parliament, 0);
        assert!(is_permanent_checkpoint(ETH, &parliament, 8_192, Some(1)));
    }

    #[test]
    fn pruning_keeps_permanent_checkpoints_and_current_sets() {
        let params = params();
        let prune_after = params.checkpoint_prune_after_ms;
        let higher = checkpoint(8_192 + 9, SccpLcCheckpointOriginV1::Advance, 100);
        assert!(!checkpoint_prune_due(
            ETH,
            &higher,
            &params,
            Some(8_192),
            100 + prune_after - 1
        ));
        assert!(checkpoint_prune_due(
            ETH,
            &higher,
            &params,
            Some(8_192),
            100 + prune_after
        ));
        assert!(!checkpoint_prune_due(
            ETH,
            &higher,
            &params,
            Some(8_192 + 9),
            u64::MAX
        ));
        let mut set = SccpLcConsensusSetV1 {
            set_id: 1,
            valid_from_source_height: 0,
            superseded_at_source_ms: None,
            set_bytes: vec![1],
        };
        assert!(!set_prune_due(&set, &params, u64::MAX));
        set.superseded_at_source_ms = Some(1_000);
        assert!(!set_prune_due(
            &set,
            &params,
            1_000 + params.set_retention_ms - 1
        ));
        assert!(set_prune_due(
            &set,
            &params,
            1_000 + params.set_retention_ms
        ));
    }

    #[test]
    fn memory_state_applies_initial_states_and_deltas() {
        let mut memory = SccpLcMemoryStateV1::new();
        let initial_head = head(10, 1);
        let light_client = SccpLightClientV1 {
            params: params(),
            head: initial_head,
            frozen: None,
            state_hash: state_hash(&params(), &initial_head, None),
        };
        let set = SccpLcConsensusSetV1 {
            set_id: 7,
            valid_from_source_height: 0,
            superseded_at_source_ms: None,
            set_bytes: vec![7],
        };
        memory.install(
            ETH,
            &SccpLcInitialStateV1 {
                light_client,
                purge: SccpLcPurgeV1::DiscardUnvetted,
                superseded_sets: Vec::new(),
                sets: vec![set.clone()],
                checkpoints: vec![checkpoint(10, SccpLcCheckpointOriginV1::Parliament, 1)],
            },
        );
        assert_eq!(memory.light_client(ETH), Some(light_client));
        assert_eq!(memory.set_count(ETH), 1);
        assert_eq!(memory.consensus_set(ETH, 7), Some(set));
        assert_eq!(memory.checkpoint_count(ETH), 1);
        assert!(SccpLcDeltaV1::default().is_empty());
        let moved = head(20, 2);
        let delta = SccpLcDeltaV1 {
            new_sets: vec![SccpLcConsensusSetV1 {
                set_id: 8,
                valid_from_source_height: 1,
                superseded_at_source_ms: None,
                set_bytes: vec![8],
            }],
            superseded_sets: vec![SccpLcSupersessionV1 {
                set_id: 7,
                superseded_at_source_ms: 55,
            }],
            checkpoints: vec![checkpoint(20, SccpLcCheckpointOriginV1::Advance, 2)],
            head: Some(moved),
        };
        assert!(!delta.is_empty() && delta.moves_head());
        memory.apply(ETH, &delta);
        let updated = memory.light_client(ETH).expect("installed");
        assert_eq!(updated.head, moved);
        assert_eq!(updated.state_hash, state_hash(&params(), &moved, None));
        assert_eq!(
            memory
                .consensus_set(ETH, 7)
                .and_then(|set| set.superseded_at_source_ms),
            Some(55)
        );
        assert!(memory.checkpoint(ETH, 20).is_some());
        memory.record_checkpoints(ETH, &[checkpoint(30, SccpLcCheckpointOriginV1::Proof, 3)]);
        assert_eq!(memory.checkpoint_count(ETH), 3);
        memory.remove_checkpoint(ETH, 30);
        assert_eq!(memory.checkpoint_count(ETH), 2);
        let mut frozen = updated;
        frozen.frozen = Some(SccpLcFreezeReasonV1::Equivocation(
            SccpLcEquivocationFreezeV1 {
                evidence_hash: [1; 32],
            },
        ));
        memory.set_light_client(ETH, frozen);
        assert!(
            memory
                .light_client(ETH)
                .is_some_and(|client| client.is_frozen())
        );
        assert_eq!(delta.next_light_client(&updated).head, moved);
    }

    fn installed_with(
        memory: &mut SccpLcMemoryStateV1,
        purge: SccpLcPurgeV1,
        superseded_sets: Vec<SccpLcSupersessionV1>,
        set_id: u64,
        height: u64,
    ) {
        let initial_head = head(height, 9);
        memory.install(
            ETH,
            &SccpLcInitialStateV1 {
                light_client: SccpLightClientV1 {
                    params: params(),
                    head: initial_head,
                    frozen: None,
                    state_hash: state_hash(&params(), &initial_head, None),
                },
                purge,
                superseded_sets,
                sets: vec![SccpLcConsensusSetV1 {
                    set_id,
                    valid_from_source_height: height,
                    superseded_at_source_ms: None,
                    set_bytes: vec![u8::try_from(set_id % 251).unwrap_or(0)],
                }],
                checkpoints: vec![checkpoint(height, SccpLcCheckpointOriginV1::Parliament, 9)],
            },
        );
    }

    #[test]
    fn install_discards_unvetted_data_of_the_network_only() {
        let mut memory = SccpLcMemoryStateV1::new();
        installed_with(
            &mut memory,
            SccpLcPurgeV1::DiscardUnvetted,
            Vec::new(),
            7,
            10,
        );
        // Learned sets and checkpoints of every origin, plus another network's data.
        memory.apply(
            ETH,
            &SccpLcDeltaV1 {
                new_sets: vec![SccpLcConsensusSetV1 {
                    set_id: 8,
                    valid_from_source_height: 20,
                    superseded_at_source_ms: None,
                    set_bytes: vec![8],
                }],
                checkpoints: vec![
                    checkpoint(20, SccpLcCheckpointOriginV1::Advance, 2),
                    checkpoint(21, SccpLcCheckpointOriginV1::Backfill, 2),
                ],
                ..SccpLcDeltaV1::default()
            },
        );
        memory.record_checkpoints(
            ETH,
            &[
                checkpoint(22, SccpLcCheckpointOriginV1::Proof, 3),
                checkpoint(23, SccpLcCheckpointOriginV1::Parliament, 3),
            ],
        );
        let bsc = SccpNetworkV1::BscMainnet;
        memory.record_checkpoints(bsc, &[checkpoint(5, SccpLcCheckpointOriginV1::Advance, 1)]);
        assert_eq!(
            (memory.set_count(ETH), memory.checkpoint_count(ETH)),
            (2, 5)
        );
        // Re-initializing a frozen light client keeps only the Parliament checkpoints.
        installed_with(
            &mut memory,
            SccpLcPurgeV1::DiscardUnvetted,
            Vec::new(),
            9,
            30,
        );
        assert_eq!(memory.set_count(ETH), 1);
        assert!(memory.consensus_set(ETH, 8).is_none());
        assert!(memory.consensus_set(ETH, 9).is_some());
        for gone in [20, 21, 22] {
            assert!(memory.checkpoint(ETH, gone).is_none(), "height {gone}");
        }
        for kept in [10, 23, 30] {
            assert!(memory.checkpoint(ETH, kept).is_some(), "height {kept}");
        }
        assert_eq!(memory.checkpoint_count(bsc), 1);
    }

    #[test]
    fn install_keeps_stored_data_and_records_supersessions_of_an_aged_client() {
        let mut memory = SccpLcMemoryStateV1::new();
        installed_with(
            &mut memory,
            SccpLcPurgeV1::DiscardUnvetted,
            Vec::new(),
            7,
            10,
        );
        memory.record_checkpoints(ETH, &[checkpoint(20, SccpLcCheckpointOriginV1::Proof, 3)]);
        installed_with(
            &mut memory,
            SccpLcPurgeV1::KeepStored,
            vec![SccpLcSupersessionV1 {
                set_id: 7,
                superseded_at_source_ms: 77,
            }],
            9,
            30,
        );
        assert_eq!(memory.set_count(ETH), 2);
        assert_eq!(
            memory
                .consensus_set(ETH, 7)
                .and_then(|set| set.superseded_at_source_ms),
            Some(77)
        );
        assert!(
            memory
                .consensus_set(ETH, 9)
                .is_some_and(|set| set.is_current())
        );
        assert_eq!(memory.checkpoint_count(ETH), 3);
        assert_eq!(
            memory
                .light_client(ETH)
                .map(|client| client.head.latest_finalized.source_height),
            Some(30)
        );
    }

    #[test]
    fn same_checkpoint_block_compares_every_committed_field() {
        let base = checkpoint(10, SccpLcCheckpointOriginV1::Advance, 1).data;
        assert!(same_checkpoint_block(&base, &base));
        let mut with_state = base;
        with_state.state_root = Some([4; 32]);
        assert!(same_checkpoint_block(&base, &with_state));
        assert!(same_checkpoint_block(&with_state, &base));
        let mut other_state = with_state;
        other_state.state_root = Some([5; 32]);
        assert!(!same_checkpoint_block(&with_state, &other_state));
        let mut other_hash = base;
        other_hash.block_hash[0] ^= 1;
        let mut other_root = base;
        other_root.receipts_or_tx_root[0] ^= 1;
        let mut other_time = base;
        other_time.source_time_ms += 1;
        let mut other_height = base;
        other_height.source_height += 1;
        for different in [other_hash, other_root, other_time, other_height] {
            assert!(!same_checkpoint_block(&base, &different));
        }
    }
}
