/// Policy and state for a shielded asset.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::state::FrontierCheckpoint")]
#[derive(
    Copy, Clone, Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize,
)]
pub struct FrontierCheckpoint {
    /// Block height when the checkpoint was recorded.
    pub height: u64,
    /// Number of commitments present when the checkpoint was recorded.
    pub commitment_count: u64,
    /// Merkle root associated with the checkpoint.
    pub root: [u8; 32],
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Summary of how a frontier checkpoint update changed the rolling history.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FrontierCheckpointUpdate {
    /// Whether a new checkpoint was recorded.
    pub recorded: bool,
    /// How many checkpoints were evicted to satisfy depth/interval constraints.
    pub evicted: u64,
}
mod zk_asset_tree_frontier_json {
    pub(super) fn serialize(
        frontier: &crate::zk::confidential_v2::ConfidentialTreeFrontierV2,
        out: &mut String,
    ) {
        out.push('[');
        for (index, node) in frontier.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            norito::json::JsonSerialize::json_serialize(node, out);
        }
        out.push(']');
    }
}
/// Canonical shielded asset ledger snapshot persisted within the world state.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::state::ZkAssetState")]
#[derive(Clone, Debug, JsonSerialize, NoritoSerialize, NoritoDeserialize)]
pub struct ZkAssetState {
    /// Authenticated commitment-tree construction for this asset.
    pub tree_profile: ConfidentialTreeProfile,
    /// Fixed-size incremental frontier authenticated by `commitments`.
    #[norito(with = "zk_asset_tree_frontier_json")]
    pub tree_frontier: crate::zk::confidential_v2::ConfidentialTreeFrontierV2,
    /// Current root authenticated by the incremental frontier and retained history.
    pub persisted_root: [u8; 32],
    /// Append‑only list of note commitments (leaves of the Merkle tree).
    pub commitments: Vec<[u8; 32]>,
    /// Historical Merkle roots for recent states (for light clients/proofs).
    pub root_history: Vec<[u8; 32]>,
    /// Set of consumed nullifiers to prevent double spends.
    pub nullifiers: std::collections::BTreeSet<[u8; 32]>,
    /// Required verifying key for unshield proofs (if configured).
    pub vk_unshield: Option<ZkAssetVerifierBinding>,
    /// Rolling set of frontier checkpoints (height, commitment count, root).
    pub frontier_checkpoints: Vec<FrontierCheckpoint>,
}
impl Default for ZkAssetState {
    fn default() -> Self {
        let tree_profile = ConfidentialTreeProfile::default();
        Self {
            tree_profile,
            tree_frontier: [None; crate::zk::confidential_v2::CONFIDENTIAL_TREE_DEPTH_V2],
            persisted_root: tree_profile.empty_root(),
            commitments: Vec::new(),
            root_history: Vec::new(),
            nullifiers: std::collections::BTreeSet::new(),
            vk_unshield: None,
            frontier_checkpoints: Vec::new(),
        }
    }
}
impl ZkAssetState {
    #[cfg(test)]
    /// Compute the root after one commitment without cloning or mutating the
    /// retained tree state.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained tree metadata is inconsistent, the
    /// commitment is not canonical, or the fixed-capacity tree is full.
    pub fn preview_commitment_root(&self, commitment: [u8; 32]) -> Result<[u8; 32], String> {
        self.validate_tree_metadata()?;
        let append = crate::zk::confidential_v2::append_confidential_tree_frontier_v2(
            self.commitments.len(),
            &self.tree_frontier,
            self.persisted_root,
            &[commitment],
        )?;
        Ok(append.current_root)
    }
    /// Validate the constant-size metadata needed by hot mutation and root reads.
    ///
    /// Complete retained-history and checkpoint validation belongs to
    /// [`Self::validate_tree_integrity`] at decode, recovery, or admitted audit
    /// boundaries. Previously validated history is append-only, so hot writes
    /// need only recheck its current authenticated tail.
    ///
    /// # Errors
    /// Returns an error if the frontier, current root, retained root-history tail,
    /// or latest checkpoint contradicts the commitment count or tree profile,
    /// contains a non-canonical node, or exceeds a fixed bound.
    pub fn validate_tree_metadata(&self) -> Result<(), String> {
        if self.frontier_checkpoints.len()
            > crate::zk::confidential_v2::CONFIDENTIAL_TREE_CAPACITY_V2
        {
            return Err(
                "confidential frontier checkpoint history exceeds its fixed bound".to_owned(),
            );
        }
        crate::zk::confidential_v2::validate_confidential_tree_frontier_v2(
            self.commitments.len(),
            &self.tree_frontier,
            self.persisted_root,
        )?;
        if self.commitments.is_empty() {
            if !self.root_history.is_empty() {
                return Err(
                    "empty confidential tree must not contain commitment root history".to_owned(),
                );
            }
            if self.persisted_root != self.tree_profile.empty_root() {
                return Err(
                    "empty confidential tree must retain its profile-defined root".to_owned(),
                );
            }
        } else if self.root_history.is_empty() {
            return Err("non-empty confidential tree must retain its current root".to_owned());
        } else if self.root_history.len() > self.commitments.len() {
            return Err("confidential root history cannot exceed the commitment count".to_owned());
        } else if self.root_history.last().copied() != Some(self.persisted_root) {
            return Err(
                "confidential root history tail does not match the persisted current root"
                    .to_owned(),
            );
        }
        if let Some(checkpoint) = self.frontier_checkpoints.last() {
            let commitment_count = usize::try_from(checkpoint.commitment_count).map_err(|_| {
                "frontier checkpoint commitment count does not fit usize".to_owned()
            })?;
            if commitment_count > self.commitments.len() {
                return Err("frontier checkpoint exceeds the persisted commitment count".to_owned());
            }
            if !crate::zk::confidential_v2::confidential_tree_node_is_canonical_v2(checkpoint.root)
            {
                return Err("frontier checkpoint root is not canonical".to_owned());
            }
            if commitment_count == 0 && checkpoint.root != self.tree_profile.empty_root() {
                return Err(
                    "empty frontier checkpoint root does not match the tree profile".to_owned(),
                );
            }
            if commitment_count == self.commitments.len() && checkpoint.root != self.persisted_root
            {
                return Err(
                    "current frontier checkpoint root does not match the persisted current root"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }
    /// Fully rebuild and validate persisted roots, frontier, and checkpoints.
    ///
    /// This linear audit is intentionally reserved for decode, recovery, and
    /// explicitly admitted audit paths. Hot appends use
    /// [`Self::validate_tree_metadata`] and the persisted incremental frontier.
    ///
    /// # Errors
    /// Returns an error for invalid tree metadata or commitment leaves, a persisted
    /// root or frontier that differs from its reconstruction, or inconsistent
    /// retained roots, checkpoint ordering, counts, or checkpoint roots.
    pub fn validate_tree_integrity(&self) -> Result<(), String> {
        self.validate_tree_metadata()?;
        let projection =
            crate::zk::confidential_v2::ConfidentialTreeProjectionV2::build(&self.commitments)?;
        if projection.root() != self.persisted_root {
            return Err(
                "persisted confidential current root does not match the commitment projection"
                    .to_owned(),
            );
        }
        if projection.frontier()? != self.tree_frontier {
            return Err(
                "persisted confidential frontier does not match the commitment projection"
                    .to_owned(),
            );
        }
        let prefix_roots = self.tree_profile.compute_prefix_roots(&self.commitments)?;
        if !self.commitments.is_empty() {
            let retained_start = self.commitments.len() - self.root_history.len();
            let expected_history = prefix_roots
                .get(retained_start..)
                .ok_or_else(|| "confidential prefix-root computation truncated state".to_owned())?;
            if self.root_history.as_slice() != expected_history {
                return Err(
                    "confidential root history does not match the persisted tree profile"
                        .to_owned(),
                );
            }
        }
        let mut previous_height = None;
        let mut previous_commitment_count = None;
        for checkpoint in &self.frontier_checkpoints {
            if previous_height.is_some_and(|height| checkpoint.height <= height) {
                return Err("frontier checkpoint heights must be strictly increasing".to_owned());
            }
            previous_height = Some(checkpoint.height);
            if previous_commitment_count.is_some_and(|count| checkpoint.commitment_count < count) {
                return Err(
                    "frontier checkpoint commitment counts must be non-decreasing".to_owned(),
                );
            }
            previous_commitment_count = Some(checkpoint.commitment_count);
            let commitment_count = usize::try_from(checkpoint.commitment_count).map_err(|_| {
                "frontier checkpoint commitment count does not fit usize".to_owned()
            })?;
            if commitment_count > self.commitments.len() {
                return Err("frontier checkpoint exceeds the persisted commitment count".to_owned());
            }
            let expected = if commitment_count == 0 {
                self.tree_profile.empty_root()
            } else {
                *prefix_roots.get(commitment_count - 1).ok_or_else(|| {
                    "confidential prefix-root computation truncated checkpoint state".to_owned()
                })?
            };
            if checkpoint.root != expected {
                return Err(
                    "frontier checkpoint root does not match the persisted tree profile".to_owned(),
                );
            }
        }
        Ok(())
    }
    /// Append a 32-byte note commitment to the shielded ledger and update the root.
    /// Enforces a cap on the number of recent roots kept (`cap`, minimum 1).
    /// Returns the new Merkle root.
    ///
    /// # Errors
    /// Returns an error if tree metadata or the commitment is invalid, tree capacity
    /// is exhausted, required storage cannot be reserved, or the append produces
    /// no root.
    pub fn push_commitment(&mut self, c: [u8; 32], cap: NonZeroUsize) -> Result<[u8; 32], String> {
        self.push_commitments(&[c], cap)?
            .into_iter()
            .next()
            .ok_or_else(|| "single commitment append produced no root".to_owned())
    }
    /// Atomically append an ordered commitment batch and return each resulting root.
    ///
    /// The complete batch is validated before either commitments or retained roots
    /// are changed, so a malformed leaf or capacity overflow leaves all persisted
    /// values unchanged.
    ///
    /// # Errors
    /// Returns an error if the count overflows or exceeds tree capacity, metadata
    /// or a commitment is invalid, or commitment and root-history storage cannot
    /// be reserved.
    pub fn push_commitments(
        &mut self,
        commitments: &[[u8; 32]],
        cap: NonZeroUsize,
    ) -> Result<Vec<[u8; 32]>, String> {
        let previous_len = self.commitments.len();
        let next_len = previous_len
            .checked_add(commitments.len())
            .ok_or_else(|| "confidential commitment count overflow".to_owned())?;
        if next_len > self.tree_profile.capacity() {
            return Err(format!(
                "confidential tree capacity {} exceeded by {next_len} commitments",
                self.tree_profile.capacity(),
            ));
        }
        self.validate_tree_metadata()?;
        if commitments.is_empty() {
            return Ok(Vec::new());
        }
        let append = crate::zk::confidential_v2::append_confidential_tree_frontier_v2(
            previous_len,
            &self.tree_frontier,
            self.persisted_root,
            commitments,
        )?;
        self.commitments
            .try_reserve(commitments.len())
            .map_err(|error| {
                format!("failed to reserve confidential commitment storage: {error}")
            })?;
        self.root_history
            .try_reserve(append.appended_roots.len())
            .map_err(|error| format!("failed to reserve confidential root history: {error}"))?;
        self.commitments.extend_from_slice(commitments);
        self.root_history.extend_from_slice(&append.appended_roots);
        // Bound retained roots by the sole confidential tree-history policy.
        let max_keep = cap.get();
        let len = self.root_history.len();
        if len > max_keep {
            let surplus = len - max_keep;
            self.root_history.drain(0..surplus);
        }
        self.tree_frontier = append.frontier;
        self.persisted_root = append.current_root;
        Ok(append.appended_roots)
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Record a frontier checkpoint for reorg recovery, enforcing interval and depth bounds.
    ///
    /// # Errors
    /// Returns an error if the retained tree metadata fails validation before the
    /// checkpoint policy is applied.
    pub fn record_frontier_checkpoint(
        &mut self,
        height: u64,
        interval: u64,
        depth_bound: u64,
    ) -> Result<FrontierCheckpointUpdate, String> {
        self.validate_tree_metadata()?;
        let mut update = FrontierCheckpointUpdate::default();
        if interval == 0 {
            return Ok(update);
        }
        let should_record = self
            .frontier_checkpoints
            .last()
            .is_none_or(|last| height.saturating_sub(last.height) >= interval);
        if should_record {
            self.frontier_checkpoints.push(FrontierCheckpoint {
                height,
                commitment_count: self.commitments.len() as u64,
                root: self.persisted_root,
            });
            update.recorded = true;
        }
        if depth_bound == 0 {
            if self.frontier_checkpoints.len() > 1 {
                let evicted = (self.frontier_checkpoints.len() - 1) as u64;
                let keep = self.frontier_checkpoints.pop();
                self.frontier_checkpoints.clear();
                if let Some(last) = keep {
                    self.frontier_checkpoints.push(last);
                }
                update.evicted += evicted;
            }
            return Ok(update);
        }
        let evict = self
            .frontier_checkpoints
            .iter()
            .take(self.frontier_checkpoints.len().saturating_sub(1))
            .take_while(|checkpoint| height.saturating_sub(checkpoint.height) > depth_bound)
            .count();
        if evict != 0 {
            self.frontier_checkpoints.drain(..evict);
            update.evicted = update
                .evicted
                .saturating_add(u64::try_from(evict).unwrap_or(u64::MAX));
        }
        let hard_excess = self
            .frontier_checkpoints
            .len()
            .saturating_sub(crate::zk::confidential_v2::CONFIDENTIAL_TREE_CAPACITY_V2);
        if hard_excess != 0 {
            self.frontier_checkpoints.drain(..hard_excess);
            update.evicted = update
                .evicted
                .saturating_add(u64::try_from(hard_excess).unwrap_or(u64::MAX));
        }
        Ok(update)
    }
}
#[cfg(all(test, feature = "telemetry"))]
impl ZkAssetState {
    /// Build [`ConfidentialTreeStats`] for the current tree snapshot.
    pub fn telemetry_stats(
        &self,
        root_evictions: u64,
        frontier_evictions: u64,
    ) -> ConfidentialTreeStats {
        let last_checkpoint = self.frontier_checkpoints.last().copied();
        let tree_depth = if self.commitments.is_empty() {
            0
        } else {
            u64::try_from(self.tree_profile.depth()).unwrap_or(u64::MAX)
        };
        ConfidentialTreeStats {
            commitments: saturating_len_to_u64(self.commitments.len()),
            tree_depth,
            root_history: saturating_len_to_u64(self.root_history.len()),
            frontier_checkpoints: saturating_len_to_u64(self.frontier_checkpoints.len()),
            last_checkpoint_height: last_checkpoint.as_ref().map_or(0, |cp| cp.height),
            last_checkpoint_commitments: last_checkpoint.map_or(0, |cp| cp.commitment_count),
            root_evictions,
            frontier_evictions,
        }
    }
}
#[cfg(all(test, feature = "telemetry"))]
fn saturating_len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}
