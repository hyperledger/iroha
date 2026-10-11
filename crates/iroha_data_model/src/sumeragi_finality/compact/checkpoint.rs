//! Fixed-cardinality restart records for locally selected native epoch authority.
//!
//! These records omit the boundary certificate history. Their exact bytes must therefore be
//! selected through authenticated local custody before restoration; decoding network input
//! cannot turn a claimed epoch into authority. The independently authenticated signed genesis
//! remains a separate required input, even for a locally selected record.

use super::*;

/// Finite canonical frame bound for two epoch contexts and their root identity.
///
/// Each context has at most 31 BLS keys of 48 bytes and proofs of possession of 96 bytes;
/// its availability layout, authorization, seeds and other fields have fixed size. The
/// existing 64 KiB result-preimage allowance more than covers each such context. Two of
/// those allowances plus 4 KiB cover both contexts, the existing 1024-byte local-checkpoint
/// chain-label bound, fixed root identities and canonical framing. This is a local-reader
/// resource limit, not a new consensus epoch-size rule.
pub const MAX_COMMIT_CHECKPOINT_BYTES: usize = 2 * MAX_RESULT_PREIMAGE_BYTES + 4 * 1024;

/// An untrusted, bounded serialization of one locally authenticated epoch selection.
///
/// There are exactly two context fields: the signed genesis context and one selected epoch.
/// They may be identical. The record never contains a growing map or a history prefix.
/// Its genesis identity is the native signed-header hash, which commits the original proposal
/// contents; it is not an execution-overlay or signature-wire digest.
///
/// [`Self::from_authenticated_genesis`] constructs the initial record without reading retained
/// decisions; [`SumeragiCommitVerifierV1::export_epoch_checkpoint`] exports an already
/// authenticated epoch. A decoded record is still DATA. Before calling
/// [`SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint`], the wallet must authenticate
/// its exact bytes through the selected protected local manifest and archive record. This is
/// not an API for accepting peer-supplied checkpoints or changing the selected trust root.
#[derive(
    Debug, Clone, PartialEq, Eq, Encode, Decode, iroha_schema::IntoSchema, norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::SumeragiCommitCheckpointV1")]
pub struct SumeragiCommitCheckpointV1 {
    genesis_hash: HashOf<BlockHeader>,
    network: NetworkId,
    chain: String,
    instance: Hash32,
    initial: ValidatorEpochContextV1,
    selected: ValidatorEpochContextV1,
}

impl SumeragiCommitCheckpointV1 {
    /// Select only the initial authority of independently authenticated global genesis.
    ///
    /// This copies the root identity and two bounded initial contexts directly. It never
    /// visits or imports `native`'s retained decisions, even when that owner has a long
    /// authenticated history. Later authority still requires separately selected local
    /// checkpoint custody or a verified boundary certificate.
    ///
    /// # Errors
    /// Rejects a private root, an oversized chain label or malformed initial authority.
    pub fn from_authenticated_genesis(
        native: &SumeragiFinalityVerifier,
    ) -> Result<Self, FinalityError> {
        need(
            matches!(
                native.root_scope(),
                crate::block::consensus::SumeragiRootScope::Global
            ),
            "compact global finality requires global signed genesis",
        )?;
        // Check the only variable-length root label before allocating its owned copy.
        need(
            !native.chain_id().is_empty() && native.chain_id().len() <= 1024,
            "compact checkpoint chain label exceeds bound",
        )?;
        // The native owner has already admitted this exact initial roster. Its size is
        // bounded independently of the number of retained authenticated decisions.
        let initial = native.initial_epoch();
        let checkpoint = Self {
            genesis_hash: native.genesis.hash(),
            network: initial.network_id,
            chain: native.chain_id().into(),
            instance: native.instance(),
            initial: initial.clone(),
            selected: initial.clone(),
        };
        checkpoint.validate_bounds()?;
        Ok(checkpoint)
    }

    /// Claimed genesis-derived network; decoding alone does not authenticate it.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// Claimed chain label; decoding alone does not authenticate it.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain
    }

    /// The one selected epoch body, not an independently authenticated capability.
    #[must_use]
    pub const fn selected_epoch(&self) -> &ValidatorEpochContextV1 {
        &self.selected
    }

    /// Encode the sole canonical bounded local-checkpoint layout.
    ///
    /// # Errors
    /// Rejects malformed context/root geometry, an oversized frame or encoding failure.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, FinalityError> {
        self.validate_bounds()?;
        norito::encode_canonical(self).map_err(malformed)
    }

    /// Decode bounded canonical DATA without authenticating the selected epoch.
    ///
    /// # Errors
    /// Rejects an empty, oversized, noncanonical or structurally malformed record.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FinalityError> {
        need(
            !bytes.is_empty() && bytes.len() <= MAX_COMMIT_CHECKPOINT_BYTES,
            "compact checkpoint frame exceeds bound",
        )?;
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(malformed)?;
        value.validate_bounds()?;
        Ok(value)
    }

    fn validate_bounds(&self) -> Result<(), FinalityError> {
        need(
            !self.chain.is_empty() && self.chain.len() <= 1024,
            "compact checkpoint chain label exceeds bound",
        )?;
        // Check the frame size before encoding an owned buffer or validating BLS PoPs.
        need(
            norito::canonical_frame_len(self).map_err(malformed)? <= MAX_COMMIT_CHECKPOINT_BYTES,
            "compact checkpoint frame exceeds bound",
        )?;
        self.initial.validate().map_err(malformed)?;
        self.selected.validate().map_err(malformed)?;
        need(
            self.initial.authorization.epoch == 0
                && self.network == NetworkId::from_genesis_hash(self.genesis_hash)
                && self.initial.network_id == self.network
                && self.selected.network_id == self.network
                && self.selected.mode == self.initial.mode
                && self.selected.da_layout == self.initial.da_layout,
            "compact checkpoint root or consensus scope differs",
        )?;
        if self.selected.authorization.epoch == self.initial.authorization.epoch {
            need(
                self.selected == self.initial,
                "compact checkpoint substitutes the initial epoch",
            )?;
        } else {
            need(
                self.selected.authorization.first_height > self.initial.authorization.last_height,
                "compact checkpoint selected epoch overlaps genesis authority",
            )?;
            if self.selected.authorization.epoch == 1 {
                self.selected
                    .validate_successor(&self.initial)
                    .map_err(malformed)?;
            }
        }
        Ok(())
    }
}

impl SumeragiCommitVerifierV1 {
    /// Export one exact epoch already authenticated by this native reader.
    ///
    /// Keep older records in authenticated archive custody if delayed receipts still need
    /// their authority. Export does not remove or otherwise alter the reader's epoch map.
    ///
    /// # Errors
    /// Rejects an unauthenticated epoch or a record outside the local encoding bounds.
    pub fn export_epoch_checkpoint(
        &self,
        epoch: u64,
    ) -> Result<SumeragiCommitCheckpointV1, FinalityError> {
        let selected = self
            .epochs
            .get(&epoch)
            .ok_or_else(|| FinalityError("cannot checkpoint an unauthenticated epoch".into()))?;
        let checkpoint = SumeragiCommitCheckpointV1 {
            genesis_hash: self.genesis_hash,
            network: self.network,
            chain: self.chain.clone(),
            instance: self.instance,
            initial: self.initial.clone(),
            selected: selected.clone(),
        };
        checkpoint.validate_bounds()?;
        Ok(checkpoint)
    }

    /// Restore exactly the initial epoch and one protected, locally selected epoch record.
    ///
    /// **Trust contract:** the caller must first authenticate `checkpoint`'s exact bytes
    /// through its manifest-selected protected local custody. Matching genesis identities
    /// alone cannot authenticate a later epoch. Never pass arbitrary incoming checkpoint
    /// bytes to this function. The separate `native` owner must already have authenticated
    /// and independently selected the intended signed global genesis. Its later decisions
    /// are not imported or needed; no earlier ordinary blocks are replayed here.
    ///
    /// # Errors
    /// Rejects malformed/bounded layout, a private root, or any difference in genesis,
    /// network, chain, native instance or complete initial authority.
    pub fn from_trusted_epoch_checkpoint(
        checkpoint: &SumeragiCommitCheckpointV1,
        native: &SumeragiFinalityVerifier,
    ) -> Result<Self, FinalityError> {
        checkpoint.validate_bounds()?;
        need(
            matches!(
                native.root_scope(),
                crate::block::consensus::SumeragiRootScope::Global
            ) && checkpoint.genesis_hash == native.genesis.hash()
                && checkpoint.network == native.initial_epoch().network_id
                && checkpoint.chain == native.chain_id()
                && checkpoint.instance == native.instance()
                && checkpoint.initial == *native.initial_epoch(),
            "compact checkpoint differs from independently selected global genesis",
        )?;
        let mut epochs = BTreeMap::new();
        epochs.insert(
            checkpoint.initial.authorization.epoch,
            checkpoint.initial.clone(),
        );
        epochs.insert(
            checkpoint.selected.authorization.epoch,
            checkpoint.selected.clone(),
        );
        Ok(Self {
            genesis_hash: checkpoint.genesis_hash,
            network: checkpoint.network,
            chain: checkpoint.chain.clone(),
            instance: checkpoint.instance,
            initial: checkpoint.initial.clone(),
            epochs,
        })
    }
}

#[cfg(all(test, feature = "transparent_api"))]
mod tests;
