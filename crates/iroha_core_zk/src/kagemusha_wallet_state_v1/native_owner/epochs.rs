//! Bounded epoch synchronization selected through rollback-sensitive wallet custody.
//!
//! A peer supplies only one original certificate. The wallet selects the incumbent
//! from its own manifest, verifies the exact boundary, and atomically publishes the
//! successor. Older epoch records remain in the authenticated archive index for delayed
//! receipts. Neither a peer checkpoint nor an in-memory cursor can select authority.

use super::*;
use iroha_data_model::sumeragi_finality::{
    MAX_COMMIT_CHECKPOINT_BYTES, SumeragiCommitCertificateV1, SumeragiCommitCheckpointV1,
    SumeragiCommitVerifierV1,
};

/// Durably selected native epoch and the exact next boundary to request from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeEpochProgressV1 {
    /// Genesis-rooted selected epoch number.
    pub epoch: u64,
    /// First height authorized for this incumbent committee.
    pub first_height: u64,
    /// Last authorized height; only its certificate may advance epoch synchronization.
    pub boundary_height: u64,
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::FinalityEpochEntry")]
pub(in crate::kagemusha_wallet_state_v1) struct EpochEntry {
    pub(in crate::kagemusha_wallet_state_v1) checkpoint: [u8; 32],
    pub(in crate::kagemusha_wallet_state_v1) boundary_original: [u8; 32],
}

fn progress(checkpoint: &SumeragiCommitCheckpointV1) -> NativeEpochProgressV1 {
    let authority = &checkpoint.selected_epoch().authorization;
    NativeEpochProgressV1 {
        epoch: authority.epoch,
        first_height: authority.first_height,
        boundary_height: authority.last_height,
    }
}

fn epoch_key(epoch: u64) -> [u8; 32] {
    manifest::sequence_key(u128::from(epoch))
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    fn epoch_entry(
        &mut self,
        manifest: &manifest::Manifest,
        epoch: u64,
    ) -> Result<EpochEntry, Error> {
        let bytes = manifest
            .finality_epochs
            .get(&mut self.archive, &epoch_key(epoch))?
            .ok_or(Error::WitnessLost("selected finality epoch index"))?;
        archive::decode(&bytes).map_err(|_| Error::WitnessLost("selected finality epoch entry"))
    }

    /// Read only an epoch already selected by the protected manifest. The epoch argument
    /// selects an archive key, never a peer-supplied roster or checkpoint.
    pub(super) fn selected_commit_epoch(
        &mut self,
        manifest: &manifest::Manifest,
        genesis: &SumeragiFinalityVerifier,
        epoch: u64,
    ) -> Result<(SumeragiCommitVerifierV1, SumeragiCommitCheckpointV1), Error> {
        let (scheme, chain) = self.proofs.ledger_scope()?;
        let initial = genesis.initial_epoch().authorization.epoch;
        let selected = manifest.finality_epoch.unwrap_or(initial);
        if scheme.scheme_id() != self.scheme_id
            || chain != genesis.chain_id()
            || genesis.initial_epoch().network_id.as_bytes() != &scheme.network_id
            || !matches!(
                genesis.root_scope(),
                iroha_data_model::block::consensus::SumeragiRootScope::Global
            )
        {
            return Err(Error::Proof("native epoch root scope"));
        }
        if epoch < initial || epoch > selected {
            return Err(Error::Invalid("finality epoch is not selected"));
        }
        if (manifest.finality_epoch.is_none()) != (manifest.finality_epochs == IndexRoot::default())
            || manifest
                .finality_epoch
                .is_some_and(|value| value <= initial)
        {
            return Err(Error::WitnessLost("selected finality epoch manifest"));
        }
        let checkpoint = if epoch == initial {
            SumeragiCommitCheckpointV1::from_authenticated_genesis(genesis)
                .map_err(|_| Error::Proof("native initial epoch"))?
        } else {
            let entry = self.epoch_entry(manifest, epoch)?;
            let bytes = self
                .archive
                .read_object(&entry.checkpoint, MAX_COMMIT_CHECKPOINT_BYTES)?;
            SumeragiCommitCheckpointV1::decode_canonical(&bytes)
                .map_err(|_| Error::WitnessLost("selected finality epoch original"))?
        };
        if checkpoint.selected_epoch().authorization.epoch != epoch {
            return Err(Error::WitnessLost("selected finality epoch identity"));
        }
        // Only this locally selected index path supplies a later checkpoint. Restoring
        // initial + one selected context also bounds working memory after long histories.
        let reader = SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, genesis)
            .map_err(|_| Error::WitnessLost("selected finality epoch root binding"))?;
        Ok((reader, checkpoint))
    }

    fn epoch_progress_selected(
        &mut self,
        genesis: &SumeragiFinalityVerifier,
    ) -> Result<NativeEpochProgressV1, Error> {
        let (_, manifest) = self.sync_manifest()?;
        let epoch = manifest
            .finality_epoch
            .unwrap_or(genesis.initial_epoch().authorization.epoch);
        let (_, checkpoint) = self.selected_commit_epoch(&manifest, genesis, epoch)?;
        Ok(progress(&checkpoint))
    }

    fn ingest_epoch_original(
        &mut self,
        genesis: &SumeragiFinalityVerifier,
        expected_epoch: u64,
        bytes: &[u8],
    ) -> Result<NativeEpochProgressV1, Error> {
        if !matches!(self.status()?, SlotStatus::Released(_)) {
            return Err(Error::NoHead);
        }
        let certificate = SumeragiCommitCertificateV1::decode_canonical(bytes)
            .map_err(|_| Error::Invalid("epoch certificate canonical original"))?;
        let (root, mut manifest) = self.sync_manifest()?;
        let current = manifest
            .finality_epoch
            .unwrap_or(genesis.initial_epoch().authorization.epoch);
        let (mut reader, incumbent) =
            self.selected_commit_epoch(&manifest, genesis, expected_epoch)?;
        if certificate
            .epoch_id()
            .map_err(|_| Error::Invalid("epoch certificate selector"))?
            != expected_epoch
            || certificate
                .height()
                .map_err(|_| Error::Invalid("epoch certificate height"))?
                != incumbent.selected_epoch().authorization.last_height
        {
            return Err(Error::Proof("epoch boundary incumbent or height"));
        }
        let checkpoint = reader
            .verify_epoch_boundary(&certificate)
            .map_err(|_| Error::Proof("epoch boundary certificate"))?;
        let next = expected_epoch
            .checked_add(1)
            .ok_or(Error::Proof("epoch number overflow"))?;
        if checkpoint.selected_epoch().authorization.epoch != next {
            return Err(Error::Proof("epoch successor continuity"));
        }
        let encoded = checkpoint
            .encode_canonical()
            .map_err(|_| Error::Proof("epoch checkpoint encoding"))?;
        let original_digest =
            crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(bytes);
        if expected_epoch < current {
            let entry = self.epoch_entry(&manifest, next)?;
            let (_, retained) = self.selected_commit_epoch(&manifest, genesis, next)?;
            if entry.boundary_original != original_digest || retained != checkpoint {
                return Err(Error::Proof("epoch retry differs from selected original"));
            }
            let (_, selected) = self.selected_commit_epoch(&manifest, genesis, current)?;
            return Ok(progress(&selected));
        }
        let checkpoint_address = self
            .archive
            .write_object(&encoded, MAX_COMMIT_CHECKPOINT_BYTES)?;
        let entry = EpochEntry {
            checkpoint: checkpoint_address,
            boundary_original: original_digest,
        };
        manifest.finality_epochs = manifest.finality_epochs.set(
            &mut self.archive,
            epoch_key(next),
            &archive::encode(&entry)?,
        )?;
        manifest.finality_epoch = Some(next);
        // An uncertain publication is reconciled from custody on retry. No in-memory
        // reader or successfully written but unselected object advances authority.
        self.publish_manifest(root, &manifest)?;
        Ok(progress(&checkpoint))
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Read the durably selected epoch and its exact next boundary request height.
    /// An absent cursor uses only the independently installed signed genesis.
    ///
    /// # Errors
    /// Unavailable, missing or substituted selected custody and foreign root scope.
    pub fn epoch_progress(&mut self) -> Result<NativeEpochProgressV1, Error> {
        let genesis = Arc::clone(&self.proofs.genesis);
        self.epoch_progress_selected(&genesis)
    }

    /// Authenticate and durably select one incumbent-boundary successor, without replaying
    /// ordinary blocks. Exact original retries reconcile an uncertain earlier publication.
    ///
    /// # Errors
    /// Noncanonical/forged/non-boundary certificates, missing epochs, changed retries,
    /// unavailable archive custody or uncertain manifest publication.
    pub fn ingest_epoch_boundary(
        &mut self,
        expected_epoch: u64,
        original: &[u8],
    ) -> Result<NativeEpochProgressV1, Error> {
        let _payment = self.scheduler.payment();
        let genesis = Arc::clone(&self.proofs.genesis);
        self.ingest_epoch_original(&genesis, expected_epoch, original)
    }
}

#[cfg(test)]
mod tests;
