//! Same-State certified-chain authority for durable application archives.
//!
//! This is local runtime evidence, not an independent wire proof. It uses the current Kura
//! commit certificate and the certified-chain reader's retained-committee trust model. Archive
//! checkpoints bind the certified block id (header and execution result), never a node-local
//! quorum's choice of signatures.

use crate::{
    kura::{ExactReplayBoundary, Kura},
    state::StateReadOnly,
    sumeragi::certified_chain::{CertifiedBlock, CertifiedChain, ChainReadError},
};

/// A failure to bind an archive operation to one exact durable, committed chain boundary.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ArchiveFinalityError {
    #[error("archive State is bound to another Kura instance")]
    ForeignKura,
    #[error("archive State or block differs from the frozen durable Kura boundary")]
    BoundaryMismatch,
    #[error("durable Kura boundary changed during archive authentication")]
    BoundaryChanged,
    #[error("cannot read durable Kura archive boundary: {0}")]
    Storage(String),
    #[error(transparent)]
    Chain(#[from] ChainReadError),
    /// Original local history acquisition has not completed.
    #[error(transparent)]
    Deferred(crate::execution_attempt::ExecutionDeferred),
}

impl From<crate::execution_attempt::ExecutionAttemptError<ChainReadError>>
    for ArchiveFinalityError
{
    fn from(error: crate::execution_attempt::ExecutionAttemptError<ChainReadError>) -> Self {
        match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => Self::Chain(error),
            crate::execution_attempt::ExecutionAttemptError::Deferred(local) => {
                Self::Deferred(local)
            }
        }
    }
}

/// One immutable State view and its exact durable Kura boundary.
pub(crate) struct CertifiedArchiveView<'v, V: StateReadOnly + ?Sized> {
    kura: &'v Kura,
    boundary: ExactReplayBoundary,
    chain: CertifiedChain<'v, V>,
}

impl<'v, V: StateReadOnly + ?Sized> CertifiedArchiveView<'v, V> {
    /// Authenticate the State/Kura association and freeze the durable hash journal.
    pub(crate) fn new(view: &'v V, kura: &'v Kura) -> Result<Self, ArchiveFinalityError> {
        if !std::ptr::eq(view.kura(), kura) {
            return Err(ArchiveFinalityError::ForeignKura);
        }
        let boundary = kura
            .exact_replay_boundary()
            .map_err(|error| ArchiveFinalityError::Storage(error.to_string()))?;
        if u64::try_from(view.height())
            .ok()
            .is_none_or(|height| height > boundary.count)
        {
            return Err(ArchiveFinalityError::BoundaryMismatch);
        }
        let chain = CertifiedChain::new(view)?;
        Ok(Self {
            kura,
            boundary,
            chain,
        })
    }

    /// The exact durable height against which lag is measured.
    pub(crate) fn tip_height(&self) -> u64 {
        self.boundary.count
    }

    /// Read one certified block belonging to both this State and the frozen durable boundary.
    pub(crate) fn block(&self, height: u64) -> Result<CertifiedBlock, ArchiveFinalityError> {
        let block = self.chain.certified(height)?;
        let index = usize::try_from(height)
            .ok()
            .and_then(|value| value.checked_sub(1));
        if index
            .and_then(|index| self.boundary.hashes.get(index))
            .copied()
            != Some(block.block_hash())
        {
            return Err(ArchiveFinalityError::BoundaryMismatch);
        }
        Ok(block)
    }

    /// Refuse publication when Kura moved while the archive operation was being prepared.
    pub(crate) fn verify_unchanged(&self) -> Result<(), ArchiveFinalityError> {
        let current = self
            .kura
            .exact_replay_boundary()
            .map_err(|error| ArchiveFinalityError::Storage(error.to_string()))?;
        if current != self.boundary {
            return Err(ArchiveFinalityError::BoundaryChanged);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::store::LiveQueryStore,
        state::{State, World},
        sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    };
    use std::sync::Arc;

    fn chain() -> CertifiedTestChain {
        CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("signed genesis")
    }

    #[test]
    fn certified_archive_authenticates_genesis_and_current_commit_certificates() {
        let mut chain = chain();
        chain.commit_at(2_000, Vec::new());
        let view = chain.state().view();
        let archive = CertifiedArchiveView::new(&view, chain.kura()).unwrap();
        assert_eq!(archive.tip_height(), 2);
        for height in 1..=2 {
            assert_eq!(
                archive.block(height).unwrap().id(),
                chain.committed(height).id()
            );
        }
        assert!(archive.block(0).is_err());
        assert!(archive.block(3).is_err());
        archive.verify_unchanged().unwrap();
    }

    #[test]
    fn certified_archive_rejects_foreign_kura_and_hash_cache_only_state() {
        let chain = chain();
        let kura = Kura::blank_kura_for_testing();
        assert!(matches!(
            CertifiedArchiveView::new(&chain.state().view(), &kura),
            Err(ArchiveFinalityError::ForeignKura)
        ));
        let mut state = State::new_with_chain_and_network_id_for_testing(
            World::new(),
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
            "sumeragi-certified-test-chain".parse().unwrap(),
            chain.network_id(),
        );
        state.push_block_hash_for_testing(chain.genesis().hash());
        assert!(matches!(
            CertifiedArchiveView::new(&state.view(), &kura),
            Err(ArchiveFinalityError::BoundaryMismatch)
        ));
    }

    #[test]
    fn certified_archive_refuses_changed_durable_boundary_and_uncommitted_successor() {
        let mut chain = chain();
        let state = Arc::clone(chain.state());
        let kura = Arc::clone(chain.kura());
        let view = state.view();
        let archive = CertifiedArchiveView::new(&view, &kura).unwrap();
        chain.commit_at(2_000, Vec::new());
        assert!(matches!(
            archive.verify_unchanged(),
            Err(ArchiveFinalityError::BoundaryChanged)
        ));
        assert!(
            archive.block(2).is_err(),
            "a durable successor is absent from the frozen State"
        );
    }

    #[test]
    fn certified_archive_does_not_accept_a_below_quorum_certificate() {
        let mut chain = chain();
        chain.commit_at(2_000, Vec::new());
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
        let view = chain.state().view();
        let archive = CertifiedArchiveView::new(&view, chain.kura()).unwrap();
        assert!(archive.block(2).is_err());
    }

    #[test]
    fn certified_archive_rejects_identical_durable_frames_for_a_foreign_state_network() {
        use iroha_crypto::{Hash, HashOf};
        use iroha_data_model::NetworkId;
        let chain = chain();
        let foreign_kura = Kura::blank_kura_for_testing();
        let mut foreign = State::new_with_chain_and_network_id_for_testing(
            World::new(),
            Arc::clone(&foreign_kura),
            LiveQueryStore::start_test(),
            "sumeragi-certified-test-chain".parse().unwrap(),
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"another network",
            ))),
        );
        let executed_genesis = chain
            .kura()
            .get_block(
                std::num::NonZeroUsize::MIN,
                &chain.state().ivm_execution_budget(),
            )
            .expect("original genesis history read completes")
            .expect("retained executed genesis");
        assert!(executed_genesis.commit_certificate().is_some());
        let genesis_hash = executed_genesis.hash();
        foreign_kura.store_block(executed_genesis).unwrap();
        foreign.push_block_hash_for_testing(genesis_hash);
        assert_eq!(
            foreign_kura
                .canonical_block_wire_bytes_for_testing(std::num::NonZeroUsize::MIN)
                .unwrap(),
            chain
                .kura()
                .canonical_block_wire_bytes_for_testing(std::num::NonZeroUsize::MIN)
                .unwrap(),
            "foreign State sees byte-identical durable genesis"
        );
        assert!(matches!(
            CertifiedArchiveView::new(&foreign.view(), &foreign_kura),
            Err(ArchiveFinalityError::Chain(ChainReadError::ForeignGenesis))
        ));
    }
}
