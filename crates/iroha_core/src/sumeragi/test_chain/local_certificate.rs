//! Invalid local certificates are injected only after an actual exact-quorum native commit.

use super::*;

impl CertifiedTestChain {
    /// Corrupt the local stored QC of a genuinely committed height for negative read tests.
    /// This never executes or publishes a block under an invalid quorum. Original executed
    /// bytes, signed availability, hash journals and State authority remain unchanged.
    ///
    /// # Panics
    /// The original certificate is invalid, the requested signers form an exact quorum, or the
    /// exclusively owned test store cannot install the deliberate local corruption.
    pub fn corrupt_local_quorum_for_test(&self, height: u64, signers: Signers) {
        let (body, original) = self.committed_body(height).unwrap().unwrap();
        let changed = self.commit_qc(height, original.block_hash, original.result, signers);
        assert_ne!(
            changed.signers.count_ones(),
            body.source().config().committee.q(),
            "negative fixture must not relabel a valid quorum as corruption"
        );
        self.kura
            .corrupt_commit_certificate_for_testing(
                std::num::NonZeroUsize::new(usize::try_from(height).unwrap()).unwrap(),
                Some(norito::encode_canonical(&changed).unwrap()),
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::certified_chain::{CertifiedChain, committed_block};

    #[test]
    fn missing_local_certificate_preserves_actual_execution_and_rejects_certified_reads() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
        chain.commit_at(2000, Vec::new());
        let original = chain.committed(2);
        let height = std::num::NonZeroUsize::new(2).unwrap();
        chain
            .kura
            .corrupt_commit_certificate_for_testing(height, None)
            .unwrap();
        let changed = chain
            .kura
            .get_block(height, &chain.state().ivm_execution_budget())
            .expect("original block read attempt")
            .unwrap();
        assert!(changed.commit_certificate().is_none());
        assert_eq!(
            changed.executed_block_wire_identity().unwrap(),
            original.block().executed_block_wire_identity().unwrap()
        );
        assert_eq!(chain.state.view().height(), 2);
        assert!(chain.committed_body(2).is_err());
        assert!(
            CertifiedChain::new(&chain.state.view())
                .unwrap()
                .certified(2)
                .is_err()
        );
    }

    #[test]
    fn invalid_local_qc_changes_only_certificate_after_genuine_native_publication() {
        for signers in [Signers::BelowQuorum, Signers::All] {
            let mut chain =
                CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
            chain.commit_at(2000, Vec::new());
            chain.commit_at(3000, Vec::new());
            let original = chain.committed(2);
            let following = chain.committed(3).block().encode_wire().unwrap();
            chain.corrupt_local_quorum_for_test(2, signers);
            let view = chain.state.view();
            assert_eq!(view.height(), 3);
            let changed =
                committed_block(&view, 2).expect("original native execution remains authoritative");
            assert_eq!(changed.id(), original.id());
            assert_eq!(
                changed.block().executed_block_wire_identity().unwrap(),
                original.block().executed_block_wire_identity().unwrap()
            );
            assert_ne!(
                changed.block().commit_certificate(),
                original.block().commit_certificate()
            );
            assert_eq!(chain.committed(3).block().encode_wire().unwrap(), following);
            assert_eq!(
                chain
                    .kura
                    .canonical_block_wire_bytes_for_testing(std::num::NonZeroUsize::new(2).unwrap())
                    .unwrap(),
                changed.block().encode_wire().unwrap()
            );
            assert!(CertifiedChain::new(&view).unwrap().certified(2).is_err());
            assert!(chain.committed_body(2).is_err());
        }
    }
}
