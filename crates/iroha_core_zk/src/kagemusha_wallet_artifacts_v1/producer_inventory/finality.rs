//! Direct ordinary Load finality bound to the independently selected signed genesis.

use super::*;
use iroha_data_model::{
    block::consensus::SumeragiRootScope, sumeragi_finality::SumeragiFinalityVerifier,
};

/// Refusal to bind a wallet installation to its native signed-genesis verifier.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum FinalityQualificationErrorV1 {
    /// The selected native root does not authenticate this wallet network.
    #[error("wallet finality requires the installed network's signed global genesis")]
    AnchorMismatch,
}

/// Native certificate verifier bound to one authenticated wallet installation.
pub struct QualifiedReceiptSourceV1 {
    verifier: SumeragiFinalityVerifier,
    scheme_id: [u8; 32],
    manifest_digest: [u8; 32],
}

impl QualifiedReceiptSourceV1 {
    /// Exact authenticated wallet installation using this native trust root.
    pub const fn installation(&self) -> ([u8; 32], [u8; 32]) {
        (self.scheme_id, self.manifest_digest)
    }

    /// Independently selected signed-genesis verifier.
    pub const fn verifier(&self) -> &SumeragiFinalityVerifier {
        &self.verifier
    }
}

impl AuthenticatedProducerInventoryV1 {
    /// Bind the independently authenticated native root to this wallet installation.
    ///
    /// # Errors
    /// A private root or another network cannot authorize ordinary wallet Loads.
    pub fn qualify_finality(
        &self,
        installed: &InstalledVerifierPackV1,
        verifier: &SumeragiFinalityVerifier,
    ) -> Result<QualifiedReceiptSourceV1, FinalityQualificationErrorV1> {
        require_root(verifier, &installed.verifier().scheme().network_id)?;
        if self.installation()
            != (
                installed.verifier().scheme().scheme_id(),
                installed.verifier().manifest_digest(),
            )
        {
            return Err(FinalityQualificationErrorV1::AnchorMismatch);
        }
        Ok(QualifiedReceiptSourceV1 {
            verifier: verifier.clone(),
            scheme_id: self.scheme_id,
            manifest_digest: self.manifest_digest,
        })
    }
}

fn require_root(
    verifier: &SumeragiFinalityVerifier,
    network: &[u8; 32],
) -> Result<(), FinalityQualificationErrorV1> {
    if verifier.root_scope() != SumeragiRootScope::Global
        || verifier.initial_epoch().network_id.as_bytes() != network
    {
        return Err(FinalityQualificationErrorV1::AnchorMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1,
        kagemusha::KagemushaWalletLoadFinalityV1,
        sumeragi_finality::test_fixtures::NativeFinalityFixture,
    };

    #[test]
    fn direct_finality_uses_exact_global_native_root_without_circuit_artifacts() {
        let fixture = NativeFinalityFixture::new_with_explicit_parameters();
        let native = fixture.verifier();
        require_root(&native, fixture.network_id().as_bytes()).unwrap();
        assert!(require_root(&native, &[0; 32]).is_err());
        let private = NativeFinalityFixture::start_with_scope(
            fixture.chain_id(),
            SumeragiRootScope::Dataspace {
                parent_network_id: fixture.network_id(),
                dataspace_id: 9_u64.into(),
            },
        );
        assert!(require_root(&private.verifier(), private.network_id().as_bytes()).is_err());
        let source = QualifiedReceiptSourceV1 {
            verifier: native,
            scheme_id: [1; 32],
            manifest_digest: [2; 32],
        };
        assert_eq!(source.installation(), ([1; 32], [2; 32]));
        assert_eq!(
            source.verifier().initial_epoch().network_id,
            fixture.network_id()
        );
    }

    #[test]
    fn qualified_native_source_verifies_the_exact_receipt_before_wallet_credit() {
        use iroha_crypto::{HashOf, MerkleTree};
        use iroha_data_model::{
            events::{
                EventBox,
                data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
            },
            sumeragi_finality::SumeragiCommitCertificateV1,
        };
        let mut fixture =
            NativeFinalityFixture::start_with_explicit_parameters("wallet-native-load");
        let receipt = KagemushaWalletLoadReceiptV1 {
            version: 1,
            scheme_id: [1; 32],
            asset_digest: [2; 32],
            wallet_id: [3; 32],
            request_id: [4; 32],
            ordinal: 0,
            amount: 100,
            online_charge: 0,
            charge_quote: [0; 32],
            transaction_hash: [5; 32],
            block_height: 2,
            payer_account_digest: [6; 32],
        };
        let event = EventBox::Data(
            DataEvent::KagemushaLoadCommitted(
                KagemushaLoadCommittedV1::from_receipt(&receipt).unwrap(),
            )
            .into(),
        );
        let tree: MerkleTree<EventBox> = [HashOf::new(&event)].into_iter().collect();
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let proof = fixture.certify_with_events(block, &[event]);
        let native = fixture.verifier();
        let verified = native.verify_retained_decision(&proof).unwrap();
        let evidence = KagemushaWalletLoadFinalityV1 {
            version: 1,
            receipt_digest: receipt.receipt_digest().unwrap(),
            certificate: SumeragiCommitCertificateV1::from_verified(&verified).unwrap(),
            event_proof: tree.get_proof(0).unwrap(),
        };
        let source = QualifiedReceiptSourceV1 {
            verifier: native,
            scheme_id: receipt.scheme_id,
            manifest_digest: [7; 32],
        };
        evidence.verify(source.verifier(), &receipt).unwrap();
        let changed = KagemushaWalletLoadReceiptV1 {
            amount: 101,
            ..receipt
        };
        assert!(evidence.verify(source.verifier(), &changed).is_err());
        let mut forged = evidence;
        forged.certificate.commit_qc[0] ^= 1;
        assert!(forged.verify(source.verifier(), &receipt).is_err());
    }
}
