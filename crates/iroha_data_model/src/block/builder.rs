//! Proposal-only block builder. Actual typed outputs are installed by one checked owner.
use super::{
    BlockExecutionContextBundle, BlockHeader, BlockPayload, BlockSignature, BlockSignatures,
    SignedBlock,
};
use crate::{
    consensus::{FinalizedGlobalThresholdBeaconPulseV1, NposConsensusEffects},
    da::{
        commitment::{DaCommitmentBundle, DaProofPolicyBundle},
        pin_intent::DaPinIntentBundle,
    },
    transaction::signed::{
        SealedTransactionReveal, SignedSealedTransactionCommitment, SignedTransaction,
        TransactionEntrypoint,
    },
};
use iroha_crypto::{HashOf, MerkleTree, SignatureOf};
use std::vec::Vec;
/// Helper to incrementally assemble a block while maintaining Merkle roots.
#[derive(Debug, Clone)]
pub struct BlockBuilder {
    header: BlockHeader,
    external_entrypoints: Vec<TransactionEntrypoint>,
    entry_merkle: MerkleTree<TransactionEntrypoint>,
    da_commitments: Option<DaCommitmentBundle>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    da_pin_intents: Option<DaPinIntentBundle>,
    npos_consensus_effects: Option<NposConsensusEffects>,
    global_beacon_pulse: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    execution_context: Option<BlockExecutionContextBundle>,
}
impl BlockBuilder {
    /// Create a new builder with an initial header. Merkle roots are derived as
    /// items are pushed and written into the header on `build()`.
    pub fn new(header: BlockHeader) -> Self {
        Self {
            header,
            external_entrypoints: Vec::new(),
            entry_merkle: MerkleTree::default(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        }
    }
    /// Push a signed transaction and update the entrypoint Merkle tree.
    pub fn push_transaction(&mut self, tx: SignedTransaction) -> usize {
        let idx = self.external_entrypoints.len();
        let h: HashOf<TransactionEntrypoint> = tx.hash_as_entrypoint();
        self.entry_merkle.add(h);
        self.external_entrypoints
            .push(TransactionEntrypoint::External(tx));
        idx
    }
    /// Push a sealed transaction commitment and update the entrypoint Merkle tree.
    pub fn push_sealed_transaction_commitment(
        &mut self,
        commitment: SignedSealedTransactionCommitment,
    ) -> usize {
        let idx = self.external_entrypoints.len();
        let entrypoint = TransactionEntrypoint::SealedCommitment(commitment);
        let h: HashOf<TransactionEntrypoint> = entrypoint.hash();
        self.entry_merkle.add(h);
        self.external_entrypoints.push(entrypoint);
        idx
    }
    /// Push a sealed transaction reveal and update the entrypoint Merkle tree.
    pub fn push_sealed_transaction_reveal(&mut self, reveal: SealedTransactionReveal) -> usize {
        let idx = self.external_entrypoints.len();
        let entrypoint = TransactionEntrypoint::SealedReveal(reveal);
        let h: HashOf<TransactionEntrypoint> = entrypoint.hash();
        self.entry_merkle.add(h);
        self.external_entrypoints.push(entrypoint);
        idx
    }
    /// Push a canonical anonymous ballot and bind its exact envelope in the input Merkle tree.
    ///
    /// This assembles untrusted proposal data; it does not verify the ballot proof,
    /// admission stamp, authenticated context or execution outcome.
    pub fn push_anonymous_ballot(
        &mut self,
        envelope: crate::governance::anonymous_ballot::CanonicalAnonymousBallotEnvelopeV1,
    ) -> usize {
        let idx = self.external_entrypoints.len();
        let entrypoint = TransactionEntrypoint::AnonymousBallot(envelope);
        self.entry_merkle.add(entrypoint.hash());
        self.external_entrypoints.push(entrypoint);
        idx
    }
    /// Attach a pre-built DA commitment bundle that will be embedded in the resulting block.
    pub fn set_da_commitments(&mut self, bundle: Option<DaCommitmentBundle>) {
        self.da_commitments = bundle.filter(|bundle| !bundle.is_empty());
    }
    /// Attach a pre-built DA proof policy bundle that will be embedded in the resulting block.
    pub fn set_da_proof_policies(&mut self, bundle: Option<DaProofPolicyBundle>) {
        self.da_proof_policies = bundle;
    }
    /// Attach a pre-built DA pin intent bundle that will be embedded in the resulting block.
    pub fn set_da_pin_intents(&mut self, bundle: Option<DaPinIntentBundle>) {
        self.da_pin_intents = bundle.filter(|bundle| !bundle.is_empty());
    }
    fn normalize_empty_da_bundles(&mut self) {
        self.da_commitments = self
            .da_commitments
            .take()
            .filter(|bundle| !bundle.is_empty());
        self.da_pin_intents = self
            .da_pin_intents
            .take()
            .filter(|bundle| !bundle.is_empty());
    }
    fn finalize_header(&mut self) {
        self.normalize_empty_da_bundles();
        self.header.merkle_root = self.entry_merkle.root();
        self.header
            .set_da_proof_policies_hash(self.da_proof_policies.as_ref().map(HashOf::new));
        self.header.da_commitments_hash = self
            .da_commitments
            .as_ref()
            .and_then(DaCommitmentBundle::merkle_commitment);
        self.header.da_pin_intents_hash = self
            .da_pin_intents
            .as_ref()
            .and_then(DaPinIntentBundle::merkle_commitment);
        self.header
            .set_npos_effects_hash(self.npos_consensus_effects.as_ref().map(HashOf::new));
        self.header
            .set_global_beacon_pulse_hash(self.global_beacon_pulse.as_ref().map(HashOf::new));
        self.header
            .set_execution_context_hash(self.execution_context.as_ref().map(HashOf::new));
    }
    /// Attach the current threshold pulse without adding transaction work.
    pub fn set_global_beacon_pulse(
        &mut self,
        pulse: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    ) {
        self.global_beacon_pulse = pulse;
    }
    /// Attach deterministic `NPoS` effects that will be embedded in the resulting block.
    pub fn set_npos_consensus_effects(&mut self, effects: Option<NposConsensusEffects>) {
        self.npos_consensus_effects = effects.filter(|bundle| !bundle.is_empty());
    }
    /// Attach durable execution context that will be embedded in the resulting block.
    pub fn set_execution_context(&mut self, context: Option<BlockExecutionContextBundle>) {
        self.execution_context = context.filter(|bundle| !bundle.is_empty());
    }
    /// Build untrusted structural block data with the provided signatures.
    /// Native inputs are not execution authority; callers must attach
    /// actual full results through the checked setter and validate the carrier.
    pub fn build(mut self, signatures: BlockSignatures) -> SignedBlock {
        self.finalize_header();
        self.into_block(signatures)
    }
    fn into_block(self, signatures: BlockSignatures) -> SignedBlock {
        let payload = BlockPayload {
            header: self.header,
            external_entrypoints: self.external_entrypoints,
            execution_context: self.execution_context,
            da_commitments: self.da_commitments,
            da_proof_policies: self.da_proof_policies,
            da_pin_intents: self.da_pin_intents,
            npos_consensus_effects: self.npos_consensus_effects,
            global_beacon_pulse: self.global_beacon_pulse,
        };
        SignedBlock {
            signatures,
            payload,
            result: None,
            commit_certificate: None,
        }
    }
    /// Convenience: fallibly sign the built header hash with a single validator and return the block.
    ///
    /// # Errors
    ///
    /// Returns [`iroha_crypto::Error::Signing`] when the configured signing
    /// backend rejects the private-key material or finalized header hash.
    pub fn try_build_with_signature(
        mut self,
        signatory_index: u64,
        private_key: &iroha_crypto::PrivateKey,
    ) -> Result<SignedBlock, iroha_crypto::Error> {
        self.finalize_header();
        let mut block = self.into_block(BlockSignatures::default());
        let sig = SignatureOf::try_from_hash(private_key, block.hash())?;
        block
            .signatures
            .try_insert(BlockSignature::new(signatory_index, sig))?;
        Ok(block)
    }
    /// Convenience: sign the built header hash with a single validator and return the block.
    #[must_use]
    pub fn build_with_signature(
        self,
        signatory_index: u64,
        private_key: &iroha_crypto::PrivateKey,
    ) -> SignedBlock {
        self.try_build_with_signature(signatory_index, private_key)
            .expect("signing should succeed for a valid private key and finalized block header")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        da::{
            commitment::{DaCommitmentBundle, DaCommitmentRecord, DaProofPolicy, DaProofScheme},
            pin_intent::DaPinIntentBundle,
            prelude::RetentionPolicy,
            types::{BlobDigest, StorageTicketId},
        },
        prelude::*,
        sorafs::pin_registry::ManifestDigest,
        transaction::signed::TransactionBuilder,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use nonzero_ext::nonzero;
    fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("generate checked block-builder fixture keypair")
    }
    fn checked_seeded_keypair(seed: u8, algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], algorithm)
            .expect("derive checked block-builder fixture keypair")
    }
    fn test_network_id() -> crate::NetworkId {
        crate::NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x15; Hash::LENGTH]),
        ))
    }
    #[test]
    fn builder_roots_match_manual_construction() {
        // Minimal header
        let header = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
        let private_key: iroha_crypto::PrivateKey =
            "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
                .parse()
                .unwrap();
        let authority = AccountId::new(iroha_crypto::PublicKey::from(private_key.clone()));
        // Two txs
        let tx1 = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([crate::isi::Log::new(crate::Level::INFO, "first".into())])
        .sign(&private_key);
        let tx2 = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([crate::isi::Log::new(crate::Level::INFO, "second".into())])
        .sign(&private_key);
        // Build incrementally
        let mut bb = BlockBuilder::new(header);
        bb.push_transaction(tx1.clone());
        bb.push_transaction(tx2.clone());
        let mut built = bb.build_with_signature(0, &private_key);
        // Manual construction
        let mut manual = SignedBlock::presigned(
            BlockSignature::new(
                0,
                SignatureOf::try_from_hash(&private_key, built.header().hash())
                    .expect("checked manual block-builder fixture signature"),
            ),
            built.header(), // reuse header values (roots) for signature correctness
            vec![tx1.clone(), tx2.clone()],
        );
        assert_eq!(built, manual);
        assert!(built.is_resultless_proposal());
        assert!(built.execution_outputs().is_empty());
        let time = crate::block::output_test_support::simple_time(&built, 0);
        let rows = vec![
            crate::block::output_test_support::network(0, Ok(Vec::default())),
            crate::block::output_test_support::network(1, Ok(Vec::default())),
            time,
        ];
        crate::block::output_test_support::install(&mut built, rows.clone(), 3).unwrap();
        crate::block::output_test_support::install(&mut manual, rows, 3).unwrap();
        assert_eq!(built, manual);
        assert_eq!(
            built
                .network_input_merkle_commitment()
                .unwrap()
                .leaf_count()
                .get(),
            2
        );
        assert_eq!(
            built.output_merkle_commitment().unwrap().leaf_count().get(),
            3
        );
    }
    #[test]
    fn builder_attaches_da_bundle_and_sets_header_hash() {
        let header = BlockHeader::new(nonzero!(5_u64), None, None, 0, 0);
        let mut builder = BlockBuilder::new(header);
        let bundle = sample_da_bundle();
        builder.set_da_commitments(Some(bundle.clone()));
        let block = builder.build(crate::block::BlockSignatures::default());
        assert_eq!(block.da_commitments().unwrap(), &bundle);
        assert!(block.header().da_commitments_hash().is_some());
    }
    #[test]
    fn builder_normalizes_empty_da_bundles() {
        let header = BlockHeader::new(nonzero!(5_u64), None, None, 0, 0);
        let mut builder = BlockBuilder::new(header);
        builder.set_da_commitments(Some(DaCommitmentBundle::default()));
        builder.set_da_pin_intents(Some(DaPinIntentBundle::default()));
        assert!(builder.da_commitments.is_none());
        assert!(builder.da_pin_intents.is_none());
        let mut unsigned_builder = builder.clone();
        unsigned_builder.da_commitments = Some(DaCommitmentBundle::default());
        unsigned_builder.da_pin_intents = Some(DaPinIntentBundle::default());
        let unsigned = unsigned_builder.build(crate::block::BlockSignatures::default());
        assert!(unsigned.da_commitments().is_none());
        assert!(unsigned.header().da_commitments_hash().is_none());
        assert!(unsigned.da_pin_intents().is_none());
        assert!(unsigned.header().da_pin_intents_hash().is_none());
        builder.da_commitments = Some(DaCommitmentBundle::default());
        builder.da_pin_intents = Some(DaPinIntentBundle::default());
        let keypair = checked_seeded_keypair(0xDA, Algorithm::Ed25519);
        let signed = builder.build_with_signature(0, keypair.private_key());
        assert!(signed.da_commitments().is_none());
        assert!(signed.header().da_commitments_hash().is_none());
        assert!(signed.da_pin_intents().is_none());
        assert!(signed.header().da_pin_intents_hash().is_none());
    }
    #[test]
    fn build_with_signature_keeps_da_policy_hash_consistent() {
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let policy = DaProofPolicy {
            lane_id: LaneId::new(1),
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "lane-1".to_string(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let bundle = DaProofPolicyBundle::new(vec![policy]);
        let mut builder = BlockBuilder::new(header);
        builder.set_da_proof_policies(Some(bundle.clone()));
        let keypair = checked_random_keypair_with_algorithm(Algorithm::BlsNormal);
        let block = builder.build_with_signature(0, keypair.private_key());
        let signature = block.signatures().next().expect("block signature exists");
        assert!(
            signature
                .signature()
                .verify_hash(keypair.public_key(), block.hash())
                .is_ok(),
            "block signature should verify after DA policy attachment"
        );
        assert_eq!(
            block.header().da_proof_policies_hash,
            Some(HashOf::new(&bundle))
        );
    }
    #[test]
    fn try_build_with_signature_matches_build_with_signature_and_verifies() {
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let keypair = checked_seeded_keypair(0x42, Algorithm::Ed25519);
        let mut builder = BlockBuilder::new(header);
        builder.set_da_commitments(Some(sample_da_bundle()));
        let fallible = builder
            .clone()
            .try_build_with_signature(7, keypair.private_key())
            .expect("fallible block signing should succeed");
        let infallible = builder.build_with_signature(7, keypair.private_key());
        assert_eq!(fallible.header(), infallible.header());
        assert_eq!(fallible.da_commitments(), infallible.da_commitments());
        let fallible_signature = fallible.signatures().next().expect("fallible signature");
        let infallible_signature = infallible
            .signatures()
            .next()
            .expect("infallible signature");
        assert_eq!(fallible_signature, infallible_signature);
        assert_eq!(fallible_signature.index(), 7);
        fallible_signature
            .signature()
            .verify_hash(keypair.public_key(), fallible.hash())
            .expect("fallible block signature verifies");
    }
    fn sample_da_bundle() -> DaCommitmentBundle {
        let record = DaCommitmentRecord::new(
            LaneId::new(7),
            1,
            1,
            BlobDigest::new([0x11; 32]),
            ManifestDigest::new([0x22; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([0x33; 32]),
            Some(Hash::prehashed([0x55; 32])),
            RetentionPolicy::default(),
            StorageTicketId::new([0x66; 32]),
            Signature::try_from_bytes(&[0x77; 64])
                .expect("checked block builder DA commitment acknowledgement signature fixture"),
        );
        DaCommitmentBundle::new(vec![record])
    }
}
