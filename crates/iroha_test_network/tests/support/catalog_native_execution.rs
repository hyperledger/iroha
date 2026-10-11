//! Exact ordinary catalog execution under independently anchored current finality.
//!
//! The fixture authenticates the complete input/output and committed single route,
//! then compares each peer's bounded local carrier with the same certified execution.
//! Payload availability requires its separate signed RS16 evidence.

use super::*;
use iroha_core::kura::{BlockIndex, BlockStore, Kura};
use iroha_data_model::{
    block::{
        SignedBlock, execution_context::ExternalExecutionContext,
        proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
    },
    query::CommittedTransaction,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityProof, VerifiedSumeragiBlock},
};

/// Require current finality and the exact ordinary input, output, and execution route.
pub(super) fn authenticated_native_execution(
    finality: &FixtureFinality,
    peer: &real_custody::CatalogPeer,
    transaction: &SignedTransaction,
    height: u64,
    route: RoutingDecision,
    expected_committee: Option<&[PeerId]>,
) -> Result<Vec<u8>> {
    let client = &peer.client;
    let store = &peer.kura_store;
    let details = client.get_successful_transaction_details(transaction.hash_as_entrypoint())?;
    let committed = &details.transaction;
    let verified =
        finality.verified_block(&peer.peer_id, client, height, *committed.block_hash())?;
    verify_ordinary_execution(
        &verified,
        &finality.network_id,
        committed,
        transaction,
        route,
    )?;
    client.get_lane_lifecycle_status()?.validate()?;
    let committee = finality
        .validators
        .iter()
        .map(|entry| PeerId::new(entry.public_key.clone()))
        .collect::<Vec<_>>();
    if let Some(expected) = expected_committee {
        ensure!(
            expected == committee,
            "catalog route committee differs from the independently pinned four validators"
        );
    }
    let mut blocks = BlockStore::open_read_only(Kura::canonical_storage_path(store))?;
    let mut index = BlockIndex::default();
    blocks.read_block_indices(
        height
            .checked_sub(1)
            .ok_or_else(|| eyre!("zero Applied height"))?,
        std::slice::from_mut(&mut index),
    )?;
    let len = usize::try_from(index.length)?;
    ensure!(
        (1..=AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1).contains(&len),
        "catalog carrier is absent or exceeds bounded wire length"
    );
    let mut bytes = vec![0; len];
    blocks.read_block_data(index.start, &mut bytes)?;
    authenticated_local_execution(&bytes, &verified, &finality.validators)
}

fn verify_ordinary_execution(
    verified: &VerifiedSumeragiBlock,
    network: &NetworkId,
    committed: &CommittedTransaction,
    transaction: &SignedTransaction,
    route: RoutingDecision,
) -> Result<()> {
    ensure!(
        committed.entrypoint() == &TransactionEntrypoint::External(transaction.clone()),
        "catalog execution differs from the exact signed transaction"
    );
    verified.verify_committed_transaction(network, committed)?;
    let block = verified.block();
    let context = block
        .execution_context()
        .ok_or_else(|| eyre!("missing execution context"))?;
    ensure!(
        context.lane_merge.is_none() && context.external.len() == block.network_entrypoint_count(),
        "ordinary catalog carrier has another execution source or incomplete route contexts"
    );
    let index = usize::try_from(committed.entrypoint_proof.leaf_index())?;
    let expected = ExternalExecutionContext::new(
        transaction.hash_as_entrypoint(),
        route.lane_id,
        route.dataspace_id,
    );
    ensure!(
        context.external.get(index) == Some(&expected)
            && context
                .external
                .iter()
                .filter(|entry| entry.entrypoint_hash == transaction.hash_as_entrypoint())
                .count()
                == 1,
        "successful transaction executed on a different route, plan, or input position"
    );
    Ok(())
}

fn authenticated_local_execution(
    bytes: &[u8],
    verified: &VerifiedSumeragiBlock,
    validators: &[FinalityValidator],
) -> Result<Vec<u8>> {
    ensure!(
        (1..=AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1).contains(&bytes.len()),
        "local catalog carrier exceeds bounded wire length"
    );
    let block =
        norito::with_decode_limits_scope(norito::canonical_decode_limits(bytes.len()), || {
            decode_framed_signed_block(bytes)
        })?;
    ensure!(
        block.header() == verified.header() && block.encode_wire()? == bytes,
        "local catalog carrier header or canonical framing differs"
    );
    SumeragiFinalityProof {
        block_header: block.header(),
        block_wire: bytes.to_vec(),
        committee: validators.to_vec(),
    }
    .decode_checked()?;
    // Different valid quorum witnesses are allowed; execution identity excludes only
    // the certificate. The current verifier authenticates every result and wire binding.
    let canonical = block.with_commit_certificate(None).encode_wire()?;
    ensure!(
        canonical == verified.canonical_executed_wire()?,
        "local catalog carrier differs from independently authenticated current execution"
    );
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        state::World,
        sumeragi::{
            finality::build_proof,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        block::CommitCertificate, sumeragi_finality::SumeragiFinalityVerifier,
        transaction::TransactionBuilder,
    };

    fn fixture() -> (
        CertifiedTestChain,
        SignedTransaction,
        VerifiedSumeragiBlock,
        Vec<FinalityValidator>,
    ) {
        init_instruction_registry();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        let signer = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
        let mut builder = TransactionBuilder::new(
            chain.network_id(),
            chain.genesis_account().clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(10_001));
        let transaction = builder
            .with_instructions([Log::new(
                Level::INFO,
                "ordinary catalog proof work".to_owned(),
            )])
            .sign(signer.private_key());
        assert_eq!(chain.commit(vec![transaction.clone()]), vec![true]);
        let validators = chain
            .validators()
            .iter()
            .map(|(peer, pop)| FinalityValidator {
                public_key: peer.public_key().clone(),
                proof_of_possession: pop.clone(),
            })
            .collect::<Vec<_>>();
        let mut verifier = SumeragiFinalityVerifier::new(
            chain.genesis(),
            chain.state().chain_id_ref().as_ref(),
            validators.clone(),
        )
        .unwrap();
        verifier
            .verify(&build_proof(&chain.state().view(), 1).unwrap())
            .unwrap();
        let verified = verifier
            .verify(&build_proof(&chain.state().view(), 2).unwrap())
            .unwrap();
        (chain, transaction, verified, validators)
    }

    fn committed(block: &SignedBlock) -> CommittedTransaction {
        let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
        let (index, _) = block.network_output_at(0).unwrap();
        let output = block.execution_outputs()[index as usize].clone();
        CommittedTransaction {
            block_hash: block.hash(),
            entrypoint_hash: entrypoint.hash(),
            entrypoint_proof: block.network_input_proof(0).unwrap(),
            entrypoint,
            output_hash: HashOf::new(&output),
            output_proof: block.output_proof(index).unwrap(),
            output,
        }
    }

    #[test]
    fn current_catalog_proof_binds_real_ordinary_route_and_success() {
        let (chain, transaction, verified, _) = fixture();
        verify_ordinary_execution(
            &verified,
            &chain.network_id(),
            &committed(verified.block()),
            &transaction,
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        )
        .unwrap();
    }

    #[test]
    fn current_catalog_proof_rejects_changed_transaction_route_or_output() {
        let (chain, transaction, verified, _) = fixture();
        let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
        let original = committed(verified.block());
        assert!(
            verify_ordinary_execution(
                &verified,
                &chain.network_id(),
                &original,
                &transaction,
                RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL),
            )
            .is_err()
        );
        let mut changed = original.clone();
        changed.output_hash = HashOf::from_untyped_unchecked(Hash::new(b"substituted output"));
        assert!(
            verify_ordinary_execution(
                &verified,
                &chain.network_id(),
                &changed,
                &transaction,
                route
            )
            .is_err()
        );
        let signer = KeyPair::from_seed(vec![0xCF; 32], Algorithm::Ed25519);
        assert!(
            TransactionBuilder::from_payload(transaction.payload().clone())
                .unwrap()
                .try_sign(signer.private_key())
                .is_err(),
            "another signer cannot construct the original authority's transaction"
        );
        let mut foreign_payload = transaction.payload().clone();
        foreign_payload.authority =
            iroha_data_model::account::AccountId::new(signer.public_key().clone());
        let changed_signer = TransactionBuilder::from_payload(foreign_payload)
            .unwrap()
            .sign(signer.private_key());
        assert!(
            verify_ordinary_execution(
                &verified,
                &chain.network_id(),
                &original,
                &changed_signer,
                route
            )
            .is_err()
        );
        assert!(
            verify_ordinary_execution(
                &verified,
                &NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                    b"foreign genesis"
                ))),
                &original,
                &transaction,
                route,
            )
            .is_err()
        );
    }

    #[test]
    fn current_catalog_wire_requires_exact_authenticated_execution_and_complete_certificate() {
        let (_, _, verified, validators) = fixture();
        let bytes = verified.block().encode_wire().unwrap();
        assert_eq!(
            authenticated_local_execution(&bytes, &verified, &validators).unwrap(),
            verified.canonical_executed_wire().unwrap()
        );
        for certificate in [
            None,
            Some(CommitCertificate::from_untrusted_parts(
                Vec::new(),
                Vec::new(),
                b"invalid result".to_vec(),
                Vec::new(),
            )),
        ] {
            let changed = verified
                .block()
                .clone()
                .with_commit_certificate(certificate)
                .encode_wire()
                .unwrap();
            assert!(authenticated_local_execution(&changed, &verified, &validators).is_err());
        }
        let mut changed = bytes;
        changed.push(0);
        assert!(authenticated_local_execution(&changed, &verified, &validators).is_err());
        let mut changed = validators;
        changed.swap(0, 1);
        assert!(
            authenticated_local_execution(
                &verified.block().encode_wire().unwrap(),
                &verified,
                &changed
            )
            .is_err()
        );
    }
}
