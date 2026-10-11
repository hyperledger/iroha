//! Native portable protocol fixtures certify synthetic results, not executed World or custody.

use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::{CommitCertificate, SignedBlock, builder::BlockBuilder},
    isi::Log,
    level::Level,
    sumeragi_finality::{
        SumeragiFinalityProof, SumeragiFinalityVerifier, authenticated_genesis,
        test_fixtures::NativeFinalityFixture,
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use std::time::Duration;

fn candidate(chain: &NativeFinalityFixture, label: &str) -> SignedBlock {
    let signer = KeyPair::from_seed(vec![0x73; 32], Algorithm::Ed25519);
    let mut transaction = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(Duration::from_millis(chain.next_header().creation_time_ms));
    let transaction = transaction
        .with_instructions([Log::new(Level::INFO, label.into())])
        .sign(signer.private_key());
    let mut builder = BlockBuilder::new(chain.next_header());
    builder.push_transaction(transaction);
    let mut block = builder.build(iroha_data_model::block::BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![Ok(Vec::new())]);
    block
}

fn restored(chain: &NativeFinalityFixture) -> SumeragiFinalityVerifier {
    SumeragiFinalityVerifier::from_trusted_checkpoint(
        &chain.checkpoint(),
        &chain.network_id(),
        chain.chain_id(),
    )
    .unwrap()
}

fn changed_certificate(
    proof: &SumeragiFinalityProof,
    change: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>),
) -> SumeragiFinalityProof {
    let mut block = iroha_data_model::block::decode_framed_signed_block(&proof.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let mut header = certificate.consensus_header().to_vec();
    let mut qc = certificate.commit_qc().to_vec();
    let mut result = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    change(&mut header, &mut qc, &mut result);
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        qc,
        result,
        availability,
    )));
    SumeragiFinalityProof {
        block_wire: block.encode_wire().unwrap(),
        ..proof.clone()
    }
}

#[test]
fn native_descendants_authenticate_beyond_the_retired_short_fixture_window() {
    let mut chain = NativeFinalityFixture::start("sccp-native-descendants");
    let initial = authenticated_genesis(chain.genesis())
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let mut verifier = restored(&chain);
    for height in 2..=12 {
        let parent = chain.latest().block_header.hash();
        let proof = chain.certify(candidate(&chain, "ordinary protocol fixture"));
        let accepted = verifier.verify(&proof).unwrap();
        assert_eq!(accepted.height(), height);
        assert_eq!(proof.committee.len(), 4);
        assert_eq!(accepted.commitment().schedule.current, initial);
        assert_eq!(accepted.header().prev_block_hash(), Some(parent));
    }
}

#[test]
fn same_epoch_descendants_bind_the_exact_source_outputs_and_wire() {
    let mut chain = NativeFinalityFixture::start("sccp-native-exact-wire");
    let mut verifier = restored(&chain);
    for height in 2..=9 {
        let parent = chain.latest().block_header.hash();
        let block = candidate(&chain, "complete synthetic output");
        let proposal = block.canonical_proposal_wire_hash().unwrap();
        let (wire_len, wire_hash) = block.executed_block_wire_identity().unwrap();
        let input = block.network_input_merkle_commitment();
        let output = block.output_merkle_commitment();
        let proof = chain.certify(block);
        let accepted = verifier.verify(&proof).unwrap();
        assert_eq!(accepted.height(), height);
        assert_eq!(accepted.header().prev_block_hash(), Some(parent));
        assert_eq!(
            accepted.block().canonical_proposal_wire_hash().unwrap(),
            proposal
        );
        assert_eq!(accepted.execution().executed_block_wire_len, wire_len);
        assert_eq!(accepted.execution().executed_block_wire_hash, wire_hash);
        assert_eq!(accepted.execution().transaction_input_commitment, input);
        assert_eq!(accepted.execution().transaction_output_commitment, output);
        accepted.block().validate_output_merkle_cache().unwrap();
        let bytes = accepted.canonical_executed_wire().unwrap();
        assert_eq!(bytes.len() as u64, wire_len);
        assert_eq!(Hash::new(&bytes), wire_hash);
    }
}

#[test]
fn signed_genesis_has_no_fabricated_commit_certificate_or_epoch_boundary() {
    let mut chain = NativeFinalityFixture::start("sccp-native-genesis");
    let mut verifier = restored(&chain);
    let genesis = verifier
        .verify_retained_decision(chain.genesis_proof())
        .unwrap();
    assert!(
        genesis
            .block()
            .commit_certificate()
            .unwrap()
            .commit_qc()
            .is_empty()
    );
    assert!(genesis.commitment().schedule.boundary.is_none());
    let next = chain.certify(candidate(&chain, "authenticate genesis parent result"));
    let accepted = verifier.verify(&next).unwrap();
    assert_eq!(
        accepted.commitment().schedule.current,
        genesis.commitment().schedule.current
    );
    let next_block = accepted.block();
    let forged = changed_certificate(chain.genesis_proof(), |header, qc, _| {
        let certificate = next_block.commit_certificate().unwrap();
        *header = certificate.consensus_header().to_vec();
        *qc = certificate.commit_qc().to_vec();
    });
    assert!(verifier.verify_retained_decision(&forged).is_err());
}

#[test]
fn portable_native_chain_rejects_forks_skips_and_corrupted_certificates() {
    let root = NativeFinalityFixture::start("sccp-native-rejections");
    let mut chain = root.clone();
    let second = chain.certify(candidate(&chain, "accepted branch"));
    let third = chain.certify(candidate(&chain, "accepted successor"));
    assert!(restored(&root).verify(&third).is_err());
    let mut fork = root.clone();
    let fork_second = fork.certify(candidate(&fork, "different branch"));
    let mut verifier = restored(&root);
    verifier.verify(&fork_second).unwrap();
    assert!(verifier.verify(&third).is_err());
    let foreign = NativeFinalityFixture::start("sccp-foreign-instance");
    assert!(restored(&foreign).verify(&second).is_err());
    for part in 0..3 {
        let changed = changed_certificate(&second, |header, qc, result| {
            let bytes = match part {
                0 => header,
                1 => qc,
                _ => result,
            };
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        });
        assert!(
            restored(&root).verify(&changed).is_err(),
            "artifact part {part}"
        );
    }
    let mut bad_pop = second.clone();
    bad_pop.committee[0].proof_of_possession[0] ^= 1;
    assert!(restored(&root).verify(&bad_pop).is_err());
}

#[test]
fn genesis_authority_is_network_bound_and_every_schedule_or_key_change_changes_identity() {
    let chain = NativeFinalityFixture::start("sccp-native-authority");
    let context = authenticated_genesis(chain.genesis())
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    context.validate().unwrap();
    let generation = context.generation();
    assert_eq!(generation.generation, 0);
    assert_eq!(context.authorization.authority_generation, 0);
    assert_eq!(context.authorization.epoch, 0);
    assert_eq!(context.authorization.first_height, 1);
    assert_eq!(context.network_id, chain.network_id());
    assert_eq!(context.authorization.network_id, chain.network_id());
    assert_eq!(generation.network_id, chain.network_id());
    assert_eq!(generation.validators.len(), 4);
    assert_eq!(
        generation.generation_id().unwrap(),
        context.authorization.authority_id
    );
    for (validator, member) in generation.validators.iter().zip(&context.committee) {
        assert_eq!(validator, &member.validator);
    }
    let identity = context.context_id().unwrap();
    for mutation in 0..9 {
        let mut invalid = context.clone();
        match mutation {
            0 => invalid.authorization.authority_generation += 1,
            1 => invalid.authorization.authority_id[0] ^= 1,
            2 => invalid.authorization.epoch += 1,
            3 => invalid.authorization.last_height -= 1,
            4 => invalid.authorization.first_height += 1,
            5 => {
                invalid.authorization.network_id = NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign genesis")),
                )
            }
            6 => invalid.committee.swap(0, 1),
            7 => {
                invalid.network_id = NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign genesis")),
                )
            }
            _ => invalid.leader_seed[0] ^= 1,
        }
        // A structurally valid schedule edit still has a different authenticated identity.
        assert_ne!(
            invalid.context_id().ok(),
            Some(identity),
            "substitution {mutation}"
        );
    }
    // A valid replacement leader schedule cannot borrow the original quorum signatures.
    let mut child_chain = chain.clone();
    let proof = child_chain.certify(candidate(&child_chain, "signed schedule"));
    let verified = restored(&chain).verify(&proof).unwrap();
    let mut commitment = verified.commitment().clone();
    commitment.schedule.current.leader_seed[0] ^= 1;
    for slot in [
        &mut commitment.schedule.next,
        &mut commitment.schedule.after_next,
    ] {
        let iroha_data_model::sumeragi_finality::ScheduledSlot::Ready(config) = slot else {
            panic!("fixture remains inside its signed scheduling epoch");
        };
        config.epoch = commitment.schedule.current.clone();
    }
    let substituted = commitment.preimage().unwrap();
    let changed = changed_certificate(&proof, |_, _, result| *result = substituted);
    assert!(restored(&chain).verify(&changed).is_err());
    let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"foreign genesis"),
    ));
    assert!(
        SumeragiFinalityVerifier::from_trusted_checkpoint(
            &chain.checkpoint(),
            &foreign,
            chain.chain_id()
        )
        .is_err()
    );
    assert!(
        SumeragiFinalityVerifier::from_trusted_checkpoint(
            &chain.checkpoint(),
            &chain.network_id(),
            "foreign-chain"
        )
        .is_err()
    );
}

#[test]
fn native_fixture_signer_rejects_skipped_and_substituted_parents() {
    let root = NativeFinalityFixture::start("sccp-native-parent-refusal");
    let mut chain = root.clone();
    let child = chain.certify(candidate(&chain, "parent"));
    let next = candidate(&chain, "successor");
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.clone().certify(next);
        }))
        .is_err()
    );
    let mut fork = root.clone();
    fork.certify(candidate(&fork, "foreign parent"));
    let wrong_parent = candidate(&fork, "substituted successor");
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            chain.clone().certify(wrong_parent);
        }))
        .is_err()
    );
    let decoded = iroha_data_model::block::decode_framed_signed_block(&child.block_wire).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.clone().certify(decoded);
        }))
        .is_err(),
        "an existing certificate cannot be silently replaced"
    );
}
