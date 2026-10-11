//! The certified-chain reader over a real certified chain: committed and certified reads,
//! per-node certificates, and the frames and certificates it must refuse.

use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    isi::{InstructionBox, Log},
    transaction::TransactionEntrypoint,
};
use iroha_logger::Level;

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
    sumeragi::{
        block_store::{commit_certificate, decode_certificate},
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};

/// Genesis and four certified blocks; block 3 carries a transaction.
fn chain() -> (CertifiedTestChain, HashOf<TransactionEntrypoint>) {
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).expect("chain");
    chain.commit_at(2_000, Vec::new());
    let author = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
    let transaction = chain.sign(
        &author,
        [InstructionBox::from(Log::new(
            Level::INFO,
            "certified".into(),
        ))],
        2_500,
    );
    let entry = transaction.hash_as_entrypoint();
    chain.commit_at(3_000, vec![transaction]);
    chain.commit_with(Some(4_000), Vec::new(), Signers::LastThree);
    chain.commit_at(5_000, Vec::new());
    (chain, entry)
}

// Construct and retain the genuine chain before entering assertion-heavy frames.
// Native parent-service decoding still uses the original unchanged default stack.
#[inline(never)]
fn with_native_chain(assert_original: fn(&CertifiedTestChain, HashOf<TransactionEntrypoint>)) {
    let (chain, entry) = chain();
    let chain = Box::new(chain);
    assert_original(&chain, entry);
}

fn frame(chain: &CertifiedTestChain, height: u64) -> iroha_data_model::block::SharedSignedBlock {
    chain
        .kura()
        .get_block(
            NonZeroUsize::new(usize::try_from(height).unwrap()).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .expect("stored frame")
}

/// `frame` with its certificate's parts replaced.
fn with_parts(
    frame: &SignedBlock,
    edit: impl FnOnce(&mut BlockHeader, &mut Qc, &mut Vec<u8>),
) -> iroha_data_model::block::SharedSignedBlock {
    let certificate = frame.commit_certificate().expect("certificate");
    let (mut header, mut qc) = decode_certificate(certificate).expect("parts");
    let mut preimage = certificate.result_preimage().to_vec();
    edit(&mut header, &mut qc, &mut preimage);
    crate::block::reserve_block_for_tests().initialize(frame.clone().with_commit_certificate(Some(
        commit_certificate(&header, &qc, preimage, certificate.availability().to_vec()).unwrap(),
    )))
}

#[test]
fn committed_and_certified_reads_of_a_real_chain() {
    let (chain, entry) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).expect("reader");
    assert_eq!(reader.instance(), chain.instance());
    let genesis = reader.certified(1).expect("genesis");
    assert_eq!(genesis.verification(), QcVerification::Genesis);
    assert!(genesis.header().is_none() && genesis.commit_qc().is_none());
    assert_eq!(genesis.block_hash(), chain.genesis().hash());
    let blocks = reader
        .walk(1, 5)
        .collect::<Result<Vec<_>, _>>()
        .expect("walk");
    assert_eq!(blocks.len(), 5);
    for (block, height) in blocks.iter().zip(1..) {
        assert_eq!(block.height(), height);
        assert_eq!(
            block.block_hash(),
            *view
                .block_hashes()
                .get(usize::try_from(height - 1).unwrap())
                .unwrap()
        );
        let committed = committed_block(&view, height).expect("committed read");
        assert_eq!(committed.id(), block.id());
        assert_eq!(
            committed.id(),
            certified_block_id(&block.core_hash(), &block.result())
        );
        if height > 1 {
            assert_eq!(block.verification(), QcVerification::Verified);
            assert_eq!(block.commit_qc().unwrap().block_hash, block.core_hash());
            assert!(block.extends(&blocks[usize::try_from(height - 2).unwrap()]));
            assert_eq!(
                block.certificate_len(),
                norito::canonical_frame_len(block.certificate().expect("certificate")).unwrap()
            );
        }
    }
    assert!(
        !blocks[3].extends(&blocks[1]),
        "block 4 does not extend block 2"
    );
    assert_eq!(
        genesis.commitment().schedule.current,
        super::super::epoch::authenticated_genesis(chain.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap()
    );
    // The transaction of block 3 is anchored by the executed wire R commits.
    let anchor = blocks[2].entry_anchor(&entry).expect("anchor");
    assert!(
        blocks[2]
            .block()
            .network_execution_proof(&entry)
            .expect("proof")
            .verify(&anchor)
    );
    assert!(blocks[1].entry_anchor(&entry).is_err());
    let (output_index, _) = blocks[2].block().network_output_at(0).expect("output");
    assert_eq!(
        blocks[2]
            .output_anchor(output_index)
            .expect("output anchor")
            .output_index(),
        output_index
    );
    // The complete verifier authenticates the exact quorum.
    let full = CertifiedChain::new(&view).expect("reader");
    assert_eq!(
        full.certified(4).expect("full check").verification(),
        QcVerification::Verified
    );
}

#[test]
fn uncommitted_heights_are_not_read() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).expect("reader");
    for height in [0, 6, u64::MAX] {
        assert_eq!(
            committed_block(&view, height).err(),
            Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
                ChainReadError::NotCommitted { height }
            ))
        );
        assert_eq!(
            reader.certified(height).err(),
            Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
                ChainReadError::NotCommitted { height }
            ))
        );
    }
    assert_eq!(
        reader
            .walk(4, 6)
            .map(|read| read.is_ok())
            .collect::<Vec<_>>(),
        [true, true, false]
    );
}

#[test]
fn frames_without_a_matching_header_preimage_or_certificate_are_refused() {
    let (chain, _) = chain();
    let original = frame(&chain, 3);
    // No certificate at all.
    let bare = crate::block::reserve_block_for_tests()
        .initialize(original.as_ref().clone().with_commit_certificate(None));
    assert_eq!(
        read_frame(bare, 3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::MissingCertificate { height: 3 }
        ))
    );
    // A header for another payload.
    let wrong_payload = with_parts(&original, |header, _, _| {
        header.payload_hash = Hash32([7; 32])
    });
    assert_eq!(
        read_frame(wrong_payload, 3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::HeaderMismatch { height: 3 }
        ))
    );
    // A header of another height.
    let wrong_height = with_parts(&original, |header, _, _| header.height = 4);
    assert_eq!(
        read_frame(wrong_height, 3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::HeaderMismatch { height: 3 }
        ))
    );
    // A result preimage that commits another executed block.
    let wrong_wire = with_parts(&original, |_, _, preimage| {
        let mut commitment = ExecutionResultCommitment::decode(preimage).unwrap();
        commitment.execution.executed_block_wire_len += 1;
        *preimage = commitment.preimage().unwrap();
    });
    assert_eq!(
        read_frame(wrong_wire, 3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::ExecutionMismatch { height: 3 }
        ))
    );
    // Garbage in the preimage or header.
    let garbage = with_parts(&original, |_, _, preimage| *preimage = vec![1, 2, 3]);
    assert!(matches!(
        read_frame(garbage, 3),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Malformed { height: 3, .. }
        ))
    ));
    // Genesis must carry the result-only certificate.
    let genesis = frame(&chain, 1);
    let certificate = genesis.commit_certificate().unwrap().clone();
    let headed = crate::block::reserve_block_for_tests().initialize(
        genesis.as_ref().clone().with_commit_certificate(Some(
            CommitCertificate::from_untrusted_parts(
                vec![1],
                Vec::new(),
                certificate.result_preimage().to_vec(),
                certificate.availability().to_vec(),
            ),
        )),
    );
    assert!(matches!(
        read_frame(headed, 1),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Malformed { height: 1, .. }
        ))
    ));
}

#[test]
fn certificates_that_do_not_certify_the_stored_block_are_refused() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).expect("reader");
    let original = frame(&chain, 4);
    let certify =
        |frame: iroha_data_model::block::SharedSignedBlock| reader.check_certificate(frame, 4);
    certify(Clone::clone(&original)).expect("the stored certificate verifies");
    // A preimage whose `R` is not the certified one (its executed wire is unchanged).
    let other_result = with_parts(&original, |_, _, preimage| {
        let mut commitment = ExecutionResultCommitment::decode(preimage).unwrap();
        let schedule::ScheduledSlot::Ready(next) = &mut commitment.schedule.after_next else {
            unreachable!()
        };
        next.params.block_time_ms += 1;
        *preimage = commitment.preimage().unwrap();
    });
    assert_eq!(
        certify(other_result).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::ResultMismatch { height: 4 }
        ))
    );
    // A header whose hash is not the certified block hash.
    let other_header = with_parts(&original, |header, _, _| header.origin_view = 3);
    assert_eq!(
        certify(other_header).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::HeaderMismatch { height: 4 }
        ))
    );
    // A Prepare certificate is not finality authority.
    let edits: [fn(&mut BlockHeader, &mut Qc, &mut Vec<u8>); 1] =
        [|_, qc, _| qc.kind = VoteKind::Prepare];
    for edit in edits {
        assert_eq!(
            certify(with_parts(&original, edit)).err(),
            Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
                ChainReadError::HeaderMismatch { height: 4 }
            ))
        );
    }
    // Another instance.
    let other_instance = with_parts(&original, |_, qc, _| qc.instance = Hash32([5; 32]));
    assert_eq!(
        certify(other_instance).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::WrongInstance { height: 4 }
        ))
    );
    // Below the quorum, or a forged aggregate.
    let (header, qc) = decode_certificate(original.commit_certificate().unwrap()).unwrap();
    let below = chain.commit_qc(4, qc.block_hash, qc.result, Signers::BelowQuorum);
    let below = with_parts(&original, |_, qc, _| *qc = below);
    assert_eq!(
        certify(below).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Certificate {
                height: 4,
                error: CertError::TooFewSigners
            }
        ))
    );
    // More signatures cannot widen the protocol's exact finality authority either.
    let all = chain.commit_qc(4, qc.block_hash, qc.result, Signers::All);
    let all = with_parts(&original, |_, qc, _| *qc = all);
    assert_eq!(
        certify(all).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Certificate {
                height: 4,
                error: CertError::TooManySigners
            }
        ))
    );
    let forged = with_parts(&original, |_, qc, _| qc.agg_sig.0[5] ^= 1);
    assert!(matches!(
        certify(forged),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Certificate { height: 4, .. }
        ))
    ));
    assert_eq!(header.height, 4);
}

/// A genuine exact-quorum QC cannot replace the original signed availability table.
#[test]
fn certified_reader_rejects_missing_foreign_and_corrupt_signed_availability() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let original = frame(&chain, 3);
    let certificate = original.commit_certificate().unwrap();
    reader
        .check_certificate(original.clone(), 3)
        .expect("original signed rows and exact quorum verify together");
    let other = frame(&chain, 4);
    let mut corrupted = certificate.availability().to_vec();
    let last = corrupted
        .last_mut()
        .expect("signed availability is present");
    *last ^= 1;
    for availability in [
        Vec::new(),
        other.commit_certificate().unwrap().availability().to_vec(),
        corrupted,
    ] {
        let changed = crate::block::reserve_block_for_tests().initialize(
            original.as_ref().clone().with_commit_certificate(Some(
                CommitCertificate::from_untrusted_parts(
                    certificate.consensus_header().to_vec(),
                    certificate.commit_qc().to_vec(),
                    certificate.result_preimage().to_vec(),
                    availability,
                ),
            )),
        );
        assert!(
            reader.check_certificate(changed, 3).is_err(),
            "table custody is independently mandatory even under the unchanged valid QC",
        );
    }
}

/// Certificates are per node: another valid `CommitQC` of the same block (other signers) gives
/// the same consensus-visible receipt, and both certificates verify.
#[test]
fn two_valid_certificates_of_one_block_give_one_consensus_receipt() {
    with_native_chain(assert_two_valid_certificates_of_one_block_give_one_consensus_receipt);
}

#[inline(never)]
fn assert_two_valid_certificates_of_one_block_give_one_consensus_receipt(
    chain: &CertifiedTestChain,
    entry: HashOf<TransactionEntrypoint>,
) {
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).expect("reader");
    let original = frame(chain, 3);
    let (_, qc) = decode_certificate(original.commit_certificate().unwrap()).unwrap();
    let other_qc = chain.commit_qc(3, qc.block_hash, qc.result, Signers::LastThree);
    assert_ne!(other_qc.signers, qc.signers);
    let other = with_parts(&original, |_, qc, _| *qc = other_qc.clone());
    assert_ne!(other.commit_certificate(), original.commit_certificate());
    let left = read_frame(Clone::clone(&original), 3).expect("committed read");
    let right = read_frame(Clone::clone(&other), 3).expect("committed read");
    assert_eq!(left.id(), right.id());
    assert_eq!(left.header(), right.header());
    assert_eq!(
        (left.core_hash(), left.result(), left.block_hash()),
        (right.core_hash(), right.result(), right.block_hash())
    );
    assert_eq!(left.commitment(), right.commitment());
    assert_eq!(left.entry_anchor(&entry), right.entry_anchor(&entry));
    assert_eq!(left.block_time_ms(), right.block_time_ms());
    for committed in [left, right] {
        assert_eq!(
            reader
                .check_certificate(committed.block, committed.height)
                .expect("both certificates verify")
                .verification(),
            QcVerification::Verified
        );
    }
}

/// Store authentic history with no live registry or schedule candidates to help the reader.
fn state_with_history(history: &[iroha_data_model::block::SharedSignedBlock]) -> State {
    let kura = Kura::blank_kura_for_testing();
    let mut state = State::new_with_chain_and_network_id_for_testing(
        World::new(),
        Clone::clone(&kura),
        LiveQueryStore::start_test(),
        "sumeragi-certified-test-chain".parse().unwrap(),
        iroha_data_model::NetworkId::from_genesis_hash(history[0].hash()),
    );
    for block in history {
        kura.store_block(Clone::clone(block)).unwrap();
        state.push_block_hash_for_testing(block.hash());
    }
    state
}

#[path = "boundary_tests.rs"]
mod boundaries;

#[path = "state_certificate_tests.rs"]
mod state_certificate;

#[test]
fn a_view_of_another_network_is_refused() {
    let (chain, _) = chain();
    // The chain's genesis frame in the Kura of a State of another network.
    let kura = Kura::blank_kura_for_testing();
    let mut state = State::new_with_chain_and_network_id_for_testing(
        World::new(),
        Clone::clone(&kura),
        LiveQueryStore::start_test(),
        "sumeragi-certified-test-chain".parse().unwrap(),
        iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"another genesis",
        ))),
    );
    kura.store_block(frame(&chain, 1)).unwrap();
    state.push_block_hash_for_testing(chain.genesis().hash());
    let view = state.view();
    assert!(
        committed_block(&view, 1).is_err(),
        "header-only foreign State has no original execution tip"
    );
    assert_eq!(
        CertifiedChain::new(&view).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::ForeignGenesis
        ))
    );
    // A view whose journal names another block at a height does not read Kura's.
    let mut other = State::new_with_chain_and_network_id_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        "sumeragi-certified-test-chain".parse().unwrap(),
        chain.network_id(),
    );
    other.push_block_hash_for_testing(chain.genesis().hash());
    assert!(
        committed_block(&other.view(), 1).is_err(),
        "a hash journal cannot mint execution authority"
    );
}

#[test]
fn historical_committee_material_cannot_bypass_global_voting_geometry() {
    use iroha_data_model::sumeragi::epoch::{ValidatorCommitteeMemberV1, validate_committee};
    use iroha_model_base::peer::PeerId;
    let pairs = (1_u8..=35)
        .map(|index| KeyPair::from_seed(vec![index; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    for count in 0..=pairs.len() {
        let mut members = pairs[..count]
            .iter()
            .map(|pair| ValidatorCommitteeMemberV1 {
                validator: PeerId::new(pair.public_key().clone()),
                proof_of_possession: iroha_crypto::bls_normal_pop_prove(pair.private_key())
                    .unwrap(),
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| {
            super::super::crypto::core_key(member.validator.public_key()).unwrap()
        });
        let result = validate_committee(&members);
        if count >= 4 && count <= 31 && (count - 1) % 3 == 0 {
            result.expect("exact global committee");
            let entry = schedule::global_committee(
                members
                    .iter()
                    .map(|member| core_key(member.validator.public_key()).unwrap())
                    .collect(),
            )
            .unwrap();
            assert_eq!(entry.q(), 2 * entry.f() + 1);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn genesis_signature_is_verified_even_when_its_header_hash_matches_the_view() {
    use iroha_crypto::SignatureOf;
    use iroha_data_model::block::BlockSignature;

    let (chain, _) = chain();
    let original = frame(&chain, 1);
    let foreign = KeyPair::from_seed(vec![0x42; 32], Algorithm::Ed25519);
    let mut forged = original.as_ref().clone();
    forged
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([BlockSignature::new(
                0,
                SignatureOf::from_hash(foreign.private_key(), original.hash()),
            )])
            .expect("at most 31 block signatures"),
        )
        .unwrap();
    assert_eq!(forged.hash(), original.hash());
    let mut extra = original.as_ref().clone();
    extra.sign(foreign.private_key(), 1);
    for block in [forged, extra] {
        let state =
            state_with_history(&[crate::block::reserve_block_for_tests().initialize(block)]);
        assert!(matches!(
            CertifiedChain::new(&state.view()),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                ChainReadError::ForeignGenesis
            ))
        ));
    }
}

#[test]
fn genesis_payload_is_bound_to_its_signed_header_before_authority_is_read() {
    let (chain, _) = chain();
    let original = frame(&chain, 1);
    let signature = original.signatures().next().unwrap().clone();
    let mut substituted = original.payload().clone();
    // Every transaction still has its genuine signature, but this extra copy was never
    // committed by the signed genesis header. Unauthenticated payloads cannot supply keys.
    substituted
        .external_entrypoints
        .push(substituted.external_entrypoints[0].clone());
    let mut missing_policy = original.payload().clone();
    missing_policy.da_proof_policies = None;
    for payload in [substituted, missing_policy] {
        let block = SignedBlock::presigned_with_payload(signature.clone(), payload);
        assert_eq!(block.hash(), original.hash());
        assert!(
            block
                .external_transactions()
                .all(|tx| tx.verify_signature().is_ok())
        );
        assert!(
            signature
                .signature()
                .verify_hash(
                    block
                        .external_transactions()
                        .next()
                        .unwrap()
                        .authority()
                        .try_signatory()
                        .unwrap(),
                    block.hash(),
                )
                .is_ok()
        );
        assert!(block.validate_proposal_commitments().is_err());
        let state =
            state_with_history(&[crate::block::reserve_block_for_tests().initialize(block)]);
        assert!(matches!(
            CertifiedChain::new(&state.view()),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                ChainReadError::ForeignGenesis
            ))
        ));
    }
    let view = chain.state().view();
    assert!(CertifiedChain::new(&view).unwrap().certified(2).is_ok());
}

#[test]
fn pinned_prefix_uses_the_exact_cut_without_a_world_authority() {
    let (chain, _) = chain();
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = chain.network_id();
    let hashes = (1..=3)
        .map(|height| frame(&chain, height).hash())
        .collect::<Vec<_>>();
    let reader = CertifiedChain::from_pinned(
        &chain_id,
        &network,
        &hashes,
        chain.kura(),
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    let receipts = reader.walk(1, 3).collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].verification(), QcVerification::Genesis);
    assert_eq!(receipts[2].verification(), QcVerification::Verified);
    assert_eq!(receipts[2].commitment(), chain.committed(3).commitment());
    // Kura also holds heights four and five, but they are outside this restoration cut.
    assert_eq!(
        reader.certified(4).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotCommitted { height: 4 }
        ))
    );
    assert_eq!(
        reader.committed(0).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotCommitted { height: 0 }
        ))
    );
    assert!(matches!(reader.source, ChainSource::Pinned { .. }));
    let prefix = reader.prefix.lock();
    let prefix = prefix.as_ref().unwrap();
    assert_eq!(prefix.tip.height(), 3);
    assert!(prefix.schedule.entries().len() <= 3);
}

#[test]
fn pinned_prefix_rejects_empty_foreign_changed_and_unavailable_sources() {
    let (chain, _) = chain();
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = chain.network_id();
    let hashes = (1..=3)
        .map(|height| frame(&chain, height).hash())
        .collect::<Vec<_>>();
    assert_eq!(
        CertifiedChain::from_pinned(
            &chain_id,
            &network,
            &[],
            chain.kura(),
            &chain.state().ivm_execution_budget(),
        )
        .err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotCommitted { height: 1 }
        ))
    );
    let wrong_hash = HashOf::from_untyped_unchecked(Hash::new(b"not the pinned block"));
    let foreign = NetworkId::from_genesis_hash(wrong_hash);
    assert_eq!(
        CertifiedChain::from_pinned(
            &chain_id,
            &foreign,
            &hashes,
            chain.kura(),
            &chain.state().ivm_execution_budget(),
        )
        .err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::ForeignGenesis
        ))
    );
    let absent = Kura::blank_kura_for_testing();
    assert_eq!(
        CertifiedChain::from_pinned(
            &chain_id,
            &network,
            &hashes,
            &absent,
            &chain.state().ivm_execution_budget(),
        )
        .err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotInView { height: 1 }
        ))
    );
    let mut changed = hashes.clone();
    changed[0] = wrong_hash;
    assert_eq!(
        CertifiedChain::from_pinned(
            &chain_id,
            &network,
            &changed,
            chain.kura(),
            &chain.state().ivm_execution_budget(),
        )
        .err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotInView { height: 1 }
        ))
    );
    let mut changed = hashes.clone();
    changed[2] = wrong_hash;
    let reader = CertifiedChain::from_pinned(
        &chain_id,
        &network,
        &changed,
        chain.kura(),
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    assert_eq!(
        reader.certified(3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotInView { height: 3 }
        ))
    );
    let wrong_chain = ChainId::from("another-configured-consensus-instance");
    let reader = CertifiedChain::from_pinned(
        &wrong_chain,
        &network,
        &hashes,
        chain.kura(),
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    assert_eq!(
        reader.certified(2).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::WrongInstance { height: 2 }
        ))
    );
    chain
        .kura()
        .corrupt_canonical_body_for_testing(NonZeroUsize::new(3).unwrap())
        .unwrap();
    let reader = CertifiedChain::from_pinned(
        &chain_id,
        &network,
        &hashes,
        chain.kura(),
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    assert_eq!(
        reader.certified(3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotInView { height: 3 }
        ))
    );
}

#[test]
fn pinned_genesis_result_is_unsigned_until_a_real_successor_authenticates_it() {
    let (chain, _) = chain();
    let genesis = frame(&chain, 1);
    let certificate = genesis.commit_certificate().unwrap();
    let mut result = ExecutionResultCommitment::decode(certificate.result_preimage()).unwrap();
    result.execution.world_state_root = Hash::new(b"unsigned pinned genesis execution replacement");
    let changed = crate::block::reserve_block_for_tests().initialize(
        genesis.as_ref().clone().with_commit_certificate(Some(
            CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                certificate.commit_qc().to_vec(),
                result.preimage().unwrap(),
                certificate.availability().to_vec(),
            ),
        )),
    );
    assert_eq!(changed.hash(), genesis.hash());
    let kura = Kura::blank_kura_for_testing();
    kura.store_block(changed).unwrap();
    kura.store_block(frame(&chain, 2)).unwrap();
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = chain.network_id();
    let hashes = [genesis.hash(), frame(&chain, 2).hash()];
    let reader = CertifiedChain::from_pinned(
        &chain_id,
        &network,
        &hashes[..1],
        &kura,
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    let receipt = reader.certified(1).unwrap();
    assert_eq!(receipt.verification(), QcVerification::Genesis);
    assert_eq!(
        receipt.commitment().execution.world_state_root,
        result.execution.world_state_root
    );
    let reader = CertifiedChain::from_pinned(
        &chain_id,
        &network,
        &hashes,
        &kura,
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    assert_eq!(
        reader.certified(2).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Discontinuous { height: 2 }
        ))
    );
}

#[test]
fn portable_committee_uses_the_authenticated_original_epoch_members() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    for height in 1..=chain.height() {
        let expected = chain
            .validators()
            .iter()
            .map(|(peer, pop)| (peer.public_key().clone(), pop.clone()))
            .collect::<Vec<_>>();
        assert_eq!(reader.proof_committee(height).unwrap(), expected);
    }
}

// Keep large reader/receipt values out of the assertion frame and the nested
// Result<Vec<_>> collector. Verification still walks the same original frames
// under the unchanged default test stack and production allocation limits.
#[inline(never)]
fn retain_native_frame_reader<'a>(
    chain_id: &'a ChainId,
    network: &'a NetworkId,
    hashes: &'a [HashOf<IrohaHeader>],
    frames: &'a [iroha_data_model::block::SharedSignedBlock],
) -> Result<Box<CertifiedChain<'a, StateView<'a>>>, ExecutionAttemptError<ChainReadError>> {
    CertifiedChain::from_frames(chain_id, network, hashes, frames).map(Box::new)
}

#[inline(never)]
fn retain_native_walk<V: StateReadOnly + ?Sized>(
    reader: &CertifiedChain<'_, V>,
    first: u64,
    last: u64,
) -> Result<Vec<Box<CertifiedBlock>>, ExecutionAttemptError<ChainReadError>> {
    let mut receipts = Vec::new();
    for receipt in reader.walk(first, last) {
        receipts.push(Box::new(receipt?));
    }
    Ok(receipts)
}

#[test]
fn borrowed_native_frames_use_the_same_verifier_and_exact_cut() {
    let (chain, _) = chain();
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = chain.network_id();
    let frames = (1..=3)
        .map(|height| frame(&chain, height))
        .collect::<Vec<_>>();
    let hashes = frames.iter().map(|block| block.hash()).collect::<Vec<_>>();
    let reader = retain_native_frame_reader(&chain_id, &network, &hashes, &frames).unwrap();
    let reads = retain_native_walk(&reader, 1, 3).unwrap();
    assert_eq!(reads[0].verification(), QcVerification::Genesis);
    assert_eq!(reads[2].verification(), QcVerification::Verified);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        reads[2].block(),
        &frames[2]
    ));
    assert_eq!(reads[2].commitment(), chain.committed(3).commitment());
    assert_eq!(
        reader.certified(4).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotCommitted { height: 4 }
        ))
    );
    assert!(retain_native_frame_reader(&chain_id, &network, &hashes[..2], &frames).is_err());
    assert!(retain_native_frame_reader(&chain_id, &network, &[], &[]).is_err());
    let foreign =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign")));
    assert_eq!(
        retain_native_frame_reader(&chain_id, &foreign, &hashes, &frames).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::ForeignGenesis
        ))
    );
    let other_chain = ChainId::from("foreign-instance");
    let reader = retain_native_frame_reader(&other_chain, &network, &hashes, &frames).unwrap();
    assert_eq!(
        reader.certified(3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::WrongInstance { height: 2 }
        ))
    );
    assert_eq!(
        retain_native_walk(&reader, 1, 3).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::WrongInstance { height: 2 }
        ))
    );
    let mut reordered = frames.clone();
    reordered.swap(1, 2);
    let reader = retain_native_frame_reader(&chain_id, &network, &hashes, &reordered).unwrap();
    assert_eq!(
        reader.certified(2).err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::NotInView { height: 2 }
        ))
    );
}

#[test]
fn borrowed_native_frames_reject_changed_result_even_under_unchanged_header_hash() {
    let (chain, _) = chain();
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = chain.network_id();
    let mut frames = (1..=3)
        .map(|height| frame(&chain, height))
        .collect::<Vec<_>>();
    let hashes = frames.iter().map(|block| block.hash()).collect::<Vec<_>>();
    frames[1] = with_parts(&frames[1], |_, _, preimage| {
        let mut result = ExecutionResultCommitment::decode(preimage).unwrap();
        result.execution.ordinary_writes_root = Hash::new(b"changed borrowed R");
        *preimage = result.preimage().unwrap();
    });
    assert_eq!(frames[1].hash(), hashes[1]);
    let reader = CertifiedChain::from_frames(&chain_id, &network, &hashes, &frames).unwrap();
    assert!(reader.certified(3).is_err());
}

#[path = "prefix_tests.rs"]
mod prefix_tests;

/// A warm decoded body never authorizes a changed on-disk certificate.
#[test]
fn durable_certificate_read_rejects_checksum_valid_corruption_after_cache_warm() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    let original = frame(&chain, 2);
    let original_wire = original.encode_wire().unwrap();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let hashes = view.block_hashes().iter().copied().collect::<Vec<_>>();
    let pinned = CertifiedChain::from_pinned(
        view.chain_id(),
        view.network_id(),
        &hashes,
        chain.kura(),
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    reader.certified(2).expect("original State certificate");
    pinned.certified(2).expect("original pinned certificate");
    let path = Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let original_file = std::fs::read(&path).unwrap();
    let offsets = original_file
        .windows(original_wire.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == original_wire.as_slice()).then_some(at))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1, "one occupied original frame");
    for wrong_height in [true, false] {
        let changed = with_parts(&original, |_, qc, _| {
            if wrong_height {
                qc.height = 1;
            } else {
                qc.agg_sig.0[0] ^= 1;
            }
        });
        let changed_wire = changed.encode_wire().unwrap();
        assert_eq!(changed_wire.len(), original_wire.len());
        let mut changed_file = original_file.clone();
        changed_file[offsets[0]..offsets[0] + changed_wire.len()].copy_from_slice(&changed_wire);
        std::fs::write(&path, changed_file).unwrap();
        assert_eq!(
            frame(&chain, 2).encode_wire().unwrap(),
            original_wire,
            "ordinary body cache remains warm, so the test exercises durable certificate reads"
        );
        assert!(
            reader.certified(2).is_err(),
            "State reader must recheck durable QC"
        );
        assert!(
            pinned.certified(2).is_err(),
            "restoration reader must recheck durable QC"
        );
        std::fs::write(&path, &original_file).unwrap();
        reader.certified(2).expect("restored exact original source");
        pinned
            .certified(2)
            .expect("restored pinned original source");
    }
}

#[test]
fn signed_genesis_initialization_does_not_repeat_completed_scope_decode() {
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let budget = chain.state().ivm_execution_budget();
    let original = frame(&chain, 1);
    let baseline = budget.reserved_bytes();
    let limits =
        norito::canonical_decode_limits(chain.kura().native_context_archive_max_bytes().get());
    let original_wire = original.encode_wire().unwrap();
    let view = chain.state().view();
    let expected_hash = *view.block_hashes().get(0).unwrap();
    let original_slot = chain
        .kura()
        .native_frame_read(1, expected_hash)
        .unwrap()
        .unwrap();
    // Measure the actual durable acquisition used by the public constructor, its original
    // prelude, and one complete canonical epoch pass. The warm Kura body is not that newly
    // decoded owner and cannot stand in for its real cumulative body-decoder debit.
    let reference = norito::core::DecodeBudgetContext::try_new_owned(limits, &budget).unwrap();
    reference.with(|| {
        let source = ChainSource::State(&view).block(GENESIS_HEIGHT).unwrap();
        assert_eq!(source.hash(), expected_hash);
        assert!(source.header().is_genesis());
        assert_eq!(source.hash().as_ref(), view.network_id().as_bytes());
        source.validate_proposal_commitments().unwrap();
        let _signed = super::super::epoch::authenticated_genesis(&source).unwrap();
        budget.with_deferred_refund_notifications(|_| drop(source));
    });
    let single_pass = usize::try_from(reference.consumed_allocated_bytes()).unwrap();
    assert!(
        single_pass > 0,
        "original signed metadata must actually decode"
    );
    drop(reference);
    assert_eq!(budget.reserved_bytes(), baseline);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            limits.max_sequence_elements(),
            limits.max_field_bytes(),
            limits.max_total_elements(),
            single_pass,
            limits.max_nesting_depth(),
        ),
        &budget,
    )
    .unwrap();
    let read = context.with(|| CertifiedChain::new(&view));
    // The old constructor exhausts this exact cumulative allowance at its duplicate JSON
    // read. Refuse unrelated fixture/runtime failures before the causal assertion.
    if let Err(error) = &read {
        assert!(
            matches!(error, ExecutionAttemptError::Deferred(local)
                if local.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
            "unexpected signed-genesis initialization failure: {error:?}"
        );
    }
    assert!(
        read.is_ok(),
        "signed genesis initialization must use the original completed scope decode once: {:?}",
        read.as_ref().err()
    );
    let reader = read.unwrap();
    assert_eq!(reader.instance(), chain.instance());
    assert_eq!(reader.genesis().hash(), expected_hash);
    assert_eq!(reader.genesis().encode_wire().unwrap(), original_wire);
    let current_slot = chain
        .kura()
        .native_frame_read(1, expected_hash)
        .unwrap()
        .unwrap();
    assert!(original_slot.same_original_slot(&current_slot));
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(single_pass).unwrap()
    );
    budget.with_deferred_refund_notifications(|_| drop(reader));
    drop(view);
    drop(context);
    assert_eq!(budget.reserved_bytes(), baseline);
}
