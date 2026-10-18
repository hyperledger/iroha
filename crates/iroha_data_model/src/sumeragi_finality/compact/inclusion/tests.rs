//! Compact selective-inclusion tests on genuine native certificates.
//! Fixture results are synthetic; they execute no World transition.

use super::*;
use crate::{
    account::AccountId,
    block::{BlockSignatures, builder::BlockBuilder, output_test_support},
    isi::Log,
    level::Level,
    query::CommittedTransaction,
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::{
        FeePaymentIntent, TransactionBuilder, TransactionResultInner,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use std::time::Duration;

fn root(fixture: &NativeFinalityFixture) -> SumeragiFinalityVerifier {
    SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap()
}

fn rejected() -> TransactionResultInner {
    Err(TransactionRejectionReason::LimitCheck(
        TransactionLimitError {
            reason: "synthetic rejection".into(),
        },
    ))
}

fn transaction(network: NetworkId, creation_time_ms: u64, label: &str) -> SignedTransaction {
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let mut builder = TransactionBuilder::new(
        network,
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    builder.set_creation_time(Duration::from_millis(creation_time_ms - 1));
    builder
        .with_instructions([Log::new(Level::INFO, label.to_owned())])
        .sign(signer.private_key())
}

/// Certify one block whose Network inputs carry exactly these synthetic results.
fn certify(
    fixture: &mut NativeFinalityFixture,
    results: Vec<TransactionResultInner>,
) -> VerifiedSumeragiBlock {
    let header = fixture.next_header();
    let mut builder = BlockBuilder::new(header);
    for index in 0..results.len() {
        builder.push_transaction(transaction(
            fixture.network_id(),
            header.creation_time_ms,
            &format!("compact inclusion {index}"),
        ));
    }
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, results);
    let proof = fixture.certify(block);
    fixture.verifier().verify_retained_decision(&proof).unwrap()
}

/// Verify the block's original certificate on a reader rooted only in signed genesis.
fn compact(
    fixture: &NativeFinalityFixture,
    block: &VerifiedSumeragiBlock,
) -> VerifiedSumeragiCommitV1 {
    SumeragiCommitVerifierV1::new(&root(fixture))
        .unwrap()
        .verify(&SumeragiCommitCertificateV1::from_verified(block).unwrap())
        .unwrap()
}

fn external(committed: &CommittedTransaction) -> SignedTransaction {
    let TransactionEntrypoint::External(signed) = &committed.entrypoint else {
        panic!("fixture inputs are external");
    };
    signed.clone()
}

fn inclusion(committed: &CommittedTransaction) -> CertifiedTransactionInclusionV1 {
    CertifiedTransactionInclusionV1 {
        entry_proof: committed.entrypoint_proof.clone(),
        output: committed.output.clone(),
        output_proof: committed.output_proof.clone(),
    }
}

#[test]
fn applied_and_rejected_network_outputs_verify_under_the_compact_certificate() {
    let mut fixture = NativeFinalityFixture::start("compact-inclusion");
    let block = certify(&mut fixture, vec![Ok(vec![]), rejected(), Ok(vec![])]);
    let certified = compact(&fixture, &block);
    for (index, applied) in [(0, true), (1, false), (2, true)] {
        let committed = output_test_support::committed(block.block(), index);
        let inclusion = inclusion(&committed);
        let result = certified
            .verify_external_execution(&fixture.network_id(), &external(&committed), &inclusion)
            .unwrap();
        assert_eq!(result.is_ok(), applied);
        assert_eq!(result, committed.result());
        assert_eq!(
            inclusion.joined_network_output().unwrap().input_index,
            index
        );
    }
}

#[test]
fn compact_inclusion_agrees_with_selective_full_block_verification() {
    let mut fixture = NativeFinalityFixture::start("compact-inclusion-equivalence");
    let block = certify(&mut fixture, vec![Ok(vec![]), rejected(), Ok(vec![])]);
    let certified = compact(&fixture, &block);
    let network = fixture.network_id();
    let header = block.header();
    let mut cases = Vec::new();
    for index in 0..3 {
        let committed = output_test_support::committed(block.block(), index);
        let other = output_test_support::committed(block.block(), (index + 1) % 3);
        cases.push(committed.clone());
        // The genuine entry path of another position.
        let mut changed = committed.clone();
        changed.entrypoint_proof = other.entrypoint_proof.clone();
        cases.push(changed);
        // Another position's complete row with its own genuine output path.
        let mut changed = committed.clone();
        changed.output = other.output.clone();
        changed.output_hash = other.output_hash;
        changed.output_proof = other.output_proof.clone();
        cases.push(changed);
        // A substituted, consistently hashed external entrypoint.
        let mut changed = committed.clone();
        changed.entrypoint = TransactionEntrypoint::External(transaction(
            network,
            header.creation_time_ms,
            "substituted entrypoint",
        ));
        changed.entrypoint_hash = changed.entrypoint.hash();
        cases.push(changed);
        // The opposite outcome in the same row, consistently rehashed.
        let mut changed = committed;
        let ExecutionOutputV1::Network(row) = &mut changed.output else {
            panic!("fixture output is a Network row");
        };
        row.result = if row.result.is_ok() {
            TransactionResult::new(rejected())
        } else {
            TransactionResult::new(Ok(vec![]))
        };
        changed.output_hash = HashOf::new(&changed.output);
        cases.push(changed);
    }
    let mut accepted = 0;
    for case in &cases {
        let full =
            case.verify_selective_in_authenticated_execution(&network, &header, block.execution());
        let membership = inclusion(case);
        let compact = certified.verify_external_execution(&network, &external(case), &membership);
        assert_eq!(full, compact.is_ok(), "membership verdicts agree");
        if let Ok(result) = compact {
            assert_eq!(result, case.result(), "certified results agree");
            accepted += 1;
        }
    }
    assert_eq!(accepted, 3, "only the three genuine positions verify");
}

#[test]
fn foreign_network_unjoined_internal_and_deep_inclusions_are_refused() {
    let mut fixture = NativeFinalityFixture::start("compact-inclusion-refusals");
    let block = certify(&mut fixture, vec![Ok(vec![]), rejected()]);
    let certified = compact(&fixture, &block);
    let network = fixture.network_id();
    let committed = output_test_support::committed(block.block(), 0);
    let other = output_test_support::committed(block.block(), 1);
    let signed = external(&committed);
    let genuine = inclusion(&committed);
    assert!(
        certified
            .verify_external_execution(&network, &signed, &genuine)
            .unwrap()
            .is_ok()
    );

    // The chain label is external to signed genesis, so changing that label alone
    // preserves NetworkId. Select a genuinely different signed genesis here.
    let foreign = NativeFinalityFixture::start_with_mode(
        "compact-inclusion-refusals",
        crate::parameter::system::SumeragiConsensusMode::Npos,
    )
    .network_id();
    assert_ne!(foreign, network);
    assert!(
        certified
            .verify_external_execution(&foreign, &signed, &genuine)
            .is_err()
    );
    // Input 0 signed for the other network: only the network differs.
    let foreign_signed = transaction(
        foreign,
        block.header().creation_time_ms,
        "compact inclusion 0",
    );
    assert!(
        certified
            .verify_external_execution(&network, &foreign_signed, &genuine)
            .is_err()
    );
    assert!(
        certified
            .verify_external_execution(&network, &external(&other), &genuine)
            .is_err(),
        "another signed input is not this entry's member"
    );

    let mut entry = genuine.clone();
    entry.entry_proof = other.entrypoint_proof.clone();
    assert!(entry.joined_network_output().is_err());
    assert!(
        certified
            .verify_external_execution(&network, &signed, &entry)
            .is_err()
    );
    let mut output_leaf = genuine.clone();
    output_leaf.output_proof = other.output_proof.clone();
    assert!(output_leaf.joined_network_output().is_err());
    assert!(
        certified
            .verify_external_execution(&network, &signed, &output_leaf)
            .is_err()
    );
    let mut swapped = genuine.clone();
    swapped.output = other.output.clone();
    assert!(
        certified
            .verify_external_execution(&network, &signed, &swapped)
            .is_err()
    );
    let mut internal = genuine.clone();
    internal.output = output_test_support::simple_time(block.block(), 0);
    assert!(internal.joined_network_output().is_err());
    assert!(
        certified
            .verify_external_execution(&network, &signed, &internal)
            .is_err()
    );
    let mut deep = genuine;
    deep.entry_proof = MerkleProof::from_audit_path(0, vec![None; 33]);
    assert!(
        certified
            .verify_external_execution(&network, &signed, &deep)
            .is_err()
    );
}
