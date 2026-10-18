//! Direct ledger-finality envelope tests on genuine native certificates.
//! Fixture results are synthetic; Native outcome custody is tested by the wallet owner.

use super::*;
use crate::{
    NetworkId,
    account::AccountId,
    block::{
        BlockSignatures, builder::BlockBuilder, execution_output::NetworkExecutionOutputV1,
        output_test_support,
    },
    isi::Log,
    level::Level,
    sumeragi_finality::{
        MAX_RESULT_PREIMAGE_BYTES, SumeragiFinalityVerifier, VerifiedSumeragiBlock,
        test_fixtures::NativeFinalityFixture,
    },
    transaction::{
        FeePaymentIntent, TransactionBuilder, TransactionResult, TransactionResultInner,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair, MerkleProof};
use iroha_sumeragi::message::Qc;
use std::time::Duration;

fn reader(fixture: &NativeFinalityFixture) -> SumeragiCommitVerifierV1 {
    let root = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap();
    SumeragiCommitVerifierV1::new(&root).unwrap()
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

/// Certify one block of two signed attempts: input 0 applied and input 1 rejected.
fn certify_attempts(fixture: &mut NativeFinalityFixture) -> VerifiedSumeragiBlock {
    let header = fixture.next_header();
    let mut builder = BlockBuilder::new(header);
    for label in ["applied attempt", "rejected attempt"] {
        builder.push_transaction(transaction(
            fixture.network_id(),
            header.creation_time_ms,
            label,
        ));
    }
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![Ok(vec![]), rejected()]);
    let proof = fixture.certify(block);
    fixture.verifier().verify_retained_decision(&proof).unwrap()
}

/// The envelope Torii serves for one Network input, and the signed wire the wallet retained.
fn attempt(
    block: &VerifiedSumeragiBlock,
    input_index: u32,
) -> (KagemushaWalletLedgerFinalityV1, SignedTransaction) {
    let committed = output_test_support::committed(block.block(), input_index);
    let TransactionEntrypoint::External(signed) = committed.entrypoint else {
        panic!("fixture inputs are external");
    };
    let envelope = KagemushaWalletLedgerFinalityV1 {
        version: 1,
        entrypoint_hash: committed.entrypoint_hash,
        certificate: SumeragiCommitCertificateV1::from_verified(block).unwrap(),
        inclusion: CertifiedTransactionInclusionV1 {
            entry_proof: committed.entrypoint_proof,
            output: committed.output,
            output_proof: committed.output_proof,
        },
    };
    (envelope, signed)
}

fn forge_aggregate_signature(envelope: &mut KagemushaWalletLedgerFinalityV1) {
    let mut qc: Qc = norito::decode_canonical(&envelope.certificate.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    envelope.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
}

/// A complete rejected Network row whose standalone canonical frame is exactly `frame` bytes.
fn network_row_of_frame_len(frame: usize) -> ExecutionOutputV1 {
    let row = |reason: usize| {
        ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result: TransactionResult::new(Err(TransactionRejectionReason::LimitCheck(
                TransactionLimitError {
                    reason: "r".repeat(reason),
                },
            ))),
            completions: Vec::new(),
        })
    };
    let mut reason = frame;
    for _ in 0..8 {
        let actual = norito::canonical_frame_len(&row(reason)).unwrap();
        if actual == frame {
            return row(reason);
        }
        reason = (reason + frame).checked_sub(actual).unwrap();
    }
    panic!("no Network row of exactly {frame} canonical bytes");
}

#[test]
fn applied_and_rejected_attempts_verify_on_a_private_reader() {
    let mut fixture = NativeFinalityFixture::start("ledger-finality");
    let block = certify_attempts(&mut fixture);
    let selected = reader(&fixture);
    for (index, accepted) in [(0, true), (1, false)] {
        let (envelope, signed) = attempt(&block, index);
        let bytes = envelope.to_canonical_bytes().unwrap();
        assert!(bytes.len() <= KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1);
        let decoded = KagemushaWalletLedgerFinalityV1::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.to_canonical_bytes().unwrap(), bytes);
        // The frame's header padding is zero on every target; an alternate spelling is refused.
        let header = norito::core::Header::SIZE;
        let mut padded = bytes;
        drop(padded.splice(header..header, [0; 8]));
        assert!(KagemushaWalletLedgerFinalityV1::decode_canonical(&padded).is_err());
        assert_eq!(decoded.selectors().unwrap(), (0, block.height()));
        let outcome = decoded
            .verify(&selected, fixture.chain_id(), &signed)
            .unwrap();
        assert_eq!(outcome.entrypoint(), *signed.hash_as_entrypoint().as_ref());
        assert_eq!(outcome.height(), block.height());
        assert_eq!(outcome.commit_hash(), block.core_hash().0);
        assert_eq!(outcome.accepted(), accepted);
        // An exact retry is the same authenticated outcome.
        assert_eq!(
            decoded
                .verify(&selected, fixture.chain_id(), &signed)
                .unwrap(),
            outcome
        );
    }
}

#[test]
fn forged_foreign_substituted_and_unjoined_envelopes_are_refused() {
    let mut fixture = NativeFinalityFixture::start("ledger-finality-refusals");
    let block = certify_attempts(&mut fixture);
    let selected = reader(&fixture);
    let chain = fixture.chain_id();
    let (genuine, signed) = attempt(&block, 0);
    let (other, other_signed) = attempt(&block, 1);
    assert!(
        genuine
            .verify(&selected, chain, &signed)
            .unwrap()
            .accepted()
    );

    let mut forged = genuine.clone();
    forge_aggregate_signature(&mut forged);
    assert!(forged.verify(&selected, chain, &signed).is_err());

    let other_instance = NativeFinalityFixture::start("ledger-finality-foreign");
    assert!(
        genuine
            .verify(&reader(&other_instance), chain, &signed)
            .is_err(),
        "another native instance"
    );
    // The chain label is external to signed genesis, so changing that label alone
    // preserves NetworkId. Select a genuinely different signed genesis here.
    let foreign = NativeFinalityFixture::start_with_mode(
        chain,
        crate::parameter::system::SumeragiConsensusMode::Npos,
    );
    assert_ne!(foreign.network_id(), fixture.network_id());
    assert!(
        genuine.verify(&reader(&foreign), chain, &signed).is_err(),
        "another signed genesis"
    );
    assert!(genuine.verify(&selected, "foreign-chain", &signed).is_err());
    // Input 0 signed for the other network: only the network differs.
    let foreign_signed = transaction(
        foreign.network_id(),
        block.header().creation_time_ms,
        "applied attempt",
    );
    let mut foreign_network = genuine.clone();
    foreign_network.entrypoint_hash = foreign_signed.hash_as_entrypoint();
    assert_ne!(foreign_network.entrypoint_hash, genuine.entrypoint_hash);
    assert!(
        foreign_network
            .verify(&selected, chain, &foreign_signed)
            .is_err()
    );

    assert!(
        genuine.verify(&selected, chain, &other_signed).is_err(),
        "the wallet recomputes the entrypoint from its own wire"
    );
    let mut substituted = genuine.clone();
    substituted.entrypoint_hash = other.entrypoint_hash;
    assert!(substituted.verify(&selected, chain, &other_signed).is_err());

    let mut entry = genuine.clone();
    entry.inclusion.entry_proof = other.inclusion.entry_proof.clone();
    assert!(entry.verify(&selected, chain, &signed).is_err());
    let mut output_leaf = genuine.clone();
    output_leaf.inclusion.output_proof = other.inclusion.output_proof.clone();
    assert!(output_leaf.verify(&selected, chain, &signed).is_err());
    let mut swapped = genuine.clone();
    swapped.inclusion.output = other.inclusion.output.clone();
    swapped.inclusion.output_proof = other.inclusion.output_proof.clone();
    assert!(swapped.verify(&selected, chain, &signed).is_err());
    let mut flipped = genuine.clone();
    let ExecutionOutputV1::Network(row) = &mut flipped.inclusion.output else {
        panic!("fixture output is a Network row");
    };
    row.result = TransactionResult::new(rejected());
    assert!(!flipped.custody_bindings().unwrap().accepted);
    assert!(
        flipped.verify(&selected, chain, &signed).is_err(),
        "a projected outcome is DATA until its row is certified"
    );

    let mut internal = genuine.clone();
    internal.inclusion.output = output_test_support::simple_time(block.block(), 0);
    let mut deep_entry = genuine.clone();
    deep_entry.inclusion.entry_proof = MerkleProof::from_audit_path(0, vec![None; 33]);
    let mut deep_output = genuine.clone();
    deep_output.inclusion.output_proof = MerkleProof::from_audit_path(0, vec![None; 33]);
    let mut version = genuine.clone();
    version.version = 2;
    for invalid in [internal, deep_entry, deep_output, version] {
        assert!(invalid.validate().is_err());
        assert!(invalid.to_canonical_bytes().is_err());
        assert!(
            KagemushaWalletLedgerFinalityV1::decode_canonical(
                &norito::encode_canonical(&invalid).unwrap()
            )
            .is_err()
        );
        assert!(invalid.verify(&selected, chain, &signed).is_err());
    }

    let bytes = genuine.to_canonical_bytes().unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(KagemushaWalletLedgerFinalityV1::decode_canonical(&trailing).is_err());
    assert!(KagemushaWalletLedgerFinalityV1::decode_canonical(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn verify_never_trusts_a_boundary_successor_carried_by_the_certificate() {
    let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let mut selected = reader(&fixture);
    let boundary = fixture
        .verifier()
        .verify_retained_decision(&chain[2])
        .unwrap();
    let successor = fixture
        .verifier()
        .verify_retained_decision(&chain[3])
        .unwrap();
    let (boundary_envelope, boundary_signed) = attempt(&boundary, 0);
    let (successor_envelope, successor_signed) = attempt(&successor, 0);
    assert_eq!(boundary_envelope.selectors().unwrap(), (0, 3));
    assert_eq!(successor_envelope.selectors().unwrap(), (1, 4));

    let outcome = boundary_envelope
        .verify(&selected, fixture.chain_id(), &boundary_signed)
        .unwrap();
    assert!(outcome.accepted());
    assert_eq!(outcome.height(), 3);
    // The boundary's certified successor epoch was installed only in the discarded clone.
    assert!(
        successor_envelope
            .verify(&selected, fixture.chain_id(), &successor_signed)
            .is_err()
    );
    assert!(
        selected
            .clone()
            .verify(&successor_envelope.certificate)
            .is_err()
    );

    // Only separately selected epoch synchronization advances the reader.
    selected
        .verify_epoch_boundary(&boundary_envelope.certificate)
        .unwrap();
    let outcome = successor_envelope
        .verify(&selected, fixture.chain_id(), &successor_signed)
        .unwrap();
    assert!(outcome.accepted());
    assert_eq!(outcome.height(), 4);
}

#[test]
fn ledger_finality_bound_is_derived_from_consensus_limits() {
    let row = usize::try_from(ExecutionOutputPolicyV1::bootstrap().max_output_bytes).unwrap();
    assert_eq!(row, 1_048_576);
    assert_eq!(KAGEMUSHA_WALLET_LEDGER_OUTPUT_MAX_BYTES_V1, row);
    assert_eq!(KAGEMUSHA_WALLET_LEDGER_FINALITY_FRAMING_BYTES_V1, 16_384);
    assert_eq!(
        KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
        MAX_COMMIT_CERTIFICATE_BYTES_V1 + row + 16_384
    );
    assert_eq!(KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1, 1_327_104);
}

#[test]
fn maximum_output_row_round_trips_under_the_derived_bound() {
    let mut fixture = NativeFinalityFixture::start("ledger-finality-maximum");
    let block = certify_attempts(&mut fixture);
    let (genuine, _) = attempt(&block, 0);
    let row = network_row_of_frame_len(KAGEMUSHA_WALLET_LEDGER_OUTPUT_MAX_BYTES_V1);
    assert_eq!(
        norito::canonical_frame_len(&row).unwrap(),
        KAGEMUSHA_WALLET_LEDGER_OUTPUT_MAX_BYTES_V1
    );
    // Every certificate component and both audit paths at their own limits.
    let maximum = KagemushaWalletLedgerFinalityV1 {
        version: 1,
        entrypoint_hash: genuine.entrypoint_hash,
        certificate: SumeragiCommitCertificateV1 {
            consensus_header: vec![1; 64 * 1024],
            commit_qc: vec![2; 4 * 1024],
            result_preimage: vec![3; MAX_RESULT_PREIMAGE_BYTES],
        },
        inclusion: CertifiedTransactionInclusionV1 {
            entry_proof: MerkleProof::from_audit_path(
                u32::MAX,
                vec![Some(HashOf::from_untyped_unchecked(Hash::new(b"entry"))); 32],
            ),
            output: row,
            output_proof: MerkleProof::from_audit_path(
                u32::MAX,
                vec![Some(HashOf::from_untyped_unchecked(Hash::new(b"output"))); 32],
            ),
        },
    };
    let bytes = maximum.to_canonical_bytes().unwrap();
    assert!(bytes.len() > KAGEMUSHA_WALLET_LEDGER_OUTPUT_MAX_BYTES_V1);
    assert!(bytes.len() <= KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletLedgerFinalityV1::decode_canonical(&bytes).unwrap(),
        maximum
    );

    let mut oversized = maximum;
    oversized.inclusion.output =
        network_row_of_frame_len(KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1);
    assert!(matches!(
        oversized.validate(),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    assert!(oversized.to_canonical_bytes().is_err());
    let raw = norito::encode_canonical(&oversized).unwrap();
    assert!(raw.len() > KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1);
    assert!(KagemushaWalletLedgerFinalityV1::decode_canonical(&raw).is_err());
}

#[test]
fn custody_bindings_decode_retained_originals_without_bls() {
    let mut fixture = NativeFinalityFixture::start("ledger-finality-custody");
    let block = certify_attempts(&mut fixture);
    let selected = reader(&fixture);
    for (index, accepted) in [(0, true), (1, false)] {
        let (envelope, signed) = attempt(&block, index);
        let outcome = envelope
            .verify(&selected, fixture.chain_id(), &signed)
            .unwrap();
        let expected = LedgerFinalityBindingsV1 {
            height: outcome.height(),
            qc_block_hash: outcome.commit_hash(),
            accepted,
            input_index: index,
        };
        assert_eq!(envelope.custody_bindings().unwrap(), expected);

        let mut forged = envelope.clone();
        forge_aggregate_signature(&mut forged);
        assert_eq!(
            forged.custody_bindings().unwrap(),
            expected,
            "the projection verifies no signature"
        );
        assert!(
            forged
                .verify(&selected, fixture.chain_id(), &signed)
                .is_err()
        );

        let mut unjoined = envelope.clone();
        unjoined.inclusion.output_proof = MerkleProof::from_audit_path(
            index + 1,
            unjoined.inclusion.output_proof.audit_path().to_vec(),
        );
        assert!(unjoined.custody_bindings().is_err());
        let mut internal = envelope.clone();
        internal.inclusion.output = output_test_support::simple_time(block.block(), 0);
        assert!(internal.custody_bindings().is_err());
        let mut malformed = envelope;
        malformed.certificate.commit_qc.push(0);
        assert!(malformed.custody_bindings().is_err());
    }
}

#[test]
fn reference_schema_matches_ledger_finality() {
    let generated = norito::json::to_value(&KagemushaWalletLedgerFinalityV1::schema()).unwrap();
    let names = [
        KagemushaWalletLedgerFinalityV1::type_name(),
        CertifiedTransactionInclusionV1::type_name(),
        SumeragiCommitCertificateV1::type_name(),
        HashOf::<TransactionEntrypoint>::type_name(),
        MerkleProof::<TransactionEntrypoint>::type_name(),
        MerkleProof::<ExecutionOutputV1>::type_name(),
    ];
    let path =
        crate::kagemusha::kagemusha_wallet_v1::test_fixture_path("specs/references/schema.json");
    let mut saved: norito::json::Value =
        norito::json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    if std::env::var_os("IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS").is_some_and(|value| value == "1") {
        let entries = saved.as_object_mut().unwrap();
        for name in &names {
            entries.insert(
                name.clone(),
                generated
                    .get(name.as_str())
                    .expect("canonical schema entry")
                    .clone(),
            );
        }
        let mut json = norito::json::to_string_pretty(&saved).unwrap();
        json.push('\n');
        std::fs::write(&path, json).unwrap();
    }
    for name in names {
        assert_eq!(
            saved.get(name.as_str()),
            generated.get(name.as_str()),
            "ledger finality schema descriptor {name}"
        );
    }
}
