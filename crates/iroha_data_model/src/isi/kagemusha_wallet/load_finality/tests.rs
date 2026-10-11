//! Native certificate and codec boundary tests. Fixture success rows are synthetic;
//! ledger balance transitions and ordinal compare-and-swap are tested by Core.
use super::*;
use crate::{
    block::{BlockSignatures, builder::BlockBuilder, consensus::SumeragiRootScope},
    isi::{InstructionBox, Log},
    level::Level,
    parameter::system::SumeragiConsensusMode,
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::{
        FeePaymentIntent, TransactionBuilder, TransactionResultInner,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use std::time::Duration;

type ReceiptMutation = Box<dyn Fn(&mut KagemushaWalletLoadReceiptV1)>;

fn payer() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn load() -> KagemushaWalletLedgerV1 {
    KagemushaWalletLedgerV1::new(
        [1; 32],
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: [2; 32],
            asset: [3; 32],
            ordinal: 7,
            request_id: [4; 32],
            amount: 123,
            charge: None,
        },
    )
}

fn certify(
    fixture: &mut NativeFinalityFixture,
    instruction: KagemushaWalletLedgerV1,
    result: TransactionResultInner,
) -> (VerifiedSumeragiBlock, CommittedTransaction) {
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let header = fixture.next_header();
    let mut transaction = TransactionBuilder::new(
        fixture.network_id(),
        payer(),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let instructions: Vec<InstructionBox> = vec![
        Log::new(Level::INFO, "before Load".into()).into(),
        instruction.into(),
    ];
    let transaction = transaction
        .with_instructions(instructions)
        .sign(signer.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction);
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![result]);
    let proof = fixture.certify(block);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    let committed = crate::block::output_test_support::committed(verified.block(), 0);
    (verified, committed)
}

fn verify(
    fixture: &NativeFinalityFixture,
    verified: &VerifiedSumeragiBlock,
    committed: &CommittedTransaction,
    expected: &KagemushaWalletLedgerV1,
) -> Result<VerifiedKagemushaWalletLoadV1, KagemushaWalletLoadFinalityErrorV1> {
    verify_finalized_kagemusha_wallet_load_v1(
        verified,
        committed,
        fixture.network_id(),
        fixture.chain_id(),
        1,
        expected,
        &payer(),
    )
}

fn certify_event(
    fixture: &mut NativeFinalityFixture,
) -> (
    VerifiedSumeragiBlock,
    CommittedTransaction,
    KagemushaWalletLoadReceiptV1,
    iroha_crypto::MerkleTree<EventBox>,
) {
    let expected = load();
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let header = fixture.next_header();
    let mut builder = TransactionBuilder::new(
        fixture.network_id(),
        payer(),
        FeePaymentIntent::authority(vec![], None),
    );
    builder.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let transaction = builder
        .with_instructions([expected.clone()])
        .sign(signer.private_key());
    let receipt = receipt_from_instruction(&expected, &transaction, header.height().get()).unwrap();
    let mut block_builder = BlockBuilder::new(header);
    block_builder.push_transaction(transaction);
    let mut block = block_builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![Ok(vec![])]);
    let events = [11, receipt.amount, 17].map(|amount| {
        let mut value = receipt;
        value.amount = amount;
        EventBox::Data(
            DataEvent::from(KagemushaLoadCommittedV1::from_receipt(&value).unwrap()).into(),
        )
    });
    let tree = events.iter().map(HashOf::new).collect();
    let proof = fixture.certify_with_events(block, &events);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    let committed = crate::block::output_test_support::committed(verified.block(), 0);
    (verified, committed, receipt, tree)
}

#[test]
fn native_event_inclusion_authenticates_the_same_receipt_as_full_transaction() {
    let mut fixture = NativeFinalityFixture::start("load-event-finality");
    let (verified, committed, receipt, tree) = certify_event(&mut fixture);
    let proof = tree.get_proof(1).unwrap();
    let event_capability = verify_finalized_kagemusha_wallet_load_event_v1(
        &verified,
        &proof,
        fixture.network_id(),
        fixture.chain_id(),
        &receipt,
    )
    .unwrap();
    let input_capability = verify_finalized_kagemusha_wallet_load_v1(
        &verified,
        &committed,
        fixture.network_id(),
        fixture.chain_id(),
        0,
        &load(),
        &payer(),
    )
    .unwrap();
    assert_eq!(event_capability.receipt(), input_capability.receipt());
    assert_eq!(event_capability.receipt(), &receipt);
    assert_eq!(event_capability.network(), fixture.network_id());
    assert_eq!(event_capability.block_hash(), verified.header().hash());
    assert_eq!(event_capability.height(), verified.height());
    assert_eq!(event_capability.event_index(), 1);
    assert_eq!(
        verified
            .execution()
            .event_commitment
            .unwrap()
            .leaf_count()
            .get(),
        3
    );
}

#[test]
fn direct_bls_load_evidence_binds_receipt_and_counted_event_without_prover() {
    use crate::{
        kagemusha::KagemushaWalletLoadFinalityV1,
        sumeragi_finality::{
            SumeragiCommitCertificateV1, SumeragiCommitVerifierV1, SumeragiFinalityVerifier,
        },
    };
    let mut fixture = NativeFinalityFixture::start("direct-load-finality");
    let selected = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap();
    let (block, _, receipt, events) = certify_event(&mut fixture);
    let evidence = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate: SumeragiCommitCertificateV1::from_verified(&block).unwrap(),
        event_proof: events.get_proof(1).unwrap(),
    };
    evidence.verify(&selected, &receipt).unwrap();
    let bytes = evidence.to_canonical_bytes().unwrap();
    KagemushaWalletLoadFinalityV1::decode_canonical(&bytes)
        .unwrap()
        .verify(&selected, &receipt)
        .unwrap();
    let mut cached = SumeragiCommitVerifierV1::new(&selected).unwrap();
    evidence.verify_with(&mut cached, &receipt).unwrap();
    assert!(
        bytes.len() < 16_384,
        "same-epoch native evidence must remain small"
    );

    let mut changed = receipt;
    changed.amount += 1;
    let mut substituted = evidence.clone();
    substituted.receipt_digest = changed.receipt_digest().unwrap();
    assert!(evidence.verify(&selected, &changed).is_err());
    assert!(substituted.verify(&selected, &changed).is_err());
    substituted = evidence.clone();
    substituted.event_proof = events.get_proof(0).unwrap();
    assert!(substituted.verify(&selected, &receipt).is_err());
    substituted = evidence.clone();
    substituted.certificate.commit_qc[0] ^= 1;
    assert!(substituted.verify(&selected, &receipt).is_err());
    changed = receipt;
    changed.block_height += 1;
    substituted = evidence.clone();
    substituted.receipt_digest = changed.receipt_digest().unwrap();
    assert!(substituted.verify(&selected, &changed).is_err());
}

#[test]
fn native_event_inclusion_rejects_every_substituted_receipt_term_and_bad_geometry() {
    let mut fixture = NativeFinalityFixture::start("load-event-negative");
    let (verified, _, receipt, tree) = certify_event(&mut fixture);
    let proof = tree.get_proof(1).unwrap();
    let check = |candidate: &KagemushaWalletLoadReceiptV1, proof: &MerkleProof<EventBox>| {
        verify_finalized_kagemusha_wallet_load_event_v1(
            &verified,
            proof,
            fixture.network_id(),
            fixture.chain_id(),
            candidate,
        )
    };
    let changes: Vec<ReceiptMutation> = vec![
        Box::new(|r| r.scheme_id[0] ^= 1),
        Box::new(|r| r.asset_digest[0] ^= 1),
        Box::new(|r| r.wallet_id[0] ^= 1),
        Box::new(|r| r.request_id[0] ^= 1),
        Box::new(|r| r.ordinal += 1),
        Box::new(|r| r.amount += 1),
        Box::new(|r| {
            r.online_charge = 1;
            r.charge_quote[0] = 1;
        }),
        Box::new(|r| r.transaction_hash[0] ^= 1),
        Box::new(|r| r.block_height += 1),
        Box::new(|r| r.payer_account_digest[0] ^= 1),
    ];
    for change in changes {
        let mut candidate = receipt;
        change(&mut candidate);
        assert!(check(&candidate, &proof).is_err());
    }
    assert!(check(&receipt, &tree.get_proof(0).unwrap()).is_err());
    assert!(
        check(
            &receipt,
            &MerkleProof::from_audit_path(3, proof.audit_path().to_vec())
        )
        .is_err()
    );
    assert!(
        check(
            &receipt,
            &MerkleProof::from_audit_path(1, proof.audit_path()[..1].to_vec())
        )
        .is_err()
    );
    let mut changed_path = proof.audit_path().to_vec();
    changed_path[0] = None;
    assert!(check(&receipt, &MerkleProof::from_audit_path(1, changed_path)).is_err());
    assert!(
        verify_finalized_kagemusha_wallet_load_event_v1(
            &verified,
            &proof,
            NativeFinalityFixture::start_with_mode(
                "load-event-negative",
                SumeragiConsensusMode::Npos
            )
            .network_id(),
            fixture.chain_id(),
            &receipt,
        )
        .is_err()
    );
    assert!(
        verify_finalized_kagemusha_wallet_load_event_v1(
            &verified,
            &proof,
            fixture.network_id(),
            "different-global-chain",
            &receipt,
        )
        .is_err()
    );
    let mut private = NativeFinalityFixture::start_with_scope(
        "private-load-event",
        SumeragiRootScope::Dataspace {
            parent_network_id: fixture.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(17),
        },
    );
    let (block, _, private_receipt, private_tree) = certify_event(&mut private);
    assert!(
        verify_finalized_kagemusha_wallet_load_event_v1(
            &block,
            &private_tree.get_proof(1).unwrap(),
            private.network_id(),
            private.chain_id(),
            &private_receipt,
        )
        .is_err()
    );
    let mut absent = NativeFinalityFixture::start("load-no-event");
    let (block, committed) = certify(&mut absent, load(), Ok(vec![]));
    let original = verify(&absent, &block, &committed, &load()).unwrap();
    assert!(block.execution().event_commitment.is_none());
    assert!(matches!(
        verify_finalized_kagemusha_wallet_load_event_v1(
            &block,
            &proof,
            absent.network_id(),
            absent.chain_id(),
            original.receipt(),
        ),
        Err(KagemushaWalletLoadFinalityErrorV1::WrongEvent)
    ));
}

#[test]
fn native_load_authenticates_exact_request_and_original_receipt() {
    let mut fixture = NativeFinalityFixture::start("load-finality");
    let expected = load();
    let (verified, committed) = certify(&mut fixture, expected.clone(), Ok(vec![]));
    let capability = verify(&fixture, &verified, &committed, &expected).unwrap();
    assert_eq!(capability.network(), fixture.network_id());
    assert_eq!(capability.payer(), &payer());
    assert_eq!(capability.instruction(), &expected);
    assert_eq!(capability.instruction_index(), 1);
    assert_eq!(capability.entrypoint_hash(), *committed.entrypoint_hash());
    assert_eq!(capability.block_hash(), *committed.block_hash());
    assert_eq!(capability.height(), 2);
    let receipt = capability.receipt();
    assert!(kagemusha_wallet_is_canonical_field_v1(
        &receipt.receipt_digest().unwrap()
    ));
    assert_eq!(receipt.version, 1);
    assert_eq!(receipt.scheme_id, [1; 32]);
    assert_eq!(receipt.wallet_id, [2; 32]);
    assert_eq!(receipt.asset_digest, [3; 32]);
    assert_eq!(receipt.request_id, [4; 32]);
    assert_eq!(receipt.ordinal, 7);
    assert_eq!(receipt.amount, 123);
    assert_eq!(receipt.online_charge, 0);
    assert_eq!(receipt.charge_quote, [0; 32]);
    assert_eq!(
        receipt.transaction_hash,
        *capability.transaction_hash().as_ref()
    );
    assert_eq!(receipt.block_height, capability.height());
    assert_eq!(
        receipt.payer_account_digest,
        kagemusha_wallet_account_digest_v1(capability.payer()).unwrap()
    );
    let bytes = receipt.to_canonical_bytes().unwrap();
    let decoded: KagemushaWalletLoadReceiptV1 =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap();
    assert_eq!(&decoded, receipt);
    assert_eq!(
        decoded.receipt_digest().unwrap(),
        receipt.receipt_digest().unwrap()
    );
    let json = norito::json::to_json(receipt).unwrap();
    assert_eq!(
        norito::json::from_str::<KagemushaWalletLoadReceiptV1>(&json).unwrap(),
        *receipt
    );
    let mut substituted = *receipt;
    substituted.request_id = [5; 32];
    assert_ne!(
        substituted.receipt_digest().unwrap(),
        receipt.receipt_digest().unwrap()
    );
}

#[test]
fn native_load_rejects_every_changed_request_term_and_wrong_instruction_index() {
    use KagemushaWalletLoadFinalityErrorV1 as Error;
    let mut fixture = NativeFinalityFixture::start("load-finality");
    let expected = load();
    let (verified, committed) = certify(&mut fixture, expected.clone(), Ok(vec![]));
    let mut changes = Vec::new();
    let mut candidate = expected.clone();
    candidate.scheme = [9; 32];
    changes.push(candidate);
    for field in 0..6 {
        let mut candidate = expected.clone();
        let KagemushaWalletLedgerActionV1::IssueLoad {
            wallet,
            asset,
            ordinal,
            request_id,
            amount,
            charge,
        } = &mut candidate.action
        else {
            unreachable!()
        };
        match field {
            0 => *wallet = [9; 32],
            1 => *asset = [9; 32],
            2 => *ordinal += 1,
            3 => *request_id = [9; 32],
            4 => *amount += 1,
            _ => {
                *charge = Some(super::super::KagemushaWalletLoadChargeV1 {
                    quote: vec![1],
                    beneficiary: payer(),
                })
            }
        }
        changes.push(candidate);
    }
    for candidate in changes {
        assert_eq!(
            verify(&fixture, &verified, &committed, &candidate).unwrap_err(),
            Error::WrongTerms
        );
    }
    for index in [0, 2, usize::MAX] {
        assert_eq!(
            verify_finalized_kagemusha_wallet_load_v1(
                &verified,
                &committed,
                fixture.network_id(),
                fixture.chain_id(),
                index,
                &expected,
                &payer()
            )
            .unwrap_err(),
            Error::WrongInstruction
        );
    }
    let other_payer = AccountId::new(
        KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert_eq!(
        verify_finalized_kagemusha_wallet_load_v1(
            &verified,
            &committed,
            fixture.network_id(),
            fixture.chain_id(),
            1,
            &expected,
            &other_payer
        )
        .unwrap_err(),
        Error::WrongPayer
    );
    let not_load = KagemushaWalletLedgerV1::new(
        [1; 32],
        KagemushaWalletLedgerActionV1::RetainRequest(vec![]),
    );
    assert_eq!(
        verify(&fixture, &verified, &committed, &not_load).unwrap_err(),
        Error::WrongInstruction
    );
}

#[test]
fn native_load_rejects_wrong_network_chain_private_root_and_substituted_inclusion() {
    let mut fixture = NativeFinalityFixture::start("load-finality");
    let expected = load();
    let (verified, committed) = certify(&mut fixture, expected.clone(), Ok(vec![]));
    let foreign =
        NativeFinalityFixture::start_with_mode("load-finality", SumeragiConsensusMode::Npos);
    assert!(
        verify_finalized_kagemusha_wallet_load_v1(
            &verified,
            &committed,
            foreign.network_id(),
            fixture.chain_id(),
            1,
            &expected,
            &payer()
        )
        .is_err()
    );
    assert!(
        verify_finalized_kagemusha_wallet_load_v1(
            &verified,
            &committed,
            fixture.network_id(),
            "another-chain",
            1,
            &expected,
            &payer()
        )
        .is_err()
    );
    let mut substituted = committed.clone();
    substituted.block_hash = HashOf::from_untyped_unchecked(Hash::new("different block"));
    assert!(verify(&fixture, &verified, &substituted, &expected).is_err());
    let mut private = NativeFinalityFixture::start_with_scope(
        "load-finality",
        SumeragiRootScope::Dataspace {
            parent_network_id: fixture.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(13),
        },
    );
    let (private_block, private_committed) = certify(&mut private, expected.clone(), Ok(vec![]));
    assert!(verify(&private, &private_block, &private_committed, &expected).is_err());
}

#[test]
fn native_load_rejects_failed_execution_and_malformed_success_terms() {
    use KagemushaWalletLoadFinalityErrorV1 as Error;
    let mut fixture = NativeFinalityFixture::start("load-finality");
    let expected = load();
    let (verified, committed) = certify(
        &mut fixture,
        expected.clone(),
        Err(TransactionRejectionReason::LimitCheck(
            TransactionLimitError {
                reason: "synthetic rejection".into(),
            },
        )),
    );
    assert!(matches!(
        verify(&fixture, &verified, &committed, &expected),
        Err(Error::Finality(_))
    ));
    let mut malformed = expected;
    let KagemushaWalletLedgerActionV1::IssueLoad { amount, .. } = &mut malformed.action else {
        unreachable!()
    };
    *amount = 0;
    let (verified, committed) = certify(&mut fixture, malformed.clone(), Ok(vec![]));
    assert!(matches!(
        verify(&fixture, &verified, &committed, &malformed),
        Err(Error::InvalidReceipt(_))
    ));
}

#[test]
fn receipt_shape_refuses_missing_terms_genesis_and_inconsistent_charges() {
    let good = KagemushaWalletLoadReceiptV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        wallet_id: [3; 32],
        request_id: [4; 32],
        ordinal: 0,
        amount: 1,
        online_charge: 0,
        charge_quote: [0; 32],
        transaction_hash: [5; 32],
        block_height: 2,
        payer_account_digest: kagemusha_wallet_account_digest_v1(&payer()).unwrap(),
    };
    good.validate().unwrap();
    for field in 0..12 {
        let mut invalid = good;
        match field {
            0 => invalid.version = 2,
            1 => invalid.scheme_id = [0; 32],
            2 => invalid.asset_digest = [0; 32],
            3 => invalid.wallet_id = [0; 32],
            4 => invalid.request_id = [0; 32],
            5 => invalid.transaction_hash = [0; 32],
            6 => invalid.amount = 0,
            7 => invalid.block_height = 1,
            8 => invalid.online_charge = 1,
            9 => invalid.charge_quote = [1; 32],
            10 => invalid.ordinal = u128::MAX,
            _ => invalid.payer_account_digest = [0; 32],
        }
        assert!(invalid.validate().is_err());
        assert!(invalid.to_canonical_bytes().is_err());
        assert!(invalid.receipt_digest().is_err());
    }
    let mut noncanonical = good;
    noncanonical.online_charge = 1;
    noncanonical.charge_quote = crate::kagemusha::KAGEMUSHA_WALLET_FIELD_MODULUS_V1;
    assert!(noncanonical.validate().is_err());
    let mut overflow = good;
    overflow.amount = u128::MAX;
    overflow.online_charge = 1;
    overflow.charge_quote = [1; 32];
    assert!(overflow.validate().is_err());
}

#[test]
fn charged_load_receipt_preserves_exact_canonical_quote_terms_and_beneficiary() {
    let fixtures: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let row = fixtures["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["type"].as_str() == Some("KagemushaWalletChargeQuoteV1")
                && row["variant"].as_str() == Some("Load")
        })
        .unwrap();
    let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    let quote: KagemushaWalletChargeQuoteV1 = norito::decode_from_bytes(&bytes).unwrap();
    let beneficiary = AccountId::new(
        KeyPair::from_seed(vec![0x5b; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let instruction = KagemushaWalletLedgerV1::new(
        quote.body.scheme_id,
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: quote.body.wallet_id,
            asset: quote.body.asset_digest,
            ordinal: quote.body.ordinal,
            request_id: [7; 32],
            amount: quote.body.net_amount,
            charge: Some(super::super::KagemushaWalletLoadChargeV1 {
                quote: bytes,
                beneficiary,
            }),
        },
    );
    let mut fixture = NativeFinalityFixture::start("charged-load-finality");
    let (verified, committed) = certify(&mut fixture, instruction.clone(), Ok(vec![]));
    let capability = verify(&fixture, &verified, &committed, &instruction).unwrap();
    assert_eq!(capability.receipt().online_charge, quote.body.online_charge);
    assert_eq!(
        capability.receipt().charge_quote,
        quote.charge_quote_digest()
    );
    let TransactionEntrypoint::External(transaction) = committed.entrypoint() else {
        unreachable!()
    };
    for field in 0..6 {
        let mut changed = instruction.clone();
        let KagemushaWalletLedgerActionV1::IssueLoad {
            wallet,
            asset,
            ordinal,
            amount,
            charge,
            ..
        } = &mut changed.action
        else {
            unreachable!()
        };
        match field {
            0 => *wallet = [9; 32],
            1 => *asset = [9; 32],
            2 => *ordinal += 1,
            3 => *amount += 1,
            4 => charge.as_mut().unwrap().beneficiary = payer(),
            _ => charge.as_mut().unwrap().quote.push(0),
        }
        assert!(receipt_from_instruction(&changed, transaction, 2).is_err());
    }
}

#[test]
fn receipt_and_load_json_reject_retired_or_missing_fields() {
    let receipt = KagemushaWalletLoadReceiptV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        wallet_id: [3; 32],
        request_id: [4; 32],
        ordinal: 0,
        amount: 1,
        online_charge: 0,
        charge_quote: [0; 32],
        transaction_hash: [5; 32],
        block_height: 2,
        payer_account_digest: kagemusha_wallet_account_digest_v1(&payer()).unwrap(),
    };
    let json = norito::json::to_json(&receipt).unwrap();
    let mut retired = json.clone();
    retired.insert_str(1, "\"authorizer_certificate\":null,");
    assert!(norito::json::from_str::<KagemushaWalletLoadReceiptV1>(&retired).is_err());
    let mut retired_payer = json.clone();
    retired_payer.insert_str(1, "\"payer\":null,");
    assert!(norito::json::from_str::<KagemushaWalletLoadReceiptV1>(&retired_payer).is_err());
    let json = norito::json::to_json(&load()).unwrap();
    for field in ["asset", "ordinal"] {
        let mut object: norito::json::Value = norito::json::from_str(&json).unwrap();
        object
            .get_mut("action")
            .unwrap()
            .get_mut("value")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        let missing = norito::json::to_json(&object).unwrap();
        assert!(norito::json::from_str::<KagemushaWalletLedgerV1>(&missing).is_err());
    }
    for kind in ["publish_voucher", "rotate_load_authorizer"] {
        let json = format!("{{\"kind\":\"{kind}\",\"value\":{{}}}}");
        assert!(norito::json::from_str::<KagemushaWalletLedgerActionV1>(&json).is_err());
    }
}

#[test]
fn registration_codec_has_no_online_authorizer_role() {
    let original = KagemushaWalletLedgerV1::new(
        [1; 32],
        KagemushaWalletLedgerActionV1::Register {
            scheme: vec![1],
            asset: vec![2],
            reserve: payer(),
            balance_scope: crate::asset::AssetBalanceScope::Global,
        },
    );
    let bytes = norito::to_bytes(&original).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<KagemushaWalletLedgerV1>(&bytes).unwrap(),
        original
    );
    let json = norito::json::to_json(&original).unwrap();
    assert_eq!(
        norito::json::from_str::<KagemushaWalletLedgerV1>(&json).unwrap(),
        original
    );
    let mut object: norito::json::Value = norito::json::from_str(&json).unwrap();
    object
        .get_mut("action")
        .unwrap()
        .get_mut("value")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("load_authorizer".into(), norito::json::Value::Array(vec![]));
    let retired = norito::json::to_json(&object).unwrap();
    assert!(norito::json::from_str::<KagemushaWalletLedgerV1>(&retired).is_err());
}
