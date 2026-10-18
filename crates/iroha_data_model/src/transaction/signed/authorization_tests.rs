//! Authorization-envelope and multisignature transaction tests.

use super::{
    Executable, FeePaymentIntent, MultisigSignature, MultisigSignatures, SignedTransaction,
    TransactionBuilder, TransactionDomain, TransactionSignature, TransactionSignatureError, model,
    test_network_id,
};
use crate::{
    Level,
    account::{AccountId, MultisigMember, MultisigPolicy},
    prelude::Log,
};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, SignatureOf};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_primitives::const_vec::ConstVec;

fn checked_transaction_payload_signature(
    private_key: &PrivateKey,
    payload: &model::TransactionPayload,
) -> SignatureOf<model::TransactionPayload> {
    SignatureOf::try_new(private_key, payload).expect("checked transaction fixture signature")
}

fn checked_random_keypair() -> KeyPair {
    KeyPair::try_random().expect("test fixture random key generation should succeed")
}

fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|error| {
        panic!("{algorithm:?} transaction fixture key generation should succeed: {error}")
    })
}

fn sample_signed_transaction() -> SignedTransaction {
    let keypair = checked_random_keypair();
    TransactionBuilder::new(
        test_network_id(0x2E),
        AccountId::new(keypair.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "authorization envelope".into())])
    .sign(keypair.private_key())
}

fn empty_multisig_payload(network: u8, policy: MultisigPolicy) -> model::TransactionPayload {
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    model::TransactionPayload {
        domain: TransactionDomain::Network(test_network_id(network)),
        authority: AccountId::new_multisig(policy),
        creation_time_ms: 0,
        instructions: Executable::Instructions(ConstVec::from(Vec::new())),
        time_to_live_ms: None,
        nonce: None,
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),

        metadata: Metadata::default(),
        attachments: None,
    }
}

#[test]
fn verify_signature_rejects_missing_multisig_signatures() {
    let signer = checked_random_keypair();
    let member =
        MultisigMember::new(signer.public_key().clone(), 1).expect("multisig member valid");
    let policy = MultisigPolicy::new(1, vec![member]).expect("multisig policy valid");
    let payload = empty_multisig_payload(0x20, policy);
    let signature = TransactionSignature(checked_transaction_payload_signature(
        signer.private_key(),
        &payload,
    ));
    let tx = SignedTransaction {
        signature,
        payload,
        multisig_signatures: None,
        entrypoint_hash: Default::default(),
    };
    let err = tx
        .verify_signature()
        .expect_err("multisig must be rejected");
    assert!(
        matches!(err, TransactionSignatureError::MissingMultisigSignatures),
        "expected MissingMultisigSignatures, got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "missing multisig signatures for multisig authority",
        "expected stable multisig missing-signatures reason"
    );
}
#[test]
fn verify_signature_accepts_multisig_with_quorum() {
    let signer = checked_random_keypair();
    let member =
        MultisigMember::new(signer.public_key().clone(), 2).expect("multisig member valid");
    let policy = MultisigPolicy::new(2, vec![member]).expect("multisig policy valid");
    let payload = empty_multisig_payload(0x21, policy);
    let member_sig = checked_transaction_payload_signature(signer.private_key(), &payload);
    let signature = TransactionSignature(member_sig.clone());
    let multisig_signatures = MultisigSignatures::new(vec![MultisigSignature::new(
        signer.public_key().clone(),
        member_sig,
    )]);
    let tx = SignedTransaction {
        signature,
        payload,
        multisig_signatures: Some(multisig_signatures),
        entrypoint_hash: Default::default(),
    };
    tx.verify_signature()
        .expect("multisig with quorum must verify");
    let mut noncanonical = tx;
    let unrelated = checked_random_keypair();
    noncanonical.signature = TransactionSignature(checked_transaction_payload_signature(
        unrelated.private_key(),
        noncanonical.payload(),
    ));
    assert_eq!(
        noncanonical
            .verify_signature()
            .expect_err("the primary signature must duplicate the first canonical bundle item"),
        TransactionSignatureError::NonCanonicalMultisigSignatures
    );
}

#[test]
fn signed_transaction_json_rejects_unknown_authorization_envelope_fields() {
    let mut single = norito::json::to_value(&sample_signed_transaction())
        .expect("serialize signed transaction JSON");
    single
        .as_object_mut()
        .expect("signed transaction envelope")
        .insert("legacy".to_owned(), norito::json::Value::Null);
    assert!(
        norito::json::from_value::<SignedTransaction>(single).is_err(),
        "unknown signed-transaction field must fail closed"
    );

    let signer = checked_random_keypair();
    let member =
        MultisigMember::new(signer.public_key().clone(), 1).expect("multisig member valid");
    let policy = MultisigPolicy::new(1, vec![member]).expect("multisig policy valid");
    let payload = empty_multisig_payload(0x2F, policy);
    let member_signature = checked_transaction_payload_signature(signer.private_key(), &payload);
    let transaction = SignedTransaction {
        signature: TransactionSignature(member_signature.clone()),
        payload,
        multisig_signatures: Some(MultisigSignatures::new(vec![MultisigSignature::new(
            signer.public_key().clone(),
            member_signature,
        )])),
        entrypoint_hash: Default::default(),
    };
    let canonical =
        norito::json::to_value(&transaction).expect("serialize multisig transaction JSON");

    let mut bundle = canonical.clone();
    bundle
        .get_mut("multisig_signatures")
        .and_then(norito::json::Value::as_object_mut)
        .expect("multisig bundle envelope")
        .insert("legacy".to_owned(), norito::json::Value::Null);
    assert!(
        norito::json::from_value::<SignedTransaction>(bundle).is_err(),
        "unknown multisig bundle field must fail closed"
    );

    let mut entry = canonical;
    entry
        .get_mut("multisig_signatures")
        .and_then(|bundle| bundle.get_mut("signatures"))
        .and_then(norito::json::Value::as_array_mut)
        .and_then(|signatures| signatures.first_mut())
        .and_then(norito::json::Value::as_object_mut)
        .expect("multisig signature envelope")
        .insert("legacy".to_owned(), norito::json::Value::Null);
    assert!(
        norito::json::from_value::<SignedTransaction>(entry).is_err(),
        "unknown multisig signature field must fail closed"
    );
}
#[test]
fn verify_signature_rejects_multisig_bundle_for_single_controller() {
    let chain = test_network_id(0x22);
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let keypair = checked_random_keypair();
    let authority = AccountId::new(keypair.public_key().clone());
    let mut tx = TransactionBuilder::new(
        chain,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "single authority".into())])
    .sign(keypair.private_key());
    // A proof bundle for a different controller shape must not create an
    // alternate accepted envelope for the same signed intent.
    let payload = tx.payload().clone();
    let extraneous_signer = checked_random_keypair();
    let stray_signature =
        checked_transaction_payload_signature(extraneous_signer.private_key(), &payload);
    tx.set_multisig_signatures(MultisigSignatures::new(vec![MultisigSignature::new(
        extraneous_signer.public_key().clone(),
        stray_signature,
    )]));
    assert_eq!(
        tx.signature_count(),
        1,
        "single controller counts only its own signature"
    );
    assert_eq!(
        tx.verify_signature()
            .expect_err("single authority must reject multisig proof data"),
        TransactionSignatureError::UnexpectedMultisigSignatures
    );
}
#[test]
fn transaction_builder_try_sign_multisig_rejects_empty_signers() {
    let chain = test_network_id(0x23);
    let signer = checked_random_keypair();
    let member =
        MultisigMember::new(signer.public_key().clone(), 1).expect("multisig member valid");
    let policy = MultisigPolicy::new(1, vec![member]).expect("multisig policy valid");
    let authority = AccountId::new_multisig(policy);
    let builder = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "empty multisig".into())]);
    let err = builder
        .try_sign_multisig(core::iter::empty::<&iroha_crypto::PrivateKey>())
        .expect_err("empty signer set must be rejected");
    assert!(matches!(err, TransactionSignatureError::NoSignatures));
}
#[test]
fn verify_signature_rejects_empty_multisig_bundle() {
    let signer = checked_random_keypair();
    let member =
        MultisigMember::new(signer.public_key().clone(), 1).expect("multisig member valid");
    let policy = MultisigPolicy::new(1, vec![member]).expect("multisig policy valid");
    let payload = empty_multisig_payload(0x24, policy);
    let signature = TransactionSignature(checked_transaction_payload_signature(
        signer.private_key(),
        &payload,
    ));
    let tx = SignedTransaction {
        signature,
        payload,
        multisig_signatures: Some(MultisigSignatures::new(Vec::new())),
        entrypoint_hash: Default::default(),
    };
    let err = tx
        .verify_signature()
        .expect_err("empty multisig bundle must fail");
    assert!(
        matches!(err, TransactionSignatureError::NoSignatures),
        "expected NoSignatures, got {err:?}"
    );
}
#[test]
fn verify_signature_rejects_unknown_signer() {
    let member_key = checked_random_keypair();
    let unknown_key = checked_random_keypair();
    let member =
        MultisigMember::new(member_key.public_key().clone(), 1).expect("multisig member valid");
    let policy = MultisigPolicy::new(1, vec![member]).expect("multisig policy valid");
    let payload = empty_multisig_payload(0x25, policy);
    let unknown_signature =
        checked_transaction_payload_signature(unknown_key.private_key(), &payload);
    let signature = TransactionSignature(unknown_signature.clone());
    let multisig_signatures = MultisigSignatures::new(vec![MultisigSignature::new(
        unknown_key.public_key().clone(),
        unknown_signature,
    )]);
    let tx = SignedTransaction {
        signature,
        payload,
        multisig_signatures: Some(multisig_signatures),
        entrypoint_hash: Default::default(),
    };
    let err = tx
        .verify_signature()
        .expect_err("unknown signer must be rejected");
    assert!(
        matches!(err, TransactionSignatureError::UnknownMultisigSigner),
        "expected UnknownMultisigSigner, got {err:?}"
    );
}
#[test]
fn verify_signature_does_not_double_count_duplicates() {
    let signer = checked_random_keypair();
    let other = checked_random_keypair();
    let members = vec![
        MultisigMember::new(signer.public_key().clone(), 1).expect("multisig member valid"),
        MultisigMember::new(other.public_key().clone(), 1).expect("multisig member valid"),
    ];
    let policy = MultisigPolicy::new(2, members).expect("multisig policy valid");
    let payload = empty_multisig_payload(0x26, policy);
    let signature = TransactionSignature(checked_transaction_payload_signature(
        signer.private_key(),
        &payload,
    ));
    let duplicate_signature = checked_transaction_payload_signature(signer.private_key(), &payload);
    let multisig_signatures = MultisigSignatures::new(vec![
        MultisigSignature::new(signer.public_key().clone(), duplicate_signature.clone()),
        MultisigSignature::new(signer.public_key().clone(), duplicate_signature),
    ]);
    let tx = SignedTransaction {
        signature,
        payload,
        multisig_signatures: Some(multisig_signatures),
        entrypoint_hash: Default::default(),
    };
    assert_eq!(
        tx.verify_signature()
            .expect_err("duplicate signatures are a non-canonical proof"),
        TransactionSignatureError::NonCanonicalMultisigSignatures
    );
}
#[test]
fn verify_signature_accepts_mixed_algorithms() {
    let chain = test_network_id(0x27);
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let ed = checked_random_keypair();
    let secp = checked_random_keypair_with_algorithm(Algorithm::Secp256k1);
    let members = vec![
        MultisigMember::new(ed.public_key().clone(), 1).expect("member"),
        MultisigMember::new(secp.public_key().clone(), 1).expect("member"),
    ];
    let policy = MultisigPolicy::new(2, members).expect("policy");
    let authority = AccountId::new_multisig(policy);
    let tx = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign_multisig(vec![ed.private_key(), secp.private_key()]);
    assert_eq!(tx.signature_count(), 2);
    tx.verify_signature()
        .expect("mixed-algorithm multisig should verify");
}
#[test]
fn signature_count_tracks_all_multisig_entries() {
    let signer = checked_random_keypair();
    let member =
        MultisigMember::new(signer.public_key().clone(), 1).expect("multisig member valid");
    let policy = MultisigPolicy::new(1, vec![member]).expect("multisig policy valid");
    let payload = empty_multisig_payload(0x28, policy);
    let signature = checked_transaction_payload_signature(signer.private_key(), &payload);
    let multisig_signatures = MultisigSignatures::new(vec![
        MultisigSignature::new(signer.public_key().clone(), signature.clone()),
        MultisigSignature::new(signer.public_key().clone(), signature.clone()),
        MultisigSignature::new(signer.public_key().clone(), signature.clone()),
    ]);
    let tx = SignedTransaction {
        signature: TransactionSignature(signature),
        payload,
        multisig_signatures: Some(multisig_signatures),
        entrypoint_hash: Default::default(),
    };
    assert_eq!(tx.signature_count(), 3);
    assert_eq!(
        tx.verify_signature()
            .expect_err("duplicate multisig entries must fail closed"),
        TransactionSignatureError::NonCanonicalMultisigSignatures
    );
}

#[test]
fn signed_transaction_verification_borrows_original_signature_under_decode_refusal() {
    for algorithm in [Algorithm::Ed25519, Algorithm::MlDsa] {
        let signer = checked_random_keypair_with_algorithm(algorithm);
        let other = checked_random_keypair_with_algorithm(algorithm);
        let transaction = TransactionBuilder::new(
            test_network_id(0x69),
            AccountId::new(signer.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "original signature".into())])
        .sign(signer.private_key());
        let mut forged = transaction.clone();
        forged.signature = TransactionSignature(checked_transaction_payload_signature(
            other.private_key(),
            forged.payload(),
        ));
        let original_signature = transaction.signature.0.payload().to_vec();
        transaction.verify_signature().unwrap();
        assert!(forged.verify_signature().is_err());
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        norito::with_decode_limits_scope(limits, || {
            transaction
                .verify_signature()
                .expect("borrowed valid relation");
            assert!(
                forged.verify_signature().is_err(),
                "forged relation remains rejected"
            );
        });
        assert_eq!(transaction.signature.0.payload(), original_signature);
        transaction.verify_signature().unwrap();
    }
}
