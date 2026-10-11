//! Codec/selection tests use a maintained unsigned receipt original and explicit proof DATA.
//! No signed corpus is generated, no proof is accepted, and no wallet is constructed.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::AccountId;

fn originals() -> (KagemushaWalletLoadReceiptV1, Vec<u8>, Vec<u8>, String) {
    let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let receipt_original = vectors["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some("KagemushaWalletLoadReceiptV1"))
        .map(|row| hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap())
        .unwrap();
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_original).unwrap();
    // Exact existing vectors_tests::BENEFICIARY_SEED account; this does not sign anything.
    let payer = AccountId::new(
        KeyPair::from_seed(vec![0x5b; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert_eq!(
        receipt.payer_account_digest,
        kagemusha_wallet_account_digest_v1(&payer).unwrap()
    );
    let event = iroha_data_model::events::EventBox::Data(
        iroha_data_model::events::data::DataEvent::KagemushaLoadCommitted(
            iroha_data_model::events::data::kagemusha::KagemushaLoadCommittedV1::from_receipt(
                &receipt,
            )
            .unwrap(),
        )
        .into(),
    );
    let finality = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        // Deliberately invalid certificate: decoding confers no finality authority.
        certificate: iroha_data_model::sumeragi_finality::SumeragiCommitCertificateV1 {
            consensus_header: vec![1],
            commit_qc: vec![2],
            result_preimage: vec![3],
        },
        event_proof: [iroha_crypto::HashOf::new(&event)]
            .into_iter()
            .collect::<iroha_crypto::MerkleTree<iroha_data_model::events::EventBox>>()
            .get_proof(0)
            .unwrap(),
    }
    .to_canonical_bytes()
    .unwrap();
    (
        receipt,
        receipt_original,
        finality,
        payer.canonical_i105().unwrap(),
    )
}

#[test]
fn exact_originals_decode_without_authenticating_the_explicit_nonproof_data() {
    let (receipt, original, finality, payer) = originals();
    let before = (original.clone(), finality.clone());
    let height = validate(
        &receipt.scheme_id,
        &receipt.wallet_id,
        &receipt.request_id,
        payer.as_bytes(),
        &original,
        &finality,
    )
    .unwrap();
    assert_eq!(height, receipt.block_height);
    assert_eq!((original, finality), before);
}

#[test]
fn each_independent_authenticated_read_identity_is_required() {
    let (receipt, original, finality, payer) = originals();
    let identities = [receipt.scheme_id, receipt.wallet_id, receipt.request_id];
    for index in 0..3 {
        let mut wrong = identities;
        wrong[index][0] ^= 1;
        assert!(
            validate(
                &wrong[0],
                &wrong[1],
                &wrong[2],
                payer.as_bytes(),
                &original,
                &finality
            )
            .is_err()
        );
        wrong[index] = [0; 32];
        assert!(
            validate(
                &wrong[0],
                &wrong[1],
                &wrong[2],
                payer.as_bytes(),
                &original,
                &finality
            )
            .is_err()
        );
    }
    let other = AccountId::new(
        KeyPair::from_seed(vec![0x5c; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert!(
        validate(
            &identities[0],
            &identities[1],
            &identities[2],
            other.canonical_i105().unwrap().as_bytes(),
            &original,
            &finality
        )
        .is_err()
    );
}

#[test]
fn another_receipt_finality_digest_or_trailing_original_is_refused() {
    let (receipt, original, finality, payer) = originals();
    let check = |first: &[u8], second: &[u8]| {
        validate(
            &receipt.scheme_id,
            &receipt.wallet_id,
            &receipt.request_id,
            payer.as_bytes(),
            first,
            second,
        )
    };
    let mut wrong = KagemushaWalletLoadFinalityV1::decode_canonical(&finality).unwrap();
    wrong.receipt_digest = [2; 32];
    assert!(check(&original, &wrong.to_canonical_bytes().unwrap()).is_err());
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(check(&trailing, &finality).is_err());
    let mut trailing = finality.clone();
    trailing.push(0);
    assert!(check(&original, &trailing).is_err());
    assert!(check(&original[..original.len() - 1], &finality).is_err());
    assert!(check(&original, &finality[..finality.len() - 1]).is_err());
}

#[test]
fn malformed_payer_and_input_ceiling_are_rejected_before_canonical_decode() {
    let (receipt, original, finality, payer) = originals();
    let check = |payer: &[u8], first: &[u8], second: &[u8]| {
        validate(
            &receipt.scheme_id,
            &receipt.wallet_id,
            &receipt.request_id,
            payer,
            first,
            second,
        )
    };
    for invalid in [
        vec![],
        vec![0xff],
        vec![b'x'; 1025],
        format!(" {payer}").into_bytes(),
        b"alice@universal".to_vec(),
    ] {
        assert!(check(&invalid, &original, &finality).is_err());
    }
    assert!(check(payer.as_bytes(), &[], &finality).is_err());
    assert!(check(payer.as_bytes(), &[0; 513], &finality).is_err());
    assert!(check(payer.as_bytes(), &original, &[]).is_err());
    assert!(
        check(
            payer.as_bytes(),
            &original,
            &vec![0; KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1 + 1]
        )
        .is_err()
    );
    // Oversized pointers are never dereferenced; this tests the actual C safety boundary.
    assert_eq!(
        unsafe {
            connect_norito_kagemusha_wallet_load_original_validate_v1(
                receipt.scheme_id.as_ptr(),
                receipt.wallet_id.as_ptr(),
                receipt.request_id.as_ptr(),
                payer.as_ptr(),
                payer.len(),
                std::ptr::null(),
                513,
                finality.as_ptr(),
                finality.len(),
                &mut 0,
            )
        },
        INVALID
    );
}
