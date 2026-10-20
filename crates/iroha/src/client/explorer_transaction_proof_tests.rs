use super::*;
use crate::client::evidence_http_tests::{
    SnapshotStore, base_url, client_with_base_url, json_response, respond_with, with_mock_http,
};
use crate::client::tests::assert_canonical_account_signed_request;
use iroha_crypto::MerkleProof;
use iroha_data_model::{
    block::execution_output::NetworkExecutionOutputV1, transaction::TransactionResult,
};
use std::sync::{Arc, Mutex};

fn evidence(client: &Client) -> ExplorerTransactionProof {
    let signed = TransactionBuilder::new(
        client.network_id,
        client.account.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .try_sign(client.key_pair.private_key())
    .expect("signed native transaction");
    let entrypoint = TransactionEntrypoint::External(signed);
    let output = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: 0,
        result: TransactionResult::new(Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("readable rejected transaction".to_owned()),
        ))),
        completions: Vec::new(),
    });
    let block_header = BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(HashOf::from_untyped_unchecked(Hash::new(b"previous block"))),
        None,
        1_700_000_000_000,
        0,
    );
    ExplorerTransactionProof {
        version: 1,
        network_id: client.network_id,
        block_height: 2,
        block_header,
        transaction: CommittedTransaction {
            block_hash: block_header.hash(),
            entrypoint_hash: entrypoint.hash(),
            entrypoint_proof: MerkleProof::from_audit_path(0, Vec::new()),
            entrypoint,
            output_hash: HashOf::new(&output),
            // Full output-tree positions need not equal the Network input position.
            output_proof: MerkleProof::from_audit_path(1, Vec::new()),
            output,
        },
        certificate: ExplorerTransactionProofCertificate {
            consensus_header: "AQID".to_owned(),
            commit_qc: "BAU=".to_owned(),
            result_preimage: "Bg==".to_owned(),
        },
    }
}

fn read(
    client: &Client,
    expected: HashOf<TransactionEntrypoint>,
    body: &str,
) -> Result<ExplorerTransactionProof> {
    let store: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    with_mock_http(
        respond_with(&store, json_response(StatusCode::OK, body)),
        |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_explorer_transaction_proof(expected)
        },
    )
}

#[test]
fn explorer_transaction_proof_signs_exact_read_with_fresh_native_auth_and_cap() {
    let client = client_with_base_url(base_url());
    let proof = evidence(&client);
    let hash = proof.transaction.entrypoint_hash;
    let store: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    with_mock_http(
        respond_with(
            &store,
            json_response(StatusCode::OK, &norito::json::to_json(&proof).unwrap()),
        ),
        |transport| {
            let client = client.clone().with_test_http_transport(transport);
            for _ in 0..2 {
                let actual = client
                    .get_explorer_transaction_proof(hash)
                    .expect("selected evidence");
                assert_eq!(actual.transaction, proof.transaction);
                assert!(actual.transaction.result().is_err());
            }
        },
    );
    let snapshots = store.lock().unwrap();
    assert_eq!(snapshots.len(), 2);
    for snapshot in snapshots.iter() {
        assert_eq!(snapshot.method, HttpMethod::GET);
        assert_eq!(
            snapshot.url.path(),
            format!(
                "/v1/explorer/transactions/{}/proof",
                hex::encode(hash.as_ref())
            )
        );
        assert!(snapshot.body.is_empty());
        assert_eq!(snapshot.timeout, Some(client.torii_request_timeout));
        assert_eq!(
            snapshot.max_response_bytes,
            EXPLORER_TRANSACTION_PROOF_MAX_BYTES
        );
        assert_canonical_account_signed_request(&client, snapshot);
    }
    let nonce = |index: usize| {
        snapshots[index]
            .headers
            .iter()
            .find(|(name, _)| name == HEADER_NONCE)
            .unwrap()
            .1
            .clone()
    };
    assert_ne!(nonce(0), nonce(1));
}

#[test]
fn explorer_transaction_proof_preserves_a_visible_sealed_reveal() {
    let client = client_with_base_url(base_url());
    let mut proof = evidence(&client);
    let TransactionEntrypoint::External(signed) = proof.transaction.entrypoint.clone() else {
        unreachable!();
    };
    proof.transaction.entrypoint = TransactionEntrypoint::SealedReveal(
        iroha_data_model::transaction::signed::SealedTransactionReveal::new(
            Hash::new(b"sealed proof commitment"),
            signed,
            [7; 32],
        ),
    );
    proof.transaction.entrypoint_hash = proof.transaction.entrypoint.hash();
    let decoded = read(
        &client,
        proof.transaction.entrypoint_hash,
        &norito::json::to_json(&proof).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.transaction.entrypoint, proof.transaction.entrypoint);
}

#[test]
fn explorer_signed_transaction_proof_refuses_a_signerless_ballot() {
    use iroha_data_model::governance::anonymous_ballot::*;

    let client = client_with_base_url(base_url());
    let mut proof = evidence(&client);
    // Canonical structural fixture only: no claim that the proof or stamp is valid.
    let envelope = AnonymousBallotEnvelopeV1 {
        network_id: client.network_id,
        ballot: AnonymousBallotV1 {
            scope: BallotScopeV1::new([1; 64]),
            vote: BallotChoiceV1::Aye,
            nullifier: NullifierV1::new([2; 128]),
            auth_v: VoteAuthorizationV1::new([3; 64]),
            profile_id: ProofProfileIdV1::V1,
            stamp: AdmissionStampV1 {
                nonce: AdmissionNonceV1::new([4; 32]),
            },
            proof: BallotProofBytesV1::new(vec![0; BallotProofBytesV1::LENGTH]).unwrap(),
        },
    };
    proof.transaction.entrypoint = TransactionEntrypoint::AnonymousBallot(
        CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope).unwrap(),
    );
    proof.transaction.entrypoint_hash = proof.transaction.entrypoint.hash();
    let error = proof
        .validate_bindings(&client.network_id, proof.transaction.entrypoint_hash)
        .expect_err("signed transaction proof endpoint cannot supply a ballot authority");
    assert!(error.to_string().contains("visible signed transaction"));
}

#[test]
fn explorer_transaction_proof_rejects_binding_substitution_and_malformed_carriers() {
    let client = client_with_base_url(base_url());
    let original = evidence(&client);
    let hash = original.transaction.entrypoint_hash;
    for mutation in 0..10 {
        let mut proof = original.clone();
        match mutation {
            0 => proof.version = 2,
            1 => {
                proof.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"another network"),
                ))
            }
            2 => proof.block_height = 1,
            3 => {
                proof.transaction.block_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"another block"))
            }
            4 => {
                proof.transaction.entrypoint_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"another transaction"))
            }
            5 => {
                proof.transaction.output_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"another output"))
            }
            6 => proof.transaction.entrypoint_proof = MerkleProof::from_audit_path(1, Vec::new()),
            7 => proof.transaction.output_proof = MerkleProof::from_audit_path(1, vec![None; 33]),
            8 => proof.certificate.commit_qc = "BAU".to_owned(),
            9 => {
                proof.certificate.commit_qc =
                    base64::engine::general_purpose::STANDARD.encode(vec![0; 4097])
            }
            _ => unreachable!(),
        }
        assert!(
            read(&client, hash, &norito::json::to_json(&proof).unwrap()).is_err(),
            "mutation {mutation}"
        );
    }
    let mut other_client = client.clone();
    other_client.network_id =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"inner network")));
    let mut substituted = evidence(&other_client);
    substituted.network_id = client.network_id;
    assert!(
        read(
            &client,
            substituted.transaction.entrypoint_hash,
            &norito::json::to_json(&substituted).unwrap()
        )
        .is_err()
    );
    let valid = norito::json::to_json(&original).unwrap();
    for body in [
        valid.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        valid.replacen("\"version\":1", "\"version\":1,\"block\":{}", 1),
        format!("{valid}{{}}"),
    ] {
        assert!(read(&client, hash, &body).is_err());
    }
    let other = HashOf::from_untyped_unchecked(Hash::new(b"different requested transaction"));
    assert!(read(&client, other, &valid).is_err());
}

#[test]
fn explorer_transaction_proof_preserves_denials_without_fallback_and_bounds_errors() {
    let client = client_with_base_url(base_url());
    let hash = evidence(&client).transaction.entrypoint_hash;
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::TEMPORARY_REDIRECT,
    ] {
        let store: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let result = with_mock_http(
            respond_with(&store, json_response(status, "{}")),
            |transport| {
                client
                    .clone()
                    .with_test_http_transport(transport)
                    .get_explorer_transaction_proof(hash)
            },
        );
        assert!(result.is_err());
        assert_eq!(store.lock().unwrap().len(), 1);
    }
    for status in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
        let store: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let oversized = Response::builder()
            .status(status)
            .body(vec![b' '; EXPLORER_TRANSACTION_PROOF_MAX_BYTES + 1])
            .unwrap();
        let result = with_mock_http(respond_with(&store, oversized), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_explorer_transaction_proof(hash)
        });
        assert!(result.is_err());
        assert_eq!(store.lock().unwrap().len(), 1);
    }
    let store: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let html = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html")
        .body(b"{}".to_vec())
        .unwrap();
    let result = with_mock_http(respond_with(&store, html), |transport| {
        client
            .clone()
            .with_test_http_transport(transport)
            .get_explorer_transaction_proof(hash)
    });
    assert!(result.is_err());
}
