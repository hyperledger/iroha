//! Bounded epoch-certificate transport is never validator authority.

use super::*;
use iroha_data_model::sumeragi_finality::{
    MAX_COMMIT_CERTIFICATE_BYTES_V1, SumeragiCommitCertificateV1,
};

fn certificate(height: u64) -> SumeragiCommitCertificateV1 {
    use iroha_sumeragi::{
        message::BlockHeader,
        types::{ControlWitness, EpochId, Hash32},
    };
    // Only the canonical header is meaningful. The QC/result are transport fixtures,
    // deliberately incapable of passing native BLS verification or granting authority.
    let header = BlockHeader {
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 0,
            context: Hash32([2; 32]),
        },
        height,
        origin_view: 0,
        parent_hash: Hash32([3; 32]),
        parent_result: Hash32([4; 32]),
        payload_hash: Hash32([5; 32]),
        availability_digest: Hash32([6; 32]),
        payload_len: 1,
        proposer: 0,
        skipped_leaders: vec![],
        control_witness: ControlWitness::empty(),
    };
    SumeragiCommitCertificateV1 {
        consensus_header: norito::encode_canonical(&header).unwrap(),
        commit_qc: vec![2],
        result_preimage: vec![3],
    }
}

fn reply(status: u16, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/x-norito")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn epoch_read_signs_exact_boundary_and_binds_one_bounded_original() {
    let initial = client_with_base_url(base_url());
    let mut receipt = original(&initial.account);
    receipt.block_height = 20;
    let expected = certificate(10);
    let response = reply(200, norito::encode_canonical(&expected).unwrap());
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(response.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    let observed = client
        .account_client()
        .unwrap()
        .kagemusha()
        .load_epoch(&receipt, 10)
        .await
        .unwrap();
    assert_eq!(observed, expected);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, Method::GET);
    assert_eq!(
        request.url.path(),
        format!(
            "/v1/kagemusha/{}/wallets/{}/loads/{}/epochs/10",
            hex::encode(receipt.scheme_id),
            hex::encode(receipt.wallet_id),
            hex::encode(receipt.request_id),
        )
    );
    assert!(request.url.query().is_none());
    assert!(request.body.is_empty());
    assert_eq!(request.max_response_bytes, MAX_COMMIT_CERTIFICATE_BYTES_V1);
    assert_eq!(header(request, "accept"), "application/x-norito");
    assert_eq!(
        header(request, "x-iroha-account"),
        client.account.to_canonical_hex().unwrap(),
    );
    let signature = Signature::try_from_bytes(
        &base64::engine::general_purpose::STANDARD
            .decode(header(request, "x-iroha-signature"))
            .unwrap(),
    )
    .unwrap();
    let timestamp = header(request, "x-iroha-timestamp-ms").parse().unwrap();
    let nonce = header(request, "x-iroha-nonce");
    for boundary in [10, 11] {
        let mut url = request.url.clone();
        url.set_path(
            &request
                .url
                .path()
                .replace("/epochs/10", &format!("/epochs/{boundary}")),
        );
        let message = Client::exact_network_request_message(
            &client.network_id,
            &request.method,
            &url,
            &request.body,
            timestamp,
            nonce,
        )
        .unwrap();
        assert_eq!(
            signature
                .verify(client.key_pair.public_key(), &message)
                .is_ok(),
            boundary == 10,
        );
    }
}

#[tokio::test]
async fn epoch_read_refuses_invalid_selectors_and_foreign_payer_before_io() {
    let initial = client_with_base_url(base_url());
    let mut receipt = original(&initial.account);
    receipt.block_height = 20;
    let (client, requests, _) = attach(
        &initial,
        |_| panic!("invalid input must fail before HTTP"),
        Duration::ZERO,
        Duration::ZERO,
    );
    let account = client.account_client().unwrap();
    for height in [0, 1, 20, u64::MAX] {
        assert!(matches!(
            account.kagemusha().load_epoch(&receipt, height).await,
            Err(Error::InvalidRequest { .. })
        ));
    }
    receipt.payer_account_digest = [91; 32];
    assert!(matches!(
        account.kagemusha().load_epoch(&receipt, 10).await,
        Err(Error::ResponseBinding { field: "payer", .. })
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn epoch_read_refuses_wrong_height_trailing_oversized_and_proof_job_replies() {
    let initial = client_with_base_url(base_url());
    let mut receipt = original(&initial.account);
    receipt.block_height = 20;
    let canonical = norito::encode_canonical(&certificate(10)).unwrap();
    let mut trailing = canonical.clone();
    trailing.push(0);
    for (status, body) in [
        (200, norito::encode_canonical(&certificate(11)).unwrap()),
        (200, trailing),
        (200, vec![0; MAX_COMMIT_CERTIFICATE_BYTES_V1 + 1]),
        (202, canonical),
    ] {
        let response = reply(status, body);
        let (client, requests, _) = attach(
            &initial,
            move |_| Ok(response.clone()),
            Duration::ZERO,
            Duration::ZERO,
        );
        let error = client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_epoch(&receipt, 10)
            .await
            .unwrap_err();
        if status == 202 {
            assert!(matches!(error, Error::Http { status: 202, .. }));
        } else {
            assert!(matches!(
                error,
                Error::ResponseBinding {
                    field: "boundary_height",
                    ..
                } | Error::ResponseTooLarge { .. }
                    | Error::CanonicalDecode { .. }
                    | Error::Decode { .. }
            ));
        }
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn blocking_epoch_read_uses_owned_runtime() {
    use iroha_data_model::kagemusha::KagemushaWalletLoadFinalityV1;

    let initial = client_with_base_url(base_url());
    let mut receipt = original(&initial.account);
    receipt.block_height = 20;
    let expected = certificate(10);
    let response = reply(200, norito::encode_canonical(&expected).unwrap());
    let finality = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate: certificate(receipt.block_height),
        event_proof: iroha_crypto::MerkleProof::from_audit_path(0, vec![]),
    };
    let finality_response = reply(200, finality.to_canonical_bytes().unwrap());
    let (client, requests, _) = attach(
        &initial,
        move |request| {
            Ok(if request.url.path().ends_with("/finality") {
                finality_response.clone()
            } else {
                response.clone()
            })
        },
        Duration::ZERO,
        Duration::ZERO,
    );
    let account = blocking::AccountClient::from_client(client.account_client().unwrap()).unwrap();
    assert_eq!(
        account.kagemusha().load_epoch(&receipt, 10).unwrap(),
        expected
    );
    assert_eq!(
        account.kagemusha().load_finality(&receipt).unwrap(),
        finality
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}
