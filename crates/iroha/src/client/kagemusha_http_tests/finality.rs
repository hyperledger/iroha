//! Bounded epoch-certificate transport is never validator authority.

use super::*;
use iroha_crypto::{HashOf, MerkleProof};
use iroha_data_model::{
    kagemusha::{KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1, KagemushaWalletLedgerFinalityV1},
    sumeragi_finality::{
        CertifiedTransactionInclusionV1, MAX_COMMIT_CERTIFICATE_BYTES_V1,
        SumeragiCommitCertificateV1,
    },
    transaction::TransactionEntrypoint,
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
                    | Error::CanonicalDecode(_)
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

fn entrypoint(byte: u8) -> HashOf<TransactionEntrypoint> {
    HashOf::from_untyped_unchecked(Hash::prehashed([byte; 32]))
}

fn ledger_envelope(entrypoint: HashOf<TransactionEntrypoint>) -> KagemushaWalletLedgerFinalityV1 {
    use iroha_data_model::{
        block::execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        transaction::TransactionResult,
    };
    // Transport DATA only: neither the certificate nor the paths can pass native verification.
    KagemushaWalletLedgerFinalityV1 {
        version: 1,
        entrypoint_hash: entrypoint,
        certificate: certificate(7),
        inclusion: CertifiedTransactionInclusionV1 {
            entry_proof: MerkleProof::from_audit_path(0, vec![]),
            output: ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 0,
                result: TransactionResult::new(Ok(Vec::new())),
                completions: Vec::new(),
            }),
            output_proof: MerkleProof::from_audit_path(0, vec![]),
        },
    }
}

#[tokio::test]
async fn ledger_finality_read_signs_exact_entrypoint_route_and_binds_the_envelope() {
    let initial = client_with_base_url(base_url());
    let (scheme, wallet, entry) = ([0x11; 32], [0x22; 32], entrypoint(0x5b));
    let expected = ledger_envelope(entry);
    let response = reply(200, expected.to_canonical_bytes().unwrap());
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
        .ledger_finality(&scheme, &wallet, &entry)
        .await
        .unwrap();
    assert_eq!(observed, expected);
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.url.path(),
            format!(
                "/v1/kagemusha/{}/wallets/{}/ledger/{}/finality",
                "11".repeat(32),
                "22".repeat(32),
                "5b".repeat(32),
            )
        );
        assert!(request.url.query().is_none());
        assert!(request.body.is_empty());
        assert_eq!(
            request.max_response_bytes,
            KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1
        );
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
        for (selected, valid) in [("5b", true), ("5d", false)] {
            let mut url = request.url.clone();
            url.set_path(
                &request
                    .url
                    .path()
                    .replace(&"5b".repeat(32), &selected.repeat(32)),
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
                valid,
            );
        }
    }
    let canonical = expected.to_canonical_bytes().unwrap();
    let mut trailing = canonical.clone();
    trailing.push(0);
    type Case = (u16, Vec<u8>, fn(Error) -> bool);
    let cases: [Case; 4] = [
        // A valid envelope for another entrypoint is refused by the binding, not the decoder.
        (
            200,
            ledger_envelope(entrypoint(0x5d))
                .to_canonical_bytes()
                .unwrap(),
            |error| {
                matches!(
                    error,
                    Error::ResponseBinding {
                        field: "entrypoint",
                        ..
                    }
                )
            },
        ),
        (200, trailing, |error| {
            matches!(error, Error::CanonicalDecode(_) | Error::Decode { .. })
        }),
        (
            200,
            vec![0; KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1 + 1],
            |error| {
                matches!(
                    error,
                    Error::ResponseTooLarge {
                        maximum: KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
                        ..
                    }
                )
            },
        ),
        (404, canonical, |error| {
            matches!(error, Error::Http { status: 404, .. })
        }),
    ];
    for (status, body, refused) in cases {
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
            .ledger_finality(&scheme, &wallet, &entry)
            .await
            .unwrap_err();
        let report = format!("{status}: {error:?}");
        assert!(refused(error), "{report}");
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn wallet_finality_reads_refuse_witness_authority_before_dispatch() {
    let (client, requests, _) = attach(
        &client_with_base_url(base_url()),
        |_| unreachable!("a witness-bearing read must not dispatch"),
        Duration::ZERO,
        Duration::ZERO,
    );
    // Boundary 10 precedes this receipt, so `load_epoch` reaches the signer check.
    let mut receipt = original(&client.account);
    receipt.block_height = 20;
    let mut builder = client.to_builder();
    builder
        .headers
        .insert("x-IrOhA-WiTnEsS".to_owned(), "untrusted".to_owned());
    let client = builder.build().unwrap();
    let account = client.account_client().unwrap();
    let wallet_reads = account.kagemusha();
    let (scheme, wallet, entry) = ([0x11; 32], [0x22; 32], entrypoint(0x5b));
    // The new ledger reads and the Load reads share one direct-signer helper.
    assert!(matches!(
        wallet_reads.ledger_finality(&scheme, &wallet, &entry).await,
        Err(Error::InvalidRequest {
            operation: "kagemusha.wallet.ledger_finality.read",
            ..
        })
    ));
    assert!(matches!(
        wallet_reads
            .ledger_epoch(&scheme, &wallet, &entry, 10)
            .await,
        Err(Error::InvalidRequest {
            operation: "kagemusha.wallet.ledger_epoch.read",
            ..
        })
    ));
    assert!(matches!(
        wallet_reads.load_finality(&receipt).await,
        Err(Error::InvalidRequest {
            operation: "kagemusha.wallet.load_finality.read",
            ..
        })
    ));
    assert!(matches!(
        wallet_reads.load_epoch(&receipt, 10).await,
        Err(Error::InvalidRequest {
            operation: "kagemusha.wallet.load_epoch.read",
            ..
        })
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ledger_epoch_read_binds_one_boundary_and_refuses_invalid_selectors_before_io() {
    let initial = client_with_base_url(base_url());
    let (scheme, wallet, entry) = ([0x11; 32], [0x22; 32], entrypoint(0x5b));
    let expected = certificate(10);
    let response = reply(200, norito::encode_canonical(&expected).unwrap());
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(response.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    let account = client.account_client().unwrap();
    assert_eq!(
        account
            .kagemusha()
            .ledger_epoch(&scheme, &wallet, &entry, 10)
            .await
            .unwrap(),
        expected
    );
    assert!(matches!(
        account
            .kagemusha()
            .ledger_epoch(&scheme, &wallet, &entry, 11)
            .await,
        Err(Error::ResponseBinding {
            field: "boundary_height",
            ..
        })
    ));
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].url.path(),
            format!(
                "/v1/kagemusha/{}/wallets/{}/ledger/{}/epochs/10",
                "11".repeat(32),
                "22".repeat(32),
                "5b".repeat(32),
            )
        );
        assert!(requests[0].body.is_empty());
        assert_eq!(
            requests[0].max_response_bytes,
            MAX_COMMIT_CERTIFICATE_BYTES_V1
        );
        assert_eq!(header(&requests[0], "accept"), "application/x-norito");
    }
    let (client, requests, _) = attach(
        &initial,
        |_| panic!("invalid input must fail before HTTP"),
        Duration::ZERO,
        Duration::ZERO,
    );
    let account = client.account_client().unwrap();
    for boundary in [0, 1] {
        assert!(matches!(
            account
                .kagemusha()
                .ledger_epoch(&scheme, &wallet, &entry, boundary)
                .await,
            Err(Error::InvalidRequest { .. })
        ));
    }
    assert!(matches!(
        account
            .kagemusha()
            .ledger_epoch(&[0; 32], &wallet, &entry, 10)
            .await,
        Err(Error::InvalidRequest { .. })
    ));
    assert!(matches!(
        account
            .kagemusha()
            .ledger_finality(&scheme, &[0; 32], &entry)
            .await,
        Err(Error::InvalidRequest { .. })
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn blocking_ledger_reads_use_owned_runtime() {
    let initial = client_with_base_url(base_url());
    let (scheme, wallet, entry) = ([0x11; 32], [0x22; 32], entrypoint(0x5b));
    let evidence = ledger_envelope(entry);
    let finality_response = reply(200, evidence.to_canonical_bytes().unwrap());
    let epoch_response = reply(200, norito::encode_canonical(&certificate(10)).unwrap());
    let (client, requests, _) = attach(
        &initial,
        move |request| {
            Ok(if request.url.path().ends_with("/finality") {
                finality_response.clone()
            } else {
                epoch_response.clone()
            })
        },
        Duration::ZERO,
        Duration::ZERO,
    );
    let account = blocking::AccountClient::from_client(client.account_client().unwrap()).unwrap();
    assert_eq!(
        account
            .kagemusha()
            .ledger_finality(&scheme, &wallet, &entry)
            .unwrap(),
        evidence
    );
    assert_eq!(
        account
            .kagemusha()
            .ledger_epoch(&scheme, &wallet, &entry, 10)
            .unwrap(),
        certificate(10)
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

/// The wallet vectors' model-valid Unload claim, which pays the account of seed `0x51`,
/// relayed by another account in one genuine native block next to the relayer's Unload of a
/// changed claim that pays the relayer instead. Execution results are synthetic.
struct RelayedUnload {
    native: iroha_data_model::testing::native_finality::NativeFinalityFixture,
    claimant: iroha_crypto::KeyPair,
    scheme: [u8; 32],
    wallet: [u8; 32],
    height: u64,
    commit_hash: [u8; 32],
    /// The relayer's wire carrying the exact claim bytes, and its certified envelope.
    relayed: (
        iroha_data_model::transaction::SignedTransaction,
        KagemushaWalletLedgerFinalityV1,
    ),
    /// The relayer's wire carrying the changed claim, and its certified envelope.
    changed: (
        iroha_data_model::transaction::SignedTransaction,
        KagemushaWalletLedgerFinalityV1,
    ),
}

fn relayed_unload() -> RelayedUnload {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        block::{BlockSignatures, builder::BlockBuilder},
        isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
        kagemusha::KagemushaWalletUnloadClaimV1,
        testing::native_finality::NativeFinalityFixture,
        transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
    };
    let vectors: norito::json::Value = norito::json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/kagemusha/wallet_v1_vectors.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let row = vectors["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some("KagemushaWalletUnloadClaimV1"))
        .unwrap();
    let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    let claim: KagemushaWalletUnloadClaimV1 =
        norito::decode_canonical_with_limits(&frame, norito::canonical_decode_limits(frame.len()))
            .unwrap();
    let claimant = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
    assert_eq!(AccountId::new(claimant.public_key().clone()), claim.account);
    let relayer = KeyPair::from_seed(vec![0x52; 32], Algorithm::Ed25519);
    let relayer_account = AccountId::new(relayer.public_key().clone());
    assert_ne!(
        relayer_account, claim.account,
        "the signer only relays this claim"
    );
    let scheme = claim.credential.body.scheme_id;
    // Relaying never authorizes retargeting: this changed claim pays the relayer.
    let mut retargeted = claim.clone();
    retargeted.account = relayer_account.clone();
    let mut native = NativeFinalityFixture::start("kagemusha-relayed-unload-client");
    let header = native.next_header();
    let unload = |bytes: Vec<u8>| {
        let mut builder = TransactionBuilder::new(
            native.network_id(),
            relayer_account.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        builder.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
        builder
            .with_instructions([KagemushaWalletLedgerV1::new(
                scheme,
                KagemushaWalletLedgerActionV1::Unload(bytes),
            )])
            .sign(relayer.private_key())
    };
    let transactions: [SignedTransaction; 2] = [
        unload(frame),
        unload(norito::encode_canonical(&retargeted).unwrap()),
    ];
    let mut builder = BlockBuilder::new(header);
    for transaction in &transactions {
        builder.push_transaction(transaction.clone());
    }
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(
        &mut block,
        vec![Ok(Vec::new()), Ok(Vec::new())],
    );
    let proof = native.certify(block);
    let verified = native.verifier().verify_retained_decision(&proof).unwrap();
    let certificate = SumeragiCommitCertificateV1::from_verified(&verified).unwrap();
    let block = verified.block();
    // The envelope Torii serves for one input of this block.
    let certified = |index: u32, signed: SignedTransaction| {
        let (output, _) = block.network_output_at(index).unwrap();
        let envelope = KagemushaWalletLedgerFinalityV1 {
            version: 1,
            entrypoint_hash: signed.hash_as_entrypoint(),
            certificate: certificate.clone(),
            inclusion: CertifiedTransactionInclusionV1 {
                entry_proof: block.network_input_proof(index).unwrap(),
                output: block.execution_outputs()[usize::try_from(output).unwrap()].clone(),
                output_proof: block.output_proof(output).unwrap(),
            },
        };
        (signed, envelope)
    };
    let [exact_wire, changed_wire] = transactions;
    RelayedUnload {
        claimant,
        scheme,
        wallet: claim.credential.body.wallet_id,
        height: verified.height(),
        commit_hash: verified.core_hash().0,
        relayed: certified(0, exact_wire),
        changed: certified(1, changed_wire),
        native,
    }
}

impl RelayedUnload {
    /// The wallet's own reader, rooted in the fixture's signed genesis.
    fn reader(&self) -> iroha_data_model::sumeragi_finality::SumeragiCommitVerifierV1 {
        let root = iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier::new(
            self.native.genesis(),
            self.native.chain_id(),
            self.native.genesis_proof().committee.clone(),
        )
        .unwrap();
        iroha_data_model::sumeragi_finality::SumeragiCommitVerifierV1::new(&root).unwrap()
    }

    /// A client of the account the claim pays, which signed no transaction here.
    fn claimant_client(&self) -> Client {
        let mut builder = client_with_base_url(base_url()).to_builder();
        builder.key_pair = self.claimant.clone();
        builder.account =
            iroha_data_model::account::AccountId::new(self.claimant.public_key().clone());
        builder.build().unwrap()
    }
}

#[tokio::test]
async fn relayed_unload_finality_is_read_and_verified_by_its_claim_account() {
    let fixture = relayed_unload();
    let reader = fixture.reader();
    let chain = fixture.native.chain_id();
    let (relayed, envelope) = &fixture.relayed;
    let (changed, changed_envelope) = &fixture.changed;
    let entry = relayed.hash_as_entrypoint();
    let entry_bytes = *AsRef::<[u8; 32]>::as_ref(&entry);
    let initial = fixture.claimant_client();
    assert_ne!(&initial.account, relayed.authority());
    let response = reply(200, envelope.to_canonical_bytes().unwrap());
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(response.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    // The claim account reads the relayer's committed Unload. The read binds the entrypoint;
    // it never compares the transaction's signer with the reader.
    let observed = client
        .account_client()
        .unwrap()
        .kagemusha()
        .ledger_finality(&fixture.scheme, &fixture.wallet, &entry)
        .await
        .unwrap();
    assert_eq!(&observed, envelope);
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url.path(),
            format!(
                "/v1/kagemusha/{}/wallets/{}/ledger/{}/finality",
                hex::encode(fixture.scheme),
                hex::encode(fixture.wallet),
                hex::encode(entry_bytes),
            )
        );
        assert_eq!(
            header(&requests[0], "x-iroha-account"),
            client.account.to_canonical_hex().unwrap(),
        );
    }
    // The wallet verifies the certificate, both memberships and the outcome itself, against
    // the relayed wire it retained.
    let outcome = observed.verify(&reader, chain, relayed).unwrap();
    assert!(outcome.accepted());
    assert_eq!(outcome.entrypoint(), entry_bytes);
    assert_eq!(outcome.height(), fixture.height);
    assert_eq!(outcome.commit_hash(), fixture.commit_hash);
    // A changed claim is another wire: the attempt's evidence never verifies for it, the
    // changed claim's own certified evidence never verifies for the retained wire, and a
    // read of the retained attempt refuses that evidence by its entrypoint binding.
    assert_ne!(changed.hash_as_entrypoint(), entry);
    assert!(observed.verify(&reader, chain, changed).is_err());
    assert!(changed_envelope.verify(&reader, chain, relayed).is_err());
    let response = reply(200, changed_envelope.to_canonical_bytes().unwrap());
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(response.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .ledger_finality(&fixture.scheme, &fixture.wallet, &entry)
            .await,
        Err(Error::ResponseBinding {
            field: "entrypoint",
            ..
        })
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn blocking_relayed_unload_read_uses_owned_runtime() {
    let fixture = relayed_unload();
    let (relayed, envelope) = &fixture.relayed;
    let entry = relayed.hash_as_entrypoint();
    let response = reply(200, envelope.to_canonical_bytes().unwrap());
    let (client, requests, _) = attach(
        &fixture.claimant_client(),
        move |_| Ok(response.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    let account = blocking::AccountClient::from_client(client.account_client().unwrap()).unwrap();
    let observed = account
        .kagemusha()
        .ledger_finality(&fixture.scheme, &fixture.wallet, &entry)
        .unwrap();
    assert_eq!(&observed, envelope);
    assert!(
        observed
            .verify(&fixture.reader(), fixture.native.chain_id(), relayed)
            .unwrap()
            .accepted()
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}
