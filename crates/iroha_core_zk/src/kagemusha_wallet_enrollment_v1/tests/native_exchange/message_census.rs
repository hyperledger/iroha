//! Exact complete-envelope evidence from genuine retained exchange originals.
//!
//! The census never opens wallet custody or signs an operation. Proof verification uses
//! the independently admitted catalog; historical producer identity stays separate from
//! this observer. Only observed variants qualify, never unexecuted controls or carriers.

use super::*;

const ORIGINAL_NAMES: [&str; 8] = [
    "a-b-payment.norito",
    "b-c-payment.norito",
    "a-credited-receive.norito",
    "b-credited-status.norito",
    "a-b-offer.norito",
    "a-b-request.norito",
    "b-c-offer.norito",
    "b-c-request.norito",
];

pub(super) fn record(
    output: &Path,
    name: &str,
    message: KagemushaWalletMessageV1,
) -> norito::json::Value {
    let maximum = message.max_bytes();
    let scheme = *message.scheme_id();
    let tag = message.tag();
    let envelope = KagemushaWalletEnvelopeV1::new(message);
    // Retain even an oversized frame before refusing it: a payload length alone must
    // never qualify the larger carrying envelope, and failed measurements are evidence.
    let frame = norito::encode_canonical(&envelope).unwrap();
    let filename = format!("{name}.envelope.norito");
    let result = norito::json!({
        "name": filename, "tag": tag, "bytes": (frame.len()),
        "sha256": (sha(&frame)), "maximum_bytes": maximum,
        "within_bound": (frame.len() <= maximum),
    });
    publish(&output.join(&filename), &frame);
    publish(
        &output.join(format!("{name}.measurement.json")),
        &norito::json::to_vec(&result).unwrap(),
    );
    assert!(
        frame.len() <= maximum,
        "complete {name} envelope exceeds bound"
    );
    assert_eq!(
        KagemushaWalletEnvelopeV1::decode_canonical(&frame, &scheme).unwrap(),
        envelope
    );
    result
}

pub(super) fn retain(
    output: &Path,
    sources: &Sources,
    sessions: [(&[u8], &[u8]); 2],
    payments: [&[u8]; 2],
    acknowledgements: [&[u8]; 2],
) -> Vec<norito::json::Value> {
    let verifier = sources.installed.verifier();
    let mut records = Vec::new();
    let mut originals = Vec::new();
    for (((name, (offer_original, request_original)), original), acknowledgement) in ["a-b", "b-c"]
        .into_iter()
        .zip(sessions)
        .zip(payments)
        .zip(acknowledgements)
    {
        let offer: KagemushaWalletOfferV1 = decode(offer_original);
        let request: KagemushaWalletRequestV1 = decode(request_original);
        // Preserve the actual signed session originals, including the dependencies
        // omitted from compact Payment; never reconstruct or sign a replacement.
        publish(&output.join(format!("{name}-offer.norito")), offer_original);
        publish(
            &output.join(format!("{name}-request.norito")),
            request_original,
        );
        records.push(record(
            output,
            &format!("{name}-offer"),
            KagemushaWalletMessageV1::Offer {
                offer: offer.clone(),
            },
        ));
        records.push(record(
            output,
            &format!("{name}-request"),
            KagemushaWalletMessageV1::Request {
                request: request.clone(),
            },
        ));
        let payment: KagemushaWalletPaymentV1 = decode(original);
        let lineage = payment
            .send
            .lineage
            .lineage()
            .expect("Send predecessor Omega")
            .clone();
        records.push(record(
            output,
            &format!("{name}-lineage"),
            KagemushaWalletMessageV1::Lineage {
                lineage: KagemushaWalletLineageMessageV1::new(lineage),
            },
        ));
        let credited: KagemushaWalletCreditedV1 = decode(acknowledgement);
        records.push(record(
            output,
            &format!("{name}-credited"),
            KagemushaWalletMessageV1::Credited {
                credited: credited.clone(),
            },
        ));
        records.push(record(
            output,
            &format!("{name}-payment"),
            KagemushaWalletMessageV1::Payment {
                payment: payment.clone(),
            },
        ));
        originals.push((name, offer, request, payment, credited));
    }
    // Record carrying frames before expensive proof verification. Failed proofs
    // retain their exact originals and decisions; they never become census success.
    let mut proof_checks = Vec::new();
    let mut all_proofs_verified = true;
    for (name, offer, request, payment, credited) in originals {
        let session_result = verify_session(verifier.scheme(), &offer, &request, &payment);
        let payment_result = verifier.verify_package_proofs(&payment.send, MemoryBudget::DEFAULT);
        let (credited_scope, credited_result) = match &credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => (
                "Receive Sigma proof only",
                verifier.verify_package_proofs(package, MemoryBudget::DEFAULT),
            ),
            KagemushaWalletCreditedEvidenceV1::Status { status } => (
                "CreditStatus Omega lineage only; no credit-membership or request linkage verdict",
                verifier.verify_lineage(&status.lineage, MemoryBudget::DEFAULT),
            ),
        };
        all_proofs_verified &=
            session_result.is_ok() && payment_result.is_ok() && credited_result.is_ok();
        proof_checks.push(norito::json!({
            "pair": name,
            "session_verification_scope": "Offer signature, payer credential and issuer; exact signed Request and its receiver credential, certificates and fee schedule; Payment model binding to those session originals",
            "session_verification_result": (format!("{session_result:?}")),
            "payment_proof_scope": "Send Sigma and predecessor Omega proofs only",
            "payment_proof_result": (format!("{payment_result:?}")),
            "credited_proof_scope": credited_scope,
            "credited_proof_result": (format!("{credited_result:?}")),
            "native_operation_admission_executed": false,
        }));
    }
    publish(
        &output.join("proof-checks.json"),
        &norito::json::to_vec(&proof_checks).unwrap(),
    );
    assert!(all_proofs_verified, "retained envelope proof check failed");
    records
}

fn verify_session(
    scheme: &KagemushaWalletSchemeV1,
    offer: &KagemushaWalletOfferV1,
    request: &KagemushaWalletRequestV1,
    payment: &KagemushaWalletPaymentV1,
) -> Result<(), KagemushaWalletValidationErrorV1> {
    offer.verify(scheme)?;
    payment
        .verify(
            scheme,
            &offer.payer_credential,
            &offer.certificates,
            request,
        )
        .map(|_| ())
}

fn manifest_originals(
    input: &Path,
    original: &[u8],
    expected_pins: &norito::json::Value,
) -> [Vec<u8>; 8] {
    let manifest: norito::json::Value = norito::json::from_slice(original).unwrap();
    assert_eq!(
        manifest["schema"].as_str(),
        Some("iroha.kagemusha.message-originals.v1")
    );
    assert_eq!(&manifest["source_pins"], expected_pins);
    let rows = manifest["originals"].as_array().unwrap();
    assert_eq!(rows.len(), 8);
    let files = norito::json!({"files": (rows.clone())});
    ORIGINAL_NAMES.map(|name| target_original(input.parent().unwrap(), &files, name, 10_000))
}

pub(super) fn read_pinned_originals() -> (Vec<u8>, [Vec<u8>; 8]) {
    let input = selected_path("KAGEMUSHA_NATIVE_MESSAGE_ORIGINALS");
    let original = read_pin(
        &input,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_MESSAGE_ORIGINALS_SHA256"),
    );
    let bytes = manifest_originals(&input, &original, &source_pins());
    (original, bytes)
}

pub(super) fn sessions_for_exchange(
    originals: [Vec<u8>; 8],
    scheme: &KagemushaWalletSchemeV1,
    payments: [&[u8]; 2],
    acknowledgements: [&[u8]; 2],
) -> [[Vec<u8>; 2]; 2] {
    for (original, expected) in originals[..4]
        .iter()
        .zip(payments.into_iter().chain(acknowledgements))
    {
        assert_eq!(original, expected, "exact same-campaign monetary original");
    }
    let [_, _, _, _, offer_ab, request_ab, offer_bc, request_bc] = originals;
    let sessions = [[offer_ab, request_ab], [offer_bc, request_bc]];
    for ([offer, request], payment) in sessions.iter().zip(payments) {
        verify_session(scheme, &decode(offer), &decode(request), &decode(payment)).unwrap();
    }
    sessions
}

#[test]
#[ignore = "read-only genuine-original census; requires admitted catalog and an independently pinned eight-original manifest"]
fn remeasure_retained_genuine_exchange_envelopes_without_wallet_mutation() {
    let (original, bytes) = read_pinned_originals();
    let output = fresh_output("KAGEMUSHA_NATIVE_MESSAGE_CENSUS_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let records = retain(
        &output,
        &sources,
        [(&bytes[4], &bytes[5]), (&bytes[6], &bytes[7])],
        [&bytes[0], &bytes[1]],
        [&bytes[2], &bytes[3]],
    );
    publish(&output.join("result.json"), &norito::json::to_vec(&norito::json!({
        "schema": "iroha.kagemusha.message-census.v1",
        "originals_manifest_sha256": (sha(&original)),
        "source_pins": (source_pins()),
        "observer_binary_sha256": (executable_hash()),
        "observer_source_snapshot_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "observer_source_scope": "Diagnostic source snapshot only; not a guarded compiler consumed-input attestation",
        "message_envelopes": records,
        "new_wallet_operations": 0, "physical_device_qualified": false,
        "scope": "Exact retained canonical Offer/Request/Payment/Credited/Lineage envelopes with authenticated session originals and Sigma/Omega proof verification against admitted catalog. CreditStatus check covers only Omega, not credit membership or request linkage. No new native message/operation admission, fresh lifecycle, all policy variants, carrier timings or current-producer qualification."
    })).unwrap());
}

fn fixture_message(kind: &str) -> KagemushaWalletMessageV1 {
    // Structural vectors test only the evidence helper; their stand-in proofs never
    // enter the genuine census, which additionally invokes the installed verifier.
    let vectors: norito::json::Value = norito::json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let row = vectors["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"].as_str() == Some(kind))
        .unwrap();
    let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    decode::<KagemushaWalletEnvelopeV1>(&frame).message
}

#[test]
fn message_census_authenticates_session_originals_and_rejects_substitution() {
    use p256::ecdsa::signature::Signer as _;

    // Real fixture signatures exercise model admission; the fixture's stand-in
    // financial proofs are deliberately never passed to the genuine census.
    let vectors: norito::json::Value = norito::json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let scheme_row = vectors["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some("KagemushaWalletSchemeV1"))
        .unwrap();
    let scheme: KagemushaWalletSchemeV1 =
        decode(&hex::decode(scheme_row["canonical_hex"].as_str().unwrap()).unwrap());
    let KagemushaWalletMessageV1::Offer { offer } = fixture_message("Offer") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Request { request } = fixture_message("Request") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Payment { payment } = fixture_message("Payment") else {
        unreachable!()
    };
    verify_session(&scheme, &offer, &request, &payment).unwrap();

    let mut changed_offer = offer.clone();
    changed_offer.body.session_nonce[0] ^= 1;
    assert!(verify_session(&scheme, &changed_offer, &request, &payment).is_err());
    let mut changed_request = request.clone();
    changed_request.body.nonce[0] ^= 1;
    assert!(verify_session(&scheme, &offer, &changed_request, &payment).is_err());
    let mut foreign_scheme = scheme;
    foreign_scheme.relation_id[0] ^= 1;
    assert!(verify_session(&foreign_scheme, &offer, &request, &payment).is_err());

    // This replacement is independently valid and signed by the SAME receiver.
    // Its rejection must bind the original Payment's exact signed Request, not
    // merely detect a broken replacement signature or a foreign receiver key.
    assert_eq!(
        public_key(&signing_key(0x52)),
        request.receiver_credential.body.payment_key
    );
    let signature: p256::ecdsa::Signature =
        signing_key(0x52).sign(&changed_request.body.signing_message());
    let signature = signature.normalize_s().unwrap_or(signature);
    changed_request.signature =
        KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).unwrap();
    changed_request.verify(&scheme).unwrap();
    assert_ne!(changed_request.signed(), payment.signed_request().unwrap());
    assert!(verify_session(&scheme, &offer, &changed_request, &payment).is_err());

    let offer_bytes = norito::encode_canonical(&offer).unwrap();
    let request_bytes = norito::encode_canonical(&request).unwrap();
    let payment_bytes = norito::encode_canonical(&payment).unwrap();
    let KagemushaWalletMessageV1::Credited { credited } = fixture_message("Credited") else {
        unreachable!()
    };
    let acknowledgement = norito::encode_canonical(&credited).unwrap();
    let originals = [
        payment_bytes.clone(),
        payment_bytes.clone(),
        acknowledgement.clone(),
        acknowledgement.clone(),
        offer_bytes.clone(),
        request_bytes.clone(),
        offer_bytes.clone(),
        request_bytes.clone(),
    ];
    assert_eq!(
        sessions_for_exchange(
            originals.clone(),
            &scheme,
            [&payment_bytes, &payment_bytes],
            [&acknowledgement, &acknowledgement],
        ),
        [
            [offer_bytes.clone(), request_bytes.clone()],
            [offer_bytes, request_bytes]
        ]
    );
    for index in 0..4 {
        let mut changed = originals.clone();
        changed[index].push(0);
        assert!(
            std::panic::catch_unwind(|| sessions_for_exchange(
                changed,
                &scheme,
                [&payment_bytes, &payment_bytes],
                [&acknowledgement, &acknowledgement],
            ))
            .is_err()
        );
    }
}

#[test]
fn message_census_manifest_requires_exact_pinned_roles() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("originals.json");
    let source_pins = norito::json!({"test_source": "structural inventory only"});
    let mut rows = Vec::new();
    let originals: [Vec<u8>; 8] = std::array::from_fn(|index| vec![index as u8 + 1; index + 1]);
    for (name, bytes) in ORIGINAL_NAMES.into_iter().zip(&originals) {
        publish(&directory.path().join(name), bytes);
        rows.push(norito::json!({"name":name,"bytes":(bytes.len()),"sha256":(sha(bytes))}));
    }
    let manifest = norito::json!({
        "schema": "iroha.kagemusha.message-originals.v1",
        "source_pins": (source_pins.clone()), "originals": rows,
    });
    assert_eq!(
        manifest_originals(
            &input,
            &norito::json::to_vec(&manifest).unwrap(),
            &source_pins
        ),
        originals
    );
    for mutation in 0..6 {
        let mut changed = manifest.clone();
        match mutation {
            0 => changed["source_pins"] = norito::json!({"test_source":"foreign"}),
            1 => changed["originals"] = norito::json!(rows[..7].to_vec()),
            2 => changed["originals"][7] = changed["originals"][6].clone(),
            3 => changed["originals"][7]["name"] = "foreign.norito".into(),
            4 => changed["originals"][7]["bytes"] = 99_u64.into(),
            5 => changed["originals"][7]["sha256"] = sha(b"foreign").into(),
            _ => unreachable!(),
        }
        assert!(
            std::panic::catch_unwind(|| manifest_originals(
                &input,
                &norito::json::to_vec(&changed).unwrap(),
                &source_pins,
            ))
            .is_err()
        );
    }
}

#[test]
fn message_census_records_session_bounds_and_retains_oversized_offer() {
    let directory = tempfile::tempdir().unwrap();
    for (kind, maximum) in [
        ("Offer", KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1),
        ("Request", KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1),
    ] {
        let message = fixture_message(kind);
        let row = record(directory.path(), kind, message.clone());
        let bytes = fs::read(directory.path().join(format!("{kind}.envelope.norito"))).unwrap();
        assert_eq!(row["maximum_bytes"].as_u64(), Some(maximum as u64));
        assert_eq!(row["bytes"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(row["sha256"].as_str(), Some(sha(&bytes).as_str()));
        assert_eq!(decode::<KagemushaWalletEnvelopeV1>(&bytes).message, message);
    }

    // This oversized structural Offer is deliberately invalid; it exercises
    // failure evidence retention, never protocol acceptance or phone sizing.
    let KagemushaWalletMessageV1::Offer { mut offer } = fixture_message("Offer") else {
        unreachable!()
    };
    let issuer = offer.certificates.certificates[0];
    offer.certificates.certificates.resize(16, issuer);
    assert!(
        std::panic::catch_unwind(|| record(
            directory.path(),
            "oversized-offer",
            KagemushaWalletMessageV1::Offer { offer }
        ))
        .is_err()
    );
    let measured: norito::json::Value = norito::json::from_slice(
        &fs::read(directory.path().join("oversized-offer.measurement.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(measured["within_bound"].as_bool(), Some(false));
    assert_eq!(
        measured["maximum_bytes"].as_u64(),
        Some(KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1 as u64)
    );
    assert!(measured["bytes"].as_u64().unwrap() > KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1 as u64);
    let frame = fs::read(directory.path().join("oversized-offer.envelope.norito")).unwrap();
    assert_eq!(measured["bytes"].as_u64(), Some(frame.len() as u64));
    assert_eq!(measured["sha256"].as_str(), Some(sha(&frame).as_str()));
}

#[test]
fn message_census_records_complete_frame_and_retains_oversize_failure() {
    let directory = tempfile::tempdir().unwrap();
    let message = fixture_message("Payment");
    let row = record(directory.path(), "valid", message.clone());
    let bytes = fs::read(directory.path().join("valid.envelope.norito")).unwrap();
    assert_eq!(row["bytes"].as_u64(), Some(bytes.len() as u64));
    assert_eq!(row["sha256"].as_str(), Some(sha(&bytes).as_str()));
    assert_eq!(row["within_bound"].as_bool(), Some(true));
    let KagemushaWalletMessageV1::Payment { mut payment } = message else {
        unreachable!()
    };
    while norito::encode_canonical(&payment).unwrap().len() < 9_995 {
        payment.send.step_proof.bytes.push(0);
    }
    assert!(norito::encode_canonical(&payment).unwrap().len() <= 10_000);
    assert!(
        std::panic::catch_unwind(|| record(
            directory.path(),
            "oversized",
            KagemushaWalletMessageV1::Payment { payment }
        ))
        .is_err()
    );
    let measured: norito::json::Value = norito::json::from_slice(
        &fs::read(directory.path().join("oversized.measurement.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(measured["within_bound"].as_bool(), Some(false));
    assert!(measured["bytes"].as_u64().unwrap() > 10_000);
    assert_eq!(
        measured["bytes"].as_u64(),
        Some(
            fs::metadata(directory.path().join("oversized.envelope.norito"))
                .unwrap()
                .len()
        )
    );
}
