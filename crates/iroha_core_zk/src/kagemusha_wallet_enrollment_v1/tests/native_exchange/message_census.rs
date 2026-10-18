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
    let role = match &message {
        KagemushaWalletMessageV1::Offer { .. } => "Offer",
        KagemushaWalletMessageV1::Request { .. } => "Request",
        KagemushaWalletMessageV1::Payment { .. } => "Payment",
        KagemushaWalletMessageV1::Credited { .. } => "Credited",
        KagemushaWalletMessageV1::SessionControl { .. } => "SessionControl",
        KagemushaWalletMessageV1::PolicyData { .. } => "PolicyData",
        KagemushaWalletMessageV1::Lineage { .. } => "Lineage",
    };
    let variant = match &message {
        KagemushaWalletMessageV1::Credited { credited } => match &credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { .. } => "Credited::Receive",
            KagemushaWalletCreditedEvidenceV1::Status { .. } => "Credited::Status",
        },
        _ => role,
    };
    let maximum = message.max_bytes();
    let scheme = *message.scheme_id();
    let tag = message.tag();
    let envelope = KagemushaWalletEnvelopeV1::new(message);
    // Retain even an oversized frame before refusing it: a payload length alone must
    // never qualify the larger carrying envelope, and failed measurements are evidence.
    let frame = norito::encode_canonical(&envelope).unwrap();
    let filename = format!("{name}.envelope.norito");
    let result = norito::json!({
        "name": filename, "role": role, "variant": variant, "tag": tag, "bytes": (frame.len()),
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

pub(super) fn record_payment_lineage(
    output: &Path,
    label: &str,
    payment: &KagemushaWalletPaymentV1,
) -> norito::json::Value {
    let lineage = payment
        .send
        .lineage
        .lineage()
        .expect("Send predecessor Omega")
        .clone();
    record(
        output,
        &format!("{label}-lineage"),
        KagemushaWalletMessageV1::Lineage {
            lineage: KagemushaWalletLineageMessageV1::new(lineage),
        },
    )
}

fn record_credit_status_model(
    output: &Path,
    name: &str,
    scheme: &KagemushaWalletSchemeV1,
    status: &KagemushaWalletCreditStatusV1,
    request_original: &[u8],
    payment_original: &[u8],
) -> (norito::json::Value, bool) {
    let credited = KagemushaWalletCreditedV1::from_status(status.clone()).unwrap();
    let envelope = record(
        output,
        name,
        KagemushaWalletMessageV1::Credited {
            credited: credited.clone(),
        },
    );
    let request: KagemushaWalletRequestV1 = decode(request_original);
    let payment: KagemushaWalletPaymentV1 = decode(payment_original);
    let model_result = credited.verify_for(scheme, &request, &payment);
    let verified = model_result.is_ok();
    let result = norito::json!({
        "complete_envelope": envelope,
        "request_sha256": (sha(request_original)),
        "payment_sha256": (sha(payment_original)),
        "credit_status_sha256": (sha(&norito::encode_canonical(status).unwrap())),
        "receiver_wallet_id": (hex::encode(status.lineage.public.wallet_id)),
        "folded_head": (hex::encode(status.lineage.public.head.value)),
        "status_opening": (if status.opening.burned { "burned" } else { "unburned" }),
        "model_verification_result": (format!("{model_result:?}")),
        "model_verified": verified,
        "scope": "Canonical Credited::Status carrying frame and model linkage to exact held Request and Payment. No Omega proof or native operation verdict.",
    });
    publish(
        &output.join(format!("{name}.model-check.json")),
        &norito::json::to_vec(&result).unwrap(),
    );
    (result, verified)
}

pub(super) fn retain_credit_status(
    output: &Path,
    name: &str,
    sources: &Sources,
    status: &KagemushaWalletCreditStatusV1,
    request_original: &[u8],
    payment_original: &[u8],
) -> norito::json::Value {
    let verifier = sources.installed.verifier();
    // Preserve the carrying frame and model decision before the installed Omega
    // check, including a failed proof decision before refusing this capture.
    let (model, model_verified) = record_credit_status_model(
        output,
        name,
        verifier.scheme(),
        status,
        request_original,
        payment_original,
    );
    let proof_result = verifier.verify_lineage(&status.lineage, MemoryBudget::DEFAULT);
    let proof_verified = proof_result.is_ok();
    let result = norito::json!({
        "model": model,
        "lineage_proof_verification_result": (format!("{proof_result:?}")),
        "lineage_proof_verified": proof_verified,
        "scope": "Existing folded receiver CreditStatus in its real Credited::Status envelope, exact Request/Payment model linkage and installed Omega proof verification. No new monetary operation, acknowledgement admission or carrier qualification.",
    });
    publish(
        &output.join(format!("{name}.proof-check.json")),
        &norito::json::to_vec(&result).unwrap(),
    );
    assert!(
        model_verified && proof_verified,
        "retained CreditStatus check failed"
    );
    result
}

// This inventory describes retained frames, not delivery or proof acceptance. Require
// every actual role once so a partial or duplicated measurement cannot imply coverage.
pub(super) fn complete_exchange_roles(
    records: &[norito::json::Value],
    label: &str,
) -> norito::json::Value {
    let roles = [
        ("Offer", "offer", 1),
        ("Request", "request", 2),
        ("Payment", "payment", 3),
        ("Credited", "credited", 4),
        ("Lineage", "lineage", 7),
    ];
    let envelopes = roles
        .into_iter()
        .map(|(role, suffix, tag)| {
            let name = format!("{label}-{suffix}.envelope.norito");
            let matches = records
                .iter()
                .filter(|row| row["name"].as_str() == Some(name.as_str()))
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "exactly one {label} {role} frame");
            let row = matches[0];
            assert_eq!(row["role"].as_str(), Some(role));
            assert_eq!(row["tag"].as_u64(), Some(tag));
            assert_eq!(row["within_bound"].as_bool(), Some(true));
            row.clone()
        })
        .collect::<Vec<_>>();
    norito::json!({
        "variant": label, "complete_envelopes": envelopes,
        "scope": "Exactly five retained carrying-frame roles; proof and native-operation verdicts remain separate",
    })
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
        records.push(record_payment_lineage(output, name, &payment));
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
        let credited_model_result = credited.verify_for(verifier.scheme(), &request, &payment);
        let payment_result = verifier.verify_package_proofs(&payment.send, MemoryBudget::DEFAULT);
        let (credited_scope, credited_result) = match &credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => (
                "Receive Sigma proof only",
                verifier.verify_package_proofs(package, MemoryBudget::DEFAULT),
            ),
            KagemushaWalletCreditedEvidenceV1::Status { status } => (
                "CreditStatus Omega lineage proof only; model linkage is checked separately",
                verifier.verify_lineage(&status.lineage, MemoryBudget::DEFAULT),
            ),
        };
        all_proofs_verified &= session_result.is_ok()
            && credited_model_result.is_ok()
            && payment_result.is_ok()
            && credited_result.is_ok();
        proof_checks.push(norito::json!({
            "pair": name,
            "session_verification_scope": "Offer signature, payer credential and issuer; exact signed Request and its receiver credential, certificates and fee schedule; Payment model binding to those session originals",
            "session_verification_result": (format!("{session_result:?}")),
            "credited_model_scope": "Canonical Credited::verify_for against the exact held Request and retained Payment: Receive receipt signature and credit/Payment/asset linkage, or CreditStatus receipt, membership opening and receiver/credit/Payment linkage; no native operation admission",
            "credited_model_result": (format!("{credited_model_result:?}")),
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
    for name in ["a-b", "b-c"] {
        complete_exchange_roles(&records, name);
    }
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

// Producer capture pins bind exact session identity beyond Payment's protocol fields.
pub(super) fn require_selected_send_session(
    offer: &[u8],
    request: &[u8],
    selected_send: &norito::json::Value,
) {
    assert_eq!(
        selected_send["retained_offer_sha256"].as_str(),
        Some(sha(offer).as_str()),
        "census Offer differs from the original selected-Send capture"
    );
    assert_eq!(
        selected_send["retained_request_sha256"].as_str(),
        Some(sha(request).as_str()),
        "census Request differs from the original selected-Send capture"
    );
}

pub(super) fn require_manifest_continuity(
    manifest: &[u8],
    prior_continuation: &norito::json::Value,
) {
    assert_eq!(
        prior_continuation["message_originals_manifest_sha256"].as_str(),
        Some(sha(manifest).as_str()),
        "census manifest differs from the retained archive continuation"
    );
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
        "complete_exchange_roles": (["a-b", "b-c"].into_iter().map(|name| complete_exchange_roles(&records, name)).collect::<Vec<_>>()),
        "new_wallet_operations": 0, "physical_device_qualified": false,
        "scope": "Exact retained canonical Offer/Request/Payment/Credited/Lineage envelopes with authenticated session originals, canonical Credited model linkage and separate Sigma/Omega proof verification against admitted catalog. No new native message/operation admission, fresh lifecycle, all policy variants, carrier timings or current-producer qualification."
    })).unwrap());
}

fn fixture_message(variant: &str) -> KagemushaWalletMessageV1 {
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
        .find(|row| row["variant"].as_str() == Some(variant))
        .unwrap();
    let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    decode::<KagemushaWalletEnvelopeV1>(&frame).message
}

fn fixture_scheme() -> KagemushaWalletSchemeV1 {
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
    decode(&hex::decode(scheme_row["canonical_hex"].as_str().unwrap()).unwrap())
}

// Re-sign a changed stand-in proof so the replacement remains model-valid. A
// status must reject its different Payment digest even though its receipt verifies.
fn changed_fixture_payment(
    payment: &KagemushaWalletPaymentV1,
    credential: &KagemushaWalletCredentialV1,
) -> KagemushaWalletPaymentV1 {
    use p256::ecdsa::signature::Signer as _;

    assert_eq!(credential.body.payment_key, public_key(&signing_key(0x51)));
    let mut changed = payment.clone();
    changed.send.step_proof.bytes[0] ^= 1;
    let proof_digest = changed.send.proof_digest().unwrap();
    let signer = KagemushaWalletReceiptSignerV1::from_credential(credential).unwrap();
    let receipt = &changed.send.receipt;
    let body = KagemushaWalletReceiptBodyV1::derive(
        &signer,
        &changed.send.statement,
        &proof_digest,
        receipt.capsule_commitment,
        receipt.payment_digest,
    )
    .unwrap();
    let signature: p256::ecdsa::Signature = signing_key(0x51).sign(&body.signing_message());
    changed.send.receipt = KagemushaWalletReceiptV1::sign(
        credential,
        &changed.send.statement,
        &proof_digest,
        receipt.capsule_commitment,
        receipt.payment_digest,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    changed.validate().unwrap();
    changed
}

#[test]
fn message_census_final_status_retains_exact_frame_and_rejects_valid_substitutions() {
    use p256::ecdsa::signature::Signer as _;

    // Fixture signatures exercise model linkage, never genuine Omega acceptance.
    let directory = tempfile::tempdir().unwrap();
    let scheme = fixture_scheme();
    let KagemushaWalletMessageV1::Offer { offer } = fixture_message("Offer") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Request { request } = fixture_message("Request") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Payment { payment } = fixture_message("Payment") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Credited { credited } = fixture_message("Credited::Status")
    else {
        unreachable!()
    };
    let KagemushaWalletCreditedEvidenceV1::Status { status } = &credited.evidence else {
        unreachable!()
    };
    let request_bytes = norito::encode_canonical(&request).unwrap();
    let payment_bytes = norito::encode_canonical(&payment).unwrap();
    let (measured, verified) = record_credit_status_model(
        directory.path(),
        "final-status",
        &scheme,
        status,
        &request_bytes,
        &payment_bytes,
    );
    assert!(verified);
    assert_eq!(measured["status_opening"].as_str(), Some("unburned"));
    assert_eq!(
        measured["request_sha256"].as_str(),
        Some(sha(&request_bytes).as_str())
    );
    assert_eq!(
        measured["payment_sha256"].as_str(),
        Some(sha(&payment_bytes).as_str())
    );
    let frame = fs::read(directory.path().join("final-status.envelope.norito")).unwrap();
    assert_eq!(
        measured["complete_envelope"]["bytes"].as_u64(),
        Some(frame.len() as u64)
    );
    assert_eq!(
        KagemushaWalletEnvelopeV1::decode_canonical(&frame, &scheme.scheme_id())
            .unwrap()
            .message,
        KagemushaWalletMessageV1::Credited {
            credited: credited.clone()
        }
    );

    let mut changed_request = request.clone();
    changed_request.body.nonce[0] ^= 1;
    let signature: p256::ecdsa::Signature =
        signing_key(0x52).sign(&changed_request.body.signing_message());
    let signature = signature.normalize_s().unwrap_or(signature);
    changed_request.signature =
        KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).unwrap();
    changed_request.verify(&scheme).unwrap();

    let changed_payment = changed_fixture_payment(&payment, &offer.payer_credential);
    assert_ne!(
        changed_payment.payment_digest().unwrap(),
        payment.payment_digest().unwrap()
    );
    for (name, request, payment) in [
        (
            "other-request",
            norito::encode_canonical(&changed_request).unwrap(),
            payment_bytes,
        ),
        (
            "other-payment",
            request_bytes,
            norito::encode_canonical(&changed_payment).unwrap(),
        ),
    ] {
        let (refused, verified) =
            record_credit_status_model(directory.path(), name, &scheme, status, &request, &payment);
        assert!(!verified);
        assert_eq!(refused["model_verified"].as_bool(), Some(false));
        assert_eq!(
            fs::read(directory.path().join(format!("{name}.envelope.norito"))).unwrap(),
            frame
        );
        let retained: norito::json::Value = norito::json::from_slice(
            &fs::read(directory.path().join(format!("{name}.model-check.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(retained, refused);
    }
}

#[test]
fn message_census_status_metadata_distinguishes_burned_fixture_without_proof_claim() {
    let directory = tempfile::tempdir().unwrap();
    let scheme = fixture_scheme();
    let KagemushaWalletMessageV1::Request { request } = fixture_message("Request") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Payment { payment } = fixture_message("Payment") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Credited { credited } = fixture_message("Credited::Status")
    else {
        unreachable!()
    };
    let KagemushaWalletCreditedEvidenceV1::Status { mut status } = credited.evidence else {
        unreachable!()
    };
    // A changed model opening/root has no matching genuine Omega proof. This test
    // checks only metadata; retain_credit_status separately requires that proof.
    status.opening.burned = true;
    status.lineage.public.credit_digest_root = status.opening.root().unwrap();
    let (measured, verified) = record_credit_status_model(
        directory.path(),
        "burned-fixture",
        &scheme,
        &status,
        &norito::encode_canonical(&request).unwrap(),
        &norito::encode_canonical(&payment).unwrap(),
    );
    assert!(verified);
    assert_eq!(measured["status_opening"].as_str(), Some("burned"));
    assert!(
        measured
            .as_object()
            .unwrap()
            .get("lineage_proof_verified")
            .is_none()
    );
}

#[test]
fn message_census_credited_binds_both_forms_to_exact_request_and_payment() {
    use p256::ecdsa::signature::Signer as _;

    // These fixture signatures and membership openings test model linkage only.
    // Their proof stand-ins cannot satisfy the separate installed proof checks.
    let scheme = fixture_scheme();
    let KagemushaWalletMessageV1::Request { request } = fixture_message("Request") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Payment { payment } = fixture_message("Payment") else {
        unreachable!()
    };
    let mut replacement_request = request.clone();
    replacement_request.body.nonce[0] ^= 1;
    let signature: p256::ecdsa::Signature =
        signing_key(0x52).sign(&replacement_request.body.signing_message());
    let signature = signature.normalize_s().unwrap_or(signature);
    replacement_request.signature =
        KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).unwrap();
    replacement_request.verify(&scheme).unwrap();
    for variant in ["Credited::Receive", "Credited::Status"] {
        let KagemushaWalletMessageV1::Credited { credited } = fixture_message(variant) else {
            unreachable!()
        };
        credited.verify_for(&scheme, &request, &payment).unwrap();
        assert!(
            credited
                .verify_for(&scheme, &replacement_request, &payment)
                .is_err()
        );

        // Both delivery forms bind the exact retained Payment digest. Mutating the
        // evidence cannot turn an unrelated receipt/opening into that acknowledgement.
        let mut changed = credited.clone();
        match &mut changed.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => {
                package.receipt.payment_digest[0] ^= 1;
            }
            KagemushaWalletCreditedEvidenceV1::Status { status } => {
                status.opening.payment_digest[0] ^= 1;
            }
        }
        assert!(changed.verify_for(&scheme, &request, &payment).is_err());
    }
}

#[test]
fn message_census_requires_five_distinct_bounded_exchange_roles() {
    let directory = tempfile::tempdir().unwrap();
    let mut records = Vec::new();
    for (suffix, variant) in [
        ("offer", "Offer"),
        ("request", "Request"),
        ("payment", "Payment"),
        ("credited", "Credited::Receive"),
    ] {
        records.push(record(
            directory.path(),
            &format!("fixture-{suffix}"),
            fixture_message(variant),
        ));
    }
    let KagemushaWalletMessageV1::Payment { payment } = fixture_message("Payment") else {
        unreachable!()
    };
    records.push(record_payment_lineage(
        directory.path(),
        "fixture",
        &payment,
    ));
    let lineage_frame = fs::read(directory.path().join("fixture-lineage.envelope.norito")).unwrap();
    let KagemushaWalletMessageV1::Lineage { lineage } =
        decode::<KagemushaWalletEnvelopeV1>(&lineage_frame).message
    else {
        unreachable!()
    };
    assert_eq!(&lineage.lineage, payment.send.lineage.lineage().unwrap());
    let inventory = complete_exchange_roles(&records, "fixture");
    assert_eq!(inventory["complete_envelopes"].as_array().unwrap().len(), 5);
    assert_eq!(records[3]["variant"].as_str(), Some("Credited::Receive"));
    for index in 0..records.len() {
        let mut missing = records.clone();
        missing.remove(index);
        assert!(std::panic::catch_unwind(|| complete_exchange_roles(&missing, "fixture")).is_err());
        let mut duplicated = records.clone();
        duplicated.push(records[index].clone());
        assert!(
            std::panic::catch_unwind(|| complete_exchange_roles(&duplicated, "fixture")).is_err()
        );
        for (field, value) in [
            ("role", norito::json!("foreign")),
            ("tag", norito::json!(99)),
            ("within_bound", norito::json!(false)),
        ] {
            let mut changed = records.clone();
            changed[index]
                .as_object_mut()
                .unwrap()
                .insert(field.into(), value);
            assert!(
                std::panic::catch_unwind(|| complete_exchange_roles(&changed, "fixture")).is_err()
            );
        }
    }
}

#[test]
fn message_census_authenticates_session_originals_and_rejects_substitution() {
    use p256::ecdsa::signature::Signer as _;

    // Real fixture signatures exercise model admission; the fixture's stand-in
    // financial proofs are deliberately never passed to the genuine census.
    let scheme = fixture_scheme();
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
    let KagemushaWalletMessageV1::Credited { credited } = fixture_message("Credited::Receive")
    else {
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
fn message_census_recovery_pins_reject_valid_offer_and_manifest_substitution() {
    use p256::ecdsa::signature::Signer as _;

    let scheme = fixture_scheme();
    let KagemushaWalletMessageV1::Offer { offer } = fixture_message("Offer") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Request { request } = fixture_message("Request") else {
        unreachable!()
    };
    let KagemushaWalletMessageV1::Payment { payment } = fixture_message("Payment") else {
        unreachable!()
    };
    let offer_bytes = norito::encode_canonical(&offer).unwrap();
    let request_bytes = norito::encode_canonical(&request).unwrap();
    let selected = norito::json!({
        "retained_offer_sha256": (sha(&offer_bytes)),
        "retained_request_sha256": (sha(&request_bytes)),
    });
    require_selected_send_session(&offer_bytes, &request_bytes, &selected);

    // The same payer can sign another valid Offer nonce. Payment deliberately binds
    // the payer credential, not this nonce: only the capture pin rejects substitution.
    // Fixture proof stand-ins remain outside the genuine-proof census.
    let mut substitute = offer.clone();
    substitute.body.session_nonce[0] ^= 1;
    assert_eq!(
        public_key(&signing_key(0x51)),
        offer.payer_credential.body.payment_key
    );
    let signature: p256::ecdsa::Signature =
        signing_key(0x51).sign(&substitute.body.signing_message());
    let signature = signature.normalize_s().unwrap_or(signature);
    substitute.signature =
        KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).unwrap();
    verify_session(&scheme, &substitute, &request, &payment).unwrap();
    let substitute = norito::encode_canonical(&substitute).unwrap();
    assert_ne!(substitute, offer_bytes);
    assert!(
        std::panic::catch_unwind(|| require_selected_send_session(
            &substitute,
            &request_bytes,
            &selected,
        ))
        .is_err()
    );
    let mut foreign_request = request_bytes.clone();
    foreign_request.push(0);
    assert!(
        std::panic::catch_unwind(|| require_selected_send_session(
            &offer_bytes,
            &foreign_request,
            &selected,
        ))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| require_selected_send_session(
            &offer_bytes,
            &request_bytes,
            &norito::json!({}),
        ))
        .is_err()
    );

    // The first continuation selects one exact manifest. A restarted continuation
    // cannot silently replace it, even with another separately pinned input.
    let manifest = b"exact retained census manifest";
    let prior = norito::json!({"message_originals_manifest_sha256": (sha(manifest))});
    require_manifest_continuity(manifest, &prior);
    assert!(
        std::panic::catch_unwind(|| require_manifest_continuity(
            b"replacement census manifest",
            &prior,
        ))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| require_manifest_continuity(manifest, &norito::json!({}),))
            .is_err()
    );
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
        let object = changed.as_object_mut().unwrap();
        if mutation < 2 {
            let (field, value) = if mutation == 0 {
                ("source_pins", norito::json!({"test_source":"foreign"}))
            } else {
                ("originals", norito::json!(rows[..7].to_vec()))
            };
            object.insert(field.into(), value);
        } else {
            let changed_rows = object.get_mut("originals").unwrap().as_array_mut().unwrap();
            if mutation == 2 {
                changed_rows[7] = changed_rows[6].clone();
            } else {
                let (field, value) = match mutation {
                    3 => ("name", "foreign.norito".into()),
                    4 => ("bytes", 99_u64.into()),
                    5 => ("sha256", sha(b"foreign").into()),
                    _ => unreachable!(),
                };
                changed_rows[7]
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), value);
            }
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
