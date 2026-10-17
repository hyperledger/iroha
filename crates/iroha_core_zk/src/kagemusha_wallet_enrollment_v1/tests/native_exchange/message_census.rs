//! Exact complete-envelope evidence from genuine retained exchange originals.
//!
//! The census never opens wallet custody or signs an operation. Proof verification uses
//! the independently admitted catalog; historical producer identity stays separate from
//! this observer. Only observed variants qualify, never unexecuted controls or carriers.

use super::*;

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
    payments: [&[u8]; 2],
    acknowledgements: [&[u8]; 2],
) -> Vec<norito::json::Value> {
    let verifier = sources.installed.verifier();
    let mut records = Vec::new();
    let mut originals = Vec::new();
    for ((name, original), acknowledgement) in ["a-b", "b-c"]
        .into_iter()
        .zip(payments)
        .zip(acknowledgements)
    {
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
        originals.push((name, payment, credited));
    }
    // Record carrying frames before expensive proof verification. Failed proofs
    // retain their exact originals and decisions; they never become census success.
    let mut proof_checks = Vec::new();
    let mut all_proofs_verified = true;
    for (name, payment, credited) in originals {
        let payment_result = verifier.verify_package_proofs(
            &payment.send,
            Some(&payment.signed_request().unwrap().body),
            MemoryBudget::DEFAULT,
        );
        let (credited_scope, credited_result) = match &credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => (
                "Receive Sigma proof; request-body selector only",
                verifier.verify_package_proofs(
                    package,
                    Some(&payment.signed_request().unwrap().body),
                    MemoryBudget::DEFAULT,
                ),
            ),
            KagemushaWalletCreditedEvidenceV1::Status { status } => (
                "CreditStatus Omega lineage only; no credit-membership or request linkage verdict",
                verifier.verify_lineage(&status.lineage, MemoryBudget::DEFAULT),
            ),
        };
        all_proofs_verified &= payment_result.is_ok() && credited_result.is_ok();
        proof_checks.push(norito::json!({
            "pair": name,
            "payment_proof_scope": "Send Sigma and predecessor Omega proofs; request-body selector only",
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

#[test]
#[ignore = "read-only genuine-original census; requires admitted catalog and an independently pinned four-original manifest"]
fn remeasure_retained_genuine_exchange_envelopes_without_wallet_mutation() {
    let output = fresh_output("KAGEMUSHA_NATIVE_MESSAGE_CENSUS_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let input = selected_path("KAGEMUSHA_NATIVE_MESSAGE_ORIGINALS");
    let original = read_pin(
        &input,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_MESSAGE_ORIGINALS_SHA256"),
    );
    let manifest: norito::json::Value = norito::json::from_slice(&original).unwrap();
    assert_eq!(
        manifest["schema"].as_str(),
        Some("iroha.kagemusha.message-originals.v1")
    );
    assert_eq!(manifest["source_pins"], source_pins());
    let rows = manifest["originals"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let files = norito::json!({"files": (rows.clone())});
    let bytes = [
        "a-b-payment.norito",
        "b-c-payment.norito",
        "a-credited-receive.norito",
        "b-credited-status.norito",
    ]
    .map(|name| target_original(input.parent().unwrap(), &files, name, 10_000));
    let records = retain(
        &output,
        &sources,
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
        "scope": "Exact retained canonical envelopes with Sigma/Omega proof verification against admitted catalog. CreditStatus check covers only Omega, not credit membership or request linkage. No new native message/operation admission, fresh lifecycle, all policy variants, carrier timings or current-producer qualification."
    })).unwrap());
}

fn fixture_payment() -> KagemushaWalletMessageV1 {
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
        .find(|row| row["kind"].as_str() == Some("Payment"))
        .unwrap();
    let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    decode::<KagemushaWalletEnvelopeV1>(&frame).message
}

#[test]
fn message_census_records_complete_frame_and_retains_oversize_failure() {
    let directory = tempfile::tempdir().unwrap();
    let message = fixture_payment();
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
