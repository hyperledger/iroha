//! Exact preparation, packet and actual Python protocol DATA regressions.

use super::*;

#[test]
fn current_revocation_reply_is_fresh_bound_and_cannot_issue_enrollment_evidence() {
    let request = fixture(false);
    let exchange = request.packet(ActionV1::RecheckRevocation, [10; 32], [19; 32], 700_000).unwrap();
    let current = reply(&exchange, "current", Value::Null);
    assert_eq!(request.revocation_response(&exchange, &framed(&current)).unwrap(), RevocationOutcomeV1::Current);
    assert!(request.response(&exchange, &framed(&current)).is_err());
    for field in ["exchange_id", "request_sha256", "journal_incarnation", "config_sha256"] {
        let mut substituted = current.clone();
        change(&mut substituted, field, Value::from(hex::encode([0; 32])));
        assert!(request.revocation_response(&exchange, &framed(&substituted)).is_err());
    }
    let other = request.packet(ActionV1::RecheckRevocation, [10; 32], [20; 32], 700_000).unwrap();
    assert!(request.revocation_response(&other, &framed(&current)).is_err());
    let inspect = request.packet(ActionV1::Inspect, [10; 32], [19; 32], 700_000).unwrap();
    assert!(request.revocation_response(&inspect, &framed(&reply(&inspect, "current", Value::Null))).is_err());
    assert_eq!(request.revocation_response(&exchange, &framed(&reply(&exchange, "unavailable", Value::Null))).unwrap(), RevocationOutcomeV1::Unavailable);
    let mut refused = reply(&exchange, "refused", Value::Null);
    change(&mut refused, "refusal_code", Value::from(6_u16));
    assert_eq!(request.revocation_response(&exchange, &framed(&refused)).unwrap(), RevocationOutcomeV1::Revoked);
    change(&mut refused, "refusal_code", Value::from(9_u16));
    assert!(request.revocation_response(&exchange, &framed(&refused)).is_err());
    for outcome in ["evidence", "prepared", "outcome_unknown", "rejected"] {
        assert!(request.revocation_response(&exchange, &framed(&reply(&exchange, outcome, Value::Null))).is_err());
    }
    assert!(request.revocation_response(&exchange, &framed(&reply(&exchange, "current", Value::from("Zg==")))).is_err());
    let apple = fixture(true);
    let apple_exchange = apple.packet(ActionV1::RecheckRevocation, [10; 32], [19; 32], 700_000).unwrap();
    assert!(apple.revocation_response(&apple_exchange, &framed(&reply(&apple_exchange, "current", Value::Null))).is_err());
}

#[test]
fn preparation_retains_exact_account_owner_and_rejects_changed_subjects() {
    for apple in [false, true] {
        let request = fixture(apple);
        let selected = dispatch(&request.request);
        let preparation = &request.preparation;
        let value = decode(preparation.original(), 16 * 1024).unwrap();
        assert_eq!(preparation.configuration(), [7; 32]);
        assert_eq!(
            text(&value, "schema").unwrap(),
            "iroha.kagemusha.wallet-e1-worker-preparation.v1"
        );
        assert_eq!(
            binary(text(&value, "account_original_base64").unwrap(), 4096).unwrap(),
            norito::encode_canonical(&selected.account).unwrap()
        );
        assert_eq!(
            digest(&value, "account_owner_public_hex")
                .unwrap()
                .as_slice(),
            selected.account.try_signatory().unwrap().to_bytes().1
        );
        assert_eq!(
            digest(&value, "operation_id").unwrap(),
            request.request.body.challenge.challenge_digest()
        );
        assert_eq!(
            prepare(&request.request, 1_000, [7; 32])
                .unwrap()
                .original(),
            preparation.original()
        );
        assert!(prepare(&request.request, 1_000, [0; 32]).is_err());
        for offset in 0..6 {
            let mut challenge = request.request.body.challenge;
            match offset {
                0 => challenge.scheme_id[0] ^= 1,
                1 => challenge.asset_digest[0] ^= 1,
                2 => challenge.account_digest[0] ^= 1,
                3 => challenge.app_policy[0] ^= 1,
                4 => challenge.enrollment_policy[0] ^= 1,
                _ => challenge.issuer_nonce = [0; 32],
            }
            assert!(
                VerifierPreparationV1::from_selected(&selected, challenge, 1_000, [7; 32]).is_err()
            );
        }
        let mut other = selected;
        other.account = AccountId::new(
            KeyPair::from_seed(vec![44; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        assert!(
            VerifierPreparationV1::from_selected(
                &other,
                request.request.body.challenge,
                1_000,
                [7; 32]
            )
            .is_err()
        );
    }
}

#[test]
fn journal_and_prepare_replies_bind_every_exact_packet_field() {
    let request = fixture(false);
    let journal = VerifierExchangeV1::journal([7; 32], [9; 32]).unwrap();
    let prepared = request.preparation.packet([10; 32], [9; 32]).unwrap();
    for (exchange, outcome) in [(&journal, "journal"), (&prepared, "prepared")] {
        let value = reply(exchange, outcome, Value::Null);
        let check = |value: &Value| {
            if outcome == "journal" {
                exchange.journal_response(&framed(value)).map(|_| ())
            } else {
                exchange.prepared_response(&framed(value))
            }
        };
        check(&value).unwrap();
        for field in [
            "exchange_id",
            "request_sha256",
            "journal_incarnation",
            "config_sha256",
        ] {
            let mut wrong = value.clone();
            change(&mut wrong, field, Value::from(hex::encode([0; 32])));
            assert!(check(&wrong).is_err(), "{field}");
        }
        for failure in [
            "outcome_unknown",
            "unavailable",
            "rejected",
            "evidence",
            "refused",
        ] {
            assert!(check(&reply(exchange, failure, Value::Null)).is_err());
        }
        // Journal and Prepare exchanges never refuse an E1 and never carry a code.
        let mut refused = reply(exchange, "refused", Value::Null);
        change(&mut refused, "refusal_code", Value::from(9_u16));
        assert!(check(&refused).is_err());
        let mut coded = value.clone();
        change(&mut coded, "refusal_code", Value::from(9_u16));
        assert!(check(&coded).is_err());
        assert!(check(&reply(exchange, outcome, Value::from("Zg=="))).is_err());
    }
    assert_eq!(
        journal
            .journal_response(&framed(&reply(&journal, "journal", Value::Null)))
            .unwrap(),
        [10; 32]
    );
    assert!(
        journal
            .prepared_response(&framed(&reply(&journal, "prepared", Value::Null)))
            .is_err()
    );
    assert!(
        prepared
            .journal_response(&framed(&reply(&prepared, "journal", Value::Null)))
            .is_err()
    );
    assert!(request.preparation.packet([0; 32], [9; 32]).is_err());
    assert!(VerifierExchangeV1::journal([0; 32], [9; 32]).is_err());
}

#[test]
fn completed_evidence_time_can_precede_recovery_but_not_original_or_future_dispatch() {
    let fixture = fixture(true);
    let request =
        VerifierRequestV1::from_prepared(fixture.request, &fixture.preparation, 1_001).unwrap();
    let mut value = projection(&request);
    change(&mut value, "time_ms", Value::from(1_010_u64));
    let original = encode(&value, MAX_RESULT).unwrap();
    let complete = request
        .packet(ActionV1::Complete, [10; 32], [9; 32], 1_010)
        .unwrap();
    let recover = request
        .packet(ActionV1::Recover, [10; 32], [11; 32], 700_000)
        .unwrap();
    let inspect = request
        .packet(ActionV1::Inspect, [10; 32], [12; 32], 700_000)
        .unwrap();
    for exchange in [&complete, &recover, &inspect] {
        let response = reply(
            exchange,
            "evidence",
            Value::from(STANDARD.encode(&original)),
        );
        let OutcomeV1::Evidence(evidence) = request.response(exchange, &framed(&response)).unwrap()
        else {
            panic!("evidence")
        };
        assert_eq!(evidence.evidence.time_ms, 1_010);
        assert_eq!(evidence.original_result, original);
    }
    assert_eq!(
        request
            .retained_evidence(&original)
            .unwrap()
            .evidence
            .time_ms,
        1_010
    );
    for time in [1_000, 1_011, 601_001, u64::MAX] {
        let mut wrong = value.clone();
        change(&mut wrong, "time_ms", Value::from(time));
        let response = reply(
            &complete,
            "evidence",
            Value::from(STANDARD.encode(encode(&wrong, MAX_RESULT).unwrap())),
        );
        assert!(request.response(&complete, &framed(&response)).is_err());
    }
    assert!(
        request
            .packet(ActionV1::Recover, [10; 32], [9; 32], 1_000)
            .is_err()
    );
}

#[test]
fn inspect_preserves_exact_request_and_distinct_result_classes_after_expiry() {
    for apple in [false, true] {
        let request = fixture(apple);
        let inspect = request
            .packet(ActionV1::Inspect, [10; 32], [9; 32], 700_000)
            .unwrap();
        let packet = decode(&inspect.frame()[4..], MAX_PACKET).unwrap();
        assert_eq!(text(&packet, "action").unwrap(), "inspect");
        assert_eq!(integer(&packet, "dispatch_time_ms").unwrap(), 700_000);
        assert_eq!(
            binary(text(&packet, "original_base64").unwrap(), MAX_REQUEST).unwrap(),
            request.original()
        );
        for outcome in ["unavailable", "outcome_unknown", "refused"] {
            let mut answer = reply(&inspect, outcome, Value::Null);
            if outcome == "refused" {
                change(&mut answer, "refusal_code", Value::from(9_u16));
            }
            let observed = request.response(&inspect, &framed(&answer)).unwrap();
            assert!(matches!(
                (outcome, observed),
                ("unavailable", OutcomeV1::Unavailable)
                    | ("outcome_unknown", OutcomeV1::OutcomeUnknown)
                    | (
                        "refused",
                        OutcomeV1::Refused(KagemushaWalletEnrollmentRefusalV1::EvidenceInvalid)
                    )
            ));
        }
        let original = encode(&projection(&request), MAX_RESULT).unwrap();
        let response = reply(
            &inspect,
            "evidence",
            Value::from(STANDARD.encode(&original)),
        );
        let OutcomeV1::Evidence(observed) = request.response(&inspect, &framed(&response)).unwrap()
        else {
            panic!("retained evidence")
        };
        assert_eq!(observed.original_result, original);
        for field in [
            "exchange_id",
            "request_sha256",
            "journal_incarnation",
            "config_sha256",
        ] {
            let mut wrong = response.clone();
            change(&mut wrong, field, Value::from(hex::encode([3; 32])));
            assert!(
                request.response(&inspect, &framed(&wrong)).is_err(),
                "{field}"
            );
        }
        let changed =
            VerifierRequestV1::from_prepared(request.request.clone(), &request.preparation, 1_001)
                .unwrap();
        assert!(changed.response(&inspect, &framed(&response)).is_err());
        let retry = request
            .packet(ActionV1::Inspect, [10; 32], [11; 32], 700_001)
            .unwrap();
        assert!(request.response(&retry, &framed(&response)).is_err());
        let complete = request
            .packet(ActionV1::Complete, [10; 32], [9; 32], 700_000)
            .unwrap();
        assert!(request.response(&complete, &framed(&response)).is_err());
        assert!(
            request
                .packet(ActionV1::Inspect, [10; 32], [9; 32], 999)
                .is_err()
        );
    }
}

#[test]
fn request_response_refuses_other_request_preparation_and_exchange_kinds() {
    let request = fixture(false);
    let current = exchange(&request, [9; 32]);
    let response = framed(&reply(&current, "unavailable", Value::Null));
    let changed_time =
        VerifierRequestV1::from_prepared(request.request.clone(), &request.preparation, 1_001)
            .unwrap();
    let changed_preparation = prepare(&request.request, 1_001, [7; 32]).unwrap();
    let changed_preparation =
        VerifierRequestV1::from_prepared(request.request.clone(), &changed_preparation, 601_000)
            .unwrap();
    for changed in [&changed_time, &changed_preparation] {
        assert!(changed.response(&current, &response).is_err());
        assert!(
            request
                .response(&exchange(changed, [9; 32]), &response)
                .is_err()
        );
    }
    let journal = VerifierExchangeV1::journal([7; 32], [9; 32]).unwrap();
    let prepared = request.preparation.packet([10; 32], [9; 32]).unwrap();
    for wrong in [&journal, &prepared] {
        assert!(
            request
                .response(wrong, &framed(&reply(wrong, "unavailable", Value::Null)))
                .is_err()
        );
    }
    let wrong_incarnation = request
        .packet(ActionV1::Complete, [11; 32], [9; 32], 601_000)
        .unwrap();
    assert!(
        request
            .response(
                &wrong_incarnation,
                &framed(&reply(&wrong_incarnation, "unavailable", Value::Null))
            )
            .is_err()
    );
    // Packet consistency does not authorize a journal incarnation. The node compares this
    // accessor with its durable selection even if a reply echoes the other incarnation.
    assert_eq!(wrong_incarnation.journal_incarnation(), Some([11; 32]));
    assert_ne!(
        wrong_incarnation.journal_incarnation(),
        current.journal_incarnation()
    );
    let mut matching = reply(&wrong_incarnation, "unavailable", Value::Null);
    change(
        &mut matching,
        "journal_incarnation",
        Value::from(hex::encode([11; 32])),
    );
    assert!(matches!(
        request
            .response(&wrong_incarnation, &framed(&matching))
            .unwrap(),
        OutcomeV1::Unavailable
    ));
    assert_eq!(journal.journal_incarnation(), None);
}

fn vectors() -> Value {
    Value::Array(
        [false, true]
            .into_iter()
            .map(|apple| {
                let request = configuration_tests::selected(apple);
                let config = configuration_tests::configuration(&request);
                let preparation = config
                    .preparation(&dispatch(&request), request.body.challenge, 1_000)
                    .unwrap();
                let worker = config.request(request, &preparation, 1_001).unwrap();
                let journal = config.journal([9; 32]).unwrap();
                let prepare = preparation.packet([10; 32], [11; 32]).unwrap();
                let complete = worker
                    .packet(ActionV1::Complete, [10; 32], [12; 32], 1_010)
                    .unwrap();
                let recover = worker
                    .packet(ActionV1::Recover, [10; 32], [13; 32], 700_000)
                    .unwrap();
                let inspect_missing = worker
                    .packet(ActionV1::Inspect, [10; 32], [14; 32], 1_010)
                    .unwrap();
                let inspect_prepared = worker
                    .packet(ActionV1::Inspect, [10; 32], [15; 32], 1_010)
                    .unwrap();
                let inspect_claimed = worker
                    .packet(ActionV1::Inspect, [10; 32], [16; 32], 700_000)
                    .unwrap();
                let exchanges = [
                    (&journal, "journal"),
                    (&inspect_missing, "unavailable"),
                    (&prepare, "prepared"),
                    (&inspect_prepared, "unavailable"),
                    (&complete, "unavailable"),
                    (&recover, "outcome_unknown"),
                    (&inspect_claimed, "outcome_unknown"),
                ];
                let packets = exchanges
                    .iter()
                    .map(|(e, _)| Value::from(STANDARD.encode(e.frame())))
                    .collect::<Vec<_>>();
                let responses = exchanges
                    .iter()
                    .map(|(e, outcome)| {
                        Value::from(STANDARD.encode(framed(&reply_with(
                            config.digest(),
                            e,
                            outcome,
                            Value::Null,
                        ))))
                    })
                    .collect::<Vec<_>>();
                norito::json!({
                    "platform": (if apple { "apple" } else { "android" }),
                    "configuration_base64": (STANDARD.encode(config.original())),
                    "preparation_base64": (STANDARD.encode(preparation.original())),
                    "request_base64": (STANDARD.encode(worker.original())),
                    "packets_base64": (packets), "responses_base64": (responses),
                    "authority": "unadmitted DATA and exact protocol consistency only",
                })
            })
            .collect(),
    )
}

#[test]
fn private_prepared_exchange_shared_vectors_match_native_packets() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/wallet_enrollment_worker_exchange_v1.json");
    let retained: Value = json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(retained, vectors());
}

#[test]
fn rust_packets_drive_actual_python_prepare_claim_and_recovery_protocol() {
    use std::{
        io::Write as _,
        process::{Command, Stdio},
    };
    // This uses the real private parser, policy projection, explicit store initializer,
    // prepared claim and serving loop. Fixed test clock samples and an external verifier
    // returning Unavailable keep this platform-independent protocol fixture deterministic;
    // neither Linux clock/launch qualification nor attestation admission is claimed.
    const SCRIPT: &str = r#"
import base64, hashlib, io, json, os, pathlib, sys, tempfile
from unittest.mock import patch
from iroha_app_attestation import wallet_enrollment_worker as w
from iroha_app_attestation import wallet_enrollment_store as store
results = []
for vector in json.load(sys.stdin):
    raw = base64.b64decode(vector['configuration_base64'], validate=True)
    config = w.exact_json(raw, w.MAX_CONFIG)
    with tempfile.TemporaryDirectory(dir=sys.argv[1]) as path:
        path = pathlib.Path(path).resolve(strict=True)
        fd = os.open(path, os.O_RDONLY)
        with patch.object(store.os, 'urandom', return_value=bytes([10])*32):
            counters = store.E1CounterStore.initialize(path, fd)
        owner = object.__new__(w.VerifierOwner)
        owner.counters = counters
        owner.config_digest = hashlib.sha256(raw).digest()
        owner.platform = config['platform']
        owner.app_policy = bytes.fromhex(config['app_policy_hex'])
        owner.enrollment_policy = bytes.fromhex(config['enrollment_policy_hex'])
        owner.policy = w.configured_policy(config['policy'], owner.platform)
        owner.recheck = counters.recheck
        owner.openssl = pathlib.Path('/unadmitted-DATA/openssl')
        owner.current_time = None
        calls = []
        def unavailable(*args, **kwargs):
            calls.append(1)
            raise w.VerificationUnavailable('protocol test unavailable')
        try:
            preparation = base64.b64decode(vector['preparation_base64'], validate=True)
            original = base64.b64decode(vector['request_base64'], validate=True)
            owner.preparation(preparation)
            owner.request(original)
            packets = [base64.b64decode(x, validate=True) for x in vector['packets_base64']]
            output = io.BytesIO()
            complete = next(json.loads(packet[4:]) for packet in packets
                            if json.loads(packet[4:])['action'] == 'complete')
            # Protocol DATA uses a deterministic live clock; separate worker tests enforce
            # actual Linux CLOCK_BOOTTIME availability, suspension, regression and expiry.
            with patch.object(w, '_sleep_inclusive_ns', return_value=3_000_000_000), \
                    patch.object(w, '_realtime_ns', return_value=complete['dispatch_time_ms'] * 1_000_000), \
                    patch.object(w, 'verify_android_wallet_enrollment', unavailable), \
                    patch.object(w, 'verify_apple_wallet_attestation_raw', unavailable):
                w.serve(owner, io.BytesIO(b''.join(packets)), output)
            assert calls == [1], 'inspection claimed an operation or recovery repeated verification'
            data = output.getvalue()
            frames = []
            while data:
                length = int.from_bytes(data[:4], 'little')
                assert len(data) >= length + 4
                frames.append(base64.b64encode(data[:length+4]).decode())
                data = data[length+4:]
            results.append(frames)
        finally:
            counters.close()
            os.close(fd)
json.dump(results, sys.stdout, separators=(',', ':'))
"#;
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let temporary_root = repo.join("target/qualification/issuer-worker-protocol-runtime");
    std::fs::create_dir_all(&temporary_root).unwrap();
    let temporary = tempfile::Builder::new()
        .prefix("python-")
        .tempdir_in(&temporary_root)
        .unwrap();
    let vectors = vectors();
    let mut child = Command::new("python3")
        .args(["-B", "-c", SCRIPT])
        .arg(temporary.path())
        .env("PYTHONPATH", repo.join("python/iroha_app_attestation/src"))
        .env("TMPDIR", temporary.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&json::to_vec(&vectors).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let received: Value = json::from_slice(&result.stdout).unwrap();
    let expected = Value::Array(
        vectors
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["responses_base64"].clone())
            .collect(),
    );
    assert_eq!(received, expected);
}

#[test]
#[ignore = "explicit maintenance capture of current unadmitted private exchange DATA"]
fn regenerate_private_prepared_exchange_shared_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/wallet_enrollment_worker_exchange_v1.json");
    std::fs::write(path, json::to_vec(&vectors()).unwrap()).unwrap();
}

#[test]
fn bounded_preparation_preserves_shortened_session_deadline_and_rejects_extensions() {
    for apple in [false, true] {
        let request = fixture(apple);
        let selected = dispatch(&request.request);
        let challenge = request.request.body.challenge;
        let maximum = 1_000 + selected.policy.challenge_lifetime_ms;
        for expires in [1_001, 2_000, maximum] {
            let prepared = VerifierPreparationV1::from_selected_bounded(
                &selected, challenge, 1_000, expires, [7; 32],
            )
            .unwrap();
            let value = decode(prepared.original(), 16 * 1024).unwrap();
            assert_eq!(integer(&value, "expires_at_ms").unwrap(), expires);
            let captured =
                VerifierRequestV1::from_prepared(request.request.clone(), &prepared, expires - 1)
                    .unwrap();
            for time in [expires, expires + 1, u64::MAX] {
                assert!(
                    VerifierRequestV1::from_prepared(request.request.clone(), &prepared, time)
                        .is_err()
                );
            }
            // Recovery reconstructs the original captured time, never the later retry time.
            let restored =
                VerifierRequestV1::from_prepared(request.request.clone(), &prepared, expires - 1)
                    .unwrap();
            assert_eq!(restored.original(), captured.original());
        }
        for expires in [0, 999, 1_000, maximum + 1, u64::MAX] {
            assert!(
                VerifierPreparationV1::from_selected_bounded(
                    &selected, challenge, 1_000, expires, [7; 32]
                )
                .is_err()
            );
        }
    }
}
