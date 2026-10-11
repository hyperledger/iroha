//! Private boundary mutation tests with unadmitted DATA; no device-attestation claims.
use super::*;
use crate::kagemusha_wallet_enrollment_v1::RequestBodyV1;
use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
use iroha_data_model::{
    account::AccountId, asset::AssetDefinitionId, nexus::AxtAssetIncarnationV1,
};

#[path = "issuer_worker_configuration_tests.rs"]
mod configuration_tests;

#[path = "issuer_worker_protocol_tests.rs"]
mod protocol_tests;

#[test]
fn retained_evidence_rechecks_original_configuration_and_time() {
    for apple in [false, true] {
        let mut request = fixture(apple);
        let original = json::to_vec(&projection(&request)).unwrap();
        let checked = request.retained_evidence(&original).unwrap();
        assert_eq!(checked.original_result, original);
        assert_eq!(checked.evidence.time_ms, request.verification_time_ms);
        assert_eq!(
            request.retained_evidence(&[]).unwrap_err(),
            Error("frame bound")
        );
        assert_eq!(
            request
                .retained_evidence(&vec![0; MAX_RESULT + 1])
                .unwrap_err(),
            Error("frame bound")
        );
        request.configuration[0] ^= 1;
        assert_eq!(
            request.retained_evidence(&original).unwrap_err(),
            Error("evidence identity")
        );
        request.configuration[0] ^= 1;
        request.verification_time_ms += 1;
        assert_eq!(
            request.retained_evidence(&original).unwrap_err(),
            Error("evidence identity")
        );
    }
}

fn fixture(apple: bool) -> VerifierRequestV1 {
    let key = KeyPair::from_seed(vec![43; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let asset = KagemushaWalletAssetScopeV1::new(
        AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .unwrap(),
        &AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"issuer boundary DATA").as_ref())
            .unwrap(),
        2,
    )
    .unwrap();
    let app = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id: scheme().scheme_id(),
        identity: if apple {
            KagemushaWalletAppIdentityV1::Apple {
                app_id: "TEAM.org.example.wallet".into(),
            }
        } else {
            KagemushaWalletAppIdentityV1::Android {
                package_name: "org.example.wallet".into(),
                minimum_package_version: 7,
                signer_set: vec![[3; 32]],
            }
        },
    };
    let policy = KagemushaWalletEnrollmentPolicyV1 {
        version: 1,
        scheme_id: app.scheme_id,
        asset_digest: asset.asset_digest(),
        app_policy: app.policy_digest().unwrap(),
        platform: if apple {
            KagemushaWalletEnrollmentPlatformV1::Apple {
                attestation_root_sha256: [4; 32],
            }
        } else {
            KagemushaWalletEnrollmentPlatformV1::Android {
                root_set: vec![KagemushaWalletAndroidRootV1 {
                    family: KagemushaWalletAndroidRootFamilyV1::GoogleCa1,
                    spki_sha256: [4; 32],
                    revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
                }],
                patch_floor_yyyymm: 202608,
            }
        },
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
        challenge_lifetime_ms: 600_001,
        attestation_lease_lifetime_ms: 0,
    };
    let challenge = KagemushaWalletEnrollmentChallengeV1 {
        version: 1,
        scheme_id: app.scheme_id,
        asset_digest: asset.asset_digest(),
        account_digest: kagemusha_wallet_account_digest_v1(&account).unwrap(),
        app_policy: policy.app_policy,
        enrollment_policy: policy.policy_digest().unwrap(),
        issuer_nonce: [5; 32],
    };
    let payment = p256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
    let payment = KagemushaDevicePublicKeyV1::from_sec1_bytes(
        payment.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    let evidence = if apple {
        PlatformEvidenceV1::Apple {
            key_id: [6; 32],
            attestation: b"DATA attestation".to_vec(),
            key_binding_assertion: b"DATA assertion".to_vec(),
        }
    } else {
        PlatformEvidenceV1::Android {
            certificates: vec![b"DATA leaf".to_vec(), b"DATA root".to_vec()],
        }
    };
    let body = RequestBodyV1 {
        version: 1,
        challenge,
        marker: KagemushaWalletMarkerV1::enrollment(&challenge, payment).unwrap(),
        app: app.clone(),
        policy,
        account,
        asset,
        evidence: norito::encode_canonical(&evidence).unwrap(),
    };
    let account_signature =
        Signature::try_new(key.private_key(), &body.account_challenge().unwrap())
            .unwrap()
            .payload()
            .try_into()
            .unwrap();
    let request = RequestV1 {
        body,
        account_signature,
    };
    let preparation = prepare(&request, 1_000, [7; 32]).unwrap();
    VerifierRequestV1::from_prepared(request, &preparation, 601_000).unwrap()
}

fn scheme() -> KagemushaWalletSchemeV1 {
    let root = p256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
    KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *Hash::new(b"private worker vector DATA").as_ref(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            root.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        relation_id: [19; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    }
}
fn dispatch(request: &RequestV1) -> PreKeyDispatchV1 {
    use p256::ecdsa::signature::Signer as _;
    let scheme = scheme();
    let root = p256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Enrollment,
        key: scheme.scheme_root_key,
        serial: 1,
    };
    let signature: p256::ecdsa::Signature = root.sign(&body.signing_message());
    let certificate = KagemushaWalletSignerCertificateV1::sign(
        body,
        &scheme,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    PreKeyDispatchV1 {
        version: 1,
        request_id: [1; 32],
        platform: if matches!(
            request.body.policy.platform,
            KagemushaWalletEnrollmentPlatformV1::Apple { .. }
        ) {
            KagemushaEnrollmentPermitPlatformV1::Apple
        } else {
            KagemushaEnrollmentPermitPlatformV1::Android
        },
        purpose: KagemushaEnrollmentPermitPurposeV1::Fresh,
        client_nonce: [2; 32],
        native_dispatch_nonce: [3; 32],
        manifest_digest: [4; 32],
        release_digest: [5; 32],
        service_origin_digest: [6; 32],
        fi_digest: [7; 32],
        actor_digest: [8; 32],
        scheme,
        app: request.body.app.clone(),
        policy: request.body.policy.clone(),
        enrollment_certificate: certificate,
        account: request.body.account.clone(),
        asset: request.body.asset.clone(),
        previous_permit: None,
    }
}
fn prepare(
    request: &RequestV1,
    created: u64,
    config: [u8; 32],
) -> Result<VerifierPreparationV1, Error> {
    VerifierPreparationV1::from_selected(
        &dispatch(request),
        request.body.challenge,
        created,
        config,
    )
}
fn exchange(request: &VerifierRequestV1, id: [u8; 32]) -> VerifierExchangeV1 {
    request
        .packet(
            ActionV1::Complete,
            [10; 32],
            id,
            request.verification_time_ms,
        )
        .unwrap()
}

fn projection(request: &VerifierRequestV1) -> Value {
    let body = &request.request.body;
    let (kind, originals, items, key, counter) =
        match PlatformEvidenceV1::decode(&body.evidence, &body.policy).unwrap() {
            PlatformEvidenceV1::Android { certificates } => (
                KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
                IssuerEvidenceV1::Android {
                    certificates: certificates.clone(),
                },
                certificates,
                Value::Null,
                Value::Null,
            ),
            PlatformEvidenceV1::Apple {
                key_id,
                attestation,
                key_binding_assertion,
            } => (
                KagemushaWalletEvidenceKindV1::AppleAppAttest,
                IssuerEvidenceV1::Apple {
                    attestation: attestation.clone(),
                    key_binding_assertion: key_binding_assertion.clone(),
                },
                vec![attestation, key_binding_assertion],
                Value::from(hex::encode(key_id)),
                Value::from(1_u32),
            ),
        };
    let facts = kind.required_enrollment_facts()
        | if kind.is_android() {
            KAGEMUSHA_WALLET_FACT_REVOCATION_LIST_CLEAR_V1
        } else {
            KAGEMUSHA_WALLET_FACT_APP_ATTEST_PRODUCTION_V1
        };
    norito::json!({
        "config_sha256": (hex::encode(request.configuration)),
        "challenge_digest": (hex::encode(body.challenge.challenge_digest())),
        "key_binding": (hex::encode(kagemusha_wallet_enrollment_key_binding_v1(&body.challenge.challenge_digest(), &body.marker.payment_key))),
        "payment_key_base64": (STANDARD.encode(body.marker.payment_key.as_sec1_bytes())),
        "kind_tag": (kind.tag()), "time_ms": (request.verification_time_ms),
        "facts": (facts), "os_patch_level": (0_u32), "vendor_patch_level": (0_u32), "boot_patch_level": (0_u32),
        "evidence_digest": (hex::encode(originals.digest(body, kind).unwrap())),
        "original_items_base64": (items.iter().map(|v| STANDARD.encode(v)).collect::<Vec<_>>()),
        "app_attest_key_id": (key), "app_attest_counter": (counter),
    })
}
fn framed(value: &Value) -> Vec<u8> {
    let bytes = json::to_vec(value).unwrap();
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend(bytes);
    frame
}
fn reply_with(
    configuration: [u8; 32],
    exchange: &VerifierExchangeV1,
    outcome: &str,
    evidence: Value,
) -> Value {
    let packet = decode(&exchange.frame()[4..], MAX_PACKET).unwrap();
    norito::json!({
        "schema": (SCHEMA), "version": (1_u16), "exchange_id": (packet["exchange_id"].clone()),
        "request_sha256": (hex::encode(Sha256::digest(&exchange.frame()[4..]))),
        "journal_incarnation": (hex::encode([10;32])), "config_sha256": (hex::encode(configuration)),
        "outcome": (outcome), "evidence_base64": (evidence), "refusal_code": (Value::Null),
    })
}
fn reply(exchange: &VerifierExchangeV1, outcome: &str, evidence: Value) -> Value {
    reply_with([7; 32], exchange, outcome, evidence)
}
fn response(request: &VerifierRequestV1, outcome: &str, evidence: Value) -> Value {
    reply(&exchange(request, [9; 32]), outcome, evidence)
}

fn change(value: &mut Value, key: &str, next: Value) {
    *value.get_mut(key).unwrap() = next;
}

#[test]
fn retained_request_has_exact_python_fields_and_no_extra_lifetime_ceiling() {
    for apple in [false, true] {
        let request = fixture(apple);
        let decoded = decode(request.original(), MAX_REQUEST).unwrap();
        fields(
            &decoded,
            &[
                "challenge_transcript_base64",
                "payment_key_base64",
                "issued_at_ms",
                "expires_at_ms",
                "trusted_time_ms",
                "platform",
                "evidence",
            ],
        )
        .unwrap();
        assert_eq!(integer(&decoded, "issued_at_ms").unwrap(), 1_000);
        assert_eq!(integer(&decoded, "expires_at_ms").unwrap(), 601_001);
        assert_eq!(
            binary(text(&decoded, "challenge_transcript_base64").unwrap(), 194).unwrap(),
            request.request.body.challenge.transcript()
        );
        for action in [ActionV1::Complete, ActionV1::Recover, ActionV1::Inspect] {
            let packet = request
                .packet(action, [10; 32], [8; 32], request.verification_time_ms)
                .unwrap();
            let packet = packet.frame();
            assert_eq!(
                u32::from_le_bytes(packet[..4].try_into().unwrap()) as usize,
                packet.len() - 4
            );
            let value = decode(&packet[4..], MAX_PACKET).unwrap();
            assert_eq!(
                binary(text(&value, "original_base64").unwrap(), MAX_REQUEST).unwrap(),
                request.original()
            );
        }
        assert!(
            request
                .packet(
                    ActionV1::Complete,
                    [10; 32],
                    [0; 32],
                    request.verification_time_ms
                )
                .is_err()
        );
        let body = &request.request.body;
        for (created, now) in [
            (0, 1_000),
            (1_000, 999),
            (1_000, 601_001),
            (u64::MAX, u64::MAX),
        ] {
            assert!(
                prepare(&request.request, created, [7; 32])
                    .and_then(|prepared| VerifierRequestV1::from_prepared(
                        request.request.clone(),
                        &prepared,
                        now
                    ))
                    .is_err()
            );
        }
        let mut other = body.policy.clone();
        other.challenge_lifetime_ms += 1;
        assert!(
            {
                let mut changed = request.request.clone();
                changed.body.policy = other;
                VerifierRequestV1::from_prepared(changed, &request.preparation, 1_001)
            }
            .is_err()
        );
        let mut forged = request.request.clone();
        forged.account_signature[0] ^= 1;
        assert!(VerifierRequestV1::from_prepared(forged, &request.preparation, 1_001).is_err());
    }
}

#[test]
fn worker_originals_rederive_digest_and_keep_exact_private_result() {
    for apple in [false, true] {
        let request = fixture(apple);
        let original = encode(&projection(&request), MAX_RESULT).unwrap();
        let value = response(
            &request,
            "evidence",
            Value::from(STANDARD.encode(&original)),
        );
        let OutcomeV1::Evidence(result) = request
            .response(&exchange(&request, [9; 32]), &framed(&value))
            .unwrap()
        else {
            panic!("evidence projection")
        };
        assert_eq!(result.original_result, original);
        assert_eq!(
            result.evidence.digest,
            result
                .originals
                .digest(&request.request.body, result.kind)
                .unwrap()
        );
        assert_eq!(result.evidence.time_ms, request.verification_time_ms);
        assert_eq!(
            result.apple_counter,
            if apple { Some(([6; 32], 1)) } else { None }
        );
    }
}

#[test]
fn projection_rejects_foreign_identity_time_kind_facts_and_originals() {
    for apple in [false, true] {
        let request = fixture(apple);
        let baseline = projection(&request);
        let mutations = [
            ("config_sha256", Value::from(hex::encode([8; 32]))),
            ("challenge_digest", Value::from(hex::encode([8; 32]))),
            ("key_binding", Value::from(hex::encode([8; 32]))),
            ("evidence_digest", Value::from(hex::encode([8; 32]))),
            ("time_ms", Value::from(request.verification_time_ms + 1)),
            ("kind_tag", Value::from(if apple { 1_u32 } else { 2_u32 })),
            ("facts", Value::from(0_u32)),
            ("app_attest_counter", Value::from(0_u32)),
            (
                "original_items_base64",
                Value::Array(vec![
                    Value::from(STANDARD.encode(b"forged")),
                    Value::from(STANDARD.encode(b"original")),
                ]),
            ),
        ];
        for (key, next) in mutations {
            let mut value = baseline.clone();
            change(&mut value, key, next);
            assert!(
                request
                    .projection(encode(&value, MAX_RESULT).unwrap())
                    .is_err(),
                "{key}"
            );
        }
        let mut value = baseline.clone();
        change(
            &mut value,
            "facts",
            Value::from(
                integer(&baseline, "facts").unwrap()
                    | u64::from(KAGEMUSHA_WALLET_FACT_LOCAL_COMPROMISE_CHECKS_CLEAR_V1),
            ),
        );
        assert!(
            request
                .projection(encode(&value, MAX_RESULT).unwrap())
                .is_err()
        );
        let mut value = baseline;
        value
            .as_object_mut()
            .unwrap()
            .insert("approved".into(), Value::Bool(true));
        assert!(
            request
                .projection(encode(&value, MAX_RESULT).unwrap())
                .is_err()
        );
    }
}

#[test]
fn uncertain_and_unavailable_outcomes_never_become_evidence() {
    let request = fixture(false);
    for outcome in ["outcome_unknown", "unavailable"] {
        let value = response(&request, outcome, Value::Null);
        let result = request
            .response(&exchange(&request, [9; 32]), &framed(&value))
            .unwrap();
        assert!(matches!(
            (outcome, result),
            ("outcome_unknown", OutcomeV1::OutcomeUnknown)
                | ("unavailable", OutcomeV1::Unavailable)
        ));
        assert!(
            request
                .response(&exchange(&request, [8; 32]), &framed(&value))
                .is_err()
        );
        let mut coded = value.clone();
        change(&mut coded, "refusal_code", Value::from(9_u16));
        assert!(
            request
                .response(&exchange(&request, [9; 32]), &framed(&coded))
                .is_err(),
            "a recovery state never carries a refusal code"
        );
        let mut wrong = value.clone();
        change(
            &mut wrong,
            "request_sha256",
            Value::from(hex::encode([8; 32])),
        );
        assert!(
            request
                .response(&exchange(&request, [9; 32]), &framed(&wrong))
                .is_err()
        );
        change(
            &mut wrong,
            "evidence_base64",
            Value::from(STANDARD.encode(b"injected")),
        );
        assert!(
            request
                .response(&exchange(&request, [9; 32]), &framed(&wrong))
                .is_err()
        );
    }
    for outcome in ["accepted", "", "success", "evidence", "rejected"] {
        assert!(
            request
                .response(
                    &exchange(&request, [9; 32]),
                    &framed(&response(&request, outcome, Value::Null))
                )
                .is_err()
        );
    }
    let mut missing = response(&request, "unavailable", Value::Null);
    missing.as_object_mut().unwrap().remove("refusal_code");
    assert!(
        request
            .response(&exchange(&request, [9; 32]), &framed(&missing))
            .is_err()
    );
}

#[test]
fn refusals_carry_exactly_one_closed_platform_code_for_the_configured_platform() {
    for apple in [false, true] {
        let request = fixture(apple);
        for reason in KagemushaWalletEnrollmentRefusalV1::ALL {
            let mut value = response(&request, "refused", Value::Null);
            change(&mut value, "refusal_code", Value::from(reason.code()));
            let result = request.response(&exchange(&request, [9; 32]), &framed(&value));
            if !reason.is_eligibility() && reason.applies_to(!apple) {
                assert!(
                    matches!(result, Ok(OutcomeV1::Refused(actual)) if actual == reason),
                    "{reason:?}"
                );
            } else {
                // Eligibility codes come from the issuer owner, never the platform worker;
                // Android-only reasons cannot refuse Apple evidence.
                assert!(result.is_err(), "{reason:?} apple={apple}");
            }
        }
        for code in [
            Value::Null,
            Value::from(0_u16),
            Value::from(13_u16),
            Value::from(-1),
        ] {
            let mut value = response(&request, "refused", Value::Null);
            change(&mut value, "refusal_code", code.clone());
            assert!(
                request
                    .response(&exchange(&request, [9; 32]), &framed(&value))
                    .is_err(),
                "{code:?}"
            );
        }
        let mut with_evidence = response(&request, "refused", Value::from(STANDARD.encode(b"x")));
        change(&mut with_evidence, "refusal_code", Value::from(9_u16));
        assert!(
            request
                .response(&exchange(&request, [9; 32]), &framed(&with_evidence))
                .is_err()
        );
        // A refusal never answers an evidence reply.
        let original = encode(&projection(&request), MAX_RESULT).unwrap();
        let mut evidence = response(
            &request,
            "evidence",
            Value::from(STANDARD.encode(&original)),
        );
        change(&mut evidence, "refusal_code", Value::from(9_u16));
        assert!(
            request
                .response(&exchange(&request, [9; 32]), &framed(&evidence))
                .is_err()
        );
    }
}

#[test]
fn new_android_evidence_never_carries_the_retired_bit_9_fact() {
    let request = fixture(false);
    let baseline = projection(&request);
    for extra in [
        KAGEMUSHA_WALLET_FACT_PLAY_INTEGRITY_SIGNAL_V1,
        KAGEMUSHA_WALLET_FACT_LOCAL_COMPROMISE_CHECKS_CLEAR_V1,
        KAGEMUSHA_WALLET_FACT_STRONGBOX_V1,
    ] {
        let mut value = baseline.clone();
        change(
            &mut value,
            "facts",
            Value::from(integer(&baseline, "facts").unwrap() | u64::from(extra)),
        );
        assert!(
            request
                .projection(encode(&value, MAX_RESULT).unwrap())
                .is_err(),
            "{extra:#x}"
        );
    }
    // REVOCATION_LIST_CLEAR is required; PATCH_POLICY_MET is an optional recorded fact.
    let mut value = baseline.clone();
    change(
        &mut value,
        "facts",
        Value::from(
            integer(&baseline, "facts").unwrap()
                & !u64::from(KAGEMUSHA_WALLET_FACT_REVOCATION_LIST_CLEAR_V1),
        ),
    );
    assert!(
        request
            .projection(encode(&value, MAX_RESULT).unwrap())
            .is_err()
    );
    let facts = integer(&baseline, "facts").unwrap();
    let mut value = baseline;
    change(
        &mut value,
        "facts",
        Value::from(facts | u64::from(KAGEMUSHA_WALLET_FACT_PATCH_POLICY_MET_V1)),
    );
    request
        .projection(encode(&value, MAX_RESULT).unwrap())
        .unwrap();
}

#[test]
fn attested_strongbox_and_tee_kinds_are_both_admitted_under_one_android_policy() {
    let request = fixture(false);
    for (kind, facts) in [
        (
            KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
            KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1,
        ),
        (
            KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox,
            KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1 | KAGEMUSHA_WALLET_FACT_STRONGBOX_V1,
        ),
    ] {
        let body = &request.request.body;
        let mut value = projection(&request);
        change(&mut value, "kind_tag", Value::from(kind.tag()));
        change(
            &mut value,
            "facts",
            Value::from(facts | KAGEMUSHA_WALLET_FACT_REVOCATION_LIST_CLEAR_V1),
        );
        let originals = IssuerEvidenceV1::Android {
            certificates: vec![b"DATA leaf".to_vec(), b"DATA root".to_vec()],
        };
        change(
            &mut value,
            "evidence_digest",
            Value::from(hex::encode(originals.digest(body, kind).unwrap())),
        );
        let projected = request
            .projection(encode(&value, MAX_RESULT).unwrap())
            .unwrap();
        assert_eq!(projected.kind, kind);
        assert_eq!(projected.originals, originals);
    }
}

#[test]
fn private_decode_rejects_duplicate_fields_bad_numbers_and_noncanonical_binary() {
    assert!(decode(br#"{"a":1,"a":2}"#, MAX_PACKET).is_err());
    assert!(decode(b"", MAX_PACKET).is_err());
    assert!(decode(&[b' '; 9], 8).is_err());
    assert!(encode(&Value::from("too long"), 1).is_err());
    for raw in [
        br#"{"version":true}"#.as_slice(),
        br#"{"version":-1}"#.as_slice(),
        br#"{"version":1.0}"#.as_slice(),
        br#"{"version":1e0}"#.as_slice(),
        br#"{"version":18446744073709551616}"#.as_slice(),
    ] {
        assert!(integer(&decode(raw, MAX_PACKET).unwrap(), "version").is_err());
    }
    for value in ["", "Zg", "Zh==", "Zg==\n"] {
        assert!(binary(value, 10).is_err());
    }
    assert_eq!(binary("Zg==", 1).unwrap(), b"f");
    assert!(binary("Zm9v", 1).is_err());
    assert!(digest(&norito::json!({"x": ("AA".repeat(32))}), "x").is_err());
    let request = fixture(false);
    let frame = framed(&response(&request, "unavailable", Value::Null));
    assert!(
        request
            .packet(
                ActionV1::Complete,
                [10; 32],
                [0; 32],
                request.verification_time_ms
            )
            .is_err()
    );
    assert!(
        request
            .response(&exchange(&request, [9; 32]), &frame[..frame.len() - 1])
            .is_err()
    );
    let mut appended = frame;
    appended.push(0);
    assert!(
        request
            .response(&exchange(&request, [9; 32]), &appended)
            .is_err()
    );
}

#[test]
fn android_projection_items_are_exactly_the_bounded_e5_chain() {
    let request = fixture(false);
    let mut value = projection(&request);
    value
        .get_mut("original_items_base64")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(Value::from(STANDARD.encode(b"appended original response")));
    assert!(
        request
            .projection(encode(&value, MAX_RESULT).unwrap())
            .is_err()
    );
    let mut value = projection(&request);
    value
        .get_mut("original_items_base64")
        .unwrap()
        .as_array_mut()
        .unwrap()[0] = Value::from(STANDARD.encode(vec![b'd'; 16_385]));
    assert!(matches!(
        request.projection(encode(&value, MAX_RESULT).unwrap()),
        Err(Error("binary bound"))
    ));
    let mut value = projection(&request);
    change(
        &mut value,
        "original_items_base64",
        Value::Array(vec![Value::from(STANDARD.encode(b"DATA leaf")); 9]),
    );
    assert!(matches!(
        request.projection(encode(&value, MAX_RESULT).unwrap()),
        Err(Error("evidence item count"))
    ));
}
