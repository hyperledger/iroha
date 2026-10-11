//! Eligibility byte, signature, authority, freshness and substitution controls.

use super::*;
use iroha_crypto::{KeyPair, Signature};

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
fn policy() -> KagemushaEligibilityPolicyV1 {
    KagemushaEligibilityPolicyV1 {
        version: 1,
        network_id: [1; 32],
        scheme_id: [2; 32],
        asset_digest: [3; 32],
        revision: 1,
        authority: KagemushaEligibilityAuthorityV1::Bank { fi_digest: [4; 32] },
        public_key: key(17).public_key().to_bytes().1.try_into().unwrap(),
        maximum_response_ms: 1000,
    }
}
fn request(policy: &KagemushaEligibilityPolicyV1) -> KagemushaEligibilityRequestV1 {
    KagemushaEligibilityRequestV1 {
        version: 1,
        policy_digest: policy.policy_digest().unwrap(),
        account_digest: [5; 32],
        actor_digest: [6; 32],
        attempt_id: [7; 32],
        nonce: [8; 32],
        operation_digest: [9; 32],
        purpose: KagemushaEligibilityPurposeV1::PreKeyPermit,
        requested_at_ms: 1000,
        expires_at_ms: 2000,
    }
}
fn sign(body: KagemushaEligibilityResponseBodyV1, key: &KeyPair) -> KagemushaEligibilityResponseV1 {
    let signature = Signature::new(key.private_key(), &body.signing_message().unwrap())
        .payload()
        .try_into()
        .unwrap();
    KagemushaEligibilityResponseV1 { body, signature }
}
fn response(
    policy: &KagemushaEligibilityPolicyV1,
    request: &KagemushaEligibilityRequestV1,
) -> KagemushaEligibilityResponseV1 {
    sign(
        KagemushaEligibilityResponseBodyV1 {
            version: 1,
            request_digest: request.request_digest(policy).unwrap(),
            decision: KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            source_revision: 6,
            observed_at_ms: 1100,
            valid_until_ms: 2000,
        },
        &key(17),
    )
}

#[test]
fn frames_roundtrip_under_actual_encoded_bounds_for_each_authority_and_purpose() {
    for operator in [false, true] {
        let mut policy = policy();
        if operator {
            policy.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
                operator_digest: [10; 32],
            };
        }
        let original = policy.encode_canonical().unwrap();
        assert_eq!(
            KagemushaEligibilityPolicyV1::decode_canonical(&original).unwrap(),
            policy
        );
        for purpose in [
            KagemushaEligibilityPurposeV1::PreKeyPermit,
            KagemushaEligibilityPurposeV1::VerifyEvidence,
            KagemushaEligibilityPurposeV1::IssueCredential,
            KagemushaEligibilityPurposeV1::DeliverCredential,
        ] {
            let mut request = request(&policy);
            request.purpose = purpose;
            let bytes = request.encode_canonical(&policy).unwrap();
            assert_eq!(
                KagemushaEligibilityRequestV1::decode_canonical(&bytes, &policy).unwrap(),
                request
            );
            let response = response(&policy, &request);
            let bytes = response.encode_canonical().unwrap();
            assert_eq!(
                KagemushaEligibilityResponseV1::decode_canonical(&bytes, &policy, &request, 1100)
                    .unwrap(),
                response
            );
            for (name, size) in [
                ("policy", original.len()),
                ("request", request.encode_canonical(&policy).unwrap().len()),
                ("response", bytes.len()),
            ] {
                assert!(size <= KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1);
                println!(
                    "eligibility {name}: {size} bytes operator={operator} purpose={purpose:?}"
                );
            }
        }
    }
}

#[test]
fn authority_identity_is_explicit_and_never_inferred_from_missing_bank_state() {
    for authority in [
        KagemushaEligibilityAuthorityV1::Bank { fi_digest: [9; 32] },
        KagemushaEligibilityAuthorityV1::SchemeOperator {
            operator_digest: [9; 32],
        },
    ] {
        let mut value = policy();
        value.authority = authority;
        assert_eq!(authority.scope_digest(), [9; 32]);
        value.validate().unwrap();
        let request = request(&value);
        let response = response(&value, &request);
        value.authority = match authority {
            KagemushaEligibilityAuthorityV1::Bank { .. } => {
                KagemushaEligibilityAuthorityV1::SchemeOperator {
                    operator_digest: [9; 32],
                }
            }
            KagemushaEligibilityAuthorityV1::SchemeOperator { .. } => {
                KagemushaEligibilityAuthorityV1::Bank { fi_digest: [9; 32] }
            }
        };
        assert_eq!(value.authority.scope_digest(), authority.scope_digest());
        assert!(response.verify(&value, &request, 1100).is_err());
    }
    for authority in [
        KagemushaEligibilityAuthorityV1::Bank { fi_digest: [0; 32] },
        KagemushaEligibilityAuthorityV1::SchemeOperator {
            operator_digest: [0; 32],
        },
    ] {
        let mut value = policy();
        value.authority = authority;
        assert_eq!(authority.scope_digest(), [0; 32]);
        assert!(value.validate().is_err());
    }
}

#[test]
fn policy_rejects_zero_scope_weak_key_and_missing_revision_or_response_limit() {
    let cases: [fn(&mut KagemushaEligibilityPolicyV1); 8] = [
        |p| p.version = 2,
        |p| p.network_id = [0; 32],
        |p| p.scheme_id = [0; 32],
        |p| p.asset_digest = [0; 32],
        |p| p.revision = 0,
        |p| p.maximum_response_ms = 0,
        |p| p.public_key = [0; 32],
        |p| {
            p.public_key = [0; 32];
            p.public_key[0] = 1;
        },
    ];
    for change in cases {
        let mut p = policy();
        change(&mut p);
        assert!(p.encode_canonical().is_err());
    }
}

#[test]
fn every_authority_scope_or_rotation_change_invalidates_the_original_request() {
    let policy = policy();
    let request = request(&policy);
    let response = response(&policy, &request);
    let cases: [fn(&mut KagemushaEligibilityPolicyV1); 8] = [
        |p| p.network_id = [99; 32],
        |p| p.scheme_id = [99; 32],
        |p| p.asset_digest = [99; 32],
        |p| p.revision += 1,
        |p| p.maximum_response_ms += 1,
        |p| {
            p.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
                operator_digest: [4; 32],
            }
        },
        |p| {
            p.authority = KagemushaEligibilityAuthorityV1::Bank {
                fi_digest: [99; 32],
            }
        },
        |p| p.public_key = key(18).public_key().to_bytes().1.try_into().unwrap(),
    ];
    for change in cases {
        let mut p = policy;
        change(&mut p);
        assert!(response.verify(&p, &request, 1100).is_err());
    }
}

#[test]
fn nonce_actor_account_attempt_operation_purpose_and_deadline_cannot_be_substituted() {
    let policy = policy();
    let request = request(&policy);
    let response = response(&policy, &request);
    let cases: [fn(&mut KagemushaEligibilityRequestV1); 9] = [
        |r| r.policy_digest = [99; 32],
        |r| r.account_digest = [99; 32],
        |r| r.actor_digest = [99; 32],
        |r| r.attempt_id = [99; 32],
        |r| r.nonce = [99; 32],
        |r| r.operation_digest = [99; 32],
        |r| r.purpose = KagemushaEligibilityPurposeV1::DeliverCredential,
        |r| r.requested_at_ms += 1,
        |r| r.expires_at_ms -= 1,
    ];
    for change in cases {
        let mut r = request;
        change(&mut r);
        assert!(response.verify(&policy, &r, 1100).is_err());
    }
}

#[test]
fn request_interval_is_positive_bounded_and_does_not_overflow() {
    let policy = policy();
    let cases: [fn(&mut KagemushaEligibilityRequestV1); 7] = [
        |r| r.version = 2,
        |r| r.nonce = [0; 32],
        |r| r.requested_at_ms = 0,
        |r| r.expires_at_ms = r.requested_at_ms,
        |r| r.expires_at_ms = r.requested_at_ms - 1,
        |r| r.expires_at_ms += 1,
        |r| {
            r.requested_at_ms = 1;
            r.expires_at_ms = u64::MAX;
        },
    ];
    for change in cases {
        let mut r = request(&policy);
        change(&mut r);
        assert!(r.encode_canonical(&policy).is_err());
    }
    let mut r = request(&policy);
    r.requested_at_ms = u64::MAX - 1000;
    r.expires_at_ms = u64::MAX;
    assert!(r.validate(&policy).is_ok());
}

#[test]
fn response_cannot_predate_request_extend_deadline_or_claim_future_observation() {
    let policy = policy();
    let request = request(&policy);
    let response = response(&policy, &request);
    assert!(response.verify(&policy, &request, 1099).is_err());
    assert!(response.verify(&policy, &request, 1999).is_ok());
    assert!(response.verify(&policy, &request, 2000).is_err());
    assert!(response.verify(&policy, &request, u64::MAX).is_err());
    let mut body = response.body;
    body.observed_at_ms = 999;
    assert!(
        sign(body, &key(17))
            .verify(&policy, &request, 1100)
            .is_err()
    );
    let mut body = response.body;
    body.valid_until_ms = 2001;
    assert!(
        sign(body, &key(17))
            .verify(&policy, &request, 1100)
            .is_err()
    );
}

#[test]
fn signatures_bind_decision_source_revision_and_time_under_exact_selected_key() {
    let policy = policy();
    let request = request(&policy);
    let response = response(&policy, &request);
    assert!(
        sign(response.body, &key(18))
            .verify(&policy, &request, 1100)
            .is_err()
    );
    let cases: [fn(&mut KagemushaEligibilityResponseV1); 8] = [
        |r| r.body.version = 2,
        |r| r.body.decision = KagemushaEligibilityDecisionV1::Frozen,
        |r| r.body.source_revision += 1,
        |r| r.body.source_revision = 0,
        |r| r.body.observed_at_ms -= 1,
        |r| r.body.valid_until_ms -= 1,
        |r| r.signature[0] ^= 1,
        |r| r.signature = [0; 64],
    ];
    for change in cases {
        let mut r = response;
        change(&mut r);
        assert!(r.verify(&policy, &request, 1100).is_err());
    }
}

#[test]
fn authenticated_denials_remain_explicit_denials() {
    let policy = policy();
    let request = request(&policy);
    for decision in [
        KagemushaEligibilityDecisionV1::NotApproved,
        KagemushaEligibilityDecisionV1::Frozen,
    ] {
        let mut body = response(&policy, &request).body;
        body.decision = decision;
        let response = sign(body, &key(17));
        assert_eq!(response.verify(&policy, &request, 1100).unwrap(), decision);
    }
}

#[test]
fn noncanonical_truncated_and_oversize_frames_are_rejected_before_admission() {
    let policy = policy();
    let request = request(&policy);
    let response = response(&policy, &request);
    let mut originals = [
        policy.encode_canonical().unwrap(),
        request.encode_canonical(&policy).unwrap(),
        response.encode_canonical().unwrap(),
    ];
    for (index, original) in originals.iter_mut().enumerate() {
        let rejects = |bytes: &[u8]| match index {
            0 => KagemushaEligibilityPolicyV1::decode_canonical(bytes).is_err(),
            1 => KagemushaEligibilityRequestV1::decode_canonical(bytes, &policy).is_err(),
            _ => KagemushaEligibilityResponseV1::decode_canonical(bytes, &policy, &request, 1100)
                .is_err(),
        };
        assert!(rejects(&original[..original.len() - 1]));
        original.push(0);
        assert!(rejects(original));
        assert!(rejects(&vec![0; KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 + 1]));
    }
}

fn vectors() -> norito::json::Value {
    let mut cases = Vec::new();
    for authority in ["bank", "scheme-operator"] {
        let mut policy = policy();
        if authority == "scheme-operator" {
            policy.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
                operator_digest: [10; 32],
            };
        }
        for (purpose_name, purpose) in [
            (
                "pre-key-permit",
                KagemushaEligibilityPurposeV1::PreKeyPermit,
            ),
            (
                "verify-evidence",
                KagemushaEligibilityPurposeV1::VerifyEvidence,
            ),
            (
                "issue-credential",
                KagemushaEligibilityPurposeV1::IssueCredential,
            ),
            (
                "deliver-credential",
                KagemushaEligibilityPurposeV1::DeliverCredential,
            ),
        ] {
            let mut request = request(&policy);
            request.purpose = purpose;
            for (decision_name, decision) in [
                (
                    "approved-unfrozen",
                    KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
                ),
                ("not-approved", KagemushaEligibilityDecisionV1::NotApproved),
                ("frozen", KagemushaEligibilityDecisionV1::Frozen),
            ] {
                let mut body = response(&policy, &request).body;
                body.decision = decision;
                let response = sign(body, &key(17));
                cases.push(norito::json!({
                    "authority": authority, "purpose": purpose_name, "decision": decision_name,
                    "policy_hex": (hex::encode(policy.encode_canonical().unwrap())),
                    "policy_digest_hex": (hex::encode(policy.policy_digest().unwrap())),
                    "request_hex": (hex::encode(request.encode_canonical(&policy).unwrap())),
                    "request_digest_hex": (hex::encode(request.request_digest(&policy).unwrap())),
                    "response_body_hex": (hex::encode(encode_frame_v1(&body, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1).unwrap())),
                    "signing_message_hex": (hex::encode(body.signing_message().unwrap())),
                    "response_hex": (hex::encode(response.encode_canonical().unwrap())),
                    "signature_hex": (hex::encode(response.signature)),
                }));
            }
        }
    }
    norito::json!({
        "version": 1,
        "scope": "Unadmitted deterministic DATA; no actual provider, scheme authorization or issuer approval",
        "public_key_hex": (hex::encode(policy().public_key)),
        "cases": cases,
    })
}

#[test]
#[ignore = "explicit maintenance generator for public DATA; never admission or qualification"]
fn generate_enrollment_eligibility_vectors() {
    println!("{}", norito::json::to_json_pretty(&vectors()).unwrap());
}

#[test]
fn frozen_enrollment_eligibility_vectors_match_current_canonical_rust() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/enrollment_eligibility_v1_vectors.json");
    let expected = norito::json::parse_value(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(vectors(), expected);
}
