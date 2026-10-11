//! Signed protocol assertions migrated intact from the runtime owner.
use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
const NOW: u64 = 1_800_000_000;
fn catalog_keys() -> [SigningKey; 2] {
    [
        SigningKey::from_bytes(&[0x11; 32]),
        SigningKey::from_bytes(&[0x22; 32]),
    ]
}
fn gateway_keys() -> [SigningKey; 2] {
    [
        SigningKey::from_bytes(&[0x33; 32]),
        SigningKey::from_bytes(&[0x44; 32]),
    ]
}
fn trust_policy() -> GatewayComplianceTrustPolicyV1 {
    let catalog = catalog_keys();
    let gateways = gateway_keys();
    GatewayComplianceTrustPolicyV1 {
        policy_id: [0xA5; 32],
        catalog_threshold: 2,
        catalog_signers: vec![
            GatewayComplianceTrustedSignerV1 {
                signer_id: "council-a".into(),
                public_key: catalog[0].verifying_key().to_bytes(),
            },
            GatewayComplianceTrustedSignerV1 {
                signer_id: "council-b".into(),
                public_key: catalog[1].verifying_key().to_bytes(),
            },
        ],
        revoked_catalog_signer_ids: Vec::new(),
        gateway_ack_threshold: 2,
        gateway_signers: vec![
            GatewayComplianceTrustedSignerV1 {
                signer_id: "gateway-eu".into(),
                public_key: gateways[0].verifying_key().to_bytes(),
            },
            GatewayComplianceTrustedSignerV1 {
                signer_id: "gateway-us".into(),
                public_key: gateways[1].verifying_key().to_bytes(),
            },
        ],
        revoked_gateway_signer_ids: Vec::new(),
    }
}
fn payload(
    sequence: u64,
    predecessor_digest: Option<[u8; 32]>,
) -> GatewayComplianceCatalogPayloadV1 {
    GatewayComplianceCatalogPayloadV1 {
        version: GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
        sequence,
        predecessor_digest,
        policy_digest: trust_policy().canonical_digest().expect("policy digest"),
        generated_at_unix: NOW,
        valid_until_unix: NOW + 3_600,
        source_anchors: vec![GatewayComplianceSourceAnchorV1 {
            feed_id: "baseline".into(),
            feed_digest: [0x91; 32],
            generated_at_unix: NOW,
        }],
        baseline_rules: Vec::new(),
        appeal_overrides: Vec::new(),
        legal_safety_holds: Vec::new(),
        toggles: Vec::new(),
    }
}
fn sign_catalog(payload: GatewayComplianceCatalogPayloadV1) -> GatewayComplianceCatalogV1 {
    let payload = payload.normalize().expect("normalize catalog");
    let digest = payload.signing_digest().expect("catalog signing digest");
    let keys = catalog_keys();
    GatewayComplianceCatalogV1 {
        payload,
        approvals: vec![
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-a".into(),
                signature: keys[0].sign(&digest).to_bytes(),
            },
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-b".into(),
                signature: keys[1].sign(&digest).to_bytes(),
            },
        ],
    }
}
fn acknowledgement(
    gateway_index: usize,
    catalog_digest: [u8; 32],
    accepted: bool,
) -> GatewayComplianceAcknowledgementV1 {
    acknowledgement_at(gateway_index, catalog_digest, accepted, NOW + 10)
}
fn acknowledgement_at(
    gateway_index: usize,
    catalog_digest: [u8; 32],
    accepted: bool,
    observed_at_unix: u64,
) -> GatewayComplianceAcknowledgementV1 {
    let gateway_id = if gateway_index == 0 {
        "gateway-eu"
    } else {
        "gateway-us"
    };
    let payload = GatewayComplianceAcknowledgementPayloadV1 {
        version: GATEWAY_COMPLIANCE_ACK_VERSION_V1,
        gateway_id: gateway_id.into(),
        catalog_digest,
        observed_at_unix,
        accepted,
        rejection_code: (!accepted).then(|| "reload-failed".into()),
    };
    let digest = payload.signing_digest().expect("ack digest");
    GatewayComplianceAcknowledgementV1 {
        payload,
        signature: gateway_keys()[gateway_index].sign(&digest).to_bytes(),
    }
}
#[test]
fn signature_substitution_and_duplicate_quorum_fail_closed() {
    let policy = trust_policy();
    let mut catalog = sign_catalog(payload(1, None));
    catalog.payload.valid_until_unix += 1;
    assert!(matches!(
        catalog.verify(&policy, NOW + 1, 300),
        Err(GatewayComplianceProtocolError::InvalidSignature { .. })
    ));
    let mut duplicate = sign_catalog(payload(1, None));
    duplicate.approvals[1] = duplicate.approvals[0].clone();
    assert!(matches!(
        duplicate.verify(&policy, NOW + 1, 300),
        Err(GatewayComplianceProtocolError::DuplicateSigner(_))
    ));
}
#[test]
fn cid_subjects_require_canonical_lowercase_base32_round_trip() {
    let canonical = "bafyr6iffuws2ljnfuws2ljnfuws2ljnfuws2ljnfuws2ljnfuws2ljnfuu";
    assert_eq!(
        normalize_subject(GatewayComplianceSubjectKindV1::Cid, canonical).expect("canonical CID"),
        canonical
    );
    for malformed in [
        "",
        "b",
        "Bafyr6iffuws2ljnfuws2ljnfuws2ljnfuws2ljnfuws2ljnfuws2ljnfuu",
        "ba0",
        "ba1",
        "ba8",
        "ba9",
        "ba",
        "b=",
    ] {
        assert!(
            normalize_subject(GatewayComplianceSubjectKindV1::Cid, malformed).is_err(),
            "malformed CID unexpectedly admitted: {malformed}"
        );
    }
}
#[test]
fn current_feed_frames_bind_normalized_documents_and_transport_pins() {
    let document = GatewayComplianceFeedDocumentV1 {
        version: GATEWAY_COMPLIANCE_FEED_VERSION_V1,
        feed_id: "baseline".into(),
        generated_at_unix: NOW,
        baseline_rules: Vec::new(),
        appeal_overrides: Vec::new(),
        legal_safety_holds: Vec::new(),
        toggles: Vec::new(),
    }
    .normalize()
    .expect("valid normalized feed");
    let bytes = assert_current_frame(
        &document,
        "sorafs_manifest::gateway_compliance::GatewayComplianceFeedDocumentV1",
    );
    let decoded: GatewayComplianceFeedDocumentV1 =
        norito::decode_canonical(&bytes).expect("decode normalized feed frame");
    assert_eq!(
        document.canonical_digest().expect("feed digest"),
        decoded.canonical_digest().expect("decoded feed digest")
    );
    let pins = BTreeMap::from([("feed.example".to_owned(), BTreeSet::from([[0x71; 32]]))]);
    let payload = GatewayComplianceFeedTransportPolicyDigestV1 {
        version: 1,
        hosts: vec![GatewayComplianceFeedTransportHostDigestV1 {
            hostname: "feed.example".to_owned(),
            accepted_spki_sha256: vec![[0x71; 32]],
        }],
    };
    assert_eq!(
        <GatewayComplianceFeedTransportPolicyDigestV1 as norito::NoritoSchema>::nominal_name(),
        "sorafs_manifest::gateway_compliance::GatewayComplianceFeedTransportPolicyDigestV1",
    );
    let encoded = encode_bounded(&payload, MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1)
        .expect("encode-only transport fingerprint frame");
    assert_eq!(
        norito::core::from_bytes_view(&encoded)
            .expect("valid transport frame")
            .schema(),
        norito::schema::identity::frame_hash::<GatewayComplianceFeedTransportPolicyDigestV1>(),
    );
    assert!(encode_bounded(&payload, encoded.len() - 1).is_err());
    let expected = hash_canonical(
        FEED_TRANSPORT_POLICY_DOMAIN_V1,
        &payload,
        MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1,
    )
    .expect("hash exact framed transport payload");
    assert_eq!(
        gateway_compliance_feed_transport_policy_digest(&pins)
            .expect("production pin policy digest"),
        expected
    );
    let changed = BTreeMap::from([("feed.example".to_owned(), BTreeSet::from([[0x72; 32]]))]);
    assert_ne!(
        gateway_compliance_feed_transport_policy_digest(&changed)
            .expect("rotated pin policy digest"),
        expected
    );
}
#[test]
fn acknowledgement_signing_digest_preserves_exact_domain_and_valid_payloads() {
    let policy = trust_policy();
    for accepted in [true, false] {
        let signed = acknowledgement(0, [0x81; 32], accepted);
        let digest = signed
            .payload
            .signing_digest()
            .expect("canonical acknowledgement");
        assert_eq!(
            digest,
            hash_canonical(
                ACK_SIGNING_DOMAIN_V1,
                &signed.payload,
                MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1
            )
            .expect("existing exact acknowledgement framing")
        );
        signed
            .verify(&policy, [0x81; 32], NOW + 10, 300)
            .expect("valid signed acknowledgement");
        for domain in [
            CATALOG_SIGNING_DOMAIN_V1,
            CATALOG_DIGEST_DOMAIN_V1,
            ROLLBACK_SIGNING_DOMAIN_V1,
        ] {
            let wrong_digest = hash_canonical(
                domain,
                &signed.payload,
                MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1,
            )
            .expect("bounded alternate-domain payload");
            assert_ne!(digest, wrong_digest);
            let wrong_domain = GatewayComplianceAcknowledgementV1 {
                payload: signed.payload.clone(),
                signature: gateway_keys()[0].sign(&wrong_digest).to_bytes(),
            };
            assert!(matches!(
                wrong_domain.verify(&policy, [0x81; 32], NOW + 10, 300),
                Err(GatewayComplianceProtocolError::InvalidSignature { .. })
            ));
        }
    }
}
#[test]
fn acknowledgement_signing_and_verification_reject_resealed_noncanonical_payloads() {
    type Payload = GatewayComplianceAcknowledgementPayloadV1;
    type Mutation = (&'static str, fn(&mut Payload));
    let mutations: [Mutation; 10] = [
        ("version", |p| p.version = 2),
        ("empty gateway", |p| p.gateway_id.clear()),
        ("uppercase gateway", |p| p.gateway_id = "GATEWAY-EU".into()),
        ("padded gateway", |p| p.gateway_id.push(' ')),
        ("oversized gateway", |p| p.gateway_id = "a".repeat(129)),
        ("zero clock", |p| p.observed_at_unix = 0),
        ("accepted with reason", |p| {
            p.rejection_code = Some("reload-failed".into())
        }),
        ("rejected without reason", |p| p.accepted = false),
        ("noncanonical reason", |p| {
            p.accepted = false;
            p.rejection_code = Some("RELOAD-FAILED".into());
        }),
        ("empty reason", |p| {
            p.accepted = false;
            p.rejection_code = Some(String::new());
        }),
    ];
    for (label, mutate) in mutations {
        let mut payload = acknowledgement(0, [0x81; 32], true).payload;
        mutate(&mut payload);
        let error = payload.signing_digest().expect_err(label);
        // Deliberately bypass the public signer validator in this adversary:
        // even a correct signature on malformed canonical bytes must be rejected.
        let raw_digest = hash_canonical(
            ACK_SIGNING_DOMAIN_V1,
            &payload,
            MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1,
        )
        .expect("bounded malformed payload");
        let resealed = GatewayComplianceAcknowledgementV1 {
            payload,
            signature: gateway_keys()[0].sign(&raw_digest).to_bytes(),
        };
        let verify_error = resealed
            .verify(&trust_policy(), [0x81; 32], NOW + 10, 300)
            .expect_err(label);
        assert_eq!(verify_error.to_string(), error.to_string(), "{label}");
    }
}
#[test]
fn acknowledgement_public_signing_keeps_controller_context_and_signature_checks() {
    let signed = acknowledgement(0, [0x81; 32], true);
    assert!(
        matches!(signed.verify(&trust_policy(), [0x82; 32], NOW + 10, 300),
        Err(GatewayComplianceProtocolError::InvalidAcknowledgement(reason)) if reason == "catalog digest mismatch")
    );
    for now in [NOW + 10 - 301, NOW + 10 + 301] {
        assert!(
            matches!(signed.verify(&trust_policy(), [0x81; 32], now, 300),
            Err(GatewayComplianceProtocolError::InvalidAcknowledgement(reason)) if reason == "acknowledgement timestamp is invalid")
        );
    }
    let mut revoked = trust_policy();
    revoked.gateway_ack_threshold = 1;
    revoked.revoked_gateway_signer_ids = vec!["gateway-eu".into()];
    revoked
        .validate()
        .expect("canonical remaining signer policy");
    assert!(matches!(signed.verify(&revoked, [0x81; 32], NOW + 10, 300),
        Err(GatewayComplianceProtocolError::RevokedSigner(signer)) if signer == "gateway-eu"));
    let mut unknown = signed.clone();
    unknown.payload.gateway_id = "gateway-unknown".into();
    unknown.signature = gateway_keys()[0]
        .sign(&unknown.payload.signing_digest().unwrap())
        .to_bytes();
    assert!(
        matches!(unknown.verify(&trust_policy(), [0x81; 32], NOW + 10, 300),
        Err(GatewayComplianceProtocolError::UntrustedSigner(signer)) if signer == "gateway-unknown")
    );
    let mutations: [fn(&mut GatewayComplianceAcknowledgementPayloadV1); 4] = [
        |p| p.observed_at_unix += 1,
        |p| p.catalog_digest = [0x82; 32],
        |p| p.gateway_id = "gateway-us".into(),
        |p| {
            p.accepted = false;
            p.rejection_code = Some("reload-failed".into());
        },
    ];
    for mutate in mutations {
        let mut modified = signed.clone();
        mutate(&mut modified.payload);
        assert!(modified.payload.signing_digest().is_ok());
        assert!(matches!(
            modified.verify(
                &trust_policy(),
                modified.payload.catalog_digest,
                NOW + 10,
                300
            ),
            Err(GatewayComplianceProtocolError::InvalidSignature { .. })
        ));
    }
    let mut rejected = acknowledgement(0, [0x81; 32], false);
    rejected.payload.rejection_code = Some("different-reason".into());
    assert!(matches!(
        rejected.verify(&trust_policy(), [0x81; 32], NOW + 10, 300),
        Err(GatewayComplianceProtocolError::InvalidSignature { .. })
    ));
    let mut corrupted = signed;
    corrupted.signature[0] ^= 1;
    assert!(matches!(
        corrupted.verify(&trust_policy(), [0x81; 32], NOW + 10, 300),
        Err(GatewayComplianceProtocolError::InvalidSignature { .. })
    ));
}

fn assert_current_frame<T>(value: &T, nominal: &str) -> Vec<u8>
where
    T: norito::NoritoSchema
        + norito::NoritoSerialize
        + for<'de> norito::NoritoDeserialize<'de>
        + PartialEq
        + std::fmt::Debug,
{
    assert_eq!(T::nominal_name(), nominal);
    assert_eq!(T::frame_name(), nominal);
    let frame = norito::encode_canonical(value).expect("canonical frame");
    let view = norito::core::from_bytes_view(&frame).expect("canonical archive");
    assert_eq!(view.schema(), norito::schema::identity::frame_hash::<T>());
    assert_eq!(norito::canonical_frame_len(value).unwrap(), frame.len());
    assert_eq!(&norito::decode_canonical::<T>(&frame).unwrap(), value);
    assert_eq!(
        norito::codec::encode_adaptive(&norito::decode_canonical::<T>(&frame).unwrap()),
        norito::codec::encode_adaptive(value)
    );
    let mut wrong_owner = frame.clone();
    wrong_owner[6] ^= 1;
    assert!(matches!(
        norito::decode_canonical::<T>(&wrong_owner),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(norito::decode_canonical::<T>(&trailing).is_err());
    frame
}

#[test]
fn rollback_signing_and_verification_share_one_canonical_owner() {
    let policy = trust_policy();
    let payload = GatewayComplianceRollbackPayloadV1 {
        version: GATEWAY_COMPLIANCE_ROLLBACK_VERSION_V1,
        operation_id: [0x11; 32],
        from_catalog_digest: [0x22; 32],
        to_catalog_digest: [0x33; 32],
        reason_code: "bad-feed".into(),
        authorized_at_unix: NOW,
    };
    let digest = payload.signing_digest().unwrap();
    assert_eq!(
        digest,
        hash_canonical(
            ROLLBACK_SIGNING_DOMAIN_V1,
            &payload,
            MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1
        )
        .unwrap()
    );
    let keys = catalog_keys();
    let signed = GatewayComplianceRollbackV1 {
        payload,
        approvals: ["council-a", "council-b"]
            .into_iter()
            .enumerate()
            .map(|(index, signer)| GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: signer.into(),
                signature: keys[index].sign(&digest).to_bytes(),
            })
            .collect(),
    };
    verify_rollback(&signed, &policy, NOW, 300).unwrap();
    assert_current_frame(
        &signed,
        "sorafs_manifest::gateway_compliance::GatewayComplianceRollbackV1",
    );
    for field in 0..7 {
        let mut changed = signed.clone();
        match field {
            0 => changed.payload.version = 2,
            1 => changed.payload.operation_id = [0; 32],
            2 => changed.payload.from_catalog_digest = [0; 32],
            3 => changed.payload.to_catalog_digest = changed.payload.from_catalog_digest,
            4 => changed.payload.authorized_at_unix = 0,
            5 => changed.payload.reason_code = "BAD-FEED".into(),
            _ => changed.payload.reason_code = "a".repeat(129),
        }
        assert!(changed.payload.signing_digest().is_err());
        assert!(verify_rollback(&changed, &policy, NOW, 300).is_err());
    }
    assert!(matches!(
        verify_rollback(&signed, &policy, NOW + 301, 300),
        Err(GatewayComplianceProtocolError::InvalidRollback(_))
    ));
    let mut substituted = signed.clone();
    substituted.payload.operation_id = [0x42; 32];
    assert!(matches!(
        verify_rollback(&substituted, &policy, NOW, 300),
        Err(GatewayComplianceProtocolError::InvalidSignature { .. })
    ));
    let mut revoked = policy.clone();
    revoked.catalog_threshold = 1;
    revoked.revoked_catalog_signer_ids = vec!["council-a".into()];
    assert!(matches!(
        verify_rollback(&signed, &revoked, NOW, 300),
        Err(GatewayComplianceProtocolError::RevokedSigner(_))
    ));
}
#[test]
fn public_signature_verifiers_require_complete_valid_trust_policy() {
    let signed = acknowledgement(0, [0x81; 32], true);
    let mut invalid = trust_policy();
    invalid.policy_id = [0; 32];
    assert!(matches!(
        signed.verify(&invalid, [0x81; 32], NOW + 10, 300),
        Err(GatewayComplianceProtocolError::InvalidPolicy(_))
    ));
    let rollback = GatewayComplianceRollbackV1 {
        payload: GatewayComplianceRollbackPayloadV1 {
            version: 1,
            operation_id: [1; 32],
            from_catalog_digest: [2; 32],
            to_catalog_digest: [3; 32],
            reason_code: "bad-feed".into(),
            authorized_at_unix: NOW,
        },
        approvals: vec![],
    };
    assert!(matches!(
        verify_rollback(&rollback, &invalid, NOW, 300),
        Err(GatewayComplianceProtocolError::InvalidPolicy(_))
    ));
}
#[test]
fn protocol_preimages_ignore_supported_caller_layout_and_bound_complete_frames() {
    let policy = trust_policy();
    let catalog = sign_catalog(payload(1, None));
    let ack = acknowledgement(0, catalog.payload.catalog_digest().unwrap(), true);
    let expected = (
        policy.canonical_digest().unwrap(),
        catalog.payload.signing_digest().unwrap(),
        catalog.payload.catalog_digest().unwrap(),
        ack.payload.signing_digest().unwrap(),
    );
    for flags in crate::canonical_test_support::supported_layouts() {
        let _layout = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            expected,
            (
                policy.canonical_digest().unwrap(),
                catalog.payload.signing_digest().unwrap(),
                catalog.payload.catalog_digest().unwrap(),
                ack.payload.signing_digest().unwrap()
            )
        );
    }
    for value in [
        norito::encode_canonical(&catalog).unwrap(),
        norito::encode_canonical(&ack).unwrap(),
    ] {
        assert!(value.len() <= MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1);
    }
    let length = norito::canonical_frame_len(&catalog).unwrap();
    assert!(
        matches!(encode_bounded(&catalog,length-1),Err(GatewayComplianceProtocolError::ResourceLimit{resource:"canonical encoded bytes",found,maximum}) if found==length && maximum==length-1)
    );
    assert_eq!(
        encode_bounded(&catalog, length).unwrap(),
        norito::encode_canonical(&catalog).unwrap()
    );
}
