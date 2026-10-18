//! Unadmitted DATA only: public repeated pins are placeholders, without root DER or approval.

use norito::json::Value;

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::codec_tests::{
    assert_every_flip_rejected_or_rebound, norito_tag,
};

/// Path of the shared policy vectors relative to the repository fixture root.
const VECTORS_PATH: &str = "fixtures/kagemusha/wallet_enrollment_policy_v1_vectors.json";
/// Test-only switch shared with the wallet vectors: rewrite instead of comparing.
const UPDATE_VARIABLE: &str = "IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS";

fn google_rsa(spki: [u8; 32]) -> KagemushaWalletAndroidRootV1 {
    KagemushaWalletAndroidRootV1 {
        family: KagemushaWalletAndroidRootFamilyV1::GoogleRsa,
        spki_sha256: spki,
        revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
    }
}

fn vendor(adapter_id: &str, spki: [u8; 32]) -> KagemushaWalletAndroidRootV1 {
    KagemushaWalletAndroidRootV1 {
        family: KagemushaWalletAndroidRootFamilyV1::Vendor {
            adapter_id: adapter_id.to_owned(),
        },
        spki_sha256: spki,
        revocation_source: KagemushaWalletRevocationSourceV1::OperatorDenylist,
    }
}

/// Shared deterministic policy data, not external authority or current policy installation.
/// Android: one signer and one Google root; Apple: the production App Attest arm.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn policy_fixture(
    apple: bool,
) -> (
    KagemushaWalletAppPolicyV1,
    KagemushaWalletEnrollmentPolicyV1,
) {
    let identity = if apple {
        KagemushaWalletAppIdentityV1::Apple {
            app_id: "TEAMID.org.example.wallet".into(),
        }
    } else {
        KagemushaWalletAppIdentityV1::Android {
            package_name: "org.example.wallet".into(),
            minimum_package_version: 7,
            signer_set: vec![[5; 32]],
        }
    };
    let platform = if apple {
        KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256: [4; 32],
        }
    } else {
        KagemushaWalletEnrollmentPlatformV1::Android {
            root_set: vec![google_rsa([4; 32])],
            patch_floor_yyyymm: 202_608,
        }
    };
    policies(identity, platform, apple)
}

fn policies(
    identity: KagemushaWalletAppIdentityV1,
    platform: KagemushaWalletEnrollmentPlatformV1,
    lease: bool,
) -> (
    KagemushaWalletAppPolicyV1,
    KagemushaWalletEnrollmentPolicyV1,
) {
    let app = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id: [1; 32],
        identity,
    };
    let enrollment = KagemushaWalletEnrollmentPolicyV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        app_policy: app.policy_digest().unwrap(),
        platform,
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1 {
            permitted_controls: if lease { 2 } else { 0 },
            time_anchor_max_response_ms: if lease { 5000 } else { 0 },
        },
        challenge_lifetime_ms: 120_000,
        attestation_lease_lifetime_ms: if lease { 3_600_000 } else { 0 },
    };
    (app, enrollment)
}

/// The largest encodable policies: a 255-byte package, four signers and eight Vendor roots
/// with 16-byte adapter identifiers; and a 255-byte Apple App ID.
fn maximal_fixture(
    apple: bool,
) -> (
    KagemushaWalletAppPolicyV1,
    KagemushaWalletEnrollmentPolicyV1,
) {
    if apple {
        let (_, enrollment) = policy_fixture(true);
        return policies(
            KagemushaWalletAppIdentityV1::Apple {
                app_id: "é".repeat(127) + "a",
            },
            enrollment.platform,
            true,
        );
    }
    policies(
        KagemushaWalletAppIdentityV1::Android {
            package_name: "a.".to_owned() + &"b".repeat(253),
            minimum_package_version: u64::MAX,
            signer_set: (1..=4_u8).map(|index| [index * 0x11; 32]).collect(),
        },
        KagemushaWalletEnrollmentPlatformV1::Android {
            root_set: (1..=8_u8)
                .map(|index| vendor(&format!("vendor-{index:0>9}"), [index * 0x1d; 32]))
                .collect(),
            patch_floor_yyyymm: 999_912,
        },
        false,
    )
}

fn challenge(
    app: &KagemushaWalletAppPolicyV1,
    enrollment: &KagemushaWalletEnrollmentPolicyV1,
) -> KagemushaWalletEnrollmentChallengeV1 {
    KagemushaWalletEnrollmentChallengeV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        account_digest: [3; 32],
        app_policy: app.policy_digest().unwrap(),
        enrollment_policy: enrollment.policy_digest().unwrap(),
        issuer_nonce: [6; 32],
    }
}

type VectorCase = (
    &'static str,
    KagemushaWalletAppPolicyV1,
    KagemushaWalletEnrollmentPolicyV1,
);

fn vector_cases() -> Vec<VectorCase> {
    let (android_app, android) = policy_fixture(false);
    let (apple_app, apple) = policy_fixture(true);
    let (android_max_app, android_max) = maximal_fixture(false);
    let (apple_max_app, apple_max) = maximal_fixture(true);
    vec![
        ("android", android_app, android),
        ("apple", apple_app, apple),
        ("android_maximal", android_max_app, android_max),
        ("apple_maximal", apple_max_app, apple_max),
    ]
}

fn root_json(root: &KagemushaWalletAndroidRootV1) -> Value {
    let source = match root.revocation_source {
        KagemushaWalletRevocationSourceV1::GoogleAttestationStatus => "google_attestation_status",
        KagemushaWalletRevocationSourceV1::OperatorDenylist => "operator_denylist",
    };
    let spki = hex::encode(root.spki_sha256);
    match &root.family {
        KagemushaWalletAndroidRootFamilyV1::GoogleRsa => norito::json!({
            "family": "google_rsa", "spki_sha256": (spki), "revocation_source": (source),
        }),
        KagemushaWalletAndroidRootFamilyV1::GoogleCa1 => norito::json!({
            "family": "google_ca1", "spki_sha256": (spki), "revocation_source": (source),
        }),
        KagemushaWalletAndroidRootFamilyV1::Vendor { adapter_id } => norito::json!({
            "family": "vendor", "adapter_id": (adapter_id.clone()), "spki_sha256": (spki),
            "revocation_source": (source),
        }),
    }
}

/// Typed inputs of one case, in the private worker projection's spelling, so every consumer
/// can rebuild the exact policies without restating them.
fn inputs_json(
    app: &KagemushaWalletAppPolicyV1,
    enrollment: &KagemushaWalletEnrollmentPolicyV1,
) -> Value {
    let app_json = match &app.identity {
        KagemushaWalletAppIdentityV1::Android {
            package_name,
            minimum_package_version,
            signer_set,
        } => norito::json!({
            "platform": "android",
            "package_name": (package_name.clone()),
            "minimum_package_version": (*minimum_package_version),
            "app_signer_sha256": (signer_set.iter().map(hex::encode).collect::<Vec<_>>()),
        }),
        KagemushaWalletAppIdentityV1::Apple { app_id } => norito::json!({
            "platform": "apple",
            "app_id": (app_id.clone()),
        }),
    };
    let platform_json = match &enrollment.platform {
        KagemushaWalletEnrollmentPlatformV1::Android {
            root_set,
            patch_floor_yyyymm,
        } => norito::json!({
            "platform": "android",
            "roots": (root_set.iter().map(root_json).collect::<Vec<_>>()),
            "patch_floor_yyyymm": (*patch_floor_yyyymm),
        }),
        KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256,
        } => norito::json!({
            "platform": "apple",
            "root_sha256": (hex::encode(attestation_root_sha256)),
        }),
    };
    let regulator = norito::json!({
        "permitted_controls": (enrollment.regulatory_policy.permitted_controls),
        "time_anchor_max_response_ms": (enrollment.regulatory_policy.time_anchor_max_response_ms),
    });
    norito::json!({
        "version": (app.version),
        "scheme_id_hex": (hex::encode(app.scheme_id)),
        "asset_digest_hex": (hex::encode(enrollment.asset_digest)),
        "app": (app_json),
        "enrollment": (platform_json),
        "regulatory_policy": (regulator),
        "challenge_lifetime_ms": (enrollment.challenge_lifetime_ms),
        "attestation_lease_lifetime_ms": (enrollment.attestation_lease_lifetime_ms),
        "account_digest_hex": (hex::encode([3_u8; 32])),
        "issuer_nonce_hex": (hex::encode([6_u8; 32])),
    })
}

fn vectors_text() -> String {
    let cases: Vec<Value> = vector_cases()
        .into_iter()
        .map(|(name, app, enrollment)| {
            let e1 = challenge(&app, &enrollment);
            enrollment.verify_challenge(&app, &e1).unwrap();
            norito::json!({
                "name": (name),
                "inputs": (inputs_json(&app, &enrollment)),
                "app_policy_transcript_hex": (hex::encode(app.transcript().unwrap())),
                "app_policy_digest_hex": (hex::encode(app.policy_digest().unwrap())),
                "app_policy_frame_hex": (hex::encode(app.encode_canonical().unwrap())),
                "enrollment_policy_transcript_hex": (hex::encode(enrollment.transcript().unwrap())),
                "enrollment_policy_digest_hex": (hex::encode(enrollment.policy_digest().unwrap())),
                "enrollment_policy_frame_hex": (hex::encode(enrollment.encode_canonical().unwrap())),
                "challenge_transcript_hex": (hex::encode(e1.transcript())),
                "challenge_digest_hex": (hex::encode(e1.challenge_digest())),
            })
        })
        .collect();
    let document = norito::json!({
        "status": "NEW first-release grammar; unadmitted DATA only. Repeated public pins and placeholder signer, root and adapter values; no root originals, operator approvals, signers, hardware, vendor service or live authority.",
        "frame_cap_bytes": (u64::try_from(KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1).unwrap()),
        "cases": (cases),
    });
    let mut text = norito::json::to_string_pretty(&document).expect("vectors json");
    text.push('\n');
    text
}

#[test]
fn new_enrollment_policy_enum_tags_match_current_wallet_canonical_convention() {
    let (android_app, android) = policy_fixture(false);
    let (apple_app, apple) = policy_fixture(true);
    assert_eq!(norito_tag(&android_app.identity), 1);
    assert_eq!(norito_tag(&apple_app.identity), 2);
    assert_eq!(norito_tag(&android.platform), 1);
    assert_eq!(norito_tag(&apple.platform), 2);
    for (value, tag) in [
        (KagemushaWalletAndroidRootFamilyV1::GoogleRsa, 1),
        (KagemushaWalletAndroidRootFamilyV1::GoogleCa1, 2),
        (
            KagemushaWalletAndroidRootFamilyV1::Vendor {
                adapter_id: "huawei".into(),
            },
            3,
        ),
    ] {
        assert_eq!(norito_tag(&value), tag);
    }
    assert_eq!(
        norito_tag(&KagemushaWalletRevocationSourceV1::GoogleAttestationStatus),
        1
    );
    assert_eq!(
        norito_tag(&KagemushaWalletRevocationSourceV1::OperatorDenylist),
        2
    );
}

#[test]
fn new_enrollment_policy_shared_vectors_file_matches_the_generated_vectors() {
    let path = crate::kagemusha::kagemusha_wallet_v1::test_fixture_path(VECTORS_PATH);
    let text = vectors_text();
    assert_eq!(text, vectors_text(), "deterministic");
    if std::env::var_os(UPDATE_VARIABLE).is_some_and(|value| value == "1") {
        std::fs::write(&path, &text).expect("write policy vectors");
        return;
    }
    let existing = std::fs::read_to_string(&path).expect("policy vectors");
    // TODO(blacklist-local G5): regenerate wallet_enrollment_policy_v1_vectors.json.
    assert!(
        existing == text,
        "{} differs; regenerate with `{UPDATE_VARIABLE}=1 cargo test -p iroha_data_model \
         --lib enrollment_policy`",
        path.display()
    );
}

#[test]
fn new_enrollment_policy_transcript_layouts_are_exact() {
    let (android_app, android) = policy_fixture(false);
    let (apple_app, apple) = policy_fixture(true);
    let app = android_app.transcript().unwrap();
    assert_eq!(app.len(), 48 + 18 + 32);
    assert_eq!(&app[..2], &[1, 0]);
    assert_eq!(app[34], 1, "Android app tag");
    assert_eq!(&app[35..39], &18_u32.to_le_bytes());
    assert_eq!(&app[57..65], &7_u64.to_le_bytes());
    assert_eq!(app[65], 1, "signer count");
    assert_eq!(&app[66..], &[5; 32]);
    assert_eq!(apple_app.transcript().unwrap().len(), 39 + 25);
    let enrollment = android.transcript().unwrap();
    assert_eq!(enrollment.len(), 166);
    assert_eq!(enrollment[98], 1, "Android enrollment tag");
    assert_eq!(enrollment[99], 1, "root count");
    assert_eq!(enrollment[100], 1, "GoogleRsa family");
    assert_eq!(&enrollment[101..133], &[4; 32]);
    assert_eq!(enrollment[133], 1, "Google attestation status source");
    assert_eq!(&enrollment[134..138], &202_608_u32.to_le_bytes());
    assert_eq!(apple.transcript().unwrap().len(), 159);
    let (_, mut vendor_policy) = policy_fixture(false);
    vendor_policy.platform = KagemushaWalletEnrollmentPlatformV1::Android {
        root_set: vec![google_rsa([4; 32]), vendor("huawei", [9; 32])],
        patch_floor_yyyymm: 202_608,
    };
    let transcript = vendor_policy.transcript().unwrap();
    assert_eq!(transcript.len(), 132 + 34 + 38 + 6);
    assert_eq!(transcript[99], 2, "root count");
    assert_eq!(transcript[134], 3, "Vendor family");
    assert_eq!(&transcript[135..139], &6_u32.to_le_bytes());
    assert_eq!(&transcript[139..145], b"huawei");
    assert_eq!(&transcript[145..177], &[9; 32]);
    assert_eq!(transcript[177], 2, "operator denylist source");
}

#[test]
fn new_enrollment_policy_canonical_frames_and_every_byte_substitution() {
    for (_, app, enrollment) in vector_cases() {
        let app_frame = app.encode_canonical().unwrap();
        let enrollment_frame = enrollment.encode_canonical().unwrap();
        assert_eq!(
            KagemushaWalletAppPolicyV1::decode_canonical(&app_frame, &[1; 32]).unwrap(),
            app
        );
        assert_eq!(
            KagemushaWalletEnrollmentPolicyV1::decode_canonical(&enrollment_frame, &[1; 32])
                .unwrap(),
            enrollment
        );
        assert_every_flip_rejected_or_rebound(&app_frame, app.policy_digest().unwrap(), |bytes| {
            KagemushaWalletAppPolicyV1::decode_canonical(bytes, &[1; 32])
                .ok()
                .and_then(|p| p.policy_digest().ok())
        });
        assert_every_flip_rejected_or_rebound(
            &enrollment_frame,
            enrollment.policy_digest().unwrap(),
            |bytes| {
                KagemushaWalletEnrollmentPolicyV1::decode_canonical(bytes, &[1; 32])
                    .ok()
                    .and_then(|p| p.policy_digest().ok())
            },
        );
        let mut trailing = app_frame.clone();
        trailing.push(0);
        assert!(KagemushaWalletAppPolicyV1::decode_canonical(&trailing, &[1; 32]).is_err());
        assert!(
            KagemushaWalletEnrollmentPolicyV1::decode_canonical(&enrollment_frame, &[2; 32])
                .is_err()
        );
        assert!(KagemushaWalletAppPolicyV1::decode_canonical(&vec![0; 1025], &[1; 32]).is_err());
        assert!(
            KagemushaWalletEnrollmentPolicyV1::decode_canonical(&vec![0; 1025], &[1; 32]).is_err()
        );
    }
}

#[test]
fn new_enrollment_policy_rejects_cross_scope_app_platform_and_policy_substitution() {
    let (app, enrollment) = policy_fixture(false);
    let e1 = challenge(&app, &enrollment);
    for index in 0..4 {
        let mut changed = e1;
        match index {
            0 => changed.scheme_id = [7; 32],
            1 => changed.asset_digest = [7; 32],
            2 => changed.app_policy = [7; 32],
            _ => changed.enrollment_policy = [7; 32],
        }
        assert!(enrollment.verify_challenge(&app, &changed).is_err());
    }
    let (apple, _) = policy_fixture(true);
    assert!(enrollment.validate_for_app(&apple).is_err());
    let mut other = enrollment.clone();
    other.platform = KagemushaWalletEnrollmentPlatformV1::Apple {
        attestation_root_sha256: [4; 32],
    };
    assert!(other.validate_for_app(&app).is_err());
    let mut edited_app = app.clone();
    let KagemushaWalletAppIdentityV1::Android {
        minimum_package_version,
        ..
    } = &mut edited_app.identity
    else {
        unreachable!()
    };
    *minimum_package_version += 1;
    assert!(enrollment.validate_for_app(&edited_app).is_err());
    let mut added_signer = app.clone();
    let KagemushaWalletAppIdentityV1::Android { signer_set, .. } = &mut added_signer.identity
    else {
        unreachable!()
    };
    signer_set.push([6; 32]);
    added_signer.validate().unwrap();
    assert!(enrollment.validate_for_app(&added_signer).is_err());
    for name in ["", "one", "a..b", "1a.b", "org.exa-mple", "org.é"] {
        let mut changed = app.clone();
        let KagemushaWalletAppIdentityV1::Android { package_name, .. } = &mut changed.identity
        else {
            unreachable!()
        };
        *package_name = name.into();
        assert!(changed.validate().is_err(), "{name}");
    }
    let (mut apple, _) = policy_fixture(true);
    apple.identity = KagemushaWalletAppIdentityV1::Apple {
        app_id: "é".repeat(128),
    };
    assert!(apple.validate().is_err());
    apple.identity = KagemushaWalletAppIdentityV1::Apple {
        app_id: "é".repeat(127) + "a",
    };
    assert!(apple.validate().is_ok());
}

#[test]
fn new_app_policy_signer_set_is_one_to_four_nonzero_strictly_ascending_digests() {
    let (app, _) = policy_fixture(false);
    let with = |signers: Vec<[u8; 32]>| {
        let mut changed = app.clone();
        let KagemushaWalletAppIdentityV1::Android { signer_set, .. } = &mut changed.identity else {
            unreachable!()
        };
        *signer_set = signers;
        changed
    };
    for signers in [
        vec![[1; 32]],
        vec![[1; 32], [2; 32]],
        vec![[1; 32], [2; 32], [3; 32], [0xff; 32]],
    ] {
        let policy = with(signers);
        policy.validate().unwrap();
        let frame = policy.encode_canonical().unwrap();
        assert_eq!(
            KagemushaWalletAppPolicyV1::decode_canonical(&frame, &[1; 32]).unwrap(),
            policy
        );
    }
    for signers in [
        vec![],
        vec![[0; 32]],
        vec![[1; 32], [1; 32]],
        vec![[2; 32], [1; 32]],
        vec![[0; 32], [1; 32]],
        vec![[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
    ] {
        let policy = with(signers.clone());
        assert!(policy.validate().is_err(), "{signers:?}");
        assert!(policy.encode_canonical().is_err());
        assert!(policy.transcript().is_err());
        // A canonically encoded invalid set never decodes as a policy.
        let raw =
            encode_frame_v1(&policy, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1).unwrap();
        assert!(KagemushaWalletAppPolicyV1::decode_canonical(&raw, &[1; 32]).is_err());
    }
}

#[test]
fn new_enrollment_policy_root_set_grammar_pairing_and_order() {
    let (_, policy) = policy_fixture(false);
    let with = |roots: Vec<KagemushaWalletAndroidRootV1>, floor: u32| {
        let mut changed = policy.clone();
        changed.platform = KagemushaWalletEnrollmentPlatformV1::Android {
            root_set: roots,
            patch_floor_yyyymm: floor,
        };
        changed
    };
    let ca1 = KagemushaWalletAndroidRootV1 {
        family: KagemushaWalletAndroidRootFamilyV1::GoogleCa1,
        spki_sha256: [3; 32],
        revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
    };
    for (roots, floor) in [
        (vec![ca1.clone(), google_rsa([4; 32])], 202_501),
        (vec![vendor("huawei", [1; 32]), ca1.clone()], 190_001),
        (vec![vendor("a", [1; 32])], 999_912),
        (vec![vendor("a-b-0123456789xy", [1; 32])], 202_612),
    ] {
        let changed = with(roots, floor);
        changed.validate().unwrap();
        let frame = changed.encode_canonical().unwrap();
        assert_eq!(
            KagemushaWalletEnrollmentPolicyV1::decode_canonical(&frame, &[1; 32]).unwrap(),
            changed
        );
    }
    let mut google_with_denylist = google_rsa([4; 32]);
    google_with_denylist.revocation_source = KagemushaWalletRevocationSourceV1::OperatorDenylist;
    let mut vendor_with_google = vendor("huawei", [4; 32]);
    vendor_with_google.revocation_source =
        KagemushaWalletRevocationSourceV1::GoogleAttestationStatus;
    let mut invalid = vec![
        (vec![], 202_608),
        ((1..=9_u8).map(|i| google_rsa([i; 32])).collect(), 202_608),
        (vec![google_rsa([4; 32]), ca1.clone()], 202_608),
        (vec![google_rsa([4; 32]), google_rsa([4; 32])], 202_608),
        (vec![google_rsa([0; 32])], 202_608),
        (vec![google_with_denylist], 202_608),
        (vec![vendor_with_google], 202_608),
        (vec![google_rsa([4; 32])], 189_912),
        (vec![google_rsa([4; 32])], 202_600),
        (vec![google_rsa([4; 32])], 202_613),
        (vec![google_rsa([4; 32])], 1_000_001),
    ];
    for adapter in [
        "",
        "Huawei",
        "1huawei",
        "-huawei",
        "hua_wei",
        "hua wei",
        "huawéi",
        "abcdefghijklmnopq",
    ] {
        invalid.push((vec![vendor(adapter, [4; 32])], 202_608));
    }
    for (roots, floor) in invalid {
        let changed = with(roots.clone(), floor);
        assert!(changed.validate().is_err(), "{roots:?} {floor}");
        assert!(changed.encode_canonical().is_err());
        let raw =
            encode_frame_v1(&changed, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1).unwrap();
        assert!(KagemushaWalletEnrollmentPolicyV1::decode_canonical(&raw, &[1; 32]).is_err());
    }
}

#[test]
fn new_enrollment_policy_challenge_and_lease_boundaries_without_defaults() {
    let (_, mut android) = policy_fixture(false);
    android.require_live_challenge(10, 10).unwrap();
    android.require_live_challenge(10, 120_009).unwrap();
    for (created, now) in [(0, 1), (10, 9), (10, 120_010), (u64::MAX - 1, u64::MAX)] {
        assert!(android.require_live_challenge(created, now).is_err());
    }
    assert_eq!(android.lease_expires_at(10).unwrap(), 0);
    assert!(android.lease_expires_at(0).is_err());
    let (_, mut apple) = policy_fixture(true);
    assert_eq!(apple.lease_expires_at(10).unwrap(), 3_600_010);
    assert!(apple.lease_expires_at(u64::MAX - 1).is_err());
    apple.attestation_lease_lifetime_ms = 0;
    assert!(apple.validate().is_err());
    android.attestation_lease_lifetime_ms = 1;
    assert!(android.validate().is_err());
    android.attestation_lease_lifetime_ms = 0;
    android.challenge_lifetime_ms = 1;
    android.validate().unwrap();
    android.challenge_lifetime_ms = 0;
    assert!(android.validate().is_err());
}

#[test]
fn new_policy_maximal_norito_frames_fit_the_complete_frame_cap() {
    for apple in [false, true] {
        let (app, enrollment) = maximal_fixture(apple);
        assert_eq!(
            app.transcript().unwrap().len(),
            if apple { 294 } else { 431 },
            "app transcript"
        );
        assert_eq!(
            enrollment.transcript().unwrap().len(),
            if apple { 159 } else { 564 },
            "enrollment transcript"
        );
        let app_frame = app.encode_canonical().unwrap();
        let enrollment_frame = enrollment.encode_canonical().unwrap();
        let template_frame = enrollment.template().encode_canonical().unwrap();
        for (name, frame) in [
            ("app", &app_frame),
            ("enrollment", &enrollment_frame),
            ("template", &template_frame),
        ] {
            assert!(
                frame.len() <= KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1,
                "{name} frame {} bytes (apple {apple})",
                frame.len()
            );
        }
        assert_eq!(
            KagemushaWalletAppPolicyV1::decode_canonical(&app_frame, &[1; 32]).unwrap(),
            app
        );
        assert_eq!(
            KagemushaWalletEnrollmentPolicyV1::decode_canonical(&enrollment_frame, &[1; 32])
                .unwrap(),
            enrollment
        );
        let mut oversized = app.clone();
        match &mut oversized.identity {
            KagemushaWalletAppIdentityV1::Android { package_name, .. } => {
                package_name.push('b');
            }
            KagemushaWalletAppIdentityV1::Apple { app_id } => app_id.push('a'),
        }
        assert!(oversized.validate().is_err());
        assert!(oversized.encode_canonical().is_err());
    }
}
