//! Actual archive envelope/key and content-object tests; no monetary or issuer authority.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletSimFaultV1 as Fault, KagemushaWalletSimFsV1 as SimFs,
    KagemushaWalletSimPowerLossV1 as PowerLoss,
    kagemusha_wallet_archive_object_digest_v1 as object_digest,
};
use crate::kagemusha_wallet_state_v1::ObjectStore;

#[test]
fn canonical_archive_read_preserves_retired_scope_refusal_and_malformed_custody_verdict() {
    let value = vec![7u8; 128];
    let bytes = encode(&value).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let error = norito::with_decode_limits_scope(limits, || decode::<Vec<u8>>(&bytes)).unwrap_err();
    // Classify at the actual decode, then move the original through a retired scope.
    let Error::DecodeResource(original) = error else {
        panic!("archive resource refusal became a custody verdict: {error:?}");
    };
    assert_eq!(
        original.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(
            original.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
    });
    assert_eq!(decode::<Vec<u8>>(&bytes).unwrap(), value);
    let mut malformed = bytes;
    malformed.push(0);
    assert!(matches!(
        decode::<Vec<u8>>(&malformed),
        Err(Error::WitnessLost(_))
    ));
}

#[test]
fn intrinsic_archive_decode_ceiling_under_outer_scope_remains_completed_invalid() {
    let bytes = encode(&vec![7u8; 128]).unwrap();
    let generous = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 64);
    let error = norito::with_decode_limits_scope(generous, || {
        norito::decode_canonical_for_admission::<Vec<u8>>(
            &bytes,
            norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 64),
        )
    })
    .unwrap_err();
    assert_eq!(error.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
    assert!(matches!(
        crate::kagemusha_wallet_state_v1::decode_attempt_error(
            error,
            Error::WitnessLost("intrinsic archive ceiling")
        ),
        Error::WitnessLost("intrinsic archive ceiling")
    ));
}

fn prepared() -> (SimFs, Dir, FsArchive<SimFs>) {
    let fs = SimFs::new();
    let slot = Slot([0x55; 32]);
    let mut dir = Dir::root();
    for component in ["slots", slot.dir_name().as_str(), "archive"] {
        fs.mkdir(&dir, component).unwrap();
        fs.sync_dir(&dir).unwrap();
        dir = dir.child(&Name::new(component).unwrap());
    }
    let archive = FsArchive::new(fs.clone(), slot, [1; 32], [3; 32]).unwrap();
    (fs, dir, archive)
}

fn replace(fs: &SimFs, directory: &Dir, name: &str, original: &[u8]) {
    let staged = fs.staging_name().expect("staging name");
    let mut file = fs.create_new(directory, &staged).unwrap();
    fs.write_all(&mut file, original).unwrap();
    fs.sync_staged(&file).unwrap();
    fs.rename_replace(directory, &staged, name).unwrap();
    fs.sync_dir(directory).unwrap();
}

#[test]
fn every_current_archive_key_has_one_exact_canonical_codec_and_filename() {
    let keys = [
        ArchiveKey::PreparationDraft([7; 32]),
        ArchiveKey::Capsule([4; 32]),
        ArchiveKey::Object([5; 32]),
        ArchiveKey::Checkpoint {
            sequence: u128::MAX,
            ordinal: u32::MAX,
        },
        ArchiveKey::Fold(u128::MAX),
        ArchiveKey::FeeClaim([6; 32]),
    ];
    let (fs, _, mut archive) = prepared();
    for key in keys {
        let name = key.name();
        assert_eq!(parse_key(&name), Some(key));
        let bytes = encode(&key).unwrap();
        assert_eq!(decode::<ArchiveKey>(&bytes).unwrap(), key);
        let mut trailer = bytes;
        trailer.push(0);
        assert!(decode::<ArchiveKey>(&trailer).is_err());
        for changed in [
            name.to_uppercase(),
            name.replace(".arc", ".arc.r"),
            name.replace(".arc", ".arc.extra"),
            format!("x{name}"),
        ] {
            assert!(parse_key(&changed).is_none(), "{changed}");
        }
        archive.put(key, &encode(&key).unwrap()).unwrap();
    }
    fs.power_loss(PowerLoss::DropUnsynced);
    let mut expected = keys.to_vec();
    expected.sort();
    assert_eq!(archive.keys().unwrap(), expected);
    for name in [
        "f-1.arc",
        "f-0000000000000000000000000000000000f.arc",
        "p-00000000000000000000000000000001-1.arc",
        "o-01.arc",
    ] {
        assert!(
            parse_key(name).is_none(),
            "alternate spellings cannot select records"
        );
    }
}

#[test]
fn complete_envelope_scope_key_digest_length_and_canonicality_are_rechecked_on_read() {
    let (fs, directory, mut archive) = prepared();
    let key = ArchiveKey::Object([7; 32]);
    let content = b"retained exact source original".to_vec();
    archive.put(key, &content).unwrap();
    let genuine = fs.read(&directory, &key.name(), 4096).unwrap();
    for selector in 0..7 {
        let mut changed: Envelope = decode(&genuine).unwrap();
        match selector {
            0 => changed.version = 2,
            1 => changed.scheme_id[0] ^= 1,
            2 => changed.wallet_id[0] ^= 1,
            3 => changed.key = ArchiveKey::Object([8; 32]),
            4 => changed.content_digest[0] ^= 1,
            5 | 6 => {
                let mut content = zeroize::Zeroizing::new(changed.content.as_slice().to_vec());
                if selector == 5 {
                    content[0] ^= 1;
                } else {
                    content.push(0);
                }
                changed.content = PrivateArchiveBytes::from_guarded(content);
            }
            _ => unreachable!(),
        }
        let bytes = encode(&changed).unwrap();
        replace(&fs, &directory, &key.name(), &bytes);
        replace(&fs, &directory, &format!("{}.r", key.name()), &bytes);
        assert!(
            matches!(archive.get(key, content.len()), Err(Error::WitnessLost(_))),
            "changed envelope selector {selector}"
        );
    }
    let mut trailer = genuine.clone();
    trailer.push(0);
    replace(&fs, &directory, &key.name(), &trailer);
    replace(&fs, &directory, &format!("{}.r", key.name()), &trailer);
    assert!(matches!(
        archive.get(key, content.len()),
        Err(Error::WitnessLost(_))
    ));
    replace(&fs, &directory, &key.name(), &genuine);
    replace(&fs, &directory, &format!("{}.r", key.name()), &genuine);
    assert_eq!(
        archive.get(key, content.len()).unwrap().as_deref(),
        Some(content.as_slice())
    );
    assert!(archive.get(key, content.len() - 1).is_err());
    assert_eq!(
        archive.get(ArchiveKey::Object([9; 32]), 4096).unwrap(),
        None
    );
    fs.inject(fs.steps(), Fault::Error);
    assert!(matches!(
        archive.get(ArchiveKey::Object([9; 32]), 4096),
        Err(Error::Storage(_))
    ));
}

#[test]
fn exact_content_object_readback_covers_every_byte_and_never_republishes_on_restore() {
    let (fs, directory, mut archive) = prepared();
    let original = vec![0x5a; 262_145];
    let key = archive.write_object(&original, original.len()).unwrap();
    assert_eq!(key, object_digest(&original));
    fs.power_loss(PowerLoss::DropUnsynced);
    assert_eq!(archive.read_object(&key, original.len()).unwrap(), original);
    let name = ArchiveKey::Object(key).name();
    let genuine = fs
        .read(&directory, &name, original.len() + METADATA_BOUND)
        .unwrap();
    let mut changed: Envelope = decode(&genuine).unwrap();
    let mut content = zeroize::Zeroizing::new(changed.content.as_slice().to_vec());
    let last = content.len() - 1;
    content[last] ^= 1;
    changed.content = PrivateArchiveBytes::from_guarded(content);
    // The archive envelope authenticates its own content, while the selected object key
    // independently binds the exact full original. Both gates must be checked on restore.
    changed.content_digest = digest("wallet-archive-content", &changed.content);
    let changed = encode(&changed).unwrap();
    replace(&fs, &directory, &name, &changed);
    replace(&fs, &directory, &format!("{name}.r"), &changed);
    assert_eq!(
        archive
            .get(ArchiveKey::Object(key), original.len())
            .unwrap()
            .unwrap()
            .len(),
        original.len()
    );
    assert!(matches!(
        archive.read_object(&key, original.len()),
        Err(Error::WitnessLost("index object digest"))
    ));
    replace(&fs, &directory, &name, &genuine);
    replace(&fs, &directory, &format!("{name}.r"), &genuine);
    assert_eq!(archive.read_object(&key, original.len()).unwrap(), original);
    assert!(matches!(
        archive.read_object(&[9; 32], original.len()),
        Err(Error::WitnessLost(_))
    ));
    assert!(archive.write_object(&[1; 3], 2).is_err());
}

#[test]
fn archive_staging_entropy_failure_is_storage_error_and_retry_restores_both_copies() {
    let key = ArchiveKey::Fold(91);
    let content = b"exact retained fold witness";
    for before_error in [0, 1] {
        let (fs, directory, mut archive) = prepared();
        fs.inject_staging_name_error(before_error, io::ErrorKind::Other);
        assert!(matches!(archive.put(key, content), Err(Error::Storage(_))));
        let expected_names = if before_error == 0 {
            Vec::new()
        } else {
            vec![key.name()]
        };
        assert_eq!(fs.visible_names(&directory), expected_names);
        fs.power_loss(PowerLoss::DropUnsynced);
        assert_eq!(fs.visible_names(&directory), expected_names);
        let expected_content = (before_error != 0).then(|| content.to_vec());
        assert_eq!(
            archive.get(key, content.len()).unwrap().as_deref(),
            expected_content.as_deref()
        );
        archive.put(key, content).unwrap();
        fs.power_loss(PowerLoss::DropUnsynced);
        assert_eq!(
            archive.get(key, content.len()).unwrap().as_deref(),
            Some(content.as_slice())
        );
        let first = fs.read(&directory, &key.name(), 4096).unwrap();
        assert_eq!(
            fs.read(&directory, &format!("{}.r", key.name()), 4096)
                .unwrap(),
            first
        );
    }
}

#[test]
fn archive_staging_entropy_failure_leaves_existing_exact_record_readable() {
    let (fs, directory, mut archive) = prepared();
    let key = ArchiveKey::Fold(92);
    let content = b"existing durable witness";
    archive.put(key, content).unwrap();
    let original = fs.read(&directory, &key.name(), 4096).unwrap();
    let names = fs.visible_names(&directory);
    fs.inject_staging_name_error(0, io::ErrorKind::Other);
    let before = fs.steps();
    assert!(matches!(archive.put(key, content), Err(Error::Storage(_))));
    assert_eq!(
        fs.trace_since(before),
        [crate::kagemusha_wallet_advance_v1::KagemushaWalletSimStepV1::Read]
    );
    assert_eq!(fs.visible_names(&directory), names);
    assert_eq!(fs.read(&directory, &key.name(), 4096).unwrap(), original);
    assert_eq!(
        fs.read(&directory, &format!("{}.r", key.name()), 4096)
            .unwrap(),
        original
    );
    assert_eq!(
        archive.get(key, content.len()).unwrap().as_deref(),
        Some(content.as_slice())
    );
    archive.put(key, content).unwrap();
    fs.power_loss(PowerLoss::DropUnsynced);
    assert_eq!(
        archive.get(key, content.len()).unwrap().as_deref(),
        Some(content.as_slice())
    );
}

const CURRENT_OBJECT_CONTENT: &[u8] = b"stored current-schema object";
// Fixed provider addresses for ArchiveKey payload alignment 8 and 16, respectively.
const CURRENT_OBJECT_IDENTITIES: [&str; 2] = [
    "370c494b3d55ee8c0a0d9b9e13b37863f6b1b7a56786c8dd830cad07ba0eedd8",
    "bc32f049fdccf80850e7d00b8a59865c00584d5b3938d7ba6c510ac95e37be19",
];
const CURRENT_CAPSULE_IDENTITIES: [&str; 2] = [
    "882b9f56a1f15580ad6212ceb68e8ae74a806be009c36e2b33eb09fe4520a7c6",
    "7fe05c5cee7ac3b2f3beb3c103d5aa1afd602c4a09560442f8a684ae47afe79d",
];

fn current_archive_key_alignment_index() -> usize {
    // Norito frames pad their 40-byte header to the encoded type's alignment. The
    // enum contains u128: supported targets use either 8-byte or 16-byte alignment.
    match core::mem::align_of::<ArchiveKey>() {
        8 => 0,
        16 => 1,
        alignment => panic!("unsupported ArchiveKey alignment: {alignment}"),
    }
}

#[test]
fn current_archive_key_frames_and_provider_identities_are_fixed() {
    // Fixed complete frames pin the current schema's ordinals 0..=8 on both supported
    // alignments. A round trip alone would accept accidental stored-address renumbering.
    let alignment_index = current_archive_key_alignment_index();
    for (key, frames, identities) in [
        (
            ArchiveKey::BootstrapPreparation,
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440004000000000000004b9f1b1e3586a5f40000000000",
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440004000000000000004b9f1b1e3586a5f400000000000000000000000000",
            ],
            [
                "be519f3b873d8b63a606b01d5bc5a7fb98ac92b62072e6bf3ed5abef68d44de4",
                "dda6f0f77cd3cc00792c1ea40d7586bf83b4abfa5ceb269f9efcacd7d452e26a",
            ],
        ),
        (
            ArchiveKey::BootstrapFrozen,
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf244000400000000000000973e373c6b0c4be90001000000",
                "4e5254300000086e2ebbc03aca5c0da96517febaf244000400000000000000973e373c6b0c4be900000000000000000001000000",
            ],
            [
                "255f13440ef8d30ede664417a5319fa5959fe693ab7f42c3982c26db121e5005",
                "5264a3975dc7409d6deaabfa1d3d22ba875ec228bfc2d9bf321d3850ad5c2ff6",
            ],
        ),
        (
            ArchiveKey::Capsule([0x22; 32]),
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440025000000000000009e1b299866a8e89f0202000000202222222222222222222222222222222222222222222222222222222222222222",
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440025000000000000009e1b299866a8e89f02000000000000000002000000202222222222222222222222222222222222222222222222222222222222222222",
            ],
            [
                "882b9f56a1f15580ad6212ceb68e8ae74a806be009c36e2b33eb09fe4520a7c6",
                "7fe05c5cee7ac3b2f3beb3c103d5aa1afd602c4a09560442f8a684ae47afe79d",
            ],
        ),
        (
            ArchiveKey::SourceCustody([0x33; 32]),
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf244002500000000000000691aaa421a617b710203000000203333333333333333333333333333333333333333333333333333333333333333",
                "4e5254300000086e2ebbc03aca5c0da96517febaf244002500000000000000691aaa421a617b7102000000000000000003000000203333333333333333333333333333333333333333333333333333333333333333",
            ],
            [
                "1a58b21999e338436774e31d5e57cfe363b1ee754e809cff7d6714582e899607",
                "3d4a22af81415d1bb1ae56de5cfd39ed23b275ada7a878abde7d13456dc3dfcc",
            ],
        ),
        (
            ArchiveKey::Object(object_digest(CURRENT_OBJECT_CONTENT)),
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440025000000000000001501c0d824459a760204000000208371419fe31387aad2f25e7b7c54d0419cda1a262671d81cee75590a567170b3",
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440025000000000000001501c0d824459a7602000000000000000004000000208371419fe31387aad2f25e7b7c54d0419cda1a262671d81cee75590a567170b3",
            ],
            [
                "370c494b3d55ee8c0a0d9b9e13b37863f6b1b7a56786c8dd830cad07ba0eedd8",
                "bc32f049fdccf80850e7d00b8a59865c00584d5b3938d7ba6c510ac95e37be19",
            ],
        ),
        (
            ArchiveKey::Checkpoint {
                sequence: u128::MAX,
                ordinal: u32::MAX,
            },
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf244001a00000000000000468c67667efd945e020500000010ffffffffffffffffffffffffffffffff04ffffffff",
                "4e5254300000086e2ebbc03aca5c0da96517febaf244001a00000000000000468c67667efd945e0200000000000000000500000010ffffffffffffffffffffffffffffffff04ffffffff",
            ],
            [
                "caa08646e2e469154c8f8705801d442c85662463e13ffc19ff52d746b3af342d",
                "12ac51a5e77908c5da2c5da367e156de663e4bb5422c8616be92bb48f61c2181",
            ],
        ),
        (
            ArchiveKey::Fold(u128::MAX),
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf24400150000000000000055b74c8c97d2fc5a020600000010ffffffffffffffffffffffffffffffff",
                "4e5254300000086e2ebbc03aca5c0da96517febaf24400150000000000000055b74c8c97d2fc5a0200000000000000000600000010ffffffffffffffffffffffffffffffff",
            ],
            [
                "e57ae8453521816ac74b01cf1b792bca344b6763a11a9e2539a93a1079a368ad",
                "9b3a4e47ea4abbc841ab1cd159964291080cea94220c0aaab099409149a9c1f9",
            ],
        ),
        (
            ArchiveKey::FeeClaim([0x77; 32]),
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf244002500000000000000bf20ba76be1a85ee0207000000207777777777777777777777777777777777777777777777777777777777777777",
                "4e5254300000086e2ebbc03aca5c0da96517febaf244002500000000000000bf20ba76be1a85ee02000000000000000007000000207777777777777777777777777777777777777777777777777777777777777777",
            ],
            [
                "24ab903a3cde5ffdef951371b2a432deffaa491c7139138f0da003f19d489a57",
                "d136828bb84daab2133a34ffd6c16ccd252f2c47a82a57c4867045494b023dc4",
            ],
        ),
        (
            ArchiveKey::PreparationDraft([0x22; 32]),
            [
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440025000000000000005ea3a9be7de9c9420208000000202222222222222222222222222222222222222222222222222222222222222222",
                "4e5254300000086e2ebbc03aca5c0da96517febaf2440025000000000000005ea3a9be7de9c94202000000000000000008000000202222222222222222222222222222222222222222222222222222222222222222",
            ],
            [
                "40d92f585e457aafb23bc6ee83cfedc9e88a9a8f1110376c37c0a50de73a1c13",
                "9cefa2912aeddfc5a24f030707e71deac62c95805e9cece599be92296ce12aa0",
            ],
        ),
    ] {
        let expected = hex::decode(frames[alignment_index]).expect("fixed canonical frame");
        assert_eq!(encode(&key).expect("canonical key"), expected);
        assert_eq!(decode::<ArchiveKey>(&expected).expect("current key"), key);
        assert_eq!(
            hex::encode(digest("wallet-archive-key", &expected)),
            identities[alignment_index],
        );
    }
}

#[test]
fn provider_reopens_records_at_current_object_and_capsule_identities() {
    use crate::kagemusha_wallet_advance_v1::{
        KagemushaWalletAnchorPolicyV1 as Policy, KagemushaWalletProviderOptionsV1,
        KagemushaWalletProviderV1, test_support::bootstrapped_provider,
    };
    use crate::kagemusha_wallet_state_v1::{AdvanceHandle, Custody};

    // Exercise the real provider/archive adapters on the existing simulated storage fixture.
    // The fixture's test Bootstrap is storage setup, not monetary or proof authority.
    let alignment_index = current_archive_key_alignment_index();
    for policy in [Policy::NotRequired, Policy::Keychain] {
        let fs = SimFs::new();
        let (mut provider, platform, slot, _) = bootstrapped_provider(fs.clone(), policy, 0x6b);
        let before = provider.status(&slot).expect("bootstrapped status");
        let marker = before.marker().expect("current marker").marker();
        let scheme_id = marker.scheme_id;
        let wallet_id = marker.wallet_id;
        let cases = [
            (
                ArchiveKey::Object(object_digest(CURRENT_OBJECT_CONTENT)),
                CURRENT_OBJECT_CONTENT,
                CURRENT_OBJECT_IDENTITIES[alignment_index],
            ),
            (
                ArchiveKey::Capsule([0x22; 32]),
                b"stored current-schema capsule".as_slice(),
                CURRENT_CAPSULE_IDENTITIES[alignment_index],
            ),
        ];
        for (key, content, identity) in cases {
            let identity: [u8; 32] = hex::decode(identity)
                .expect("fixed provider identity")
                .try_into()
                .expect("32-byte identity");
            let record = encode(&Envelope {
                version: 1,
                scheme_id,
                wallet_id,
                key,
                content_digest: digest("wallet-archive-content", content),
                content: PrivateArchiveBytes::copy_from(content).expect("private content"),
            })
            .expect("authenticated current envelope");
            // Seed the fixed record address directly; deriving it from today's enum would
            // make this test blind to the insertion that moved Object=4 and Capsule=2.
            provider
                .with_archive(&slot, |archive| archive.write_record(&identity, &record))
                .expect("durable current record");
        }
        drop(provider);
        fs.power_loss(PowerLoss::DropUnsynced);
        let provider = KagemushaWalletProviderV1::open(
            fs,
            platform,
            scheme_id,
            KagemushaWalletProviderOptionsV1 {
                ballast_bytes: 2_048, // Match bootstrapped_provider's storage fixture.
            },
        )
        .expect("reopen existing custody");
        let mut handle = AdvanceHandle::new(provider, slot);
        let mut archive = handle.archive(scheme_id, wallet_id);
        for (key, content, _) in cases {
            assert_eq!(
                archive
                    .get(key, 128)
                    .expect("retrieve current key")
                    .as_deref(),
                Some(content),
            );
        }
        assert_eq!(
            archive
                .read_object(&object_digest(CURRENT_OBJECT_CONTENT), 128)
                .expect("retrieve current content-addressed object"),
            CURRENT_OBJECT_CONTENT,
        );
        assert_eq!(Custody::status(&mut handle).expect("same custody"), before);
    }
}
