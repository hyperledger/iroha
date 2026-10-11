//! Actual archive envelope/key and content-object tests; no monetary or issuer authority.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletSimFaultV1 as Fault, KagemushaWalletSimFsV1 as SimFs,
    KagemushaWalletSimPowerLossV1 as PowerLoss,
    kagemusha_wallet_archive_object_digest_v1 as object_digest,
};
use crate::kagemusha_wallet_state_v1::ObjectStore;

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
            5 => changed.content[0] ^= 1,
            6 => changed.content.push(0),
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
        archive.get(key, content.len()).unwrap(),
        Some(content.clone())
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
    let last = changed.content.len() - 1;
    changed.content[last] ^= 1;
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
        assert_eq!(archive.get(key, content.len()).unwrap(), expected_content);
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
