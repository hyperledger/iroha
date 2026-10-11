use super::*;

fn root() -> (tempfile::TempDir, PrivateDirectory) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("encoded");
    let root = PrivateDirectory::open_or_create(path).unwrap();
    (temp, root)
}
fn seal(root: &PrivateDirectory, name: &str, bytes: &[u8]) {
    let mut file = root.create_retained_private(name, bytes.len()).unwrap();
    file.write_all(bytes).unwrap();
    file.seal_read_only().unwrap();
}
fn encode(bytes: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(bytes, 1).unwrap()
}
fn input(root: &PrivateDirectory, raw: &[u8], stored: &[u8]) -> EncodedDirectoryOriginalsV1 {
    let row = EncodedOriginalV1 {
        original: BlobV1::of(raw),
        stored: BlobV1::of(stored),
    };
    seal(root, &hex::encode(row.original.sha256), stored);
    EncodedDirectoryOriginalsV1::open_existing(
        root.path(),
        &EncodedTransportV1::new(vec![row]).unwrap(),
    )
    .unwrap()
}
fn refuses(raw: &[u8], stored: &[u8]) {
    let (_temp, root) = root();
    let source = input(&root, raw, stored);
    assert!(source.verify_original(BlobV1::of(raw)).is_err());
}

#[test]
fn encoded_original_roundtrip_and_immutable_publication() {
    let (_temp, destination) = root();
    let raw_path = destination.path().parent().unwrap().join("raw");
    PrivateDirectory::open_or_create(&raw_path).unwrap();
    let mut raw = DirectoryOriginalsV1::open_existing(&raw_path, PROVING_KEY_MAX_BYTES_V1).unwrap();
    let bytes = vec![42; 256 << 10];
    let identity = BlobV1::of(&bytes);
    raw.store_original(identity, &bytes).unwrap();
    let row = encode_original(&raw, &destination, identity).unwrap();
    assert!(row.stored.bytes < identity.bytes);
    let file = destination
        .open_retained_read_only(hex::encode(identity.sha256), ENCODED_ORIGINAL_MAX_BYTES_V1)
        .unwrap();
    let before = file.identity().unwrap();
    assert_eq!(row, encode_original(&raw, &destination, identity).unwrap());
    file.revalidate().unwrap();
    assert_eq!(file.identity().unwrap(), before);
    let transport = EncodedTransportV1::new(vec![row]).unwrap();
    let source =
        EncodedDirectoryOriginalsV1::open_existing(destination.path(), &transport).unwrap();
    let mut reader = source.open_original(identity.sha256).unwrap();
    drop(source);
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(
        std::fs::read(raw_path.join(hex::encode(identity.sha256))).unwrap(),
        bytes
    );
}

#[test]
fn encoded_rejects_corruption_truncation_raw_and_multiple_frames() {
    let raw = b"bounded original bytes, still precisely the signed original";
    let encoded = encode(raw);
    refuses(raw, raw);
    for length in 1..encoded.len() {
        refuses(raw, &encoded[..length]);
    }
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    refuses(raw, &corrupt);
    let mut concatenated = encoded.clone();
    concatenated.extend(encode(b""));
    refuses(raw, &concatenated);
    let mut trailing = encoded;
    trailing.push(0);
    refuses(raw, &trailing);
    // A skippable frame followed by a genuine frame is not the selected representation.
    let mut skippable = vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
    skippable.extend(encode(raw));
    refuses(raw, &skippable);
}

#[test]
fn encoded_checks_both_hashes_lengths_and_expansion_before_last_byte() {
    let raw = b"exact identity";
    let encoded = encode(raw);
    let row = EncodedOriginalV1 {
        original: BlobV1::of(raw),
        stored: BlobV1::of(&encoded),
    };
    for bad in [
        EncodedOriginalV1 {
            original: BlobV1 {
                bytes: row.original.bytes - 1,
                ..row.original
            },
            ..row
        },
        EncodedOriginalV1 {
            original: BlobV1 {
                bytes: row.original.bytes + 1,
                ..row.original
            },
            ..row
        },
        EncodedOriginalV1 {
            stored: BlobV1 {
                sha256: [7; 32],
                ..row.stored
            },
            ..row
        },
        EncodedOriginalV1 {
            stored: BlobV1 {
                bytes: row.stored.bytes + 1,
                ..row.stored
            },
            ..row
        },
    ] {
        let (_temp, root) = root();
        seal(&root, &hex::encode(row.original.sha256), &encoded);
        let source = EncodedDirectoryOriginalsV1::open_existing(
            root.path(),
            &EncodedTransportV1::new(vec![bad]).unwrap(),
        )
        .unwrap();
        assert!(source.verify_original(bad.original).is_err());
    }
    let (_temp, root) = root();
    let source = input(&root, raw, &encode(b"wrong identity"));
    let mut reader = source.open_original(row.original.sha256).unwrap();
    // Reading exactly the declared raw extent is sufficient to close all checks.
    assert!(reader.read_exact(&mut vec![0; raw.len()]).is_err());
    assert!(reader.read(&mut [0; 1]).is_err());
}

#[test]
fn encoded_rejects_excessive_decoder_window() {
    let raw = vec![42; 16 << 20];
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder.window_log(24).unwrap();
    encoder.include_contentsize(false).unwrap();
    for chunk in raw.chunks(64 << 10) {
        encoder.write_all(chunk).unwrap();
    }
    let stored = encoder.finish().unwrap();
    refuses(&raw, &stored);
}

#[cfg(unix)]
#[test]
fn encoded_rejects_symlink_and_path_replacement_even_with_buffered_output() {
    use std::os::unix::fs::symlink;
    let raw = vec![17; 128 << 10];
    let stored = encode(&raw);
    let (_temp, root) = root();
    let source = input(&root, &raw, &stored);
    let identity = BlobV1::of(&raw);
    let name = hex::encode(identity.sha256);
    let mut reader = source.open_original(identity.sha256).unwrap();
    reader.read_exact(&mut [0; 1]).unwrap();
    std::fs::rename(root.path().join(&name), root.path().join("retained-old")).unwrap();
    seal(&root, &name, &stored);
    assert!(matches!(
        source.open_original(identity.sha256),
        Err(Error::Inventory)
    ));
    let error = reader.read(&mut [0; 1]).unwrap_err();
    assert!(
        error
            .get_ref()
            .is_some_and(|e| e.is::<OriginalCustodyFailure>())
    );
    std::fs::remove_file(root.path().join(&name)).unwrap();
    symlink(root.path().join("retained-old"), root.path().join(&name)).unwrap();
    assert!(source.open_original(identity.sha256).is_err());
}

#[test]
fn encoded_initial_absence_never_excuses_later_missing_custody() {
    let (_temp, root) = root();
    let raw = b"original DATA";
    let stored = encode(raw);
    let row = EncodedOriginalV1 {
        original: BlobV1::of(raw),
        stored: BlobV1::of(&stored),
    };
    let source = EncodedDirectoryOriginalsV1::open_existing(
        root.path(),
        &EncodedTransportV1::new(vec![row]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        source.open_original(row.original.sha256),
        Err(Error::Unavailable)
    ));
    let name = hex::encode(row.original.sha256);
    seal(&root, &name, &stored);
    source.verify_original(row.original).unwrap();
    std::fs::rename(
        root.path().join(name),
        root.path().join("retained-original"),
    )
    .unwrap();
    assert!(matches!(
        source.open_original(row.original.sha256),
        Err(Error::Inventory)
    ));
}

#[test]
fn encoded_transport_is_closed_canonical_bounded_data() {
    let row = EncodedOriginalV1 {
        original: BlobV1::of(b"raw"),
        stored: BlobV1::of(b"frame"),
    };
    let transport = EncodedTransportV1::new(vec![row]).unwrap();
    let wire = transport.to_json();
    assert_eq!(EncodedTransportV1::from_json(&wire).unwrap(), transport);
    assert!(wire.ends_with(b"\n"));
    for changed in [
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"encoding\":\"zstd\",", ""),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("zstd", "raw"),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"storedBytes\":5", "\"storedBytes\":0"),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"storedBytes\":5", "\"storedBytes\":5.0"),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"bytes\":3", "\"bytes\":1073741825"),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"storedBytes\":5", "\"storedBytes\":1077936129"),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"bytes\":3", "\"other\":0,\"bytes\":3"),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"bytes\":3", "\"bytes\":3,\"bytes\":3"),
        String::from_utf8(wire.clone())
            .unwrap()
            .replace("{\"schema", "{ \"schema"),
        String::from_utf8(wire.clone())
            .unwrap()
            .trim_end()
            .to_string(),
    ] {
        assert!(
            EncodedTransportV1::from_json(changed.as_bytes()).is_err(),
            "accepted {changed}"
        );
    }
    assert!(EncodedTransportV1::new(vec![]).is_err());
    assert!(EncodedTransportV1::new(vec![row, row]).is_err());
    assert!(EncodedTransportV1::from_json(&vec![b' '; TRANSPORT_MAX_BYTES_V1 + 1]).is_err());
}

#[test]
fn encoded_carrier_publisher_refuses_foreign_or_partial_complete_namespaces() {
    let (_temp, root) = root();
    require_carrier_entries(&root, false).unwrap();
    assert!(require_carrier_entries(&root, true).is_err());
    root.ensure_child("wallet-originals").unwrap();
    for name in [
        "financial-originals.json",
        "producer-inventory.norito",
        "transport.json",
        "verifier-pack.norito",
    ] {
        seal(&root, name, b"DATA");
    }
    require_carrier_entries(&root, true).unwrap();
    seal(&root, "unselected-original", b"PRESERVE");
    assert!(require_carrier_entries(&root, false).is_err());
    assert!(require_carrier_entries(&root, true).is_err());
    assert_eq!(
        std::fs::read(root.path().join("unselected-original")).unwrap(),
        b"PRESERVE"
    );
}
