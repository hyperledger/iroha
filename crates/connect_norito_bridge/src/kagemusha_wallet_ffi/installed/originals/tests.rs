//! Closed carrier DATA tests. These inventory fixtures contain no source keys or authority.
use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
    DirectoryOriginalsV1, OpeningWorkV1, OriginalV1, encode_original,
};
fn fixture() -> ProducerInventoryV1 {
    let blob = |n| BlobV1 {
        bytes: 16,
        sha256: [n; 32],
    };
    ProducerInventoryV1 {
        version: 1,
        native_profile: [0; 32],
        originals: vec![
            OriginalV1 {
                descriptor: blob(1),
                verifying_key: blob(2),
                proving_key: blob(3),
            },
            OriginalV1 {
                descriptor: blob(3),
                verifying_key: blob(4),
                proving_key: blob(5),
            },
        ],
        sigma: [0; 16],
        operations: vec![],
        routes: vec![],
        terminals: vec![],
        omega: 0,
    }
}
fn transport(rows: norito::json::Value) -> Vec<u8> {
    format!("{{\"schema\":\"iroha.kagemusha.wallet-artifact-original-transport.v1\",\"encoding\":\"zstd\",\"walletOriginals\":{}}}\n", norito::json::to_json(&rows).unwrap()).into_bytes()
}
fn fixture_transport(root: &Path) -> EncodedTransportV1 {
    EncodedTransportV1::from_json(&std::fs::read(root.join("transport.json")).unwrap()).unwrap()
}
fn rows() -> norito::json::Value {
    norito::json::Value::Array(
        (1u8..=5)
            .map(|n| norito::json!({"bytes":16,"sha256":(hex::encode([n;32])),"storedBytes":20,"storedSha256":(hex::encode([n+10;32]))}))
            .collect(),
    )
}
#[test]
fn transport_is_the_exact_sorted_deduplicated_whole_catalog_closure() {
    require_transport(&fixture(), &transport(rows())).unwrap();
    let norito::json::Value::Array(mut actual) = rows() else {
        panic!("rows")
    };
    actual.swap(0, 1);
    assert!(require_transport(&fixture(), &transport(norito::json::Value::Array(actual))).is_err());
    let norito::json::Value::Array(mut actual) = rows() else {
        panic!("rows")
    };
    actual.push(actual[0].clone());
    assert!(require_transport(&fixture(), &transport(norito::json::Value::Array(actual))).is_err());
    let norito::json::Value::Array(mut actual) = rows() else {
        panic!("rows")
    };
    actual.pop();
    assert!(require_transport(&fixture(), &transport(norito::json::Value::Array(actual))).is_err());
}
#[test]
fn transport_extent_and_cross_role_conflicts_cannot_choose_other_originals() {
    let mut inventory = fixture();
    inventory.originals[1].descriptor.bytes = 17;
    assert!(require_transport(&inventory, &transport(rows())).is_err());
    let mut roles = BTreeMap::new();
    let original = BlobV1 {
        bytes: 16,
        sha256: [3; 32],
    };
    insert(&mut roles, original).unwrap();
    insert(&mut roles, original).unwrap();
    assert_eq!(roles[&original.sha256], original);
    assert!(
        insert(
            &mut roles,
            BlobV1 {
                bytes: 17,
                ..original
            },
        )
        .is_err()
    );
    assert!(
        insert(
            &mut roles,
            BlobV1 {
                bytes: 0,
                ..original
            },
        )
        .is_err()
    );
    assert!(
        insert(
            &mut roles,
            BlobV1 {
                sha256: [0; 32],
                ..original
            },
        )
        .is_err()
    );
}
#[test]
fn partial_offerings_are_invalid_and_io_never_means_financial_absence() {
    assert_eq!(
        storage(std::io::Error::from(std::io::ErrorKind::NotFound)).status,
        INVALID
    );
    assert_eq!(
        storage(std::io::Error::from(std::io::ErrorKind::InvalidData)).status,
        INVALID
    );
    assert_eq!(
        storage(std::io::Error::from(std::io::ErrorKind::PermissionDenied)).status,
        UNAVAILABLE
    );
    let extra = norito::json::to_json(
        &norito::json!({"schema":"iroha.kagemusha.wallet-artifact-original-transport.v1",
        "walletOriginals":[],"finalityOriginals":[],"ready":true}),
    )
    .unwrap()
    .into_bytes();
    assert!(require_transport(&fixture(), &extra).is_err());
}

#[test]
fn retired_project_transport_schema_is_rejected_even_with_exact_rows() {
    let raw = transport(rows());
    let old = std::str::from_utf8(&raw).unwrap().replace(
        "iroha.kagemusha.wallet-artifact-original-transport.v1",
        "bpng.current-wallet-artifact-original-transport.v1",
    );
    assert!(require_transport(&fixture(), old.as_bytes()).is_err());
}

#[test]
fn metadata_inventory_requires_the_four_current_originals_and_wallet_cas_child() {
    // This owner-private namespace observation conveys no verifier or source authority.
    let temp = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temp.path().join("bundle")).unwrap();
    root.ensure_child("wallet-originals").unwrap();
    for name in [
        "verifier-pack.norito",
        "producer-inventory.norito",
        "transport.json",
    ] {
        root.write_atomic(name, b"DATA", iroha_fs::PublishMode::CreateNew)
            .unwrap();
    }
    assert_eq!(
        require_metadata_inventory(&root).unwrap_err().status,
        INVALID
    );
    root.write_atomic(
        "financial-originals.json",
        b"DATA",
        iroha_fs::PublishMode::CreateNew,
    )
    .unwrap();
    require_metadata_inventory(&root).unwrap();
    root.write_atomic(
        "wallet-verifier-pack.norito",
        b"AMBIGUOUS_DATA",
        iroha_fs::PublishMode::CreateNew,
    )
    .unwrap();
    assert_eq!(
        require_metadata_inventory(&root).unwrap_err().status,
        INVALID
    );
}

/// Inert source DATA, not a signed inventory or qualified wallet. This exercises
/// the same private directory reader used after production inventory authentication.
fn wallet_data_fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    ProducerInventoryV1,
    [Vec<u8>; 3],
) {
    let temp = tempfile::tempdir().unwrap();
    // The immutable reader deliberately rejects OS path aliases such as macOS /var.
    let root = temp.path().canonicalize().unwrap().join("bundle");
    let metadata = PrivateDirectory::open_or_create(&root).unwrap();
    metadata.ensure_child("wallet-originals").unwrap();
    // Exact original readers reject OS aliases such as macOS /var -> /private/var.
    let root = root.canonicalize().unwrap();
    let originals = [
        b"inert wallet descriptor DATA".to_vec(),
        b"inert wallet verifying key DATA".to_vec(),
        b"inert wallet proving key DATA".to_vec(),
    ];
    let blobs = originals.each_ref().map(|bytes| BlobV1::of(bytes));
    let raw_root = root.parent().unwrap().join("raw");
    PrivateDirectory::open_or_create(&raw_root).unwrap();
    let target = PrivateDirectory::open_exact(root.join("wallet-originals")).unwrap();
    let mut wallet =
        DirectoryOriginalsV1::open_existing(raw_root, PROVING_KEY_MAX_BYTES_V1).unwrap();
    let mut encoded = Vec::new();
    for (blob, bytes) in blobs.iter().zip(&originals) {
        wallet.store_original(*blob, bytes).unwrap();
        encoded.push(encode_original(&wallet, &target, *blob).unwrap());
    }
    encoded.sort_by_key(|row| row.original.sha256);
    metadata
        .write_atomic(
            "transport.json",
            &EncodedTransportV1::new(encoded).unwrap().to_json(),
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    let mut inventory = fixture();
    inventory.originals = vec![OriginalV1 {
        descriptor: blobs[0],
        verifying_key: blobs[1],
        proving_key: blobs[2],
    }];
    (temp, root, inventory, originals)
}

#[test]
fn wallet_catalog_reader_requires_only_wallet_artifacts() {
    let (_temp, root, inventory, originals) = wallet_data_fixture();
    let mut source = CatalogReader::open(
        PrivateDirectory::open_exact(&root).unwrap(),
        &root,
        &inventory,
        &fixture_transport(&root),
    )
    .unwrap();
    source
        .with_snapshot::<_, OriginalError>(|snapshot| {
            for original in &originals {
                let mut bytes = Vec::new();
                snapshot
                    .open(BlobV1::of(original).sha256)?
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(&bytes, original);
            }
            assert!(matches!(
                snapshot.open([0x55; 32]),
                Err(OriginalError::Inventory)
            ));
            Ok(())
        })
        .unwrap();
    for original in &originals {
        let digest = BlobV1::of(original).sha256;
        let mut bytes = Vec::new();
        OriginalSourceV1::open(&mut source, digest)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(&bytes, original);
    }
    assert!(!root.join("finality-originals").exists());
    assert!(matches!(
        OriginalSourceV1::open(&mut source, [0x55; 32]),
        Err(OriginalError::Inventory)
    ));
}

#[test]
fn wallet_catalog_snapshot_refuses_changed_extent_hash_or_missing_original() {
    let (_temp, root, inventory, originals) = wallet_data_fixture();
    let load = |inventory: &ProducerInventoryV1| {
        CatalogReader::open(
            PrivateDirectory::open_exact(&root).unwrap(),
            &root,
            inventory,
            &fixture_transport(&root),
        )
    };
    let mut wrong_length = inventory.clone();
    wrong_length.originals[0].verifying_key.bytes += 1;
    assert!(load(&wrong_length).is_err_and(|error| error.status == INVALID));
    let mut wrong_hash = inventory.clone();
    wrong_hash.originals[0].descriptor.sha256 = [0x66; 32];
    assert!(load(&wrong_hash).is_err_and(|error| error.status == INVALID));

    // Identical bytes outside the selected directory cannot satisfy the catalog.
    let name = hex::encode(BlobV1::of(&originals[1]).sha256);
    std::fs::rename(root.join("wallet-originals").join(&name), root.join(&name)).unwrap();
    let source = load(&inventory).unwrap();
    let mut entered = false;
    assert!(
        source
            .with_snapshot::<_, OriginalError>(|_| {
                entered = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!entered);
}

#[test]
fn wallet_snapshot_keeps_observed_original_identity_for_live_runtime_reads() {
    let (_temp, root, inventory, originals) = wallet_data_fixture();
    let mut source = CatalogReader::open(
        PrivateDirectory::open_exact(&root).unwrap(),
        &root,
        &inventory,
        &fixture_transport(&root),
    )
    .unwrap();
    source
        .with_snapshot::<_, OriginalError>(|_| Ok(()))
        .unwrap();
    let digest = BlobV1::of(&originals[0]).sha256;
    let path = root.join("wallet-originals").join(hex::encode(digest));
    std::fs::rename(path, root.join("retained-original")).unwrap();
    assert!(matches!(source.open(digest), Err(OriginalError::Inventory)));
}

#[test]
fn wallet_snapshot_closes_metadata_ancestry_on_body_failure() {
    let (_temp, root, inventory, _) = wallet_data_fixture();
    let source = CatalogReader::open(
        PrivateDirectory::open_exact(&root).unwrap(),
        &root,
        &inventory,
        &fixture_transport(&root),
    )
    .unwrap();
    let result = source.with_snapshot::<(), OriginalError>(|_| {
        std::fs::rename(&root, root.with_file_name("retained-bundle")).unwrap();
        Err(OriginalError::Unavailable)
    });
    assert!(matches!(result, Err(OriginalError::Inventory)));
}

#[test]
fn wallet_transport_requires_all_originals_and_rejects_retired_finality_graph() {
    let (_temp, _root, inventory, _originals) = wallet_data_fixture();
    let record = &inventory.originals[0];
    let blobs = [record.descriptor, record.verifying_key, record.proving_key];
    let wire = |indices: &[usize]| {
        let mut rows: Vec<_> = indices
            .iter()
            .map(|&i| (blobs[i].sha256, blobs[i].bytes))
            .collect();
        rows.sort();
        let wallet_originals: Vec<_> = rows
            .into_iter()
            .map(|(hash, bytes)| norito::json!({"bytes":bytes,"sha256":(hex::encode(hash)),"storedBytes":20,"storedSha256":(hex::encode([7;32]))}))
            .collect();
        transport(norito::json::Value::Array(wallet_originals))
    };
    require_transport(&inventory, &wire(&[0, 1, 2])).unwrap();
    for indices in [&[0][..], &[1], &[0, 1], &[0, 2], &[]] {
        assert!(require_transport(&inventory, &wire(indices)).is_err());
    }
    let mut retired: norito::json::Value = norito::json::from_slice(&wire(&[0, 1, 2])).unwrap();
    retired
        .as_object_mut()
        .unwrap()
        .insert("finalityOriginals".into(), norito::json!([]));
    assert!(require_transport(&inventory, &norito::json::to_vec(&retired).unwrap()).is_err());
}

/// The inert DATA carrier after its complete admission snapshot, as a memo entry holds it.
fn admitted_reader(root: &Path, inventory: &ProducerInventoryV1) -> CatalogReader {
    let source = CatalogReader::open(
        PrivateDirectory::open_exact(root).unwrap(),
        root,
        inventory,
        &fixture_transport(root),
    )
    .unwrap();
    source
        .with_snapshot::<_, OriginalError>(|_| Ok(()))
        .unwrap();
    source
}
/// A later attempt's freshly opened root and transport, offered to the admitted reader.
fn reuse_at(source: &CatalogReader, root: &Path) -> Result<()> {
    source.reuse(
        &PrivateDirectory::open_exact(root).unwrap(),
        &fixture_transport(root),
    )
}

#[test]
fn admitted_reader_reuse_closes_custody_and_rehashes_frames_without_decoding() {
    let (_temp, root, inventory, originals) = wallet_data_fixture();
    let transport = fixture_transport(&root);
    let source = CatalogReader::open(
        PrivateDirectory::open_exact(&root).unwrap(),
        &root,
        &inventory,
        &transport,
    )
    .unwrap();
    // Reuse never stands in for the complete admission snapshot.
    assert_eq!(reuse_at(&source, &root), Err(Failure::code(INVALID)));
    let before = OpeningWorkV1::current_thread();
    source
        .with_snapshot::<_, OriginalError>(|_| Ok(()))
        .unwrap();
    let admission = OpeningWorkV1::current_thread().since(before);
    let before = OpeningWorkV1::current_thread();
    reuse_at(&source, &root).unwrap();
    let reuse = OpeningWorkV1::current_thread().since(before);
    let stored: u64 = transport
        .originals()
        .iter()
        .map(|row| row.stored.bytes)
        .sum();
    let raw: u64 = transport
        .originals()
        .iter()
        .map(|row| row.original.bytes)
        .sum();
    assert_eq!(admission.zstd_decodes, 3);
    assert_eq!(admission.raw_bytes_hashed, raw);
    // The second opening skips every decode: one custody check and one stored-frame hash
    // per original, against the transport the admission verified.
    assert_eq!(reuse.stored_files_opened, 3);
    assert_eq!(reuse.stored_bytes_hashed, stored);
    assert_eq!(reuse.zstd_decodes, 0);
    assert_eq!(reuse.raw_bytes_hashed, 0);
    // The next owner shares the same reader and observed map and reads identical bytes.
    let mut reused = source.clone();
    assert!(Arc::ptr_eq(&reused.wallet, &source.wallet));
    for original in &originals {
        let mut bytes = Vec::new();
        OriginalSourceV1::open(&mut reused, BlobV1::of(original).sha256)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(&bytes, original);
    }
    reuse_at(&source, &root).unwrap();
}

#[test]
fn admitted_reader_reuse_requires_the_same_transport_and_root_object() {
    let (temp, root, inventory, _) = wallet_data_fixture();
    let source = admitted_reader(&root, &inventory);
    let transport = fixture_transport(&root);
    // Another transport, even one stored identity, routes another graph.
    let mut rows = transport.originals().to_vec();
    rows[0].stored.sha256 = [0x77; 32];
    let other = EncodedTransportV1::new(rows).unwrap();
    assert_eq!(
        source.reuse(&PrivateDirectory::open_exact(&root).unwrap(), &other),
        Err(Failure::code(INVALID))
    );
    // Another directory object is another carrier root.
    let elsewhere = temp.path().canonicalize().unwrap().join("elsewhere");
    PrivateDirectory::open_or_create(&elsewhere).unwrap();
    assert_eq!(
        source.reuse(
            &PrivateDirectory::open_exact(&elsewhere).unwrap(),
            &transport
        ),
        Err(Failure::code(INVALID))
    );
    reuse_at(&source, &root).unwrap();
    // A root replaced at the same path is refused, whatever it contains.
    std::fs::rename(&root, root.with_file_name("retained-bundle")).unwrap();
    PrivateDirectory::open_or_create(&root).unwrap();
    assert!(
        source
            .reuse(&PrivateDirectory::open_exact(&root).unwrap(), &transport)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn custody_change_or_corrupted_frame_after_admission_refuses_reuse() {
    use std::os::unix::fs::PermissionsExt as _;
    for corrupt in [false, true] {
        let (_temp, root, inventory, originals) = wallet_data_fixture();
        let source = admitted_reader(&root, &inventory);
        reuse_at(&source, &root).unwrap();
        let path = root
            .join("wallet-originals")
            .join(hex::encode(BlobV1::of(&originals[1]).sha256));
        let mut stored = std::fs::read(&path).unwrap();
        if corrupt {
            // The same extent rewritten in place with one changed stored byte.
            let last = stored.len() - 1;
            stored[last] ^= 1;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        } else {
            // Identical bytes under the same name, as another file.
            std::fs::rename(&path, root.join("retained-original")).unwrap();
        }
        std::fs::write(&path, &stored).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            reuse_at(&source, &root),
            Err(Failure::code(INVALID)),
            "corrupt {corrupt}"
        );
    }
}

#[test]
fn failed_live_original_access_marks_the_shared_reader_and_refuses_reuse() {
    let (_temp, root, inventory, _) = wallet_data_fixture();
    let source = admitted_reader(&root, &inventory);
    reuse_at(&source, &root).unwrap();
    // A live owner's refused open, through any clone, marks the shared reader.
    let mut live = source.clone();
    assert!(matches!(
        OriginalSourceV1::open(&mut live, [0x55; 32]),
        Err(OriginalError::Inventory)
    ));
    // Custody is unchanged, yet this reader is never shared with another owner again.
    assert_eq!(reuse_at(&source, &root), Err(Failure::code(INVALID)));
    // A refused live read marks it too; successful reads pass their bytes through unmarked.
    struct Refusing;
    impl Read for Refusing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("DATA refusal"))
        }
    }
    let failed = Arc::new(AtomicBool::new(false));
    let mut watched = Watched {
        reader: Box::new(&b"DATA"[..]),
        failed: Arc::clone(&failed),
    };
    let mut bytes = Vec::new();
    watched.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"DATA");
    assert!(!failed.load(Ordering::SeqCst));
    let mut watched = Watched {
        reader: Box::new(Refusing),
        failed: Arc::clone(&failed),
    };
    assert!(watched.read(&mut [0; 1]).is_err());
    assert!(failed.load(Ordering::SeqCst));
}

#[test]
fn concurrent_reuse_of_one_admitted_reader_stays_exact() {
    let (_temp, root, inventory, originals) = wallet_data_fixture();
    let source = admitted_reader(&root, &inventory);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                reuse_at(&source, &root).unwrap();
                let mut reused = source.clone();
                for original in &originals {
                    let mut bytes = Vec::new();
                    OriginalSourceV1::open(&mut reused, BlobV1::of(original).sha256)
                        .unwrap()
                        .read_to_end(&mut bytes)
                        .unwrap();
                    assert_eq!(&bytes, original);
                }
            });
        }
    });
    reuse_at(&source, &root).unwrap();
}
