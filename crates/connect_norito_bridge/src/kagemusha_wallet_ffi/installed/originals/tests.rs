//! Closed carrier DATA tests. These inventory fixtures contain no source keys or authority.
use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::OriginalV1;
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
    norito::json::to_json(
        &norito::json!({"schema":"iroha.kagemusha.wallet-artifact-original-transport.v1",
        "walletOriginals":rows}),
    )
    .unwrap()
    .into_bytes()
}
fn rows() -> norito::json::Value {
    norito::json::Value::Array(
        (1u8..=5)
            .map(|n| norito::json!({"bytes":16,"sha256":(hex::encode([n;32]))}))
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
    let mut wallet = DirectoryOriginalsV1::open_existing(
        root.join("wallet-originals"),
        PROVING_KEY_MAX_BYTES_V1,
    )
    .unwrap();
    for (blob, bytes) in blobs.iter().zip(&originals) {
        wallet.store_original(*blob, bytes).unwrap();
    }
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
    let mut source = CatalogReader::load(
        PrivateDirectory::open_exact(&root).unwrap(),
        &root,
        &inventory,
    )
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
fn wallet_catalog_reader_refuses_changed_extent_hash_or_missing_original() {
    let (_temp, root, inventory, originals) = wallet_data_fixture();
    let load = |inventory: &ProducerInventoryV1| {
        CatalogReader::load(
            PrivateDirectory::open_exact(&root).unwrap(),
            &root,
            inventory,
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
    assert!(load(&inventory).is_err_and(|error| error.status == INVALID));
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
            .map(|(hash, bytes)| norito::json!({"bytes":bytes,"sha256":(hex::encode(hash))}))
            .collect();
        norito::json::to_json(&norito::json!({
            "schema":"iroha.kagemusha.wallet-artifact-original-transport.v1",
            "walletOriginals": wallet_originals
        }))
        .unwrap()
        .into_bytes()
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
