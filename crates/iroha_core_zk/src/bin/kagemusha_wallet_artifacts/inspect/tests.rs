//! Inspection selects representations explicitly and binds their entire raw closure.

use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
    EncodedOriginalV1, OriginalV1,
};

fn inventory() -> ProducerInventoryV1 {
    // Structural DATA solely for testing the closure comparison, not authentication.
    ProducerInventoryV1 {
        version: 1,
        native_profile: [1; 32],
        originals: vec![OriginalV1 {
            descriptor: BlobV1::of(b"descriptor"),
            verifying_key: BlobV1::of(b"verifier"),
            proving_key: BlobV1::of(b"compact original"),
        }],
        sigma: [0; 11],
        operations: Vec::new(),
        routes: Vec::new(),
        terminals: Vec::new(),
        omega: 0,
    }
}

fn transport(mut raw: Vec<BlobV1>) -> EncodedTransportV1 {
    raw.sort_by_key(|blob| blob.sha256);
    EncodedTransportV1::new(
        raw.into_iter()
            .map(|original| EncodedOriginalV1 {
                original,
                stored: BlobV1::of(b"encoded DATA verified by the native decoder"),
            })
            .collect(),
    )
    .unwrap()
}

#[test]
fn inspection_representation_is_explicit_and_never_a_fallback() {
    assert_eq!(
        Encoding::from_flag("--inspect-sources"),
        Some(Encoding::Raw)
    );
    assert_eq!(
        Encoding::from_flag("--inspect-encoded-sources"),
        Some(Encoding::Zstd)
    );
    for flag in [
        "--inspect",
        "--inspect-encoded",
        "--request",
        "--encode-carrier",
        "zstd",
    ] {
        assert_eq!(Encoding::from_flag(flag), None);
    }
}

#[test]
fn encoded_inspection_requires_exact_signed_original_closure() {
    let mut inventory = inventory();
    let row = inventory.originals[0];
    let raw = vec![row.descriptor, row.verifying_key, row.proving_key];
    require_transport(&inventory, &transport(raw.clone())).unwrap();
    // Shared role originals are deduplicated without relaxing any identity.
    inventory.originals.push(row);
    require_transport(&inventory, &transport(raw.clone())).unwrap();
    for missing in 0..raw.len() {
        let mut changed = raw.clone();
        changed.remove(missing);
        assert!(require_transport(&inventory, &transport(changed)).is_err());
    }
    let mut extra = raw.clone();
    extra.push(BlobV1::of(b"unsigned extra original"));
    assert!(require_transport(&inventory, &transport(extra)).is_err());
    let mut changed = raw.clone();
    changed[0].bytes += 1;
    assert!(require_transport(&inventory, &transport(changed)).is_err());
    inventory.originals[1].descriptor.bytes += 1;
    assert!(require_transport(&inventory, &transport(raw)).is_err());
}

#[test]
fn malformed_inspection_is_read_only_and_never_opens_source_files() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("carrier"))
            .unwrap();
    publish(&root, "verifier-pack.norito", b"invalid signed pack").unwrap();
    publish(
        &root,
        "producer-inventory.norito",
        b"invalid signed inventory",
    )
    .unwrap();
    for encoding in [Encoding::Raw, Encoding::Zstd] {
        assert!(
            sources(
                root.path().to_str().unwrap(),
                &"01".repeat(32),
                &"02".repeat(32),
                encoding
            )
            .is_err()
        );
    }
    assert_eq!(root.entries(10).unwrap().len(), 2);
    assert_eq!(
        std::fs::read(root.path().join("verifier-pack.norito")).unwrap(),
        b"invalid signed pack"
    );
    assert_eq!(
        std::fs::read(root.path().join("producer-inventory.norito")).unwrap(),
        b"invalid signed inventory"
    );
}
