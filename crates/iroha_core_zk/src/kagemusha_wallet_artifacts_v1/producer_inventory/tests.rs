//! Structural inventory and content-reader tests; these bytes are not proof artifacts.

use std::{collections::BTreeMap, io::Cursor};

use super::*;

#[path = "sigma_tests.rs"]
mod sigma_tests;

#[test]
fn original_io_failure_remains_distinct_from_wrong_length_or_hash() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
    }
    impl OriginalSourceV1 for Broken {
        fn open(&mut self, _: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
            Ok(Box::new(Broken))
        }
    }
    let blob = BlobV1::of(&[1, 2, 3]);
    assert_eq!(read(&mut Broken, blob, 3), Err(Error::Unavailable));
    struct Bytes(Vec<u8>);
    impl OriginalSourceV1 for Bytes {
        fn open(&mut self, _: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
            Ok(Box::new(Cursor::new(&self.0)))
        }
    }
    assert_eq!(read(&mut Bytes(vec![1, 2]), blob, 3), Err(Error::Inventory));
    assert_eq!(
        read(&mut Bytes(vec![1, 2, 4]), blob, 3),
        Err(Error::Inventory)
    );
    assert_eq!(read(&mut Bytes(vec![1, 2, 3]), blob, 3), Ok(vec![1, 2, 3]));
}

#[test]
fn cancellation_during_original_read_discards_partial_bytes_and_allows_exact_retry() {
    use std::cell::Cell;

    struct Source {
        bytes: Vec<u8>,
        token: iroha_pasta::CancellationToken,
        cancel_on_read: bool,
        fail_read: bool,
        reads: Cell<usize>,
    }
    struct Reader<'a> {
        source: &'a Source,
        cursor: Cursor<&'a [u8]>,
    }
    impl Read for Reader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            self.source.reads.set(self.source.reads.get() + 1);
            let count = self.cursor.read(output)?;
            if self.source.cancel_on_read {
                self.source.token.cancel();
            }
            if self.source.fail_read {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
            Ok(count)
        }
    }
    impl OriginalSourceV1 for Source {
        fn open(&mut self, _: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
            Ok(Box::new(Reader {
                source: self,
                cursor: Cursor::new(self.bytes.as_slice()),
            }))
        }
    }
    let expected = vec![0x5a; 3 * 64 * 1024 + 17];
    let blob = BlobV1::of(&expected);
    let mut source = Source {
        bytes: expected.clone(),
        token: iroha_pasta::CancellationToken::new(),
        cancel_on_read: true,
        fail_read: false,
        reads: Cell::new(0),
    };
    for fail_read in [false, true] {
        source.token = iroha_pasta::CancellationToken::new();
        source.fail_read = fail_read;
        source.reads.set(0);
        let token = source.token.clone();
        assert_eq!(
            read_cancellable(&mut source, blob, expected.len(), Some(&token)),
            Err(Error::Cancelled)
        );
        assert_eq!(source.reads.get(), 1);
    }
    source.token = iroha_pasta::CancellationToken::new();
    source.cancel_on_read = false;
    source.fail_read = false;
    source.reads.set(0);
    let token = source.token.clone();
    assert_eq!(
        read_cancellable(&mut source, blob, expected.len(), Some(&token)),
        Ok(expected)
    );
    assert!(source.reads.get() > 1);
}

#[test]
fn cancelled_original_import_does_not_open_custody() {
    let selected = AuthenticatedProducerInventoryV1 {
        inventory: structural_inventory(),
        scheme_id: [1; 32],
        manifest_digest: [2; 32],
    };
    let mut source = memory();
    let token = iroha_pasta::CancellationToken::new();
    token.cancel();
    assert!(matches!(
        selected.read_original_cancellable(0, &mut source, 3, Some(&token)),
        Err(Error::Cancelled)
    ));
    assert_eq!(source.opens, 0);
    let fresh = iroha_pasta::CancellationToken::new();
    let original = selected
        .read_original_cancellable(0, &mut source, 3, Some(&fresh))
        .unwrap();
    assert_eq!(original.descriptor, [1]);
    assert_eq!(original.verifying_key, [2]);
    assert_eq!(original.proving_key, [3, 4, 5]);
    assert_eq!(source.opens, 3);
}

fn structural_inventory() -> ProducerInventoryV1 {
    let routes = compiled_routes();
    let operations = Variant::ALL
        .into_iter()
        .enumerate()
        .map(|(i, variant)| {
            let selected: Vec<_> = routes
                .iter()
                .filter(|route| route.variant == variant)
                .collect();
            let mut own_class: Vec<_> = selected.iter().map(|r| r.own).collect();
            own_class.sort_unstable();
            own_class.dedup();
            let mut incoming_class: Vec<_> = selected.iter().filter_map(|r| r.incoming).collect();
            incoming_class.sort_unstable();
            incoming_class.dedup();
            let schedule = OperationSchedule::for_variant(variant);
            OperationV1 {
                variant: u8::try_from(i + 1).unwrap(),
                own_class,
                incoming_class,
                context: vec![Fp::from(1).to_repr()],
                q: vec![0; schedule.q_partitions().iter().flatten().count()],
                a: vec![0; schedule.stage_count()],
                w: vec![0; schedule.stage_count() - 1],
            }
        })
        .collect();
    ProducerInventoryV1 {
        version: 1,
        native_profile: artifact_digest(
            b"native-profile",
            &native_profile_transcript_v1().unwrap(),
        ),
        originals: vec![OriginalV1 {
            descriptor: BlobV1::of(&[1]),
            verifying_key: BlobV1::of(&[2]),
            proving_key: BlobV1::of(&[3, 4, 5]),
        }],
        sigma: [0; 16],
        operations,
        routes: routes
            .iter()
            .map(|r| {
                u32::try_from(Variant::ALL.iter().position(|v| *v == r.variant).unwrap()).unwrap()
            })
            .collect(),
        terminals: vec![0],
        omega: 0,
    }
}

#[test]
fn canonical_inventory_covers_all_routes_and_rejects_missing_or_foreign_members() {
    let source = structural_inventory();
    let bytes = source.to_canonical_bytes().unwrap();
    let decoded: ProducerInventoryV1 =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap();
    assert_eq!(decoded, source);
    assert_eq!(decoded.to_canonical_bytes().unwrap(), bytes);
    assert_eq!(
        source.digest().unwrap(),
        artifact_digest(b"producer-catalog", &bytes)
    );
    for i in 0..source.routes.len() {
        let mut changed = source.clone();
        changed.routes.remove(i);
        assert_eq!(changed.validate(), Err(Error::Inventory));
        let mut changed = source.clone();
        changed.routes[i] = u32::MAX;
        assert_eq!(changed.validate(), Err(Error::Inventory));
    }
    for i in 0..source.operations.len() {
        let mut changed = source.clone();
        changed.operations[i].a.pop();
        assert_eq!(changed.validate(), Err(Error::Inventory));
        let mut changed = source.clone();
        changed.operations[i].context[0] = [0xff; 32];
        assert_eq!(changed.validate(), Err(Error::Inventory));
        let mut changed = source.clone();
        changed.operations[i].own_class.clear();
        assert_eq!(changed.validate(), Err(Error::Inventory));
        let mut changed = source.clone();
        let foreign = (0..16)
            .find(|selector| !changed.operations[i].own_class.contains(selector))
            .unwrap();
        changed.operations[i].own_class.push(foreign);
        changed.operations[i].own_class.sort_unstable();
        assert_eq!(changed.validate(), Err(Error::Inventory));
        if !source.operations[i].incoming_class.is_empty() {
            let mut changed = source.clone();
            changed.operations[i].incoming_class.insert(0, 0);
            assert_eq!(changed.validate(), Err(Error::Inventory));
        }
    }
    let mut changed = source.clone();
    changed.originals.push(source.originals[0]);
    assert_eq!(changed.validate(), Err(Error::Inventory));
    let mut changed = source.clone();
    changed.sigma[15] = 1;
    assert_eq!(changed.validate(), Err(Error::Inventory));
    let mut changed = source.clone();
    changed.terminals.push(0);
    assert_eq!(changed.validate(), Err(Error::Inventory));
    let mut changed = source;
    changed.native_profile[0] ^= 1;
    assert_eq!(changed.validate(), Err(Error::Inventory));
}

struct Memory {
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
    opens: usize,
}
impl OriginalSourceV1 for Memory {
    fn open(&mut self, hash: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.opens += 1;
        Ok(Box::new(Cursor::new(
            self.blobs.get(&hash).ok_or(Error::Inventory)?.as_slice(),
        )))
    }
}
fn memory() -> Memory {
    Memory {
        blobs: [vec![1], vec![2], vec![3, 4, 5]]
            .into_iter()
            .map(|bytes| (BlobV1::of(&bytes).sha256, bytes))
            .collect(),
        opens: 0,
    }
}

#[test]
fn one_original_reader_checks_caps_before_open_and_every_exact_content_hash() {
    // Private construction tests only the reader; it does not authenticate this fixture.
    let selected = AuthenticatedProducerInventoryV1 {
        inventory: structural_inventory(),
        scheme_id: [1; 32],
        manifest_digest: [2; 32],
    };
    let mut source = memory();
    assert!(selected.read_original(0, &mut source, 2).is_err());
    assert_eq!(source.opens, 0);
    assert!(selected.read_original(u32::MAX, &mut source, 3).is_err());
    assert_eq!(source.opens, 0);
    let original = selected.read_original(0, &mut source, 3).unwrap();
    assert_eq!(original.descriptor, [1]);
    assert_eq!(original.verifying_key, [2]);
    assert_eq!(original.proving_key, [3, 4, 5]);
    assert_eq!(source.opens, 3);
    let mut metadata_source = memory();
    metadata_source.blobs.remove(&BlobV1::of(&[3, 4, 5]).sha256);
    let metadata = selected
        .read_verifier_original(0, &mut metadata_source)
        .unwrap();
    assert_eq!(metadata.descriptor, [1]);
    assert_eq!(metadata.verifying_key, [2]);
    assert_eq!(metadata_source.opens, 2);
    assert!(selected.read_original(0, &mut metadata_source, 3).is_err());
    let original = selected.inventory.originals[0];
    for blob in [
        original.descriptor,
        original.verifying_key,
        original.proving_key,
    ] {
        for mutation in 0..3 {
            let mut source = memory();
            let bytes = source.blobs.get_mut(&blob.sha256).unwrap();
            match mutation {
                0 => {
                    bytes.pop();
                }
                1 => bytes.push(0),
                _ => bytes[0] ^= 1,
            }
            assert!(selected.read_original(0, &mut source, 3).is_err());
        }
    }
}

#[test]
#[ignore = "actual signed seventeen-verifier inventory; run optimized explicitly"]
fn signed_inventory_authenticates_exact_producer_preimage_without_source_admission() {
    let (pack, installation, bytes) = engineering_fixture::signed_inventory_with_catalog(|pack| {
        let mut inventory = structural_inventory();
        inventory.originals = pack
            .steps
            .iter()
            .map(|s| &s.artifact)
            .chain([&pack.lineage])
            .map(|original| OriginalV1 {
                descriptor: BlobV1::of(&original.descriptor),
                verifying_key: BlobV1::of(&original.verifying_key),
                // The installation test deliberately has no actual producer tables.
                proving_key: BlobV1::of(&[3, 4, 5]),
            })
            .collect();
        inventory.sigma = core::array::from_fn(|i| u32::try_from(i).unwrap());
        inventory.omega = 16;
        Some(inventory.to_canonical_bytes().unwrap())
    });
    let bytes = bytes.unwrap();
    let installed =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let authenticated = installed.authenticate_producer_inventory(&bytes).unwrap();
    assert_eq!(
        authenticated.installation(),
        (installation.scheme_id, installation.manifest_digest)
    );
    assert_eq!(
        authenticated.inventory().to_canonical_bytes().unwrap(),
        bytes
    );
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(installed.authenticate_producer_inventory(&changed).is_err());
    let mut changed = authenticated.inventory().clone();
    changed.originals[0].proving_key = BlobV1::of(b"different original");
    assert!(
        installed
            .authenticate_producer_inventory(&changed.to_canonical_bytes().unwrap())
            .is_err()
    );
    let mut changed = pack.clone();
    changed.producer_catalog_digest[0] ^= 1;
    assert!(
        InstalledVerifierPackV1::load(&changed.to_canonical_bytes().unwrap(), installation)
            .is_err()
    );
    // Authentication is not a source import: these dummy PK bytes are still not valid keys.
    let mut source = memory();
    assert!(authenticated.read_original(0, &mut source, 3).is_err());
}

#[path = "stream_tests.rs"]
mod stream_tests;
