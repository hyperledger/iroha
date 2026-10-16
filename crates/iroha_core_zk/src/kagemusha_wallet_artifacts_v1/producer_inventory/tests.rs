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
fn builtin_profile_binds_network_source_policy_and_complete_ordered_inventory() {
    use iroha_plonk_gadgets::p256::native::Affine;
    let point = |root: Affine| {
        let mut bytes = vec![4];
        for coordinate in [root.x, root.y] {
            for word in coordinate.iter().rev() {
                bytes.extend(word.to_be_bytes());
            }
        }
        KagemushaDevicePublicKeyV1::from_sec1_bytes(&bytes).unwrap()
    };
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: [1; 32],
        provider_contract: [2; 32],
        scheme_root_key: point(Affine::GENERATOR),
        relation_id: [3; 32],
    };
    let inventory = structural_inventory();
    let expected = super::builtin::profile_bytes(&inventory, &scheme).unwrap();
    for change in 0..3 {
        let mut changed = scheme.clone();
        match change {
            0 => changed.network_id[0] ^= 1,
            1 => changed.provider_contract[0] ^= 1,
            _ => changed.scheme_root_key = point(Affine::GENERATOR.neg()),
        }
        assert_ne!(
            super::builtin::profile_bytes(&inventory, &changed).unwrap(),
            expected
        );
    }
    for change in 0..12 {
        let mut changed = inventory.clone();
        match change {
            0 => changed.originals[0].descriptor.sha256[0] ^= 1,
            1 => changed.originals[0].verifying_key.sha256[0] ^= 1,
            2 => changed.originals[0].proving_key.sha256[0] ^= 1,
            3 => changed.originals[0].proving_key.bytes += 1,
            4 => changed.operations[0].context[0][0] ^= 1,
            5 => {
                changed.operations.remove(0);
            }
            6 => changed.routes.swap(0, 1),
            7 => {
                changed.routes.pop();
            }
            8 => changed.operations[0].a.push(0),
            9 => changed.operations[0].q.push(0),
            10 => changed.terminals.push(0),
            _ => changed.native_profile[0] ^= 1,
        }
        match super::builtin::profile_bytes(&changed, &scheme) {
            Ok(bytes) => assert_ne!(bytes, expected, "mutation {change}"),
            Err(_) => {} // Structurally invalid graphs fail before registry lookup.
        }
    }
    // A byte transcript can only select a compiled entry; unknown input cannot
    // itself register a profile or authorize even one member.
    assert!(iroha_plonk::keys::BuiltinSourceProfileV1::match_actual(&expected, None).is_err());
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

// Two genuine canonical V2 descriptor frames (one per curve) of one tiny gate.
// They are decoding fixtures only, never wallet sources or authority.
fn descriptor_frames() -> [Vec<u8>; 2] {
    use iroha_plonk::{
        cs::{Advice, Column, ConstraintSystem, Fixed, Rotation, Selector},
        frontend::{Circuit, Error as LayoutError, Layouter, SimpleFloorPlanner, Value},
        keys::{KeygenConfigV2, keygen_vk_with_binding_v2},
        pcs::ipa::PinnedParams,
    };

    #[derive(Clone)]
    struct Gate;
    impl<F: iroha_pasta::PastaField> Circuit<F> for Gate {
        type Config = (Column<Advice>, Column<Fixed>, Selector);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            Self
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice = meta.advice_column();
            let fixed = meta.fixed_column();
            let selector = meta.selector();
            meta.create_gate("descriptor memo fixture", |cells| {
                vec![
                    cells.query_selector(selector)
                        * (cells.query_advice(advice, Rotation::cur())
                            - cells.query_fixed(fixed, Rotation::cur())),
                ]
            });
            (advice, fixed, selector)
        }
        fn synthesize(
            &self,
            (advice, fixed, selector): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), LayoutError> {
            layouter.assign_region(
                || "descriptor memo fixture",
                |mut region| {
                    region.assign_advice(advice, 0, Value::<F>::unknown())?;
                    region.assign_fixed(fixed, 0, F::from(7_u64))?;
                    selector.enable(&mut region, 0)?;
                    Ok(())
                },
            )
        }
    }
    let config = KeygenConfigV2::pipa_r(vec![]);
    let (pallas, _) =
        keygen_vk_with_binding_v2(&PinnedParams::<Ep>::derive(6).unwrap(), &Gate, &config).unwrap();
    let (vesta, _) =
        keygen_vk_with_binding_v2(&PinnedParams::<Eq>::derive(6).unwrap(), &Gate, &config).unwrap();
    assert_ne!(pallas.encoded(), vesta.encoded());
    [pallas.encoded().to_vec(), vesta.encoded().to_vec()]
}

#[test]
fn descriptor_memo_matches_fresh_decodes_and_reuses_only_exact_successful_content() {
    use iroha_plonk::keys::AdmissionWorkV1;
    let [first, second] = descriptor_frames();
    let addresses = [BlobV1::of(&first).sha256, BlobV1::of(&second).sha256];
    let mut changed = first.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let invalid = [1_u8, 2, 3];
    // Lookups as a qualification presents them, plus content that only a broken
    // caller could present under a foreign address: a hit needs equal bytes.
    let reads: [([u8; 32], &[u8]); 9] = [
        (addresses[0], &first),
        (addresses[1], &second),
        (addresses[0], &first),
        (addresses[0], &changed),
        (addresses[0], &second),
        (addresses[1], &second),
        (addresses[0], &first),
        (BlobV1::of(&invalid).sha256, &invalid),
        (BlobV1::of(&invalid).sha256, &invalid),
    ];
    let run = |memo: &DescriptorMemo| {
        let before = AdmissionWorkV1::current_thread();
        let verdicts: Vec<_> = reads
            .iter()
            .map(|(address, bytes)| memo.decode_v2(*address, bytes))
            .collect();
        let decodes = AdmissionWorkV1::current_thread()
            .since(before)
            .descriptor_decodes;
        (verdicts, decodes)
    };
    let memo = DescriptorMemo::default();
    let (memoized, memoized_decodes) = run(&memo);
    let (fresh, fresh_decodes) = run(&DescriptorMemo::with_capacity(0));
    // Memo on and off give identical verdicts and bindings for every lookup,
    // and both equal a direct decode of the presented bytes.
    assert_eq!(memoized, fresh);
    for ((_, bytes), verdict) in reads.iter().zip(&memoized) {
        assert_eq!(verdict, &DescriptorBinding::decode_v2(bytes));
    }
    // Only exact repeats of earlier successful content are reused: the changed
    // frame, another frame under the first address and both invalid lookups
    // decode afresh, and no error is ever stored.
    assert_eq!(fresh_decodes, 9);
    assert_eq!(memoized_decodes, 6);
    assert!(memoized[0].is_ok() && memoized[1].is_ok() && memoized[4].is_ok());
    assert_ne!(memoized[3], memoized[0]);
    assert_ne!(memoized[4], memoized[0]);
    assert!(memoized[7].is_err() && memoized[8].is_err());
    // The memo holds exactly the successful first decodes, in order, under the
    // address each was presented with: no error, repeat or hit adds an entry.
    let mut expected = vec![
        (addresses[0], first.clone()),
        (addresses[1], second.clone()),
    ];
    if memoized[3].is_ok() {
        expected.push((addresses[0], changed.clone()));
    }
    expected.push((addresses[0], second.clone()));
    let stored: Vec<_> = memo
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|(address, binding)| (*address, binding.encoded().to_vec()))
        .collect();
    assert_eq!(stored, expected);
    // The bound keeps the first entries only; content past it always decodes.
    let bounded = DescriptorMemo::with_capacity(1);
    let before = AdmissionWorkV1::current_thread();
    for (address, bytes) in [
        (addresses[0], &first),
        (addresses[1], &second),
        (addresses[1], &second),
        (addresses[0], &first),
    ] {
        assert_eq!(
            bounded.decode_v2(address, bytes),
            DescriptorBinding::decode_v2(bytes)
        );
    }
    assert_eq!(
        AdmissionWorkV1::current_thread()
            .since(before)
            .descriptor_decodes,
        // Each line above: memo lookup plus the direct reference decode.
        3 + 4
    );
    assert_eq!(bounded.entries.lock().unwrap().len(), 1);
}

#[test]
fn memoized_verifier_reads_keep_every_read_check_and_decode_distinct_content_once() {
    let [first, second] = descriptor_frames();
    let mut inventory = structural_inventory();
    // Two members share one descriptor; a third has another.
    inventory.originals = [(&first, 6_u8), (&first, 7), (&second, 8)]
        .into_iter()
        .map(|(descriptor, key)| OriginalV1 {
            descriptor: BlobV1::of(descriptor),
            verifying_key: BlobV1::of(&[key]),
            proving_key: BlobV1::of(&[3, 4, 5]),
        })
        .collect();
    // Private construction tests only the reader; it does not authenticate this fixture.
    let selected = AuthenticatedProducerInventoryV1 {
        inventory,
        scheme_id: [1; 32],
        manifest_digest: [2; 32],
    };
    let mut source = memory();
    for bytes in [first.clone(), second.clone(), vec![6], vec![7], vec![8]] {
        source.blobs.insert(BlobV1::of(&bytes).sha256, bytes);
    }
    let order = [0_u32, 1, 2, 0, 2, 1, 0];
    let descriptors = DescriptorMemo::default();
    let before = OpeningWorkV1::current_thread();
    let opens = source.opens;
    let memoized: Vec<_> = order
        .iter()
        .map(|index| {
            selected
                .read_verifier_metadata(*index, &mut source, &descriptors)
                .unwrap()
        })
        .collect();
    let work = OpeningWorkV1::current_thread().since(before);
    // Opening counters: one decode per distinct descriptor content, while every
    // descriptor and VK original is still opened, bounded and hashed per read.
    assert_eq!(work.descriptor_decodes, 2);
    assert_eq!(work.originals_opened, 2 * order.len() as u64);
    assert_eq!(source.opens - opens, 2 * order.len());
    // Memo off: the same reads decoded afresh give identical bindings and keys.
    for (index, decoded) in order.iter().zip(&memoized) {
        let original = selected
            .read_verifier_original(*index, &mut source)
            .unwrap();
        assert_eq!(
            decoded.binding,
            DescriptorBinding::decode_v2(&original.descriptor)
        );
        assert_eq!(decoded.verifying_key, original.verifying_key);
    }
    // Mutated, truncated or extended stored bytes are refused by the read itself
    // although a hit for that content address exists; the memo is unchanged and
    // the exact original is still served afterwards.
    let address = BlobV1::of(&first).sha256;
    for mutation in 0..3 {
        let bytes = source.blobs.get_mut(&address).unwrap();
        match mutation {
            0 => bytes[0] ^= 1,
            1 => {
                bytes.pop();
            }
            _ => bytes.push(0),
        }
        let before = OpeningWorkV1::current_thread();
        assert!(matches!(
            selected.read_verifier_metadata(0, &mut source, &descriptors),
            Err(Error::Inventory)
        ));
        assert_eq!(
            OpeningWorkV1::current_thread()
                .since(before)
                .descriptor_decodes,
            0
        );
        assert_eq!(descriptors.entries.lock().unwrap().len(), 2);
        source.blobs.insert(address, first.clone());
    }
    let before = OpeningWorkV1::current_thread();
    let again = selected
        .read_verifier_metadata(1, &mut source, &descriptors)
        .unwrap();
    assert_eq!(again.binding, memoized[1].binding);
    assert_eq!(
        OpeningWorkV1::current_thread()
            .since(before)
            .descriptor_decodes,
        0
    );
}

#[test]
fn shared_descriptor_memo_decodes_each_exact_address_once_across_workers() {
    use iroha_plonk::keys::AdmissionWorkV1;
    let [first, second] = descriptor_frames();
    let lookups = [
        (BlobV1::of(&first).sha256, first.as_slice()),
        (BlobV1::of(&second).sha256, second.as_slice()),
    ];
    let memo = DescriptorMemo::default();
    let verdicts = std::sync::Mutex::new(Vec::new());
    let decodes = std::sync::atomic::AtomicU64::new(0);
    // The route workers of one qualification share its memo: eight threads present
    // both descriptors, in opposite orders, many times each.
    std::thread::scope(|scope| {
        for worker in 0..8_usize {
            let (memo, verdicts, decodes) = (&memo, &verdicts, &decodes);
            scope.spawn(move || {
                let before = AdmissionWorkV1::current_thread();
                for round in 0..32_usize {
                    let lookup = (worker + round) % lookups.len();
                    let (address, bytes) = lookups[lookup];
                    let verdict = memo.decode_v2(address, bytes);
                    verdicts.lock().unwrap().push((lookup, verdict));
                }
                let work = AdmissionWorkV1::current_thread().since(before);
                decodes.fetch_add(work.descriptor_decodes, std::sync::atomic::Ordering::SeqCst);
            });
        }
    });
    let verdicts = verdicts.into_inner().unwrap();
    // One decode per distinct exact address over all threads, as one worker makes,
    // and every lookup returns what a fresh decode of its bytes returns.
    assert_eq!(decodes.into_inner(), 2);
    assert_eq!(verdicts.len(), 8 * 32);
    for (lookup, verdict) in &verdicts {
        assert_eq!(verdict, &DescriptorBinding::decode_v2(lookups[*lookup].1));
    }
    let stored: Vec<_> = memo
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|(address, _)| *address)
        .collect();
    assert_eq!(stored.len(), 2);
    assert!(lookups.iter().all(|(address, _)| stored.contains(address)));
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
