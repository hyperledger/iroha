// Native read-only disk admission tests. Disk observation alone is not a finality proof.
#[cfg(unix)]
mod canonical_evidence_reader_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    struct Fixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
        blocks: Vec<iroha_data_model::block::SharedSignedBlock>,
    }
    #[test]
    fn index_and_hash_reject_unaddressable_heights_without_overflow() {
        let fixture = Fixture::new();
        let reader = fixture.open();
        for height in [
            0,
            u64::MAX,
            u64::MAX / BlockIndex::SIZE + 1,
            u64::MAX / SIZE_OF_BLOCK_HASH + 1,
        ] {
            assert!(reader.index(height).is_err());
            assert!(reader.hash(height).is_err());
        }
        let first = reader.index(1).unwrap();
        assert_eq!(first.start, 0);
        assert_eq!(
            first.length,
            u64::try_from(fixture.blocks[0].encode_wire().unwrap().len()).unwrap()
        );
        assert_eq!(reader.hash(1).unwrap(), fixture.blocks[0].hash());
    }

    impl Fixture {
        fn new() -> Self {
            // Native originals execute once; individual tests retain only immutable block images.
            static BLOCKS: std::sync::OnceLock<Vec<iroha_data_model::block::SharedSignedBlock>> =
                std::sync::OnceLock::new();
            let blocks = BLOCKS
                .get_or_init(|| {
                    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
                    let mut chain = CertifiedTestChain::start(TestChainConfig::new(
                        crate::state::World::default(),
                        1,
                    ))
                    .unwrap();
                    chain.commit(Vec::new());
                    chain.commit(Vec::new());
                    (1..=3)
                        .map(|height| {
                            chain
                                .kura()
                                .get_block(
                                    NonZeroUsize::new(height).unwrap(),
                                    &chain.state().view().execution_budget(),
                                )
                                .expect("completed structural storage read")
                                .unwrap()
                        })
                        .collect()
                })
                .clone();
            let directory = tempfile::tempdir().expect("fixture directory");
            let root = directory
                .path()
                .canonicalize()
                .expect("absolute real directory");
            let fixture = Self {
                _directory: directory,
                root,
                blocks,
            };
            fixture.write_store();
            fixture
        }
        fn write_store(&self) {
            let mut data = Vec::new();
            let mut indices = Vec::new();
            let mut hashes = Vec::new();
            for block in &self.blocks {
                let wire = block.encode_wire().expect("actual canonical block wire");
                indices.extend_from_slice(
                    &BlockIndex {
                        start: data.len() as u64,
                        length: wire.len() as u64,
                    }
                    .encode(),
                );
                hashes.extend_from_slice(block.hash().as_ref());
                data.extend_from_slice(&wire);
            }
            fs::write(self.root.join(DATA_FILE_NAME), data).unwrap();
            fs::write(self.root.join(INDEX_FILE_NAME), indices).unwrap();
            fs::write(self.root.join(HASHES_FILE_NAME), hashes).unwrap();
            self.write_marker(BlockStoreCommitMarker::new(
                self.blocks.len() as u64,
                self.blocks.last().map(|b| b.hash()),
            ));
        }
        fn write_marker(&self, marker: BlockStoreCommitMarker) {
            fs::write(
                self.root.join(COUNT_FILE_NAME),
                norito::encode_canonical(&marker).unwrap(),
            )
            .unwrap();
        }
        fn limits(&self) -> CanonicalKuraEvidenceLimits {
            CanonicalKuraEvidenceLimits {
                first_height: 1,
                last_height: 3,
                max_committed_blocks: 10,
                max_store_data_bytes: 2 * 1024 * 1024,
                max_carrier_bytes: 1024 * 1024,
                max_output_bytes: 8 * 1024 * 1024,
                max_decode_allocation_bytes: 64 * 1024 * 1024,
                owner_uid: fs::metadata(&self.root).unwrap().uid(),
            }
        }
        fn open(&self) -> CanonicalKuraEvidenceReader {
            CanonicalKuraEvidenceReader::open(&self.root, self.limits())
                .expect("clean native fixture admission")
        }
        fn read_all(&self, reader: &mut CanonicalKuraEvidenceReader) -> u64 {
            let mut size = 0;
            for (index, block) in self.blocks.iter().enumerate() {
                let wire = reader
                    .read_carrier(index as u64 + 1)
                    .expect("complete next carrier");
                assert_eq!(wire, block.encode_wire().unwrap());
                size += wire.len() as u64;
            }
            size
        }
        fn files(&self) -> Vec<PathBuf> {
            [
                DATA_FILE_NAME,
                INDEX_FILE_NAME,
                HASHES_FILE_NAME,
                COUNT_FILE_NAME,
            ]
            .map(|name| self.root.join(name))
            .to_vec()
        }
        fn snapshot(&self) -> Vec<(Vec<u8>, u32, i64, i64, i64, i64, u64)> {
            self.files()
                .iter()
                .map(|path| {
                    let metadata = fs::metadata(path).unwrap();
                    (
                        fs::read(path).unwrap(),
                        metadata.mode(),
                        metadata.mtime(),
                        metadata.mtime_nsec(),
                        metadata.ctime(),
                        metadata.ctime_nsec(),
                        metadata.ino(),
                    )
                })
                .collect()
        }
    }

    #[test]
    fn read_only_evidence_preserves_exact_native_certificate_bytes_and_read_only_files() {
        for use_consumer in [false, true] {
            let fixture = Fixture::new();
            for path in fixture.files() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
            }
            let before = fixture.snapshot();
            let mut reader = fixture.open();
            let mut bytes = 0;
            for (index, original) in fixture.blocks.iter().enumerate() {
                let height = index as u64 + 1;
                let wire = if use_consumer {
                    reader.read_carrier_with(height, Ok).unwrap()
                } else {
                    reader.read_carrier(height).unwrap()
                };
                let decoded = iroha_data_model::block::decode_framed_signed_block(&wire).unwrap();
                let actual = decoded.commit_certificate().unwrap();
                let expected = original.commit_certificate().unwrap();
                assert_eq!(actual.consensus_header(), expected.consensus_header());
                assert_eq!(actual.commit_qc(), expected.commit_qc());
                assert_eq!(actual.result_preimage(), expected.result_preimage());
                assert_eq!(actual.availability(), expected.availability());
                assert_eq!(wire, original.encode_wire().unwrap());
                bytes += wire.len() as u64;
            }
            let complete = reader.finish().unwrap();
            assert_eq!(complete.committed_height(), 3);
            assert_eq!(complete.carrier_count(), 3);
            assert_eq!(complete.output_bytes(), bytes);
            complete.recheck_sources().unwrap();
            assert_eq!(fixture.snapshot(), before);
        }
    }

    fn no_decode_allocation() -> norito::DecodeLimits {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX)
    }

    // The fixed-size marker decodes in place without allocating, so its
    // enclosing-scope refusal is exercised through the per-field byte limit.
    fn no_decode_field_bytes() -> norito::DecodeLimits {
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX)
    }

    fn assert_original_decode_refusal(error: CanonicalKuraEvidenceError) {
        use std::error::Error as _;

        assert!(error.source().is_some());
        let CanonicalKuraEvidenceError::Decode(error) = error else {
            panic!("original canonical decoder cause required");
        };
        assert_eq!(
            error.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(matches!(
            error.into_error().decode_resource_error(),
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
        ));
    }

    #[test]
    fn read_only_evidence_marker_refusal_preserves_original_decode_origin() {
        let fixture = Fixture::new();
        let before = fixture.snapshot();
        let error = norito::with_decode_limits_scope(no_decode_field_bytes(), || {
            CanonicalKuraEvidenceReader::open(&fixture.root, fixture.limits())
        })
        .expect_err("actual marker decoding must respect the enclosing operation");
        {
            use std::error::Error as _;

            assert!(error.source().is_some());
            let CanonicalKuraEvidenceError::Decode(error) = error else {
                panic!("original canonical decoder cause required");
            };
            assert_eq!(
                error.kind(),
                norito::core::DecodeAttemptErrorKind::EnclosingLimit
            );
            assert!(matches!(
                error.into_error().decode_resource_error(),
                Some(
                    norito::core::DecodeResourceError::FieldLengthExceeded { limit: 0, .. }
                        | norito::core::DecodeResourceError::ArchiveLengthExceeded { limit: 0, .. }
                )
            ));
        }
        assert_eq!(fixture.snapshot(), before);
        let mut retry = fixture.open();
        fixture.read_all(&mut retry);
        assert_eq!(retry.finish().unwrap().carrier_count(), 3);
        assert_eq!(fixture.snapshot(), before);

        // An invalid frame remains invalid even under the same enclosing pressure.
        let marker_path = fixture.root.join(COUNT_FILE_NAME);
        let mut bytes = fs::read(&marker_path).unwrap();
        bytes[0] ^= 0xff;
        fs::write(marker_path, bytes).unwrap();
        assert!(matches!(
            norito::with_decode_limits_scope(no_decode_field_bytes(), || {
                CanonicalKuraEvidenceReader::open(&fixture.root, fixture.limits())
            }),
            Err(CanonicalKuraEvidenceError::Decode(error))
                if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid
        ));
    }

    #[test]
    fn read_only_evidence_decoder_refusal_preserves_original_cursor_and_retries_source() {
        let fixture = Fixture::new();
        let mut reader = fixture.open();
        let before_files = fixture.snapshot();
        let before = (reader.next_height, reader.output_bytes);
        let consumed = std::cell::Cell::new(false);
        let error = norito::with_decode_limits_scope(no_decode_allocation(), || {
            reader.read_carrier_with(1, |wire| {
                consumed.set(true);
                Ok(wire)
            })
        })
        .expect_err("actual body decoder pressure");
        assert_original_decode_refusal(error);
        assert!(!consumed.get());
        assert!(!reader.poisoned);
        assert_eq!((reader.next_height, reader.output_bytes), before);
        let bytes = fixture.read_all(&mut reader);
        let complete = reader.finish().unwrap();
        assert_eq!(complete.carrier_count(), 3);
        assert_eq!(complete.output_bytes(), bytes);
        assert_eq!(fixture.snapshot(), before_files);
    }

    #[test]
    fn read_only_evidence_file_allocator_refusal_preserves_original_cursor_and_retry() {
        use std::error::Error as _;

        let fixture = Fixture::new();
        let mut reader = fixture.open();
        let wire = fixture.blocks[0].encode_wire().unwrap();
        let before_files = fixture.snapshot();
        let before = (reader.next_height, reader.output_bytes);
        let consumed = std::cell::Cell::new(false);
        let (result, refused) = crate::test_allocations::refuse_one_layout_during(
            std::alloc::Layout::array::<u8>(wire.len()).unwrap(),
            || {
                reader.read_carrier_with(1, |wire| {
                    consumed.set(true);
                    Ok(wire)
                })
            },
        );
        assert!(
            refused,
            "the actual file buffer must request the exact layout"
        );
        let error = result.expect_err("physical allocator refused original file buffer");
        assert!(error.source().is_some_and(|source| {
            source
                .downcast_ref::<std::collections::TryReserveError>()
                .is_some()
        }));
        assert!(matches!(error, CanonicalKuraEvidenceError::Allocator(_)));
        assert!(!consumed.get());
        assert!(!reader.poisoned);
        assert_eq!((reader.next_height, reader.output_bytes), before);
        assert_eq!(reader.read_carrier(1).unwrap(), wire);
        for (offset, block) in fixture.blocks.iter().enumerate().skip(1) {
            assert_eq!(
                reader.read_carrier(offset as u64 + 1).unwrap(),
                block.encode_wire().unwrap()
            );
        }
        let complete = reader.finish().unwrap();
        assert_eq!(complete.carrier_count(), 3);
        assert_eq!(
            complete.output_bytes(),
            fixture
                .blocks
                .iter()
                .map(|block| block.encode_wire().unwrap().len() as u64)
                .sum::<u64>()
        );
        assert_eq!(fixture.snapshot(), before_files);
    }

    #[test]
    fn read_only_evidence_resource_retry_rechecks_every_original_descriptor() {
        for source in 0..4 {
            let fixture = Fixture::new();
            let mut reader = fixture.open();
            let before = (reader.next_height, reader.output_bytes);
            reader.begin().unwrap();
            let error = norito::with_decode_limits_scope(no_decode_allocation(), || {
                reader.prepare_carrier(1)
            })
            .expect_err("actual pre-consumer decoder refusal");
            assert!(matches!(
                &error,
                CanonicalKuraEvidenceError::Decode(error)
                    if error.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit
            ));
            // Exercise the actual post-refusal boundary after a genuine refusal,
            // replacing one admitted inode with byte-identical content.
            let path = &fixture.files()[source];
            let bytes = fs::read(path).unwrap();
            fs::rename(path, path.with_extension("retired")).unwrap();
            fs::write(path, bytes).unwrap();
            assert!(matches!(
                reader.refuse_before_consumer::<Vec<u8>>(error),
                Err(CanonicalKuraEvidenceError::Invalid(
                    "held or named source changed"
                ))
            ));
            assert!(reader.poisoned);
            assert_eq!((reader.next_height, reader.output_bytes), before);
            assert!(reader.finish().is_err(), "changed source {source}");
        }
    }

    #[test]
    fn read_only_evidence_consumer_resource_error_still_poisons_original_owner() {
        let fixture = Fixture::new();
        let mut reader = fixture.open();
        let original = fixture.blocks[0].encode_wire().unwrap();
        let consumed = std::cell::Cell::new(false);
        let error = reader
            .read_carrier_with::<()>(1, |wire| {
                consumed.set(true);
                assert_eq!(wire, original);
                let error = norito::with_decode_limits_scope(no_decode_allocation(), || {
                    iroha_data_model::block::decode_framed_signed_block(&wire)
                })
                .expect_err("genuine consumer-owned decoder refusal");
                Err(CanonicalKuraEvidenceError::Decode(error))
            })
            .expect_err("consumer errors cannot grant a retry after provisional effects");
        assert_original_decode_refusal(error);
        assert!(consumed.get());
        assert!(reader.poisoned);
        assert_eq!(reader.next_height, 1);
        assert_eq!(reader.output_bytes, original.len() as u64);
        assert!(matches!(
            reader.read_carrier(1),
            Err(CanonicalKuraEvidenceError::Invalid("poisoned reader"))
        ));
        assert!(reader.finish().is_err());
    }

    #[test]
    fn read_only_evidence_marker_recheck_is_allocation_free_and_exact() {
        let fixture = Fixture::new();
        let reader = fixture.open();
        let mut result = None;
        let allocations = crate::test_allocations::allocations_during(|| {
            result = Some(reader.check_sources());
        });
        result.unwrap().unwrap();
        assert_eq!(
            allocations, 0,
            "resource retry needs no second marker buffer"
        );
        let mut incorrect = reader.marker_bytes.clone();
        let last = incorrect.last_mut().unwrap();
        *last ^= 1;
        assert!(matches!(
            reader.sources.marker.check_marker_bytes(&incorrect),
            Err(CanonicalKuraEvidenceError::Invalid(
                "published marker changed"
            ))
        ));
        assert!(matches!(
            reader
                .sources
                .marker
                .check_marker_bytes(&incorrect[..incorrect.len() - 1]),
            Err(CanonicalKuraEvidenceError::Invalid(
                "published marker recheck bound"
            ))
        ));
    }

    #[test]
    fn read_only_evidence_requires_every_requested_native_carrier() {
        let fixture = Fixture::new();
        assert!(fixture.open().finish().is_err());
        let mut reader = fixture.open();
        reader.read_carrier(1).unwrap();
        reader.read_carrier(2).unwrap();
        assert!(reader.finish().is_err());
        let mut reader = fixture.open();
        fixture.read_all(&mut reader);
        assert_eq!(reader.finish().unwrap().carrier_count(), 3);
    }
    #[test]
    fn read_only_evidence_rejects_skips_repeats_and_extra_reads() {
        let fixture = Fixture::new();
        let mut skipped = fixture.open();
        assert!(skipped.read_carrier(2).is_err());
        assert!(skipped.read_carrier(1).is_err());
        assert!(skipped.finish().is_err());
        let mut repeated = fixture.open();
        repeated.read_carrier(1).unwrap();
        assert!(repeated.read_carrier(1).is_err());
        assert!(repeated.finish().is_err());
        let mut extra = fixture.open();
        fixture.read_all(&mut extra);
        assert!(extra.read_carrier(4).is_err());
        assert!(extra.finish().is_err());
    }
    #[test]
    fn read_only_evidence_callback_error_and_caught_panic_poison_finish() {
        let fixture = Fixture::new();
        let mut reader = fixture.open();
        assert!(
            reader
                .read_carrier_with::<()>(1, |_| Err(CanonicalKuraEvidenceError::Invalid(
                    "consumer rejection"
                )))
                .is_err()
        );
        assert!(reader.finish().is_err());
        let mut reader = fixture.open();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reader.read_carrier_with::<()>(1, |_| panic!("consumer panic"))
        }));
        assert!(caught.is_err());
        assert!(reader.read_carrier(1).is_err());
        assert!(reader.finish().is_err());
    }
    #[test]
    fn read_only_evidence_all_four_sources_are_bound_through_consuming_finish() {
        for source in 0..4 {
            let fixture = Fixture::new();
            let mut reader = fixture.open();
            fixture.read_all(&mut reader);
            let path = &fixture.files()[source];
            let mut bytes = fs::read(path).unwrap();
            bytes.push(0);
            fs::write(path, bytes).unwrap();
            assert!(reader.finish().is_err(), "source {source}");
        }
    }
    #[test]
    fn read_only_evidence_catches_changes_inside_consumer_before_read_success() {
        let fixture = Fixture::new();
        let mut reader = fixture.open();
        let result = reader.read_carrier_with(1, |_| {
            let path = fixture.root.join(COUNT_FILE_NAME);
            let mut bytes = fs::read(&path).unwrap();
            bytes.push(0);
            fs::write(path, bytes).unwrap();
            Ok(())
        });
        assert!(result.is_err());
        assert!(reader.finish().is_err());
    }
    #[test]
    fn read_only_evidence_rejects_replaced_parent_and_permission_drift() {
        for change_mode in [false, true] {
            let fixture = Fixture::new();
            let mut reader = fixture.open();
            fixture.read_all(&mut reader);
            if change_mode {
                fs::set_permissions(
                    fixture.root.join(DATA_FILE_NAME),
                    fs::Permissions::from_mode(0o400),
                )
                .expect("mode change");
            } else {
                let nested = fixture.root.join("moved");
                fs::create_dir(&nested).expect("alternate");
                fs::rename(
                    fixture.root.join(DATA_FILE_NAME),
                    nested.join(DATA_FILE_NAME),
                )
                .expect("move original");
                fs::write(fixture.root.join(DATA_FILE_NAME), []).expect("replacement");
            }
            assert!(reader.finish().is_err());
        }
        let parent = tempfile::tempdir().expect("outer");
        let store = parent.path().join("store");
        fs::create_dir(&store).expect("store");
        let fixture = Fixture::new();
        for path in fixture.files() {
            fs::copy(&path, store.join(path.file_name().expect("name"))).expect("copy");
        }
        let store = store.canonicalize().expect("real path");
        let mut reader =
            CanonicalKuraEvidenceReader::open(&store, fixture.limits()).expect("admit nested");
        fs::rename(&store, store.with_extension("old")).expect("parent replacement");
        fs::create_dir(&store).expect("new named parent");
        assert!(reader.read_carrier(1).is_err());
        assert!(reader.finish().is_err());
    }
    #[test]
    fn read_only_evidence_does_not_create_missing_paths_or_admit_aliases() {
        let fixture = Fixture::new();
        let missing = fixture.root.join("missing");
        assert!(CanonicalKuraEvidenceReader::open(&missing, fixture.limits()).is_err());
        assert!(!missing.exists());
        let data = fixture.root.join(DATA_FILE_NAME);
        let index = fixture.root.join(INDEX_FILE_NAME);
        fs::remove_file(&index).unwrap();
        fs::hard_link(&data, &index).unwrap();
        assert!(CanonicalKuraEvidenceReader::open(&fixture.root, fixture.limits()).is_err());
        fs::remove_file(&data).unwrap();
        assert!(CanonicalKuraEvidenceReader::open(&fixture.root, fixture.limits()).is_err());
        assert!(!data.exists());
    }
    #[test]
    fn read_only_evidence_rejects_symlink_hardlink_fifo_and_post_admission_replacement() {
        for kind in 0..4 {
            let fixture = Fixture::new();
            let original = fixture.root.join("original");
            fs::rename(fixture.root.join(DATA_FILE_NAME), &original).expect("save file");
            match kind {
                0 => symlink(&original, &fixture.root.join(DATA_FILE_NAME)).expect("symlink"),
                1 => {
                    fs::hard_link(&original, &fixture.root.join(DATA_FILE_NAME)).expect("hardlink")
                }
                2 => {
                    drop(resource_file_fifo_with_live_peer(
                        &fixture.root.join(DATA_FILE_NAME),
                    ));
                }
                _ => {
                    fs::create_dir(&fixture.root.join(DATA_FILE_NAME)).expect("directory");
                }
            }
            assert!(
                CanonicalKuraEvidenceReader::open(&fixture.root, fixture.limits()).is_err(),
                "kind {kind}"
            );
        }
        for fifo in [false, true] {
            let fixture = Fixture::new();
            let mut peer = None;
            let result = CanonicalKuraEvidenceReader::open_after_admission(
                &fixture.root,
                fixture.limits(),
                |path| {
                    if path != fixture.root.join(DATA_FILE_NAME) {
                        return;
                    }
                    fs::remove_file(path).expect("replace after metadata");
                    if fifo {
                        peer = Some(resource_file_fifo_with_live_peer(path));
                    } else {
                        fs::write(path, []).expect("same bytes new inode");
                    }
                },
            );
            assert!(result.is_err());
            drop(peer);
        }
    }
    #[test]
    fn read_only_evidence_rejects_noncanonical_marker_and_committed_prefix_corruption() {
        for variant in 0..11 {
            let fixture = Fixture::new();
            match variant {
                0 => fixture.write_marker(BlockStoreCommitMarker {
                    version: 2,
                    count: 3,
                    tip_hash: Some(fixture.blocks[2].hash()),
                }),
                1 => fixture.write_marker(BlockStoreCommitMarker::new(0, None)),
                2 => fixture.write_marker(BlockStoreCommitMarker::new(
                    2,
                    Some(fixture.blocks[1].hash()),
                )),
                3 => fixture.write_marker(BlockStoreCommitMarker::new(
                    3,
                    Some(fixture.blocks[0].hash()),
                )),
                4 => {
                    let path = fixture.root.join(COUNT_FILE_NAME);
                    let mut bytes = fs::read(&path).expect("marker");
                    bytes.push(0);
                    fs::write(path, bytes).expect("tail");
                }
                5 | 6 => {
                    let path = fixture.root.join(if variant == 5 {
                        INDEX_FILE_NAME
                    } else {
                        HASHES_FILE_NAME
                    });
                    let mut bytes = fs::read(&path).expect("journal");
                    bytes.pop();
                    fs::write(path, bytes).expect("partial record");
                }
                7 => {
                    fs::OpenOptions::new()
                        .append(true)
                        .open(fixture.root.join(DATA_FILE_NAME))
                        .expect("data")
                        .write_all(&[0])
                        .expect("uncommitted suffix");
                }
                8 => {
                    let path = fixture.root.join(INDEX_FILE_NAME);
                    let mut bytes = fs::read(&path).expect("index");
                    bytes[..8].copy_from_slice(&1_u64.to_le_bytes());
                    fs::write(path, bytes).expect("gap");
                }
                9 => {
                    let path = fixture.root.join(INDEX_FILE_NAME);
                    let mut bytes = fs::read(&path).expect("index");
                    bytes[..8].copy_from_slice(&EVICTED_BLOCK_START.to_le_bytes());
                    fs::write(path, bytes).expect("evicted");
                }
                _ => {
                    let path = fixture.root.join(HASHES_FILE_NAME);
                    let mut bytes = fs::read(&path).expect("hashes");
                    bytes[31] &= !1;
                    fs::write(path, bytes).expect("noncanonical hash");
                }
            }
            assert!(
                CanonicalKuraEvidenceReader::open(&fixture.root, fixture.limits()).is_err(),
                "variant {variant}"
            );
        }
    }
    #[test]
    fn read_only_evidence_carrier_decode_hash_and_parent_failures_poison() {
        for variant in 0..3 {
            let mut fixture = Fixture::new();
            if variant == 0 {
                let path = fixture.root.join(DATA_FILE_NAME);
                let mut bytes = fs::read(&path).expect("data");
                bytes[0] = 255;
                fs::write(path, bytes).expect("version");
            }
            if variant == 1 {
                let path = fixture.root.join(HASHES_FILE_NAME);
                let mut bytes = fs::read(&path).expect("hashes");
                bytes[0] ^= 2;
                fs::write(path, bytes).expect("wrong first hash, same marker tip");
            }
            if variant == 2 {
                fixture.blocks[1] = (fixture.blocks[0]).clone();
                fixture.write_store();
            }
            let mut reader = fixture.open();
            if variant == 2 {
                reader.read_carrier(1).expect("unchanged first carrier");
                assert!(reader.read_carrier(2).is_err());
            } else {
                assert!(reader.read_carrier(1).is_err());
            }
            assert!(reader.finish().is_err());
        }
    }
    #[test]
    fn read_only_evidence_rejects_missing_or_wrong_height_native_certificate_shape() {
        use iroha_data_model::block::CommitCertificate;
        for variant in 0..5 {
            let mut fixture = Fixture::new();
            let at = usize::from(variant != 1);
            let mut block = (*fixture.blocks[at]).clone();
            let original = block.commit_certificate().unwrap();
            let header = original.consensus_header().to_vec();
            let qc = original.commit_qc().to_vec();
            let result = original.result_preimage().to_vec();
            let availability = original.availability().to_vec();
            assert_eq!(availability.is_empty(), at == 0);
            let replacement = match variant {
                0 => None,
                1 => Some(CommitCertificate::from_untrusted_parts(
                    vec![1],
                    vec![2],
                    result,
                    availability,
                )),
                2 => Some(CommitCertificate::from_untrusted_parts(
                    Vec::new(),
                    qc,
                    result,
                    availability,
                )),
                3 => Some(CommitCertificate::from_untrusted_parts(
                    header,
                    Vec::new(),
                    result,
                    availability,
                )),
                _ => Some(CommitCertificate::from_untrusted_parts(
                    header,
                    qc,
                    Vec::new(),
                    availability,
                )),
            };
            block.set_commit_certificate(replacement);
            fixture.blocks[at] = share_storage_fixture(block);
            fixture.write_store();
            let mut reader = fixture.open();
            if at > 0 {
                reader.read_carrier(1).unwrap();
            }
            assert!(
                reader.read_carrier(at as u64 + 1).is_err(),
                "shape {variant}"
            );
            assert!(reader.finish().is_err());
        }
    }
    /// Native carriers require their original signed availability before any bytes escape.
    #[test]
    fn read_only_evidence_rejects_missing_native_availability() {
        use iroha_data_model::block::CommitCertificate;
        let mut fixture = Fixture::new();
        let mut block = (*fixture.blocks[1]).clone();
        let original = block.commit_certificate().unwrap();
        assert!(
            !original.availability().is_empty(),
            "native signed availability"
        );
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            original.consensus_header().to_vec(),
            original.commit_qc().to_vec(),
            original.result_preimage().to_vec(),
            Vec::new(),
        )));
        fixture.blocks[1] = share_storage_fixture(block);
        fixture.write_store();
        let before = fixture.snapshot();
        let mut reader = fixture.open();
        reader
            .read_carrier(1)
            .expect("unchanged result-only genesis");
        let mut consumed = false;
        let error = reader
            .read_carrier_with(2, |wire| {
                consumed = true;
                Ok(wire)
            })
            .unwrap_err();
        assert!(matches!(
            error,
            CanonicalKuraEvidenceError::Invalid("native commit certificate shape")
        ));
        assert!(
            !consumed,
            "malformed native carrier must not reach the consumer"
        );
        assert!(
            reader.finish().is_err(),
            "rejection poisons the evidence owner"
        );
        assert_eq!(fixture.snapshot(), before, "rejection remains read-only");
    }

    /// The result-only genesis exception cannot carry a later native availability frame.
    #[test]
    fn read_only_evidence_rejects_native_availability_on_genesis() {
        use iroha_data_model::block::CommitCertificate;
        let mut fixture = Fixture::new();
        let availability = fixture.blocks[1]
            .commit_certificate()
            .unwrap()
            .availability()
            .to_vec();
        assert!(
            !availability.is_empty(),
            "genuine later native availability"
        );
        let mut block = (*fixture.blocks[0]).clone();
        let original = block.commit_certificate().unwrap();
        assert!(original.consensus_header().is_empty());
        assert!(original.commit_qc().is_empty());
        assert!(original.availability().is_empty());
        assert!(!original.result_preimage().is_empty());
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            original.consensus_header().to_vec(),
            original.commit_qc().to_vec(),
            original.result_preimage().to_vec(),
            availability,
        )));
        fixture.blocks[0] = share_storage_fixture(block);
        fixture.write_store();
        let before = fixture.snapshot();
        let mut reader = fixture.open();
        let mut consumed = false;
        let error = reader
            .read_carrier_with(1, |wire| {
                consumed = true;
                Ok(wire)
            })
            .unwrap_err();
        assert!(matches!(
            error,
            CanonicalKuraEvidenceError::Invalid("native commit certificate shape")
        ));
        assert!(!consumed, "malformed genesis must not reach the consumer");
        assert!(
            reader.finish().is_err(),
            "rejection poisons the evidence owner"
        );
        assert_eq!(fixture.snapshot(), before, "rejection remains read-only");
    }

    #[test]
    fn read_only_evidence_carries_untrusted_native_signature_bytes_without_rewriting() {
        use iroha_data_model::block::CommitCertificate;
        let mut fixture = Fixture::new();
        let mut block = (*fixture.blocks[1]).clone();
        let original = block.commit_certificate().unwrap();
        let mut qc = original.commit_qc().to_vec();
        let last = qc.last_mut().unwrap();
        *last ^= 1;
        let availability = original.availability().to_vec();
        assert!(!availability.is_empty(), "native signed availability");
        let changed = CommitCertificate::from_untrusted_parts(
            original.consensus_header().to_vec(),
            qc.clone(),
            original.result_preimage().to_vec(),
            availability.clone(),
        );
        block.set_commit_certificate(Some(changed));
        fixture.blocks[1] = share_storage_fixture(block);
        fixture.write_store();
        let mut reader = fixture.open();
        reader.read_carrier(1).unwrap();
        let wire = reader.read_carrier(2).unwrap();
        let decoded = iroha_data_model::block::decode_framed_signed_block(&wire).unwrap();
        assert_eq!(decoded.commit_certificate().unwrap().commit_qc(), qc);
        assert_eq!(
            decoded.commit_certificate().unwrap().availability(),
            availability
        );
        assert_eq!(wire, fixture.blocks[1].encode_wire().unwrap());
        reader.read_carrier(3).unwrap();
        reader.finish().unwrap(); // Disk completion grants no signature or execution authority.
    }
    #[test]
    fn read_only_evidence_applies_independent_size_frame_owner_and_decode_bounds() {
        for variant in 0..10 {
            let fixture = Fixture::new();
            let mut limits = fixture.limits();
            match variant {
                0 => limits.first_height = 0,
                1 => limits.last_height = 4,
                2 => limits.max_committed_blocks = 1_000_001,
                3 => limits.max_store_data_bytes = 1,
                4 => limits.max_committed_blocks = 2,
                5 => limits.owner_uid ^= 1,
                6 => limits.max_carrier_bytes = 32 * 1024 * 1024 + 1,
                7 => limits.max_output_bytes = 0,
                8 => limits.max_decode_allocation_bytes = 0,
                _ => limits.max_store_data_bytes = 2 * 1024 * 1024 * 1024 + 1,
            }
            assert!(
                CanonicalKuraEvidenceReader::open(&fixture.root, limits).is_err(),
                "variant {variant}"
            );
        }
        let fixture = Fixture::new();
        for variant in 0..3 {
            let mut limits = fixture.limits();
            match variant {
                0 => limits.max_carrier_bytes = 1,
                1 => limits.max_output_bytes = 1,
                _ => limits.max_decode_allocation_bytes = 1,
            }
            // The fixed-size marker decodes in place, so a one-byte allocation
            // budget admits the reader and refuses the first carrier body.
            let mut reader = CanonicalKuraEvidenceReader::open(&fixture.root, limits).unwrap();
            assert!(reader.read_carrier(1).is_err());
            assert!(reader.finish().is_err());
        }
    }
    #[test]
    fn read_only_evidence_exact_returned_byte_budget_succeeds_and_one_less_fails() {
        let fixture = Fixture::new();
        let exact = fixture
            .blocks
            .iter()
            .map(|block| block.encode_wire().unwrap().len() as u64)
            .sum::<u64>();
        for deficit in [0, 1] {
            let mut limits = fixture.limits();
            limits.max_output_bytes = exact - deficit;
            let mut reader = CanonicalKuraEvidenceReader::open(&fixture.root, limits).unwrap();
            reader.read_carrier(1).unwrap();
            reader.read_carrier(2).unwrap();
            let result = reader.read_carrier(3);
            if deficit == 0 {
                result.unwrap();
                assert_eq!(reader.finish().unwrap().output_bytes(), exact);
            } else {
                assert!(result.is_err());
                assert!(reader.finish().is_err());
            }
        }
    }
    #[test]
    fn read_only_evidence_requested_subinterval_validates_complete_index_prefix() {
        let fixture = Fixture::new();
        let mut limits = fixture.limits();
        limits.first_height = 3;
        let mut reader = CanonicalKuraEvidenceReader::open(&fixture.root, limits).unwrap();
        assert_eq!(
            reader.read_carrier(3).unwrap(),
            fixture.blocks[2].encode_wire().unwrap()
        );
        assert_eq!(reader.finish().unwrap().carrier_count(), 1);
        let path = fixture.root.join(INDEX_FILE_NAME);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] = 1;
        fs::write(path, bytes).unwrap();
        assert!(
            CanonicalKuraEvidenceReader::open(&fixture.root, limits).is_err(),
            "unrequested old index still validated"
        );
    }
    #[test]
    fn read_only_evidence_actual_handles_are_nonblocking_close_on_exec_and_read_only() {
        let fixture = Fixture::new();
        let reader = fixture.open();
        for source in [
            &reader.sources.data,
            &reader.sources.index,
            &reader.sources.hashes,
            &reader.sources.marker,
        ] {
            let (flags, descriptor_flags) = source.flags_for_test().expect("actual retained flags");
            assert_eq!(
                flags & rustix::fs::OFlags::ACCMODE,
                rustix::fs::OFlags::RDONLY
            );
            assert!(flags.contains(rustix::fs::OFlags::NONBLOCK));
            assert!(descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC));
        }
    }
    #[test]
    fn read_only_evidence_retained_read_rejects_truncation_and_replacement_after_check() {
        for replace in [false, true] {
            let fixture = Fixture::new();
            let reader = fixture.open();
            let result = reader
                .sources
                .data
                .read_after_check(0, reader.sources.data.len(), || {
                    let path = fixture.root.join(DATA_FILE_NAME);
                    if replace {
                        let bytes = fs::read(&path).expect("preimage");
                        fs::rename(&path, path.with_extension("old")).expect("old retained inode");
                        fs::write(&path, bytes).expect("same-byte new inode");
                    } else {
                        fs::OpenOptions::new()
                            .write(true)
                            .open(path)
                            .expect("writer")
                            .set_len(0)
                            .expect("truncate");
                    }
                });
            assert!(result.is_err(), "post-check change {replace}");
        }
    }
    #[test]
    fn read_only_evidence_rejects_parent_symlinks_relative_and_non_normal_paths() {
        let fixture = Fixture::new();
        let outer = tempfile::tempdir().expect("outer");
        let alias = outer.path().join("alias");
        symlink(&fixture.root, &alias).expect("directory alias");
        assert!(CanonicalKuraEvidenceReader::open(&alias, fixture.limits()).is_err());
        assert!(
            CanonicalKuraEvidenceReader::open(Path::new("relative"), fixture.limits()).is_err()
        );
        let dot = fixture.root.join(".");
        assert!(CanonicalKuraEvidenceReader::open(&dot, fixture.limits()).is_err());
        let extra = fixture.root.join("..sample").join("..");
        assert!(CanonicalKuraEvidenceReader::open(&extra, fixture.limits()).is_err());
    }
    #[test]
    fn read_only_evidence_requires_actual_framed_wire_and_rejects_bare_versioned_store() {
        let fixture = Fixture::new();
        let mut reader = fixture.open();
        fixture.read_all(&mut reader);
        assert_eq!(
            reader
                .finish()
                .expect("actual framed positive")
                .carrier_count(),
            3
        );
        let mut data = Vec::new();
        let mut index = Vec::new();
        for block in &fixture.blocks {
            let wire = block.canonical_wire().expect("real canonical frame");
            let mut bare = vec![wire.version()];
            bare.extend_from_slice(wire.payload());
            assert_ne!(wire.as_framed(), bare.as_slice());
            assert!(iroha_data_model::block::decode_framed_signed_block(wire.as_framed()).is_ok());
            assert!(iroha_data_model::block::decode_framed_signed_block(&bare).is_err());
            index.extend_from_slice(
                &BlockIndex {
                    start: data.len() as u64,
                    length: bare.len() as u64,
                }
                .encode(),
            );
            data.extend_from_slice(&bare);
        }
        // Preserve the valid count/tip/hash association and complete contiguous
        // lengths so the negative reaches the actual carrier wire decoder.
        fs::write(fixture.root.join(DATA_FILE_NAME), data).expect("bare data");
        fs::write(fixture.root.join(INDEX_FILE_NAME), index).expect("matching bare lengths");
        let mut reader = fixture.open();
        assert!(matches!(
            reader.read_carrier(1),
            Err(CanonicalKuraEvidenceError::Decode(error))
                if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid
        ));
        assert!(reader.finish().is_err());
    }
    #[test]
    fn read_only_completion_keeps_source_custody_and_excludes_source_publication() {
        let fixture = Fixture::new();
        let mut reader = fixture.open();
        fixture.read_all(&mut reader);
        let complete = reader.finish().unwrap();
        let source = fs::metadata(&fixture.root).unwrap();
        assert!(
            complete
                .ensure_publication_ancestry(&[(source.dev(), source.ino())])
                .is_err()
        );
        assert!(complete.ensure_publication_ancestry(&[]).is_err());
        let unrelated = tempfile::tempdir().unwrap();
        let outside = fs::metadata(unrelated.path()).unwrap();
        complete
            .ensure_publication_ancestry(&[(outside.dev(), outside.ino())])
            .unwrap();
        complete.recheck_sources().unwrap();
        let path = fixture.root.join(DATA_FILE_NAME);
        let bytes = fs::read(&path).unwrap();
        fs::rename(&path, path.with_extension("old")).unwrap();
        fs::write(&path, bytes).unwrap();
        assert!(complete.recheck_sources().is_err());
        assert!(
            complete
                .ensure_publication_ancestry(&[(outside.dev(), outside.ino())])
                .is_err()
        );
    }
}
