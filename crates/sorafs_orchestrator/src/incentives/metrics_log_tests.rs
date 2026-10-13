// Real metrics log framing, replay, and resource-boundary regressions.

fn log_test_limits() -> MetricsLogReadLimitsV1 {
    MetricsLogReadLimitsV1 {
        max_records: 16,
        max_total_frame_bytes: 1024 * 1024,
        max_total_allocated_bytes: 16 * 1024 * 1024,
    }
}

fn read_test_metrics_frame(reader: &mut impl Read) -> Result<RelayEpochMetricsV1, norito::Error> {
    read_metrics_frame(reader, &mut 0, METRICS_LOG_MAX_READ_BYTES_V1)
}

fn log_test_entries() -> Vec<RelayEpochMetricsV1> {
    let mut first = metrics(1_000, 1_000);
    metadata_insert(&mut first.metadata, "epoch_tag", Json::new("epoch-1"));
    let mut second = first.clone();
    second.epoch = 2;
    second.reward_score = 77;
    // One record spans the default BufReader capacity, independent of record boundaries.
    second.measurement_ids = (0_u16..513)
        .map(|id| {
            let mut measurement = [0x53; 32];
            measurement[..2].copy_from_slice(&id.to_le_bytes());
            measurement
        })
        .collect();
    let mut third = first.clone();
    third.epoch = 3;
    metadata_insert(&mut third.metadata, "reward_decision", Json::new("skipped"));
    vec![first, second, third]
}

#[test]
fn metrics_log_canonical_frames_replay_across_all_layouts() {
    let entries = log_test_entries();
    let frames: Vec<_> = entries
        .iter()
        .map(|entry| norito::encode_canonical(entry).unwrap())
        .collect();
    for frame in &frames {
        assert_eq!(
            norito::core::Header::read(frame.as_slice()).unwrap().flags,
            norito::core::default_encode_flags()
        );
    }
    assert!(frames[1].len() > 8 * 1_024);
    let expected_bytes = frames.concat();
    let expected_digest = blake3::hash(&expected_bytes);
    let mut layouts = 0;
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        layouts += 1;
        let _caller = norito::core::DecodeFlagsGuard::enter(flags);
        let temp = tempdir().unwrap();
        let path = temp.path().join("metrics.log");
        let log = MetricsLog::open(path.clone()).unwrap();
        log.append(&entries[0]).unwrap();
        log.append(&entries[1]).unwrap();
        drop(log);
        assert_eq!(
            read_metrics_log(&path, log_test_limits()).unwrap(),
            entries[..2]
        );
        let reopened = MetricsLog::open(path.clone()).unwrap();
        reopened.append(&entries[2]).unwrap();
        drop(reopened);
        let stored = std::fs::read(&path).unwrap();
        assert_eq!(stored, expected_bytes);
        assert_eq!(blake3::hash(&stored), expected_digest);
        assert_eq!(read_metrics_log(&path, log_test_limits()).unwrap(), entries);
        // Each boundary consumes exactly its own complete frame, without an EOF probe.
        let mut reader = io::Cursor::new(stored);
        let mut offset = 0;
        for (entry, frame) in entries.iter().zip(&frames) {
            assert_eq!(&read_test_metrics_frame(&mut reader).unwrap(), entry);
            offset += frame.len();
            assert_eq!(reader.position(), offset as u64);
        }
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
    assert_eq!(layouts, 2);
}

#[test]
fn metrics_log_rejects_alternate_frames_and_corruption() {
    let entry = log_test_entries().remove(0);
    let canonical = norito::encode_canonical(&entry).unwrap();
    let temp = tempdir().unwrap();
    let path = temp.path().join("metrics.log");
    let mut alternates = 0;
    for flags in (0..=u8::MAX).filter(|flags| norito::core::validate_header_flags(*flags).is_ok()) {
        let _caller = norito::core::DecodeFlagsGuard::enter(flags);
        let alternate = norito::to_bytes(&entry).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<RelayEpochMetricsV1>(&alternate).unwrap(),
            entry
        );
        if alternate != canonical {
            alternates += 1;
            std::fs::write(&path, [canonical.as_slice(), alternate.as_slice()].concat()).unwrap();
            assert!(matches!(
                read_metrics_log(&path, log_test_limits()),
                Err(MetricsLogError::Decode {
                    source: norito::Error::NonCanonicalEncoding,
                    ..
                })
            ));
        }
        std::fs::write(&path, [canonical.as_slice(), canonical.as_slice()].concat()).unwrap();
        assert_eq!(
            read_metrics_log(&path, log_test_limits()).unwrap(),
            vec![entry.clone(); 2]
        );
    }
    assert!(
        alternates > 0,
        "deny an actual same-value alternate encoding"
    );

    let header = norito::core::Header::read(canonical.as_slice()).unwrap();
    let payload_start = canonical.len() - header.length as usize;
    assert_eq!(payload_start, metrics_frame_overhead());
    for offset in norito::core::Header::SIZE..payload_start {
        assert_eq!(canonical[offset], 0);
        let mut bad_padding = canonical.clone();
        bad_padding[offset] = 1;
        std::fs::write(
            &path,
            [canonical.as_slice(), bad_padding.as_slice()].concat(),
        )
        .unwrap();
        assert!(matches!(
            read_metrics_log(&path, log_test_limits()),
            Err(MetricsLogError::Decode {
                source: norito::Error::LengthMismatch,
                ..
            })
        ));
    }
    let mut corrupt = canonical.clone();
    *corrupt.last_mut().unwrap() ^= 0x80;
    std::fs::write(&path, [canonical.as_slice(), corrupt.as_slice()].concat()).unwrap();
    assert!(matches!(
        read_metrics_log(&path, log_test_limits()),
        Err(MetricsLogError::Decode {
            source: norito::Error::ChecksumMismatch,
            ..
        })
    ));
    let mut wrong_magic = canonical.clone();
    wrong_magic[0] ^= 1;
    std::fs::write(
        &path,
        [canonical.as_slice(), wrong_magic.as_slice()].concat(),
    )
    .unwrap();
    assert!(matches!(
        read_metrics_log(&path, log_test_limits()),
        Err(MetricsLogError::Decode {
            source: norito::Error::InvalidMagic,
            ..
        })
    ));
}

#[test]
fn metrics_log_rejects_every_partial_tail_and_preserves_clean_eof() {
    let entry = log_test_entries().remove(0);
    let canonical = norito::encode_canonical(&entry).unwrap();
    let temp = tempdir().unwrap();
    let path = temp.path().join("metrics.log");
    assert!(
        read_metrics_log(&path, log_test_limits())
            .unwrap()
            .is_empty()
    );
    std::fs::write(&path, []).unwrap();
    assert!(
        read_metrics_log(&path, log_test_limits())
            .unwrap()
            .is_empty()
    );
    std::fs::write(&path, &canonical).unwrap();
    assert_eq!(
        read_metrics_log(&path, log_test_limits()).unwrap(),
        vec![entry.clone()]
    );
    for retained in 1..canonical.len() {
        // A clean first record cannot turn a damaged suffix into successful prefix recovery.
        std::fs::write(
            &path,
            [canonical.as_slice(), &canonical[..retained]].concat(),
        )
        .unwrap();
        assert!(
            matches!(
                read_metrics_log(&path, log_test_limits()),
                Err(MetricsLogError::Decode { source: norito::Error::Io(error), .. })
                    if error.kind() == io::ErrorKind::UnexpectedEof
            ),
            "partial record of {retained} bytes must reject"
        );
    }
    std::fs::write(&path, [canonical.as_slice(), canonical.as_slice()].concat()).unwrap();
    assert_eq!(
        read_metrics_log(&path, log_test_limits()).unwrap(),
        vec![entry; 2]
    );
}

#[test]
fn metrics_log_rejects_valid_foreign_frame_before_allocation() {
    #[derive(
        Debug, PartialEq, norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema,
    )]
    #[norito_schema(name = "sorafs_orchestrator::incentives::tests::ForeignMetricsFrame")]
    struct ForeignMetricsFrame {
        epoch: u32,
    }
    let foreign = ForeignMetricsFrame { epoch: 7 };
    let bytes = norito::encode_canonical(&foreign).expect("valid foreign root frame");
    assert_eq!(
        norito::decode_canonical::<ForeignMetricsFrame>(&bytes).unwrap(),
        foreign
    );
    let header = norito::core::Header::read(bytes.as_slice()).unwrap();
    assert_eq!(header.flags, norito::core::default_encode_flags());
    assert_eq!(header.compression, norito::Compression::None);
    assert_ne!(
        header.schema,
        norito::schema::identity::frame_hash::<RelayEpochMetricsV1>()
    );
    let zero = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let mut reader = io::Cursor::new(bytes);
    let (result, used) =
        norito::core::with_decode_limits_measured(zero, || read_test_metrics_frame(&mut reader));
    assert!(matches!(result, Err(norito::Error::SchemaMismatch)));
    assert_eq!(used.total_allocated_bytes(), 0);
    assert_eq!(reader.position(), norito::core::Header::SIZE as u64);
}
#[test]
fn metrics_log_header_admission_precedes_allocation() {
    use norito::core::Header;
    let entry = log_test_entries().remove(0);
    let canonical = norito::encode_canonical(&entry).unwrap();
    let header = Header::read(canonical.as_slice()).unwrap();
    let compression_offset = header.magic.len() + 2 + header.schema.len();
    let mut tagged = canonical.clone();
    tagged[compression_offset] = norito::Compression::Zstd as u8;
    tagged[compression_offset + 1..compression_offset + 9].copy_from_slice(&u64::MAX.to_le_bytes());
    let forged = Header::read(tagged.as_slice()).unwrap();
    assert_eq!(forged.compression, norito::Compression::Zstd);
    assert_eq!(forged.length, u64::MAX);
    let zero = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    for bytes in [tagged.as_slice(), &tagged[..Header::SIZE]] {
        let mut reader = io::Cursor::new(bytes);
        let (result, used) = norito::core::with_decode_limits_measured(zero, || {
            read_test_metrics_frame(&mut reader)
        });
        assert!(matches!(result, Err(norito::Error::NonCanonicalEncoding)));
        assert_eq!(used.total_allocated_bytes(), 0);
        assert_eq!(reader.position(), Header::SIZE as u64);
    }
    for flags in (0..=u8::MAX).filter(|flags| norito::core::validate_header_flags(*flags).is_ok()) {
        if flags == norito::core::default_encode_flags() {
            continue;
        }
        let mut alternate_header = canonical[..Header::SIZE].to_vec();
        alternate_header[Header::SIZE - 1] = flags;
        assert_eq!(
            Header::read(alternate_header.as_slice()).unwrap().flags,
            flags
        );
        let mut reader = io::Cursor::new(alternate_header);
        let (result, used) = norito::core::with_decode_limits_measured(zero, || {
            read_test_metrics_frame(&mut reader)
        });
        assert!(matches!(result, Err(norito::Error::NonCanonicalEncoding)));
        assert_eq!(used.total_allocated_bytes(), 0);
        assert_eq!(reader.position(), Header::SIZE as u64);
    }
    let mut invalid_flags = canonical[..Header::SIZE].to_vec();
    invalid_flags[Header::SIZE - 1] = 0x80;
    let (result, used) = norito::core::with_decode_limits_measured(zero, || {
        read_test_metrics_frame(&mut io::Cursor::new(invalid_flags))
    });
    assert!(matches!(
        result,
        Err(norito::Error::UnsupportedFeature("layout flag"))
    ));
    assert_eq!(used.total_allocated_bytes(), 0);
    tagged[compression_offset] = norito::Compression::None as u8;
    let limit = norito::core::max_archive_len();
    let mut reader = io::Cursor::new(&tagged[..Header::SIZE]);
    let (result, used) =
        norito::core::with_decode_limits_measured(zero, || read_test_metrics_frame(&mut reader));
    assert!(
        matches!(result, Err(norito::Error::ArchiveLengthExceeded { length: u64::MAX, limit: actual }) if actual == limit)
    );
    assert_eq!(used.total_allocated_bytes(), 0);

    let mut wrong_schema = canonical.clone();
    wrong_schema[header.magic.len() + 2] ^= 1;
    let mut reader = io::Cursor::new(&wrong_schema[..Header::SIZE]);
    let (result, used) =
        norito::core::with_decode_limits_measured(zero, || read_test_metrics_frame(&mut reader));
    assert!(matches!(result, Err(norito::Error::SchemaMismatch)));
    assert_eq!(used.total_allocated_bytes(), 0);

    let mut reader = io::Cursor::new(canonical.as_slice());
    let (result, used) =
        norito::core::with_decode_limits_measured(zero, || read_test_metrics_frame(&mut reader));
    assert!(
        matches!(result, Err(norito::Error::TotalAllocationExceeded { attempted, limit: 0 }) if attempted == canonical.len() as u64)
    );
    assert_eq!(used.total_allocated_bytes(), 0);
    assert_eq!(reader.position(), Header::SIZE as u64);
}

#[test]
fn metrics_log_frame_buffer_respects_exact_outer_allocation_budget() {
    let entry = log_test_entries().remove(0);
    let canonical = norito::encode_canonical(&entry).unwrap();
    let limits = norito::canonical_decode_limits(canonical.len());
    let (result, used) = norito::core::with_decode_limits_measured(limits, || {
        read_test_metrics_frame(&mut io::Cursor::new(canonical.as_slice()))
    });
    assert_eq!(result.unwrap(), entry);
    let allocation = used.total_allocated_bytes();
    assert!(allocation >= canonical.len());
    let exact = norito::DecodeLimits::new(
        limits.max_sequence_elements(),
        limits.max_field_bytes(),
        limits.max_total_elements(),
        allocation,
        limits.max_nesting_depth(),
    );
    assert_eq!(
        norito::with_decode_limits_scope(exact, || read_test_metrics_frame(&mut io::Cursor::new(
            canonical.as_slice()
        )))
        .unwrap(),
        entry
    );
    let short = norito::DecodeLimits::new(
        limits.max_sequence_elements(),
        limits.max_field_bytes(),
        limits.max_total_elements(),
        allocation - 1,
        limits.max_nesting_depth(),
    );
    assert!(matches!(
        norito::with_decode_limits_scope(short, || read_test_metrics_frame(&mut io::Cursor::new(canonical.as_slice()))),
        Err(norito::Error::TotalAllocationExceeded { limit, .. }) if limit == (allocation - 1) as u64
    ));
}

#[test]
fn metrics_log_read_policy_is_validated_before_path_access() {
    struct UnreachablePath;
    impl AsRef<Path> for UnreachablePath {
        fn as_ref(&self) -> &Path {
            panic!("invalid policy must fail before path resolution or filesystem access");
        }
    }
    for (slot, maximum) in [
        METRICS_LOG_MAX_READ_RECORDS_V1,
        METRICS_LOG_MAX_READ_BYTES_V1,
        METRICS_LOG_MAX_READ_ALLOCATION_BYTES_V1,
    ]
    .into_iter()
    .enumerate()
    {
        for invalid in [0, maximum + 1, usize::MAX] {
            let mut policy = log_test_limits();
            match slot {
                0 => policy.max_records = invalid,
                1 => policy.max_total_frame_bytes = invalid,
                _ => policy.max_total_allocated_bytes = invalid,
            }
            assert!(matches!(read_metrics_log(UnreachablePath, policy),
                Err(MetricsLogError::InvalidReadLimits { limits }) if limits == policy));
        }
    }
    MetricsLogReadLimitsV1 {
        max_records: METRICS_LOG_MAX_READ_RECORDS_V1,
        max_total_frame_bytes: METRICS_LOG_MAX_READ_BYTES_V1,
        max_total_allocated_bytes: METRICS_LOG_MAX_READ_ALLOCATION_BYTES_V1,
    }
    .validate()
    .unwrap();
    let temp = tempdir().unwrap();
    let path = temp.path().join("existing-file");
    std::fs::write(&path, []).unwrap();
    assert!(matches!(
        read_metrics_log(path.join("child"), log_test_limits()),
        Err(MetricsLogError::Open { .. })
    ));
}

#[test]
fn metrics_log_batch_enforces_exact_full_frame_and_record_limits() {
    let entries = log_test_entries();
    let frames: Vec<_> = entries
        .iter()
        .map(|entry| norito::encode_canonical(entry).unwrap())
        .collect();
    let bytes = frames.concat();
    let temp = tempdir().unwrap();
    let path = temp.path().join("metrics.log");
    std::fs::write(&path, &bytes).unwrap();
    let policy = MetricsLogReadLimitsV1 {
        max_records: entries.len(),
        max_total_frame_bytes: bytes.len(),
        ..log_test_limits()
    };
    assert_eq!(read_metrics_log(&path, policy).unwrap(), entries);
    assert!(matches!(
        read_metrics_log(
            &path,
            MetricsLogReadLimitsV1 {
                max_records: entries.len() - 1,
                ..policy
            }
        ),
        Err(MetricsLogError::Decode {
            source: norito::Error::SequenceLengthExceeded {
                length: 3,
                limit: 2
            },
            ..
        })
    ));
    assert!(matches!(read_metrics_log(&path, MetricsLogReadLimitsV1 {
        max_total_frame_bytes: bytes.len() - 1, ..policy
    }), Err(MetricsLogError::Decode { source: norito::Error::ArchiveLengthExceeded { length, limit }, .. })
        if length == bytes.len() as u64 && limit == (bytes.len() - 1) as u64));
    // Full frame accounting includes the actual header and schema-owned alignment padding.
    let payload_only: usize = frames
        .iter()
        .map(|frame| norito::core::Header::read(frame.as_slice()).unwrap().length as usize)
        .sum();
    assert!(payload_only < bytes.len());
    assert!(
        read_metrics_log(
            &path,
            MetricsLogReadLimitsV1 {
                max_total_frame_bytes: payload_only,
                ..policy
            }
        )
        .is_err()
    );
    let mut total = usize::MAX;
    let mut reader = io::Cursor::new(frames[0].as_slice());
    let zero = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let (result, used) = norito::core::with_decode_limits_measured(zero, || {
        read_metrics_frame(&mut reader, &mut total, usize::MAX)
    });
    assert!(matches!(result, Err(norito::Error::LengthMismatch)));
    assert_eq!(used.total_allocated_bytes(), 0);
    assert_eq!(total, usize::MAX);
    assert_eq!(reader.position(), norito::core::Header::SIZE as u64);
}

#[test]
fn metrics_log_allocation_is_cumulative_across_records_and_output_growth() {
    let entry = log_test_entries().remove(0);
    let frame = norito::encode_canonical(&entry).unwrap();
    let count = 33; // Cross the 16- and 32-entry geometric growth boundaries.
    let bytes = frame.repeat(count);
    let temp = tempdir().unwrap();
    let path = temp.path().join("metrics.log");
    std::fs::write(&path, &bytes).unwrap();
    let policy = MetricsLogReadLimitsV1 {
        max_records: count,
        max_total_frame_bytes: bytes.len(),
        ..log_test_limits()
    };
    let (result, used) = norito::core::with_decode_limits_measured(policy.decode_limits(), || {
        read_metrics_log(&path, policy)
    });
    assert_eq!(result.unwrap(), vec![entry.clone(); count]);
    let output_requests = (16 + 32 + 33) * std::mem::size_of::<RelayEpochMetricsV1>();
    let allocation = used.total_allocated_bytes();
    assert!(allocation >= METRICS_LOG_READER_BUFFER_BYTES + bytes.len() + output_requests);
    let exact = MetricsLogReadLimitsV1 {
        max_total_allocated_bytes: allocation,
        ..policy
    };
    assert_eq!(
        read_metrics_log(&path, exact).unwrap(),
        vec![entry.clone(); count]
    );
    assert!(matches!(read_metrics_log(&path, MetricsLogReadLimitsV1 {
        max_total_allocated_bytes: allocation - 1, ..policy
    }), Err(MetricsLogError::Decode { source: norito::Error::TotalAllocationExceeded { limit, .. }, .. }) if limit == (allocation - 1) as u64));
    let outer = norito::DecodeLimits::new(
        policy.decode_limits().max_sequence_elements(),
        policy.max_total_frame_bytes,
        policy.decode_limits().max_total_elements(),
        allocation - 1,
        norito::core::MAX_VALUE_NESTING_DEPTH,
    );
    assert!(
        matches!(norito::with_decode_limits_scope(outer, || read_metrics_log(&path, policy)),
        Err(MetricsLogError::Decode { source: norito::Error::TotalAllocationExceeded { limit, .. }, .. })
            if limit == (allocation - 1) as u64)
    );
    assert!(matches!(read_metrics_log(&path, MetricsLogReadLimitsV1 {
        max_total_allocated_bytes: METRICS_LOG_READER_BUFFER_BYTES - 1, ..policy
    }), Err(MetricsLogError::Decode { source: norito::Error::TotalAllocationExceeded { attempted, limit }, .. })
        if attempted == METRICS_LOG_READER_BUFFER_BYTES as u64 && limit == (METRICS_LOG_READER_BUFFER_BYTES - 1) as u64));
    let single_policy = MetricsLogReadLimitsV1 {
        max_records: 1,
        max_total_frame_bytes: frame.len(),
        ..policy
    };
    std::fs::write(&path, &frame).unwrap();
    let (single, single_used) =
        norito::core::with_decode_limits_measured(single_policy.decode_limits(), || {
            read_metrics_log(&path, single_policy)
        });
    assert_eq!(single.unwrap(), vec![entry.clone()]);
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        read_metrics_log(
            &path,
            MetricsLogReadLimitsV1 {
                max_total_allocated_bytes: single_used.total_allocated_bytes(),
                ..policy
            }
        ),
        Err(MetricsLogError::Decode {
            source: norito::Error::TotalAllocationExceeded { .. },
            ..
        })
    ));

    // Isolate output storage accounting: fewer than twice the final slot count is
    // requested in total, rather than reallocating a prefix for every record.
    let mut output = Vec::new();
    let slots = 128;
    let (_, growth) =
        norito::core::with_decode_limits_measured(log_test_limits().decode_limits(), || {
            for _ in 0..slots {
                reserve_metrics_entry(&mut output, slots).unwrap();
                output.push(entry.clone());
            }
        });
    assert_eq!(
        growth.total_allocated_bytes(),
        (16 + 32 + 64 + 128) * std::mem::size_of::<RelayEpochMetricsV1>()
    );
    assert!(
        growth.total_allocated_bytes() < 2 * slots * std::mem::size_of::<RelayEpochMetricsV1>()
    );
}

#[test]
fn metrics_log_writer_preflights_full_canonical_output() {
    for entry in log_test_entries() {
        let canonical = norito::encode_canonical(&entry).unwrap();
        let payload_len = norito::core::Header::read(canonical.as_slice())
            .unwrap()
            .length;
        assert_eq!(
            norito::canonical_frame_len(&entry).unwrap(),
            canonical.len()
        );
        assert_eq!(
            encode_metrics_frame(&entry, payload_len, canonical.len()).unwrap(),
            canonical
        );
        assert!(
            matches!(encode_metrics_frame(&entry, payload_len, canonical.len() - 1),
            Err(norito::Error::ArchiveLengthExceeded { length, limit })
                if length == canonical.len() as u64 && limit == (canonical.len() - 1) as u64)
        );
        assert!(
            matches!(encode_metrics_frame(&entry, payload_len - 1, canonical.len()),
            Err(norito::Error::ArchiveLengthExceeded { length, limit })
                if length == payload_len && limit == payload_len - 1)
        );
    }
}

#[test]
fn reward_config_retains_original_metrics_open_path_and_filesystem_cause() {
    use std::error::Error as _;

    let temp = tempdir().unwrap();
    let occupied = temp.path().join("occupied");
    std::fs::write(&occupied, b"existing file").unwrap();
    let mut config = engine(500, 500, 0).config().clone();
    let requested = occupied.join("metrics.log");
    config.metrics_log_path = Some(requested.clone());
    let error = RelayRewardEngine::new(config.clone()).unwrap_err();
    assert!(error.to_string().contains(&format!("{requested:?}")));
    let RewardConfigError::MetricsLog { path, source } = error else {
        panic!("expected original log-opening failure");
    };
    assert_eq!(path, requested);
    assert!(
        source
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .is_some()
    );
    let MetricsLogOpenError::CreateDir { path, source } = source else {
        panic!("expected failed parent-directory creation");
    };
    assert_eq!(path, occupied);
    let expected = std::fs::create_dir_all(&occupied).unwrap_err();
    assert_eq!(source.kind(), expected.kind());
    assert_eq!(source.raw_os_error(), expected.raw_os_error());

    config.metrics_log_path = Some(temp.path().to_path_buf());
    let error = RelayRewardEngine::new(config).unwrap_err();
    let RewardConfigError::MetricsLog { path, source } = error else {
        panic!("expected log file open failure");
    };
    assert_eq!(path, temp.path());
    let MetricsLogOpenError::Open { path, source } = source else {
        panic!("expected failed log file open");
    };
    assert_eq!(path, temp.path());
    let expected = OpenOptions::new()
        .create(true)
        .append(true)
        .open(temp.path())
        .unwrap_err();
    assert_eq!(source.kind(), expected.kind());
    assert_eq!(source.raw_os_error(), expected.raw_os_error());
    assert_eq!(std::fs::read(occupied).unwrap(), b"existing file");
}
