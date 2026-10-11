//! Complete original commitment/tag/signature graphs and exact assembly retirement.
use super::*;
use iroha_schema::IntoSchema;
use norito::core::{DecodeFlagsGuard, Encoder, SerializePayload, header_flags};

fn record(i: u8, tag: String, payload: &[u8]) -> DaCommitmentRecord {
    DaCommitmentRecord::new(
        LaneId::new(u32::from(i)),
        u64::from(i),
        u64::from(i) + 1,
        BlobDigest::new([i; 32]),
        ManifestDigest::new([i.wrapping_add(1); 32]),
        DaProofScheme::MerkleSha256,
        Hash::new([i; 32]),
        if i.is_multiple_of(2) {
            Some(Hash::new([i.wrapping_add(2); 32]))
        } else {
            None
        },
        RetentionPolicy {
            hot_retention_secs: u64::from(i),
            cold_retention_secs: u64::from(i) + 100,
            required_replicas: u16::from(i) + 1,
            storage_class: match i % 3 {
                0 => StorageClass::Hot,
                1 => StorageClass::Warm,
                _ => StorageClass::Cold,
            },
            governance_tag: GovernanceTag(tag),
        },
        StorageTicketId::new([i.wrapping_add(3); 32]),
        Signature::from_bytes(payload),
    )
}
fn fixture() -> DaCommitmentBundle {
    DaCommitmentBundle::new(vec![
        record(3, "é漢🙂".into(), &[0x61; 3]),
        record(7, String::new(), &[0x63; 96]),
    ])
}
fn bytes(value: &impl SerializePayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut bytes))
        .unwrap();
    bytes
}
fn source(
    value: &DaCommitmentBundle,
    pool: &AllocationBudget,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let wire = bytes(value);
    let mut input = ChargedBuffer::new(wire.len() + 9, pool).unwrap();
    input.append(&[0xa5; 9]).unwrap();
    input.append(&wire).unwrap();
    (
        input,
        SequenceSpan {
            start: 9,
            end: 9 + wire.len(),
        },
    )
}
#[test]
fn da_commitment_immutable_owner_preserves_complete_wire_json_schema_merkle_and_untrusted_claims() {
    #[derive(norito::codec::Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::da::commitment::DaCommitmentBundle")]
    struct SoleWire {
        version: u16,
        commitments: Vec<DaCommitmentRecord>,
    }
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let original = fixture();
        let mut reversed = original.commitments().to_vec();
        reversed.reverse();
        let malformed = DaCommitmentBundle::from_untrusted_parts(9, reversed);
        for value in [original, malformed, DaCommitmentBundle::default()] {
            let independent = SoleWire {
                version: value.version(),
                commitments: value.commitments().to_vec(),
            };
            assert_eq!(bytes(&value), bytes(&independent));
            assert_eq!(
                norito::to_bytes(&value).unwrap(),
                norito::to_bytes(&independent).unwrap()
            );
            let pool = AllocationBudget::new(1 << 20);
            let (source, span) = source(&value, &pool);
            let floor = pool.reserved_bytes();
            let mut pending =
                PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
            pending.prepare(&source).unwrap();
            let admitted = pending
                .finish(&source)
                .unwrap_or_else(|_| panic!("complete original commitment owner"));
            assert_eq!(admitted, value);
            assert!(admitted.admitted_to(&pool));
            assert!(!value.admitted_to(&pool));
            assert_eq!(
                norito::to_bytes(&admitted).unwrap(),
                norito::to_bytes(&value).unwrap()
            );
            assert_eq!(admitted.merkle_root(), value.merkle_root());
            assert_eq!(admitted.merkle_commitment(), value.merkle_commitment());
            let json = norito::json::to_json(&value).unwrap();
            assert_eq!(norito::json::to_json(&admitted).unwrap(), json);
            let decoded: DaCommitmentBundle = norito::json::from_json(&json).unwrap();
            assert_eq!(decoded, value);
            assert!(!decoded.admitted_to(&pool));
            let ordinary = norito::decode_from_bytes::<DaCommitmentBundle>(
                &norito::to_bytes(&admitted).unwrap(),
            )
            .unwrap();
            assert_eq!(ordinary, value);
            assert!(!ordinary.admitted_to(&pool));
            let shared = admitted.clone();
            assert!(DaCommitmentBundle::ptr_eq(&admitted, &shared));
            drop(admitted);
            assert!(shared.admitted_to(&pool));
            drop(shared);
            assert_eq!(pool.reserved_bytes(), floor);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let mut bad = bytes(&fixture());
        bad.push(0x91);
        assert!(
            DaCommitmentBundle::decode_from_slice(&bad).is_err(),
            "original archived whole-input contract rejects trailer"
        );
        let mut map = iroha_schema::MetaMap::new();
        DaCommitmentBundle::update_schema_map(&mut map);
        let iroha_schema::Metadata::Struct(fields) = map.get::<DaCommitmentBundle>().unwrap()
        else {
            panic!("same canonical named record");
        };
        assert_eq!(
            fields
                .declarations
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["version", "commitments"]
        );
        assert_eq!(fields.declarations[0].ty, std::any::TypeId::of::<u16>());
        assert_eq!(
            fields.declarations[1].ty,
            std::any::TypeId::of::<Vec<DaCommitmentRecord>>()
        );
    }
}
#[test]
fn da_commitment_generated_children_reject_truncated_wire_bad_utf8_and_original_fixed_signature_causes()
 {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let value = fixture();
        let wire = bytes(&value);
        for end in 0..wire.len() {
            let pool = AllocationBudget::new(1 << 20);
            let mut source = ChargedBuffer::new(end, &pool).unwrap();
            source.append(&wire[..end]).unwrap();
            let floor = pool.reserved_bytes();
            if let Ok(mut pending) = PreparedDaCommitmentBundle::from_source(
                &source,
                SequenceSpan { start: 0, end },
                &pool,
            ) {
                assert!(pending.prepare(&source).is_err());
            }
            assert_eq!(pool.reserved_bytes(), floor);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let pool = AllocationBudget::new(1 << 20);
        let (mut source, span) = source(&value, &pool);
        let offset = source
            .as_slice()
            .windows("é漢🙂".len())
            .position(|part| part == "é漢🙂".as_bytes())
            .unwrap();
        source.as_mut_slice()[offset] = 0xff;
        let mut pending = PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
        let error = pending.prepare(&source).unwrap_err();
        let DaCommitmentCustodyError::Decode(original) = error else {
            panic!("bad UTF-8 must preserve the original decode error");
        };
        assert!(matches!(original.into_error(), norito::Error::InvalidUtf8));
        assert!(pending.phase < PreparationPhase::PayloadAdmitted);
        assert!(pending.values.value.is_none());
        drop(pending);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
        for (payload, expected) in [
            (Vec::new(), iroha_crypto::SignaturePayloadError::Empty),
            (vec![0; 3], iroha_crypto::SignaturePayloadError::AllZero),
        ] {
            let malformed =
                DaCommitmentBundle::new(vec![record(3, "original tag".into(), &payload)]);
            let pool = AllocationBudget::new(1 << 20);
            let (source, span) = self::source(&malformed, &pool);
            let mut pending =
                PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
            let error = pending.prepare(&source).unwrap_err();
            assert!(
                matches!(error,DaCommitmentCustodyError::Signature(PreparedCryptoDecodeError::Signature(actual)) if actual==expected)
            );
            assert!(pending.phase < PreparationPhase::PayloadAdmitted);
            assert!(pending.values.value.is_none());
            drop(pending);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        assert_eq!(
            fixed_tuple::<BlobDigest>(&bytes(&BlobDigest::new([0x53; 32]))).unwrap(),
            [0x53; 32]
        );
        assert_eq!(
            fixed_tuple::<ManifestDigest>(&bytes(&ManifestDigest::new([0x55; 32]))).unwrap(),
            [0x55; 32]
        );
        assert_eq!(
            fixed_tuple::<StorageTicketId>(&bytes(&StorageTicketId::new([0x57; 32]))).unwrap(),
            [0x57; 32]
        );
        assert!(fixed_tuple::<BlobDigest>(&[0]).is_err());
        for class in [StorageClass::Hot, StorageClass::Warm, StorageClass::Cold] {
            let (decoded, used) = StorageClass::decode_from_slice(&bytes(&class)).unwrap();
            assert_eq!(decoded, class);
            assert_eq!(used, bytes(&class).len());
        }
        assert!(StorageClass::decode_from_slice(&[0xff; 4]).is_err());
    }
}
#[test]
fn da_commitment_actual_finish_interruption_destroys_original_tag_signature_array_before_refund() {
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    for point in [1, 2] {
        let value = fixture();
        let pool = AllocationBudget::new(1 << 20);
        let (source, span) = source(&value, &pool);
        let floor = pool.reserved_bytes();
        let pointer = source.as_slice().as_ptr();
        let hash = Hash::new(source.as_slice());
        let mut pending = PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
        pending.prepare(&source).unwrap();
        assert!(pool.reserved_bytes() > floor);
        ASSEMBLY_PANIC_AFTER.with(|p| p.set(Some(point)));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = pending.finish(&source);
        }));
        ASSEMBLY_PANIC_AFTER.with(|p| p.set(None));
        assert!(interrupted.is_err());
        assert_eq!(pool.reserved_bytes(), floor);
        assert_eq!(source.as_slice().as_ptr(), pointer);
        assert_eq!(Hash::new(source.as_slice()), hash);
        let mut retry = PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
        retry.prepare(&source).unwrap();
        let admitted = retry
            .finish(&source)
            .unwrap_or_else(|_| panic!("original complete retry"));
        assert_eq!(admitted, value);
        drop(admitted);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn da_commitment_payload_refusal_keeps_planned_phase_and_original_backings_until_retry() {
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source(&original, &pool);
    let source_floor = pool.reserved_bytes();
    let mut pending = PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
    assert_eq!(pending.phase, PreparationPhase::Unadmitted);
    let metadata_bytes = pending
        .planning_layouts()
        .unwrap()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes() - metadata_bytes)
        .unwrap();
    assert!(matches!(
        pending.prepare(&source),
        Err(DaCommitmentCustodyError::Admission(_))
    ));
    assert_eq!(pending.phase, PreparationPhase::Planned);
    let rows = pending.rows.value.as_ref().unwrap().as_slice().as_ptr();
    let spans = pending.spans.value.as_ref().unwrap().as_slice().as_ptr();
    let refused_reservation = pool.reserved_bytes();
    assert!(pending.prepare(&source).is_err());
    assert_eq!(pending.phase, PreparationPhase::Planned);
    assert_eq!(
        pending.rows.value.as_ref().unwrap().as_slice().as_ptr(),
        rows
    );
    assert_eq!(
        pending.spans.value.as_ref().unwrap().as_slice().as_ptr(),
        spans
    );
    assert_eq!(pool.reserved_bytes(), refused_reservation);
    drop(blocker);
    pending.prepare(&source).unwrap();
    assert_eq!(pending.phase, PreparationPhase::Ready);
    let admitted = pending
        .finish(&source)
        .unwrap_or_else(|_| panic!("complete original owner after exact retry"));
    assert_eq!(admitted, original);
    drop(admitted);
    assert_eq!(pool.reserved_bytes(), source_floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn da_commitment_inline_digest_fields_keep_exact_raw_wire_and_zero_decode_charges() {
    type DigestDecoder = fn(&[u8]) -> Result<[u8; 32], norito::Error>;
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let cases: [(DigestDecoder, Vec<u8>, [u8; 32]); 3] = [
            (
                fixed_tuple::<BlobDigest>,
                bytes(&BlobDigest::new([0x53; 32])),
                [0x53; 32],
            ),
            (
                fixed_tuple::<ManifestDigest>,
                bytes(&ManifestDigest::new([0x55; 32])),
                [0x55; 32],
            ),
            (
                fixed_tuple::<StorageTicketId>,
                bytes(&StorageTicketId::new([0x57; 32])),
                [0x57; 32],
            ),
        ];
        for (decode, wire, expected) in cases {
            let mut literal = if flags == header_flags::COMPACT_LEN {
                vec![32]
            } else {
                32_u64.to_le_bytes().to_vec()
            };
            literal.extend_from_slice(&expected);
            assert_eq!(wire, literal);
            let limits = norito::DecodeLimits::new(0, 32, 0, 0, 0);
            let (decoded, usage) =
                norito::core::with_decode_limits_measured(limits, || decode(&wire));
            assert_eq!(decoded.unwrap(), expected);
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
        // The same destination keeps the existing scalar field depth and stack decoder.
        let lane = LaneId::new(0x0102_0304);
        let wire = bytes(&lane);
        let limits = norito::DecodeLimits::new(0, 4, 0, 0, 1);
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits, || inline_lane(&wire));
        assert_eq!(decoded.unwrap(), lane);
        assert_eq!(usage.total_elements(), 0);
        assert_eq!(usage.total_allocated_bytes(), 0);
    }
}

#[test]
fn da_commitment_inline_digest_fields_reject_wrong_width_framed_arrays_and_original_limits() {
    type DigestDecoder = fn(&[u8]) -> Result<[u8; 32], norito::Error>;
    let decoders: [DigestDecoder; 3] = [
        fixed_tuple::<BlobDigest>,
        fixed_tuple::<ManifestDigest>,
        fixed_tuple::<StorageTicketId>,
    ];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let canonical = bytes(&BlobDigest::new([0x53; 32]));
        let generic_array = bytes(&[0x53_u8; 32]);
        assert_ne!(generic_array.len(), 32);
        let mut framed_array = Vec::new();
        norito::core::write_len_to_vec_with_flags(
            &mut framed_array,
            generic_array.len() as u64,
            flags,
        );
        framed_array.extend_from_slice(&generic_array);
        let mut trailing = canonical.clone();
        trailing.push(0x99);
        let mut missing_body = Vec::new();
        norito::core::write_len_to_vec_with_flags(&mut missing_body, 33, flags);
        for decode in decoders {
            let zero = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 0);
            for width in [31_u64, 33] {
                let mut wrong_width = Vec::new();
                norito::core::write_len_to_vec_with_flags(&mut wrong_width, width, flags);
                wrong_width.extend(std::iter::repeat_n(0x53, usize::try_from(width).unwrap()));
                let (rejected, usage) =
                    norito::core::with_decode_limits_measured(zero, || decode(&wrong_width));
                assert!(matches!(rejected, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_elements(), 0);
                assert_eq!(usage.total_allocated_bytes(), 0);
            }
            for malformed in [&framed_array, &trailing] {
                let (rejected, usage) =
                    norito::core::with_decode_limits_measured(zero, || decode(malformed));
                assert!(matches!(rejected, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_elements(), 0);
                assert_eq!(usage.total_allocated_bytes(), 0);
            }
            for end in 0..canonical.len() {
                let (truncated, usage) =
                    norito::core::with_decode_limits_measured(zero, || decode(&canonical[..end]));
                assert!(truncated.is_err());
                assert_eq!(usage.total_elements(), 0);
                assert_eq!(usage.total_allocated_bytes(), 0);
            }
            // Its declared field ceiling wins before the absent body or any local allocation.
            let narrow = norito::DecodeLimits::new(0, 32, 0, 0, 0);
            let (refused, usage) =
                norito::core::with_decode_limits_measured(narrow, || decode(&missing_body));
            assert!(matches!(
                refused,
                Err(norito::Error::FieldLengthExceeded {
                    length: 33,
                    limit: 32
                })
            ));
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
            let (malformed, usage) =
                norito::core::with_decode_limits_measured(zero, || decode(&missing_body));
            assert!(matches!(malformed, Err(norito::Error::LengthMismatch)));
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
    }
}
