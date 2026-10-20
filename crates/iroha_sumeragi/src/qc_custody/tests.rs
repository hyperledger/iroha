//! Exact nine-field transport, original source/ledger lifetime and scoped refusal controls.
use super::*;
use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext};
fn fixture(kind: VoteKind, bytes: usize) -> Qc {
    Qc {
        kind,
        instance: Hash32([3; 32]),
        epoch: EpochId {
            epoch: 7,
            context: Hash32([5; 32]),
        },
        height: 11,
        view: 13,
        block_hash: Hash32([17; 32]),
        result: Hash32([19; 32]),
        signers: Bitmap::from_bytes(vec![0x55; bytes]),
        agg_sig: AggregateSignature([23; crate::types::SIGNATURE_LEN]),
    }
}
fn source(
    bytes: &[u8],
    pool: &AllocationBudget,
    prefix: usize,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let mut input = ChargedBuffer::new(prefix + bytes.len(), pool).unwrap();
    for _ in 0..prefix {
        input.push_reserved(0xa5);
    }
    for byte in bytes {
        input.push_reserved(*byte);
    }
    (
        input,
        SequenceSpan {
            start: prefix,
            end: prefix + bytes.len(),
        },
    )
}
fn generous() -> DecodeLimits {
    DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64)
}
fn cause(error: QcCustodyError) -> norito::core::DecodeAttemptError {
    let QcCustodyError::Decode(PreparedDecodeError::Codec(error)) = error else {
        panic!("expected original codec/scope cause")
    };
    error
}
#[test]
fn all_nine_qc_fields_full_frame_and_last_reader_keep_original_source_and_bitmap_charge() {
    for kind in [VoteKind::Prepare, VoteKind::Commit] {
        for length in [0, 1, 4, 128] {
            for prefix in [0, 1, 7, 16] {
                let original = fixture(kind, length);
                let frame = norito::encode_canonical(&original).unwrap();
                assert_eq!(norito::decode_canonical::<Qc>(&frame).unwrap(), original);
                let pool = AllocationBudget::new(1 << 20);
                let (input, range) = source(&frame, &pool, prefix);
                let floor = pool.reserved_bytes();
                let pointer = input.as_slice().as_ptr();
                let hash = norito::core::crc64_fallback(input.as_slice());
                let mut pending = PreparedQc::new(&input, range, &pool).unwrap();
                let controls = PreparedQc::control_layouts()
                    .iter()
                    .map(Layout::size)
                    .sum::<usize>();
                assert_eq!(pool.reserved_bytes(), floor + controls);
                pending.prepare(&input, range, generous()).unwrap();
                let bitmap_pointer = pending.fields.payload.signers.as_bytes().as_ptr();
                assert_eq!(pool.reserved_bytes(), floor + controls + length);
                let original = norito::decode_canonical::<Qc>(&frame).unwrap();
                let owner = pending.finish().unwrap();
                assert_eq!(owner.get(), &original);
                assert!(owner.belongs_to(&pool));
                assert_eq!(owner.source_bytes(), frame);
                assert_eq!(owner.get().signers.as_bytes().as_ptr(), bitmap_pointer);
                let other = owner.clone();
                assert!(NativeQc::ptr_eq(&owner, &other));
                drop(owner);
                assert_eq!(pool.reserved_bytes(), floor + controls + length);
                assert_eq!(other.get().signers.as_bytes().as_ptr(), bitmap_pointer);
                assert_eq!(norito::encode_canonical(other.get()).unwrap(), frame);
                assert_eq!(input.as_slice().as_ptr(), pointer);
                assert_eq!(norito::core::crc64_fallback(input.as_slice()), hash);
                drop(other);
                assert_eq!(pool.reserved_bytes(), floor);
                drop(input);
                assert_eq!(pool.reserved_bytes(), 0);
            }
        }
    }
}
#[test]
fn qc_source_lifetime_and_exact_range_refuse_foreign_or_equal_replacement_sources() {
    let frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 0);
    let (copy, _) = source(&frame, &pool, 0);
    let foreign = AllocationBudget::new(1 << 20);
    let (other, _) = source(&frame, &foreign, 0);
    assert!(matches!(
        PreparedQc::new(&other, range, &pool),
        Err(QcCustodyError::Source)
    ));
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let occupied = pool.reserved_bytes();
    assert!(matches!(
        decoder.prepare(&copy, range, generous()),
        Err(QcCustodyError::Source)
    ));
    assert!(matches!(
        decoder.prepare(
            &input,
            SequenceSpan {
                start: 1,
                end: range.end
            },
            generous()
        ),
        Err(QcCustodyError::Source)
    ));
    assert_eq!(pool.reserved_bytes(), occupied);
    decoder.prepare(&input, range, generous()).unwrap();
    let owner = decoder.finish().unwrap();
    assert!(!owner.belongs_to(&foreign));
    drop(owner);
    drop(input);
    drop(copy);
    drop(other);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}
#[test]
fn qc_complete_canonical_frame_rejections_match_original_before_any_structural_check() {
    let frame = norito::encode_canonical(&fixture(VoteKind::Commit, 4)).unwrap();
    let mut cases = vec![vec![], frame[..frame.len() - 1].to_vec()];
    let mut checksum = frame.clone();
    *checksum.last_mut().unwrap() ^= 1;
    cases.push(checksum);
    let mut schema = frame.clone();
    schema[6] ^= 1;
    cases.push(schema);
    let mut flags = frame.clone();
    flags[39] ^= 0x80;
    cases.push(flags);
    let mut extra = frame.clone();
    extra.push(0);
    cases.push(extra);
    for bytes in cases {
        let ordinary = norito::decode_canonical::<Qc>(&bytes).unwrap_err();
        let pool = AllocationBudget::new(1 << 20);
        let (input, range) = source(&bytes, &pool, 3);
        let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
        let original = cause(decoder.prepare(&input, range, generous()).unwrap_err());
        assert_eq!(original.kind(), DecodeAttemptErrorKind::Invalid);
        assert_eq!(original.error().to_string(), ordinary.to_string());
        drop(original);
        drop(decoder);
        drop(input);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn qc_transport_1024_bitmap_bound_never_becomes_31_seat_or_quorum_authentication() {
    for n in [128, 129] {
        let value = fixture(VoteKind::Prepare, n);
        let frame = norito::encode_canonical(&value).unwrap();
        let pool = AllocationBudget::new(1 << 20);
        let (input, range) = source(&frame, &pool, 0);
        let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
        let controls_floor = pool.reserved_bytes();
        let result = decoder.prepare(&input, range, generous());
        assert_eq!(pool.reserved_bytes(), controls_floor + n);
        if n == 128 {
            result.unwrap();
            let owner = decoder.finish().unwrap();
            assert!(!owner.get().signers.is_well_formed(31));
            drop(owner);
        } else {
            assert!(matches!(
                result,
                Err(QcCustodyError::Structural(CodecError::Limit("bitmap")))
            ));
            let bitmap_pointer = decoder.fields.payload.signers.as_bytes().as_ptr();
            pool.set_limit_bytes(controls_floor + n);
            assert!(matches!(
                decoder.prepare(&input, range, generous()),
                Err(QcCustodyError::Structural(CodecError::Limit("bitmap")))
            ));
            assert_eq!(
                decoder.fields.payload.signers.as_bytes().as_ptr(),
                bitmap_pointer
            );
            assert_eq!(pool.reserved_bytes(), controls_floor + n);
            let (decoder, error) = decoder.finish().unwrap_err();
            assert!(matches!(error, QcCustodyError::Incomplete));
            drop(decoder);
        }
        drop(input);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let mut invalid = norito::encode_canonical(&fixture(VoteKind::Prepare, 129)).unwrap();
    *invalid.last_mut().unwrap() ^= 1;
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&invalid, &pool, 0);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    assert!(
        matches!(
            decoder.prepare(&input, range, generous()),
            Err(QcCustodyError::Decode(_))
        ),
        "checksum failure precedes structural bitmap limit"
    );
}
#[test]
fn qc_original_enclosing_counter_cause_survives_retry_scope_retirement_and_last_reader() {
    let value = fixture(VoteKind::Commit, 4);
    let frame = norito::encode_canonical(&value).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 0);
    let narrow = DecodeLimits::new(1 << 20, 0, 1 << 20, 1 << 20, 64);
    let caller = DecodeBudgetContext::try_new_owned(narrow, &pool).unwrap();
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let error = caller
        .with(|| decoder.prepare(&input, range, generous()))
        .unwrap_err();
    let original = cause(error);
    assert_eq!(original.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert!(original.local_refusal().is_some());
    let descriptor = original.error().decode_resource_error();
    decoder.prepare(&input, range, generous()).unwrap();
    let owner = decoder.finish().unwrap();
    drop(caller);
    assert_eq!(original.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(original.error().decode_resource_error(), descriptor);
    drop(owner);
    drop(original);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn qc_protocol_counter_refusal_is_invalid_never_reclassified_as_local_retry() {
    let frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 0);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let error = cause(
        decoder
            .prepare(
                &input,
                range,
                DecodeLimits::new(1 << 20, 0, 1 << 20, 1 << 20, 64),
            )
            .unwrap_err(),
    );
    assert_eq!(error.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(error.local_refusal().is_none());
    drop(error);
    decoder.prepare(&input, range, generous()).unwrap();
    drop(decoder.finish().unwrap());
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn qc_bitmap_capacity_refusal_retains_original_controls_and_retries_only_same_pool() {
    let frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 2);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let occupied = pool.reserved_bytes();
    pool.set_limit_bytes(occupied);
    let error = decoder.prepare(&input, range, generous()).unwrap_err();
    let QcCustodyError::Decode(PreparedDecodeError::Destination(QcFieldError::Bitmap(
        ChargedBufferError::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            ..
        }),
    ))) = error
    else {
        panic!("actual original bitmap pool must refuse")
    };
    assert_eq!(requested_bytes, 4);
    assert_eq!(reserved_bytes, occupied);
    assert_eq!(pool.reserved_bytes(), occupied);
    let foreign = AllocationBudget::new(1 << 20);
    drop(foreign.try_reserve_bytes(4).unwrap());
    assert!(decoder.prepare(&input, range, generous()).is_err());
    pool.set_limit_bytes(occupied + 4);
    decoder.prepare(&input, range, generous()).unwrap();
    let owner = decoder.finish().unwrap();
    assert_eq!(pool.reserved_bytes(), occupied + 4);
    drop(owner);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn qc_late_canonical_trailer_failure_retains_same_bitmap_allocation_and_never_publishes() {
    let mut frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let header = norito::core::Header::read(frame.as_slice()).unwrap();
    let offset = frame.len() - usize::try_from(header.length).unwrap();
    frame.push(0);
    frame[23..31].copy_from_slice(&(header.length + 1).to_le_bytes());
    let checksum = norito::core::crc64_fallback(&frame[offset..]);
    frame[31..39].copy_from_slice(&checksum.to_le_bytes());
    let ordinary = norito::decode_canonical::<Qc>(&frame).unwrap_err();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 1);
    let floor = pool.reserved_bytes();
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let first = cause(decoder.prepare(&input, range, generous()).unwrap_err());
    assert_eq!(first.error().to_string(), ordinary.to_string());
    assert!(decoder.fields.bitmap.initialized);
    let pointer = decoder.fields.payload.signers.as_bytes().as_ptr();
    let occupied = pool.reserved_bytes();
    assert!(occupied > floor + 4);
    pool.set_limit_bytes(occupied);
    let second = cause(decoder.prepare(&input, range, generous()).unwrap_err());
    assert_eq!(first.error().to_string(), second.error().to_string());
    assert_eq!(decoder.fields.payload.signers.as_bytes().as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), occupied);
    drop(first);
    drop(second);
    let (decoder, error) = decoder.finish().unwrap_err();
    assert!(matches!(error, QcCustodyError::Incomplete));
    drop(decoder);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn qc_closed_vote_kind_uses_original_invalid_tag_before_bitmap_or_publication() {
    let mut frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let header = norito::core::Header::read(frame.as_slice()).unwrap();
    let offset = frame.len() - usize::try_from(header.length).unwrap();
    let (kind_len, prefix_len) = norito::core::read_len_dyn_slice(&frame[offset..]).unwrap();
    assert_eq!(kind_len, 4);
    frame[offset + prefix_len..offset + prefix_len + kind_len]
        .copy_from_slice(&2_u32.to_le_bytes());
    let checksum = norito::core::crc64_fallback(&frame[offset..]);
    frame[31..39].copy_from_slice(&checksum.to_le_bytes());
    let ordinary = norito::decode_canonical::<Qc>(&frame).unwrap_err();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 1);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let occupied = pool.reserved_bytes();
    let error = cause(decoder.prepare(&input, range, generous()).unwrap_err());
    assert_eq!(error.kind(), DecodeAttemptErrorKind::Invalid);
    assert_eq!(error.error().to_string(), ordinary.to_string());
    assert!(!decoder.fields.bitmap.initialized);
    assert!(decoder.fields.bitmap.pending_charge.is_none());
    assert_eq!(pool.reserved_bytes(), occupied);
    drop(error);
    let (decoder, error) = decoder.finish().unwrap_err();
    assert!(matches!(error, QcCustodyError::Incomplete));
    drop(decoder);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

// This private probe exercises the nested QC kernel in a real seven-field TC
// frame. Empty TC entries require no child graph. It is not a funded TC owner,
// quorum verifier or production path; complete nonempty TC custody remains open.
struct TcReplayProbe {
    payload: crate::message::TimeoutCert,
    ledger: ChargedBuffer<AllocationCharge>,
    bitmap: QcBitmapAllocation,
    pool: AllocationBudget,
}
impl norito::core::FieldDestination for TcReplayProbe {
    type Error = QcFieldError;
}
macro_rules! tc_inline {
    ($index:literal, $ty:ty, $slot:ident) => {
        impl DecodeField<$index, $ty> for TcReplayProbe {
            type Value = ();
            fn decode_field(
                &mut self,
                value: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<QcFieldError>> {
                self.payload.$slot = inline::read_field(value).map_err(|error| match error {
                    DecodeIntoError::Codec(error) => DecodeIntoError::Codec(error),
                    DecodeIntoError::Destination(never) => match never {},
                })?;
                Ok(())
            }
        }
    };
}
tc_inline!(0, Hash32, instance);
tc_inline!(1, EpochId, epoch);
tc_inline!(2, u64, height);
tc_inline!(3, u64, view);
tc_inline!(5, AggregateSignature, agg_sig);
impl DecodeField<4, Vec<crate::message::TcEntry>> for TcReplayProbe {
    type Value = ();
    fn decode_field(
        &mut self,
        value: CanonicalField<'_, Vec<crate::message::TcEntry>>,
    ) -> Result<(), DecodeIntoError<QcFieldError>> {
        value.with_payload(|bytes| {
            let (entries, used) = norito::core::decode_element_sequence_from_slice_serial::<
                crate::message::TcEntry,
            >(bytes)?;
            assert!(
                entries.is_empty(),
                "the nested-kernel probe has no TC entry allocation"
            );
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.payload.entries = entries;
            Ok(())
        })
    }
}
impl DecodeField<6, Option<Qc>> for TcReplayProbe {
    type Value = ();
    fn decode_field(
        &mut self,
        value: CanonicalField<'_, Option<Qc>>,
    ) -> Result<(), DecodeIntoError<QcFieldError>> {
        let visited = value.decode_optional(|field| {
            // Keep the actual parent field and its original inline custody state
            // through later outer failure. No temporary standalone Qc is decoded.
            let slot = self.payload.high_pqc.get_or_insert_with(empty_qc);
            field.with_payload(|bytes| {
                decode_qc_payload(slot, &mut self.ledger, &mut self.bitmap, &self.pool, bytes)
            })
        })?;
        assert!(
            visited.is_some(),
            "the real TC probe contains an original QC field"
        );
        Ok(())
    }
}
impl SerializePayload for TcReplayProbe {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.payload.serialize(writer)
    }
}
impl PreparedRecordDestination<crate::message::TimeoutCert> for TcReplayProbe {
    fn reset(&mut self) {}
}
#[test]
fn real_tc_outer_frame_retains_nested_qc_parent_slot_after_late_refusal_and_exact_replay() {
    use crate::message::TimeoutCert;
    let original = TimeoutCert {
        instance: Hash32([27; 32]),
        epoch: EpochId {
            epoch: 29,
            context: Hash32([31; 32]),
        },
        height: 37,
        view: 41,
        entries: Vec::new(),
        agg_sig: AggregateSignature([43; crate::types::SIGNATURE_LEN]),
        high_pqc: Some(fixture(VoteKind::Prepare, 4)),
    };
    let canonical = norito::encode_canonical(&original).unwrap();
    assert_eq!(
        norito::decode_canonical::<TimeoutCert>(&canonical).unwrap(),
        original
    );
    for late_trailer in [false, true] {
        let mut frame = canonical.clone();
        if late_trailer {
            let header = norito::core::Header::read(frame.as_slice()).unwrap();
            let offset = frame.len() - usize::try_from(header.length).unwrap();
            frame.push(0);
            frame[23..31].copy_from_slice(&(header.length + 1).to_le_bytes());
            let checksum = norito::core::crc64_fallback(&frame[offset..]);
            frame[31..39].copy_from_slice(&checksum.to_le_bytes());
        }
        let pool = AllocationBudget::new(1 << 20);
        let (input, range) = source(&frame, &pool, 1);
        let floor = pool.reserved_bytes();
        let ledger = ChargedBuffer::new(1, &pool).unwrap();
        let mut reservation = pool
            .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
            .unwrap();
        let mut workspace =
            PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
        assert_eq!(reservation.remaining_bytes(), 0);
        let mut probe = TcReplayProbe {
            payload: TimeoutCert {
                instance: Hash32::ZERO,
                epoch: EpochId {
                    epoch: 0,
                    context: Hash32::ZERO,
                },
                height: 0,
                view: 0,
                entries: Vec::new(),
                agg_sig: AggregateSignature([0; crate::types::SIGNATURE_LEN]),
                high_pqc: None,
            },
            ledger,
            bitmap: QcBitmapAllocation::default(),
            pool: pool.clone(),
        };
        let controls = pool.reserved_bytes();
        let first = workspace.decode_canonical_into::<TimeoutCert, _>(
            range.get(input.as_slice()).unwrap(),
            generous(),
            &mut probe,
        );
        assert_eq!(&probe.payload, &original);
        assert!(probe.bitmap.initialized);
        assert_eq!(probe.ledger.as_slice().len(), 1);
        let ptr = probe
            .payload
            .high_pqc
            .as_ref()
            .unwrap()
            .signers
            .as_bytes()
            .as_ptr();
        assert_eq!(pool.reserved_bytes(), controls + 4);
        pool.set_limit_bytes(controls + 4);
        if late_trailer {
            let PreparedDecodeError::Codec(first) = first.unwrap_err() else {
                panic!("original outer codec cause");
            };
            let ordinary = norito::decode_canonical::<TimeoutCert>(&frame).unwrap_err();
            assert_eq!(first.error().to_string(), ordinary.to_string());
            let PreparedDecodeError::Codec(second) = workspace
                .decode_canonical_into::<TimeoutCert, _>(
                    range.get(input.as_slice()).unwrap(),
                    generous(),
                    &mut probe,
                )
                .unwrap_err()
            else {
                panic!("same original outer cause");
            };
            assert_eq!(first.error().to_string(), second.error().to_string());
            drop(first);
            drop(second);
        } else {
            first.unwrap();
            workspace
                .decode_canonical_into::<TimeoutCert, _>(
                    range.get(input.as_slice()).unwrap(),
                    generous(),
                    &mut probe,
                )
                .unwrap();
            assert_eq!(norito::encode_canonical(&probe.payload).unwrap(), canonical);
        }
        assert_eq!(
            probe
                .payload
                .high_pqc
                .as_ref()
                .unwrap()
                .signers
                .as_bytes()
                .as_ptr(),
            ptr
        );
        assert_eq!(probe.ledger.as_slice().len(), 1);
        assert_eq!(pool.reserved_bytes(), controls + 4);
        drop(probe);
        drop(workspace);
        drop(reservation);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(input);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn qc_raw_bitmap_leaf_preserves_original_storage_refusal_before_trailing_byte_error() {
    let mut frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let header = norito::core::Header::read(frame.as_slice()).unwrap();
    let offset = frame.len() - usize::try_from(header.length).unwrap();
    let payload = &frame[offset..];
    let mut position = 0;
    for _ in 0..7 {
        let (length, prefix) = norito::core::read_len_dyn_slice(&payload[position..]).unwrap();
        position += prefix + length;
    }
    let (bitmap_length, bitmap_prefix) =
        norito::core::read_len_dyn_slice(&payload[position..]).unwrap();
    let bitmap_start = position + bitmap_prefix;
    let bitmap = &payload[bitmap_start..bitmap_start + bitmap_length];
    let (raw_length, raw_prefix) = norito::core::read_len_dyn_slice(bitmap).unwrap();
    assert_eq!(raw_prefix + raw_length, bitmap.len());
    let mut raw = bitmap[raw_prefix..].to_vec();
    raw.push(0);
    let mut replacement = Vec::new();
    norito::core::write_len_to_vec_with_flags(
        &mut replacement,
        u64::try_from(raw.len()).unwrap(),
        header.flags,
    );
    replacement.extend_from_slice(&raw);
    let mut changed = payload[..position].to_vec();
    norito::core::write_len_to_vec_with_flags(
        &mut changed,
        u64::try_from(replacement.len()).unwrap(),
        header.flags,
    );
    changed.extend_from_slice(&replacement);
    changed.extend_from_slice(&payload[bitmap_start + bitmap_length..]);
    frame.truncate(offset);
    frame.extend_from_slice(&changed);
    frame[23..31].copy_from_slice(&u64::try_from(changed.len()).unwrap().to_le_bytes());
    let checksum = norito::core::crc64_fallback(&changed);
    frame[31..39].copy_from_slice(&checksum.to_le_bytes());
    let ordinary = norito::decode_canonical::<Qc>(&frame).unwrap_err();
    let tight = DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 4, 64);
    // Compare the original owning raw Vec leaf relation. Ordinary full-QC
    // archived alignment copies are separate removed heap work, not this leaf.
    let original_leaf = norito::core::with_decode_limits(tight, || {
        let (_, used) = Vec::<u8>::decode_from_slice(&raw)?;
        if used != raw.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(
        original_leaf.decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: 8,
            limit: 4
        })
    ));
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 0);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let controls = pool.reserved_bytes();
    let caller = DecodeBudgetContext::try_new_owned(tight, &pool).unwrap();
    let original = cause(
        caller
            .with(|| decoder.prepare(&input, range, generous()))
            .unwrap_err(),
    );
    assert_eq!(original.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        original.error().decode_resource_error(),
        original_leaf.decode_resource_error()
    );
    assert!(!decoder.fields.bitmap.initialized);
    assert!(decoder.fields.bitmap.pending_charge.is_none());
    drop(caller);
    drop(original);
    assert_eq!(pool.reserved_bytes(), controls);
    let invalid = cause(decoder.prepare(&input, range, generous()).unwrap_err());
    assert_eq!(invalid.kind(), DecodeAttemptErrorKind::Invalid);
    assert_eq!(invalid.error().to_string(), ordinary.to_string());
    assert!(decoder.fields.bitmap.initialized);
    assert_eq!(pool.reserved_bytes(), controls + 4);
    let pointer = decoder.fields.payload.signers.as_bytes().as_ptr();
    pool.set_limit_bytes(controls + 4);
    let replay = cause(decoder.prepare(&input, range, generous()).unwrap_err());
    assert_eq!(replay.error().to_string(), invalid.error().to_string());
    assert_eq!(decoder.fields.payload.signers.as_bytes().as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), controls + 4);
    drop(invalid);
    drop(replay);
    drop(decoder);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn qc_error_chain_borrows_original_enclosing_counter_cause_through_scope_retirement() {
    use std::error::Error as _;
    let frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 0);
    let floor = pool.reserved_bytes();
    let caller = DecodeBudgetContext::try_new_owned(
        DecodeLimits::new(1 << 20, 0, 1 << 20, 1 << 20, 64),
        &pool,
    )
    .unwrap();
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let error = caller
        .with(|| decoder.prepare(&input, range, generous()))
        .unwrap_err();
    let QcCustodyError::Decode(original) = &error else {
        panic!("actual original decoder cause");
    };
    let linked = error
        .source()
        .unwrap()
        .downcast_ref::<PreparedDecodeError<QcFieldError>>()
        .unwrap();
    assert!(std::ptr::eq(linked, original));
    let PreparedDecodeError::Codec(captured) = linked else {
        panic!("original scope cause");
    };
    assert_eq!(captured.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert!(captured.local_refusal().is_some());
    let descriptor = captured.error().decode_resource_error();
    drop(caller);
    let linked_after = error
        .source()
        .unwrap()
        .downcast_ref::<PreparedDecodeError<QcFieldError>>()
        .unwrap();
    assert!(std::ptr::eq(linked_after, original));
    let PreparedDecodeError::Codec(captured_after) = linked_after else {
        unreachable!()
    };
    assert!(std::ptr::eq(captured_after, captured));
    assert_eq!(captured_after.error().decode_resource_error(), descriptor);
    decoder.prepare(&input, range, generous()).unwrap();
    drop(decoder.finish().unwrap());
    assert!(
        pool.reserved_bytes() > floor,
        "the original captured counter owner still has a reader"
    );
    drop(error);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn qc_error_chain_retains_exact_original_bitmap_pool_refusal_without_projection() {
    use std::error::Error as _;
    let frame = norito::encode_canonical(&fixture(VoteKind::Commit, 4)).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 0);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let occupied = pool.reserved_bytes();
    pool.set_limit_bytes(occupied);
    let error = decoder.prepare(&input, range, generous()).unwrap_err();
    let QcCustodyError::Decode(original) = &error else {
        panic!("original prepared destination refusal");
    };
    let linked = error
        .source()
        .unwrap()
        .downcast_ref::<PreparedDecodeError<QcFieldError>>()
        .unwrap();
    assert!(std::ptr::eq(linked, original));
    let PreparedDecodeError::Destination(original_field) = linked else {
        panic!("actual bitmap backing refusal");
    };
    let field = linked
        .source()
        .unwrap()
        .downcast_ref::<QcFieldError>()
        .unwrap();
    assert!(std::ptr::eq(field, original_field));
    let QcFieldError::Bitmap(original_buffer) = field else {
        panic!("original pool admission");
    };
    let buffer = field
        .source()
        .unwrap()
        .downcast_ref::<ChargedBufferError>()
        .unwrap();
    assert!(std::ptr::eq(buffer, original_buffer));
    let ChargedBufferError::Admission(original_refusal) = buffer else {
        panic!("same pool refused exact bytes");
    };
    let refusal = buffer
        .source()
        .unwrap()
        .downcast_ref::<AllocationRefusal>()
        .unwrap();
    assert!(std::ptr::eq(refusal, original_refusal));
    assert!(
        matches!(refusal,AllocationRefusal::Capacity{requested_bytes:4,reserved_bytes,..} if *reserved_bytes==occupied)
    );
    assert_eq!(pool.reserved_bytes(), occupied);
    let foreign = AllocationBudget::new(1 << 20);
    drop(foreign.try_reserve_bytes(4).unwrap());
    assert!(decoder.prepare(&input, range, generous()).is_err());
    assert_eq!(pool.reserved_bytes(), occupied);
    pool.set_limit_bytes(occupied + 4);
    decoder.prepare(&input, range, generous()).unwrap();
    let owner = decoder.finish().unwrap();
    assert!(owner.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), occupied + 4);
    assert!(std::ptr::eq(
        buffer
            .source()
            .unwrap()
            .downcast_ref::<AllocationRefusal>()
            .unwrap(),
        original_refusal
    ));
    drop(error);
    drop(owner);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn qc_terminal_geometry_source_retention_and_layout_errors_stay_typed_without_retry_owner() {
    use std::error::Error as _;
    assert!(QcCustodyError::Source.source().is_none());
    assert!(QcCustodyError::Incomplete.source().is_none());
    assert!(QcFieldError::Geometry.source().is_none());
    let error = QcCustodyError::Retention(RetainedPayloadError::ForeignLedger);
    let QcCustodyError::Retention(original) = &error else {
        unreachable!()
    };
    let source = error
        .source()
        .unwrap()
        .downcast_ref::<RetainedPayloadError>()
        .unwrap();
    assert!(std::ptr::eq(source, original));
    assert!(source.source().is_none());
    let layout = iroha_allocation::ChargedBufferFromChargeError::LayoutMismatch {
        expected: Layout::array::<u8>(4).unwrap(),
        actual: Layout::array::<u8>(3).unwrap(),
    };
    let error = QcFieldError::BitmapBacking(layout);
    let QcFieldError::BitmapBacking(original) = &error else {
        unreachable!()
    };
    let source = error
        .source()
        .unwrap()
        .downcast_ref::<iroha_allocation::ChargedBufferFromChargeError>()
        .unwrap();
    assert!(std::ptr::eq(source, original));
    assert!(matches!(
        source,
        iroha_allocation::ChargedBufferFromChargeError::LayoutMismatch { .. }
    ));
    assert!(source.source().is_none());
    assert!(!error.source().unwrap().is::<AllocationRefusal>());
}

fn shared_source(
    bytes: &[u8],
    pool: &AllocationBudget,
    prefix: usize,
) -> (ChargedShared<ChargedBuffer<u8>>, SequenceSpan) {
    let (input, range) = source(bytes, pool, prefix);
    let mut credit = pool
        .try_reserve_layouts([ChargedShared::<ChargedBuffer<u8>>::allocation_layout()])
        .unwrap();
    let owner = ChargedShared::from_reservation(input, &mut credit)
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    (owner, range)
}

#[test]
fn shared_qc_retains_original_source_partial_fields_and_fixed_pool_retry() {
    let value = fixture(VoteKind::Commit, 4);
    let frame = norito::encode_canonical(&value).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (source, range) = shared_source(&frame, &pool, 7);
    let pointer = source.as_slice().as_ptr();
    let bytes = pool.reserved_bytes();
    let mut pending: PreparedQc<'static> =
        PreparedQc::new_shared(source.clone(), range, &pool).unwrap();
    let occupied = pool.reserved_bytes();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - occupied - 3)
        .unwrap();
    let first = pending
        .prepare_shared(&source, range, generous())
        .unwrap_err();
    let QcCustodyError::Decode(PreparedDecodeError::Destination(QcFieldError::Bitmap(
        ChargedBufferError::Admission(first),
    ))) = first
    else {
        panic!("actual original shared QC bitmap Capacity refusal")
    };
    assert!(
        matches!(&first, AllocationRefusal::Capacity { requested_bytes: 4, reserved_bytes, limit_bytes, .. }
        if *reserved_bytes == pool.limit_bytes() - 3 && *limit_bytes == 1 << 20)
    );
    let QcCustodyError::Decode(PreparedDecodeError::Destination(QcFieldError::Bitmap(
        ChargedBufferError::Admission(repeated),
    ))) = pending
        .prepare_shared(&source, range, generous())
        .unwrap_err()
    else {
        panic!("original repeated Capacity")
    };
    assert_eq!(first, repeated);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(pending.fields.payload.block_hash, value.block_hash);
    assert_eq!(pool.reserved_bytes(), occupied + blocker.remaining_bytes());
    drop(blocker);
    pending.prepare_shared(&source, range, generous()).unwrap();
    let bitmap = pending.fields.payload.signers.as_bytes().as_ptr();
    let owner = pending.finish().unwrap();
    let clone = owner.clone();
    assert!(NativeQc::ptr_eq(&owner, &clone));
    drop(source);
    drop(owner);
    assert_eq!(clone.source_bytes(), frame);
    assert_eq!(clone.get(), &value);
    assert_eq!(clone.get().signers.as_bytes().as_ptr(), bitmap);
    assert!(clone.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), occupied + 4);
    assert!(occupied > bytes);
    drop(clone);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(pool.limit_bytes(), 1 << 20);
}

#[test]
fn shared_qc_refuses_same_wire_replacement_and_different_source_span() {
    let frame = norito::encode_canonical(&fixture(VoteKind::Prepare, 4)).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (source, range) = shared_source(&frame, &pool, 7);
    let (replacement, _) = shared_source(&frame, &pool, 7);
    let mut pending = PreparedQc::new_shared(source.clone(), range, &pool).unwrap();
    let occupied = pool.reserved_bytes();
    assert!(
        matches!(
            pending.prepare_shared(&replacement, range, generous()),
            Err(QcCustodyError::Source)
        ),
        "shared QC retry must retain the exact original immutable source control"
    );
    assert!(matches!(
        pending.prepare_shared(
            &source,
            SequenceSpan {
                start: 0,
                end: range.end
            },
            generous()
        ),
        Err(QcCustodyError::Source)
    ));
    assert_eq!(pool.reserved_bytes(), occupied);
    pending.prepare_shared(&source, range, generous()).unwrap();
    drop(pending.finish().unwrap());
    drop(source);
    drop(replacement);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn shared_qc_requires_leaf_and_control_to_share_the_exact_original_pool() {
    let frame = norito::encode_canonical(&fixture(VoteKind::Commit, 4)).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let other = AllocationBudget::new(1 << 20);
    let (input, range) = source(&frame, &pool, 0);
    let mut credit = other
        .try_reserve_layouts([ChargedShared::<ChargedBuffer<u8>>::allocation_layout()])
        .unwrap();
    let shared = ChargedShared::from_reservation(input, &mut credit)
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    let original_bytes = pool.reserved_bytes();
    let original_control = other.reserved_bytes();
    assert!(
        matches!(
            PreparedQc::new_shared(shared.clone(), range, &pool),
            Err(QcCustodyError::Source)
        ),
        "shared QC source control must belong to the original byte pool"
    );
    assert!(matches!(
        PreparedQc::new_shared(shared.clone(), range, &other),
        Err(QcCustodyError::Source)
    ));
    assert_eq!(pool.reserved_bytes(), original_bytes);
    assert_eq!(other.reserved_bytes(), original_control);
    drop(shared);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(other.reserved_bytes(), 0);
}
