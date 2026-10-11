//! One derived field walk, exact canonical byte parity and original destination refusal.

use iroha_allocation::{AllocationBudget, AllocationRefusal};
use norito::core::{
    CanonicalField, DecodeField, DecodeFlagsGuard, DecodeFromSlice, DecodeIntoError, DecodeLimits,
    DecodeRecordFields, FieldDestination, OwnedFields, PreparedDecodeWorkspace, SerializePayload,
    header_flags,
};
use norito::{DeserializePayload, NoritoSchema, NoritoSerialize};

#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "prepared.Record")]
#[norito(decode_fields)]
struct Record {
    tag: u8,
    fixed: [u8; 4],
    bytes: Vec<u8>,
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "prepared.Record")]
struct ReferenceRecord {
    tag: u8,
    fixed: [u8; 4],
    bytes: Vec<u8>,
}
#[derive(NoritoSerialize)]
struct Filled<'a> {
    tag: u8,
    fixed: [u8; 4],
    bytes: &'a [u8],
}
#[derive(Debug)]
enum DestinationError {
    Allocation(AllocationRefusal),
    Storage { available: usize, required: usize },
}
struct Destination {
    tag: Option<u8>,
    fixed: Option<[u8; 4]>,
    bytes: [u8; 16],
    length: Option<usize>,
    refusal: Option<AllocationRefusal>,
}
impl Destination {
    fn new() -> Self {
        Self {
            tag: None,
            fixed: None,
            bytes: [0; 16],
            length: None,
            refusal: None,
        }
    }
    fn reset(&mut self) {
        self.tag = None;
        self.fixed = None;
        self.length = None;
    }
    fn filled(&self) -> Filled<'_> {
        Filled {
            tag: self.tag.unwrap(),
            fixed: self.fixed.unwrap(),
            bytes: &self.bytes[..self.length.unwrap()],
        }
    }
}
impl FieldDestination for Destination {
    type Error = DestinationError;
}
impl DecodeField<0, u8> for Destination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u8>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let value = field.with_payload(|bytes| {
            let (value, used) = u8::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(value)
        })?;
        self.tag = Some(value);
        Ok(())
    }
}
impl DecodeField<1, [u8; 4]> for Destination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, [u8; 4]>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        if let Some(original) = self.refusal.take() {
            return Err(DecodeIntoError::Destination(DestinationError::Allocation(
                original,
            )));
        }
        self.fixed = Some(field.decode_owned()?);
        Ok(())
    }
}
impl DecodeField<2, Vec<u8>> for Destination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Vec<u8>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (length, used) =
                norito::core::decode_raw_byte_sequence_into(bytes, &mut self.bytes).map_err(
                    |error| match error {
                        norito::core::SequenceDestinationError::Codec(error) => {
                            DecodeIntoError::Codec(error)
                        }
                        norito::core::SequenceDestinationError::Storage {
                            available,
                            required,
                        } => DecodeIntoError::Destination(DestinationError::Storage {
                            available,
                            required,
                        }),
                    },
                )?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.length = Some(length);
            Ok(())
        })
    }
}
fn fixture() -> Record {
    Record {
        tag: 9,
        fixed: [4, 3, 2, 1],
        bytes: vec![7, 8, 9, 10, 11],
    }
}
fn bare(value: &dyn SerializePayload, flags: u8) -> Vec<u8> {
    super::bare_bytes(value, flags)
}
fn codec(error: DecodeIntoError<DestinationError>) -> norito::Error {
    match error {
        DecodeIntoError::Codec(error) => error,
        other => panic!("unexpected custody refusal: {other:?}"),
    }
}

#[test]
fn generated_destination_and_owned_walk_keep_exact_record_bytes_and_rejection_order() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let record = fixture();
        let reference = ReferenceRecord {
            tag: record.tag,
            fixed: record.fixed,
            bytes: record.bytes.clone(),
        };
        let bytes = bare(&record, flags);
        assert_eq!(bytes, bare(&reference, flags));
        let (owned, used) = norito::core::decode_field_canonical::<Record>(&bytes).unwrap();
        let (prior, prior_used) =
            norito::core::decode_field_canonical::<ReferenceRecord>(&bytes).unwrap();
        assert_eq!(owned, record);
        assert_eq!((used, prior_used), (bytes.len(), bytes.len()));
        assert_eq!(prior, reference);
        let mut destination = Destination::new();
        let (_, used) = Record::decode_fields(&bytes, &mut destination).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(bare(&destination.filled(), flags), bytes);
        for end in 0..bytes.len() {
            let prior =
                norito::core::decode_field_canonical::<ReferenceRecord>(&bytes[..end]).unwrap_err();
            let owned = Record::decode_fields(&bytes[..end], &mut OwnedFields)
                .unwrap_err()
                .into_codec();
            destination.reset();
            let prepared =
                codec(Record::decode_fields(&bytes[..end], &mut destination).unwrap_err());
            assert_eq!(
                prior.to_string(),
                owned.to_string(),
                "owned truncation {end}, flags {flags}"
            );
            assert_eq!(
                prior.to_string(),
                prepared.to_string(),
                "prepared truncation {end}, flags {flags}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Record::decode_fields(&trailing, &mut destination).is_err());
    }
}

#[test]
fn generated_walk_preserves_original_destination_cause_and_exact_retry_order() {
    let pool = AllocationBudget::new(1);
    let held = pool.try_reserve_bytes(1).unwrap();
    let original = pool.try_reserve_bytes(1).unwrap_err();
    let mut destination = Destination::new();
    destination.refusal = Some(original.clone());
    let bytes = bare(&fixture(), header_flags::COMPACT_LEN);
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let error = Record::decode_fields(&bytes, &mut destination).unwrap_err();
    assert!(
        matches!(error,DecodeIntoError::Destination(DestinationError::Allocation(source)) if source==original)
    );
    assert_eq!(destination.tag, Some(9));
    assert!(destination.fixed.is_none());
    assert!(destination.length.is_none());
    let pointer = destination.bytes.as_ptr();
    drop(held);
    destination.reset();
    Record::decode_fields(&bytes, &mut destination).unwrap();
    assert_eq!(destination.bytes.as_ptr(), pointer);
    assert_eq!(
        bare(&destination.filled(), header_flags::COMPACT_LEN),
        bytes
    );
}

#[test]
fn generated_prepared_walk_uses_no_heap_or_alignment_copy_after_scope_admission() {
    let pool = AllocationBudget::new(4096);
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    let mut destination = Destination::new();
    let bytes = bare(&fixture(), header_flags::COMPACT_LEN);
    let limit = DecodeLimits::new(1024, 1024, 1024, 4096, 32);
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    pool.set_limit_bytes(0);
    // No first-decode warm-up: prepared field entry never installs the owned
    // archived decoder's panic hook or makes a temporary aligned frame.
    let allocations = super::allocations_during(|| {
        for _ in 0..8 {
            destination.reset();
            workspace
                .with_limits(limit, limit, || {
                    Record::decode_fields(&bytes, &mut destination)
                })
                .unwrap()
                .unwrap();
        }
    });
    assert_eq!(allocations, 0);
    assert_eq!(
        bare(&destination.filled(), header_flags::COMPACT_LEN),
        bytes
    );
}

impl SerializePayload for Destination {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.filled().serialize(encoder)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.filled().encoded_len_exact()
    }
}
impl norito::core::PreparedRecordDestination<Record> for Destination {
    fn reset(&mut self) {
        Destination::reset(self);
    }
}
fn decode_prepared(
    workspace: &mut PreparedDecodeWorkspace,
    bytes: &[u8],
    destination: &mut Destination,
) -> Result<(), norito::core::PreparedDecodeError<DestinationError>> {
    workspace.decode_canonical_into::<Record, _>(
        bytes,
        norito::canonical_decode_limits(bytes.len()),
        destination,
    )
}

#[test]
fn prepared_canonical_entry_preserves_complete_header_payload_and_error_identity() {
    use norito::core::{DecodeAttemptErrorKind, Header, PreparedDecodeError};
    let pool = AllocationBudget::new(4096);
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    let mut destination = Destination::new();
    let frame = norito::encode_canonical(&fixture()).unwrap();
    let mut mutations = Vec::new();
    for end in 0..frame.len() {
        mutations.push(frame[..end].to_vec());
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    mutations.push(trailing);
    for field in 0..3 {
        let mut changed = frame.clone();
        // Mutate the wire directly: the canonical header writer must reject
        // invalid flags and is deliberately not a public fixture encoder.
        Header::read(std::io::Cursor::new(&changed)).unwrap();
        match field {
            0 => changed[6] ^= 1,
            1 => changed[Header::SIZE - 9] ^= 1,
            _ => changed[Header::SIZE - 1] = 0x80,
        }
        mutations.push(changed);
    }
    // A complete alternate advertised layout reaches the final canonical-byte
    // comparison. Prepared validity must still retire when the source is not
    // the single canonical writer's encoding.
    let alternate =
        norito::core::frame_bare_with_header_flags::<Record>(&bare(&fixture(), 0), 0).unwrap();
    assert_ne!(alternate, frame);
    mutations.push(alternate);
    for bytes in mutations {
        let ordinary = norito::decode_canonical_for_admission::<ReferenceRecord>(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap_err();
        let PreparedDecodeError::Codec(prepared) =
            decode_prepared(&mut workspace, &bytes, &mut destination).unwrap_err()
        else {
            panic!("exact canonical codec failure")
        };
        assert_eq!(ordinary.kind(), prepared.kind());
        assert_eq!(ordinary.to_string(), prepared.to_string());
        assert!(
            destination.tag.is_none()
                && destination.fixed.is_none()
                && destination.length.is_none()
        );
    }
    pool.set_limit_bytes(0);
    let allocations = super::allocations_during(|| {
        decode_prepared(&mut workspace, &frame, &mut destination).unwrap()
    });
    assert_eq!(
        allocations, 0,
        "full prepared frame decode/compare must not allocate"
    );
    assert_eq!(norito::encode_canonical(&fixture()).unwrap(), frame);
    // An intrinsic field limit remains invalid even inside a stricter enclosing scope.
    let too_small = DecodeLimits::new(0, 0, 0, 0, 0);
    let local = norito::core::with_decode_limits_scope(too_small, || {
        workspace.decode_canonical_into::<Record, _>(&frame, too_small, &mut destination)
    })
    .unwrap_err();
    assert!(
        matches!(local,PreparedDecodeError::Codec(error) if error.kind()==DecodeAttemptErrorKind::Invalid)
    );
    decode_prepared(&mut workspace, &frame, &mut destination).unwrap();
}

#[test]
fn prepared_frame_keeps_exact_owned_raw_storage_limit_and_local_bank_refusal() {
    use norito::core::{DecodeAttemptErrorKind, PreparedDecodeError};
    let record = fixture();
    let frame = norito::encode_canonical(&record).unwrap();
    let pool = AllocationBudget::new(4096);
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    let mut destination = Destination::new();
    let pointer = destination.bytes.as_ptr();
    let occupied = pool.reserved_bytes();
    // This fixture's raw-byte field begins at aligned payload offset eight,
    // so the owned path has no unrelated alignment-copy charge. The shared
    // framing kernel borrows each declared field payload. Vec retains its
    // existing sequence-planning charge and charges the owned backing separately.
    let count_charge = record.bytes.len();
    let retained_charge = record.bytes.len();
    let required = count_charge + retained_charge;
    for allowed in [
        0,
        count_charge - 1,
        count_charge,
        count_charge + 1,
        required - 2,
        required - 1,
    ] {
        decode_prepared(&mut workspace, &frame, &mut destination).unwrap();
        let limits = DecodeLimits::new(1024, 4096, 1024, allowed, 32);
        let ordinary = norito::core::with_decode_limits_scope(limits, || {
            norito::decode_canonical_for_admission::<ReferenceRecord>(
                &frame,
                norito::canonical_decode_limits(frame.len()),
            )
        })
        .unwrap_err();
        let PreparedDecodeError::Codec(prepared) =
            norito::core::with_decode_limits_scope(limits, || {
                decode_prepared(&mut workspace, &frame, &mut destination)
            })
            .unwrap_err()
        else {
            panic!("original raw-storage work ceiling must refuse")
        };
        assert_eq!(ordinary.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        assert_eq!(prepared.kind(), ordinary.kind());
        assert_eq!(prepared.to_string(), ordinary.to_string());
        assert_eq!(
            prepared.into_error().decode_resource_error(),
            ordinary.into_error().decode_resource_error()
        );
        assert!(
            destination.tag.is_none()
                && destination.fixed.is_none()
                && destination.length.is_none()
        );
        assert_eq!(destination.bytes.as_ptr(), pointer);
        assert_eq!(pool.reserved_bytes(), occupied);
    }
    let exact = DecodeLimits::new(1024, 4096, 1024, required, 32);
    let ordinary = norito::core::with_decode_limits_scope(exact, || {
        norito::decode_canonical_for_admission::<ReferenceRecord>(
            &frame,
            norito::canonical_decode_limits(frame.len()),
        )
    })
    .unwrap();
    norito::core::with_decode_limits_scope(exact, || {
        decode_prepared(&mut workspace, &frame, &mut destination)
    })
    .unwrap();
    assert_eq!(ordinary.bytes, record.bytes);
    assert_eq!(destination.filled().bytes, record.bytes);
    assert_eq!(destination.bytes.as_ptr(), pointer);
    let oversized = Record {
        bytes: vec![7; 17],
        ..record
    };
    let oversized_frame = norito::encode_canonical(&oversized).unwrap();
    assert!(matches!(
        decode_prepared(&mut workspace, &oversized_frame, &mut destination),
        Err(PreparedDecodeError::Destination(
            DestinationError::Storage {
                available: 16,
                required: 17
            }
        ))
    ));
    assert!(destination.length.is_none());
    assert_eq!(destination.bytes.as_ptr(), pointer);
    pool.set_limit_bytes(0);
    assert_eq!(
        super::allocations_during(
            || decode_prepared(&mut workspace, &frame, &mut destination).unwrap()
        ),
        0
    );
    assert_eq!(pool.reserved_bytes(), occupied);
    drop((workspace, destination, reservation));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[derive(
    Debug, PartialEq, norito::NoritoSerialize, norito::DeserializePayload, norito::NoritoSchema,
)]
#[norito_schema(name = "prepared.NestedRows")]
#[norito(decode_fields)]
struct NestedRows {
    rows: Vec<Row>,
}
#[derive(Debug, PartialEq, norito::NoritoSerialize, norito::DeserializePayload)]
#[norito(decode_fields)]
struct Row {
    scalar: u64,
    fixed: [u8; 4],
}
#[derive(Clone, Copy, Default)]
struct RowSlot {
    scalar: Option<u64>,
    fixed: Option<[u8; 4]>,
}
impl FieldDestination for RowSlot {
    type Error = norito::core::SequenceDestinationError;
}
impl DecodeField<0, u64> for RowSlot {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u64>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let value = field.with_payload(|bytes| {
            let (value, used) = u64::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(value)
        })?;
        self.scalar = Some(value);
        Ok(())
    }
}
impl DecodeField<1, [u8; 4]> for RowSlot {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, [u8; 4]>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.fixed = Some(field.decode_owned()?);
        Ok(())
    }
}
impl SerializePayload for RowSlot {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        let scalar = self.scalar.ok_or(norito::Error::InvalidValue {
            context: "unfinished prepared scalar",
        })?;
        let fixed = self.fixed.ok_or(norito::Error::InvalidValue {
            context: "unfinished prepared array",
        })?;
        Row { scalar, fixed }.serialize(writer)
    }
}
struct RowsDestination {
    slots: iroha_allocation::ChargedBuffer<RowSlot>,
    spans: iroha_allocation::ChargedBuffer<norito::core::SequenceSpan>,
    len: Option<usize>,
}
impl RowsDestination {
    fn new(pool: &AllocationBudget, count: usize) -> Self {
        let mut reservation = pool
            .try_reserve_layouts([
                std::alloc::Layout::array::<RowSlot>(count).unwrap(),
                std::alloc::Layout::array::<norito::core::SequenceSpan>(count).unwrap(),
            ])
            .unwrap();
        let mut slots =
            iroha_allocation::ChargedBuffer::from_reservation(count, &mut reservation).unwrap();
        let mut spans =
            iroha_allocation::ChargedBuffer::from_reservation(count, &mut reservation).unwrap();
        for _ in 0..count {
            slots.push_reserved(RowSlot::default());
            spans.push_reserved(norito::core::SequenceSpan {
                start: usize::MAX,
                end: usize::MAX,
            });
        }
        Self {
            slots,
            spans,
            len: None,
        }
    }
}
impl FieldDestination for RowsDestination {
    type Error = norito::core::SequenceDestinationError;
}
impl DecodeField<0, Vec<Row>> for RowsDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Vec<Row>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let plan = norito::core::prepare_element_sequence(bytes, self.spans.as_mut_slice())
                .map_err(|error| match error {
                    norito::core::SequenceDestinationError::Codec(error) => {
                        DecodeIntoError::Codec(error)
                    }
                    error => DecodeIntoError::Destination(error),
                })?;
            if plan.used() != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            plan.decode_elements::<Row, Self::Error>(|index, field| {
                field.with_payload(|bytes| {
                    let (_, used) =
                        Row::decode_fields(bytes, &mut self.slots.as_mut_slice()[index])?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(())
                })
            })?;
            self.len = Some(plan.len());
            Ok(())
        })
    }
}
struct FilledRowSequence<'a>(&'a [RowSlot]);
impl SerializePayload for FilledRowSequence<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<RowSlot, _>(writer, self.0.iter())
    }
}
impl SerializePayload for RowsDestination {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct FilledRows<'a> {
            rows: FilledRowSequence<'a>,
        }
        let count = self.len.ok_or(norito::Error::InvalidValue {
            context: "unfinished prepared rows",
        })?;
        FilledRows {
            rows: FilledRowSequence(&self.slots.as_slice()[..count]),
        }
        .serialize(writer)
    }
}
impl norito::core::PreparedRecordDestination<NestedRows> for RowsDestination {
    fn reset(&mut self) {
        self.len = None;
        for slot in self.slots.as_mut_slice() {
            *slot = RowSlot::default();
        }
    }
}

#[test]
fn prepared_nested_records_keep_exact_frames_at_all_alignments_without_replacing_backing() {
    for count in [4, 31, 961] {
        let rows = NestedRows {
            rows: (0..count)
                .map(|i| Row {
                    scalar: i as u64,
                    fixed: (i as u32).to_le_bytes(),
                })
                .collect(),
        };
        let frame = norito::encode_canonical(&rows).unwrap();
        let ordinary = norito::decode_canonical::<NestedRows>(&frame).unwrap();
        assert_eq!(ordinary, rows);
        let pool = AllocationBudget::new(1 << 20);
        let mut reservation = pool
            .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
            .unwrap();
        let mut workspace =
            PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
        let mut destination = RowsDestination::new(&pool, count);
        let slots = destination.slots.as_slice().as_ptr();
        let spans = destination.spans.as_slice().as_ptr();
        let occupied = pool.reserved_bytes();
        let held = pool
            .try_reserve_bytes(pool.limit_bytes() - occupied)
            .unwrap();
        for offset in 0..16 {
            let mut shifted = vec![0xa5; offset];
            shifted.extend_from_slice(&frame);
            let input = &shifted[offset..];
            let allocations = super::allocations_during(|| {
                workspace
                    .decode_canonical_into::<NestedRows, _>(
                        input,
                        norito::canonical_decode_limits(input.len()),
                        &mut destination,
                    )
                    .unwrap();
            });
            assert_eq!(allocations, 0, "count {count}, alignment offset {offset}");
            assert_eq!(destination.len, Some(count));
            assert_eq!(destination.slots.as_slice().as_ptr(), slots);
            assert_eq!(destination.spans.as_slice().as_ptr(), spans);
            for (actual, expected) in destination.slots.as_slice().iter().zip(&rows.rows) {
                assert_eq!(actual.scalar, Some(expected.scalar));
                assert_eq!(actual.fixed, Some(expected.fixed));
            }
        }
        drop(held);
        assert_eq!(pool.reserved_bytes(), occupied);
        drop((workspace, destination, reservation));
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn prepared_nested_late_scope_failure_keeps_both_original_banks_for_unchanged_retry() {
    let rows = NestedRows {
        rows: vec![
            Row {
                scalar: 1,
                fixed: [1; 4],
            },
            Row {
                scalar: 2,
                fixed: [2; 4],
            },
        ],
    };
    let frame = norito::encode_canonical(&rows).unwrap();
    let pool = AllocationBudget::new(4096);
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    let mut destination = RowsDestination::new(&pool, 2);
    let pointer = destination.slots.as_slice().as_ptr();
    let occupied = pool.reserved_bytes();
    // The complete source spans are admitted, then nominal DTO output storage
    // refuses before the first row. The outer scope has ended before classification.
    let limit = 2 + 2 * std::mem::size_of::<norito::core::SequenceSpan>();
    let error = norito::core::with_decode_limits_scope(
        DecodeLimits::new(1024, 4096, 1024, limit, 32),
        || {
            workspace.decode_canonical_into::<NestedRows, _>(
                &frame,
                norito::canonical_decode_limits(frame.len()),
                &mut destination,
            )
        },
    )
    .unwrap_err();
    assert!(
        matches!(error,norito::core::PreparedDecodeError::Codec(ref error) if error.kind()==norito::core::DecodeAttemptErrorKind::EnclosingLimit)
    );
    assert_eq!(pool.reserved_bytes(), occupied);
    assert!(destination.len.is_none());
    assert!(
        destination
            .slots
            .as_slice()
            .iter()
            .all(|slot| slot.scalar.is_none() && slot.fixed.is_none())
    );
    assert_eq!(destination.slots.as_slice().as_ptr(), pointer);
    workspace
        .decode_canonical_into::<NestedRows, _>(
            &frame,
            norito::canonical_decode_limits(frame.len()),
            &mut destination,
        )
        .unwrap();
    assert_eq!(destination.len, Some(2));
    assert_eq!(destination.slots.as_slice().as_ptr(), pointer);
    drop((error, workspace, destination, reservation));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "prepared.Tuple")]
struct TupleRecord(u32, u64, [u8; 4]);
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito(decode_from_slice)]
#[norito_schema(name = "prepared.Tuple")]
struct OriginalTuple(u32, u64, [u8; 4]);
struct TupleDestination {
    first: u32,
    second: u64,
    fixed: [u8; 4],
}
impl FieldDestination for TupleDestination {
    type Error = std::convert::Infallible;
}
impl DecodeField<0, u32> for TupleDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u32>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (value, used) = u32::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.first = value;
            Ok(())
        })
    }
}
impl DecodeField<1, u64> for TupleDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u64>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (value, used) = u64::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.second = value;
            Ok(())
        })
    }
}
impl DecodeField<2, [u8; 4]> for TupleDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, [u8; 4]>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.fixed = field.decode_owned()?;
        Ok(())
    }
}
impl SerializePayload for TupleDestination {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        TupleRecord(self.first, self.second, self.fixed).serialize(encoder)
    }
}
impl norito::core::PreparedRecordDestination<TupleRecord> for TupleDestination {
    fn reset(&mut self) {
        self.first = 0;
        self.second = 0;
        self.fixed = [0; 4];
    }
}
#[test]
fn closed_tuple_keeps_original_wire_error_and_slice_contract_with_zero_allocation_prepared_scalars()
{
    let pool = AllocationBudget::new(1 << 20);
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let mut work = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let value = TupleRecord(0x11223344, 0x1122334455667788, [3, 5, 7, 11]);
        let original = OriginalTuple(value.0, value.1, value.2);
        let bytes = super::bare_bytes(&value, flags);
        assert_eq!(bytes, super::bare_bytes(&original, flags));
        assert_eq!(
            norito::to_bytes(&value).unwrap(),
            norito::to_bytes(&original).unwrap()
        );
        let mut source = iroha_allocation::ChargedBuffer::new(bytes.len() + 1, &pool).unwrap();
        source.append(&[0xa5]).unwrap();
        source.append(&bytes).unwrap();
        let pointer = source.as_slice().as_ptr();
        let mut destination = TupleDestination {
            first: 0,
            second: 0,
            fixed: [0; 4],
        };
        let held = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        let mut used = None;
        let allocations = super::allocations_during(|| {
            used = Some(
                work.with_limits(tuple_limits(1 << 20), tuple_limits(1 << 20), || {
                    TupleRecord::decode_fields(&source.as_slice()[1..], &mut destination)
                })
                .unwrap()
                .unwrap()
                .1,
            );
        });
        assert_eq!(allocations, 0);
        assert_eq!(used, Some(bytes.len()));
        assert_eq!(
            (destination.first, destination.second, destination.fixed),
            (value.0, value.1, value.2)
        );
        assert_eq!(source.as_slice().as_ptr(), pointer);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        drop(held);
        for end in 0..bytes.len() {
            let ordinary = OriginalTuple::decode_from_slice(&bytes[..end]).unwrap_err();
            let updated = TupleRecord::decode_from_slice(&bytes[..end]).unwrap_err();
            assert_eq!(ordinary.to_string(), updated.to_string());
            assert!(TupleRecord::decode_fields(&bytes[..end], &mut destination).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(&[0xff, 0xee]);
        assert_eq!(
            OriginalTuple::decode_from_slice(&trailing)
                .unwrap_err()
                .to_string(),
            TupleRecord::decode_from_slice(&trailing)
                .unwrap_err()
                .to_string()
        );
        // The bare and ordinary cases above retain the selected ambient layout.
        // Canonical admission requires the sole canonical V1 encoder's flags.
        let frame = norito::encode_canonical(&value).unwrap();
        let held = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        let allocations = super::allocations_during(|| {
            work.decode_canonical_into::<TupleRecord, _>(
                &frame,
                tuple_limits(1 << 20),
                &mut destination,
            )
            .unwrap()
        });
        assert_eq!(allocations, 0);
        assert_eq!(
            (destination.first, destination.second, destination.fixed),
            (value.0, value.1, value.2)
        );
        drop(held);
    }
    drop(work);
    assert_eq!(pool.reserved_bytes(), 0);
}

fn tuple_limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(4096, 1 << 20, 1 << 20, bytes, 64)
}
