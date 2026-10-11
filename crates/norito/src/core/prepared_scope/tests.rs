//! Original prepared controls, limit precedence, attempt identity and unwind tests.

use super::*;

fn limit(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn prepared(pool: &AllocationBudget) -> PreparedDecodeWorkspace {
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    PreparedDecodeWorkspace::from_reservation(pool, &mut reservation).unwrap()
}
fn demand() -> usize {
    PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .map(Layout::size)
        .sum()
}

#[test]
fn aggregate_preparation_refuses_foreign_or_short_original_remainder_before_consumption() {
    let pool = AllocationBudget::new(demand());
    let foreign = AllocationBudget::new(demand());
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    assert!(matches!(
        PreparedDecodeWorkspace::from_reservation(&foreign, &mut reservation),
        Err(PreparedDecodeScopeError::ForeignPool)
    ));
    assert_eq!(reservation.remaining_bytes(), demand());
    let held = reservation.try_split(Layout::new::<u8>()).unwrap();
    assert!(
        matches!(PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation),
        Err(PreparedDecodeScopeError::Reservation(InsufficientReservation { requested_bytes, remaining_bytes })) if requested_bytes==demand() && remaining_bytes==demand()-1)
    );
    assert_eq!(reservation.remaining_bytes(), demand() - 1);
    drop((reservation, held));
    let workspace = prepared(&pool);
    assert!(workspace.belongs_to(&pool));
    assert!(!workspace.belongs_to(&foreign));
    assert_eq!(pool.reserved_bytes(), demand());
    drop(workspace);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prepared_scope_uses_original_enclosing_limits_and_retains_control_through_error_lifetime() {
    let pool = AllocationBudget::new(demand());
    let mut workspace = prepared(&pool);
    pool.set_limit_bytes(0);
    let error = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| {
            workspace
                .with_limits(limit(8), limit(8), || reserve_decode_allocation(1))
                .unwrap()
        })
    })
    .unwrap_err();
    assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        error.into_error().decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded {
            attempted: 1,
            limit: 0
        })
    );
    let error = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| {
            workspace
                .with_limits(limit(8), limit(8), || reserve_decode_allocation(1))
                .unwrap()
        })
    })
    .unwrap_err();
    drop(workspace);
    assert_eq!(
        pool.reserved_bytes(),
        PreparedDecodeWorkspace::allocation_layouts()[0].size()
    );
    assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    drop(error);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(!decode_limits_active());
}

#[test]
fn reused_workspace_cannot_launder_old_error_into_new_attempt_and_protocol_limits_win() {
    let pool = AllocationBudget::new(demand());
    let mut workspace = prepared(&pool);
    let original = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| {
            workspace
                .with_limits(limit(8), limit(8), || reserve_decode_allocation(1))
                .unwrap()
        })
    })
    .unwrap_err();
    let stale = original.into_error();
    let replayed = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| {
            workspace
                .with_limits(limit(8), limit(8), || Err::<(), _>(stale))
                .unwrap()
        })
    })
    .unwrap_err();
    assert_eq!(replayed.kind(), DecodeAttemptErrorKind::Invalid);
    let intrinsic = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| {
            workspace
                .with_limits(limit(0), limit(0), || reserve_decode_allocation(1))
                .unwrap()
        })
    })
    .unwrap_err();
    assert_eq!(intrinsic.kind(), DecodeAttemptErrorKind::Invalid);
    workspace
        .with_limits(limit(8), limit(8), || reserve_decode_allocation(8))
        .unwrap()
        .unwrap();
    drop((workspace, replayed, intrinsic));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn one_scope_chain_deduplicates_reapplied_context_and_restores_on_unwind() {
    let context = DecodeBudgetContext::new(limit(5));
    context
        .with(|| context.with(|| reserve_decode_allocation(3)))
        .unwrap();
    assert_eq!(
        context
            .layer
            .budget
            .counters
            .total_allocated_bytes
            .load(Ordering::Relaxed),
        3
    );
    assert!(!decode_limits_active());
    let pool = AllocationBudget::new(demand());
    let mut workspace = prepared(&pool);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.with(|| {
            workspace.with_limits(limit(8), limit(8), || {
                reserve_decode_allocation(2).unwrap();
                panic!("prepared scope interrupted");
            })
        })
    }));
    assert!(caught.is_err());
    assert!(!decode_limits_active());
    assert_eq!(DECODE_NESTING_DEPTH.with(Cell::get), 0);
    workspace
        .with_limits(limit(8), limit(8), || reserve_decode_allocation(8))
        .unwrap()
        .unwrap();
    workspace.attempt = u64::MAX;
    let mut called = false;
    assert!(matches!(
        workspace.with_limits(limit(8), limit(8), || called = true),
        Err(PreparedDecodeScopeError::AttemptExhausted)
    ));
    assert!(!called);
    assert!(!decode_limits_active());
    drop(workspace);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[derive(
    Debug, PartialEq, crate::NoritoSerialize, crate::NoritoDeserialize, crate::NoritoSchema,
)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "prepared.archive.root")]
struct ArchiveRecord {
    first: u64,
    fixed: [u8; 4],
}

// The oracle does not opt into prepared destinations. Its ordinary generated
// named slice decoder is the actual ArchiveView root contract.
#[derive(
    Debug, PartialEq, crate::NoritoSerialize, crate::NoritoDeserialize, crate::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(name = "prepared.archive.root")]
struct ArchiveOracle {
    first: u64,
    fixed: [u8; 4],
}

#[derive(Default)]
struct ArchiveDestination {
    first: Option<u64>,
    fixed: Option<[u8; 4]>,
    first_schema: Option<[u8; 16]>,
    first_flags: Option<u8>,
}
impl FieldDestination for ArchiveDestination {
    type Error = std::convert::Infallible;
}
impl DecodeField<0, u64> for ArchiveDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u64>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let state = payload_ctx_state().expect("actual generated record context");
        self.first_schema = state.schema;
        self.first_flags = Some(state.flags);
        let value = field.with_payload(|bytes| {
            let (value, used) = <u64 as DecodeFromSlice>::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(Error::LengthMismatch.into());
            }
            Ok(value)
        })?;
        self.first = Some(value);
        Ok(())
    }
}
impl DecodeField<1, [u8; 4]> for ArchiveDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, [u8; 4]>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.fixed = Some(field.decode_owned()?);
        Ok(())
    }
}
impl SerializePayload for ArchiveDestination {
    fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        ArchiveRecord {
            first: self.first.ok_or(Error::LengthMismatch)?,
            fixed: self.fixed.ok_or(Error::LengthMismatch)?,
        }
        .serialize(encoder)
    }
}
impl PreparedRecordDestination<ArchiveRecord> for ArchiveDestination {
    fn reset(&mut self) {
        self.first = None;
        self.fixed = None;
        self.first_schema = None;
        self.first_flags = None;
    }
}
fn archive_frame() -> Vec<u8> {
    crate::encode_canonical(&ArchiveRecord {
        first: 17,
        fixed: [2, 3, 5, 7],
    })
    .unwrap()
}
struct ArchiveRefusal {
    kind: DecodeAttemptErrorKind,
    error: Error,
}
fn archive_original(cause: DecodeAttemptError) -> ArchiveRefusal {
    let kind = cause.kind();
    ArchiveRefusal {
        kind,
        error: cause.into_error(),
    }
}
fn archive_cause(
    result: Result<(), PreparedDecodeError<std::convert::Infallible>>,
) -> ArchiveRefusal {
    match result {
        Err(PreparedDecodeError::Codec(cause)) => archive_original(cause),
        _ => panic!("the original archive-root codec must refuse before destination completion"),
    }
}

#[test]
fn prepared_archive_root_retains_first_field_refusal_instead_of_whole_record() {
    let frame = archive_frame();
    let source = frame.as_ptr();
    let hash = crc64(&frame);
    let pool = AllocationBudget::new(demand());
    let mut work = prepared(&pool);
    let derived = std::ptr::from_ref(&*work.derived);
    let explicit = std::ptr::from_ref(&*work.explicit);
    let mut destination = ArchiveDestination::default();
    let backing = std::ptr::from_ref(&destination);
    let narrow = DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, usize::MAX);
    let ordinary = archive_original(
        with_decode_limits_scope(narrow, || {
            classify_decode_attempt(|| from_bytes_view(&frame)?.decode::<ArchiveOracle>())
        })
        .unwrap_err(),
    );
    assert_eq!(ordinary.kind, DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        ordinary.error.decode_resource_error(),
        Some(DecodeResourceError::FieldLengthExceeded {
            length: 8,
            limit: 1
        })
    );
    let refused = archive_cause(with_decode_limits_scope(narrow, || {
        work.decode_canonical_archive_into::<ArchiveRecord, _>(
            &frame,
            limit(4096),
            &mut destination,
        )
    }));
    assert_eq!(refused.kind, ordinary.kind);
    assert_eq!(
        refused.error.decode_resource_error(),
        ordinary.error.decode_resource_error()
    );
    assert!(destination.first.is_none() && destination.fixed.is_none());
    assert_eq!(DECODE_NESTING_DEPTH.with(Cell::get), 0);
    assert_eq!(std::ptr::from_ref(&*work.derived), derived);
    assert_eq!(std::ptr::from_ref(&*work.explicit), explicit);
    assert_eq!(pool.reserved_bytes(), demand());
    // Retain both genuine old causes while the original workspace starts its
    // next nonrepeating attempt. It must not inherit their old refusal identity.
    work.decode_canonical_archive_into::<ArchiveRecord, _>(&frame, limit(4096), &mut destination)
        .unwrap();
    assert_eq!(destination.first, Some(17));
    assert_eq!(destination.fixed, Some([2, 3, 5, 7]));
    assert_eq!(
        destination.first_schema,
        Some(crate::schema::identity::frame_hash::<ArchiveRecord>())
    );
    assert_eq!(destination.first_flags, Some(default_encode_flags()));
    assert_eq!(std::ptr::from_ref(&destination), backing);
    assert_eq!(frame.as_ptr(), source);
    assert_eq!(crc64(&frame), hash);
    assert!(work.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), demand());
    drop((refused, ordinary, work));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prepared_archive_root_matches_original_zero_and_one_depth_without_extra_record_level() {
    let frame = archive_frame();
    let pool = AllocationBudget::new(demand());
    let mut work = prepared(&pool);
    let mut destination = ArchiveDestination::default();
    for depth in [0, 1] {
        let ceiling = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth);
        let original = with_decode_limits_scope(ceiling, || {
            classify_decode_attempt(|| from_bytes_view(&frame)?.decode::<ArchiveOracle>())
        });
        let filled = with_decode_limits_scope(ceiling, || {
            work.decode_canonical_archive_into::<ArchiveRecord, _>(
                &frame,
                limit(4096),
                &mut destination,
            )
        });
        if depth == 0 {
            let original = archive_original(original.unwrap_err());
            let filled = archive_cause(filled);
            assert_eq!(original.kind, DecodeAttemptErrorKind::EnclosingLimit);
            assert_eq!(
                original.error.decode_resource_error(),
                Some(DecodeResourceError::NestingDepthExceeded {
                    depth: 1,
                    limit: 0,
                    context: "decode budget"
                })
            );
            assert_eq!(filled.kind, original.kind);
            assert_eq!(
                filled.error.decode_resource_error(),
                original.error.decode_resource_error()
            );
            assert!(destination.first.is_none() && destination.fixed.is_none());
        } else {
            let original = original.unwrap();
            filled.unwrap();
            assert_eq!(destination.first, Some(original.first));
            assert_eq!(destination.fixed, Some(original.fixed));
        }
        assert_eq!(DECODE_NESTING_DEPTH.with(Cell::get), 0);
        assert_eq!(pool.reserved_bytes(), demand());
    }
    assert!(!decode_limits_active());
}

#[test]
fn prepared_canonical_field_entry_keeps_original_whole_record_limit_and_depth_order() {
    let frame = archive_frame();
    let pool = AllocationBudget::new(demand());
    let mut work = prepared(&pool);
    let mut destination = ArchiveDestination::default();
    for ceiling in [
        DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 0),
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
    ] {
        let original = archive_original(
            with_decode_limits_scope(ceiling, || {
                crate::decode_canonical_for_admission::<ArchiveOracle>(&frame, limit(4096))
            })
            .unwrap_err(),
        );
        let filled = archive_cause(with_decode_limits_scope(ceiling, || {
            work.decode_canonical_into::<ArchiveRecord, _>(&frame, limit(4096), &mut destination)
        }));
        assert_eq!(filled.kind, original.kind);
        assert_eq!(
            filled.error.decode_resource_error(),
            original.error.decode_resource_error()
        );
        assert!(destination.first.is_none() && destination.fixed.is_none());
        assert_eq!(DECODE_NESTING_DEPTH.with(Cell::get), 0);
    }
}

#[test]
fn prepared_archive_root_authenticates_complete_frame_before_field_refusal_and_keeps_exact_retry() {
    let frame = archive_frame();
    let pool = AllocationBudget::new(demand());
    let mut work = prepared(&pool);
    let mut destination = ArchiveDestination::default();
    let narrow = DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 0);
    let mut invalid = frame.clone();
    *invalid.last_mut().unwrap() ^= 1;
    let ordinary = archive_original(
        with_decode_limits_scope(narrow, || {
            classify_decode_attempt(|| from_bytes_view(&invalid)?.decode::<ArchiveOracle>())
        })
        .unwrap_err(),
    );
    assert!(matches!(ordinary.error, Error::ChecksumMismatch));
    let filled = archive_cause(with_decode_limits_scope(narrow, || {
        work.decode_canonical_archive_into::<ArchiveRecord, _>(
            &invalid,
            limit(4096),
            &mut destination,
        )
    }));
    assert!(matches!(filled.error, Error::ChecksumMismatch));
    assert_eq!(filled.kind, ordinary.kind);
    assert!(destination.first.is_none() && destination.fixed.is_none());
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(
        work.decode_canonical_archive_into::<ArchiveRecord, _>(
            &trailing,
            limit(4096),
            &mut destination
        )
        .is_err()
    );
    // A complete alternate supported layout still cannot authenticate as the sole
    // canonical frame. No successful prefix or advertised flag suffices alone.
    let alternate_payload = {
        let _flags = DecodeFlagsGuard::enter(0);
        crate::core::to_bytes(&ArchiveRecord {
            first: 17,
            fixed: [2, 3, 5, 7],
        })
        .unwrap()
    };
    assert_ne!(alternate_payload, frame);
    assert!(
        work.decode_canonical_archive_into::<ArchiveRecord, _>(
            &alternate_payload,
            limit(4096),
            &mut destination
        )
        .is_err()
    );
    work.decode_canonical_archive_into::<ArchiveRecord, _>(&frame, limit(4096), &mut destination)
        .unwrap();
    assert_eq!(destination.first, Some(17));
    assert_eq!(destination.fixed, Some([2, 3, 5, 7]));
    assert_eq!(DECODE_NESTING_DEPTH.with(Cell::get), 0);
}
