//! Canonical metadata layout, original provenance, sharing and allocator refusal controls.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_data_model::{
    block::decode_framed_signed_block, sumeragi_finality::test_fixtures::NativeFinalityFixture,
};

fn values() -> (BlockHeader, Qc) {
    let fixture = NativeFinalityFixture::new();
    let block = decode_framed_signed_block(&fixture.latest().block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let mut header: BlockHeader = norito::decode_canonical(certificate.consensus_header()).unwrap();
    header.skipped_leaders = vec![
        PublicKey::new(vec![0x51; 47]).unwrap(),
        PublicKey::new(vec![0x62; 79]).unwrap(),
    ];
    header.control_witness = ControlWitness::try_from_slice(b"original inline witness").unwrap();
    let qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    (header, qc)
}

fn header_layouts(value: &BlockHeader) -> Vec<Layout> {
    let mut layouts = vec![
        ChargedShared::<RetainedPayload<BlockHeader>>::allocation_layout(),
        Layout::array::<AllocationCharge>(value.skipped_leaders.len() + 1).unwrap(),
        Layout::array::<PublicKey>(value.skipped_leaders.len()).unwrap(),
    ];
    layouts.extend(
        value
            .skipped_leaders
            .iter()
            .map(|key| Layout::array::<u8>(key.as_bytes().len()).unwrap()),
    );
    layouts
}

fn qc_layouts(value: &Qc) -> [Layout; 3] {
    [
        ChargedShared::<RetainedPayload<Qc>>::allocation_layout(),
        Layout::array::<AllocationCharge>(1).unwrap(),
        Layout::array::<u8>(value.signers.as_bytes().len()).unwrap(),
    ]
}

#[test]
fn metadata_retains_exact_original_graph_through_moves_sharing_and_last_reader() {
    let (expected_header, expected_qc) = values();
    let header_wire = norito::encode_canonical(&expected_header).unwrap();
    let qc_wire = norito::encode_canonical(&expected_qc).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let mut result = None;
    let allocations = allocations_during(|| {
        result = Some((
            header(&header_wire, &pool).unwrap(),
            qc(&qc_wire, &pool).unwrap(),
        ));
    });
    let (header, qc) = result.unwrap();
    assert!(
        header.belongs_to(&pool),
        "HC960 canonical metadata retains the original pool"
    );
    assert!(qc.belongs_to(&pool));
    assert!(!header.belongs_to(&foreign) && !qc.belongs_to(&foreign));
    assert_eq!(*header, expected_header);
    assert_eq!(*qc, expected_qc);
    let exact_header: usize = header_layouts(&header).iter().map(Layout::size).sum();
    let exact_qc: usize = qc_layouts(&qc).iter().map(Layout::size).sum();
    assert_eq!(
        allocations, 12,
        "every physical metadata allocation has an exact owner"
    );
    assert_eq!(header.allocation_bytes(), exact_header);
    assert_eq!(qc.allocation_bytes(), exact_qc);
    assert_eq!(pool.reserved_bytes(), exact_header + exact_qc);
    let key_array = header.skipped_leaders.as_ptr();
    let key = header.skipped_leaders[0].as_bytes().as_ptr();
    let bitmap = qc.signers.as_bytes().as_ptr();
    let mut shared = None;
    assert_eq!(
        allocations_during(|| shared = Some((header.clone(), qc.clone()))),
        0
    );
    let (moved_header, moved_qc) = (header, qc);
    assert_eq!(moved_header.skipped_leaders.as_ptr(), key_array);
    assert_eq!(moved_header.skipped_leaders[0].as_bytes().as_ptr(), key);
    assert_eq!(moved_qc.signers.as_bytes().as_ptr(), bitmap);
    drop((moved_header, moved_qc));
    assert_eq!(pool.reserved_bytes(), exact_header + exact_qc);
    let shared = shared.unwrap();
    assert_eq!(shared.0.skipped_leaders.as_ptr(), key_array);
    assert_eq!(shared.1.signers.as_bytes().as_ptr(), bitmap);
    assert_eq!(norito::encode_canonical(&*shared.0).unwrap(), header_wire);
    assert_eq!(norito::encode_canonical(&*shared.1).unwrap(), qc_wire);
    drop(shared);
    assert_eq!(pool.reserved_bytes(), 0);
}

fn physical(error: CertificateReadError, layout: Layout) {
    assert!(
        matches!(error,
        CertificateReadError::Admission(ByteAdmissionError::Buffer(ChargedBufferError::Allocator { requested_bytes }))
        | CertificateReadError::Admission(ByteAdmissionError::ControlAllocation(iroha_allocation::PrepaidSharedError::Allocator { requested_bytes }))
        if requested_bytes == layout.size()),
        "physical metadata failure never invents a capacity-release observation"
    );
}

#[test]
fn metadata_refuses_every_physical_layout_and_retires_partial_graphs() {
    let (expected_header, expected_qc) = values();
    let header_wire = norito::encode_canonical(&expected_header).unwrap();
    let qc_wire = norito::encode_canonical(&expected_qc).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    for layout in header_layouts(&expected_header) {
        let (result, refused) = refuse_one_layout_during(layout, || header(&header_wire, &pool));
        assert!(refused, "the exact header allocation must be observed");
        physical(result.unwrap_err(), layout);
        assert_eq!(pool.reserved_bytes(), 0);
        drop(header(&header_wire, &pool).unwrap());
        assert_eq!(pool.reserved_bytes(), 0);
    }
    for layout in qc_layouts(&expected_qc) {
        let (result, refused) = refuse_one_layout_during(layout, || qc(&qc_wire, &pool));
        assert!(refused, "the exact quorum allocation must be observed");
        physical(result.unwrap_err(), layout);
        assert_eq!(pool.reserved_bytes(), 0);
        drop(qc(&qc_wire, &pool).unwrap());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn metadata_capacity_refusal_preserves_original_release_and_unwind_reclaims() {
    let (expected_header, expected_qc) = values();
    let header_wire = norito::encode_canonical(&expected_header).unwrap();
    let qc_wire = norito::encode_canonical(&expected_qc).unwrap();
    let header_retained: usize = header_layouts(&expected_header)
        .iter()
        .map(Layout::size)
        .sum();
    let qc_retained: usize = qc_layouts(&expected_qc).iter().map(Layout::size).sum();
    let header_demand = header_retained + workspace_bytes().unwrap();
    let qc_demand = qc_retained + workspace_bytes().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - header_demand + 1)
        .unwrap();
    let expected = pool.try_reserve_bytes(header_demand).unwrap_err();
    let actual = header(&header_wire, &pool).unwrap_err();
    assert!(matches!(actual,
        CertificateReadError::Admission(ByteAdmissionError::Buffer(ChargedBufferError::Admission(actual)))
        if actual == expected));
    drop(blocker);
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - qc_demand + 1)
        .unwrap();
    let expected = pool.try_reserve_bytes(qc_demand).unwrap_err();
    let actual = qc(&qc_wire, &pool).unwrap_err();
    assert!(matches!(actual,
        CertificateReadError::Admission(ByteAdmissionError::Buffer(ChargedBufferError::Admission(actual)))
        if actual == expected));
    drop(blocker);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PANIC_AFTER_KEY.with(|enabled| enabled.set(Some(0)));
        let _ = header(&header_wire, &pool);
    }));
    assert!(failure.is_err());
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "partial metadata is deallocated before original credit returns"
    );
    drop(header(&header_wire, &pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn metadata_rejects_noncanonical_nested_shapes_and_limits_without_admission() {
    let (mut expected_header, mut expected_qc) = values();
    let pool = AllocationBudget::new(1 << 20);
    expected_header.skipped_leaders =
        vec![PublicKey::new(vec![1]).unwrap(); MAX_COMMITTEE_SIZE + 1];
    let raw = norito::encode_canonical(&expected_header).unwrap();
    assert!(matches!(
        header(&raw, &pool),
        Err(CertificateReadError::Canonical(original))
            if original.kind() == ncore::DecodeAttemptErrorKind::Invalid
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    expected_qc.signers = Bitmap::from_bytes(vec![0; MAX_BITMAP_BYTES + 1]);
    let raw = norito::encode_canonical(&expected_qc).unwrap();
    assert!(matches!(
        qc(&raw, &pool),
        Err(CertificateReadError::Canonical(original))
            if original.kind() == ncore::DecodeAttemptErrorKind::Invalid
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    for raw in [&[][..], &[1, 2, 3][..]] {
        assert!(matches!(
            header(raw, &pool),
            Err(CertificateReadError::Canonical(original))
            if original.kind() == ncore::DecodeAttemptErrorKind::Invalid
        ));
        assert!(matches!(
            qc(raw, &pool),
            Err(CertificateReadError::Canonical(original))
            if original.kind() == ncore::DecodeAttemptErrorKind::Invalid
        ));
    }
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn metadata_preserves_inherited_cumulative_decode_limits_before_physical_admission() {
    let (expected_header, expected_qc) = values();
    let header_wire = norito::encode_canonical(&expected_header).unwrap();
    let qc_wire = norito::encode_canonical(&expected_qc).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, 0, usize::MAX, 128);
    assert!(
        norito::core::with_decode_limits_scope(limits, || header(&header_wire, &pool)).is_err()
    );
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(norito::core::with_decode_limits_scope(limits, || qc(&qc_wire, &pool)).is_err());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn metadata_preflight_retains_original_limits_after_retirement_for_both_destinations() {
    let (expected_header, expected_qc) = values();
    let header_wire = norito::encode_canonical(&expected_header).unwrap();
    let qc_wire = norito::encode_canonical(&expected_qc).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    for is_header in [true, false] {
        for is_funded in [true, false] {
            let read = || match (is_header, is_funded) {
                (true, true) => header(&header_wire, &pool).map(drop),
                (true, false) => decoded_header(&header_wire).map(drop),
                (false, true) => qc(&qc_wire, &pool).map(drop),
                (false, false) => decoded_qc(&qc_wire).map(drop),
            };
            for elements in [true, false] {
                let limits = norito::DecodeLimits::new(
                    usize::MAX,
                    usize::MAX,
                    if elements { 0 } else { usize::MAX },
                    if elements { usize::MAX } else { 0 },
                    128,
                );
                let error = norito::with_decode_limits_scope(limits, read).unwrap_err();
                let CertificateReadError::Canonical(original) = error else {
                    panic!("original metadata preflight refusal: {error:?}");
                };
                assert_eq!(
                    original.kind(),
                    ncore::DecodeAttemptErrorKind::EnclosingLimit
                );
                let refusal = original.local_refusal().unwrap();
                if elements {
                    assert!(matches!(
                        refusal.resource_error(),
                        ncore::DecodeResourceError::TotalElementsExceeded { attempted, limit: 0 }
                            if attempted > 0
                    ));
                } else {
                    assert!(matches!(
                        refusal.resource_error(),
                        ncore::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }
                            if attempted > 0
                    ));
                }
                assert!(!ncore::decode_error_matches_active_limits(original.error()));
                norito::with_decode_limits_scope(limits, || {
                    assert!(
                        !ncore::decode_error_matches_active_limits(original.error()),
                        "equal limits cannot claim the retired original counter owner"
                    );
                });
                // The captured family keeps one original prepared control alive.
                let retained_control_bytes = if is_funded {
                    ncore::PreparedDecodeWorkspace::allocation_layouts()[0].size()
                } else {
                    0
                };
                assert_eq!(pool.reserved_bytes(), retained_control_bytes);
                let moved = original.into_local_refusal().unwrap();
                assert_eq!(moved, refusal);
                drop(moved);
                assert_eq!(pool.reserved_bytes(), retained_control_bytes);
                read().expect("unchanged original metadata retries after scope retirement");
                assert_eq!(pool.reserved_bytes(), retained_control_bytes);
                drop(refusal);
                assert_eq!(pool.reserved_bytes(), 0);
            }
        }
    }
}

#[test]
fn qc_preflight_accounts_once_at_ordinary_decoder_element_and_allocation_boundaries() {
    let (_, expected) = values();
    assert_eq!(expected.signers.as_bytes().len(), 1);
    let wire = norito::encode_canonical(&expected).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    for limits in [
        norito::DecodeLimits::new(usize::MAX, usize::MAX, 1, usize::MAX, 128),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 2, 128),
    ] {
        assert_eq!(
            norito::with_decode_limits_scope(limits, || norito::decode_canonical::<Qc>(&wire))
                .unwrap(),
            expected
        );
        assert_eq!(
            *norito::with_decode_limits_scope(limits, || qc(&wire, &pool)).unwrap(),
            expected
        );
        assert_eq!(
            norito::with_decode_limits_scope(limits, || decoded_qc(&wire)).unwrap(),
            expected
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn qc_preflight_rejects_one_byte_allocation_ceiling_at_all_three_destinations() {
    let (_, expected) = values();
    assert_eq!(expected.signers.as_bytes().len(), 1);
    let wire = norito::encode_canonical(&expected).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, 128);
    // One sequence element and its one-byte backing are charged by the same traversal.
    for destination in 0..3 {
        let original = norito::with_decode_limits_scope(limits, || {
            if destination == 0 {
                return ncore::classify_decode_attempt(|| norito::decode_canonical::<Qc>(&wire))
                    .unwrap_err();
            }
            let error = if destination == 1 {
                qc(&wire, &pool).map(drop)
            } else {
                decoded_qc(&wire).map(drop)
            }
            .unwrap_err();
            let CertificateReadError::Canonical(original) = error else {
                panic!("original one-byte ceiling refusal: {error:?}");
            };
            original
        });
        assert_eq!(
            original.kind(),
            ncore::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            original.local_refusal().unwrap().resource_error(),
            ncore::DecodeResourceError::TotalAllocationExceeded {
                attempted: 2,
                limit: 1
            }
        );
        // Only the funded destination retains a charged control in its refusal.
        let retained_control_bytes = if destination == 1 {
            ncore::PreparedDecodeWorkspace::allocation_layouts()[0].size()
        } else {
            0
        };
        assert_eq!(pool.reserved_bytes(), retained_control_bytes);
        // An old refusal cannot block or fund a fresh successful read of the same bytes.
        if destination == 0 {
            assert_eq!(norito::decode_canonical::<Qc>(&wire).unwrap(), expected);
        } else if destination == 1 {
            assert_eq!(*qc(&wire, &pool).unwrap(), expected);
        } else {
            assert_eq!(decoded_qc(&wire).unwrap(), expected);
        }
        assert_eq!(pool.reserved_bytes(), retained_control_bytes);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn metadata_nested_fields_preserve_inherited_depth_before_physical_admission() {
    let (expected_header, _) = values();
    let header_wire = norito::encode_canonical(&expected_header).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 2);
    assert!(
        norito::core::with_decode_limits_scope(limits, || header(&header_wire, &pool)).is_err()
    );
    assert_eq!(pool.reserved_bytes(), 0);
    drop(header(&header_wire, &pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn metadata_refuses_each_repeated_key_layout_and_unwinds_each_partial_prefix() {
    let (mut expected_header, _) = values();
    expected_header.skipped_leaders = vec![
        PublicKey::new(vec![0x51; 48]).unwrap(),
        PublicKey::new(vec![0x62; 48]).unwrap(),
    ];
    let wire = norito::encode_canonical(&expected_header).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    for index in 0..expected_header.skipped_leaders.len() {
        REFUSE_KEY.with(|selected| selected.set(Some(index)));
        physical(
            header(&wire, &pool).unwrap_err(),
            Layout::array::<u8>(48).unwrap(),
        );
        assert_eq!(REFUSE_KEY.with(std::cell::Cell::get), None);
        assert_eq!(pool.reserved_bytes(), 0);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PANIC_AFTER_KEY.with(|selected| selected.set(Some(index)));
            let _ = header(&wire, &pool);
        }));
        assert!(failure.is_err());
        assert_eq!(PANIC_AFTER_KEY.with(std::cell::Cell::get), None);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    drop(header(&wire, &pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
}

fn alternate_layout<T: ncore::NoritoSerialize>(value: &T) -> Vec<u8> {
    let _flags = ncore::DecodeFlagsGuard::enter(
        ncore::default_encode_flags() ^ ncore::header_flags::COMPACT_LEN,
    );
    ncore::to_bytes(value).unwrap()
}

#[test]
fn metadata_accepts_only_the_exact_canonical_frame_of_its_value() {
    let (expected_header, expected_qc) = values();
    let pool = AllocationBudget::new(1 << 20);
    let header_frame = alternate_layout(&expected_header);
    let qc_frame = alternate_layout(&expected_qc);
    // Each alternate frame is a well-formed checksummed frame of the same value; the
    // generic layout-aware decoder accepts it, so only the exact relation can reject it.
    assert_ne!(
        header_frame,
        norito::encode_canonical(&expected_header).unwrap()
    );
    assert_ne!(qc_frame, norito::encode_canonical(&expected_qc).unwrap());
    assert_eq!(
        norito::decode_from_bytes::<BlockHeader>(&header_frame).unwrap(),
        expected_header
    );
    assert_eq!(
        norito::decode_from_bytes::<Qc>(&qc_frame).unwrap(),
        expected_qc
    );
    let results = [
        header(&header_frame, &pool).map(drop),
        decoded_header(&header_frame).map(drop),
        qc(&qc_frame, &pool).map(drop),
        decoded_qc(&qc_frame).map(drop),
    ];
    for result in results {
        assert!(
            matches!(
                result,
                Err(CertificateReadError::Canonical(original))
                    if original.kind() == ncore::DecodeAttemptErrorKind::Invalid
                        && matches!(original.error(), norito::Error::NonCanonicalEncoding)
            ),
            "HC961 metadata accepts only the exact canonical frame of its decoded value"
        );
    }
    assert_eq!(pool.reserved_bytes(), 0);
    // Both destinations still accept the canonical frames of the same values.
    let header_wire = norito::encode_canonical(&expected_header).unwrap();
    let qc_wire = norito::encode_canonical(&expected_qc).unwrap();
    assert_eq!(*header(&header_wire, &pool).unwrap(), expected_header);
    assert_eq!(decoded_header(&header_wire).unwrap(), expected_header);
    assert_eq!(*qc(&qc_wire, &pool).unwrap(), expected_qc);
    assert_eq!(decoded_qc(&qc_wire).unwrap(), expected_qc);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn metadata_workspace_refuses_both_equal_layout_occurrences_and_refunds_original_pool() {
    let (value, quorum) = values();
    let header_wire = norito::encode_canonical(&value).unwrap();
    let qc_wire = norito::encode_canonical(&quorum).unwrap();
    let layouts = ncore::PreparedDecodeWorkspace::allocation_layouts();
    assert_eq!(layouts[0], layouts[1]);
    let pool = AllocationBudget::new(1 << 20);
    for is_header in [true, false] {
        for occurrence in 0..2 {
            let mut observed = None;
            let successful = allocations_during(|| {
                observed = Some(crate::test_allocations::refuse_layout_occurrence_during(
                    layouts[occurrence],
                    occurrence,
                    || {
                        if is_header {
                            header(&header_wire, &pool).map(drop)
                        } else {
                            qc(&qc_wire, &pool).map(drop)
                        }
                    },
                ));
            });
            let (result, refused) = observed.unwrap();
            assert!(
                refused,
                "the selected equal-layout workspace control was attempted"
            );
            assert_eq!(
                successful, occurrence,
                "only preceding actual workspace controls were allocated"
            );
            physical(result.unwrap_err(), layouts[occurrence]);
            assert_eq!(
                pool.reserved_bytes(),
                0,
                "completed controls and original reservation retire together"
            );
            if is_header {
                drop(header(&header_wire, &pool).unwrap());
            } else {
                drop(qc(&qc_wire, &pool).unwrap());
            }
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn metadata_peak_admission_includes_controls_but_retained_graph_does_not() {
    let (value, quorum) = values();
    for (wire, is_header, retained) in [
        (
            norito::encode_canonical(&value).unwrap(),
            true,
            header_layouts(&value)
                .iter()
                .map(Layout::size)
                .sum::<usize>(),
        ),
        (
            norito::encode_canonical(&quorum).unwrap(),
            false,
            qc_layouts(&quorum).iter().map(Layout::size).sum::<usize>(),
        ),
    ] {
        let peak = retained + workspace_bytes().unwrap();
        let short = AllocationBudget::new(peak - 1);
        let result = if is_header {
            header(&wire, &short).map(drop)
        } else {
            qc(&wire, &short).map(drop)
        };
        assert!(matches!(result, Err(CertificateReadError::Admission(_))));
        assert_eq!(short.reserved_bytes(), 0);
        let exact = AllocationBudget::new(peak);
        if is_header {
            let value = header(&wire, &exact).unwrap();
            assert!(value.belongs_to(&exact));
            assert_eq!(exact.reserved_bytes(), retained);
            assert_eq!(value.allocation_bytes(), retained);
            drop(value);
        } else {
            let value = qc(&wire, &exact).unwrap();
            assert!(value.belongs_to(&exact));
            assert_eq!(exact.reserved_bytes(), retained);
            assert_eq!(value.allocation_bytes(), retained);
            drop(value);
        }
        assert_eq!(exact.reserved_bytes(), 0);
    }
}

fn ordinary(raw: &[u8], is_header: bool) -> Result<(), ncore::DecodeAttemptError> {
    if is_header {
        norito::decode_canonical_for_admission::<BlockHeader>(
            raw,
            norito::canonical_decode_limits(raw.len()),
        )
        .map(drop)
    } else {
        norito::decode_canonical_for_admission::<Qc>(
            raw,
            norito::canonical_decode_limits(raw.len()),
        )
        .map(drop)
    }
}
fn metadata_read(
    raw: &[u8],
    is_header: bool,
    funded: bool,
    pool: &AllocationBudget,
) -> Result<(), CertificateReadError> {
    match (is_header, funded) {
        (true, true) => header(raw, pool).map(drop),
        (true, false) => decoded_header(raw).map(drop),
        (false, true) => qc(raw, pool).map(drop),
        (false, false) => decoded_qc(raw).map(drop),
    }
}
#[derive(Debug, PartialEq)]
struct DecodeVerdict {
    kind: ncore::DecodeAttemptErrorKind,
    resource: Option<ncore::DecodeResourceError>,
    text: String,
}
fn verdict(result: Result<(), ncore::DecodeAttemptError>) -> Result<(), DecodeVerdict> {
    result.map_err(|original| DecodeVerdict {
        kind: original.kind(),
        resource: original.error().decode_resource_error(),
        text: original.to_string(),
    })
}
fn same_boundary(
    raw: &[u8],
    is_header: bool,
    limits: norito::DecodeLimits,
    pool: &AllocationBudget,
) {
    let expected = verdict(norito::with_decode_limits_scope(limits, || {
        ordinary(raw, is_header)
    }));
    for funded in [true, false] {
        let actual = norito::with_decode_limits_scope(limits, || {
            metadata_read(raw, is_header, funded, pool)
        });
        let actual = match actual {
            Ok(()) => Ok(()),
            Err(CertificateReadError::Canonical(original)) => verdict(Err(original)),
            Err(error) => panic!("unexpected non-codec boundary refusal: {error:?}"),
        };
        assert_eq!(
            actual, expected,
            "HC968 metadata retains the ordinary canonical root and sole accounting traversal\nfunded={funded}"
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn metadata_canonical_root_matches_depth_field_element_and_allocation_boundaries() {
    let (value, quorum) = values();
    let pool = AllocationBudget::new(1 << 20);
    let unlimited = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128);
    for (wire, is_header) in [
        (norito::encode_canonical(&value).unwrap(), true),
        (norito::encode_canonical(&quorum).unwrap(), false),
    ] {
        let (result, usage) =
            ncore::with_decode_limits_measured(unlimited, || ordinary(&wire, is_header));
        result.unwrap();
        for depth in 0..=8 {
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth),
                &pool,
            );
        }
        let payload = ncore::from_bytes_view(&wire).unwrap().as_bytes().len();
        for field in [0, payload - 1, payload, payload + 1] {
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(usize::MAX, field, usize::MAX, usize::MAX, 128),
                &pool,
            );
        }
        for sequence in [0, 1, 2, 47, 78, 79, 80] {
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(sequence, usize::MAX, usize::MAX, usize::MAX, 128),
                &pool,
            );
        }
        for elements in [
            usage.total_elements() - 1,
            usage.total_elements(),
            usage.total_elements() + 1,
        ] {
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, elements, usize::MAX, 128),
                &pool,
            );
        }
        for allocation in [
            usage.total_allocated_bytes() - 1,
            usage.total_allocated_bytes(),
            usage.total_allocated_bytes() + 1,
        ] {
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 128),
                &pool,
            );
        }
        for mixed in [
            norito::DecodeLimits::new(0, 0, 0, 0, 0),
            norito::DecodeLimits::new(0, usize::MAX, 0, 0, 0),
        ] {
            same_boundary(&wire, is_header, mixed, &pool);
        }
    }
}

fn frame_metadata_payload(payload: &[u8], flags: u8, is_header: bool) -> Vec<u8> {
    let result = if is_header {
        ncore::frame_bare_with_header_flags::<BlockHeader>(payload, flags)
    } else {
        ncore::frame_bare_with_header_flags::<Qc>(payload, flags)
    }
    .unwrap();
    ncore::from_bytes_view(&result).unwrap();
    result
}

fn replace_payload(raw: &[u8], is_header: bool, mutate: impl FnOnce(&mut [u8], u8)) -> Vec<u8> {
    let view = ncore::from_bytes_view(raw).unwrap();
    let mut payload = view.as_bytes().to_vec();
    mutate(&mut payload, view.flags());
    frame_metadata_payload(&payload, view.flags(), is_header)
}

#[test]
fn malformed_metadata_shape_cannot_preempt_original_canonical_root_refusal() {
    let (value, quorum) = values();
    let pool = AllocationBudget::new(1 << 20);
    for (wire, is_header, index) in [
        (norito::encode_canonical(&value).unwrap(), true, 10),
        (norito::encode_canonical(&quorum).unwrap(), false, 7),
    ] {
        for malformed_count in [true, false] {
            let malformed = replace_payload(&wire, is_header, |payload, flags| {
                let mut offset = 0;
                let mut range = 0..0;
                for _ in 0..=index {
                    range = shape_field(payload, &mut offset, flags).unwrap();
                }
                let field = &mut payload[range];
                let count_start = if is_header {
                    0
                } else {
                    ncore::inspect_raw_len_from_slice_with_flags(field, flags)
                        .unwrap()
                        .1
                };
                if malformed_count {
                    field[count_start..count_start + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                } else {
                    let prefix_start = if is_header { 8 } else { 0 };
                    field[prefix_start..prefix_start + 10].fill(0x80);
                }
            });
            if is_header {
                assert!(HeaderPlan::new(&malformed).is_err());
            } else {
                assert!(QcPlan::new(&malformed).is_err());
            }
            for limits in [
                norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 0),
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
            ] {
                same_boundary(&malformed, is_header, limits, &pool);
            }
        }
    }
}

fn rewritten_fields<const N: usize>(
    raw: &[u8],
    rewrite: impl FnOnce(&mut [Vec<u8>; N], u8),
) -> Vec<u8> {
    let frame = if N == 12 {
        Frame::<N>::parse::<BlockHeader>(raw).unwrap()
    } else {
        Frame::<N>::parse::<Qc>(raw).unwrap()
    };
    let mut fields = std::array::from_fn(|index| frame.field(index).to_vec());
    rewrite(&mut fields, frame.flags);
    let mut payload = Vec::new();
    for field in fields {
        ncore::write_len_to_vec_with_flags(&mut payload, field.len() as u64, frame.flags);
        payload.extend_from_slice(&field);
    }
    frame_metadata_payload(&payload, frame.flags, N == 12)
}
fn rewrite_first_key(fields: &mut [Vec<u8>; 12], flags: u8, rewrite: impl FnOnce(&mut Vec<u8>)) {
    let keys = &fields[10];
    let (count, mut offset) = ncore::inspect_raw_seq_len_slice(keys).unwrap();
    let first = shape_field(keys, &mut offset, flags).unwrap();
    let mut key = keys[first].to_vec();
    rewrite(&mut key);
    let mut changed = (count as u64).to_le_bytes().to_vec();
    ncore::write_len_to_vec_with_flags(&mut changed, key.len() as u64, flags);
    changed.extend_from_slice(&key);
    changed.extend_from_slice(&keys[offset..]);
    fields[10] = changed;
}

#[test]
fn malformed_wrapper_suffix_keeps_nested_depth_and_budget_precedence() {
    let (value, quorum) = values();
    let header = norito::encode_canonical(&value).unwrap();
    let qc = norito::encode_canonical(&quorum).unwrap();
    let malformed_header = rewritten_fields::<12>(&header, |fields, flags| {
        rewrite_first_key(fields, flags, |key| key.push(0xff));
    });
    let malformed_qc = rewritten_fields::<9>(&qc, |fields, _| fields[7].push(0xff));
    let pool = AllocationBudget::new(1 << 20);
    for (wire, is_header) in [(malformed_header, true), (malformed_qc, false)] {
        for depth in 0..=6 {
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth),
                &pool,
            );
        }
        for ceiling in [0, 1, 2, 47, 128, usize::MAX] {
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, ceiling, usize::MAX, 128),
                &pool,
            );
            same_boundary(
                &wire,
                is_header,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, ceiling, 128),
                &pool,
            );
        }
    }
}

#[test]
fn complete_intrinsic_metadata_bounds_are_terminal_before_caller_quotas_at_both_destinations() {
    let (mut value, mut quorum) = values();
    let original_header = norito::encode_canonical(&value).unwrap();
    value.skipped_leaders = vec![PublicKey::new(vec![1]).unwrap(); MAX_COMMITTEE_SIZE + 1];
    quorum.signers = Bitmap::from_bytes(vec![1; MAX_BITMAP_BYTES + 1]);
    let mut cases = vec![
        (norito::encode_canonical(&value).unwrap(), true),
        (norito::encode_canonical(&quorum).unwrap(), false),
    ];
    for length in [0, MAX_PUBLIC_KEY_LEN + 1] {
        let wire = rewritten_fields::<12>(&original_header, |fields, flags| {
            rewrite_first_key(fields, flags, |key| {
                let mut bytes = (length as u64).to_le_bytes().to_vec();
                bytes.resize(8 + length, 1);
                key.clear();
                ncore::write_len_to_vec_with_flags(key, bytes.len() as u64, flags);
                key.extend_from_slice(&bytes);
            });
        });
        cases.push((wire, true));
    }
    let pool = AllocationBudget::new(1 << 20);
    let zero = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    for (wire, is_header) in cases {
        for funded in [true, false] {
            let error = norito::with_decode_limits_scope(zero, || {
                metadata_read(&wire, is_header, funded, &pool)
            })
            .unwrap_err();
            let CertificateReadError::Canonical(original) = error else {
                panic!("captured intrinsic metadata policy");
            };
            assert_eq!(original.kind(), ncore::DecodeAttemptErrorKind::Invalid);
            assert!(matches!(
                original.error(),
                norito::Error::NonCanonicalEncoding
            ));
            assert!(original.local_refusal().is_none());
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn metadata_inline_witness_uses_original_bound_extent_and_resource_order() {
    let (value, _) = values();
    let wire = norito::encode_canonical(&value).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    for case in 0..3 {
        let malformed = rewritten_fields::<12>(&wire, |fields, _| match case {
            0 => {
                let count = iroha_sumeragi::types::MAX_CONTROL_WITNESS_BYTES + 1;
                fields[11] = (count as u64).to_le_bytes().to_vec();
                fields[11].resize(8 + count, 1);
            }
            1 => {
                fields[11][..8].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            _ => fields[11].push(0xff),
        });
        for depth in 0..=6 {
            same_boundary(
                &malformed,
                true,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth),
                &pool,
            );
        }
        for ceiling in [0, 1, 128, usize::MAX] {
            same_boundary(
                &malformed,
                true,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, ceiling, usize::MAX, 128),
                &pool,
            );
            same_boundary(
                &malformed,
                true,
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, ceiling, 128),
                &pool,
            );
        }
    }
}

#[test]
fn intrinsic_quorum_kind_rejection_never_allocates_an_owned_enum_diagnostic() {
    let (_, quorum) = values();
    let wire = norito::encode_canonical(&quorum).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    for suffix in [false, true] {
        let invalid = rewritten_fields::<9>(&wire, |fields, _| {
            fields[0] = 2_u32.to_le_bytes().to_vec();
            if suffix {
                fields[0].push(0xff);
            }
        });
        for funded in [true, false] {
            let mut result = None;
            let allocations =
                norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
                    allocations_during(|| {
                        result = Some(metadata_read(&invalid, false, funded, &pool))
                    })
                });
            assert_eq!(
                allocations, 0,
                "intrinsic invalid kind needs no enum diagnostic allocation"
            );
            let CertificateReadError::Canonical(original) = result.unwrap().unwrap_err() else {
                panic!("captured intrinsic kind");
            };
            assert_eq!(original.kind(), ncore::DecodeAttemptErrorKind::Invalid);
            assert!(matches!(
                original.error(),
                norito::Error::NonCanonicalEncoding
            ));
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
