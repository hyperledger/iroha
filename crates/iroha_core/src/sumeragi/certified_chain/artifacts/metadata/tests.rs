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
        allocations, 8,
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
    let header_demand: usize = header_layouts(&expected_header)
        .iter()
        .map(Layout::size)
        .sum();
    let qc_demand: usize = qc_layouts(&expected_qc).iter().map(Layout::size).sum();
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
        Err(CertificateReadError::Decode(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    expected_qc.signers = Bitmap::from_bytes(vec![0; MAX_BITMAP_BYTES + 1]);
    let raw = norito::encode_canonical(&expected_qc).unwrap();
    assert!(matches!(
        qc(&raw, &pool),
        Err(CertificateReadError::Decode(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    for raw in [&[][..], &[1, 2, 3][..]] {
        assert!(matches!(
            header(raw, &pool),
            Err(CertificateReadError::Decode(_))
        ));
        assert!(matches!(
            qc(raw, &pool),
            Err(CertificateReadError::Decode(_))
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
                Err(CertificateReadError::Decode(
                    norito::Error::NonCanonicalEncoding
                ))
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
