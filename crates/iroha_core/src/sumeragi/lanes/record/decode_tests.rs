//! Every bulk decode backing/control phase retains its actual source and partial owners.

use iroha_allocation::ChargedShared;
use iroha_sumeragi::types::MAX_COMMITTEE_SIZE;

use super::*;
use crate::sumeragi::lanes::record::tests::{fixture, raw_job, verify};

#[test]
fn four_resource_refusals_keep_same_raw_table_and_payload_owners() {
    let (mut job, source, budget, crypto) = raw_job(23572);
    let layout = parse(job.raw.as_slice()).unwrap();
    let (raw, table, payload) = (
        job.raw.capacity(),
        layout.availability.len(),
        layout.payload.len(),
    );
    let control = ChargedShared::<ChargedBuffer<u8>>::allocation_layout().size();
    let raw_pointer = job.raw.as_slice().as_ptr();
    let mut pointers = [None; 2];
    for (limit, expected, shared) in [
        (raw + table - 1, raw, false),
        (raw + table + control - 1, raw + table, true),
        (
            raw + table + control + payload - 1,
            raw + table + control,
            false,
        ),
        (
            raw + table + payload + 2 * control - 1,
            raw + table + payload + control,
            true,
        ),
    ] {
        budget.set_limit_bytes(limit);
        for _ in 0..2 {
            let (retained, error) = job
                .complete(&budget)
                .err()
                .expect("exact original phase refusal");
            assert_eq!(
                matches!(
                    error,
                    LaneRecordError::Bytes(ByteAdmissionError::ControlAdmission(_))
                ),
                shared
            );
            job = retained;
            assert_eq!(job.raw.as_slice().as_ptr(), raw_pointer);
            assert_eq!(budget.reserved_bytes(), expected);
            let current = [
                job.table_backing
                    .as_ref()
                    .map(|b| b.as_slice().as_ptr())
                    .or_else(|| job.table.as_ref().map(|b| b.as_slice().as_ptr())),
                job.payload_backing
                    .as_ref()
                    .map(|b| b.as_slice().as_ptr())
                    .or_else(|| job.payload.as_ref().map(|b| b.as_slice().as_ptr())),
            ];
            for (prior, now) in pointers.iter_mut().zip(current) {
                if prior.is_some() {
                    assert_eq!(*prior, now);
                } else {
                    *prior = now;
                }
            }
        }
        let foreign = AllocationBudget::new(1 << 25);
        let (retained, error) = job.complete(&foreign).err().unwrap();
        assert!(matches!(error, LaneRecordError::ForeignBudget));
        job = retained;
        assert_eq!(budget.reserved_bytes(), expected);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
    budget.set_limit_bytes(raw + table + payload + 2 * control);
    let record = job
        .complete(&budget)
        .unwrap_or_else(|_| panic!("all original controls admitted"));
    assert_eq!(
        pointers,
        [
            Some(record.availability.as_slice().as_ptr()),
            Some(record.payload.as_slice().as_ptr()),
        ]
    );
    assert_eq!(budget.reserved_bytes(), table + payload + 2 * control);
    verify(&source, record.commit_qc(), &crypto);
    record.check_context(&source, &crypto).unwrap();
    let (restoration, qc) = record.into_restoration(source);
    budget.set_limit_bytes(1 << 25);
    let body = restoration
        .complete(&budget, &crypto)
        .unwrap_or_else(|_| panic!("actual original availability restoration"));
    assert_eq!(Some(body.payload().as_slice().as_ptr()), pointers[1]);
    assert_eq!(Some(body.availability().as_slice().as_ptr()), pointers[0]);
    drop(body);
    drop(qc);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn dropping_refused_payload_control_releases_every_original_charge() {
    let (job, _, budget, _) = raw_job(1025);
    let layout = parse(job.raw.as_slice()).unwrap();
    let control = ChargedShared::<ChargedBuffer<u8>>::allocation_layout().size();
    budget.set_limit_bytes(
        job.raw.capacity() + layout.availability.len() + layout.payload.len() + 2 * control - 1,
    );
    let (job, error) = job.complete(&budget).err().unwrap();
    assert!(matches!(
        error,
        LaneRecordError::Bytes(ByteAdmissionError::ControlAdmission(_))
    ));
    assert!(job.table.is_some() && job.payload_backing.is_some());
    drop(job);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn corruption_missing_frame_and_noncanonical_layout_reject_before_bulk_destinations() {
    let (body, qc, _, budget, _) = fixture(1025);
    let exact = LaneRecordRef {
        header: FieldRef(body.header()),
        availability: BytesRef(body.availability().as_slice()),
        payload: BytesRef(body.payload().as_slice()),
        commit_qc: QcRef::from(&qc),
    };
    let bytes = norito::encode_canonical(&exact).unwrap();
    let mut changed = bytes.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let missing = norito::encode_canonical(&LaneRecordRef {
        header: FieldRef(body.header()),
        availability: BytesRef(&[]),
        payload: BytesRef(body.payload().as_slice()),
        commit_qc: QcRef::from(&qc),
    })
    .unwrap();
    let alternate = {
        let _flags = ncore::DecodeFlagsGuard::enter(0);
        ncore::to_bytes(&exact).unwrap()
    };
    for bad in [
        changed,
        missing,
        alternate,
        bytes[..bytes.len() - 1].to_vec(),
    ] {
        let mut raw = ChargedBuffer::new(bad.len(), &budget).unwrap();
        raw.append(&bad).unwrap();
        let retained = budget.reserved_bytes();
        let mut job = LaneRecordDecode::new(raw);
        for _ in 0..2 {
            let (same, error) = job.complete(&budget).err().expect("canonical rejection");
            assert!(matches!(error, LaneRecordError::Codec(_)));
            assert!(same.table_backing.is_none() && same.payload_backing.is_none());
            assert_eq!(budget.reserved_bytes(), retained);
            job = same;
        }
    }
}

#[test]
fn maximum_qc_bitmap_is_bounded_before_any_bulk_decode() {
    let (body, mut qc, _, budget, _) = fixture(1);
    // Untrusted codec boundary fixture, not a claimed valid quorum certificate.
    qc.signers = iroha_sumeragi::types::Bitmap::new(MAX_COMMITTEE_SIZE);
    let bytes = norito::encode_canonical(&LaneRecordRef {
        header: FieldRef(body.header()),
        availability: BytesRef(body.availability().as_slice()),
        payload: BytesRef(body.payload().as_slice()),
        commit_qc: QcRef::from(&qc),
    })
    .unwrap();
    parse(&bytes).expect("largest metadata is accepted by finite codec boundary");
    qc.signers = iroha_sumeragi::types::Bitmap::new(MAX_COMMITTEE_SIZE + 8);
    let bytes = norito::encode_canonical(&LaneRecordRef {
        header: FieldRef(body.header()),
        availability: BytesRef(body.availability().as_slice()),
        payload: BytesRef(body.payload().as_slice()),
        commit_qc: QcRef::from(&qc),
    })
    .unwrap();
    let mut raw = ChargedBuffer::new(bytes.len(), &budget).unwrap();
    raw.append(&bytes).unwrap();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    let (job, error) = LaneRecordDecode::new(raw)
        .complete(&budget)
        .err()
        .expect("metadata count exceeds bound");
    assert!(matches!(error, LaneRecordError::Codec(_)));
    assert!(job.layout.is_none() && job.table_backing.is_none());
    assert_eq!(budget.reserved_bytes(), retained);
}

#[test]
fn standalone_qc_uses_the_same_bounded_canonical_metadata_parser() {
    let (_, qc, _, _, _) = fixture(1);
    let raw = norito::encode_canonical(&qc).unwrap();
    let metadata = qc::parse_frame(&raw).unwrap();
    assert_eq!(norito::encode_canonical(&metadata.borrowed()).unwrap(), raw);
    let mut changed = raw;
    changed[0] ^= 1;
    assert!(qc::parse_frame(&changed).is_err());
}
