//! Funded decoding and restoration retain the actual original raw and destination allocations.

use crate::sumeragi::crypto::BlsCrypto;
use iroha_allocation::ChargedShared;
use iroha_sumeragi::{
    message::ByteAdmissionError,
    types::{MAX_COMMITTEE_SIZE, MAX_CONTROL_WITNESS_BYTES, MAX_PUBLIC_KEY_LEN},
};

use super::*;
use crate::sumeragi::body_record::tests::{decode_record, fixture};

fn raw_record(size: usize) -> (BodyRecordDecode, AvailabilitySource, AllocationBudget) {
    let (body, source, budget) = fixture(size);
    let mut prepared = PreparedBodyWrite::new(body);
    let bytes = prepared.prepare(&budget).unwrap();
    let mut raw = ChargedBuffer::new(bytes.len(), &budget).unwrap();
    raw.append(bytes).unwrap();
    drop(prepared);
    (BodyRecordDecode::new(raw), source, budget)
}

#[test]
fn every_backing_and_control_refusal_retains_exact_source_and_destination_pointers() {
    let (mut job, source, budget) = raw_record(23572);
    let raw_pointer = job.raw.as_slice().as_ptr();
    let raw_length = job.raw.capacity();
    let layout = parse_layout(job.raw.as_slice()).unwrap();
    let table_length = layout.availability.len();
    let payload_length = layout.payload.len();
    let control = ChargedShared::<ChargedBuffer<u8>>::allocation_layout().size();
    assert_eq!(budget.reserved_bytes(), raw_length);
    let mut table_pointer = None;
    let mut payload_pointer = None;
    for (additional, control_failure) in [
        (table_length - 1, false),
        (table_length + control - 1, true),
        (table_length + control + payload_length - 1, false),
        (table_length + control + payload_length + control - 1, true),
    ] {
        budget.set_limit_bytes(raw_length + additional);
        let (retained, error) = job.complete(&budget).expect_err("exact phase refusal");
        assert!(matches!(&error, BodyDecodeError::Bytes(error) if error.is_local_refusal()));
        assert_eq!(
            matches!(
                error,
                BodyDecodeError::Bytes(ByteAdmissionError::ControlAdmission(_))
            ),
            control_failure
        );
        job = retained;
        assert_eq!(job.raw.as_slice().as_ptr(), raw_pointer);
        assert!(job.raw.belongs_to(&budget));
        if let Some(bytes) = job.table_backing.as_ref() {
            assert!(bytes.belongs_to(&budget));
            table_pointer.get_or_insert(bytes.as_slice().as_ptr());
            assert_eq!(Some(bytes.as_slice().as_ptr()), table_pointer);
        }
        if let Some(table) = job.table.as_ref() {
            assert_eq!(Some(table.as_slice().as_ptr()), table_pointer);
            assert!(table.admitted_to(&budget));
        }
        if let Some(bytes) = job.payload_backing.as_ref() {
            assert!(bytes.belongs_to(&budget));
            payload_pointer.get_or_insert(bytes.as_slice().as_ptr());
            assert_eq!(Some(bytes.as_slice().as_ptr()), payload_pointer);
        }
        let expected = raw_length
            + job.table_backing.as_ref().map_or(0, |b| b.capacity())
            + job.payload_backing.as_ref().map_or(0, |b| b.capacity())
            + job
                .table
                .as_ref()
                .map_or(0, |b| b.as_slice().len() + control)
            + job
                .payload
                .as_ref()
                .map_or(0, |b| b.as_slice().len() + control);
        assert_eq!(budget.reserved_bytes(), expected);
    }
    budget.set_limit_bytes(raw_length + table_length + payload_length + 2 * control);
    let record = job
        .complete(&budget)
        .unwrap_or_else(|_| panic!("complete original destinations"));
    assert_eq!(Some(record.availability.as_slice().as_ptr()), table_pointer);
    assert_eq!(Some(record.payload.as_slice().as_ptr()), payload_pointer);
    assert_eq!(
        budget.reserved_bytes(),
        table_length + payload_length + 2 * control
    );
    budget.set_limit_bytes(budget.reserved_bytes());
    let (restoration, error) = record
        .into_restoration(source.clone())
        .complete(&budget, &BlsCrypto::new())
        .expect_err("RS16 scratch refusal must retain admitted owners");
    assert!(error.is_local_refusal());
    assert_eq!(restoration.source(), &source);
    assert_eq!(
        budget.reserved_bytes(),
        table_length + payload_length + 2 * control
    );
    budget.set_limit_bytes(1 << 25);
    let body = restoration
        .complete(&budget, &BlsCrypto::new())
        .unwrap_or_else(|_| panic!("strict restoration after resource relief"));
    assert_eq!(Some(body.availability().as_slice().as_ptr()), table_pointer);
    assert_eq!(Some(body.payload().as_slice().as_ptr()), payload_pointer);
    assert!(body.admitted_to(&budget));
    drop(body);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn a_foreign_retry_cannot_move_or_recharge_partially_prepared_destinations() {
    let (job, _, budget) = raw_record(1025);
    let layout = parse_layout(job.raw.as_slice()).unwrap();
    budget.set_limit_bytes(job.raw.capacity() + layout.availability.len());
    let (job, _) = job.complete(&budget).err().unwrap();
    let pointer = job.table_backing.as_ref().unwrap().as_slice().as_ptr();
    let reserved = budget.reserved_bytes();
    let foreign = AllocationBudget::new(1 << 25);
    let (job, error) = job.complete(&foreign).err().unwrap();
    assert!(matches!(error, BodyDecodeError::ForeignBudget));
    assert_eq!(
        job.table_backing.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(foreign.reserved_bytes(), 0);
    drop(job);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn all_partial_phase_owners_refund_only_when_the_retained_job_is_dropped() {
    for phase in 0..4 {
        let (job, _, budget) = raw_record(1025);
        let layout = parse_layout(job.raw.as_slice()).unwrap();
        let raw = job.raw.capacity();
        let table = layout.availability.len();
        let payload = layout.payload.len();
        let control = ChargedShared::<ChargedBuffer<u8>>::allocation_layout().size();
        let available = [
            table - 1,
            table + control - 1,
            table + control + payload - 1,
            table + control + payload + control - 1,
        ][phase];
        budget.set_limit_bytes(raw + available);
        let (job, _) = job.complete(&budget).err().unwrap();
        assert!(budget.reserved_bytes() >= raw);
        drop(job);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn canonical_frame_validation_uses_declared_flags_and_restores_ambient_context() {
    let (job, _, budget) = raw_record(1025);
    let original = job.raw.as_slice();
    for index in [0, 6, original.len() - 1] {
        let mut corrupt = original.to_vec();
        corrupt[index] ^= 1;
        assert!(decode_record(&corrupt, &budget).is_err());
    }
    let _ambient = ncore::DecodeFlagsGuard::enter(0);
    let prior_flags = ncore::get_decode_flags();
    assert!(parse_layout(original).is_ok());
    assert_eq!(ncore::get_decode_flags(), prior_flags);
    assert!(parse_layout(&original[..original.len() - 1]).is_err());
    assert_eq!(ncore::get_decode_flags(), prior_flags);
}

#[test]
fn largest_supported_header_metadata_is_accepted_under_its_separate_finite_budget() {
    let (body, _, budget) = fixture(1);
    let mut header = body.header().clone();
    header.skipped_leaders = vec![
        iroha_sumeragi::types::PublicKey::new(vec![3; MAX_PUBLIC_KEY_LEN])
            .unwrap();
        MAX_COMMITTEE_SIZE
    ];
    header.control_witness =
        iroha_sumeragi::types::ControlWitness::try_from_slice(&[5; MAX_CONTROL_WITNESS_BYTES])
            .unwrap();
    let borrowed = BodyRecordRef {
        header: FieldRef(&header),
        availability: BytesRef(body.availability().as_slice()),
        payload: BytesRef(body.payload().as_slice()),
    };
    let encoded = norito::encode_canonical(&borrowed).unwrap();
    let record = decode_record(&encoded, &budget).unwrap();
    assert_eq!(record.header, header);
    assert!(record.availability.admitted_to(&budget));
    assert!(record.payload.admitted_to(&budget));
    header
        .skipped_leaders
        .push(header.skipped_leaders[0].clone());
    let invalid = BodyRecordRef {
        header: FieldRef(&header),
        availability: BytesRef(body.availability().as_slice()),
        payload: BytesRef(body.payload().as_slice()),
    };
    assert!(decode_record(&norito::encode_canonical(&invalid).unwrap(), &budget).is_err());
}

#[test]
fn alternate_layout_is_not_an_accepted_fallback() {
    let (body, _, budget) = fixture(1);
    let bytes = {
        let _flags = ncore::DecodeFlagsGuard::enter(0);
        ncore::to_bytes(&BodyRecordRef::from(&body)).unwrap()
    };
    assert!(decode_record(&bytes, &budget).is_err());
}

#[test]
fn oversized_header_field_is_refused_before_decoding_or_bulk_destination_allocation() {
    let (body, _, budget) = fixture(1);
    let mut header = body.header().clone();
    header.skipped_leaders = vec![
        iroha_sumeragi::types::PublicKey::new(vec![9; MAX_PUBLIC_KEY_LEN])
            .unwrap();
        MAX_COMMITTEE_SIZE * 2
    ];
    let malicious = BodyRecordRef {
        header: FieldRef(&header),
        availability: BytesRef(body.availability().as_slice()),
        payload: BytesRef(body.payload().as_slice()),
    };
    let bytes = norito::encode_canonical(&malicious).unwrap();
    let mut raw = ChargedBuffer::new(bytes.len(), &budget).unwrap();
    raw.append(&bytes).unwrap();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    let (job, error) = BodyRecordDecode::new(raw).complete(&budget).err().unwrap();
    assert!(
        matches!(error, BodyDecodeError::Decode(norito::Error::FieldLengthExceeded { limit, .. }) if limit == MAX_HEADER_METADATA_BYTES as u64)
    );
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(job.layout.is_none());
    assert!(job.table_backing.is_none());
    assert!(job.payload_backing.is_none());
}

#[test]
fn a_raw_header_payload_record_without_original_table_has_no_decoder_path() {
    #[derive(norito::Encode, norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::sumeragi::BodyRecord",
        frame = "iroha_core::sumeragi::BodyRecord"
    )]
    struct MissingTable<'a> {
        header: FieldRef<'a, BlockHeader>,
        payload: BytesRef<'a>,
    }
    let (body, _, budget) = fixture(1025);
    let bytes = norito::encode_canonical(&MissingTable {
        header: FieldRef(body.header()),
        payload: BytesRef(body.payload().as_slice()),
    })
    .unwrap();
    let mut raw = ChargedBuffer::new(bytes.len(), &budget).unwrap();
    raw.append(&bytes).unwrap();
    let retained = budget.reserved_bytes();
    let (job, error) = BodyRecordDecode::new(raw).complete(&budget).err().unwrap();
    assert!(matches!(error, BodyDecodeError::Decode(_)));
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(job.table_backing.is_none());
    assert!(job.payload_backing.is_none());
}
