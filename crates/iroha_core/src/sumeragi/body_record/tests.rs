//! Original-backed write preparation and untrusted record restoration controls.

use std::io::Write as _;

use iroha_sumeragi::{
    availability::{PayloadAuthoring, recommended_data_availability_layout},
    crypto::Signer as _,
    types::{ChainParams, Committee, ControlWitness, EpochConfig, EpochId, Hash32, HeightConfig},
};

use super::*;
use crate::sumeragi::crypto::{BlsCrypto, KeyPairSigner};
use iroha_crypto::{Algorithm, KeyPair};

pub(crate) fn fixture(size: usize) -> (AvailableBody, AvailabilitySource, AllocationBudget) {
    let crypto = BlsCrypto::new();
    let mut signers: Vec<_> = (1..=4)
        .map(|seed| {
            KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)).unwrap()
        })
        .collect();
    signers.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    let epoch = EpochConfig {
        da_layout: recommended_data_availability_layout(),
        id: EpochId {
            epoch: 0,
            context: Hash32([0xE0; 32]),
        },
        authority_generation: Hash32([0xE1; 32]),
        first_height: 0,
        last_height: u64::MAX,
        leader_seed: Hash32([0xE2; 32]),
    };
    let config = HeightConfig {
        epoch: Box::new(epoch),
        committee: Committee::new(
            signers
                .iter()
                .map(|signer| signer.public_key().clone())
                .collect(),
        )
        .unwrap(),
        params: ChainParams::default(),
    };
    let budget = AllocationBudget::new(1 << 25);
    let mut bytes = ChargedBuffer::new(size, &budget).unwrap();
    for index in 0..size {
        bytes.push_reserved((index % 251) as u8);
    }
    let payload = PayloadBytes::from_charged(bytes, &budget)
        .unwrap_or_else(|_| panic!("original payload admission"));
    let instance = Hash32([0x53; 32]);
    let header = BlockHeader {
        instance,
        epoch: config.epoch.id,
        height: 1,
        origin_view: 0,
        parent_hash: Hash32([1; 32]),
        parent_result: Hash32([2; 32]),
        payload_hash: iroha_sumeragi::preimage::payload_hash(&crypto, payload.as_slice()),
        availability_digest: Hash32::ZERO,
        payload_len: u32::try_from(size).unwrap(),
        proposer: 0,
        skipped_leaders: vec![],
        control_witness: ControlWitness::empty(),
    };
    let authored = PayloadAuthoring::new(header, payload)
        .complete(instance, &config, &budget, &crypto, &signers[0])
        .unwrap_or_else(|_| panic!("authenticated original authoring"));
    let body = authored.body;
    drop(authored.codeword);
    let source = AvailabilitySource::new(
        instance,
        body.header().height,
        body.header().hash(&crypto),
        config,
    )
    .unwrap();
    (body, source, budget)
}

pub(crate) fn decode_record(
    bytes: &[u8],
    budget: &AllocationBudget,
) -> Result<BodyRecord, BodyDecodeError> {
    let mut raw = ChargedBuffer::new(bytes.len(), budget).map_err(|error| {
        BodyDecodeError::Bytes(iroha_sumeragi::message::ByteAdmissionError::Buffer(error))
    })?;
    raw.append(bytes).unwrap();
    BodyRecordDecode::new(raw)
        .complete(budget)
        .map_err(|(_, error)| error)
}

#[test]
fn borrowed_write_matches_the_one_owned_record_and_restores_exact_signed_material() {
    for size in [1, 1025, 23572] {
        let (body, source, budget) = fixture(size);
        let payload_pointer = body.payload().as_slice().as_ptr();
        let frame_pointer = body.availability().as_slice().as_ptr();
        let owned = BodyRecord {
            header: body.header().clone(),
            availability: body.availability().clone(),
            payload: body.payload().clone(),
        };
        let expected = norito::encode_canonical(&owned).unwrap();
        let expected_length = norito::canonical_frame_len(&owned).unwrap();
        let reserved = budget.reserved_bytes();
        let mut prepared = PreparedBodyWrite::new(body);
        let encoded = prepared.prepare(&budget).unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), expected_length);
        assert_eq!(budget.reserved_bytes(), reserved + expected_length);
        let output_pointer = encoded.as_ptr();
        let decoded: BodyRecord = decode_record(encoded, &budget).unwrap();
        assert_eq!(decoded.header(), owned.header());
        assert!(decoded.availability.admitted_to(&budget));
        assert!(decoded.payload.admitted_to(&budget));
        let restored = decoded
            .into_restoration(source)
            .complete(&budget, &BlsCrypto::new())
            .unwrap_or_else(|_| panic!("independent source and original authorizations verify"));
        assert_eq!(restored, prepared.body);
        assert_eq!(
            prepared.body().payload().as_slice().as_ptr(),
            payload_pointer
        );
        assert_eq!(
            prepared.body().availability().as_slice().as_ptr(),
            frame_pointer
        );
        assert_eq!(prepared.prepare(&budget).unwrap().as_ptr(), output_pointer);
    }
}

#[test]
fn resource_refusal_retains_original_body_then_allocates_output_once() {
    let (body, _, budget) = fixture(23572);
    let payload = body.payload().as_slice().as_ptr();
    let frame = body.availability().as_slice().as_ptr();
    let length = norito::canonical_frame_len(&BodyRecordRef::from(&body)).unwrap();
    let retained = budget.reserved_bytes();
    let mut prepared = PreparedBodyWrite::new(body);
    budget.set_limit_bytes(retained + length - 1);
    assert!(matches!(
        prepared.prepare(&budget),
        Err(BodyWriteError::Allocation(_))
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(prepared.bytes.is_none());
    assert_eq!(prepared.body().payload().as_slice().as_ptr(), payload);
    assert_eq!(prepared.body().availability().as_slice().as_ptr(), frame);
    budget.set_limit_bytes(retained + length);
    let pointer = prepared.prepare(&budget).unwrap().as_ptr();
    let peak = budget.peak_reserved_bytes();
    for _ in 0..3 {
        assert_eq!(prepared.prepare(&budget).unwrap().as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), retained + length);
        assert_eq!(budget.peak_reserved_bytes(), peak);
    }
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn foreign_pool_neither_admits_nor_borrows_original_output() {
    let (body, _, budget) = fixture(1025);
    let foreign = AllocationBudget::new(1 << 25);
    let mut prepared = PreparedBodyWrite::new(body);
    assert!(matches!(
        prepared.prepare(&foreign),
        Err(BodyWriteError::ForeignBudget)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    let pointer = prepared.prepare(&budget).unwrap().as_ptr();
    let reserved = budget.reserved_bytes();
    assert!(matches!(
        prepared.prepare(&foreign),
        Err(BodyWriteError::ForeignBudget)
    ));
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(prepared.prepare(&budget).unwrap().as_ptr(), pointer);
}

#[test]
fn fixed_writer_refuses_growth_without_losing_original_backing() {
    let budget = AllocationBudget::new(3);
    let mut bytes = ChargedBuffer::new(3, &budget).unwrap();
    let mut writer = FixedWriter(&mut bytes);
    writer.write_all(b"ab").unwrap();
    writer.flush().unwrap();
    let pointer = writer.0.as_slice().as_ptr();
    assert!(writer.write_all(b"cd").is_err());
    assert_eq!(writer.0.as_slice(), b"ab");
    assert_eq!(writer.0.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), 3);
    writer.write_all(b"c").unwrap();
    assert_eq!(writer.0.as_slice(), b"abc");
}

#[test]
fn decoded_record_cannot_supply_its_own_source_authority() {
    let (body, source, budget) = fixture(1025);
    let mut prepared = PreparedBodyWrite::new(body);
    let decoded: BodyRecord = decode_record(prepared.prepare(&budget).unwrap(), &budget).unwrap();
    let wrong_source = AvailabilitySource::new(
        source.instance(),
        source.height(),
        Hash32([99; 32]),
        source.config().clone(),
    )
    .unwrap();
    let reserved = budget.reserved_bytes();
    let (job, error) = decoded
        .into_restoration(wrong_source.clone())
        .complete(&budget, &BlsCrypto::new())
        .err()
        .expect("foreign expected identity is rejected");
    assert!(!error.is_local_refusal());
    assert_eq!(job.source(), &wrong_source);
    assert_eq!(
        budget.reserved_bytes(),
        reserved,
        "identity rejects before admission"
    );
}

#[test]
fn complete_decode_requires_mandatory_table_and_rejects_truncation_or_extra_bytes() {
    let (body, source, budget) = fixture(1);
    let mut prepared = PreparedBodyWrite::new(body);
    let original = prepared.prepare(&budget).unwrap();
    for length in [0, 1, original.len() - 1] {
        assert!(decode_record(&original[..length], &budget).is_err());
    }
    let mut extra = original.to_vec();
    extra.push(0);
    assert!(decode_record(&extra, &budget).is_err());
    let mut decoded: BodyRecord = decode_record(original, &budget).unwrap();
    let mut table = decoded.availability.as_slice().to_vec();
    let last = table.len() - 1;
    table[last] ^= 1;
    decoded.availability = AvailabilityFrame::from_untrusted(table).unwrap();
    let (_, error) = decoded
        .into_restoration(source)
        .complete(&budget, &BlsCrypto::new())
        .err()
        .expect("corrupt original signature rejects");
    assert!(!error.is_local_refusal());
}
