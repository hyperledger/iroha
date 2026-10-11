//! Real BLS lane records, exact wire parity, context rejection and retained write funding.

use iroha_crypto::{Algorithm, KeyPair, bls_normal_pop_prove};
use iroha_sumeragi::{
    crypto::{Crypto, Signer, Verifier},
    types::{AggregateSignature, Bitmap, Hash32, SIGNATURE_LEN},
};

use super::*;
use crate::sumeragi::{
    body_record,
    crypto::{BlsCrypto, KeyPairSigner},
};

pub(in crate::sumeragi) fn fixture(
    size: usize,
) -> (
    AvailableBody,
    Qc,
    AvailabilitySource,
    AllocationBudget,
    BlsCrypto,
) {
    let (body, source, budget) = body_record::tests::fixture(size);
    let crypto = BlsCrypto::new();
    let pairs: Vec<_> = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    let mut signers = Vec::new();
    for pair in &pairs {
        crypto
            .admit(
                pair.public_key(),
                &bls_normal_pop_prove(pair.private_key()).unwrap(),
            )
            .unwrap();
        signers.push(KeyPairSigner::new(pair).unwrap());
    }
    signers.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let mut qc = Qc {
        kind: VoteKind::Commit,
        instance: body.header().instance,
        epoch: body.header().epoch,
        height: body.header().height,
        view: body.header().origin_view,
        block_hash: body.hash(&crypto),
        result: Hash32([3; 32]),
        signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
        agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
    };
    let signatures: Vec<_> = signers[..3]
        .iter()
        .map(|signer| signer.sign(&qc.preimage()))
        .collect();
    qc.agg_sig = crypto.aggregate(&signatures);
    (body, qc, source, budget, crypto)
}

pub(in crate::sumeragi) fn verify(source: &AvailabilitySource, qc: &Qc, crypto: &BlsCrypto) {
    let verifier = Verifier::new(
        crypto,
        &qc.instance,
        &source.config().epoch.id,
        &source.config().committee,
    );
    verifier.verify_qc(qc).unwrap();
}

pub(super) fn raw_job(
    size: usize,
) -> (
    LaneRecordDecode,
    AvailabilitySource,
    AllocationBudget,
    BlsCrypto,
) {
    let (body, qc, source, budget, crypto) = fixture(size);
    verify(&source, &qc, &crypto);
    let mut prepared = PreparedLaneWrite::new(body, qc);
    prepared.check_context(&source, &crypto).unwrap();
    let bytes = prepared.prepare(&budget).unwrap();
    let mut raw = ChargedBuffer::new(bytes.len(), &budget).unwrap();
    raw.append(bytes).unwrap();
    drop(prepared);
    (LaneRecordDecode::new(raw), source, budget, crypto)
}

#[test]
fn exact_owned_borrowed_wire_roundtrip_preserves_real_bls_body_and_qc() {
    for size in [1, 1025, 23572] {
        let (body, qc, source, budget, crypto) = fixture(size);
        verify(&source, &qc, &crypto);
        let expected = norito::encode_canonical(&LaneRecord {
            header: body.header().clone(),
            availability: body.availability().clone(),
            payload: body.payload().clone(),
            commit_qc: qc.clone(),
        })
        .unwrap();
        assert_eq!(
            norito::encode_canonical(&QcRef::from(&qc)).unwrap(),
            norito::encode_canonical(&qc).unwrap()
        );
        let mut prepared = PreparedLaneWrite::new(body, qc);
        prepared.check_context(&source, &crypto).unwrap();
        let encoded = prepared.prepare(&budget).unwrap();
        assert_eq!(encoded, expected);
        let mut raw = ChargedBuffer::new(encoded.len(), &budget).unwrap();
        raw.append(encoded).unwrap();
        let record = LaneRecordDecode::new(raw)
            .complete(&budget)
            .unwrap_or_else(|_| panic!("funded canonical decode"));
        record.check_context(&source, &crypto).unwrap();
        assert_eq!(record.header(), prepared.body().header());
        assert_eq!(record.availability(), prepared.body().availability());
        assert_eq!(record.commit_qc(), prepared.commit_qc());
        verify(&source, record.commit_qc(), &crypto);
        let (restoration, qc) = record.into_restoration(source);
        let restored = restoration
            .complete(&budget, &crypto)
            .unwrap_or_else(|_| panic!("actual full-codeword restoration"));
        assert_eq!(&restored, prepared.body());
        assert_eq!(&qc, prepared.commit_qc());
    }
}

#[test]
fn retained_write_refusal_and_foreign_pool_preserve_original_pointers() {
    let (body, qc, source, budget, crypto) = fixture(1025);
    let pointers = (
        body.payload().as_slice().as_ptr(),
        body.availability().as_slice().as_ptr(),
    );
    let mut prepared = PreparedLaneWrite::new(body, qc);
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    assert!(matches!(
        prepared.prepare(&budget),
        Err(LaneRecordError::Allocation(_))
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    let foreign = AllocationBudget::new(1 << 25);
    assert!(matches!(
        prepared.prepare(&foreign),
        Err(LaneRecordError::ForeignBudget)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    budget.set_limit_bytes(1 << 25);
    prepared.check_context(&source, &crypto).unwrap();
    let pointer = prepared.prepare(&budget).unwrap().as_ptr();
    let charged = budget.reserved_bytes();
    for _ in 0..3 {
        assert_eq!(prepared.prepare(&budget).unwrap().as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), charged);
    }
    assert_eq!(
        pointers,
        (
            prepared.body().payload().as_slice().as_ptr(),
            prepared.body().availability().as_slice().as_ptr(),
        )
    );
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn context_mismatches_and_foreign_body_never_prepare_an_output() {
    for changed in 0..4 {
        let (body, mut qc, _, budget, _) = fixture(1);
        match changed {
            0 => qc.kind = VoteKind::Prepare,
            1 => qc.instance = Hash32([9; 32]),
            2 => qc.epoch.context = Hash32([9; 32]),
            _ => qc.height += 1,
        }
        let before = budget.reserved_bytes();
        let mut prepared = PreparedLaneWrite::new(body, qc);
        assert!(matches!(
            prepared.prepare(&budget),
            Err(LaneRecordError::Context)
        ));
        assert!(prepared.bytes.is_none());
        assert_eq!(budget.reserved_bytes(), before);
    }
    let (body, qc, source, original, crypto) = fixture(1);
    let budget = AllocationBudget::new(1 << 20);
    assert!(body.admitted_to(&original));
    let mut prepared = PreparedLaneWrite::new(body, qc);
    assert!(matches!(
        prepared.prepare(&budget),
        Err(LaneRecordError::ForeignBudget)
    ));
    assert!(prepared.bytes.is_none());
    let wrong = AvailabilitySource::new(
        source.instance(),
        source.height(),
        Hash32([9; 32]),
        source.config().clone(),
    )
    .unwrap();
    assert!(matches!(
        prepared.check_context(&wrong, &crypto),
        Err(LaneRecordError::Context)
    ));
}

#[test]
fn prepared_lane_parts_move_original_metadata_and_bulk_owners_without_readmission() {
    let (body, qc, _source, budget, _crypto) = fixture(1025);
    let payload = body.payload().as_slice().as_ptr();
    let availability = body.availability().as_slice().as_ptr();
    let epoch = std::ptr::from_ref(&*body.source().config().epoch);
    let signers = qc.signers.as_bytes().as_ptr();
    let mut prepared = PreparedLaneWrite::new(body, qc);
    let retained = budget.reserved_bytes();
    let output_len = prepared.prepare(&budget).unwrap().len();
    assert_eq!(budget.reserved_bytes(), retained + output_len);
    budget.set_limit_bytes(0);
    let (body, qc) = prepared.into_parts();
    assert_eq!(body.payload().as_slice().as_ptr(), payload);
    assert_eq!(body.availability().as_slice().as_ptr(), availability);
    assert_eq!(std::ptr::from_ref(&*body.source().config().epoch), epoch);
    assert_eq!(qc.signers.as_bytes().as_ptr(), signers);
    assert!(body.admitted_to(&budget));
    assert_eq!(budget.reserved_bytes(), retained);
    drop(body);
    drop(qc);
    assert_eq!(budget.reserved_bytes(), 0);
}
