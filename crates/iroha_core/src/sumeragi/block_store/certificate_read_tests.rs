//! Real-model certificate parsing, exact retained admission and corruption controls.

use super::*;
use iroha_data_model::{
    block::{CommitCertificate, decode_framed_signed_block},
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
};

fn fixture() -> iroha_data_model::block::SharedSignedBlock {
    let fixture = NativeFinalityFixture::new();
    crate::block::reserve_block_for_tests()
        .initialize(decode_framed_signed_block(&fixture.latest().block_wire).unwrap())
}

fn with_parts(
    source: &SignedBlock,
    header: Vec<u8>,
    qc: Vec<u8>,
    table: Vec<u8>,
) -> iroha_data_model::block::SharedSignedBlock {
    crate::block::reserve_block_for_tests().initialize(
        source
            .clone()
            .with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                header,
                qc,
                source
                    .commit_certificate()
                    .unwrap()
                    .result_preimage()
                    .to_vec(),
                table,
            ))),
    )
}

#[test]
fn exact_canonical_artifacts_retain_original_source_and_original_pool() {
    let source = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("valid canonical artifacts"));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &source,
        &decoded.source
    ));
    assert!(decoded.availability.admitted_to(&budget));
    let original = source.commit_certificate().unwrap();
    assert_eq!(
        norito::encode_canonical(&decoded.header).unwrap(),
        original.consensus_header()
    );
    assert_eq!(
        norito::encode_canonical(&decoded.commit_qc).unwrap(),
        original.commit_qc()
    );
    assert_eq!(
        norito::encode_canonical(&decoded.availability).unwrap(),
        original.availability()
    );
    drop(decoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn every_backing_and_shared_control_refusal_retains_exact_original_owners() {
    let base = fixture();
    let measure = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(base.clone(), measure.clone())
        .complete(&measure)
        .unwrap_or_else(|_| panic!("measure actual availability control"));
    let table_len = decoded.availability.as_slice().len();
    let table_total = measure.reserved_bytes();
    assert!(table_total > table_len);
    drop(decoded);
    assert_eq!(measure.reserved_bytes(), 0);

    let source = base;
    let budget = AllocationBudget::new(0);
    let (job, error) = CertificateRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .err()
        .expect("table backing refuses");
    assert!(matches!(error, CertificateReadError::Admission(ref e) if e.is_local_refusal()));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &source
    ));
    assert!(job.table_backing.is_none());
    assert_eq!(
        job.retained_owners_for_test(),
        (std::ptr::from_ref(source.as_ref()), None)
    );

    budget.set_limit_bytes(table_len);
    let (job, error) = job
        .complete(&budget)
        .err()
        .expect("table shared control refuses");
    assert!(matches!(error, CertificateReadError::Admission(ref e) if e.is_local_refusal()));
    let table_pointer = job.table_backing.as_ref().unwrap().as_slice().as_ptr();
    assert_eq!(
        job.retained_owners_for_test(),
        (std::ptr::from_ref(source.as_ref()), Some(table_pointer))
    );
    assert_eq!(budget.reserved_bytes(), table_len);
    let (job, _) = job.complete(&budget).err().expect("same table retained");
    assert_eq!(
        job.table_backing.as_ref().unwrap().as_slice().as_ptr(),
        table_pointer
    );

    budget.set_limit_bytes(table_total);
    let decoded = job
        .complete(&budget)
        .unwrap_or_else(|_| panic!("all original owners complete"));
    assert_eq!(decoded.availability.as_slice().as_ptr(), table_pointer);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &decoded.source,
        &source
    ));
    drop(decoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn foreign_pool_cannot_replace_captured_pool_before_or_during_admission() {
    let source = fixture();
    let budget = AllocationBudget::new(0);
    let foreign = AllocationBudget::new(1 << 25);
    let (job, error) = CertificateRead::new(source.clone(), budget.clone())
        .complete(&foreign)
        .err()
        .expect("foreign initial pool");
    assert!(matches!(error, CertificateReadError::ForeignBudget));
    assert!(job.layout.is_none());
    let (job, _) = job.complete(&budget).err().expect("original refusal");
    let (job, error) = job.complete(&foreign).err().expect("foreign retry pool");
    assert!(matches!(error, CertificateReadError::ForeignBudget));
    assert_eq!(foreign.reserved_bytes(), 0);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &source
    ));
    budget.set_limit_bytes(1 << 25);
    let decoded = job
        .complete(&budget)
        .unwrap_or_else(|_| panic!("original pool resumes"));
    assert!(decoded.availability.admitted_to(&budget));
    assert!(!decoded.availability.admitted_to(&foreign));
}

#[test]
fn malformed_frames_remain_corruption_without_funded_destination_or_absence() {
    let source = fixture();
    let c = source.commit_certificate().unwrap();
    let parts = [c.consensus_header(), c.commit_qc(), c.availability()];
    for index in 0..3 {
        for replacement in [vec![], vec![1, 2, 3], [parts[index], &[0]].concat()] {
            let mut changed = parts.map(<[u8]>::to_vec);
            changed[index] = replacement;
            let [header, qc, table] = changed;
            let changed = with_parts(&source, header, qc, table);
            let budget = AllocationBudget::new(1 << 25);
            let (job, error) = CertificateRead::new(changed.clone(), budget.clone())
                .complete(&budget)
                .err()
                .expect("malformed canonical part");
            assert!(matches!(error, CertificateReadError::Decode(_)));
            assert_eq!(budget.reserved_bytes(), 0);
            let (job, error) = job
                .complete(&budget)
                .err()
                .expect("same corruption on retry");
            assert!(matches!(error, CertificateReadError::Decode(_)));
            assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                job.source(),
                &changed
            ));
        }
    }
}

#[test]
fn malformed_signed_table_count_and_header_cap_reject_before_output_allocation() {
    let source = fixture();
    let c = source.commit_certificate().unwrap();
    let original: AvailabilityFrame = norito::decode_canonical(c.availability()).unwrap();
    for count in [0u32, 1, u32::MAX] {
        let mut bytes = original.as_slice().to_vec();
        bytes[..4].copy_from_slice(&count.to_be_bytes());
        let table =
            norito::encode_canonical(&AvailabilityFrame::from_untrusted(bytes).unwrap()).unwrap();
        let source = with_parts(
            &source,
            c.consensus_header().to_vec(),
            c.commit_qc().to_vec(),
            table,
        );
        let budget = AllocationBudget::new(1 << 25);
        let (_, error) = CertificateRead::new(source, budget.clone())
            .complete(&budget)
            .err()
            .unwrap();
        assert!(matches!(error, CertificateReadError::Decode(_)));
        assert_eq!(budget.reserved_bytes(), 0);
    }
    assert!(matches!(
        header(&vec![
            0;
            MAX_HEADER_METADATA_BYTES + ncore::Header::SIZE + 1
        ]),
        Err(norito::Error::FieldLengthExceeded { .. })
    ));
}

#[test]
fn absent_certificate_is_an_explicit_error() {
    let source = crate::block::reserve_block_for_tests()
        .initialize(fixture().as_ref().clone().with_commit_certificate(None));
    let budget = AllocationBudget::new(0);
    let (_, error) = CertificateRead::new(source, budget.clone())
        .complete(&budget)
        .err()
        .unwrap();
    assert!(matches!(error, CertificateReadError::MissingCertificate));
    assert_eq!(budget.reserved_bytes(), 0);
}
