//! Actual signed model fixtures projected through the retained stored-body boundary.

use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::crypto::BlsCrypto;
use iroha_data_model::{
    block::{CommitCertificate, decode_framed_signed_block},
    sumeragi_finality::{ScheduledSlot, test_fixtures::NativeFinalityFixture},
};
use iroha_sumeragi::{availability::AvailabilityFrame, types::Hash32};

fn fixture() -> (
    iroha_data_model::block::SharedSignedBlock,
    AvailabilitySource,
    SharedCrypto,
) {
    let fixture = NativeFinalityFixture::new();
    let parent = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("authenticated next fixture authority");
    };
    let source = crate::block::reserve_block_for_tests()
        .initialize(decode_framed_signed_block(&fixture.latest().block_wire).unwrap());
    let header: iroha_sumeragi::message::BlockHeader =
        norito::decode_canonical(source.commit_certificate().unwrap().consensus_header()).unwrap();
    let crypto: SharedCrypto = Arc::new(BlsCrypto::new());
    let authority = AvailabilitySource::new(
        fixture.verifier().instance(),
        2,
        header.hash(&*crypto),
        scheduled.height_config().unwrap(),
    )
    .unwrap();
    (source, authority, crypto)
}

#[test]
fn stored_body_retains_original_certificate_and_projected_payload_across_refusals() {
    let (block, source, crypto) = fixture();
    let measure = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(block.clone(), measure.clone())
        .complete(&measure)
        .unwrap_or_else(|_| panic!("measure actual decoded artifact"));
    let decoded_size = measure.reserved_bytes();
    drop(decoded);
    assert_eq!(measure.reserved_bytes(), 0);
    let budget = AllocationBudget::new(0);
    let mut read = StoredBodyRead::new(
        source.clone(),
        Some(block.clone()),
        budget.clone(),
        crypto.clone(),
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    assert_eq!(read.source(), &source);
    let Stage::Certificate(job) = &read.stage else {
        panic!("same certificate owner")
    };
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &block
    ));

    budget.set_limit_bytes(decoded_size);
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    let Stage::Projecting(job) = &read.stage else {
        panic!("one funded projection")
    };
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &job.source().source,
        &block
    ));
    let table_pointer = job.source().availability.as_slice().as_ptr();
    let payload_len = block.resultless_proposal_wire_len().unwrap();
    budget.set_limit_bytes(decoded_size + payload_len);
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    let held = budget.reserved_bytes();
    assert_eq!(held, decoded_size + payload_len);
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    assert_eq!(budget.reserved_bytes(), held);
    let Stage::Projecting(job) = &read.stage else {
        panic!("same encoded projection")
    };
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &job.source().source,
        &block
    ));
    assert_eq!(job.source().availability.as_slice().as_ptr(), table_pointer);

    budget.set_limit_bytes(1 << 25);
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("original exact body")
    };
    assert_eq!(restoration.source(), &source);
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Completed)));
    let body = restoration
        .complete(&budget, &*crypto)
        .unwrap_or_else(|_| panic!("real signatures and full codeword verify"));
    assert_eq!(body.availability().as_slice().as_ptr(), table_pointer);
    assert_eq!(
        body.payload().as_slice(),
        block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection")
            .encode_wire()
            .unwrap()
    );
    assert!(body.admitted_to(&budget));
    drop(body);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn absence_foreign_pool_and_corrupt_storage_are_separate_outcomes() {
    let (block, source, crypto) = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let mut absent = StoredBodyRead::new(
        source.clone(),
        None,
        budget.clone(),
        crypto.clone(),
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    assert!(matches!(
        absent.poll(&AllocationBudget::new(1 << 25)),
        Err(BodyReadError::ForeignBudget)
    ));
    assert!(matches!(absent.poll(&budget), Ok(BodyReadPoll::Absent)));
    assert!(matches!(
        absent.poll(&budget),
        Err(BodyReadError::Completed)
    ));
    let corrupt = crate::block::reserve_block_for_tests()
        .initialize(block.as_ref().clone().with_commit_certificate(None));
    let mut read = StoredBodyRead::new(
        source,
        Some(corrupt),
        budget.clone(),
        crypto,
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    for _ in 0..2 {
        assert!(
            matches!(read.poll(&budget), Err(BodyReadError::Io(ref e)) if e.kind() == io::ErrorKind::InvalidData)
        );
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn requested_hash_cannot_be_replaced_by_the_stored_certificate() {
    let (block, source, crypto) = fixture();
    let source = AvailabilitySource::new(
        source.instance(),
        source.height(),
        Hash32([0x91; 32]),
        source.config().clone(),
    )
    .unwrap();
    let budget = AllocationBudget::new(1 << 25);
    let mut read = StoredBodyRead::new(
        source.clone(),
        Some(block.clone()),
        budget.clone(),
        crypto,
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    for _ in 0..2 {
        assert!(
            matches!(read.poll(&budget), Err(BodyReadError::Io(ref e)) if e.kind() == io::ErrorKind::InvalidData)
        );
        let Stage::Decoded(decoded) = &read.stage else {
            panic!("keep exact rejected artifact")
        };
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &decoded.source,
            &block
        ));
        assert_eq!(read.source(), &source);
    }
}

#[test]
fn canonical_but_invalid_author_signature_never_becomes_available_custody() {
    let (block, source, crypto) = fixture();
    let old = block.commit_certificate().unwrap();
    let original: AvailabilityFrame = norito::decode_canonical(old.availability()).unwrap();
    let mut table = original.as_slice().to_vec();
    let last = table.len() - 1;
    table[last] ^= 1;
    let table = AvailabilityFrame::from_untrusted(table).unwrap();
    let certificate = CommitCertificate::from_untrusted_parts(
        old.consensus_header().to_vec(),
        old.commit_qc().to_vec(),
        old.result_preimage().to_vec(),
        norito::encode_canonical(&table).unwrap(),
    );
    let changed = crate::block::reserve_block_for_tests().initialize(
        block
            .as_ref()
            .clone()
            .with_commit_certificate(Some(certificate)),
    );
    let budget = AllocationBudget::new(1 << 25);
    let mut read = StoredBodyRead::new(
        source,
        Some(changed),
        budget.clone(),
        crypto.clone(),
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("canonical untrusted input only")
    };
    let (_, error) = restoration
        .complete(&budget, &*crypto)
        .err()
        .expect("actual signature rejection");
    assert!(!error.is_local_refusal());
}

#[test]
fn stored_result_decode_refusal_retains_original_decoded_owners_and_retries() {
    use iroha_data_model::sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES;

    let (block, source, crypto) = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(block.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("original decoded certificate"));
    let table = decoded.availability.as_slice().as_ptr();
    let bitmap = decoded.commit_qc.signers.as_bytes().as_ptr();
    let mut read = StoredBodyRead::from_decoded(
        source.clone(),
        decoded,
        budget.clone(),
        crypto.clone(),
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    let retained = budget.reserved_bytes();
    for _ in 0..2 {
        let outcome = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(96, MAX_RESULT_PREIMAGE_BYTES, usize::MAX, 0, 32),
            || read.poll(&budget),
        );
        let Err(BodyReadError::Deferred(reason)) = outcome else {
            panic!("result decode must refuse locally before projection");
        };
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(
            reason.allocation_refusal().is_none(),
            "Norito scopes do not invent a pool"
        );
        let Stage::Decoded(decoded) = &read.stage else {
            panic!("retain the same original decoded source");
        };
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &decoded.source,
            &block
        ));
        assert_eq!(decoded.availability.as_slice().as_ptr(), table);
        assert_eq!(decoded.commit_qc.signers.as_bytes().as_ptr(), bitmap);
        assert_eq!(read.source(), &source);
        assert_eq!(budget.reserved_bytes(), retained);
    }
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("retry the original input after local decode funding is available");
    };
    let body = restoration
        .complete(&budget, &*crypto)
        .unwrap_or_else(|_| panic!("the genuine signed body still verifies"));
    assert_eq!(body.availability().as_slice().as_ptr(), table);
    assert_eq!(body.source(), &source);
    assert!(body.admitted_to(&budget));
    drop((body, read));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn malformed_result_preimage_remains_terminal_storage_corruption() {
    use iroha_data_model::sumeragi_finality::{CertifiedResultError, CommitmentError};

    let (block, _, _) = fixture();
    let original = block.commit_certificate().unwrap();
    let mut preimage = original.result_preimage().to_vec();
    preimage[iroha_data_model::sumeragi_finality::certified_result::X_LEN] ^= 0xff;
    let certificate = CommitCertificate::from_untrusted_parts(
        original.consensus_header().to_vec(),
        original.commit_qc().to_vec(),
        preimage,
        original.availability().to_vec(),
    );
    let changed = block
        .as_ref()
        .clone()
        .with_commit_certificate(Some(certificate));
    let Attempt::Rejected(error) = super::super::execution::validate(
        &changed,
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    )
    .unwrap_err() else {
        panic!("malformed result must remain terminal");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(matches!(
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<CertifiedResultError>()),
        Some(CertifiedResultError::Body(CommitmentError::Encoding(_)))
    ));
}

#[test]
fn stored_certificate_allocator_refusal_keeps_original_read_and_retries() {
    use crate::test_allocations::refuse_one_layout_during;
    let (block, source, crypto) = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let mut read = StoredBodyRead::new(
        source.clone(),
        Some(Clone::clone(&block)),
        budget.clone(),
        crypto.clone(),
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    let (result, refused) =
        refuse_one_layout_during(std::alloc::Layout::array::<u8>(8).unwrap(), || {
            read.poll(&budget)
        });
    assert!(
        refused,
        "the real canonical bitmap decoder must reach the physical allocator"
    );
    let BodyReadError::Deferred(reason) =
        result.err().expect("physical decoder allocation refuses")
    else {
        panic!("physical allocation failure must remain an operational refusal");
    };
    assert_eq!(
        reason.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(
        reason.allocation_refusal().is_none(),
        "physical failure cannot invent pool custody"
    );
    let Stage::Certificate(job) = &read.stage else {
        panic!("same original certificate read");
    };
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &block
    ));
    assert_eq!(read.source(), &source);
    assert_eq!(budget.reserved_bytes(), 0);
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("original read resumes");
    };
    let body = restoration
        .complete(&budget, &*crypto)
        .unwrap_or_else(|_| panic!("real source, signatures and complete codeword verify"));
    assert_eq!(body.source(), &source);
    drop(body);
    assert_eq!(budget.reserved_bytes(), 0);
}

/// Storage stage of the resource contract (`specs/zk_resource_contract.json`,
/// `block.max_block_bytes`): the stored-body projection is bounded by the committed payload
/// limit of the independently authenticated height. A stored proposal of exactly the limit is
/// restored; under a limit one byte smaller the read ends as storage corruption on every
/// attempt and reserves nothing, so no oversize body is rebuilt from disk.
#[test]
fn stored_body_projection_accepts_the_payload_limit_and_refuses_one_over() {
    let (block, source, crypto) = fixture();
    let payload_len = block.resultless_proposal_wire_len().unwrap();
    assert!(payload_len > 0);
    let with_limit = |max_block_bytes: usize| {
        let mut config = source.config().clone();
        config.params.max_block_bytes = u32::try_from(max_block_bytes).unwrap();
        AvailabilitySource::new(
            source.instance(),
            source.height(),
            source.block_hash(),
            config,
        )
        .unwrap()
    };

    // Exactly the committed limit.
    let budget = AllocationBudget::new(1 << 25);
    let exact = with_limit(payload_len);
    let mut read = StoredBodyRead::new(
        exact.clone(),
        Some(block.clone()),
        budget.clone(),
        crypto.clone(),
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("a stored proposal of exactly the payload limit is restored");
    };
    assert_eq!(restoration.source(), &exact);
    drop((restoration, read));
    assert_eq!(budget.reserved_bytes(), 0);

    // One byte over the committed limit.
    let budget = AllocationBudget::new(1 << 25);
    let mut read = StoredBodyRead::new(
        with_limit(payload_len - 1),
        Some(block.clone()),
        budget.clone(),
        crypto,
        iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    );
    for _ in 0..2 {
        assert!(
            matches!(
                read.poll(&budget),
                Err(BodyReadError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData
            ),
            "one byte over the payload limit is a deterministic storage refusal"
        );
        let Stage::Projecting(job) = &read.stage else {
            panic!("the refused projection keeps its original decoded source");
        };
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &job.source().source,
            &block
        ));
    }
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}
