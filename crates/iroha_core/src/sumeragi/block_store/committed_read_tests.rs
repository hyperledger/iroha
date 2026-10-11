//! Original decoded quorum-certificate ownership across committed-body restoration.
use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::{
    crypto::BlsCrypto,
    schedule::ScheduledSlot,
    test_chain::{CertifiedTestChain, Signers},
};
use iroha_sumeragi::types::HeightConfig;

struct FixedSchedule {
    instance: Hash32,
    config: HeightConfig,
}
impl AvailabilitySchedule for FixedSchedule {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        assert_eq!(height, 10, "the retained source must never change height");
        Ok(Some(self.config.clone()))
    }
}

#[test]
fn committed_read_returns_original_qc_backing_after_projection_refusal_and_retry() {
    let _epoch = crossbeam_epoch::pin();
    let mut chain = CertifiedTestChain::npos_boundary_fixture();
    chain.commit_with(Some(10_000), Vec::new(), Signers::LastThree);
    let parent = chain.committed(9);
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("real parent authenticates the selected authority");
    };
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(scheduled.epoch.committee.iter().map(|member| {
            (
                member.validator.public_key(),
                member.proof_of_possession.as_slice(),
            )
        }))
        .unwrap();
    let schedule = Arc::new(FixedSchedule {
        instance: chain.instance(),
        config: scheduled.height_config().unwrap(),
    });
    let source = chain
        .kura()
        .get_block(
            std::num::NonZeroUsize::new(10).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    let budget = AllocationBudget::new(1 << 27);
    let decoded = CertificateRead::new(Clone::clone(&source), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("real original native certificate"));
    let original_bitmap = decoded.commit_qc.signers.as_bytes().as_ptr();
    let original_signature = decoded.commit_qc.agg_sig;

    assert!(!decoded.commit_qc.signers.as_bytes().is_empty());
    assert_eq!(decoded.commit_qc.signers.count_ones(), 3);

    let original_header = decoded.header.clone();
    let mut read = CommittedRead {
        height: 10,
        budget: budget.clone(),
        crypto,
        schedule,
        phase: Phase::Decoded(decoded),
    };
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    for _ in 0..2 {
        let error = read.poll().unwrap_err();
        assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
        assert!(
            matches!(error, Attempt::Deferred(_)),
            "refusal must not allocate a diagnostic"
        );
        assert_eq!(budget.reserved_bytes(), retained);
    }
    budget.set_limit_bytes(1 << 27);
    let (body, qc) = read.poll().unwrap();
    assert_eq!(body.header(), &original_header);
    assert_eq!(body.source().height(), 10);
    assert_eq!(body.source().instance(), chain.instance());
    assert_eq!(
        qc.signers.as_bytes().as_ptr(),
        original_bitmap,
        "the original decoded bitmap must be moved, never copied"
    );
    assert_eq!(qc.agg_sig, original_signature);

    drop((body, qc, read));
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "all original read owners refund on drop"
    );
}

#[test]
fn body_only_read_discards_invalid_qc_before_untrusted_restoration() {
    use crate::sumeragi::body_read::{BodyReadJob, BodyReadPoll};

    let _epoch = crossbeam_epoch::pin();
    let mut chain = CertifiedTestChain::npos_boundary_fixture();
    chain.commit_with(Some(10_000), Vec::new(), Signers::LastThree);
    let parent = chain.committed(9);
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("actual parent authorizes H10");
    };
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(scheduled.epoch.committee.iter().map(|member| {
            (
                member.validator.public_key(),
                member.proof_of_possession.as_slice(),
            )
        }))
        .unwrap();
    let schedule = FixedSchedule {
        instance: chain.instance(),
        config: scheduled.height_config().unwrap(),
    };
    let original = chain
        .kura()
        .get_block(
            std::num::NonZeroUsize::new(10).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    let budget = AllocationBudget::new(1 << 27);
    let genuine = CertificateRead::new(Clone::clone(&original), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("genuine original quorum"));
    let source =
        certified_source(&schedule, &*crypto, 10, &genuine.header, &genuine.commit_qc).unwrap();
    drop(genuine);
    // The independently selected body remains genuine. Its changed certificate is explicitly
    // inadmissible; this adapter returns only untrusted body-restoration input, never finality.
    let certificate = original.commit_certificate().unwrap();
    let mut changed_qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    changed_qc.agg_sig.0[0] ^= 1;
    let changed = crate::block::reserve_block_for_tests().initialize(
        original.as_ref().clone().with_commit_certificate(Some(
            iroha_data_model::block::CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                norito::encode_canonical(&changed_qc).unwrap(),
                certificate.result_preimage().to_vec(),
                certificate.availability().to_vec(),
            ),
        )),
    );
    let decoded = CertificateRead::new(changed, budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("original certified artifacts"));
    assert!(
        certified_source(&schedule, &*crypto, 10, &decoded.header, &decoded.commit_qc,).is_err(),
        "the changed signature cannot authenticate a native committed body"
    );
    let mut read =
        body_read::StoredBodyRead::from_decoded(source.clone(), decoded, budget.clone(), crypto);
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    assert!(matches!(
        read.poll(&budget).unwrap(),
        BodyReadPoll::Pending(_)
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(matches!(
        read.poll(&AllocationBudget::new(1 << 27)),
        Err(crate::sumeragi::body_read::BodyReadError::ForeignBudget)
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    budget.set_limit_bytes(1 << 27);
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("original projection resumes");
    };
    assert_eq!(read.source(), &source);
    assert!(matches!(
        read.poll(&budget),
        Err(crate::sumeragi::body_read::BodyReadError::Completed)
    ));
    let after_projection = budget.reserved_bytes();
    drop(read);
    assert_eq!(
        budget.reserved_bytes(),
        after_projection,
        "completed job retains no hidden QC owner"
    );
    drop(restoration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn committed_result_decode_refusal_keeps_original_read_slot_and_retries() {
    use iroha_data_model::sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES;

    let _epoch = crossbeam_epoch::pin();
    let mut chain = CertifiedTestChain::npos_boundary_fixture();
    chain.commit_with(Some(10_000), Vec::new(), Signers::LastThree);
    let parent = chain.committed(9);
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("real parent authenticates the selected authority");
    };
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(scheduled.epoch.committee.iter().map(|member| {
            (
                member.validator.public_key(),
                member.proof_of_possession.as_slice(),
            )
        }))
        .unwrap();
    let schedule = Arc::new(FixedSchedule {
        instance: chain.instance(),
        config: scheduled.height_config().unwrap(),
    });

    let block = chain
        .kura()
        .get_block(
            std::num::NonZeroUsize::new(10).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    let budget = AllocationBudget::new(1 << 27);
    let decoded = CertificateRead::new(block.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("original certified source"));
    let source = certified_source(
        &*schedule,
        &*crypto,
        10,
        &decoded.header,
        &decoded.commit_qc,
    )
    .unwrap();
    let bitmap = decoded.commit_qc.signers.as_bytes().as_ptr();
    let signature = decoded.commit_qc.agg_sig;

    let read = CommittedRead {
        height: 10,
        budget: budget.clone(),
        crypto: crypto.clone(),
        schedule: schedule.clone(),
        phase: Phase::Projecting(body_read::StoredBodyRead::from_decoded(
            source.clone(),
            decoded,
            budget.clone(),
            crypto.clone(),
        )),
    };
    let store = KuraBlockStore::new(
        chain.kura().clone(),
        crypto,
        1,
        Staging::new(),
        budget.clone(),
        schedule,
    );
    *store.read.lock() = Some(read);
    let retained = budget.reserved_bytes();
    // A request for another height must first preserve the original refused read.
    for height in [10, 9] {
        let error = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(96, MAX_RESULT_PREIMAGE_BYTES, usize::MAX, 0, 32),
            || store.committed_body(height),
        )
        .unwrap_err();
        assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
        assert!(
            matches!(error, Attempt::Deferred(_)),
            "resource refusal cannot allocate a replacement boxed diagnostic"
        );
        assert_eq!(
            store
                .read
                .lock()
                .as_ref()
                .expect("retain original read slot")
                .height(),
            10
        );
        assert_eq!(budget.reserved_bytes(), retained);
    }
    let (body, qc) = store.committed_body(10).unwrap().unwrap();
    assert_eq!(body.source(), &source);
    assert_eq!(qc.signers.as_bytes().as_ptr(), bitmap);
    assert_eq!(qc.agg_sig, signature);

    assert!(store.read.lock().is_none());
    drop((body, qc, store));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn committed_certificate_allocator_refusal_retains_original_slot_and_retries() {
    use crate::test_allocations::refuse_one_layout_during;
    use iroha_data_model::{
        block::decode_framed_signed_block, sumeragi_finality::test_fixtures::NativeFinalityFixture,
    };
    let fixture = NativeFinalityFixture::new();
    let parent = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("original genesis authenticates successor");
    };
    let source = crate::block::reserve_block_for_tests()
        .initialize(decode_framed_signed_block(&fixture.latest().block_wire).unwrap());
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(
            scheduled
                .epoch
                .committee
                .iter()
                .map(|m| (m.validator.public_key(), m.proof_of_possession.as_slice())),
        )
        .unwrap();
    struct OriginalSchedule {
        instance: Hash32,
        config: HeightConfig,
    }
    impl AvailabilitySchedule for OriginalSchedule {
        fn instance(&self) -> Hash32 {
            self.instance
        }
        fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
            assert_eq!(height, 2);
            Ok(Some(self.config.clone()))
        }
    }
    let budget = AllocationBudget::new(1 << 25);
    let mut read = CommittedRead::new(
        Clone::clone(&source),
        2,
        budget.clone(),
        crypto,
        Arc::new(OriginalSchedule {
            instance: fixture.verifier().instance(),
            config: scheduled.height_config().unwrap(),
        }),
    );
    let owners = read.retained_certificate_owners_for_test().unwrap();
    let (result, refused) =
        refuse_one_layout_during(std::alloc::Layout::array::<u8>(8).unwrap(), || read.poll());
    assert!(
        refused,
        "actual certificate bitmap must reach the fallible allocator"
    );
    let error = result.err().expect("physical decoder allocation refuses");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(matches!(error, Attempt::Deferred(_)));
    assert_eq!(read.retained_certificate_owners_for_test().unwrap(), owners);
    assert_eq!(budget.reserved_bytes(), 0);
    let (body, qc) = read.poll().unwrap();
    assert_eq!(body.source().height(), 2);
    assert_eq!(qc.height, 2);
    drop((body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
}
