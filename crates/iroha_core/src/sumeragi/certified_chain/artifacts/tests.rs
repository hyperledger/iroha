//! Original source, exact bulk funding, retry and certificate-verification parity.

use super::*;
use crate::state::World;
use crate::sumeragi::{
    certified_chain::{
        CertifiedPrefix, PrefixHeader, PrefixQc, QcVerification, VerificationReadError,
    },
    test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_data_model::{block::CommitCertificate, sumeragi_finality::EpochValidationScope};
use iroha_model_base::chain::ChainId;
use std::num::NonZeroUsize;

fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    chain
}
// Keep authenticated genesis setup outside the later certificate temporary frame.
// All plain-prefix assertions borrow the same original heap-owned chain; default
// native stack size and production verification/allocation limits stay unchanged.
#[inline(never)]
fn with_prefix_chain(assert_original: fn(&CertifiedTestChain)) {
    let chain = Box::new(chain());
    assert_original(&chain);
}
fn frame(chain: &CertifiedTestChain, height: usize) -> iroha_data_model::block::SharedSignedBlock {
    chain
        .kura()
        .get_block(
            NonZeroUsize::new(height).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap()
}
fn read(
    source: iroha_data_model::block::SharedSignedBlock,
    budget: &AllocationBudget,
) -> PrefixArtifacts {
    PrefixArtifactsRead::new(source, budget.clone())
        .complete(budget)
        .unwrap_or_else(|(_, error)| panic!("canonical original artifacts: {error}"))
}
fn changed_qc(
    source: &SignedBlock,
    mutate: impl FnOnce(&mut Qc),
) -> iroha_data_model::block::SharedSignedBlock {
    let certificate = source.commit_certificate().unwrap();
    let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    mutate(&mut qc);
    crate::block::reserve_block_for_tests().initialize(source.clone().with_commit_certificate(
        Some(CommitCertificate::from_untrusted_parts(
            certificate.consensus_header().to_vec(),
            norito::encode_canonical(&qc).unwrap(),
            certificate.result_preimage().to_vec(),
            certificate.availability().to_vec(),
        )),
    ))
}

#[test]
fn prefix_artifacts_keep_exact_source_and_all_bulk_owners_in_original_pool() {
    with_prefix_chain(
        assert_prefix_artifacts_keep_exact_source_and_all_bulk_owners_in_original_pool,
    );
}

#[inline(never)]
fn assert_prefix_artifacts_keep_exact_source_and_all_bulk_owners_in_original_pool(
    chain: &CertifiedTestChain,
) {
    let source = frame(chain, 2);
    let budget = AllocationBudget::new(1 << 26);
    let owner = read(Clone::clone(&source), &budget);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        owner.source(),
        &source
    ));
    assert!(owner.payload.admitted_to(&budget));
    assert!(owner.decoded.availability.admitted_to(&budget));
    assert!(owner.belongs_to(&budget));
    assert!(
        !owner.belongs_to(&AllocationBudget::new(1 << 26)),
        "completed prefix artifacts reject a foreign original pool"
    );
    assert!(!owner.payload.admitted_to(&AllocationBudget::new(1 << 26)));
    let mut expected = Vec::new();
    source
        .write_resultless_proposal_wire(&mut expected)
        .unwrap();
    assert_eq!(owner.payload.as_slice(), expected);
    assert_eq!(
        norito::encode_canonical(&*owner.decoded.commit_qc).unwrap(),
        source.commit_certificate().unwrap().commit_qc()
    );
    assert!(budget.reserved_bytes() > expected.len() + owner.decoded.availability.as_slice().len());
    let retained = budget.reserved_bytes();
    let header = std::ptr::from_ref(&**owner.header());
    let bitmap = owner.decoded.commit_qc.signers.as_bytes().as_ptr();
    let table = owner.decoded.availability.as_slice().as_ptr();
    let payload = owner.payload.as_slice().as_ptr();
    let mut shared = None;
    assert_eq!(
        crate::test_allocations::allocations_during(|| shared = Some(owner.clone())),
        0
    );
    drop(owner);
    assert_eq!(budget.reserved_bytes(), retained);
    let shared = shared.unwrap();
    assert_eq!(std::ptr::from_ref(&**shared.header()), header);
    assert_eq!(shared.decoded.commit_qc.signers.as_bytes().as_ptr(), bitmap);
    assert_eq!(shared.decoded.availability.as_slice().as_ptr(), table);
    assert_eq!(shared.payload.as_slice().as_ptr(), payload);
    drop(shared);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prefix_artifacts_refusal_keeps_table_and_completed_projection() {
    with_prefix_chain(assert_prefix_artifacts_refusal_keeps_table_and_completed_projection);
}

#[inline(never)]
fn assert_prefix_artifacts_refusal_keeps_table_and_completed_projection(
    chain: &CertifiedTestChain,
) {
    let source = frame(chain, 2);
    let measure = AllocationBudget::new(1 << 26);
    let decoded = CertificateRead::new(Clone::clone(&source), measure.clone())
        .complete_for_prefix(&measure)
        .unwrap_or_else(|_| panic!("bounded candidate"));
    let certificate_bytes = measure.reserved_bytes();
    let metadata_bytes = decoded.header.allocation_bytes() + decoded.commit_qc.allocation_bytes();
    let table_len = decoded.availability.as_slice().len();
    drop(decoded);
    let measured = read(Clone::clone(&source), &measure);
    let full_bytes = measure.reserved_bytes();
    let payload_len = measured.payload.as_slice().len();
    drop(measured);
    assert_eq!(measure.reserved_bytes(), 0);

    let budget = AllocationBudget::new(0);
    let (job, error) = PrefixArtifactsRead::new(Clone::clone(&source), budget.clone())
        .complete(&budget)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(metadata_bytes + table_len);
    let (job, error) = job.complete(&budget).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    let Stage::Certificate(ref partial) = job.stage else {
        panic!("table control refused")
    };
    let originals = partial.retained_owners_for_test();
    assert_eq!(originals.0, std::ptr::from_ref(source.as_ref()));
    assert!(originals.1.is_some());
    let (job, _) = job.complete(&budget).err().unwrap();
    let Stage::Certificate(ref partial) = job.stage else {
        panic!("same certificate job")
    };
    assert_eq!(partial.retained_owners_for_test(), originals);

    budget.set_limit_bytes(certificate_bytes);
    let (job, error) = job.complete(&budget).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    let Stage::Projecting(ref partial) = job.stage else {
        panic!("payload backing refused")
    };
    let table = partial.source().availability.as_slice().as_ptr();
    assert_eq!(Some(table), originals.1);
    assert_eq!(budget.reserved_bytes(), certificate_bytes);

    budget.set_limit_bytes(certificate_bytes + payload_len);
    let (job, error) = job.complete(&budget).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(budget.reserved_bytes(), certificate_bytes + payload_len);
    let (job, _) = job.complete(&budget).err().unwrap();
    assert_eq!(budget.reserved_bytes(), certificate_bytes + payload_len);
    budget.set_limit_bytes(full_bytes);
    let owner = job
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("retry: {error}"));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        owner.source(),
        &source
    ));
    assert_eq!(owner.decoded.availability.as_slice().as_ptr(), table);
    assert_eq!(budget.reserved_bytes(), full_bytes);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prefix_artifacts_reject_foreign_pool_and_drop_partial_owners_once() {
    with_prefix_chain(assert_prefix_artifacts_reject_foreign_pool_and_drop_partial_owners_once);
}

#[inline(never)]
fn assert_prefix_artifacts_reject_foreign_pool_and_drop_partial_owners_once(
    chain: &CertifiedTestChain,
) {
    let source = frame(chain, 2);
    let measure = AllocationBudget::new(1 << 26);
    let owner = read(Clone::clone(&source), &measure);
    let table_len = owner.decoded.availability.as_slice().len();
    let metadata_bytes =
        owner.decoded.header.allocation_bytes() + owner.decoded.commit_qc.allocation_bytes();
    drop(owner);
    let budget = AllocationBudget::new(metadata_bytes + table_len);
    let foreign = AllocationBudget::new(1 << 26);
    let (job, error) = PrefixArtifactsRead::new(source, budget.clone())
        .complete(&foreign)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
    let (job, error) = job.complete(&budget).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(budget.reserved_bytes(), metadata_bytes + table_len);
    let (job, error) = job.complete(&foreign).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(budget.reserved_bytes(), metadata_bytes + table_len);
    drop(job);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prefix_artifacts_cannot_be_rebound_to_equal_hash_carrier_or_changed_header() {
    with_prefix_chain(
        assert_prefix_artifacts_cannot_be_rebound_to_equal_hash_carrier_or_changed_header,
    );
}

#[test]
fn admitted_prefix_rejects_foreign_completed_metadata_before_frame_allocation() {
    with_prefix_chain(
        assert_admitted_prefix_rejects_foreign_completed_metadata_before_frame_allocation,
    );
}

#[inline(never)]
fn assert_admitted_prefix_rejects_foreign_completed_metadata_before_frame_allocation(
    chain: &CertifiedTestChain,
) {
    use crate::{
        execution_attempt::ExecutionAttemptError, sumeragi::certified_chain::AdmittedPrefixPush,
    };
    let budget = AllocationBudget::new(32 << 20);
    let foreign = AllocationBudget::new(32 << 20);
    let mut prefix = CertifiedPrefix::new_admitted(
        chain.state().chain_id_ref(),
        chain.network_id(),
        frame(chain, 1),
        &budget,
    )
    .unwrap();
    let original_tip = prefix.as_slice()[0].prefix.tip.id();
    let artifacts = read(frame(chain, 2), &foreign);
    let original_bytes = budget.reserved_bytes();
    let foreign_bytes = foreign.reserved_bytes();
    let mut read = AdmittedPrefixPush::default();
    let mut outcome = None;
    let allocations = crate::test_allocations::allocations_during(|| {
        outcome = Some(read.complete_prepared_with_finish(
            &mut prefix.as_mut_slice()[0],
            &artifacts,
            &budget,
            |_| (),
        ));
    });
    assert!(
        matches!(outcome, Some(Err(ExecutionAttemptError::Deferred(ref original)))
        if original.allocation_refusal().is_none()),
        "HC955 prefix advancement rejects foreign metadata before allocating"
    );
    assert_eq!(allocations, 0);
    assert!(read.frame.committed.is_none() && read.frame.result.is_none());
    assert_eq!(prefix.as_slice()[0].prefix.tip.id(), original_tip);
    assert_eq!(budget.reserved_bytes(), original_bytes);
    assert_eq!(foreign.reserved_bytes(), foreign_bytes);
    drop((artifacts, prefix, read));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[inline(never)]
fn assert_prefix_artifacts_cannot_be_rebound_to_equal_hash_carrier_or_changed_header(
    chain: &CertifiedTestChain,
) {
    let source = frame(chain, 2);
    let budget = AllocationBudget::new(1 << 26);
    let owner = read(Clone::clone(&source), &budget);
    let replacement = crate::block::reserve_block_for_tests().initialize(source.as_ref().clone());
    assert_eq!(replacement.hash(), source.hash());
    let local = |result: Result<_, VerificationReadError>| {
        matches!(result, Err(VerificationReadError::Deferred(original))
            if original.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation
                && original.allocation_refusal().is_none())
    };
    // Carrier and funded header identity are local custody, never a verdict on equal bytes.
    let header = PrefixHeader::Funded(owner.decoded.header.clone());
    assert!(local(owner.into_parts(&replacement, &header)));
    drop(header);
    let owner = read(Clone::clone(&source), &budget);
    let other = read(Clone::clone(&source), &budget);
    assert_eq!(*other.decoded.header, *owner.decoded.header);
    let header = PrefixHeader::Funded(other.decoded.header.clone());
    assert!(local(owner.into_parts(&source, &header)));
    drop((header, other));
    // An independently decoded header must equal the sole funded decoder's value.
    let owner = read(Clone::clone(&source), &budget);
    let mut header = (*owner.decoded.header).clone();
    header.origin_view += 1;
    assert!(matches!(
        owner.into_parts(&source, &PrefixHeader::Decoded(header)),
        Err(VerificationReadError::Source(
            ChainReadError::HeaderMismatch { height: 2 }
        ))
    ));
    let owner = read(Clone::clone(&source), &budget);
    let header = PrefixHeader::Decoded((*owner.decoded.header).clone());
    assert!(owner.into_parts(&source, &header).is_ok());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn funded_prefix_keeps_quorum_checks_and_matches_portable_prefix() {
    with_prefix_chain(assert_funded_prefix_keeps_quorum_checks_and_matches_portable_prefix);
}

#[inline(never)]
fn assert_funded_prefix_keeps_quorum_checks_and_matches_portable_prefix(
    chain: &CertifiedTestChain,
) {
    let id = chain.state().chain_id_ref();
    let mut funded = CertifiedPrefix::new(id, chain.network_id(), frame(chain, 1)).unwrap();
    let mut portable = CertifiedPrefix::new(id, chain.network_id(), frame(chain, 1)).unwrap();
    let budget = AllocationBudget::new(1 << 26);
    let bad = changed_qc(&frame(chain, 2), |qc| qc.agg_sig.0[0] ^= 1);
    assert!(funded.push_prepared(read(bad, &budget)).is_err());
    assert_eq!(
        funded.prefix.tip.height(),
        1,
        "invalid signature cannot advance cursor"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let original = frame(chain, 2);
    let certificate = original.commit_certificate().unwrap();
    let mut table: AvailabilityFrame =
        norito::decode_canonical(certificate.availability()).unwrap();
    let mut bytes = table.as_slice().to_vec();
    bytes[10] ^= 1;
    table = AvailabilityFrame::from_untrusted(bytes).unwrap();
    let tampered_value = crate::block::reserve_block_for_tests().initialize(
        original.as_ref().clone().with_commit_certificate(Some(
            CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                certificate.commit_qc().to_vec(),
                certificate.result_preimage().to_vec(),
                norito::encode_canonical(&table).unwrap(),
            ),
        )),
    );
    assert!(
        funded.push_prepared(read(tampered_value, &budget)).is_err(),
        "signed table remains verified"
    );
    assert_eq!(funded.prefix.tip.height(), 1);
    assert_eq!(budget.reserved_bytes(), 0);
    for height in 2..=3 {
        let (actual, anchor) = funded
            .push_prepared(read(frame(chain, height), &budget))
            .unwrap()
            .into_parts();
        let (expected, expected_anchor) = portable.push(frame(chain, height)).unwrap().into_parts();
        assert_eq!(actual.verification(), QcVerification::Verified);
        assert_eq!(actual.core_hash(), expected.core_hash());
        assert_eq!(actual.result(), expected.result());
        assert_eq!(actual.commit_qc(), expected.commit_qc());
        assert_eq!(
            anchor.map(|a| a.successor()),
            expected_anchor.map(|a| a.successor())
        );
        drop(actual);
        // The tip keeps the sole funded header owner its frame was verified with.
        assert_eq!(
            budget.reserved_bytes(),
            retained_header_bytes(&funded.prefix.tip)
        );
    }
    drop(funded);
    assert_eq!(budget.reserved_bytes(), 0);
}

// The exact funded header graph that a prepared prefix tip retains in the original pool.
fn retained_header_bytes(tip: &crate::sumeragi::certified_chain::CommittedBlock) -> usize {
    match tip.header.as_ref().expect("non-genesis prepared tip") {
        PrefixHeader::Funded(header) => header.allocation_bytes(),
        PrefixHeader::Decoded(_) => panic!("a prepared push retains its sole funded header owner"),
    }
}

// Keep the authentic genesis/boundary constructor out of later certificate temporary
// frames. The chain remains one heap owner; each assertion gets only its original borrow.
// Default native test stack and every production allocation/verification path are unchanged.
#[inline(never)]
fn with_funded_original_boundary(assert_original: fn(&CertifiedTestChain)) {
    // A global epoch pin cannot postpone release of the reader's actual artifact owners.
    let _epoch = crossbeam_epoch::pin();
    let mut chain = Box::new(CertifiedTestChain::npos_boundary_fixture());
    chain.commit_with(Some(10_000), Vec::new(), Signers::LastThree);
    assert_original(&chain);
}

#[test]
fn funded_boundary_keeps_original_certificate_without_application_seals_until_receipt_drop() {
    with_funded_original_boundary(
        assert_funded_boundary_keeps_original_certificate_without_application_seals_until_receipt_drop,
    );
}

#[inline(never)]
fn assert_funded_boundary_keeps_original_certificate_without_application_seals_until_receipt_drop(
    chain: &CertifiedTestChain,
) {
    let mut prefix = CertifiedPrefix::new(
        &ChainId::from("sumeragi-certified-test-chain"),
        chain.network_id(),
        frame(chain, 1),
    )
    .unwrap();
    let budget = AllocationBudget::new(1 << 26);
    for height in 2..10 {
        prefix
            .push_prepared(read(frame(chain, height), &budget))
            .unwrap();
    }
    assert_eq!(
        budget.reserved_bytes(),
        retained_header_bytes(&prefix.prefix.tip)
    );
    let original = frame(chain, 10);
    let tampered = changed_qc(&original, |qc| qc.agg_sig.0[0] ^= 1);
    assert!(matches!(
        prefix.push_prepared(read(tampered, &budget)),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Certificate { .. }
        ))
    ));
    assert_eq!(prefix.prefix.tip.height(), 9);
    let artifacts = read(original, &budget);
    assert!(budget.reserved_bytes() > 0);
    let (receipt, _) = prefix.push_prepared(artifacts).unwrap().into_parts();
    let qc = receipt.commit_qc().unwrap();
    assert_eq!(qc.signers.count_ones(), 3);

    // The receipt and new tip share the sole funded header owner, and the receipt keeps the
    // funded QC owner. The transient original-funded table and proposal retire after full
    // availability verification.
    let Some(PrefixQc::Funded(funded_qc)) = receipt.commit_qc.as_ref() else {
        panic!("a prepared receipt retains its sole funded QC owner")
    };
    let header_bytes = retained_header_bytes(&prefix.prefix.tip);
    assert_eq!(header_bytes, retained_header_bytes(receipt.committed()));
    assert_eq!(
        budget.reserved_bytes(),
        header_bytes + funded_qc.allocation_bytes()
    );
    drop(receipt);
    assert_eq!(budget.reserved_bytes(), header_bytes);
    drop(prefix);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn physical_metadata_refusal_is_retryable_but_format_limits_are_not() {
    let refused = PrefixArtifactsError::Certificate(CertificateReadError::Decode(
        norito::Error::AllocationFailed { bytes: 128 },
    ));
    assert_eq!(refused.kind(), io::ErrorKind::WouldBlock);
    assert!(matches!(
        refused,
        PrefixArtifactsError::Certificate(CertificateReadError::Decode(
            norito::Error::AllocationFailed { bytes: 128 }
        ))
    ));
    for error in [
        norito::Error::LengthMismatch,
        norito::Error::TotalAllocationExceeded {
            attempted: 129,
            limit: 128,
        },
    ] {
        assert_eq!(
            PrefixArtifactsError::Certificate(CertificateReadError::Decode(error)).kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn funded_original_boundary_result_graph_is_borrowed_without_redecoding() {
    with_funded_original_boundary(
        assert_funded_original_boundary_result_graph_is_borrowed_without_redecoding,
    );
}

#[inline(never)]
fn assert_funded_original_boundary_result_graph_is_borrowed_without_redecoding(
    chain: &CertifiedTestChain,
) {
    use crate::sumeragi::{
        certified_chain::{CertifiedChain, VerifiedAuthority, read_frame},
        schedule,
    };

    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let original = frame(chain, 10);
    let preimage = original.commit_certificate().unwrap().result_preimage();
    let original_preimage = preimage.as_ptr();
    let current = read_frame(Clone::clone(&original), 10, chain.root_scope()).unwrap();
    let original_committee = current.commitment().schedule.current.committee.as_ptr();
    let parent = chain.committed(9);
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("actual authenticated parent authorizes the boundary");
    };
    let mut validation = EpochValidationScope::new();
    let config = scheduled
        .height_config_with_validation(&mut validation)
        .unwrap();
    let authority = VerifiedAuthority::new(scheduled.epoch.clone(), 10, &mut validation).unwrap();
    let budget = AllocationBudget::new(1 << 26);
    let artifacts = read(Clone::clone(&original), &budget);
    let original_bitmap = artifacts.decoded.commit_qc.signers.as_bytes().as_ptr();
    let original_signature = artifacts.decoded.commit_qc.agg_sig;
    let qc_bytes = artifacts.decoded.commit_qc.allocation_bytes();

    let retained = budget.reserved_bytes();
    assert!(retained > 0);

    let certified =
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, 1 << 26, 128),
            || {
                reader.verification_context().verify_certificate_with_scratch_admission(
            current,
            &authority,
            Some(&config),
            Some(artifacts),
            &mut crate::sumeragi::certified_chain::state_certificate::query_scratch_admission,
        )
            },
        )
        .expect("already decoded exact source must not decode its result graph again");
    assert_eq!(certified.verification(), QcVerification::Verified);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        certified.block(),
        &original
    ));
    assert_eq!(
        certified.commitment().schedule.current.committee.as_ptr(),
        original_committee
    );
    assert_eq!(
        original
            .commit_certificate()
            .unwrap()
            .result_preimage()
            .as_ptr(),
        original_preimage
    );
    let qc = certified.commit_qc().unwrap();
    assert_eq!(qc.signers.as_bytes().as_ptr(), original_bitmap);
    assert_eq!(qc.agg_sig, original_signature);

    // The receipt retains the same original QC bitmap, ledger and shared control.
    // Its transient header, table and proposal retire after full availability verification.
    assert_eq!(budget.reserved_bytes(), qc_bytes);
    assert!(budget.reserved_bytes() <= retained);
    drop(certified);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_certificate_rejects_foreign_signature_before_borrowing_graph() {
    with_funded_original_boundary(
        assert_native_certificate_rejects_foreign_signature_before_borrowing_graph,
    );
}

#[inline(never)]
fn assert_native_certificate_rejects_foreign_signature_before_borrowing_graph(
    chain: &CertifiedTestChain,
) {
    use crate::sumeragi::certified_chain::{CertifiedChain, VerifiedAuthority, read_frame};
    use crate::sumeragi::schedule;

    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let original = frame(chain, 10);
    let older = frame(chain, 9);
    let foreign_qc: Qc =
        norito::decode_canonical(older.commit_certificate().unwrap().commit_qc()).unwrap();
    let tampered_value = changed_qc(&original, |qc| qc.agg_sig = foreign_qc.agg_sig);
    let parent = chain.committed(9);
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("authenticated predecessor authorizes H10");
    };
    let mut validation = EpochValidationScope::new();
    let config = scheduled
        .height_config_with_validation(&mut validation)
        .unwrap();
    let authority = VerifiedAuthority::new(scheduled.epoch.clone(), 10, &mut validation).unwrap();
    let budget = AllocationBudget::new(1 << 26);
    let outcome = reader
        .verification_context()
        .verify_certificate_with_scratch_admission(
            read_frame(Clone::clone(&tampered_value), 10, chain.root_scope()).unwrap(),
            &authority,
            Some(&config),
            Some(read(Clone::clone(&tampered_value), &budget)),
            &mut crate::sumeragi::certified_chain::state_certificate::query_scratch_admission,
        );
    assert!(
        matches!(
            outcome,
            Err(
                crate::sumeragi::certified_chain::VerificationReadError::Source(
                    ChainReadError::Certificate {
                        height: 10,
                        error: iroha_sumeragi::crypto::CertError::BadSignature
                    }
                )
            )
        ),
        "foreign signature cannot authorize the already-decoded original graph"
    );
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "rejection releases the original partial reader owners"
    );
    let receipt = reader
        .verification_context()
        .verify_certificate_with_scratch_admission(
            read_frame(Clone::clone(&original), 10, chain.root_scope()).unwrap(),
            &authority,
            Some(&config),
            Some(read(Clone::clone(&original), &budget)),
            &mut crate::sumeragi::certified_chain::state_certificate::query_scratch_admission,
        )
        .unwrap();
    assert_eq!(receipt.verification(), QcVerification::Verified);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        receipt.block(),
        &original
    ));

    drop(receipt);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_boundary_quorums_bind_every_signed_field() {
    use crate::sumeragi::{certified_chain::read_frame, crypto::BlsCrypto, schedule};
    use iroha_sumeragi::crypto::Verifier;
    let mut chain = CertifiedTestChain::npos_boundary_fixture();
    chain.commit_with(Some(10_000), Vec::new(), Signers::LastThree);
    let original = frame(&chain, 10);
    let current = read_frame(Clone::clone(&original), 10, chain.root_scope()).unwrap();
    let parent = chain.committed(9);
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("the original committed parent authenticates H10");
    };
    let config = scheduled.height_config().unwrap();
    let crypto = BlsCrypto::new();
    crypto
        .admit_committee(scheduled.epoch.committee.iter().map(|member| {
            (
                member.validator.public_key(),
                member.proof_of_possession.as_slice(),
            )
        }))
        .unwrap();
    let instance = chain.instance();
    let verifier = Verifier::new(&crypto, &instance, &config.epoch.id, &config.committee);
    let actual: Qc =
        norito::decode_canonical(original.commit_certificate().unwrap().commit_qc()).unwrap();
    let alternative = chain.commit_qc(10, current.core_hash(), current.result(), Signers::Quorum);
    assert_ne!(actual.signers, alternative.signers);
    for qc in [&actual, &alternative] {
        verifier.verify_qc(qc).unwrap();
        assert_eq!(qc.signers.count_ones(), 3);

        let changes: [fn(&mut Qc); 8] = [
            |qc| qc.instance.0[0] ^= 1,
            |qc| qc.epoch.epoch += 1,
            |qc| qc.epoch.context.0[31] ^= 1,
            |qc| qc.height += 1,
            |qc| qc.view += 1,
            |qc| qc.block_hash.0[0] ^= 1,
            |qc| qc.result.0[0] ^= 1,
            |qc| qc.agg_sig.0[0] ^= 1,
        ];
        for change in changes {
            let mut tampered_value = qc.clone();
            change(&mut tampered_value);
            assert!(verifier.verify_qc(&tampered_value).is_err());
        }
    }
    assert_eq!(chain.height(), 10);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &frame(&chain, 10),
        &original
    ));
}
