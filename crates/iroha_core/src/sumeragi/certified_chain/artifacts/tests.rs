//! Original source, exact bulk funding, retry and certificate-verification parity.

use super::*;
use crate::state::World;
use crate::sumeragi::{
    certified_chain::{CertifiedPrefix, QcVerification},
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
    assert!(!owner.payload.admitted_to(&AllocationBudget::new(1 << 26)));
    let mut expected = Vec::new();
    source
        .write_resultless_proposal_wire(&mut expected)
        .unwrap();
    assert_eq!(owner.payload.as_slice(), expected);
    assert_eq!(
        norito::encode_canonical(&owner.decoded.commit_qc).unwrap(),
        source.commit_certificate().unwrap().commit_qc()
    );
    assert!(budget.reserved_bytes() > expected.len() + owner.decoded.availability.as_slice().len());
    drop(owner);
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
        .complete(&measure)
        .unwrap_or_else(|_| panic!("bounded candidate"));
    let certificate_bytes = measure.reserved_bytes();
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
    budget.set_limit_bytes(table_len);
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
    drop(owner);
    let budget = AllocationBudget::new(table_len);
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
    assert_eq!(budget.reserved_bytes(), table_len);
    let (job, error) = job.complete(&foreign).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(budget.reserved_bytes(), table_len);
    drop(job);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prefix_artifacts_cannot_be_rebound_to_equal_hash_carrier_or_changed_header() {
    with_prefix_chain(
        assert_prefix_artifacts_cannot_be_rebound_to_equal_hash_carrier_or_changed_header,
    );
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
    let header = owner.decoded.header.clone();
    assert!(matches!(
        owner.into_parts(&replacement, &header),
        Err(ChainReadError::HeaderMismatch { height: 2 })
    ));
    let owner = read(Clone::clone(&source), &budget);
    let mut header = owner.decoded.header.clone();
    header.origin_view += 1;
    assert!(matches!(
        owner.into_parts(&source, &header),
        Err(ChainReadError::HeaderMismatch { height: 2 })
    ));
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
    let changed = crate::block::reserve_block_for_tests().initialize(
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
        funded.push_prepared(read(changed, &budget)).is_err(),
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
        assert_eq!(budget.reserved_bytes(), 0);
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
    assert_eq!(budget.reserved_bytes(), 0);
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

    // The receipt retains independently decoded QC metadata. Its transient
    // original-funded table and proposal retire after full availability verification.
    assert_eq!(budget.reserved_bytes(), 0);
    drop(receipt);
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
    let current = read_frame(Clone::clone(&original), 10).unwrap();
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

    // The receipt retains independently decoded QC metadata. Its transient
    // original-funded table and proposal retire after full availability verification.
    assert_eq!(budget.reserved_bytes(), 0);
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
    let changed = changed_qc(&original, |qc| qc.agg_sig = foreign_qc.agg_sig);
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
            read_frame(Clone::clone(&changed), 10).unwrap(),
            &authority,
            Some(&config),
            Some(read(Clone::clone(&changed), &budget)),
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
            read_frame(Clone::clone(&original), 10).unwrap(),
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
    let current = read_frame(Clone::clone(&original), 10).unwrap();
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
            let mut changed = qc.clone();
            change(&mut changed);
            assert!(verifier.verify_qc(&changed).is_err());
        }
    }
    assert_eq!(chain.height(), 10);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &frame(&chain, 10),
        &original
    ));
}
