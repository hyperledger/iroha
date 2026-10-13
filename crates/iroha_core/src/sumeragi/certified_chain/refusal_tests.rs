//! Original signed-history decode refusal and completed malformed-frame controls.

use super::*;
use crate::{
    block::BlockValidationError,
    execution_attempt::ExecutionAttemptError,
    state::{World, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

fn original_chain() -> CertifiedTestChain {
    CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("original signed four-validator genesis")
}

fn no_decode_allocation<T>(read: impl FnOnce() -> T) -> T {
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        read,
    )
}

#[test]
fn original_successor_history_refusal_is_local_and_same_source_retries() {
    let chain = original_chain();
    let proposal = chain.proposal(Some(2_000), Vec::new());
    let view = chain.state().view();
    let parent = committed_block(&view, 1).expect("original published genesis");
    let epoch = &view.world().consensus_schedule().ready(2).unwrap().epoch;
    let context = iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
        instance: chain.instance().0,
        epoch: epoch.authorization.epoch,
        epoch_context_id: epoch.context_id().unwrap(),
        parent_consensus_hash: parent.core_hash().0,
        parent_result: parent.result().0,
    };
    let original_wire = parent.block().encode_wire().unwrap();
    let height = view.height();
    let authenticate = || {
        super::super::schedule::authenticate_successor_context(&view, &proposal.header(), &context)
            .map_err(BlockValidationError::from)
    };
    authenticate().expect("same original source is valid before scoped refusal");
    let error = no_decode_allocation(authenticate).unwrap_err();
    let BlockValidationError::ExecutionDeferred(local) = error else {
        panic!("original history read must remain a local attempt: {error:?}");
    };
    assert_eq!(
        local.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(
        local.allocation_refusal().is_none(),
        "Norito scope has no pool release owner"
    );
    assert_eq!(view.height(), height);
    authenticate().expect("identical signed history retries after caller budget releases");
    let retry = committed_block(&view, 1).unwrap();
    assert_eq!(retry.block().encode_wire().unwrap(), original_wire);
    assert_eq!(retry.result(), parent.result());
    assert_eq!(retry.core_hash(), parent.core_hash());
}

#[test]
fn original_result_frame_refusal_is_local_and_same_bytes_retry() {
    let chain = original_chain();
    let frame = Clone::clone(
        chain
            .kura()
            .get_block(
                NonZeroUsize::new(1).unwrap(),
                &chain.state().ivm_execution_budget(),
            )
            .expect("original block read attempt")
            .as_ref()
            .unwrap(),
    );
    let wire = frame.encode_wire().unwrap();
    let original = read_frame(Clone::clone(&frame), 1, chain.root_scope()).unwrap();
    let error: ExecutionAttemptError<ChainReadError> =
        no_decode_allocation(|| read_frame(Clone::clone(&frame), 1, chain.root_scope()))
            .unwrap_err()
            .into();
    let ExecutionAttemptError::Deferred(local) = error else {
        panic!("the original result decoder refusal is not malformed evidence: {error:?}");
    };
    assert_eq!(
        local.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(local.allocation_refusal().is_none());
    assert_eq!(frame.encode_wire().unwrap(), wire);
    let retry = read_frame(Clone::clone(&frame), 1, chain.root_scope()).unwrap();
    assert_eq!(retry.result(), original.result());
    assert_eq!(retry.core_hash(), original.core_hash());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        retry.block(),
        &frame
    ));
}

#[test]
fn original_result_scope_retirement_preserves_refusal_against_foreign_equal_budget() {
    let chain = original_chain();
    let frame = chain.committed(1);
    let bytes = frame
        .block()
        .commit_certificate()
        .unwrap()
        .result_preimage();
    let original = bytes.to_vec();
    let error = no_decode_allocation(|| {
        CertifiedResultV1::decode(bytes, CertifiedResultScope::TairaGlobal)
    })
    .unwrap_err();
    let CertifiedResultError::Body(super::super::commitment::CommitmentError::Resource(attempt)) =
        &error
    else {
        panic!("actual result decoder must retain its original refusal: {error:?}");
    };
    assert_eq!(
        attempt.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    no_decode_allocation(|| {
        assert!(!norito::core::decode_error_matches_active_limits(
            attempt.error()
        ));
    });
    let mapped = no_decode_allocation(|| frame_result_error(1, error));
    let ExecutionAttemptError::Deferred(local) = mapped else {
        panic!("the original refusal remains local after its scope retires: {mapped:?}");
    };
    assert_eq!(
        local.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(local.allocation_refusal().is_none());
    assert_eq!(bytes, original);
    let retry = CertifiedResultV1::decode(bytes, CertifiedResultScope::TairaGlobal)
        .expect("same original result retries");
    assert_eq!(retry.result().unwrap(), frame.result());
}

#[test]
fn malformed_original_result_frame_is_a_completed_rejection() {
    let chain = original_chain();
    let original = Clone::clone(
        chain
            .kura()
            .get_block(
                NonZeroUsize::new(1).unwrap(),
                &chain.state().ivm_execution_budget(),
            )
            .expect("original block read attempt")
            .as_ref()
            .unwrap(),
    );
    let certificate = original.commit_certificate().unwrap();
    let mut malformed = certificate.result_preimage().to_vec();
    malformed.push(0);
    let changed = crate::block::reserve_block_for_tests().initialize(
        original.as_ref().clone().with_commit_certificate(Some(
            iroha_data_model::block::CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                certificate.commit_qc().to_vec(),
                malformed,
                certificate.availability().to_vec(),
            ),
        )),
    );
    let error: ExecutionAttemptError<ChainReadError> = read_frame(changed, 1, chain.root_scope())
        .unwrap_err()
        .into();
    assert!(matches!(
        error,
        ExecutionAttemptError::Rejected(ChainReadError::Malformed { height: 1, .. })
    ));
    assert!(
        read_frame(original, 1, chain.root_scope()).is_ok(),
        "original signed frame remains valid"
    );
}

#[test]
fn original_durable_certificate_refusal_preserves_local_reason_and_retries() {
    let chain = original_chain();
    let view = chain.state().view();
    let bytes = chain.committed(1).block().encode_wire().unwrap();
    let error = no_decode_allocation(|| CertifiedChain::new(&view))
        .err()
        .unwrap();
    let ExecutionAttemptError::Deferred(local) = error else {
        panic!("original durable read must retain its caller refusal: {error:?}");
    };
    assert_eq!(
        local.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(local.allocation_refusal().is_none());
    let reader = CertifiedChain::new(&view).unwrap();
    assert_eq!(reader.genesis().encode_wire().unwrap(), bytes);
    assert_eq!(view.height(), 1);
}

#[test]
fn original_canonical_frame_preserves_refusal_after_decoder_scope_retirement() {
    let chain = original_chain();
    let bytes = chain.committed(1).block().encode_wire().unwrap();
    no_decode_allocation(|| {
        let error = iroha_data_model::block::decode_framed_signed_block(&bytes).unwrap_err();
        let mapped = crate::execution_attempt::canonical_decode_attempt_error(error, |error| error);
        assert!(matches!(mapped, ExecutionAttemptError::Deferred(_)));
    });
    let original =
        no_decode_allocation(|| iroha_data_model::block::decode_framed_signed_block(&bytes))
            .unwrap_err();
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(matches!(
        crate::execution_attempt::canonical_decode_attempt_error(original, |e| e),
        ExecutionAttemptError::Deferred(_)
    ));
    // A limit introduced inside the owner is intrinsic even if its numeric fields match.
    let intrinsic = norito::core::classify_decode_attempt(|| {
        no_decode_allocation(|| {
            iroha_data_model::block::decode_framed_signed_block(&bytes)
                .map_err(norito::core::DecodeAttemptError::into_error)
        })
    })
    .unwrap_err();
    assert_eq!(
        intrinsic.kind(),
        norito::core::DecodeAttemptErrorKind::Invalid
    );
    assert!(matches!(
        crate::execution_attempt::canonical_decode_attempt_error(intrinsic, |e| e),
        ExecutionAttemptError::Rejected(_)
    ));
    assert!(iroha_data_model::block::decode_framed_signed_block(&bytes).is_ok());
}

#[test]
fn original_availability_history_refusal_is_pending_without_corruption() {
    use crate::sumeragi::{
        availability_schedule::AvailabilitySchedule, runtime_availability::NativeGlobalAvailability,
    };
    let mut chain = original_chain();
    chain.commit(Vec::new());
    let provider = NativeGlobalAvailability::new(
        chain.state().clone(),
        chain.instance(),
        Arc::new(BlsCrypto::new()),
    )
    .unwrap();
    let expected = provider.height_config(2).unwrap();
    assert!(expected.is_some());
    let error = no_decode_allocation(|| provider.height_config(2)).unwrap_err();
    let ExecutionAttemptError::Deferred(owner) = error else {
        panic!("original historical schedule refusal was erased: {error:?}");
    };
    assert_eq!(
        owner.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(
        owner.allocation_refusal().is_none(),
        "Norito has no allocation pool notification"
    );
    assert_eq!(provider.height_config(2).unwrap(), expected);
}

#[test]
fn original_availability_constructor_refusal_retries_without_installing_authority() {
    use crate::sumeragi::{
        availability_schedule::AvailabilitySchedule, runtime_availability::NativeGlobalAvailability,
    };
    let chain = original_chain();
    let original = chain.committed(1).block().encode_wire().unwrap();
    let error = no_decode_allocation(|| {
        NativeGlobalAvailability::new(
            chain.state().clone(),
            chain.instance(),
            Arc::new(BlsCrypto::new()),
        )
    })
    .err()
    .expect("actual original signed genesis read must refuse");
    let ExecutionAttemptError::Deferred(owner) = error else {
        panic!("startup refusal was erased: {error:?}");
    };
    assert_eq!(
        owner.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(owner.allocation_refusal().is_none());
    assert_eq!(chain.height(), 1);
    assert_eq!(chain.committed(1).block().encode_wire().unwrap(), original);
    let provider = NativeGlobalAvailability::new(
        chain.state().clone(),
        chain.instance(),
        Arc::new(BlsCrypto::new()),
    )
    .unwrap();
    assert_eq!(provider.instance(), chain.instance());
    assert!(provider.height_config(2).unwrap().is_some());
}

#[test]
fn certified_wrapper_scope_and_block_time_are_checked_by_both_reader_owners() {
    use iroha_data_model::block::consensus::SumeragiRootScope;
    use iroha_data_model::sumeragi_finality::{
        CertifiedResultError, CertifiedResultScope, CertifiedResultV1, SccpFinalityHeaderV1,
        certified_result::{FLAG_ACTIVE, context_committee_root},
    };
    use iroha_model_base::topology::DataSpaceId;
    let chain = original_chain();
    let original = chain.committed(1).block().clone();
    let certificate = original.commit_certificate().unwrap();
    let decoded = CertifiedResultV1::decode(
        certificate.result_preimage(),
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap();
    let mut fields = decoded.header().fields();
    fields.flags = FLAG_ACTIVE;
    fields.generation = 1;
    fields.committee_root = context_committee_root(&decoded.commitment().schedule.current).unwrap();
    let active = CertifiedResultV1::new(
        SccpFinalityHeaderV1::from_fields(&fields).unwrap(),
        decoded.commitment().clone(),
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap();
    let changed = |bytes: Vec<u8>| {
        crate::block::reserve_block_for_tests().initialize(
            original.as_ref().clone().with_commit_certificate(Some(
                iroha_data_model::block::CommitCertificate::from_untrusted_parts(
                    certificate.consensus_header().to_vec(),
                    certificate.commit_qc().to_vec(),
                    bytes,
                    certificate.availability().to_vec(),
                ),
            )),
        )
    };
    // Structural read only: this does not turn a modified genesis result into execution authority.
    let active_frame = changed(active.preimage().unwrap());
    read_frame(active_frame.clone(), 1, SumeragiRootScope::Global).unwrap();
    let mut late = active.header().fields();
    late.timestamp_ms += 1;
    let wrong_time = CertifiedResultV1::from_parts_unvalidated(
        SccpFinalityHeaderV1::from_fields(&late).unwrap(),
        active.commitment().clone(),
    );
    // The canonical result hash rejects missing X before decoding. A parsed X with
    // the wrong scope or block time instead reaches the precise wrapper check.
    // Pin each rejection; none may be accepted or relabelled as a local refusal.
    let bare_body = decoded.commitment().preimage().unwrap();
    assert!(result_of_preimage(&bare_body).is_none());
    for (source, scope, rejection) in [
        (
            active_frame,
            SumeragiRootScope::Dataspace {
                parent_network_id: chain.network_id(),
                dataspace_id: DataSpaceId::new(7),
            },
            ChainReadError::Malformed {
                height: 1,
                reason: CertifiedResultError::ActiveOutsideGlobal.to_string(),
            },
        ),
        (
            changed(wrong_time.preimage().unwrap()),
            SumeragiRootScope::Global,
            ChainReadError::Malformed {
                height: 1,
                reason: CertifiedResultError::BlockMismatch.to_string(),
            },
        ),
        (
            changed(bare_body),
            SumeragiRootScope::Global,
            ChainReadError::ResultMismatch { height: 1 },
        ),
    ] {
        let expected = read_frame(source.clone(), 1, scope).unwrap_err();
        assert!(
            matches!(&expected, ExecutionAttemptError::Rejected(actual) if actual == &rejection),
            "the original reader must preserve {rejection:?}, got {expected:?}"
        );
        let budget = iroha_allocation::AllocationBudget::new(16 * 1024 * 1024);
        let actual = AdmittedCommittedBlock::read(
            source,
            1,
            scope,
            &mut EpochValidationScope::new(),
            &budget,
        )
        .err()
        .expect("same wrapper refusal in original prepaid destination");
        assert_eq!(expected.to_string(), actual.to_string());
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let retry = read_frame(original.clone(), 1, SumeragiRootScope::Global).unwrap();
    assert_eq!(
        retry.block().encode_wire().unwrap(),
        original.encode_wire().unwrap()
    );
}
