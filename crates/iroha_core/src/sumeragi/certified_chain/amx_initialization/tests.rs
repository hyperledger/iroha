//! Original constructor body/raw custody around actual genesis authentication and prefix decode.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use norito::core::DecodeBudgetContext;

fn counter(budget: &iroha_allocation::AllocationBudget, maximum: usize) -> DecodeBudgetContext {
    DecodeBudgetContext::try_new_owned(norito::canonical_decode_limits(maximum), budget).unwrap()
}

#[test]
fn initial_authenticated_genesis_failure_keeps_original_body_raw_and_pool_until_retirement() {
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    // The canonical frame comes from the genuine independent producer. Only this
    // reader's authenticated network scope is foreign; no block/proof is fabricated.
    let wrong = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign-amx-initial-network",
    )));
    let mut view = chain.state().view();
    // Adversarial reader scope must not rebind the genuine producer's State/Kura.
    view.network_id = wrong;
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let context = counter(
        &budget,
        chain.kura().native_context_archive_max_bytes().get(),
    );
    let before = budget.reserved_bytes();
    let mut stage = AmxChainInitialization::new(&view).unwrap();
    chain.kura().reset_canonical_query_reads_for_test();
    assert!(matches!(
        context.with(|| stage.complete()),
        Err(ExecutionAttemptError::Rejected(
            ChainReadError::ForeignGenesis
        ))
    ));
    let body = stage.body.as_ref().unwrap();
    let pointer: *const SignedBlock = body.as_ref();
    assert!(body.belongs_to(&budget));
    let raw = stage.frame_for_test().unwrap();
    let raw_pointer = raw.as_slice().as_ptr();
    assert!(raw.belongs_to(&budget));
    let length = raw.as_slice().len();
    assert_eq!(
        budget.reserved_bytes(),
        before + length + SharedSignedBlock::allocation_layout().size()
    );
    let reads = chain.kura().canonical_query_reads_for_test();
    assert_eq!(reads, (1, u64::try_from(length).unwrap()));
    let consumed = context.consumed_allocated_bytes();
    assert!(matches!(
        context.with(|| stage.complete()),
        Err(ExecutionAttemptError::Rejected(
            ChainReadError::ForeignGenesis
        ))
    ));
    assert!(std::ptr::eq::<SignedBlock>(
        stage.body.as_ref().unwrap().as_ref(),
        pointer
    ));
    assert_eq!(
        stage.frame_for_test().unwrap().as_slice().as_ptr(),
        raw_pointer
    );
    assert_eq!(chain.kura().canonical_query_reads_for_test(), reads);
    assert!(context.consumed_allocated_bytes() >= consumed);
    // Normal caller-scoped retirement drops body/control before the raw owner/pool.
    // No new refund is introduced inside either failed authentication call.
    budget.with_deferred_refund_notifications(|_| drop(stage));
    assert_eq!(budget.reserved_bytes(), before);
    drop(view);
    drop(context);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn initial_prefix_decoder_refusal_reuses_original_genesis_body_raw_and_cumulative_context() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let context = counter(
        &budget,
        chain.kura().native_context_archive_max_bytes().get(),
    );
    let mut stage = AmxChainInitialization::new(&view).unwrap();
    chain.kura().reset_canonical_query_reads_for_test();
    let reader = context.with(|| stage.complete()).unwrap();
    assert!(stage.completed && stage.body.is_none() && stage.acquisition.is_none());
    assert!(matches!(
        context.with(|| stage.complete()),
        Err(ExecutionAttemptError::Rejected(ChainReadError::NotInView {
            height: 1
        }))
    ));
    let original = reader.amx_genesis_source.as_ref().unwrap();
    let bytes = original.bytes_for_test().unwrap();
    let raw_pointer = bytes.as_slice().as_ptr();
    assert!(bytes.belongs_to(&budget) && reader.genesis.belongs_to(&budget));
    let body_pointer: *const SignedBlock = reader.genesis.as_ref();
    let reads = chain.kura().canonical_query_reads_for_test();
    assert_eq!(reads, (1, u64::try_from(bytes.as_slice().len()).unwrap()));
    let retained = budget.reserved_bytes();
    let before = context.consumed_allocated_bytes();
    // Tighten only the existing result decoder layer, after the same current-source
    // check. This does not create another verifier, pool or replacement context.
    context.with(|| original.recheck_original_source()).unwrap();
    let limits =
        norito::canonical_decode_limits(chain.kura().native_context_archive_max_bytes().get());
    let refused = context.with(|| {
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(
                limits.max_sequence_elements(),
                0,
                limits.max_total_elements(),
                limits.max_total_allocated_bytes(),
                limits.max_nesting_depth(),
            ),
            || reader.genesis_prefix_from_original(reader.genesis.clone()),
        )
    });
    assert!(
        matches!(refused, Err(ExecutionAttemptError::Deferred(ref local))
        if local.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "actual original genesis-result decoder must preserve its typed local refusal"
    );
    assert!(reader.prefix.lock().is_none());
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(std::ptr::eq::<SignedBlock>(
        reader.genesis.as_ref(),
        body_pointer
    ));
    assert_eq!(
        reader
            .amx_genesis_source
            .as_ref()
            .unwrap()
            .bytes_for_test()
            .unwrap()
            .as_slice()
            .as_ptr(),
        raw_pointer
    );
    assert_eq!(chain.kura().canonical_query_reads_for_test(), reads);
    assert!(context.consumed_allocated_bytes() >= before);
    let prefix = context.with(|| reader.genesis_prefix()).unwrap();
    assert!(SharedSignedBlock::ptr_eq(
        prefix.tip.block(),
        &reader.genesis
    ));
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        reads,
        "initial prefix retries must lend the original constructor body rather than reread genesis"
    );
    drop(prefix);
    let certified = context.with(|| reader.certified(2)).unwrap();
    assert_eq!(certified.height(), 2);
    assert_eq!(certified.verification(), QcVerification::Verified);
    budget.with_deferred_refund_notifications(|_| {
        drop(certified);
        drop(reader);
        drop(stage);
    });
    drop(view);
    drop(context);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_policy_admission_preserves_real_pool_release_and_decoder_causes() {
    use iroha_allocation::{AllocationBudget, ChargedBufferError};
    use iroha_data_model::sumeragi_finality::GenesisReadError;
    use ivm::error::ExecutionDeferral;
    let pool = AllocationBudget::new(8);
    let occupied = pool.try_reserve_bytes(8).unwrap();
    let original = pool.try_reserve_bytes(1).unwrap_err();
    let ExecutionAttemptError::Deferred(retained) = original_authentication_error(
        OriginalGenesisReadError::Allocation(ChargedBufferError::Admission(original.clone())),
    ) else {
        panic!("original allocation refusal cannot become a genesis rejection");
    };
    assert_eq!(retained.allocation_refusal(), Some(&original));
    let ExecutionAttemptError::Deferred(retained) = original_authentication_error(
        OriginalGenesisReadError::Allocation(ChargedBufferError::Allocator { requested_bytes: 8 }),
    ) else {
        panic!("physical allocator refusal cannot become a genesis rejection");
    };
    assert_eq!(retained.reason(), ExecutionDeferral::AllocationUnavailable);
    assert!(retained.allocation_refusal().is_none());
    let ExecutionAttemptError::Deferred(retained) =
        original_authentication_error(OriginalGenesisReadError::Validation(
            GenesisReadError::Json(norito::json::Error::DecodeResourceLimit),
        ))
    else {
        panic!("original decoder refusal cannot become a genesis rejection");
    };
    assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
    assert!(retained.allocation_refusal().is_none());
    assert!(matches!(
        original_authentication_error(OriginalGenesisReadError::ForeignPool),
        ExecutionAttemptError::Rejected(ChainReadError::ForeignGenesis)
    ));
    drop(occupied);
}
