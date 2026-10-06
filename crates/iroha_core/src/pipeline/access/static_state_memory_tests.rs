//! Actual State-pool refusal declines optional exact hints and keeps conservative routing.

use super::*;
use crate::state::{State, World};
use iroha_data_model::transaction::{Executable, IvmBytecode, TransactionBuilder};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;

pub(super) fn retention() -> ivm::ivm_cache::CacheLimitsGuard {
    ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: 64,
        max_bytes: 64 * 1024 * 1024,
        max_decoded_ops: 0,
    })
}

pub(super) fn fixture() -> (State, IvmBytecode, ContractManifest, ContractArtifactId) {
    let (bytes, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            "seiyaku FundedAccessHints { state StateMap<int, int> Values; kotoage fn write_one() authorize(\"CanWrite\") { Values[1] = 10; } }",
        ).unwrap();
    let artifact = ContractArtifactId::new(DataSpaceId::UNIVERSAL, ivm::contract_code_hash(&bytes));
    let authority = iroha_test_samples::ALICE_ID.clone();
    let account = Account::new(authority.clone()).build(&authority);
    let mut world = World::with([], [account], []);
    world.contract_manifests.insert(artifact, manifest.clone());
    let mut state = State::new(
        crate::pipeline::overlay::test_support::with_global_root(world),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    state.edit_pipeline_for_testing(|pipeline| pipeline.access_set_cache_enabled = false);
    (state, IvmBytecode::from_compiled(bytes), manifest, artifact)
}

#[test]
fn trigger_hint_uses_original_state_pool_and_keeps_state_fence_on_refusal() {
    let _retention = retention();
    let (state, bytes, _manifest, artifact) = fixture();
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let prepared = cache
        .get_or_prepare(artifact.code_hash, bytes.as_ref())
        .unwrap();
    let budget = cache.execution_budget();
    let limit = budget.limit_bytes();
    let baseline = budget.reserved_bytes();
    let before = cache.stats();
    budget.set_limit_bytes(0);
    assert!(derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).is_none());
    assert_eq!(
        cache.stats().hits,
        before.hits + 1,
        "retained artifact reaches funded analysis"
    );
    assert_eq!(cache.stats().preparations, before.preparations);
    assert_eq!(budget.reserved_bytes(), baseline);
    let mut conservative = AccessSet::new();
    assert!(apply_prepared_ivm_access_fence(
        &prepared,
        &mut conservative
    ));
    assert!(conservative.write_keys.contains("state:*"));
    budget.set_limit_bytes(limit);
    let exact = derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).unwrap();
    assert!(
        exact
            .write_keys
            .iter()
            .any(|key| key.starts_with("state:Values/"))
    );
    assert!(!exact.write_keys.contains("state:*"));
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "the hint consumer releases scratch and its final analysis key view"
    );
}

#[test]
fn final_key_publication_refusal_keeps_original_state_fence_and_retries() {
    let _retention = retention();
    let (state, bytes, _manifest, artifact) = fixture();
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let prepared = cache
        .get_or_prepare(artifact.code_hash, bytes.as_ref())
        .unwrap();
    // Measure the exact same immutable analysis geometry in an explicit local
    // diagnostic pool. It cannot provide any credit to the actual State path.
    let probe = AllocationBudget::new(64 * 1024 * 1024);
    let report =
        ivm::analysis::analyze_prepared_static_state_accesses(&prepared, Some("write_one"), &probe)
            .unwrap()
            .unwrap();
    let output_bytes = probe.reserved_bytes();
    let demand = probe.peak_reserved_bytes();
    assert!(output_bytes > 0 && demand > output_bytes);
    drop(report);
    assert_eq!(probe.reserved_bytes(), 0);
    let budget = cache.execution_budget();
    let baseline = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    budget.set_limit_bytes(baseline + demand - 1);
    assert!(matches!(
        ivm::analysis::analyze_prepared_static_state_accesses(&prepared, Some("write_one"), &budget),
        Err(ivm::VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == output_bytes
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    assert!(derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).is_none());
    assert_eq!(budget.reserved_bytes(), baseline);
    let mut conservative = AccessSet::new();
    assert!(apply_prepared_ivm_access_fence(
        &prepared,
        &mut conservative
    ));
    assert!(conservative.write_keys.contains("state:*"));
    budget.set_limit_bytes(limit);
    let exact = derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).unwrap();
    assert!(
        exact
            .write_keys
            .iter()
            .any(|key| key.starts_with("state:Values/"))
    );
    assert!(!exact.write_keys.contains("state:*"));
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn raw_transaction_hint_refusal_remains_conservative_and_retries_without_execution() {
    let _retention = retention();
    let (state, bytes, manifest, artifact) = fixture();
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let prepared = cache
        .get_or_prepare(artifact.code_hash, bytes.as_ref())
        .unwrap();
    let budget = cache.execution_budget();
    let limit = budget.limit_bytes();
    let baseline = budget.reserved_bytes();
    let before = cache.stats();
    let network = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(
        IrohaHash::new(b"funded-static-access-network"),
    ));
    let mut metadata = Metadata::default();
    metadata.insert(
        "contract_entrypoint".parse().unwrap(),
        Json::new("write_one"),
    );
    metadata.insert(MANIFEST_METADATA_KEY.parse().unwrap(), Json::new(manifest));
    let tx = TransactionBuilder::new(
        network,
        iroha_test_samples::ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_metadata(metadata)
    .with_executable(Executable::Ivm(bytes))
    .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    budget.set_limit_bytes(0);
    let (set, source) = derive_for_transaction_with_source_and_prepared(
        &tx,
        Some(&view),
        IvmStrategy::Conservative,
        Some(&prepared),
    );
    assert!(set.write_keys.contains("*"));
    assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(limit);
    let (set, source) = derive_for_transaction_with_source_and_prepared(
        &tx,
        Some(&view),
        IvmStrategy::Conservative,
        Some(&prepared),
    );
    assert_eq!(source, Some(AccessSetSource::EntrypointHints));
    assert!(
        set.write_keys
            .iter()
            .any(|key| key.starts_with("state:Values/"))
    );
    assert!(!set.write_keys.contains("*"));
    assert_eq!(
        cache.stats(),
        before,
        "hint planning does not load or execute a VM"
    );
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn foreign_prepared_image_cannot_fund_exact_hints_and_semantic_rejections_remain_closed() {
    let _retention = retention();
    let (state, bytes, manifest, artifact) = fixture();
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let prepared = cache
        .get_or_prepare(artifact.code_hash, bytes.as_ref())
        .unwrap();
    let original = cache.execution_budget().reserved_bytes();
    let foreign = AllocationBudget::new(0);
    assert!(
        manifest_access_set(
            &manifest,
            artifact,
            &prepared,
            false,
            Some("write_one"),
            &foreign
        )
        .is_none()
    );
    assert_eq!(foreign.peak_reserved_bytes(), 0);
    assert_eq!(cache.execution_budget().reserved_bytes(), original);
    foreign.set_limit_bytes(64 * 1024 * 1024);
    assert!(
        manifest_access_set(
            &manifest,
            artifact,
            &prepared,
            false,
            Some("write_one"),
            &foreign
        )
        .is_some()
    );
    assert!(foreign.peak_reserved_bytes() > 0);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(cache.execution_budget().reserved_bytes(), original);
    let mut incomplete = manifest.clone();
    incomplete.entrypoints.as_mut().unwrap()[0].access_hints_complete = Some(false);
    assert!(
        manifest_access_set(
            &incomplete,
            artifact,
            &prepared,
            false,
            Some("write_one"),
            &foreign
        )
        .is_none()
    );
    assert!(
        manifest_access_set(
            &manifest,
            artifact,
            &prepared,
            false,
            Some("missing"),
            &foreign
        )
        .is_none()
    );
    let wrong = ContractArtifactId::new(DataSpaceId::UNIVERSAL, IrohaHash::new(b"wrong-artifact"));
    assert!(
        manifest_access_set(
            &manifest,
            wrong,
            &prepared,
            false,
            Some("write_one"),
            &foreign
        )
        .is_none()
    );
}

#[test]
fn canonical_text_index_refusal_keeps_the_actual_state_fence_and_retries() {
    let _retention = retention();
    let (state, bytes, _manifest, artifact) = fixture();
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let prepared = cache
        .get_or_prepare(artifact.code_hash, bytes.as_ref())
        .unwrap();
    // Three original admissions are facts/FIFO, symbolic key sites, and the
    // borrowed text index. Observe actual refusals instead of duplicating their
    // private Rust layouts. This diagnostic pool grants no State capacity.
    let probe = AllocationBudget::new(0);
    let mut preceding = 0;
    let mut text_bytes = 0;
    for stage in 0..3 {
        probe.set_limit_bytes(preceding);
        let error = ivm::analysis::analyze_prepared_static_state_accesses(
            &prepared,
            Some("write_one"),
            &probe,
        )
        .unwrap_err();
        let requested = match error {
            ivm::VMError::AllocationDeferred(
                iroha_allocation::AllocationRefusal::ExceedsLimit {
                    requested_bytes, ..
                }
                | iroha_allocation::AllocationRefusal::Capacity {
                    requested_bytes, ..
                },
            ) => requested_bytes,
            error => panic!("unexpected analysis refusal: {error}"),
        };
        assert!(requested > 0);
        assert_eq!(probe.reserved_bytes(), 0);
        if stage == 2 {
            text_bytes = requested;
        } else {
            preceding += requested;
        }
    }
    let budget = cache.execution_budget();
    let baseline = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    budget.set_limit_bytes(baseline + preceding + text_bytes - 1);
    assert!(matches!(
        ivm::analysis::analyze_prepared_static_state_accesses(&prepared, Some("write_one"), &budget),
        Err(ivm::VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. }))
            if requested_bytes == text_bytes
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    assert!(derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).is_none());
    let mut conservative = AccessSet::new();
    assert!(apply_prepared_ivm_access_fence(
        &prepared,
        &mut conservative
    ));
    assert!(conservative.write_keys.contains("state:*"));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(limit);
    let exact = derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).unwrap();
    assert!(
        exact
            .write_keys
            .iter()
            .any(|key| key.starts_with("state:Values/"))
    );
    assert!(!exact.write_keys.contains("state:*"));
    assert_eq!(budget.reserved_bytes(), baseline);
}
