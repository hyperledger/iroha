//! The native streamed cache hash retains actual State capacity and canonical frame identity.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use norito::core::{BoundedEncodeError, DecodeBudgetContext};

const FRAME_LIMIT: usize = 1024 * 1024;

fn manifest() -> ContractManifest {
    ContractManifest {
        seiyaku_name: Some("borrowed signing content".repeat(4096)),
        code_hash: Some(IrohaHash::new(b"native cache hash artifact")),
        abi_hash: Some(IrohaHash::new(b"native cache hash ABI")),
        error_messages: Some(Vec::new()),
        compiler_fingerprint: None,
        features_bitmap: None,
        access_set_hints: None,
        entrypoints: None,
        states: None,
        provenance: None,
        error_types: None,
        kotoba: None,
    }
}

fn buffered_digest(manifest: &ContractManifest) -> IrohaHash {
    let pool = AllocationBudget::new(2 * FRAME_LIMIT);
    let _output = pool.try_reserve_bytes(FRAME_LIMIT).unwrap();
    let context = DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(FRAME_LIMIT, FRAME_LIMIT, FRAME_LIMIT, FRAME_LIMIT, 256),
        &pool,
    )
    .unwrap();
    let bytes = manifest
        .signature_payload_bytes(&context, FRAME_LIMIT)
        .unwrap();
    IrohaHash::new(bytes)
}

#[test]
fn manifest_signature_hash_matches_native_frame_with_only_the_paid_counter_allocation() {
    let manifest = manifest();
    let expected = buffered_digest(&manifest);
    let pool = AllocationBudget::new(FRAME_LIMIT);
    // Warm codec metadata and thread-local machinery outside the physical census.
    assert_eq!(manifest_signature_hash(&manifest, &pool).unwrap(), expected);
    let mut actual = None;
    let allocations = allocations_during(|| {
        actual = Some(manifest_signature_hash(&manifest, &pool));
    });
    assert_eq!(actual.unwrap().unwrap(), expected);
    assert_eq!(
        allocations, 1,
        "only the native shared counter is allocated"
    );
    assert_eq!(
        pool.peak_reserved_bytes(),
        DecodeBudgetContext::allocation_layout().size()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn manifest_signature_hash_preserves_optional_presence_and_signed_content_changes() {
    let mut manifest = manifest();
    let pool = AllocationBudget::new(FRAME_LIMIT);
    let original = manifest_signature_hash(&manifest, &pool).unwrap();
    manifest.error_messages = None;
    let absent = manifest_signature_hash(&manifest, &pool).unwrap();
    assert_ne!(
        original, absent,
        "Some(empty) and None are distinct signing bytes"
    );
    assert_eq!(absent, buffered_digest(&manifest));
    manifest.features_bitmap = Some(1);
    assert_ne!(manifest_signature_hash(&manifest, &pool).unwrap(), absent);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn manifest_signature_hash_pool_refusal_is_typed_and_allocates_no_fallback() {
    let manifest = manifest();
    let layout = DecodeBudgetContext::allocation_layout();
    let pool = AllocationBudget::new(layout.size() - 1);
    let mut result = None;
    let allocations = allocations_during(|| {
        result = Some(manifest_signature_hash(&manifest, &pool));
    });
    assert!(matches!(
        result.unwrap(),
        Err(BoundedEncodeError::Serialization(norito::Error::AllocationFailed { bytes }))
            if bytes == layout.size() as u64
    ));
    assert_eq!(allocations, 0);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(pool.peak_reserved_bytes(), 0);
}

#[test]
fn manifest_signature_hash_native_allocator_refusal_returns_the_original_codec_category() {
    let manifest = manifest();
    let pool = AllocationBudget::new(FRAME_LIMIT);
    let layout = DecodeBudgetContext::allocation_layout();
    let (result, refused) =
        refuse_one_layout_during(layout, || manifest_signature_hash(&manifest, &pool));
    assert!(
        refused,
        "the actual native shared-counter allocation was refused"
    );
    assert!(matches!(
        result,
        Err(BoundedEncodeError::Serialization(norito::Error::AllocationFailed { bytes }))
            if bytes == layout.size() as u64
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(
        manifest_signature_hash(&manifest, &pool).unwrap(),
        buffered_digest(&manifest)
    );
}

#[test]
fn manifest_signature_hash_frame_refusal_never_allocates_a_frame_or_partial_digest() {
    let manifest = manifest();
    let pool = AllocationBudget::new(DecodeBudgetContext::allocation_layout().size());
    let mut result = None;
    let allocations = allocations_during(|| {
        result = Some(manifest_signature_hash(&manifest, &pool));
    });
    assert!(matches!(
        result.unwrap(),
        Err(BoundedEncodeError::FrameTooLarge { encoded_bytes, max_bytes })
            if encoded_bytes > max_bytes && max_bytes == pool.limit_bytes()
    ));
    assert_eq!(
        allocations, 1,
        "only the paid counter exists on frame refusal"
    );
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn manifest_signature_hash_cached_state_hints_refuse_before_lookup_and_retry_conservatively() {
    let _retention = super::static_state_memory_tests::retention();
    let (mut state, bytes, manifest, artifact) = super::static_state_memory_tests::fixture();
    state.edit_pipeline_for_testing(|pipeline| pipeline.access_set_cache_enabled = true);
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let prepared = cache
        .get_or_prepare(artifact.code_hash, bytes.as_ref())
        .unwrap();
    let pool = cache.execution_budget();
    let baseline = pool.reserved_bytes();
    let limit = pool.limit_bytes();
    let expected =
        derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).unwrap();
    let key = AccessSetCacheKey {
        artifact_id: artifact,
        entrypoint: Some("write_one".to_owned()),
    };
    let original_hash = manifest_signature_hash(&manifest, pool).unwrap();
    // Other native tests clear this process-wide optional cache. Retain this
    // exact fixture entry under a read guard across the refusal observation;
    // setup uses the genuine completed derivation and native signing hash.
    let mut cache_guard = access_set_cache().write();
    cache_guard.insert(
        key.clone(),
        AccessSetCacheEntry {
            manifest_hash: original_hash,
            set: expected.clone(),
        },
    );
    let cache_guard = parking_lot::RwLockWriteGuard::downgrade(cache_guard);
    pool.set_limit_bytes(baseline + DecodeBudgetContext::allocation_layout().size() - 1);
    assert!(
        manifest_access_set(
            &manifest,
            artifact,
            &prepared,
            true,
            Some("write_one"),
            pool,
        )
        .is_none()
    );
    let prepared_before = cache.stats();
    assert!(derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).is_none());
    assert_eq!(cache.stats().hits, prepared_before.hits + 1);
    assert_eq!(cache.stats().preparations, prepared_before.preparations);
    assert_eq!(cache_guard.get(&key).unwrap().manifest_hash, original_hash);
    assert_eq!(
        pool.reserved_bytes(),
        baseline,
        "no fallback pool or output allocation survives"
    );
    let mut conservative = AccessSet::new();
    assert!(apply_prepared_ivm_access_fence(
        &prepared,
        &mut conservative
    ));
    assert!(conservative.write_keys.contains("state:*"));
    pool.set_limit_bytes(limit);
    drop(cache_guard);
    assert_eq!(
        derive_access_from_ivm_trigger(&bytes, artifact, Some("write_one"), &view).unwrap(),
        expected
    );
    assert_eq!(pool.reserved_bytes(), baseline);
}
