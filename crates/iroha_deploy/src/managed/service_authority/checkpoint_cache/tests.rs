//! Real generated paid checkpoints exercise optional import reuse without supplying currentness.

use super::*;
use crate::{
    managed::{
        LocalnetPorts,
        native_operation::{
            MAX_CHECKPOINT_BYTES, checkpoint_bytes,
            test_support::{
                UnavailablePeers,
                native_fixture::{NativeFixture, quote_instructions},
            },
        },
        service_authority::NetworkPurpose,
    },
    verify::finality::FinalityVerifier,
};
use iroha_data_model::isi::{InstructionBox, Log};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(super) fn attempts(authority: &ServiceAuthority) -> usize {
    authority
        .effective_checkpoint_cache()
        .decode_attempts
        .load(Ordering::Relaxed)
}

pub(super) fn assert_entry(authority: &ServiceAuthority, bytes: &[u8]) {
    let slot = authority
        .effective_checkpoint_cache()
        .entry
        .try_lock()
        .unwrap();
    let entry = slot
        .slots
        .iter()
        .flatten()
        .find(|entry| entry.bytes == bytes)
        .expect("the exact successful original");
    assert_eq!(entry.bytes, bytes);
    assert_eq!(entry.network, authority.config.network_id);
    assert_eq!(entry.chain, authority.config.chain.as_str());
    assert_eq!(checkpoint_bytes(&entry.verifier).unwrap(), bytes);
    assert!(entry.bytes.len() <= MAX_CHECKPOINT_BYTES);
    assert!(
        slot.slots
            .iter()
            .flatten()
            .map(|entry| entry.bytes.capacity())
            .sum::<usize>()
            <= MAX_CHECKPOINT_BYTES
    );
    assert!(
        slot.slots
            .iter()
            .flatten()
            .map(|entry| entry.retained_import_envelope)
            .sum::<usize>()
            <= retained_import_envelope(MAX_CHECKPOINT_BYTES).unwrap()
    );
    assert!(
        slot.slots
            .iter()
            .flatten()
            .all(|entry| entry.chain.capacity() <= MAX_CHAIN_CAPACITY)
    );
}

pub(super) fn assert_refused(authority: &ServiceAuthority, bytes: &[u8], actual_imports: usize) {
    let expected = decode_checkpoint(
        bytes,
        authority.config.network_id,
        authority.config.chain.as_str(),
    )
    .unwrap_err()
    .to_string();
    let before = attempts(authority);
    assert_eq!(
        authority.decode_checkpoint(bytes).unwrap_err().to_string(),
        expected
    );
    assert_eq!(attempts(authority), before + actual_imports);
    assert!(
        authority
            .effective_checkpoint_cache()
            .entry
            .try_lock()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn authenticated_single_checkpoint_reuse_preserves_scope_mutation_and_custody_checks() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "checkpoint-import",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let signed = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "original checkpoint import".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let original = native.observe(&authority);
    assert_eq!(original.checkpoint().height(), 2);
    let bytes = checkpoint_bytes(&original).unwrap();
    drop(ports);
    let unavailable = UnavailablePeers::start(&prepared);

    assert_eq!(attempts(&authority), 0);
    let mut returned = authority.decode_checkpoint(&bytes).unwrap();
    assert_eq!(returned, original);
    assert_eq!(attempts(&authority), 1);
    for _ in 0..3 {
        let reused = authority.decode_checkpoint(&bytes).unwrap();
        assert_eq!(reused, original);
        assert!(std::ptr::eq(reused.checkpoint(), returned.checkpoint()));
        let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let borrowed =
            norito::with_decode_limits_scope(no_allocation, || reused.verified_tip_ref())
                .expect("the same genuinely imported immutable native tip needs no owned copy");
        assert!(std::ptr::eq(borrowed, returned.verified_tip_ref().unwrap()));
        borrowed
            .verify_global_scope(authority.config.network_id, authority.config.chain.as_str())
            .unwrap();
        assert_eq!(checkpoint_bytes(&reused).unwrap(), bytes);
    }
    assert_eq!(attempts(&authority), 1);
    assert_entry(&authority, &bytes);

    // Scope is read from the current explicit configuration on every hit, not from construction.
    let network = authority.config.network_id;
    authority.config.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"foreign checkpoint cache network"),
        ));
    assert_refused(&authority, &bytes, 2);
    authority.config.network_id = network;
    authority.decode_checkpoint(&bytes).unwrap();
    let chain = authority.config.chain.clone();
    authority.config.chain = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    assert_ne!(authority.config.chain, chain);
    assert_refused(&authority, &bytes, 2);
    authority.config.chain = chain;

    // Exact supplied bytes remain mandatory, even when an authenticated old image was warm.
    authority.decode_checkpoint(&bytes).unwrap();
    let mut changed = bytes.clone();
    changed.push(0);
    assert_refused(&authority, &changed, 2);
    assert_refused(&authority, &changed, 1);
    authority.decode_checkpoint(&bytes).unwrap();
    assert_refused(&authority, &[], 2);
    authority.decode_checkpoint(&bytes).unwrap();
    assert_refused(&authority, &vec![0; MAX_CHECKPOINT_BYTES + 1], 1);

    // A caller's genuine fresh observation advances only its returned verifier.
    let original_selected = authority.decode_checkpoint(&bytes).unwrap();
    let observing_original = returned.clone();
    assert!(std::ptr::eq(
        returned.checkpoint(),
        observing_original.checkpoint()
    ));
    let next = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "checkpoint import successor".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![next]), vec![true]);
    assert_eq!(returned.observe(&native, &[17; 32]).unwrap().verified(), 4);
    assert_eq!(returned.checkpoint().height(), 3);
    assert!(!std::ptr::eq(
        returned.verified_tip_ref().unwrap(),
        observing_original.verified_tip_ref().unwrap()
    ));
    assert!(!std::ptr::eq(
        returned.checkpoint(),
        observing_original.checkpoint()
    ));
    assert_eq!(checkpoint_bytes(&observing_original).unwrap(), bytes);
    assert_eq!(original.checkpoint().height(), 2);
    let before = attempts(&authority);
    let still_original = authority.decode_checkpoint(&bytes).unwrap();
    assert_eq!(still_original, original);
    assert!(std::ptr::eq(
        still_original.checkpoint(),
        original_selected.checkpoint()
    ));
    assert!(std::ptr::eq(
        still_original.verified_tip_ref().unwrap(),
        original_selected.verified_tip_ref().unwrap()
    ));
    assert_eq!(attempts(&authority), before);
    assert_entry(&authority, &bytes);
    let successor = checkpoint_bytes(&returned).unwrap();
    authority.decode_checkpoint(&successor).unwrap();
    assert_entry(&authority, &successor);
    assert_eq!(attempts(&authority), before + 1);
    authority.decode_checkpoint(&bytes).unwrap();
    assert_entry(&authority, &bytes);
    assert_eq!(attempts(&authority), before + 1);

    // Historical import reuse supplies neither original file custody nor a current observation.
    authority
        .directory
        .write_atomic("carrier.nrt", &bytes, PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        authority
            .retained_finality(&authority.directory, &signed)
            .unwrap()
            .unwrap()
            .height,
        2
    );
    std::fs::remove_file(authority.directory.path().join("carrier.nrt")).unwrap();
    assert!(
        authority
            .retained_finality(&authority.directory, &signed)
            .unwrap()
            .is_none()
    );
    authority
        .directory
        .write_atomic("current-checkpoint.nrt", &changed, PublishMode::CreateNew)
        .unwrap();
    let error = authority
        .observe_finality(Instant::now() + Duration::from_secs(60))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid retained native operation checkpoint")
    );
    assert!(unavailable.requests.lock().unwrap().is_empty());
    std::fs::remove_file(authority.directory.path().join("current-checkpoint.nrt")).unwrap();
    authority.decode_checkpoint(&bytes).unwrap();
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let peer = generation.read("peer3.toml", 1024 * 1024).unwrap();
    std::fs::remove_file(generation.path().join("peer3.toml")).unwrap();
    assert!(authority.validate_profile().is_err());
    // Existing bytes still prove their historical cut, never the missing live profile.
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    generation
        .write_atomic("peer3.toml", &peer, PublishMode::CreateNew)
        .unwrap();
    authority.validate_profile().unwrap();

    // Optional cache synchronization cannot return a stale success or replace canonical errors.
    let held = authority
        .effective_checkpoint_cache()
        .entry
        .try_lock()
        .unwrap();
    let before = attempts(&authority);
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    assert!(authority.decode_checkpoint(&changed).is_err());
    assert_eq!(attempts(&authority), before + 2);
    drop(held);
    assert_entry(&authority, &bytes);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = authority.effective_checkpoint_cache().entry.lock().unwrap();
            panic!("poison only the optional checkpoint memo");
        }))
        .is_err()
    );
    let before = attempts(&authority);
    assert!(authority.decode_checkpoint(&changed).is_err());
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    assert_eq!(attempts(&authority), before + 2);
    let poisoned = match authority.effective_checkpoint_cache().entry.try_lock() {
        Err(TryLockError::Poisoned(poisoned)) => poisoned,
        _ => panic!("optional memo remains poisoned"),
    };
    assert!(poisoned.into_inner().is_empty());
    assert!(unavailable.requests.lock().unwrap().is_empty());
}

#[test]
fn checkpoint_reuse_preserves_service_authority_send_and_sync() {
    fn requires_send_sync<T: Send + Sync>() {}
    requires_send_sync::<ServiceAuthority>();
    requires_send_sync::<FinalityVerifier>();
}

#[test]
fn warm_checkpoint_import_rechecks_active_caller_admission_and_retries_original_bytes() {
    use iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint;
    use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError};

    fn limits(allocation: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(
            1024 * 1024,
            MAX_CHECKPOINT_BYTES,
            8 * 1024 * 1024,
            allocation,
            64,
        )
    }

    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "checkpoint-active-owner",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let signed = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "active caller checkpoint admission".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let original = native.observe(&authority);
    assert_eq!(original.checkpoint().height(), 2);
    let bytes = checkpoint_bytes(&original).unwrap();
    drop(ports);
    let unavailable = UnavailablePeers::start(&prepared);

    // The source is genuinely paid and fully certified. Warm first, then install the
    // new caller; physical Arc sharing alone would otherwise bypass its input admission.
    let warm = authority.decode_checkpoint(&bytes).unwrap();
    assert_entry(&authority, &bytes);
    assert_eq!(attempts(&authority), 1);
    let baseline_budget = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let baseline = baseline_budget
        .with(|| {
            assert!(norito::core::decode_limits_active());
            decode_checkpoint(
                &bytes,
                authority.config.network_id,
                authority.config.chain.as_str(),
            )
        })
        .unwrap();
    let charge = baseline_budget.consumed_allocated_bytes();
    assert!(charge > 0 && charge < 64 * 1024 * 1024);
    let strict = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let before = attempts(&authority);
    let admitted = strict.with(|| authority.decode_checkpoint(&bytes)).unwrap();
    assert_eq!(strict.consumed_allocated_bytes(), charge);
    assert_eq!(attempts(&authority), before + 1);
    assert_eq!(admitted, baseline);
    assert!(!std::ptr::eq(admitted.checkpoint(), warm.checkpoint()));
    assert_eq!(checkpoint_bytes(&admitted).unwrap(), bytes);
    assert_eq!(
        crate::managed::native_operation::verify_carrier(&admitted, &signed)
            .unwrap()
            .height,
        2
    );
    assert!(
        authority
            .effective_checkpoint_cache()
            .entry
            .try_lock()
            .unwrap()
            .is_empty()
    );
    assert!(!norito::core::decode_limits_active());
    let cold_budget = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let before = attempts(&authority);
    let cold = cold_budget
        .with(|| authority.decode_checkpoint(&bytes))
        .unwrap();
    assert_eq!(cold, baseline);
    assert_eq!(cold_budget.consumed_allocated_bytes(), charge);
    assert_eq!(attempts(&authority), before + 1);
    assert!(
        authority
            .effective_checkpoint_cache()
            .entry
            .try_lock()
            .unwrap()
            .is_empty()
    );

    // Derive a positive refusal from the real first allocation request. This is
    // neither a guessed field width nor total-success-minus-one: optional memo
    // admission could decline at the latter ceiling and still permit success.
    let zero = DecodeBudgetContext::new(limits(0));
    let first = zero
        .with(|| {
            norito::decode_canonical_for_admission::<SumeragiFinalityCheckpoint>(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
        })
        .unwrap_err();
    assert_eq!(first.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let first_request = match first.into_error().decode_resource_error().unwrap() {
        DecodeResourceError::TotalAllocationExceeded {
            attempted,
            limit: 0,
        } => attempted,
        other => panic!("original allocation refusal expected: {other:?}"),
    };
    assert!(first_request > 1);
    let positive_refusal = usize::try_from(first_request.checked_sub(1).unwrap()).unwrap();
    for allocation in [0, positive_refusal] {
        let warm = authority.decode_checkpoint(&bytes).unwrap();
        assert_eq!(warm, original);
        assert_entry(&authority, &bytes);
        let expected_budget = DecodeBudgetContext::new(limits(allocation));
        let expected = expected_budget
            .with(|| {
                decode_checkpoint(
                    &bytes,
                    authority.config.network_id,
                    authority.config.chain.as_str(),
                )
            })
            .unwrap_err()
            .to_string();
        let actual_budget = DecodeBudgetContext::new(limits(allocation));
        let before = attempts(&authority);
        let actual = actual_budget
            .with(|| authority.decode_checkpoint(&bytes))
            .unwrap_err();
        assert_eq!(actual.to_string(), expected);
        assert_eq!(attempts(&authority), before + 1);
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
        assert!(
            authority
                .effective_checkpoint_cache()
                .entry
                .try_lock()
                .unwrap()
                .is_empty()
        );
        assert!(!norito::core::decode_limits_active());
        // Preserve the original typed decoder provenance at the canonical input
        // boundary; the managed facade deliberately retains its existing error.
        let provenance_budget = DecodeBudgetContext::new(limits(allocation));
        let provenance = provenance_budget
            .with(|| {
                norito::decode_canonical_for_admission::<SumeragiFinalityCheckpoint>(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
            })
            .unwrap_err();
        assert_eq!(provenance.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        assert_eq!(
            provenance.into_error().decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded {
                attempted: first_request,
                limit: u64::try_from(allocation).unwrap(),
            })
        );
        let retry = authority.decode_checkpoint(&bytes).unwrap();
        assert_eq!(retry, original);
        assert_entry(&authority, &bytes);
        let before = attempts(&authority);
        let hit = authority.decode_checkpoint(&bytes).unwrap();
        assert_eq!(attempts(&authority), before);
        assert!(std::ptr::eq(hit.checkpoint(), retry.checkpoint()));
        let zero = DecodeBudgetContext::new(limits(0));
        let tip = zero.with(|| hit.verified_tip_ref()).unwrap();
        assert!(std::ptr::eq(tip, retry.verified_tip_ref().unwrap()));
        assert_eq!(zero.consumed_allocated_bytes(), 0);
    }

    // Nonwaiting held/poisoned gates keep the original cold path. An active
    // successful import must not populate a second retained cache graph.
    let held = authority
        .effective_checkpoint_cache()
        .entry
        .try_lock()
        .unwrap();
    let before = attempts(&authority);
    let held_budget = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let held_admitted = held_budget
        .with(|| authority.decode_checkpoint(&bytes))
        .unwrap();
    assert_eq!(held_admitted, baseline);
    assert_eq!(held_budget.consumed_allocated_bytes(), charge);
    let refused_budget = DecodeBudgetContext::new(limits(positive_refusal));
    assert!(
        refused_budget
            .with(|| authority.decode_checkpoint(&bytes))
            .is_err()
    );
    assert_eq!(attempts(&authority), before + 2);
    assert!(!std::ptr::eq(
        held.slots
            .iter()
            .flatten()
            .find(|entry| entry.bytes == bytes)
            .unwrap()
            .verifier
            .checkpoint(),
        held_admitted.checkpoint(),
    ));
    drop(held);
    assert_entry(&authority, &bytes);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = authority.effective_checkpoint_cache().entry.lock().unwrap();
            panic!("poison only the optional active-owner memo");
        }))
        .is_err()
    );
    let before = attempts(&authority);
    let poisoned_budget = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let poisoned_admitted = poisoned_budget
        .with(|| authority.decode_checkpoint(&bytes))
        .unwrap();
    assert_eq!(poisoned_admitted, baseline);
    assert_eq!(poisoned_budget.consumed_allocated_bytes(), charge);
    let poisoned_refusal = DecodeBudgetContext::new(limits(positive_refusal));
    assert!(
        poisoned_refusal
            .with(|| authority.decode_checkpoint(&bytes))
            .is_err()
    );
    assert_eq!(attempts(&authority), before + 2);
    let poisoned = match authority.effective_checkpoint_cache().entry.try_lock() {
        Err(TryLockError::Poisoned(poisoned)) => poisoned,
        _ => panic!("original poisoned memo must remain poisoned"),
    };
    assert!(poisoned.into_inner().is_empty());
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    assert!(unavailable.requests.lock().unwrap().is_empty());
    assert_eq!(native.chain.height(), 2);
    assert_eq!(checkpoint_bytes(&original).unwrap(), bytes);
}

#[test]
fn borrowed_epoch_imports_keep_late_outer_admission_and_exact_single_cache_entry() {
    use iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint;
    use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError};

    fn limits(allocation: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(
            1024 * 1024,
            MAX_CHECKPOINT_BYTES,
            8 * 1024 * 1024,
            allocation,
            64,
        )
    }
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "checkpoint-borrowed-epoch",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let signed = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "borrowed pure epoch admission".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let original = native.observe(&authority);
    let bytes = checkpoint_bytes(&original).unwrap();
    assert_eq!(original.checkpoint().height(), 2);
    drop(ports);
    let unavailable = UnavailablePeers::start(&prepared);

    let mut validation = EpochValidationScope::new();
    let mut imports = CheckpointImports::new(&authority, Some(&mut validation));
    let warm = imports.decode(&bytes).unwrap();
    assert_eq!(warm, original);
    assert_entry(&authority, &bytes);
    let baseline_budget = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let expected = baseline_budget
        .with(|| {
            decode_checkpoint(
                &bytes,
                authority.config.network_id,
                authority.config.chain.as_str(),
            )
        })
        .unwrap();
    let charge = baseline_budget.consumed_allocated_bytes();
    assert!(charge > 0 && charge < 64 * 1024 * 1024);
    let budget = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let before = attempts(&authority);
    let admitted = budget.with(|| imports.decode(&bytes)).unwrap();
    assert_eq!(admitted, expected);
    assert_eq!(budget.consumed_allocated_bytes(), charge);
    assert_eq!(attempts(&authority), before + 1);
    assert!(!std::ptr::eq(admitted.checkpoint(), warm.checkpoint()));
    assert!(
        authority
            .effective_checkpoint_cache()
            .entry
            .try_lock()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        crate::managed::native_operation::verify_carrier(&admitted, &signed)
            .unwrap()
            .height,
        2
    );

    let zero = DecodeBudgetContext::new(limits(0));
    let first = zero
        .with(|| {
            norito::decode_canonical_for_admission::<SumeragiFinalityCheckpoint>(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
        })
        .unwrap_err();
    assert_eq!(first.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let first_request = match first.into_error().decode_resource_error().unwrap() {
        DecodeResourceError::TotalAllocationExceeded {
            attempted,
            limit: 0,
        } => attempted,
        other => panic!("original allocation refusal required: {other:?}"),
    };
    assert!(first_request > 1);
    let cap = usize::try_from(first_request.checked_sub(1).unwrap()).unwrap();
    for allocation in [0, cap] {
        imports.decode(&bytes).unwrap();
        assert_entry(&authority, &bytes);
        let original_budget = DecodeBudgetContext::new(limits(allocation));
        let expected = original_budget
            .with(|| {
                decode_checkpoint(
                    &bytes,
                    authority.config.network_id,
                    authority.config.chain.as_str(),
                )
            })
            .unwrap_err()
            .to_string();
        let actual_budget = DecodeBudgetContext::new(limits(allocation));
        let before = attempts(&authority);
        let actual = actual_budget.with(|| imports.decode(&bytes)).unwrap_err();
        assert_eq!(actual.to_string(), expected);
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            original_budget.consumed_allocated_bytes()
        );
        assert_eq!(attempts(&authority), before + 1);
        assert!(
            authority
                .effective_checkpoint_cache()
                .entry
                .try_lock()
                .unwrap()
                .is_empty()
        );
        let retry = imports.decode(&bytes).unwrap();
        assert_eq!(retry, original);
        assert_entry(&authority, &bytes);
    }
    let held = authority
        .effective_checkpoint_cache()
        .entry
        .try_lock()
        .unwrap();
    let before = attempts(&authority);
    let held_budget = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    assert_eq!(
        held_budget.with(|| imports.decode(&bytes)).unwrap(),
        expected
    );
    assert_eq!(held_budget.consumed_allocated_bytes(), charge);
    assert_eq!(attempts(&authority), before + 1);
    drop(held);
    assert_entry(&authority, &bytes);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = authority.effective_checkpoint_cache().entry.lock().unwrap();
            panic!("poison only the optional borrowed-epoch memo");
        }))
        .is_err()
    );
    let before = attempts(&authority);
    let poisoned_budget = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let admitted = poisoned_budget.with(|| imports.decode(&bytes)).unwrap();
    assert_eq!(admitted, expected);
    assert_eq!(poisoned_budget.consumed_allocated_bytes(), charge);
    let refused_budget = DecodeBudgetContext::new(limits(cap));
    assert!(refused_budget.with(|| imports.decode(&bytes)).is_err());
    assert_eq!(attempts(&authority), before + 2);
    let poisoned = match authority.effective_checkpoint_cache().entry.try_lock() {
        Err(TryLockError::Poisoned(poisoned)) => poisoned,
        _ => panic!("original optional memo remains poisoned"),
    };
    assert!(poisoned.into_inner().is_empty());
    drop(imports);
    drop(validation);
    let before = attempts(&authority);
    let same = authority.decode_checkpoint(&bytes).unwrap();
    assert_eq!(same, original);
    assert_eq!(attempts(&authority), before + 1);
    assert_eq!(checkpoint_bytes(&same).unwrap(), bytes);
    assert!(unavailable.requests.lock().unwrap().is_empty());
    assert_eq!(native.chain.height(), 2);
}
