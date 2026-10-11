//! Real cross-purpose checkpoint imports retain fresh custody and one bounded lexical memo.

use super::{
    tests::{assert_entry, assert_refused, attempts},
    *,
};
use crate::managed::{
    LocalnetPorts,
    native_operation::{
        checkpoint_bytes,
        test_support::{
            UnavailablePeers,
            native_fixture::{NativeFixture, quote_instructions},
        },
    },
    service_authority::NetworkPurpose,
};
use iroha_data_model::{
    isi::{InstructionBox, Log},
    transaction::SignedTransaction,
};
use iroha_fs::{FileIdentity, PrivateDirectory, PublishMode};
use norito::core::DecodeBudgetContext;
use std::sync::atomic::Ordering;

struct Fixture {
    _temporary: tempfile::TempDir,
    parent: ServiceAuthority,
    native: NativeFixture,
    unavailable: UnavailablePeers,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "graph-checkpoint-scope",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let parent =
            ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
        for purpose in [
            NetworkPurpose::InitialReservePolicy,
            NetworkPurpose::InitialReputationPolicy,
            NetworkPurpose::BuildRegistry,
        ] {
            drop(ServiceAuthority::open_network(&prepared, purpose).unwrap());
        }
        let native = NativeFixture::from_generated(&prepared, &parent);
        drop(ports);
        let unavailable = UnavailablePeers::start(&prepared);
        Self {
            _temporary: temporary,
            parent,
            native,
            unavailable,
        }
    }

    fn paid(&mut self, label: &str) -> (SignedTransaction, FinalityVerifier, Vec<u8>) {
        let signed = quote_instructions(
            &self.native,
            &self.parent.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                label.into(),
            ))],
        );
        assert_eq!(self.native.chain.commit(vec![signed.clone()]), vec![true]);
        let original = self.native.observe(&self.parent);
        let bytes = checkpoint_bytes(&original).unwrap();
        (signed, original, bytes)
    }

    fn pair(&self, scope: &CheckpointImportScope) -> (ServiceAuthority, ServiceAuthority) {
        let a = ServiceAuthority::open_network_existing_from_original(
            &self.parent,
            NetworkPurpose::InitialReservePolicy,
            Some(scope),
        )
        .unwrap()
        .unwrap();
        let b = ServiceAuthority::open_network_existing_from_original(
            &self.parent,
            NetworkPurpose::InitialReputationPolicy,
            Some(scope),
        )
        .unwrap()
        .unwrap();
        assert!(std::ptr::eq(
            a.effective_checkpoint_cache(),
            b.effective_checkpoint_cache()
        ));
        assert!(std::ptr::eq(
            a.effective_checkpoint_cache(),
            scope.cache.as_ref()
        ));
        assert_ne!(
            a.directory.identity().unwrap(),
            b.directory.identity().unwrap()
        );
        assert_ne!(
            FileIdentity::of(&a._lock).unwrap(),
            FileIdentity::of(&b._lock).unwrap()
        );
        for child in [&a, &b] {
            assert!(child.checkpoint_cache.entry.try_lock().unwrap().is_empty());
            assert_eq!(
                child
                    .checkpoint_cache
                    .decode_attempts
                    .load(Ordering::Relaxed),
                0
            );
            child.validate_profile().unwrap();
        }
        (a, b)
    }
}

fn checkpoint_limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        1024 * 1024,
        MAX_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        allocation,
        64,
    )
}

#[test]
fn graph_scope_shares_cold_imports_without_sharing_source_lock_or_transaction_verdicts() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::new();
    let scope = CheckpointImportScope::for_original(&fixture.parent).unwrap();
    let (a, b) = fixture.pair(&scope);
    let (signed, original, bytes) = fixture.paid("shared original carrier");
    let _imports = ServiceAuthority::test_begin_graph_import_counts();
    for child in [&a, &b] {
        child
            .directory
            .write_atomic("carrier.nrt", &bytes, PublishMode::CreateNew)
            .unwrap();
        child.validate_profile().unwrap();
        assert_eq!(
            child
                .retained_finality(&child.directory, &signed)
                .unwrap()
                .unwrap()
                .height,
            2
        );
        child.validate_profile().unwrap();
    }
    assert_eq!(attempts(&a), 1);
    assert_eq!(attempts(&b), 1);
    assert_eq!(ServiceAuthority::test_graph_import_snapshot(), Some(1));
    assert_entry(&a, &bytes);
    assert_entry(&b, &bytes);

    // Each purpose still reads its own original, even when another purpose warmed this image.
    std::fs::remove_file(b.directory.path().join("carrier.nrt")).unwrap();
    assert!(
        b.retained_finality(&b.directory, &signed)
            .unwrap()
            .is_none()
    );
    let mut changed = bytes.clone();
    changed.push(0);
    b.directory
        .write_atomic("carrier.nrt", &changed, PublishMode::CreateNew)
        .unwrap();
    assert!(b.retained_finality(&b.directory, &signed).is_err());
    b.directory
        .write_atomic("carrier.nrt", &bytes, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        b.retained_finality(&b.directory, &signed)
            .unwrap()
            .unwrap()
            .height,
        2
    );
    let before = attempts(&a);
    let uncommitted = quote_instructions(
        &fixture.native,
        &fixture.parent.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "validly signed but absent from the shared certified block".into(),
        ))],
    );
    assert_ne!(uncommitted, signed);
    assert!(b.retained_finality(&b.directory, &uncommitted).is_err());
    assert_eq!(attempts(&a), before, "a hit is not transaction inclusion");
    assert_eq!(
        a.retained_finality(&a.directory, &signed)
            .unwrap()
            .unwrap()
            .height,
        2
    );

    // Profile and lock checks are independent of immutable import reuse, exactly as in graph callers.
    let generation = PrivateDirectory::open_exact(
        fixture
            .parent
            .prepared
            .context
            .client_config
            .parent()
            .unwrap(),
    )
    .unwrap();
    let peer = generation.read("peer3.toml", 1024 * 1024).unwrap();
    std::fs::remove_file(generation.path().join("peer3.toml")).unwrap();
    assert!(a.validate_profile().is_err());
    assert!(b.validate_profile().is_err());
    assert!(
        ServiceAuthority::open_network_existing_from_original(
            &fixture.parent,
            NetworkPurpose::BuildRegistry,
            Some(&scope),
        )
        .is_err()
    );
    assert_eq!(a.decode_checkpoint(&bytes).unwrap(), original);
    generation
        .write_atomic("peer3.toml", &peer, PublishMode::CreateNew)
        .unwrap();
    a.validate_profile().unwrap();
    b.validate_profile().unwrap();

    let lock = a.directory.path().join("operation.lock");
    let saved_lock = a.directory.path().join("saved-operation.lock");
    let lock_identity = FileIdentity::of(&a._lock).unwrap();
    #[cfg(unix)]
    {
        std::fs::rename(&lock, &saved_lock).unwrap();
        assert!(a.validate_profile().is_err());
        assert_eq!(b.decode_checkpoint(&bytes).unwrap(), original);
        std::fs::rename(&saved_lock, &lock).unwrap();
    }
    #[cfg(windows)]
    assert!(std::fs::rename(&lock, &saved_lock).is_err());
    a.validate_profile().unwrap();
    assert_eq!(FileIdentity::of(&a._lock).unwrap(), lock_identity);
    assert_eq!(
        a.directory
            .read("carrier.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        bytes
    );

    let original_path = a.directory.path().to_path_buf();
    let displaced = original_path.with_file_name("saved-reserve-purpose");
    let identity = a.directory.identity().unwrap();
    #[cfg(unix)]
    {
        std::fs::rename(&original_path, &displaced).unwrap();
        assert!(a.retained_finality(&a.directory, &signed).is_err());
        let replacement = PrivateDirectory::open_or_create(&original_path).unwrap();
        assert!(a.retained_finality(&a.directory, &signed).is_err());
        drop(replacement);
        std::fs::remove_dir(&original_path).unwrap();
        std::fs::rename(&displaced, &original_path).unwrap();
    }
    #[cfg(windows)]
    assert!(std::fs::rename(&original_path, &displaced).is_err());
    a.validate_profile().unwrap();
    assert_eq!(a.directory.identity().unwrap(), identity);
    assert_eq!(
        a.retained_finality(&a.directory, &signed)
            .unwrap()
            .unwrap()
            .height,
        2
    );
    assert!(fixture.unavailable.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.native.chain.height(), 2);
}

#[test]
fn graph_scope_keeps_exact_keys_observation_isolation_and_cold_return_lifetime() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::new();
    let scope = CheckpointImportScope::for_original(&fixture.parent).unwrap();
    let weak = Arc::downgrade(&scope.cache);
    let (a, mut b) = fixture.pair(&scope);
    let (_, original, bytes) = fixture.paid("shared immutable observation original");
    let mut returned = a.decode_checkpoint(&bytes).unwrap();
    let isolated = b.decode_checkpoint(&bytes).unwrap();
    assert_eq!(attempts(&a), 1);
    assert!(std::ptr::eq(returned.checkpoint(), isolated.checkpoint()));

    let network = b.config.network_id;
    b.config.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"different shared import network"),
        ));
    assert_refused(&b, &bytes, 2);
    b.config.network_id = network;
    a.decode_checkpoint(&bytes).unwrap();
    let chain = b.config.chain.clone();
    b.config.chain = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    assert_ne!(b.config.chain, chain);
    assert_refused(&b, &bytes, 2);
    b.config.chain = chain;
    a.decode_checkpoint(&bytes).unwrap();
    let mut malformed = bytes.clone();
    malformed.push(0);
    assert_refused(&b, &malformed, 2);
    let selected = a.decode_checkpoint(&bytes).unwrap();
    let before = attempts(&a);
    let (_, successor, _) = fixture.paid("shared immutable observation successor");
    assert_eq!(
        returned
            .observe(&fixture.native, &[17; 32])
            .unwrap()
            .verified(),
        4
    );
    assert_eq!(returned.checkpoint().height(), 3);
    assert_eq!(returned, successor);
    assert_eq!(checkpoint_bytes(&isolated).unwrap(), bytes);
    assert_eq!(isolated, original);
    let hit = b.decode_checkpoint(&bytes).unwrap();
    assert!(std::ptr::eq(hit.checkpoint(), selected.checkpoint()));
    assert!(std::ptr::eq(
        hit.verified_tip_ref().unwrap(),
        selected.verified_tip_ref().unwrap()
    ));
    assert_eq!(attempts(&a), before);
    assert!(!std::ptr::eq(returned.checkpoint(), hit.checkpoint()));

    // Caller verifiers may escape; the graph's memo and native owners do not escape with them.
    drop(a);
    drop(b);
    drop(scope);
    assert!(weak.upgrade().is_none());
    assert_eq!(checkpoint_bytes(&hit).unwrap(), bytes);
    let next_scope = CheckpointImportScope::for_original(&fixture.parent).unwrap();
    let (next, other) = fixture.pair(&next_scope);
    assert_eq!(attempts(&next), 0);
    let cold = next.decode_checkpoint(&bytes).unwrap();
    assert_eq!(cold, original);
    assert_eq!(attempts(&other), 1);
    assert!(!std::ptr::eq(cold.checkpoint(), hit.checkpoint()));
    assert_entry(&other, &bytes);
    assert!(fixture.unavailable.requests.lock().unwrap().is_empty());
}

#[test]
fn graph_scope_preserves_effective_fifo_limits_and_active_owned_fallback() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::new();
    let scope = CheckpointImportScope::for_original(&fixture.parent).unwrap();
    let (a, b) = fixture.pair(&scope);
    let mut originals = Vec::new();
    let mut images = Vec::new();
    for index in 0..4 {
        let (_, original, image) = fixture.paid(&format!("cross-owner FIFO original {index}"));
        originals.push(original);
        images.push(image);
    }
    for (index, image) in images[..3].iter().enumerate() {
        let child = if index % 2 == 0 { &a } else { &b };
        assert_eq!(child.decode_checkpoint(image).unwrap(), originals[index]);
        assert_entry(&a, image);
        assert_entry(&b, image);
    }
    assert_eq!(attempts(&a), 3);
    for image in &images[..3] {
        a.decode_checkpoint(image).unwrap();
        b.decode_checkpoint(image).unwrap();
    }
    assert_eq!(attempts(&b), 3);
    b.decode_checkpoint(&images[3]).unwrap();
    assert_eq!(attempts(&a), 4);
    {
        let selected = scope.cache.entry.try_lock().unwrap();
        assert_eq!(selected.len, SLOTS);
        for offset in 0..SLOTS {
            assert_eq!(
                selected.slots[(selected.first + offset) % SLOTS]
                    .as_ref()
                    .unwrap()
                    .bytes,
                images[offset + 1]
            );
        }
    }
    let escaped = a.decode_checkpoint(&images[0]).unwrap();
    assert_eq!(attempts(&b), 5);
    {
        let mut selected = scope.cache.entry.try_lock().unwrap();
        assert!(selected.make_room(
            MAX_CHECKPOINT_BYTES,
            retained_import_envelope(MAX_CHECKPOINT_BYTES).unwrap()
        ));
        assert!(selected.is_empty());
    }
    assert_eq!(checkpoint_bytes(&escaped).unwrap(), images[0]);

    let baseline = DecodeBudgetContext::new(checkpoint_limits(64 * 1024 * 1024));
    let expected = baseline
        .with(|| decode_checkpoint(&images[0], a.config.network_id, a.config.chain.as_str()))
        .unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1 && charge < 64 * 1024 * 1024);
    for cap in [0, 1, charge] {
        for image in &images[..3] {
            a.decode_checkpoint(image).unwrap();
        }
        assert_eq!(scope.cache.entry.try_lock().unwrap().len, SLOTS);
        let ordinary = DecodeBudgetContext::new(checkpoint_limits(cap));
        let original_result = ordinary
            .with(|| decode_checkpoint(&images[0], a.config.network_id, a.config.chain.as_str()));
        let active = DecodeBudgetContext::new(checkpoint_limits(cap));
        let before = attempts(&a);
        let mut imports = CheckpointImports::new(&b, None);
        let actual = active.with(|| imports.decode(&images[0]));
        assert_eq!(attempts(&a), before + 1);
        assert_eq!(
            active.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        match (actual, original_result) {
            (Ok(actual), Ok(original)) => {
                assert_eq!(actual, original);
                assert_eq!(actual, expected);
                assert!(!std::ptr::eq(actual.checkpoint(), escaped.checkpoint()));
            }
            (Err(actual), Err(original)) => assert_eq!(actual.to_string(), original.to_string()),
            other => panic!("shared active admission must match the canonical producer: {other:?}"),
        }
        assert!(
            a.effective_checkpoint_cache()
                .entry
                .try_lock()
                .unwrap()
                .is_empty()
        );
        assert!(
            b.effective_checkpoint_cache()
                .entry
                .try_lock()
                .unwrap()
                .is_empty()
        );
        assert!(a.checkpoint_cache.entry.try_lock().unwrap().is_empty());
    }

    // Passing a scope cannot bypass full constructor admission or attach it to an active child.
    fn profile_limits(allocation: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocation, 64)
    }
    let ordinary = DecodeBudgetContext::new(profile_limits(64 * 1024 * 1024));
    let (expected_child, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            ordinary.with(|| {
                ServiceAuthority::open_network_existing(
                    &fixture.parent.prepared,
                    NetworkPurpose::BuildRegistry,
                )
            })
        });
    let expected_child = expected_child.unwrap().unwrap();
    assert_eq!(parses, 1);
    assert!(matches!(
        &expected_child.profile,
        AuthorityProfile::Owned(_)
    ));
    let profile_charge = usize::try_from(ordinary.consumed_allocated_bytes()).unwrap();
    assert!(profile_charge > 0);
    let child_identity = expected_child.directory.identity().unwrap();
    drop(expected_child);
    let references = Arc::strong_count(&scope.cache);
    for cap in [0, profile_charge - 1, profile_charge] {
        let ordinary = DecodeBudgetContext::new(profile_limits(cap));
        let expected = ordinary.with(|| {
            ServiceAuthority::open_network_existing(
                &fixture.parent.prepared,
                NetworkPurpose::BuildRegistry,
            )
        });
        let expected = match expected {
            Ok(Some(child)) => {
                drop(child);
                Ok(())
            }
            Err(error) => Err(error.to_string()),
            Ok(None) => panic!("seeded original must exist"),
        };
        let active = DecodeBudgetContext::new(profile_limits(cap));
        let (actual, parses) =
            crate::localnet::service_authorities::count_profile_validations(|| {
                active.with(|| {
                    assert!(CheckpointImportScope::for_original(&fixture.parent).is_none());
                    ServiceAuthority::open_network_existing_from_original(
                        &fixture.parent,
                        NetworkPurpose::BuildRegistry,
                        Some(&scope),
                    )
                })
            });
        assert_eq!(
            active.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        match (actual, expected) {
            (Ok(Some(child)), Ok(())) => {
                assert_eq!(parses, 1);
                assert!(matches!(&child.profile, AuthorityProfile::Owned(_)));
                assert!(child.checkpoint_import_scope().is_none());
                assert!(!std::ptr::eq(
                    child.effective_checkpoint_cache(),
                    scope.cache.as_ref()
                ));
                assert_eq!(child.directory.identity().unwrap(), child_identity);
            }
            (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected),
            _ => panic!("scope must not change original constructor admission"),
        }
        assert_eq!(Arc::strong_count(&scope.cache), references);
    }

    // A held or poisoned optional shared gate remains a cold, nonwaiting canonical path.
    a.decode_checkpoint(&images[0]).unwrap();
    let held = scope.cache.entry.try_lock().unwrap();
    let before = attempts(&a);
    assert_eq!(b.decode_checkpoint(&images[0]).unwrap(), originals[0]);
    let mut changed = images[0].clone();
    changed.push(0);
    assert!(b.decode_checkpoint(&changed).is_err());
    assert_eq!(attempts(&a), before + 2);
    drop(held);
    assert_entry(&a, &images[0]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = scope.cache.entry.lock().unwrap();
            panic!("poison only the shared optional import memo");
        }))
        .is_err()
    );
    let before = attempts(&a);
    assert!(b.decode_checkpoint(&changed).is_err());
    assert_eq!(a.decode_checkpoint(&images[0]).unwrap(), originals[0]);
    assert_eq!(attempts(&b), before + 2);
    match scope.cache.entry.try_lock() {
        Err(TryLockError::Poisoned(poisoned)) => assert!(poisoned.into_inner().is_empty()),
        _ => panic!("the same actual selected memo must remain poisoned"),
    }

    let Fixture {
        _temporary,
        parent,
        native,
        unavailable,
    } = fixture;
    let prepared = parent.prepared.clone();
    drop(a);
    drop(b);
    drop(parent);
    let owner_budget = DecodeBudgetContext::new(profile_limits(64 * 1024 * 1024));
    let owned = owner_budget
        .with(|| {
            ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
        })
        .unwrap()
        .unwrap();
    assert!(matches!(&owned.profile, AuthorityProfile::Owned(_)));
    assert!(CheckpointImportScope::for_original(&owned).is_none());
    let (child, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        ServiceAuthority::open_network_existing_from_original(
            &owned,
            NetworkPurpose::BuildRegistry,
            Some(&scope),
        )
    });
    let child = child.unwrap().unwrap();
    assert_eq!(
        parses, 1,
        "Owned parents outside their old scope still capture the full original"
    );
    assert!(child.checkpoint_import_scope().is_none());
    assert!(!std::ptr::eq(
        child.effective_checkpoint_cache(),
        scope.cache.as_ref()
    ));
    assert_eq!(child.directory.identity().unwrap(), child_identity);
    child.validate_profile().unwrap();
    assert!(unavailable.requests.lock().unwrap().is_empty());
    assert_eq!(native.chain.height(), 5);
}

// Measure the existing native context roundtrip under a generous finite owner. A cold
// valid miss must successfully admit and retain its owned context; an exact retained hit
// returns only the Copy core projection. Unlike an allocation-zero probe, this deliberately
// permits insertion on a miss and compares its positive charge with a hit's zero charge.
fn graph_epoch_charge(
    cache: &CheckpointCache,
    context: &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
) -> u64 {
    let shared = cache.epoch_validation.as_ref().unwrap();
    let mut validation = match shared.try_lock() {
        Ok(validation) => validation,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => panic!("test probe needs its own unborrowed workspace"),
    };
    epoch_charge(&mut validation, context)
}

fn epoch_charge(
    validation: &mut EpochValidationScope,
    context: &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
) -> u64 {
    let finite = DecodeBudgetContext::new(checkpoint_limits(64 * 1024 * 1024));
    finite.with(|| validation.core_epoch(context)).unwrap();
    finite.consumed_allocated_bytes()
}

#[test]
fn graph_epoch_scope_reuses_exact_context_across_cold_imports_and_ends_with_lexical_owner() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::new();
    let context =
        iroha_data_model::sumeragi_finality::authenticated_genesis(fixture.native.chain.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
    let (_, first, first_bytes) = fixture.paid("first graph epoch import");
    let (_, second, second_bytes) = fixture.paid("second graph epoch import");
    assert_ne!(first_bytes, second_bytes);
    let scope = CheckpointImportScope::for_original(&fixture.parent).unwrap();
    let weak = Arc::downgrade(&scope.cache);
    let (a, b) = fixture.pair(&scope);
    assert!(fixture.parent.checkpoint_cache.epoch_validation.is_none());
    assert_eq!(
        std::mem::size_of::<Option<Box<Mutex<EpochValidationScope>>>>(),
        std::mem::size_of::<usize>(),
        "the standalone owner retains one optional pointer, not an inline epoch pair"
    );
    let mut cold = EpochValidationScope::new();
    let cold_charge = epoch_charge(&mut cold, &context);
    assert!(
        cold_charge > 0,
        "the finite native context roundtrip must admit owned allocations"
    );
    drop(cold);
    assert_eq!(a.decode_checkpoint(&first_bytes).unwrap(), first);
    assert_eq!(attempts(&a), 1);
    assert_eq!(graph_epoch_charge(&scope.cache, &context), 0);
    let escaped = b.decode_checkpoint(&second_bytes).unwrap();
    assert_eq!(escaped, second);
    assert_eq!(
        attempts(&a),
        2,
        "both distinct frames ran the cold producer"
    );
    assert_eq!(graph_epoch_charge(&scope.cache, &context), 0);

    // Existing caller-local scopes are not a second populated pair under the graph owner.
    scope.cache.entry.try_lock().unwrap().clear();
    let mut local = EpochValidationScope::new();
    let mut imports = CheckpointImports::new(&b, Some(&mut local));
    assert_eq!(imports.decode(&first_bytes).unwrap(), first);
    drop(imports);
    assert_eq!(attempts(&a), 3);
    assert_eq!(epoch_charge(&mut local, &context), cold_charge);
    drop(local);
    assert_eq!(graph_epoch_charge(&scope.cache, &context), 0);
    let mut changed = context.clone();
    changed.leader_seed[0] ^= 1;
    changed.validate().unwrap();
    assert!(
        graph_epoch_charge(&scope.cache, &changed) > 0,
        "the same epoch number with a different complete body is a real native miss"
    );
    let mut invalid = context.clone();
    invalid.committee[0].proof_of_possession[0] ^= 1;
    assert!(invalid.validate().is_err());
    {
        let mut validation = scope
            .cache
            .epoch_validation
            .as_ref()
            .unwrap()
            .try_lock()
            .unwrap();
        assert!(validation.core_epoch(&invalid).is_err());
    }
    assert_eq!(graph_epoch_charge(&scope.cache, &context), 0);

    let mut malformed = first_bytes.clone();
    malformed.push(0);
    let original_error =
        decode_checkpoint(&malformed, a.config.network_id, a.config.chain.as_str())
            .unwrap_err()
            .to_string();
    assert_eq!(
        b.decode_checkpoint(&malformed).unwrap_err().to_string(),
        original_error
    );
    assert!(scope.cache.entry.try_lock().unwrap().is_empty());
    assert_eq!(a.decode_checkpoint(&first_bytes).unwrap(), first);
    a.validate_profile().unwrap();
    b.validate_profile().unwrap();
    drop(a);
    drop(b);
    drop(scope);
    assert!(weak.upgrade().is_none());
    assert_eq!(checkpoint_bytes(&escaped).unwrap(), second_bytes);
    let next_scope = CheckpointImportScope::for_original(&fixture.parent).unwrap();
    // This positive cold probe itself inserts the context. The following checkpoint remains
    // a cold frame import; the earlier two-frame assertions established actual producer warming.
    assert_eq!(graph_epoch_charge(&next_scope.cache, &context), cold_charge);
    let (next, other) = fixture.pair(&next_scope);
    assert_eq!(next.decode_checkpoint(&first_bytes).unwrap(), first);
    assert_eq!(attempts(&other), 1);
    assert_eq!(graph_epoch_charge(&next_scope.cache, &context), 0);
    assert!(fixture.unavailable.requests.lock().unwrap().is_empty());
}

#[test]
fn graph_epoch_scope_keeps_active_charges_nonwaiting_fallback_and_no_local_duplication() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::new();
    let context =
        iroha_data_model::sumeragi_finality::authenticated_genesis(fixture.native.chain.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
    let (_, original, bytes) = fixture.paid("graph epoch active and optional fallback");
    let scope = CheckpointImportScope::for_original(&fixture.parent).unwrap();
    let (a, b) = fixture.pair(&scope);
    let baseline = DecodeBudgetContext::new(checkpoint_limits(64 * 1024 * 1024));
    let expected = baseline
        .with(|| decode_checkpoint(&bytes, a.config.network_id, a.config.chain.as_str()))
        .unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1 && charge < 64 * 1024 * 1024);
    let mut cold = EpochValidationScope::new();
    let cold_charge = epoch_charge(&mut cold, &context);
    assert!(cold_charge > 0);
    drop(cold);
    for cap in [0, 1, charge] {
        a.decode_checkpoint(&bytes).unwrap();
        assert_eq!(graph_epoch_charge(&scope.cache, &context), 0);
        let ordinary = DecodeBudgetContext::new(checkpoint_limits(cap));
        let raw = ordinary
            .with(|| decode_checkpoint(&bytes, a.config.network_id, a.config.chain.as_str()));
        let active = DecodeBudgetContext::new(checkpoint_limits(cap));
        let mut local = EpochValidationScope::new();
        let mut imports = CheckpointImports::new(&b, Some(&mut local));
        let before = attempts(&a);
        let actual = active.with(|| imports.decode(&bytes));
        drop(imports);
        assert_eq!(attempts(&a), before + 1);
        assert_eq!(
            active.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        match (actual, raw) {
            (Ok(actual), Ok(raw)) => {
                assert_eq!(actual, raw);
                assert_eq!(actual, expected);
            }
            (Err(actual), Err(raw)) => assert_eq!(actual.to_string(), raw.to_string()),
            other => panic!("the original active producer must match: {other:?}"),
        }
        assert!(scope.cache.entry.try_lock().unwrap().is_empty());
        // Both positive miss probes insert only after observing the original active return.
        assert_eq!(graph_epoch_charge(&scope.cache, &context), cold_charge);
        assert_eq!(epoch_charge(&mut local, &context), cold_charge);
        drop(local);
    }

    // Hold the real epoch gate while forcing a cold checkpoint miss on this same thread.
    // Completion itself proves the router never waits or tries to populate a second local pair.
    assert_eq!(a.decode_checkpoint(&bytes).unwrap(), original);
    scope.cache.entry.try_lock().unwrap().clear();
    let shared = scope.cache.epoch_validation.as_ref().unwrap();
    let mut held = shared.try_lock().unwrap();
    let mut local = EpochValidationScope::new();
    let mut imports = CheckpointImports::new(&b, Some(&mut local));
    let before = attempts(&a);
    assert_eq!(imports.decode(&bytes).unwrap(), original);
    drop(imports);
    assert_eq!(attempts(&a), before + 1);
    assert_eq!(epoch_charge(&mut local, &context), cold_charge);
    drop(local);
    assert_eq!(epoch_charge(&mut held, &context), 0);
    let mut malformed = bytes.clone();
    malformed.push(0);
    assert!(b.decode_checkpoint(&malformed).is_err());
    drop(held);
    assert_eq!(graph_epoch_charge(&scope.cache, &context), 0);
    assert_eq!(a.decode_checkpoint(&bytes).unwrap(), original);

    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = shared.lock().unwrap();
            panic!("poison only the graph's optional pure epoch workspace");
        }))
        .is_err()
    );
    scope.cache.entry.try_lock().unwrap().clear();
    let mut local = EpochValidationScope::new();
    let mut imports = CheckpointImports::new(&b, Some(&mut local));
    let before = attempts(&a);
    assert_eq!(imports.decode(&bytes).unwrap(), original);
    assert!(imports.decode(&malformed).is_err());
    drop(imports);
    assert!(attempts(&a) > before);
    assert_eq!(epoch_charge(&mut local, &context), cold_charge);
    drop(local);
    assert_eq!(graph_epoch_charge(&scope.cache, &context), cold_charge);
    assert!(matches!(shared.try_lock(), Err(TryLockError::Poisoned(_))));
    assert_eq!(a.decode_checkpoint(&bytes).unwrap(), original);
    a.validate_profile().unwrap();
    b.validate_profile().unwrap();
    assert!(fixture.unavailable.requests.lock().unwrap().is_empty());
}
