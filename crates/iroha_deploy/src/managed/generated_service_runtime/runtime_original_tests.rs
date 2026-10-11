//! Closed constructor-image sharing keeps real child owners, reads and physical admission.

use super::*;
use crate::localnet::service_authorities::count_profile_images;
use crate::managed::service_authority::{
    NetworkPurpose, ProviderPurpose, profile_validation_test_support as observe,
};
use norito::core::DecodeBudgetContext;

fn read(
    authority: &ServiceAuthority,
    old: bool,
) -> (Result<RuntimeSelection>, usize, Vec<PathBuf>) {
    let ((result, images), locks) = observe::operation_paths(|| {
        count_profile_images(|| {
            if old {
                observe::without_runtime_read(|| RuntimeSelection::read(authority))
            } else {
                RuntimeSelection::read(authority)
            }
        })
    });
    (result, images, locks)
}
fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}
fn policy_result(result: Result<GeneratedServicePolicies>) -> std::result::Result<Vec<u8>, String> {
    result
        .and_then(|policies| encode(&policies, MAX_POLICY_BYTES))
        .map_err(|error| error.to_string())
}

#[test]
fn runtime_original_counts_direct_constructor_images_and_preserves_lock_order() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-original-counts");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let (ordinary, old_images, old_locks) = read(&owner.authority, true);
    let (current, images, locks) = read(&owner.authority, false);
    let ordinary = ordinary.unwrap();
    let current = current.unwrap();
    assert_same_runtime_selection(&owner.authority, &current, &ordinary);
    assert!(current.initial.iter().all(Option::is_none));
    // Unlike the authority-method counter, this includes open_profile's direct image scan.
    assert_eq!((old_images, images), (15, 2));
    assert_eq!(old_locks.len(), 32);
    assert_eq!(locks, old_locks);
    let nested = count_profile_images(|| {
        owner.authority.validate_profile().unwrap();
        let (_, count) = count_profile_images(|| owner.authority.validate_profile().unwrap());
        assert_eq!(count, 1);
        owner.authority.validate_profile().unwrap();
    });
    assert_eq!(
        nested.1, 2,
        "nested counter restores the exact previous observer"
    );
    no_http(&peers);
}

#[test]
fn runtime_original_keeps_genuine_selected_histories_and_all_their_profile_fences() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-original-histories", false, false);
    let peers = fixture.peers();
    assert_eq!(fixture.carriers.len(), 6);
    let (ordinary, old_images, old_locks) = read(&fixture.owner.authority, true);
    let (current, images, locks) = read(&fixture.owner.authority, false);
    let ordinary = ordinary.unwrap();
    let current = current.unwrap();
    assert!(ordinary.initial.iter().all(Option::is_some));
    assert_same_runtime_selection(&fixture.owner.authority, &current, &ordinary);
    // Each selected history still owns inspector entry/exit and parser plan entry/exit.
    assert_eq!((old_images, images), (30, 14));
    assert_eq!(old_locks.len(), 56);
    assert_eq!(locks, old_locks);
    no_http(&peers);
}

#[test]
fn runtime_original_full_exit_overrides_child_error_and_refuses_source_substitution() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-original-source-exit");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let expected = RuntimeSelection::read(&owner.authority).unwrap();
    let generation = PrivateDirectory::open_exact(generation_path(&prepared).unwrap()).unwrap();
    let bytes = generation.read("peer3.toml", MAX_CONFIG_BYTES).unwrap();
    let mut changed = bytes.to_vec();
    changed.extend_from_slice(b"\n# persistent original image change\n");
    let bootstrap =
        ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
            .unwrap()
            .unwrap();
    let initial = bootstrap.directory.open_child("initial").unwrap();
    let original = initial.read("original.nrt", 512 * 1024).unwrap();
    drop(bootstrap);
    for malformed in [false, true] {
        let source = generation.retain().unwrap();
        let changed = changed.clone();
        let hook = observe::on_existing_child_exit(move |child| {
            let child = child.as_ref().unwrap().as_ref().unwrap();
            source
                .write_atomic("peer3.toml", &changed, PublishMode::Replace)
                .unwrap();
            if malformed {
                child
                    .directory
                    .open_child("initial")
                    .unwrap()
                    .write_atomic(
                        "original.nrt",
                        b"invalid child Original",
                        PublishMode::Replace,
                    )
                    .unwrap();
            }
        });
        let failure = RuntimeSelection::read(&owner.authority).err().unwrap();
        drop(hook);
        generation
            .write_atomic("peer3.toml", &bytes, PublishMode::Replace)
            .unwrap();
        initial
            .write_atomic("original.nrt", &original, PublishMode::Replace)
            .unwrap();
        assert_eq!(
            failure.to_string(),
            "retained service profile input custody differs"
        );
        assert_same_runtime_selection(
            &owner.authority,
            &RuntimeSelection::read(&owner.authority).unwrap(),
            &expected,
        );
    }
    initial
        .write_atomic(
            "original.nrt",
            b"invalid child Original",
            PublishMode::Replace,
        )
        .unwrap();
    let ordinary = RuntimeSelection::read(&owner.authority).err().unwrap();
    initial
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        ordinary.to_string(),
        "invalid original service bootstrap intent"
    );

    let lock = initial.path().parent().unwrap().join("operation.lock");
    let saved = initial
        .path()
        .parent()
        .unwrap()
        .join("saved-operation.lock");
    let changed_lock = lock.clone();
    let saved_lock = saved.clone();
    let hook = observe::on_existing_child_exit(move |child| {
        let child = child.as_ref().unwrap().as_ref().unwrap();
        #[cfg(unix)]
        {
            std::fs::rename(&changed_lock, &saved_lock).unwrap();
            child
                .directory
                .write_atomic("operation.lock", b"", PublishMode::CreateNew)
                .unwrap();
        }
        #[cfg(windows)]
        {
            assert!(std::fs::rename(&changed_lock, &saved_lock).is_err());
            child.validate_profile().unwrap();
        }
    });
    let changed = RuntimeSelection::read(&owner.authority);
    drop(hook);
    #[cfg(unix)]
    {
        std::fs::remove_file(&lock).unwrap();
        std::fs::rename(&saved, &lock).unwrap();
        assert_eq!(
            changed.err().unwrap().to_string(),
            "managed native operation lock was replaced"
        );
    }
    #[cfg(windows)]
    assert_same_runtime_selection(&owner.authority, &changed.unwrap(), &expected);
    assert_same_runtime_selection(
        &owner.authority,
        &RuntimeSelection::read(&owner.authority).unwrap(),
        &expected,
    );
    no_http(&peers);
}

#[test]
fn runtime_original_refuses_foreign_scope_and_retains_absence_and_lock_contention() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-original-owner");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let intent = owner.authority.original_intent().unwrap();
    let read = intent.runtime_read().unwrap();
    let (_foreign_temporary, foreign_prepared, foreign_peers) = fixture("runtime-original-foreign");
    select(&foreign_prepared);
    let foreign = GeneratedServiceRuntime::open(&foreign_prepared).unwrap();
    assert!(ManagedServiceBootstrap::open_existing_in_runtime(&foreign.authority, &read).is_err());
    let mut child = ServiceAuthority::open_network_existing_in_runtime(
        &owner.authority,
        NetworkPurpose::ServiceBootstrap,
        &read,
    )
    .unwrap()
    .unwrap();
    assert!(
        ServiceAuthority::open_provider_existing_in_runtime(
            &child,
            read_provider(&owner.authority),
            ProviderPurpose::Custody,
            None,
            &read,
        )
        .is_err(),
        "same image does not replace the exact constructor parent"
    );
    let original_prepared = child.prepared.clone();
    child.prepared = foreign_prepared.clone();
    assert!(
        read.eligible(&child).is_err(),
        "same Arc cannot substitute prepared generation"
    );
    child.prepared = original_prepared;
    let original_manifest = child.manifest.clone();
    child.manifest = foreign.authority.manifest.clone();
    assert!(
        read.eligible(&child).is_err(),
        "same Arc cannot substitute original manifest"
    );
    child.manifest = original_manifest;
    assert!(read.eligible(&child).unwrap());
    let (old, _, old_locks) = read_selection(&owner.authority, true);
    let (current, _, locks) = read_selection(&owner.authority, false);
    assert_eq!(
        old.err().unwrap().to_string(),
        "another managed native operation holds this generation"
    );
    assert_eq!(
        current.err().unwrap().to_string(),
        "another managed native operation holds this generation"
    );
    assert_eq!(locks, old_locks);
    drop(child);
    assert!(
        ServiceAuthority::open_provider_existing_in_runtime(
            &owner.authority,
            read_provider(&owner.authority),
            ProviderPurpose::Custody,
            None,
            &read,
        )
        .unwrap()
        .is_none()
    );
    let mut independent =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceObservation).unwrap();
    assert!(!std::ptr::eq(&independent, &owner.authority));
    assert!(
        read.eligible(&independent).is_err(),
        "equal configuration is not the same captured Arc"
    );
    independent.manifest = owner.authority.manifest.clone();
    assert!(read.eligible(&independent).is_err());
    drop(independent);
    intent.finish().unwrap();
    RuntimeSelection::read(&owner.authority).unwrap();
    no_http(&peers);
    no_http(&foreign_peers);
}

fn read_provider(authority: &ServiceAuthority) -> iroha_data_model::sorafs::capacity::ProviderId {
    authority.provider_plans().unwrap()[0].provider_id()
}
// Avoid shadowing the diagnostic helper with the borrowed runtime scope in the owner test.
fn read_selection(
    authority: &ServiceAuthority,
    old: bool,
) -> (Result<RuntimeSelection>, usize, Vec<PathBuf>) {
    read(authority, old)
}

#[test]
fn runtime_original_keeps_dynamic_active_and_owned_recipes_and_charges() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-original-admission");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let intent = owner.authority.original_intent().unwrap();
    let read = intent.runtime_read().unwrap();
    let child = ManagedServiceBootstrap::open_existing_in_runtime(&owner.authority, &read)
        .unwrap()
        .unwrap();
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    baseline.with(|| child.selected_policies()).unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1);
    for cap in [1, charge - 1, charge] {
        let old = DecodeBudgetContext::new(limits(cap));
        let current = DecodeBudgetContext::new(limits(cap));
        let old_observation = observe::operation_paths(|| {
            count_profile_images(|| policy_result(old.with(|| child.selected_policies())))
        });
        let new_observation = observe::operation_paths(|| {
            count_profile_images(|| {
                policy_result(current.with(|| child.selected_policies_in_runtime(&read)))
            })
        });
        assert_eq!(new_observation, old_observation);
        assert_eq!(
            current.consumed_allocated_bytes(),
            old.consumed_allocated_bytes()
        );
    }
    drop(child);
    // The constructor also rechecks dynamic admission after the token was minted.
    // Its active fallback must keep the complete independent capture, including failures.
    let construct = |scoped: bool, allocated| {
        let budget = DecodeBudgetContext::new(limits(allocated));
        let result = observe::operation_paths(|| {
            count_profile_images(|| {
                policy_result(budget.with(|| {
                    let child = if scoped {
                        ManagedServiceBootstrap::open_existing_in_runtime(&owner.authority, &read)
                    } else {
                        ManagedServiceBootstrap::open_existing_from_original(&owner.authority)
                    }?
                    .ok_or_else(|| invalid("original bootstrap absent"))?;
                    child.selected_policies()
                }))
            })
        });
        (result, budget.consumed_allocated_bytes())
    };
    let admitted = construct(false, 64 * 1024 * 1024);
    assert!(admitted.0.0.0.is_ok());
    let allocation = usize::try_from(admitted.1).unwrap();
    assert!(allocation > 1);
    for cap in [1, allocation - 1, allocation] {
        assert_eq!(construct(true, cap), construct(false, cap));
    }
    intent.finish().unwrap();
    drop(owner);
    let budget = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let owned = budget
        .with(|| GeneratedServiceRuntime::open(&prepared))
        .unwrap();
    let (old, old_images, old_locks) = read_selection(&owned.authority, true);
    let (current, images, locks) = read_selection(&owned.authority, false);
    assert_same_runtime_selection(&owned.authority, &current.unwrap(), &old.unwrap());
    assert_eq!((images, locks), (old_images, old_locks));
    no_http(&peers);
}
