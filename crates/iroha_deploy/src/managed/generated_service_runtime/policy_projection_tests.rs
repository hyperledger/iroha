//! Original-intent policy projection retains full values, lock custody and physical admission.

use super::*;
use crate::managed::service_authority::profile_validation_test_support;
use norito::core::DecodeBudgetContext;

fn observe<T>(action: impl FnOnce() -> T) -> (T, usize, usize) {
    let ((result, profiles), locks) =
        profile_validation_test_support::count_operation_custody(|| {
            profile_validation_test_support::count(action)
        });
    (result, profiles, locks)
}

fn outcome(result: Result<()>) -> std::result::Result<(), String> {
    result.map_err(|error| error.to_string())
}

fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}

#[test]
fn policy_projection_keeps_complete_values_and_each_original_lock_observation() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("policy-projection-counts");
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let original = encode(&policies, MAX_POLICY_BYTES).unwrap();
    let intent = owner.authority.original_intent().unwrap();
    let (old, old_profiles, old_locks) = observe(|| policies.validate(&owner.authority));
    old.unwrap();
    let (projected, profiles, locks) = observe(|| intent.validate_policies(&policies));
    projected.unwrap();
    assert_eq!((old_profiles, profiles), (2, 0));
    assert_eq!((old_locks, locks), (4, 4));
    intent.finish().unwrap();
    assert_eq!(encode(&policies, MAX_POLICY_BYTES).unwrap(), original);

    let (selected, profiles, _) = observe(|| RuntimeSelection::read(&owner.authority));
    let selected = selected.unwrap();
    assert_eq!(
        profiles, 2,
        "all fresh child reads and the full exit remain"
    );
    assert_eq!(
        encode(&selected.policies, MAX_POLICY_BYTES).unwrap(),
        original
    );
    assert!(selected.initial.iter().all(Option::is_none));
    no_http(&peers);
}

#[test]
fn policy_projection_full_exit_refuses_persistent_sources_before_ordinary_results() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("policy-projection-exit");
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let generation = PrivateDirectory::open_exact(generation_path(&prepared).unwrap()).unwrap();
    let original = generation.read("peer3.toml", MAX_CONFIG_BYTES).unwrap();
    let mut changed = original.to_vec();
    changed.extend_from_slice(b"\n# same semantics, changed original bytes\n");
    let mut wrong = policies.clone();
    wrong.providers[0].custody.binding.policy_digest[0] ^= 1;
    let policy_error = "original generated service policies changed";
    let lock = owner.authority.directory.path().join("operation.lock");
    let saved_lock = owner
        .authority
        .directory
        .path()
        .join("saved-operation.lock");
    let lock_identity = iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap();

    #[cfg(unix)]
    let replacements = [false, true];
    #[cfg(windows)]
    let replacements = [false];
    for replace_lock in replacements {
        for ordinary_error in [false, true] {
            let intent = owner.authority.original_intent().unwrap();
            let result = intent.validate_policies(if ordinary_error { &wrong } else { &policies });
            assert_eq!(
                result.as_ref().map(|_| ()).map_err(ToString::to_string),
                if ordinary_error {
                    Err(policy_error.into())
                } else {
                    Ok(())
                }
            );
            if replace_lock {
                std::fs::rename(&lock, &saved_lock).unwrap();
                owner
                    .authority
                    .directory
                    .write_atomic("operation.lock", b"", PublishMode::CreateNew)
                    .unwrap();
            } else {
                generation
                    .write_atomic("peer3.toml", &changed, PublishMode::Replace)
                    .unwrap();
            }
            // This is RuntimeSelection's production ordinary-result closure: the complete
            // source exit is evaluated before the retained projection result is returned.
            let closed = intent.finish().and(result);
            if replace_lock {
                std::fs::remove_file(&lock).unwrap();
                std::fs::rename(&saved_lock, &lock).unwrap();
            } else {
                generation
                    .write_atomic("peer3.toml", &original, PublishMode::Replace)
                    .unwrap();
            }
            assert_eq!(
                outcome(closed),
                Err(if replace_lock {
                    "managed native operation lock was replaced".into()
                } else {
                    "retained service profile input custody differs".into()
                })
            );
            let retry = owner.authority.original_intent().unwrap();
            retry.validate_policies(&policies).unwrap();
            retry.finish().unwrap();
            assert_eq!(
                iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap(),
                lock_identity
            );
        }
    }

    #[cfg(unix)]
    {
        // The nested entry retains the exact original named-lock check before policy comparison.
        let intent = owner.authority.original_intent().unwrap();
        std::fs::rename(&lock, &saved_lock).unwrap();
        owner
            .authority
            .directory
            .write_atomic("operation.lock", b"", PublishMode::CreateNew)
            .unwrap();
        let result = intent.validate_policies(&wrong);
        let exit = intent.finish();
        std::fs::remove_file(&lock).unwrap();
        std::fs::rename(&saved_lock, &lock).unwrap();
        assert_eq!(
            outcome(result),
            Err("managed native operation lock was replaced".into())
        );
        assert_eq!(
            outcome(exit),
            Err("managed native operation lock was replaced".into())
        );
    }
    #[cfg(windows)]
    {
        // Windows retains a deny-delete handle for the original lock. Replacement must
        // fail at the native boundary, leaving the exact source available for admission.
        let intent = owner.authority.original_intent().unwrap();
        assert!(std::fs::rename(&lock, &saved_lock).is_err());
        intent.validate_policies(&policies).unwrap();
        intent.finish().unwrap();
        assert_eq!(
            iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap(),
            lock_identity
        );
    }
    owner.authority.validate_profile().unwrap();
    no_http(&peers);
}

#[test]
fn policy_projection_refuses_foreign_intent_and_keeps_dynamic_active_admission() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("policy-projection-active");
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let (_other_temporary, other_prepared, other_peers) = fixture("policy-projection-foreign");
    let foreign = select(&other_prepared);
    let intent = owner.authority.original_intent().unwrap();
    let expected = outcome(foreign.validate(&owner.authority));
    assert_eq!(
        expected,
        Err("original generated service policies changed".into())
    );
    assert_eq!(outcome(intent.validate_policies(&foreign)), expected);

    // The original view was admitted before the budget became active. Admission is checked
    // at each projection call, and both paths retain the original encode/decode/error recipe.
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    baseline
        .with(|| policies.validate(&owner.authority))
        .unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1);
    for selected in [&policies, &foreign] {
        for allocated in [1, charge - 1, charge] {
            let old = DecodeBudgetContext::new(limits(allocated));
            let expected = observe(|| outcome(old.with(|| selected.validate(&owner.authority))));
            let current = DecodeBudgetContext::new(limits(allocated));
            let actual = observe(|| outcome(current.with(|| intent.validate_policies(selected))));
            assert_eq!(actual, expected);
            assert_eq!(
                current.consumed_allocated_bytes(),
                old.consumed_allocated_bytes()
            );
            if allocated == 1 {
                assert!(actual.0.is_err());
            }
            if allocated == charge && std::ptr::eq(selected, &policies) {
                assert_eq!(actual.0, Ok(()));
                assert_eq!((actual.1, actual.2), (2, 4));
            }
        }
    }
    intent.finish().unwrap();
    no_http(&peers);
    no_http(&other_peers);
}

#[test]
fn policy_projection_owned_original_keeps_standalone_checks_outside_admission() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("policy-projection-owned");
    let policies = select(&prepared);
    let caller = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let owner = caller
        .with(|| GeneratedServiceRuntime::open(&prepared))
        .unwrap();
    assert!(!norito::core::decode_limits_active());
    let intent = owner.authority.original_intent().unwrap();
    let expected = observe(|| outcome(policies.validate(&owner.authority)));
    let actual = observe(|| outcome(intent.validate_policies(&policies)));
    assert_eq!(actual, expected);
    assert_eq!(actual, (Ok(()), 2, 4));
    intent.finish().unwrap();
    no_http(&peers);
}
