use super::validate_permissions;

const APP: u32 = 10123;

#[test]
fn observed_pixel6_stock_ancestors_are_accepted() {
    // Actual owner/group/modes from the read-only Pixel 6 observation; not faked handles.
    for (owner, group, mode) in [(0, 0, 0o755), (1000, 1000, 0o771), (1000, 1000, 0o511)] {
        validate_permissions(owner, group, mode, APP, false).unwrap();
    }
}

#[test]
fn only_privileged_owners_may_use_the_writable_system_group() {
    for owner in [0, 1000] {
        validate_permissions(owner, 1000, 0o771, APP, false).unwrap();
        for group in [0, 1001, 2000, APP] {
            assert!(validate_permissions(owner, group, 0o771, APP, false).is_err());
        }
    }
    for owner in [APP, 1, 1001, 2000, APP + 1] {
        assert!(validate_permissions(owner, 1000, 0o771, APP, false).is_err());
    }
}

#[test]
fn world_write_is_rejected_even_with_privileged_sticky_ownership() {
    for owner in [0, 1000, APP] {
        for mode in 0..=0o7777 {
            if mode & 0o002 != 0 {
                assert!(validate_permissions(owner, 1000, mode, APP, false).is_err());
            }
        }
    }
}

#[test]
fn current_app_ancestors_allow_search_only_but_never_shared_writes() {
    for mode in [0o111, 0o511, 0o700, 0o711, 0o755] {
        validate_permissions(APP, APP, mode, APP, false).unwrap();
    }
    for mode in [0o720, 0o770, 0o771, 0o777, 0o1777] {
        assert!(validate_permissions(APP, APP, mode, APP, false).is_err());
        assert!(validate_permissions(APP, 1000, mode, APP, false).is_err());
    }
}

#[test]
fn unrelated_android_service_and_app_owners_never_qualify() {
    for owner in [1, 999, 1001, 2000, 3003, APP + 1, u32::MAX] {
        for mode in [0o111, 0o511, 0o700, 0o711, 0o755] {
            assert!(validate_permissions(owner, 1000, mode, APP, false).is_err());
        }
    }
}

#[test]
fn private_leaf_requires_exact_current_owner_0700_for_every_permission_mode() {
    for mode in 0..=0o7777 {
        for group in [0, 1000, APP] {
            assert_eq!(
                validate_permissions(APP, group, mode, APP, true).is_ok(),
                mode == 0o700
            );
        }
    }
    for owner in [0, 1000, APP + 1] {
        assert!(validate_permissions(owner, 1000, 0o700, APP, true).is_err());
    }
}

#[test]
fn special_bits_do_not_mask_world_or_untrusted_group_writes() {
    for special in [0o1000, 0o2000, 0o4000, 0o7000] {
        assert!(validate_permissions(0, 1000, special | 0o773, APP, false).is_err());
        assert!(validate_permissions(1000, APP, special | 0o771, APP, false).is_err());
        assert!(validate_permissions(APP, 1000, special | 0o771, APP, false).is_err());
        assert!(validate_permissions(APP, APP, special | 0o700, APP, true).is_err());
    }
}

#[test]
fn android_policy_refusal_has_permission_denied_kind() {
    for (owner, group, mode, private) in [
        (APP + 1, 1000, 0o755, false),
        (0, 0, 0o1777, false),
        (APP, APP, 0o755, true),
    ] {
        assert_eq!(
            validate_permissions(owner, group, mode, APP, private)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
