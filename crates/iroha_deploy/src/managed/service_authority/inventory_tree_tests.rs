//! Native inventory ancestry, mutation, error-exit and active-admission controls.

use super::*;
use crate::managed::Error;
use std::{path::PathBuf, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Recipe {
    Full,
    Tree,
}

type Observer = Box<dyn FnMut(&PrivateDirectory, Recipe)>;
std::thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

pub(super) fn observe(directory: &PrivateDirectory, recipe: Recipe) {
    OBSERVER.with(|observer| {
        if let Some(observer) = observer.borrow_mut().as_mut() {
            observer(directory, recipe);
        }
    });
}

fn with_observer<T>(
    observer: impl FnMut(&PrivateDirectory, Recipe) + 'static,
    action: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Observer>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|observer| *observer.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(OBSERVER.with(|slot| slot.replace(Some(Box::new(observer)))));
    action()
}

fn observations<T>(action: impl FnOnce() -> T) -> (T, Vec<(PathBuf, Recipe)>) {
    let values = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&values);
    let result = with_observer(
        move |directory, recipe| {
            recorded
                .borrow_mut()
                .push((directory.path().to_path_buf(), recipe))
        },
        action,
    );
    let values = values.borrow().clone();
    (result, values)
}

fn fixture() -> (tempfile::TempDir, ServiceAuthority) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "inventory-tree",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let parent =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    drop(
        ServiceAuthority::open_provider(
            &prepared,
            parent.manifest.providers[0].provider_id,
            ProviderPurpose::Custody,
        )
        .unwrap(),
    );
    (temporary, parent)
}

fn expected_order(inventory: &ServiceChildInventory<'_>, shared: bool) -> Vec<(PathBuf, Recipe)> {
    inventory
        .branches
        .iter()
        .enumerate()
        .map(|(index, branch)| {
            (
                branch.directory.path().to_path_buf(),
                if shared && index != 0 {
                    Recipe::Tree
                } else {
                    Recipe::Full
                },
            )
        })
        .chain(inventory.empty_prefixes.borrow().iter().map(|branch| {
            (
                branch.directory.path().to_path_buf(),
                if shared { Recipe::Tree } else { Recipe::Full },
            )
        }))
        .collect()
}

#[test]
fn inventory_tree_retains_original_identities_names_order_and_empty_prefix() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let network = PrivateDirectory::open_exact(parent.directory.path().parent().unwrap()).unwrap();
    let prefix = network
        .ensure_child(NetworkPurpose::InitialReservePolicy.directory_name())
        .unwrap();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    assert!(inventory.share_ancestry);
    assert!(
        inventory
            .open_network(NetworkPurpose::InitialReservePolicy)
            .unwrap()
            .is_none()
    );
    assert_eq!(inventory.empty_prefixes.borrow().len(), 1);
    let identities = inventory
        .branches
        .iter()
        .map(|branch| branch.directory.identity().unwrap())
        .collect::<Vec<_>>();
    let names = inventory
        .branches
        .iter()
        .map(|branch| branch.directory.entries(MAX_BRANCH_NAMES).unwrap())
        .collect::<Vec<_>>();
    let lock = iroha_fs::FileIdentity::of(&parent._lock).unwrap();
    let (result, observed) = observations(|| inventory.revalidate());
    result.unwrap();
    assert_eq!(observed, expected_order(&inventory, true));
    assert_eq!(
        inventory
            .branches
            .iter()
            .map(|branch| branch.directory.identity().unwrap())
            .collect::<Vec<_>>(),
        identities
    );
    assert_eq!(
        inventory
            .branches
            .iter()
            .map(|branch| branch.directory.entries(MAX_BRANCH_NAMES).unwrap())
            .collect::<Vec<_>>(),
        names
    );
    assert_eq!(iroha_fs::FileIdentity::of(&parent._lock).unwrap(), lock);
    assert!(prefix.entries(1).unwrap().is_empty());
    let appeared = prefix.ensure_child("appeared-prefix-content").unwrap();
    let refused = inventory.revalidate();
    let appeared_path = appeared.path().to_path_buf();
    drop(appeared);
    std::fs::remove_dir(appeared_path).unwrap();
    assert!(matches!(refused, Err(Error::Invalid(_))));
    inventory.revalidate().unwrap();
    inventory.finish().unwrap();
}

#[test]
fn inventory_tree_refuses_real_name_changes_and_retries_original_census() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    for branch in &inventory.branches {
        let added = branch.directory.ensure_child("appeared-purpose").unwrap();
        let error = inventory.revalidate().unwrap_err();
        let added_path = added.path().to_path_buf();
        drop(added);
        std::fs::remove_dir(added_path).unwrap();
        assert!(matches!(error, Error::Invalid(_)));
        assert_eq!(
            error.to_string(),
            "service child namespace changed during inventory"
        );
        inventory.revalidate().unwrap();
    }
    inventory.finish().unwrap();
}

#[cfg(unix)]
#[test]
fn inventory_tree_refuses_replaced_branch_and_runtime_then_restores_original() {
    let _guard = crate::managed::native_test_guard();
    let (temporary, parent) = fixture();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let provider = inventory.providers[0].unwrap();
    for (index, branch) in [provider, 0].into_iter().enumerate() {
        let path = inventory.branches[branch].directory.path().to_path_buf();
        let identity = inventory.branches[branch].directory.identity().unwrap();
        let saved = temporary.path().join(format!("saved-branch-{index}"));
        std::fs::rename(&path, &saved).unwrap();
        let replacement = PrivateDirectory::open_or_create(&path).unwrap();
        let result = inventory.revalidate();
        std::fs::remove_dir(replacement.path()).unwrap();
        std::fs::rename(&saved, &path).unwrap();
        assert!(result.is_err());
        inventory.revalidate().unwrap();
        assert_eq!(
            inventory.branches[branch].directory.identity().unwrap(),
            identity
        );
    }
    inventory.finish().unwrap();
}

#[cfg(unix)]
#[test]
fn inventory_tree_closes_branch_and_root_on_success_and_semantic_error() {
    use std::os::unix::fs::PermissionsExt as _;
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let provider = inventory.providers[0].unwrap();
    let selected = inventory.branches[provider].directory.path().to_path_buf();
    let runtime = inventory.branches[0].directory.path().to_path_buf();
    // The branch census has genuinely changed, so the unmodified-custody outcome is its
    // original semantic error. The callback does not manufacture a decoded owner or result.
    let appeared = inventory.branches[provider]
        .directory
        .ensure_child("appeared-purpose")
        .unwrap();
    let original = inventory.revalidate().unwrap_err();
    assert!(matches!(original, Error::Invalid(_)));
    assert_eq!(
        original.to_string(),
        "service child namespace changed during inventory"
    );
    std::fs::remove_dir(appeared.path()).unwrap();
    for semantic_error in [false, true] {
        let appeared = semantic_error.then(|| {
            inventory.branches[provider]
                .directory
                .ensure_child("appeared-purpose")
                .unwrap()
        });
        for target in [&selected, &runtime] {
            let target = target.to_path_buf();
            let saved_permissions = std::fs::metadata(&target).unwrap().permissions();
            let changed = target.clone();
            let selected = selected.clone();
            let result = with_observer(
                move |directory, recipe| {
                    if recipe == Recipe::Tree && directory.path() == selected {
                        std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o755))
                            .unwrap();
                    }
                },
                || inventory.revalidate(),
            );
            std::fs::set_permissions(&target, saved_permissions).unwrap();
            assert!(
                matches!(result, Err(Error::Io(_))),
                "native exit refusal takes priority over every ordinary body result"
            );
        }
        if let Some(appeared) = appeared {
            std::fs::remove_dir(appeared.path()).unwrap();
        }
        inventory.revalidate().unwrap();
    }
    inventory.finish().unwrap();
}

#[cfg(unix)]
#[test]
fn inventory_tree_shares_native_prefix_but_reopened_same_path_keeps_full_checks() {
    use std::os::unix::fs::PermissionsExt as _;
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let mut inventory = ServiceChildInventory::begin(&parent).unwrap();
    let original_network = inventory.branches[2].directory.retain().unwrap();
    for independent in [false, true] {
        if independent {
            // Same path and inode, independently opened native ancestors. Path equality is
            // insufficient to share the runtime bracket's original native handle prefix.
            inventory.branches[2].directory =
                PrivateDirectory::open_exact(original_network.path()).unwrap();
            assert_eq!(
                inventory.branches[2].directory.identity().unwrap(),
                original_network.identity().unwrap()
            );
        }
        let runtime = inventory.branches[0].directory.path().to_path_buf();
        let permissions = std::fs::metadata(&runtime).unwrap().permissions();
        let operations = inventory.branches[1].directory.path().to_path_buf();
        let changed = runtime.clone();
        let count = Rc::new(std::cell::Cell::new(0));
        let observed = Rc::clone(&count);
        let result = with_observer(
            move |directory, recipe| {
                if recipe == Recipe::Tree {
                    observed.set(observed.get() + 1);
                }
                if recipe == Recipe::Tree && directory.path() == operations {
                    // Independently opened network custody treats runtime as a non-private
                    // ancestor: 0755 is permitted there. Public write is refused by both
                    // ancestor policies, so this mutation proves the full fallback's visit.
                    std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o777))
                        .unwrap();
                }
            },
            || inventory.revalidate(),
        );
        std::fs::set_permissions(&runtime, permissions).unwrap();
        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(
            count.get(),
            if independent {
                1
            } else {
                inventory.branches.len() - 1
            }
        );
        inventory.revalidate().unwrap();
    }
    inventory.finish().unwrap();
}

// The original physical inventory recipe is the active-admission comparator, including
// both parent custody fences and its exact branch/prefix order. No semantic decode is skipped.
fn original_revalidate(inventory: &ServiceChildInventory<'_>) -> Result<()> {
    inventory.parent.validate_operation_custody()?;
    for branch in &inventory.branches {
        branch.revalidate()?;
    }
    for prefix in inventory.empty_prefixes.borrow().iter() {
        prefix.revalidate()?;
    }
    inventory.parent.validate_operation_custody()
}

#[test]
fn inventory_tree_keeps_active_and_inherited_active_norito_recipes() {
    use norito::core::DecodeBudgetContext;
    fn limits(allocated: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
    }
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    for allocation in [0, 1, 64 * 1024 * 1024] {
        let ordinary = DecodeBudgetContext::new(limits(allocation));
        let (expected, expected_reads) =
            observations(|| ordinary.with(|| original_revalidate(&inventory)));
        let active = DecodeBudgetContext::new(limits(allocation));
        let (actual, actual_reads) = observations(|| active.with(|| inventory.revalidate()));
        assert_eq!(
            actual.map_err(|error| error.to_string()),
            expected.map_err(|error| error.to_string())
        );
        assert_eq!(
            active.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert_eq!(actual_reads, expected_reads);
        assert_eq!(actual_reads, expected_order(&inventory, false));
    }
    inventory.finish().unwrap();
    let admission = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let inventory = admission
        .with(|| ServiceChildInventory::begin(&parent))
        .unwrap();
    assert!(!norito::core::decode_limits_active());
    assert!(!inventory.share_ancestry);
    let (result, actual) = observations(|| inventory.revalidate());
    result.unwrap();
    assert_eq!(actual, expected_order(&inventory, false));
    inventory.finish().unwrap();
    let prepared = parent.prepared.clone();
    drop(parent);
    let admission = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let parent = admission
        .with(|| {
            ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
        })
        .unwrap()
        .unwrap();
    assert!(matches!(&parent.profile, AuthorityProfile::Owned(_)));
    assert!(!norito::core::decode_limits_active());
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    assert!(!inventory.share_ancestry);
    let (result, actual) = observations(|| inventory.revalidate());
    result.unwrap();
    assert_eq!(actual, expected_order(&inventory, false));
    inventory.finish().unwrap();
}
