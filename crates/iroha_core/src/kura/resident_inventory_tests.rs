//! Real shared-registry and resident-mutex publication tests.

use super::*;
use std::collections::BTreeSet;

#[derive(Debug)]
struct TestOwner {
    values: BTreeSet<u64>,
    complete: bool,
}

impl TestOwner {
    fn empty() -> Self {
        Self {
            values: BTreeSet::new(),
            complete: true,
        }
    }
}

impl ResidentOwner for TestOwner {
    const FAMILY: Family = Family::ResidentCanonical;
    fn resident_associations(&self) -> Result<u64, Unavailable> {
        lengths([self.values.len()])
    }
    fn resident_complete(&self) -> bool {
        self.complete
    }
}

fn isolated_empty_registry() -> Arc<Inventory> {
    // An isolated engine fixture: every declared owner is actually empty.
    // Live Kura initialization never calls this test-only constructor.
    let families = super::super::resource_inventory::ALL_FAMILIES;
    let registry = Arc::new(Inventory::default());
    let values = families.map(|family| (family, Usage::default()));
    registry
        .initialize(registry.reconciliation_generation().unwrap(), &values)
        .unwrap();
    registry
}

#[test]
fn nested_association_arithmetic_is_checked_and_sticky() {
    let mut count = AssociationCount::default();
    count.inserted(false);
    assert_eq!(count.get(), Ok(0));
    count.inserted(true);
    count.inserted(false);
    assert_eq!(count.get(), Ok(1));
    count.removed(Some(1));
    assert_eq!(count.get(), Ok(0));
    count.removed(Some(1));
    count.inserted(true);
    assert_eq!(count.get(), Err(Unavailable::Arithmetic));
    let mut maximum = AssociationCount(Some(u64::MAX));
    maximum.inserted(true);
    maximum.removed(Some(1));
    assert_eq!(maximum.get(), Err(Unavailable::Arithmetic));
    let mut failed_removal = AssociationCount::default();
    failed_removal.removed(None);
    assert_eq!(failed_removal.get(), Err(Unavailable::Arithmetic));
}

#[test]
fn resident_publication_counts_duplicates_replacements_and_distinct_owners() {
    let registry = isolated_empty_registry();
    let first = ResidentMutex::new(TestOwner::empty(), &registry);
    let second = ResidentMutex::new(TestOwner::empty(), &registry);
    let original_generation = registry.try_snapshot().unwrap().generation;
    assert!(first.lock().values.is_empty());
    assert_eq!(
        registry.try_snapshot().unwrap().generation,
        original_generation
    );
    {
        let mut owner = first.lock();
        assert!(owner.values.insert(7));
        assert!(!owner.values.insert(7));
        assert!(matches!(registry.try_snapshot(), Err(Unavailable::Busy)));
        assert!(first.try_lock().is_none());
    }
    assert_eq!(
        registry.try_snapshot().unwrap().total.resident_associations,
        1
    );
    second.lock().values.insert(7);
    assert_eq!(
        registry.try_snapshot().unwrap().total.resident_associations,
        2
    );
    *first.lock() = TestOwner::empty();
    assert_eq!(
        registry.try_snapshot().unwrap().total.resident_associations,
        1
    );
    assert!(second.lock().values.remove(&7));
    assert_eq!(
        registry.try_snapshot().unwrap().total.resident_associations,
        0
    );
}

#[test]
fn resident_publication_never_certifies_unwind_or_incomplete_owner() {
    let registry = isolated_empty_registry();
    let owner = ResidentMutex::new(TestOwner::empty(), &registry);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.lock().values.insert(1);
        let mut mutation = owner.lock();
        mutation.values.insert(2);
        panic!("interrupt multi-map mutation");
    }));
    assert!(outcome.is_err());
    assert_eq!(owner.lock().values.len(), 2);
    assert!(registry.try_snapshot().is_err());
    let incomplete_registry = isolated_empty_registry();
    let incomplete = ResidentMutex::new(TestOwner::empty(), &incomplete_registry);
    incomplete.lock().complete = false;
    assert!(matches!(
        incomplete_registry.try_snapshot(),
        Err(Unavailable::InvalidInventory)
    ));
    incomplete.lock().complete = true;
    assert!(
        incomplete_registry.try_snapshot().is_err(),
        "a later mutation cannot silently clear a failed audit"
    );
}

#[test]
fn resident_registration_rejects_a_crossing_mutation_and_partial_coverage() {
    let registry = Arc::new(Inventory::default());
    let owner = ResidentMutex::new(TestOwner::empty(), &registry);
    let generation = registry.reconciliation_generation().unwrap();
    owner.lock().values.insert(9);
    assert_eq!(
        registry.initialize(generation, &[(Family::ResidentCanonical, Usage::default())]),
        Err(Unavailable::GenerationChanged)
    );
    let current = registry.reconciliation_generation().unwrap();
    registry
        .initialize(
            current,
            &[(
                Family::ResidentCanonical,
                Usage {
                    resident_associations: 1,
                    ..Usage::default()
                },
            )],
        )
        .unwrap();
    assert!(matches!(
        registry.try_snapshot(),
        Err(Unavailable::Unregistered)
    ));
}

#[derive(Debug)]
struct ExpandedFailureOwner {
    values: BTreeSet<u64>,
    complete: bool,
    count_failed: bool,
    panic_on_count: bool,
    panic_on_complete: bool,
}

impl ResidentOwner for ExpandedFailureOwner {
    const FAMILY: Family = Family::ResidentCanonical;
    fn resident_associations(&self) -> Result<u64, Unavailable> {
        assert!(!self.panic_on_count, "interrupt expanded count callback");
        if self.count_failed {
            return Err(Unavailable::Arithmetic);
        }
        lengths([self.values.len()])
    }
    fn resident_complete(&self) -> bool {
        assert!(
            !self.panic_on_complete,
            "interrupt expanded completeness callback"
        );
        self.complete
    }
    fn failure_invalidation_mask() -> u32 {
        Self::FAMILY.mask() | Family::StorageBytes.mask() | Family::EvidenceKeyRecords.mask()
    }
}

#[test]
fn expanded_failure_masks_preserve_successful_owner_publication_and_forwarding() {
    let registry = isolated_empty_registry();
    let owner = ResidentMutex::new(
        ExpandedFailureOwner {
            values: BTreeSet::new(),
            complete: true,
            count_failed: false,
            panic_on_count: false,
            panic_on_complete: false,
        },
        &registry,
    );
    assert_eq!(
        TestOwner::failure_invalidation_mask(),
        Family::ResidentCanonical.mask()
    );
    assert_eq!(
        <ResidentGuard<'_, ExpandedFailureOwner> as ResidentOwner>::failure_invalidation_mask(),
        ExpandedFailureOwner::failure_invalidation_mask()
    );
    let before = registry.try_snapshot().unwrap();
    owner.lock().values.insert(7);
    let after = registry.try_snapshot().unwrap();
    assert_eq!(after.total.resident_associations, 1);
    assert_eq!(
        after.components[Family::StorageBytes as usize],
        before.components[Family::StorageBytes as usize]
    );
    assert_eq!(
        after.components[Family::EvidenceKeyRecords as usize],
        before.components[Family::EvidenceKeyRecords as usize]
    );
    assert_eq!(
        after.components[Family::ResidentQueue as usize],
        before.components[Family::ResidentQueue as usize]
    );
}

#[test]
fn expanded_failure_masks_cover_unwind_missing_state_and_count_publication_errors() {
    for mode in [
        "incomplete",
        "unwind",
        "count_unwind",
        "complete_unwind",
        "before_count",
        "after_count",
        "missing_before",
        "missing_token",
        "publish",
    ] {
        let registry = isolated_empty_registry();
        let owner = ResidentMutex::new(
            ExpandedFailureOwner {
                values: BTreeSet::new(),
                complete: true,
                count_failed: mode == "before_count",
                panic_on_count: false,
                panic_on_complete: false,
            },
            &registry,
        );
        let generation = registry.reconciliation_generation().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = owner.lock();
            guard.values.insert(9);
            match mode {
                "incomplete" => guard.complete = false,
                "unwind" => panic!("interrupt the expanded owner"),
                "count_unwind" => guard.panic_on_count = true,
                "complete_unwind" => guard.panic_on_complete = true,
                "before_count" => guard.count_failed = false,
                "after_count" => guard.count_failed = true,
                // Explicit bookkeeping-corruption controls prove that lost
                // local state never narrows invalidation to only the token.
                "missing_before" => guard.before = None,
                "missing_token" => drop(guard.mutation.take()),
                "publish" => {
                    guard.before = Some(Usage {
                        resident_associations: u64::MAX,
                        ..Usage::default()
                    })
                }
                _ => unreachable!(),
            }
        }));
        assert_eq!(result.is_err(), mode.ends_with("unwind"));
        for family in [
            Family::ResidentCanonical,
            Family::StorageBytes,
            Family::EvidenceKeyRecords,
        ] {
            assert!(
                registry.component_usage_for_tests(family).is_err(),
                "{mode}: {family:?}"
            );
        }
        assert_eq!(
            registry.component_usage_for_tests(Family::ResidentQueue),
            Ok(Usage::default())
        );
        assert!(registry.reconciliation_generation().unwrap() > generation);
        assert_eq!(
            registry.initialize(generation, &[(Family::StorageBytes, Usage::default())]),
            Err(Unavailable::GenerationChanged)
        );
        assert!(registry.try_snapshot().is_err());
    }
}
