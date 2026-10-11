//! Original canonical rows, source cursor, finite work and final nodes survive refusal.

use super::*;
use crate::test_allocations::allocations_during;
use iroha_allocation::AllocationRefusal;
use iroha_data_model::trigger::TriggerId;
use std::cell::Cell;

const TABLE: &str = "triggers.data";
const IDENTITY: &str = "iroha:state:trigger-data-action:v1";

fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 8,
        max_payload_bytes: 4096,
        max_ordered_table_bytes: 64 * 1024,
        max_streamed_value_bytes: 64 * 1024,
    }
}
fn keys() -> [TriggerId; 2] {
    ["original_a".parse().unwrap(), "original_b".parse().unwrap()]
}
fn project(value: &u32) -> u32 {
    *value
}

// Independent original consuming finalizer: existing canonical digest primitives
// feed the unchanged typed paired finalizer, not the new retained finalizer.
fn original_snapshot(
    keys: &[TriggerId],
    values: &[u32],
    budget: &AllocationBudget,
) -> CanonicalTablePairedSnapshot {
    let policy = limits();
    let selection = CanonicalTableLeafSet::new(&[TABLE], policy, budget).unwrap();
    let (table, (key_schema, value_schema)) = selection.selection.table(TABLE).unwrap();
    let mut rows = StagedRows::new(keys.len(), budget).unwrap();
    let mut retained = 0;
    let mut streamed = 0;
    for (key, value) in keys.iter().zip(values) {
        let key =
            staging::encode_key(table, key_schema, key, policy.max_payload_bytes, budget).unwrap();
        charge_digest_row(&mut retained, key.as_slice().len(), policy).unwrap();
        let (ordered_value_digest, lookup_value_digest, length) = semantic_bare_payload_digests(
            table,
            value_schema,
            IDENTITY,
            value,
            value_stream_bound(policy, streamed).unwrap(),
        )
        .unwrap();
        charge_streamed_value(&mut streamed, length, policy).unwrap();
        rows.push(PairedDigestRow {
            key,
            ordered_value_digest,
            lookup_value_digest,
        })
        .unwrap();
    }
    CanonicalTableLeafSet::paired_table_from_digest_rows(
        TABLE, policy, budget, selection, rows, retained,
    )
    .unwrap()
}

struct OriginalRows<'a> {
    keys: &'a [TriggerId],
    values: &'a [u32],
    next: usize,
    budget: AllocationBudget,
    polls: &'a Cell<usize>,
}
impl<'a> Iterator for OriginalRows<'a> {
    type Item = (&'a TriggerId, &'a u32);
    fn next(&mut self) -> Option<Self::Item> {
        self.polls.set(self.polls.get() + 1);
        if self.next == 1 {
            // A real later key allocation refuses in the exact original pool.
            self.budget.set_limit_bytes(self.budget.reserved_bytes());
        }
        let key = self.keys.get(self.next)?;
        let value = &self.values[self.next];
        self.next += 1;
        Some((key, value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.keys.len() - self.next;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for OriginalRows<'_> {}

#[test]
fn retained_semantic_original_rows_and_cursor_survive_later_refusal() {
    let keys = keys();
    let values = [11, 22];
    let oracle_pool = AllocationBudget::new(1024 * 1024);
    let oracle = original_snapshot(&keys, &values, &oracle_pool);
    let budget = AllocationBudget::new(1024 * 1024);
    let scope = budget.try_owned_refund_scope().unwrap();
    let polls = Cell::new(0);
    let mut rows = RetainedSemanticRows::new(
        TABLE,
        IDENTITY,
        limits(),
        &budget,
        (&scope, usize::MAX),
        || OriginalRows {
            keys: &keys,
            values: &values,
            next: 0,
            budget: budget.clone(),
            polls: &polls,
        },
        project,
    )
    .unwrap();
    let Err(RetainedSemanticError::Table(LeafError::Admission(AllocationRefusal::Capacity {
        ..
    }))) = rows.advance(usize::MAX)
    else {
        panic!("later original key must refuse");
    };
    assert_eq!(
        rows.progress().rows,
        1,
        "successful original canonical row survives later refusal"
    );
    assert_eq!(rows.fetched, 2);
    assert_eq!(polls.get(), 2);
    let first_key = rows.builder.encoded.as_slice()[0].key.as_slice().as_ptr();
    let original_value = rows.builder.encoded.as_slice()[0].ordered_value_digest;
    let before = rows.progress();
    let reserved = budget.reserved_bytes();
    let attempts = allocations_during(|| {
        assert!(
            matches!(rows.advance(before.work), Err(RetainedSemanticError::Work { used, .. }) if used == before.work)
        );
    });
    assert_eq!(attempts, 0);
    assert_eq!(rows.progress(), before);
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(
        rows.builder.encoded.as_slice()[0].key.as_slice().as_ptr(),
        first_key
    );
    assert_eq!(
        rows.builder.encoded.as_slice()[0].ordered_value_digest,
        original_value
    );
    assert_eq!(
        polls.get(),
        2,
        "pending original row prevents another source poll"
    );
    budget.set_limit_bytes(1024 * 1024);
    let complete = rows.advance(usize::MAX).unwrap();
    assert!(complete.complete);
    assert_eq!(complete.rows, 2);
    assert!(complete.work > before.work);
    assert_eq!(
        polls.get(),
        3,
        "only the original exhausted iterator is polled once more"
    );
    let actual = rows.snapshot().unwrap();
    assert_eq!(actual.root(), oracle.root());
    assert_eq!(actual.ordered_root(), oracle.ordered_root());
    assert_eq!(actual.lookup.root(), oracle.lookup.root());
    drop(scope);
    assert!(
        budget.reserved_bytes() > 0,
        "retained rows own the original refund scope"
    );
    drop(rows);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_semantic_pending_digest_preserves_key_and_encoder_on_slot_refusal() {
    let keys = keys();
    let budget = AllocationBudget::new(1024 * 1024);
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut rows =
        RetainedSemanticTable::new(TABLE, IDENTITY, limits(), &budget, Some(&scope)).unwrap();
    rows.push(&keys[0], || 11_u32, usize::MAX).unwrap();
    let first_key = rows.encoded.as_slice()[0].key.as_slice().as_ptr();
    let key_bytes = norito::codec::encode_adaptive(&keys[1]).len();
    let limit = budget.limit_bytes();
    assert_eq!(rows.encoded.growth_rows(), rows.encoded.len());
    let slot_bytes = std::alloc::Layout::array::<PairedDigestRow>(rows.encoded.len() + 1)
        .unwrap()
        .size();
    assert!(slot_bytes <= limit);
    // Keep the original ceiling large enough for the real replacement layout.
    // Occupy its remaining capacity, leaving only the exact canonical key bytes.
    let occupied = budget
        .try_reserve_bytes(limit - budget.reserved_bytes() - key_bytes)
        .unwrap();
    let calls = Cell::new(0);
    let result = rows.push(
        &keys[1],
        || {
            calls.set(calls.get() + 1);
            22_u32
        },
        usize::MAX,
    );
    assert!(
        matches!(&result,
            Err(RetainedSemanticError::Table(LeafError::Admission(
                AllocationRefusal::Capacity { requested_bytes, limit_bytes, .. }
            ))) if *requested_bytes == slot_bytes && *limit_bytes == limit),
        "original overlapping slot allocation must refuse with its exact capacity demand: {result:?}",
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(rows.observe().rows, 1);
    assert!(rows.observe().pending_digest);
    let key = rows.pending_row.as_ref().unwrap().key.as_slice().as_ptr();
    let digest = rows.pending_row.as_ref().unwrap().ordered_value_digest;
    let old_work = rows.work;
    assert!(matches!(
        rows.push(
            &keys[1],
            || -> u32 { panic!("completed projection must not be repeated") },
            usize::MAX
        ),
        Err(RetainedSemanticError::Table(LeafError::Admission(
            AllocationRefusal::Capacity { requested_bytes, limit_bytes, .. }
        ))) if requested_bytes == slot_bytes && limit_bytes == limit
    ));
    assert!(rows.work > old_work);
    assert_eq!(
        rows.pending_row.as_ref().unwrap().key.as_slice().as_ptr(),
        key
    );
    assert_eq!(
        rows.pending_row.as_ref().unwrap().ordered_value_digest,
        digest
    );
    drop(occupied);
    assert_eq!(budget.limit_bytes(), limit);
    rows.push(
        &keys[1],
        || -> u32 { panic!("completed projection must not be repeated") },
        usize::MAX,
    )
    .unwrap();
    assert_eq!(
        rows.encoded.as_slice()[0].key.as_slice().as_ptr(),
        first_key
    );
    assert_eq!(rows.encoded.as_slice()[1].key.as_slice().as_ptr(), key);
    assert_eq!(calls.get(), 1);
    rows.seal_rows();
    rows.advance_finalizer(usize::MAX).unwrap();
    drop(scope);
    drop(rows);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_semantic_ordered_and_lookup_frontiers_survive_work_refusal() {
    let keys = keys();
    let values = [11, 22];
    let oracle_pool = AllocationBudget::new(1024 * 1024);
    let oracle = original_snapshot(&keys, &values, &oracle_pool);
    let budget = AllocationBudget::new(1024 * 1024);
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut rows =
        RetainedSemanticTable::new(TABLE, IDENTITY, limits(), &budget, Some(&scope)).unwrap();
    for (key, value) in keys.iter().zip(values) {
        rows.push(key, || value, usize::MAX).unwrap();
    }
    rows.seal_rows();
    let sort = SORT_BOUND_STEP + sort_bound(2).unwrap() * (2 * rows.maximum_key + 8);
    let ordered = 2 * (4 * rows.maximum_key + 160) + 3 * 128;
    let limit = rows.work + sort + ordered;
    assert!(matches!(
        rows.advance_finalizer(limit),
        Err(RetainedSemanticError::Work { .. })
    ));
    assert!(rows.observe().ordered);
    assert_eq!(rows.observe().lookup_rows, 0);
    let original_ordered_key = rows
        .ordered
        .as_ref()
        .unwrap()
        .digest_rows()
        .next()
        .unwrap()
        .0
        .as_ptr();
    let reserved = budget.reserved_bytes();
    let work = rows.work;
    let attempts = allocations_during(|| {
        assert!(
            matches!(rows.advance_finalizer(work), Err(RetainedSemanticError::Work { used, .. }) if used == work)
        );
    });
    assert_eq!(attempts, 0);
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(
        rows.ordered
            .as_ref()
            .unwrap()
            .digest_rows()
            .next()
            .unwrap()
            .0
            .as_ptr(),
        original_ordered_key
    );
    let first = rows.encoded.as_slice()[0].key.as_slice().len() + rows.framing + LOOKUP_STEP;
    assert!(matches!(
        rows.advance_finalizer(work + first),
        Err(RetainedSemanticError::Work { .. })
    ));
    assert_eq!(rows.observe().lookup_rows, 1);
    let reserved = budget.reserved_bytes();
    let work = rows.work;
    let attempts = allocations_during(|| {
        assert!(rows.advance_finalizer(work).is_err());
    });
    assert_eq!(attempts, 0);
    assert_eq!(rows.observe().lookup_rows, 1);
    assert_eq!(budget.reserved_bytes(), reserved);
    rows.advance_finalizer(usize::MAX).unwrap();
    let actual = rows.completed.as_ref().unwrap();
    assert_eq!(
        actual.ordered.digest_rows().next().unwrap().0.as_ptr(),
        original_ordered_key
    );
    assert_eq!(actual.root(), oracle.root());
    assert_eq!(actual.lookup.root(), oracle.lookup.root());
    let work = rows.work;
    let attempts = allocations_during(|| {
        rows.advance_finalizer(work).unwrap();
    });
    assert_eq!(attempts, 0);
    assert_eq!(rows.work, work);
    drop(rows);
    assert_eq!(
        budget.reserved_bytes(),
        OwnedAllocationScope::allocation_layout().size()
    );
    drop(scope);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_semantic_physical_lookup_refusal_and_zero_budget_retirement_keep_completed_nodes() {
    let keys = keys();
    let values = [11, 22];
    let oracle_pool = AllocationBudget::new(1024 * 1024);
    let oracle = original_snapshot(&keys, &values, &oracle_pool);
    let budget = AllocationBudget::new(1024 * 1024);
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut rows =
        RetainedSemanticTable::new(TABLE, IDENTITY, limits(), &budget, Some(&scope)).unwrap();
    for (key, value) in keys.iter().zip(values) {
        rows.push(key, || value, usize::MAX).unwrap();
    }
    rows.seal_rows();
    let ordered_limit = rows.work
        + SORT_BOUND_STEP
        + sort_bound(2).unwrap() * (2 * rows.maximum_key + 8)
        + 2 * (4 * rows.maximum_key + 160)
        + 3 * 128;
    assert!(matches!(
        rows.advance_finalizer(ordered_limit),
        Err(RetainedSemanticError::Work { .. })
    ));
    assert!(rows.observe().ordered);
    let ordered_key = rows
        .ordered
        .as_ref()
        .unwrap()
        .digest_rows()
        .next()
        .unwrap()
        .0
        .as_ptr();
    let base = budget.reserved_bytes();
    budget.set_limit_bytes(base);
    let Err(RetainedSemanticError::Table(LeafError::Admission(AllocationRefusal::Capacity {
        requested_bytes: first_node,
        reserved_bytes,
        limit_bytes,
        ..
    }))) = rows.advance_finalizer(usize::MAX)
    else {
        panic!("first lookup uses original exhausted pool");
    };
    assert_eq!((reserved_bytes, limit_bytes), (base, base));
    assert!(first_node > 0);
    assert_eq!(rows.lookup_next, 0);
    assert!(rows.pending_lookup.is_some());
    assert_eq!(
        rows.ordered
            .as_ref()
            .unwrap()
            .digest_rows()
            .next()
            .unwrap()
            .0
            .as_ptr(),
        ordered_key
    );
    budget.set_limit_bytes(base + first_node);
    assert!(matches!(
        rows.advance_finalizer(usize::MAX),
        Err(RetainedSemanticError::Table(LeafError::Admission(
            AllocationRefusal::Capacity { .. }
        )))
    ));
    assert_eq!(
        rows.lookup_next, 1,
        "the complete first path survives later physical refusal"
    );
    let first_root = rows.selection.as_ref().unwrap().root();
    let first_charge = budget.reserved_bytes();
    let first_work = rows.work;
    let attempts = allocations_during(|| {
        assert!(matches!(
            rows.advance_finalizer(usize::MAX),
            Err(RetainedSemanticError::Table(LeafError::Admission(_)))
        ));
    });
    assert_eq!(
        attempts, 0,
        "pending path retries original admission before physical allocation"
    );
    assert_eq!(rows.selection.as_ref().unwrap().root(), first_root);
    assert_eq!(rows.lookup_next, 1);
    assert_eq!(budget.reserved_bytes(), first_charge);
    assert!(rows.work > first_work);
    assert_eq!(
        rows.ordered
            .as_ref()
            .unwrap()
            .digest_rows()
            .next()
            .unwrap()
            .0
            .as_ptr(),
        ordered_key
    );
    budget.set_limit_bytes(1024 * 1024);
    // Retain both completed trees and refuse only the final framing work.
    let limit = rows.work + LOOKUP_STEP;
    assert!(matches!(
        rows.advance_finalizer(limit),
        Err(RetainedSemanticError::Work { .. })
    ));
    assert_eq!(rows.lookup_next, 2);
    let before_retirement = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    let attempts = allocations_during(|| {
        rows.advance_finalizer(usize::MAX).unwrap();
    });
    assert_eq!(
        attempts, 0,
        "zero-capacity staging retirement has no physical allocation or refusal"
    );
    assert!(rows.observe().complete);
    assert_eq!(rows.encoded.len(), 0);
    assert!(budget.reserved_bytes() < before_retirement);
    let actual = rows.completed.as_ref().unwrap();
    assert_eq!(
        actual.ordered.digest_rows().next().unwrap().0.as_ptr(),
        ordered_key
    );
    assert_eq!(actual.root(), oracle.root());
    assert_eq!(actual.lookup_root(), oracle.lookup_root());
    drop(scope);
    drop(rows);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_semantic_foreign_scope_and_original_error_priority_refuse() {
    let keys = keys();
    let values = [11_u32, 22];
    let budget = AllocationBudget::new(1024 * 1024);
    let foreign = AllocationBudget::new(4096);
    let scope = foreign.try_owned_refund_scope().unwrap();
    let calls = Cell::new(0);
    let attempts = allocations_during(|| {
        let result = RetainedSemanticRows::new(
            TABLE,
            IDENTITY,
            limits(),
            &budget,
            (&scope, usize::MAX),
            || {
                calls.set(calls.get() + 1);
                keys.iter().zip(&values)
            },
            project,
        );
        assert!(matches!(result, Err(RetainedSemanticError::ScopeIdentity)));
    });
    assert_eq!(attempts, 0);
    assert_eq!(calls.get(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
    // A broad caller byte policy keeps the existing u32-framed stream bound;
    // a smaller MAX_NORITO_VALUE_BYTES cap would invent a materializer refusal.
    let mut broad = limits();
    broad.max_payload_bytes = usize::MAX;
    broad.max_streamed_value_bytes = u64::MAX;
    let original = original_snapshot(&keys, &values, &budget);
    let actual = CanonicalTableLeafSet::paired_semantic_table_from_rows(
        TABLE,
        IDENTITY,
        broad,
        &budget,
        keys.iter().zip(&values),
        |value| *value,
    )
    .unwrap();
    assert_eq!(actual.root(), original.root());
    drop(actual);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
    // Do not use exact source length to reorder an earlier key type refusal.
    let mut policy = limits();
    policy.max_rows = 1;
    let bad_keys = [11_u32, 22];
    assert!(matches!(
        RetainedSemanticRows::once(
            TABLE,
            IDENTITY,
            policy,
            &budget,
            || bad_keys.iter().zip(&values),
            project
        )
        .unwrap()
        .finish_once(),
        Err(LeafError::TypeMismatch("triggers.data"))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    let duplicate = [&keys[0], &keys[0]];
    assert!(matches!(
        CanonicalTableLeafSet::paired_semantic_table_from_rows(
            TABLE,
            IDENTITY,
            limits(),
            &budget,
            duplicate.into_iter().zip(&values),
            |value| *value
        ),
        Err(LeafError::OrderedRange(NoritoKeyRangeError::UnsortedKeys))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_semantic_zero_setup_work_refuses_before_metadata_and_source() {
    let keys = keys();
    let values = [11_u32, 22];
    let budget = AllocationBudget::new(1024 * 1024);
    let scope = budget.try_owned_refund_scope().unwrap();
    let source_calls = Cell::new(0);
    let before = budget.reserved_bytes();
    let attempts = allocations_during(|| {
        let result = RetainedSemanticRows::new(
            TABLE,
            IDENTITY,
            limits(),
            &budget,
            (&scope, 0),
            || {
                source_calls.set(source_calls.get() + 1);
                keys.iter().zip(&values)
            },
            project,
        );
        assert!(
            matches!(result, Err(RetainedSemanticError::Work { used: 0, required, limit: 0 })
            if required == setup_selector_work(TABLE).unwrap())
        );
    });
    assert_eq!(attempts, 0);
    assert_eq!(source_calls.get(), 0);
    assert_eq!(budget.reserved_bytes(), before);
    let selector = setup_selector_work(TABLE).unwrap();
    let (key, value) = closed_setup_literal(TABLE).unwrap();
    let registry = setup_registry_work(key, value).unwrap();
    let result = RetainedSemanticRows::new(
        TABLE,
        IDENTITY,
        limits(),
        &budget,
        (&scope, selector + registry - 1),
        || {
            source_calls.set(source_calls.get() + 1);
            keys.iter().zip(&values)
        },
        project,
    );
    assert!(
        matches!(result, Err(RetainedSemanticError::Work { used, required, limit })
        if used == selector && required == selector + registry && limit == required - 1)
    );
    assert_eq!(source_calls.get(), 0);
    assert_eq!(budget.reserved_bytes(), before);
    drop(scope);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_semantic_closed_setup_names_match_actual_registry_literal_fast_paths() {
    let budget = AllocationBudget::new(0);
    for table in [
        "world.musubi_archive_availability",
        "world.musubi_resolver_index",
        "world.musubi_public_directory",
        TABLE,
    ] {
        let (key_literal, value_literal) = closed_setup_literal(table).unwrap();
        let selection = CanonicalTableLeafSet::new(&[table], limits(), &budget).unwrap();
        let (_, (key, value)) = selection.selection.table(table).unwrap();
        let Schema::Norito { nominal_name, .. } = key else {
            panic!("actual key is native Norito");
        };
        assert!(
            matches!(nominal_name(), std::borrow::Cow::Borrowed(actual) if actual == key_literal)
        );
        assert!(matches!(value, Schema::Semantic { identity, .. } if identity == value_literal));
        assert!(setup_registry_work(key_literal, value_literal).unwrap() > REGISTRY_GEOMETRY);
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_semantic_heap_comparisons_have_an_exact_finite_ceiling() {
    fn check(rows: &mut [usize]) {
        let count = Cell::new(0_usize);
        let bound = sort_bound(rows.len()).unwrap();
        let attempts = allocations_during(|| {
            heap_sort_by(rows, |left, right| {
                count.set(count.get() + 1);
                left.cmp(right)
            })
        });
        assert_eq!(attempts, 0);
        assert!(
            count.get() <= bound,
            "{} comparisons exceed {bound} for {} rows",
            count.get(),
            rows.len()
        );
        assert!(rows.windows(2).all(|pair| pair[0] <= pair[1]));
    }
    fn permutations(rows: &mut [usize], offset: usize) {
        if offset == rows.len() {
            let mut candidate = rows.to_vec();
            check(&mut candidate);
            return;
        }
        for index in offset..rows.len() {
            rows.swap(offset, index);
            permutations(rows, offset + 1);
            rows.swap(offset, index);
        }
    }
    for length in 0..=8 {
        permutations(&mut (0..length).collect::<Vec<_>>(), 0);
    }
    for power in 1..=12 {
        for length in [(1 << power) - 1, 1 << power, (1 << power) + 1] {
            check(&mut (0..length).rev().collect::<Vec<_>>());
            check(&mut (0..length).map(|index| index % 7).collect::<Vec<_>>());
        }
    }
}
