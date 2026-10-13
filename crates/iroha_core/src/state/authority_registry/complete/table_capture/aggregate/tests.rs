//! Original-budget aggregate backing, typed refusal and partial-capture cleanup.

use super::*;
fn policy(tables: LeafLimits) -> TableCaptureLimits {
    TableCaptureLimits {
        musubi: crate::state::authority_registry::complete::table_capture::musubi_test_limits(),
        tables,
        membership: MembershipWorkLimits {
            max_row_visits: 64,
            max_streamed_bytes: 131_072,
            max_ordered_bytes: 131_072,
        },
    }
}

use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        AccountValue, World,
        authority_registry::{Canonical, Field, Role, schema},
    },
};
use iroha_allocation::AllocationBudget;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::{AccountDetails, AccountId, rekey::AccountAlias};
use iroha_model_base::topology::DataSpaceId;
use std::{
    alloc::Layout,
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

type Reader = fn(&State, LeafLimits) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError>;

const FIELDS: &[Field] = &[
    Field::new(
        "world.accounts",
        Role::Canonical(Canonical::Table {
            key: schema::<AccountId>(),
            value: schema::<AccountValue>(),
        }),
    ),
    Field::new(
        "world.account_aliases",
        Role::Canonical(Canonical::Table {
            key: schema::<AccountAlias>(),
            value: schema::<AccountId>(),
        }),
    ),
];

thread_local! {
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static FIRST_RESERVED: Cell<usize> = const { Cell::new(0) };
    static SECOND_RESERVED: Cell<usize> = const { Cell::new(0) };
}

fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 2,
        max_rows: 8,
        max_payload_bytes: 4096,
        max_ordered_table_bytes: 32 * 1024,
        max_streamed_value_bytes: 32 * 1024,
    }
}

fn state() -> State {
    CALLS.set(0);
    FIRST_RESERVED.set(0);
    SECOND_RESERVED.set(0);
    let mut state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let account = AccountId::new(
        KeyPair::from_seed(b"funded-table-array".to_vec(), Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    state.world.accounts.insert(
        account.clone(),
        AccountValue::new(AccountDetails::default()),
    );
    state.world.account_aliases.insert(
        AccountAlias::domainless("captured".parse().unwrap(), DataSpaceId::UNIVERSAL),
        account,
    );
    state.world.rebuild_account_alias_index().unwrap();
    state
}

fn note_reader(state: &State) {
    let calls = CALLS.get();
    CALLS.set(calls + 1);
    let reserved = state.ivm_execution_budget().reserved_bytes();
    if calls == 0 {
        FIRST_RESERVED.set(reserved);
    } else {
        SECOND_RESERVED.set(reserved);
    }
}

fn accounts(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    note_reader(state);
    super::super::capture_accounts_table_once(state, limits)
}

fn aliases(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    note_reader(state);
    super::super::capture_account_alias_table_once(state, limits)
}

fn materializers(second: TableMaterializer) -> [TableMaterializer; 2] {
    [
        TableMaterializer::Single {
            id: "world.accounts",
            capture: accounts,
        },
        second,
    ]
}

fn normal_readers() -> [TableMaterializer; 2] {
    materializers(TableMaterializer::Single {
        id: "world.account_aliases",
        capture: aliases,
    })
}

fn backing_bytes() -> usize {
    Layout::array::<CanonicalTablePairedSnapshot>(2)
        .unwrap()
        .size()
}

#[test]
fn exact_outer_backing_is_admitted_before_first_reader_and_retained_until_final_owner() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let capture = capture_tables_once(&state, FIELDS, &normal_readers(), policy(limits()))
        .unwrap()
        .unwrap();
    assert_eq!(CALLS.get(), 2);
    assert_eq!(FIRST_RESERVED.get(), before + backing_bytes());
    assert!(
        SECOND_RESERVED.get() > FIRST_RESERVED.get(),
        "first table remains retained"
    );
    assert_eq!(capture.nodes.capacity(), 2);
    assert_eq!(capture.nodes.as_slice().len(), 2);
    assert_eq!(capture.nodes.as_slice()[0].row_count(), 1);
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(matches!(
        capture_tables_once(&state, FIELDS, &normal_readers(), policy(limits())),
        Err(TableCaptureError::Admission(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(
        CALLS.get(),
        2,
        "no reader runs after outer admission refusal"
    );
    assert_eq!(capture.nodes.as_slice()[1].row_count(), 1);
    drop(capture);
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn empty_catalog_uses_zero_backing_and_catalog_errors_precede_pool_refusal() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    let empty = capture_tables_once(&state, &[], &[], policy(limits()))
        .unwrap()
        .unwrap();
    assert_eq!(empty.nodes.capacity(), 0);
    assert!(empty.nodes.as_slice().is_empty());
    assert_eq!(budget.reserved_bytes(), before);
    drop(empty);
    assert!(
        matches!(capture_tables_once(&state, FIELDS, &normal_readers(), policy(limits())),
        Err(TableCaptureError::Admission(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes: 0 })) if requested_bytes == backing_bytes())
    );
    assert_eq!(
        capture_tables_once(
            &state,
            FIELDS,
            &normal_readers(),
            policy(LeafLimits {
                max_tables: 1,
                ..limits()
            })
        )
        .err()
        .unwrap(),
        TableCaptureError::MaterializerLimit
    );
    assert_eq!(
        capture_tables_once(&state, FIELDS, &[], policy(limits()))
            .err()
            .unwrap(),
        TableCaptureError::MissingMaterializer("world.accounts")
    );
    let over_count = [normal_readers()[0]; super::super::MAX_TABLE_MATERIALIZERS + 1];
    assert_eq!(
        capture_tables_once(&state, FIELDS, &over_count, policy(limits()))
            .err()
            .unwrap(),
        TableCaptureError::MaterializerLimit
    );
    assert_eq!(CALLS.get(), 0);
    let mut publication = state.state_view_publication();
    let guard = publication.begin();
    assert!(
        capture_tables_once(&state, FIELDS, &normal_readers(), policy(limits()))
            .unwrap()
            .is_none()
    );
    drop(guard);
    assert_eq!(budget.reserved_bytes(), before);
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn occupied_original_pool_preserves_exact_refusal_wake_and_retry() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let before = budget.reserved_bytes();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - before)
        .unwrap();
    let expected = budget.try_reserve_bytes(backing_bytes()).unwrap_err();
    let TableCaptureError::Admission(actual) =
        capture_tables_once(&state, FIELDS, &normal_readers(), policy(limits()))
            .err()
            .unwrap()
    else {
        panic!("original typed admission refusal");
    };
    assert_eq!(actual, expected);
    assert_eq!(CALLS.get(), 0);
    let AllocationRefusal::Capacity { release, .. } = actual else {
        panic!("occupied original pool");
    };
    let wakes = Arc::new(Wakes::default());
    let task_waker = Waker::from(Arc::clone(&wakes));
    let mut context = Context::from_waker(&task_waker);
    let mut future = release.wait_for_release(&mut registration);
    assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
    let unrelated = AllocationBudget::new(backing_bytes());
    drop(unrelated.try_reserve_bytes(backing_bytes()).unwrap());
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
    drop(occupied);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Ready(()));
    let capture = capture_tables_once(&state, FIELDS, &normal_readers(), policy(limits()))
        .unwrap()
        .unwrap();
    assert_eq!(FIRST_RESERVED.get(), before + backing_bytes());
    drop(capture);
    assert_eq!(budget.reserved_bytes(), before);
    drop(future);
    drop(registration);
    assert_eq!(
        budget.reserved_bytes(),
        before - iroha_allocation::release::ReleaseRegistration::allocation_layout().size()
    );
}

fn rejected_second(
    state: &State,
    _: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    note_reader(state);
    Err(LeafError::PayloadLimit)
}

fn unavailable_second(
    state: &State,
    _: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    note_reader(state);
    Ok(None)
}

fn generation_changed_second(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let result = aliases(state, limits)?;
    let mut publication = state.state_view_publication();
    let guard = publication.begin();
    drop(guard);
    Ok(result)
}

#[test]
fn partial_child_failure_identity_mismatch_and_both_generation_retries_release_all_backing() {
    let cases: [(Reader, Option<TableCaptureError>); 4] = [
        (
            rejected_second,
            Some(TableCaptureError::Leaf(LeafError::PayloadLimit)),
        ),
        (
            accounts,
            Some(TableCaptureError::IdentityMismatch {
                expected: "world.account_aliases",
                actual: "world.accounts",
            }),
        ),
        (unavailable_second, None),
        (generation_changed_second, None),
    ];
    for (capture, expected) in cases {
        let state = state();
        let budget = state.ivm_execution_budget();
        let before = budget.reserved_bytes();
        let result = capture_tables_once(
            &state,
            FIELDS,
            &materializers(TableMaterializer::Single {
                id: "world.account_aliases",
                capture,
            }),
            policy(limits()),
        );
        match expected {
            Some(error) => assert_eq!(result.err().unwrap(), error),
            None => assert!(result.unwrap().is_none()),
        }
        assert_eq!(CALLS.get(), 2);
        assert!(SECOND_RESERVED.get() > FIRST_RESERVED.get());
        assert_eq!(budget.reserved_bytes(), before);
    }
}

fn panic_second(
    state: &State,
    _: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    note_reader(state);
    panic!("injected reader unwind");
}

#[test]
fn aggregate_row_failure_and_reader_unwind_release_completed_nodes_and_outer_backing() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    assert_eq!(
        capture_tables_once(
            &state,
            FIELDS,
            &normal_readers(),
            policy(LeafLimits {
                max_rows: 1,
                ..limits()
            })
        )
        .err()
        .unwrap(),
        TableCaptureError::AggregateRowLimit
    );
    assert_eq!(CALLS.get(), 2);
    assert_eq!(budget.reserved_bytes(), before);
    CALLS.set(0);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        capture_tables_once(
            &state,
            FIELDS,
            &materializers(TableMaterializer::Single {
                id: "world.account_aliases",
                capture: panic_second,
            }),
            policy(limits()),
        )
    }));
    assert!(failed.is_err());
    assert_eq!(CALLS.get(), 2);
    assert!(SECOND_RESERVED.get() > FIRST_RESERVED.get());
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn allocator_error_mapping_remains_operational_without_fabricating_a_release_owner() {
    assert_eq!(
        TableCaptureError::from(ChargedBufferError::Allocator {
            requested_bytes: backing_bytes()
        }),
        TableCaptureError::Allocation
    );
}
