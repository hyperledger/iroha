//! Group descriptor, same-source companion, funded slots and aggregate cleanup.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        AccountValue, World,
        authority_registry::{Canonical, Role, schema},
    },
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    account::{AccountDetails, AccountId, rekey::AccountAlias},
    prelude::TransactionEntrypoint,
};
use iroha_model_base::topology::DataSpaceId;
use std::{alloc::Layout, cell::Cell, num::NonZeroUsize};

type Key = HashOf<TransactionEntrypoint>;
type Reader = fn(&State, LeafLimits) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError>;
const FRONTIER: Field = Field::new(
    "state.transactions.frontier",
    Role::Canonical(Canonical::Cell(schema::<u64>())),
);
const MEMBERSHIP_FIELDS: &[Field] = &[
    FRONTIER,
    Field::new(
        "state.transactions.current",
        Role::Canonical(Canonical::Table {
            key: schema::<Key>(),
            value: schema::<u64>(),
        }),
    ),
    Field::new(
        "state.transactions.rollback",
        Role::Canonical(Canonical::Table {
            key: schema::<Key>(),
            value: schema::<u64>(),
        }),
    ),
];
const MEMBERSHIP: Field = Field::new(
    "state.transactions",
    Role::Canonical(Canonical::Owner(MEMBERSHIP_FIELDS)),
);
const ACCOUNTS: Field = Field::new(
    "world.accounts",
    Role::Canonical(Canonical::Table {
        key: schema::<AccountId>(),
        value: schema::<AccountValue>(),
    }),
);
const ALIASES: Field = Field::new(
    "world.account_aliases",
    Role::Canonical(Canonical::Table {
        key: schema::<AccountAlias>(),
        value: schema::<AccountId>(),
    }),
);
// A scoped fixture inventory places a trailing reader after the group to test
// aggregate failure custody. The real catalog keeps membership after all World.
const FIELDS: &[Field] = &[ACCOUNTS, MEMBERSHIP, ALIASES];
const GROUP_ONLY: &[Field] = &[MEMBERSHIP];

thread_local! {
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static FIRST_RESERVED: Cell<usize> = const { Cell::new(0) };
    static LAST_RESERVED: Cell<usize> = const { Cell::new(0) };
}

fn policy() -> TableCaptureLimits {
    TableCaptureLimits {
        musubi: crate::state::authority_registry::complete::table_capture::musubi_test_limits(),
        tables: LeafLimits {
            max_tables: 4,
            max_rows: 16,
            max_payload_bytes: 4096,
            max_ordered_table_bytes: 65536,
            max_streamed_value_bytes: 65536,
        },
        membership: MembershipWorkLimits {
            max_row_visits: 6,
            max_streamed_bytes: 65536,
            max_ordered_bytes: 65536,
        },
    }
}

fn key(n: u8) -> Key {
    Key::from_untyped_unchecked(Hash::new([n]))
}

fn insert_membership(state: &State, height: usize, keys: &[Key]) {
    let mut block = state.transactions.block();
    block.insert_block(
        keys.iter().copied().collect(),
        NonZeroUsize::new(height).unwrap(),
    );
    block.commit().unwrap();
}

fn state() -> State {
    CALLS.set(0);
    FIRST_RESERVED.set(0);
    LAST_RESERVED.set(0);
    let mut state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let account = AccountId::new(
        KeyPair::from_seed(b"grouped-membership".to_vec(), Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    state.world.accounts.insert(
        account.clone(),
        AccountValue::new(AccountDetails::default()),
    );
    state.world.account_aliases.insert(
        AccountAlias::domainless("grouped".parse().unwrap(), DataSpaceId::UNIVERSAL),
        account,
    );
    state.world.rebuild_account_alias_index().unwrap();
    insert_membership(&state, 1, &[key(1), key(2)]);
    insert_membership(&state, 2, &[key(2), key(3)]);
    state
}

fn accounts(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    CALLS.set(CALLS.get() + 1);
    FIRST_RESERVED.set(state.ivm_execution_budget().reserved_bytes());
    super::super::capture_accounts_table_once(state, limits)
}
fn aliases(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    CALLS.set(CALLS.get() + 1);
    LAST_RESERVED.set(state.ivm_execution_budget().reserved_bytes());
    super::super::capture_account_alias_table_once(state, limits)
}
fn readers(last: Reader) -> [TableMaterializer; 3] {
    [
        TableMaterializer::Single {
            id: "world.accounts",
            capture: accounts,
        },
        TableMaterializer::TransactionMembership,
        TableMaterializer::Single {
            id: "world.account_aliases",
            capture: last,
        },
    ]
}

#[test]
fn exact_group_captures_two_slots_with_inseparable_frontier_surface_and_roots() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let expected_surface = state.transactions.block().publication_surface();
    let captured = capture_tables_once(&state, FIELDS, &readers(aliases), policy())
        .unwrap()
        .unwrap();
    assert_eq!(
        CALLS.get(),
        2,
        "two singles and one closed grouped acquisition"
    );
    assert_eq!(
        FIRST_RESERVED.get(),
        before
            + Layout::array::<CanonicalTablePairedSnapshot>(4)
                .unwrap()
                .size()
    );
    assert!(LAST_RESERVED.get() > FIRST_RESERVED.get());
    assert_eq!(captured.nodes.capacity(), 4);
    assert_eq!(
        captured
            .nodes()
            .iter()
            .map(CanonicalTablePairedSnapshot::table_id)
            .collect::<Vec<_>>(),
        [
            "world.accounts",
            "state.transactions.current",
            "state.transactions.rollback",
            "world.account_aliases"
        ]
    );
    assert_eq!(
        captured
            .nodes()
            .iter()
            .map(CanonicalTablePairedSnapshot::row_count)
            .collect::<Vec<_>>(),
        [1, 3, 2, 1]
    );
    let companion = captured.membership.as_ref().unwrap();
    assert_eq!(companion.frontier(), 2);
    assert_eq!(companion.original_surface(), &expected_surface);
    assert!(companion.matches_nodes(captured.nodes()));
    assert!(!companion.matches_nodes(&captured.nodes()[..2]));
    insert_membership(&state, 3, &[key(4)]);
    assert_eq!(companion.frontier(), 2);
    assert_eq!(companion.original_surface(), &expected_surface);
    assert!(companion.matches_nodes(captured.nodes()));
    let mut changed_policy = policy();
    changed_policy.membership.max_row_visits = 16;
    let changed = capture_tables_once(&state, FIELDS, &readers(aliases), changed_policy)
        .unwrap()
        .unwrap();
    assert!(!companion.matches_nodes(changed.nodes()));
    assert_ne!(
        changed.membership.as_ref().unwrap().original_surface(),
        companion.original_surface()
    );
    drop(changed);
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), retained);
    drop(captured);
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn exact_group_descriptor_rejects_missing_duplicate_displaced_and_single_routes() {
    let group = TableMaterializer::TransactionMembership;
    assert_eq!(
        require_exact_table_materializers(GROUP_ONLY, &[group]).unwrap(),
        2
    );
    assert!(matches!(
        require_exact_table_materializers(GROUP_ONLY, &[]),
        Err(TableCaptureError::MissingMaterializer(
            "state.transactions.current"
        ))
    ));
    assert!(matches!(
        require_exact_table_materializers(GROUP_ONLY, &[group, group]),
        Err(TableCaptureError::DuplicateMaterializer(
            "state.transactions.current"
        ))
    ));
    let mut displaced = readers(aliases);
    displaced.swap(0, 1);
    assert!(matches!(
        require_exact_table_materializers(FIELDS, &displaced),
        Err(TableCaptureError::DisplacedMaterializer("world.accounts"))
    ));
    let singles = [
        TableMaterializer::Single {
            id: "state.transactions.current",
            capture: accounts,
        },
        TableMaterializer::Single {
            id: "state.transactions.rollback",
            capture: accounts,
        },
    ];
    assert!(matches!(
        require_exact_table_materializers(GROUP_ONLY, &singles),
        Err(TableCaptureError::MalformedMembershipGroup)
    ));
    const NO_OWNER: &[Field] = &[MEMBERSHIP_FIELDS[1], MEMBERSHIP_FIELDS[2]];
    const DUP_FRONTIER: &[Field] = &[MEMBERSHIP, FRONTIER];
    const BAD_FRONTIER_FIELDS: &[Field] = &[
        Field::new(
            "state.transactions.frontier",
            Role::Canonical(Canonical::Cell(schema::<u32>())),
        ),
        MEMBERSHIP_FIELDS[1],
        MEMBERSHIP_FIELDS[2],
    ];
    const BAD_FRONTIER: &[Field] = &[Field::new(
        "state.transactions",
        Role::Canonical(Canonical::Owner(BAD_FRONTIER_FIELDS)),
    )];
    const BAD_TABLE_FIELDS: &[Field] = &[
        FRONTIER,
        Field::new(
            "state.transactions.current",
            Role::Canonical(Canonical::Table {
                key: schema::<Key>(),
                value: schema::<u32>(),
            }),
        ),
        MEMBERSHIP_FIELDS[2],
    ];
    const BAD_TABLE: &[Field] = &[Field::new(
        "state.transactions",
        Role::Canonical(Canonical::Owner(BAD_TABLE_FIELDS)),
    )];
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let peak_before = budget.peak_reserved_bytes();
    budget.set_limit_bytes(0);
    for fields in [NO_OWNER, DUP_FRONTIER, BAD_FRONTIER, BAD_TABLE] {
        assert!(matches!(
            capture_tables_once(&state, fields, &[group], policy())
                .err()
                .unwrap(),
            TableCaptureError::MalformedMembershipGroup
        ));
        assert_eq!(budget.peak_reserved_bytes(), peak_before);
        assert_eq!(budget.reserved_bytes(), before);
    }
    assert_eq!(CALLS.get(), 0);
}

#[test]
fn grouped_output_count_and_original_pool_are_admitted_before_any_reader() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let mut limited = policy();
    limited.tables.max_tables = 3;
    assert!(matches!(
        capture_tables_once(&state, FIELDS, &readers(aliases), limited)
            .err()
            .unwrap(),
        TableCaptureError::MaterializerLimit
    ));
    assert_eq!(CALLS.get(), 0);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - before)
        .unwrap();
    let bytes = Layout::array::<CanonicalTablePairedSnapshot>(4)
        .unwrap()
        .size();
    let expected = budget.try_reserve_bytes(bytes).unwrap_err();
    assert!(
        matches!(&(capture_tables_once(&state, FIELDS, &readers(aliases), policy())
            .err()
            .unwrap()), TableCaptureError::Admission(actual) if actual == &expected)
    );
    assert_eq!(CALLS.get(), 0);
    drop(occupied);
    drop(
        capture_tables_once(&state, FIELDS, &readers(aliases), policy())
            .unwrap()
            .unwrap(),
    );
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn busy_source_work_and_pair_row_refusals_reclaim_preceding_native_nodes() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let held = state.transactions.block();
    let expected = state
        .transactions
        .try_membership_observation()
        .err()
        .unwrap();
    assert!(
        matches!(&(capture_tables_once(&state, FIELDS, &readers(aliases), policy())
            .err()
            .unwrap()), TableCaptureError::Membership(MembershipCaptureError::Acquisition(actual)) if actual == &expected)
    );
    assert_eq!(CALLS.get(), 1);
    assert_eq!(budget.reserved_bytes(), before);
    drop(held);
    let mut work = policy();
    work.membership.max_row_visits = 5;
    assert!(matches!(capture_tables_once(&state, FIELDS, &readers(aliases), work),
        Err(TableCaptureError::Membership(MembershipCaptureError::Authority(
            crate::state::storage_transactions::authority::TransactionMembershipAuthorityError::TraversalRefused {required:6,limit:5})))));
    assert_eq!(budget.reserved_bytes(), before);
    let mut rows = policy();
    rows.tables.max_rows = 5;
    assert!(matches!(
        capture_tables_once(&state, FIELDS, &readers(aliases), rows),
        Err(TableCaptureError::Membership(
            MembershipCaptureError::AggregateLimit
        ))
    ));
    assert_eq!(budget.reserved_bytes(), before);
    assert!(state.transactions.try_membership_observation().is_ok());
}

fn rejected(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    drop(aliases(state, limits)?);
    Err(LeafError::PayloadLimit)
}
fn mismatched(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    drop(aliases(state, limits)?);
    super::super::capture_accounts_table_once(state, limits)
}
fn changed_generation(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let result = aliases(state, limits)?;
    let mut publication = state.state_view_publication();
    drop(publication.begin());
    Ok(result)
}

#[test]
fn post_group_error_identity_and_generation_retry_drop_pair_and_companion() {
    let cases: [(Reader, Option<TableCaptureError>); 3] = [
        (
            rejected,
            Some(TableCaptureError::Leaf(LeafError::PayloadLimit)),
        ),
        (
            mismatched,
            Some(TableCaptureError::IdentityMismatch {
                expected: "world.account_aliases",
                actual: "world.accounts",
            }),
        ),
        (changed_generation, None),
    ];
    for (last, expected) in cases {
        let state = state();
        let budget = state.ivm_execution_budget();
        let before = budget.reserved_bytes();
        let result = capture_tables_once(&state, FIELDS, &readers(last), policy());
        if let Some(expected) = expected {
            assert!(match (&result.err().unwrap(), &expected) {
                (TableCaptureError::Leaf(actual), TableCaptureError::Leaf(expected)) =>
                    actual == expected,
                (
                    TableCaptureError::IdentityMismatch {
                        expected: actual_expected,
                        actual: actual_actual,
                    },
                    TableCaptureError::IdentityMismatch {
                        expected: expected_expected,
                        actual: expected_actual,
                    },
                ) => actual_expected == expected_expected && actual_actual == expected_actual,
                _ => false,
            });
        } else {
            assert!(result.unwrap().is_none());
        }
        assert_eq!(CALLS.get(), 2);
        assert!(LAST_RESERVED.get() > FIRST_RESERVED.get());
        assert_eq!(budget.reserved_bytes(), before);
        assert!(state.transactions.try_membership_observation().is_ok());
    }
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let peak_before = budget.peak_reserved_bytes();
    budget.set_limit_bytes(0);
    let mut publication = state.state_view_publication();
    let guard = publication.begin();
    assert!(
        capture_tables_once(&state, FIELDS, &readers(aliases), policy())
            .unwrap()
            .is_none()
    );
    assert_eq!(CALLS.get(), 0);
    assert_eq!(budget.peak_reserved_bytes(), peak_before);
    assert_eq!(budget.reserved_bytes(), before);
    drop(guard);
}
