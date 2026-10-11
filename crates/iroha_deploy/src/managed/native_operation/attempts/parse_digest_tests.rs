//! Actual canonical wallet prefixes exercise parse-local hashes and unchanged fresh admissions.
//! These local records and request-only retirements grant no native finality or live authority.

use super::*;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Counts {
    pub(super) requested: usize,
    pub(super) computed: usize,
    pub(super) by_ordinal: [u8; MAX_ATTEMPTS],
    pub(super) reads: usize,
    pub(super) decoded: usize,
}
impl Default for Counts {
    fn default() -> Self {
        Self {
            requested: 0,
            computed: 0,
            by_ordinal: [0; MAX_ATTEMPTS],
            reads: 0,
            decoded: 0,
        }
    }
}
thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}
pub(super) struct Counter;
impl Counter {
    pub(super) fn begin() -> Self {
        COUNTS.with(|state| {
            assert!(state.get().is_none(), "one parse observer per test scope");
            state.set(Some(Counts::default()));
        });
        Self
    }
    pub(super) fn finish(self) -> Counts {
        COUNTS.with(|state| state.get().expect("the parse observer remains installed"))
    }
}
impl Drop for Counter {
    fn drop(&mut self) {
        COUNTS.with(|state| state.set(None));
    }
}
fn update(change: impl FnOnce(&mut Counts)) {
    COUNTS.with(|state| {
        if let Some(mut counts) = state.get() {
            change(&mut counts);
            state.set(Some(counts));
        }
    });
}
pub(in crate::managed::native_operation::attempts) fn digest_requested() {
    update(|counts| counts.requested += 1);
}
pub(in crate::managed::native_operation::attempts) fn digest_computed(ordinal: u8) {
    update(|counts| {
        counts.computed += 1;
        counts.by_ordinal[usize::from(ordinal) - 1] += 1;
    });
}
pub(in crate::managed::native_operation::attempts) fn record_read() {
    update(|counts| counts.reads += 1);
}
pub(in crate::managed::native_operation::attempts) fn record_decoded() {
    update(|counts| counts.decoded += 1);
}
fn observed(fixture: &Fixture) -> (Result<History>, Counts) {
    let counter = Counter::begin();
    let result = fixture.history();
    (result, counter.finish())
}
fn canonical_rows(fixture: &Fixture) {
    let mut previous = fixture.reserve();
    fixture.commit(&previous);
    for ordinal in 1..=2_u8 {
        let next = fixture
            .history()
            .unwrap()
            .reserve(
                &fixture.operation,
                Origin::Generated {
                    ordinal,
                    epoch: [ordinal; 32],
                    parent_intent: [0x73; 32],
                },
                fixture.terms.clone(),
            )
            .unwrap();
        let receipt = fixture
            .wallet
            .retire_initial_reserve_policy_unprepared(
                &previous.wallet_path(),
                &fixture.request(&previous),
            )
            .unwrap();
        retire_request(&previous, &next, &receipt).unwrap();
        let retained = fixture.retain(&next);
        commit(&next, Some(&previous), Observation::ordinary(), &retained).unwrap();
        previous = next;
    }
}
fn assert_three_rows(counts: Counts) {
    assert_eq!(counts.requested, 10);
    assert_eq!(counts.computed, 3);
    assert_eq!(counts.reads, 15);
    assert_eq!(counts.decoded, 12);
    assert_eq!(&counts.by_ordinal[..3], &[1, 1, 1]);
    assert!(counts.by_ordinal[3..].iter().all(|count| *count == 0));
}

#[test]
fn genuine_selected_history_rehashes_each_fresh_parse_and_preserves_refusal_order_and_retry() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    canonical_rows(&fixture);
    let (parsed, counts) = observed(&fixture);
    let history = parsed.unwrap();
    assert_three_rows(counts);
    history
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    let selected = history.selected().unwrap().unwrap();
    assert_eq!(selected.ordinal(), 3);
    assert_eq!(
        fixture.inspect(selected).unwrap().phase(),
        NativePreparationPhase::RequestOnly
    );
    let request = std::fs::read(selected.wallet_path().join("preparation.json")).unwrap();
    let dispatch = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();

    let first = &history.attempts[0];
    let first_commit = first
        .directory
        .read("committed.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let mut changed_commit = first.commit.clone().unwrap();
    changed_commit.request_sha256 = "invalid".into();
    first
        .directory
        .write_atomic(
            "committed.nrt",
            &encode(&changed_commit, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    let (refused, counts) = observed(&fixture);
    assert_eq!(
        refused.err().unwrap().to_string(),
        "dispatch commit differs from original custody"
    );
    assert_eq!(
        counts.requested, 0,
        "the invalid request digest must refuse before row hashing"
    );
    assert_eq!(counts.computed, 0);
    first
        .directory
        .write_atomic("committed.nrt", &first_commit, PublishMode::Replace)
        .unwrap();

    let middle = &history.attempts[1];
    let original = middle
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let mut changed = middle.authorization.clone();
    changed.terms.signing_deadline_unix_ms -= 1;
    middle
        .directory
        .write_atomic(
            "authorization.nrt",
            &encode(&changed, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    let (refused, counts) = observed(&fixture);
    assert_eq!(
        refused.err().unwrap().to_string(),
        "dispatch commit differs from original custody"
    );
    assert_eq!(
        counts.computed, 2,
        "changed current bytes receive their own current-row hash"
    );
    assert_eq!(&counts.by_ordinal[..3], &[1, 1, 0]);
    middle
        .directory
        .write_atomic("authorization.nrt", &original, PublishMode::Replace)
        .unwrap();

    let no_allocations =
        norito::DecodeLimits::new(MAX_RECORD_BYTES, MAX_RECORD_BYTES, MAX_RECORD_BYTES, 0, 32);
    let counter = Counter::begin();
    let refused = norito::core::with_decode_limits_scope(no_allocations, || fixture.history());
    let counts = counter.finish();
    assert_eq!(
        refused.err().unwrap().to_string(),
        "invalid canonical dispatch custody record"
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 0);
    assert_eq!(counts.computed, 0);

    let wide = norito::DecodeLimits::new(
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        64 * 1024 * 1024,
        32,
    );
    let counter = Counter::begin();
    let retried = norito::core::with_decode_limits_scope(wide, || fixture.history());
    let counts = counter.finish();
    assert_three_rows(counts);
    let retried = retried.unwrap();
    assert_eq!(retried.selected().unwrap().unwrap().ordinal(), 3);
    let (fresh, counts) = observed(&fixture);
    assert_three_rows(counts);
    fresh
        .unwrap()
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        dispatch
    );
    assert_eq!(
        middle
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert_eq!(
        std::fs::read(selected.wallet_path().join("preparation.json")).unwrap(),
        request
    );
    assert!(!selected.wallet_path().join("payload.json").exists());
    assert!(!selected.wallet_path().join("operation.json").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn pending_absent_and_empty_suffixes_hash_the_first_row_only_at_its_original_use() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let first = fixture.reserve();
    fixture
        .history()
        .unwrap()
        .reserve_pending(
            &fixture.operation,
            Origin::Generated {
                ordinal: 1,
                epoch: [1; 32],
                parent_intent: [0x75; 32],
            },
            fixture.terms.clone(),
        )
        .unwrap();
    let dispatch = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let original = first
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let (parsed, counts) = observed(&fixture);
    let history = parsed.unwrap();
    assert_eq!(counts.requested, 2);
    assert_eq!(counts.computed, 1);
    assert_eq!(counts.reads, 7);
    assert_eq!(counts.decoded, 2);
    assert_eq!(counts.by_ordinal[0], 1);
    assert!(history.reservation_pending() && history.empty_tail);
    assert!(matches!(
        history.selected(),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::TransitionPending
        ))
    ));

    let empty = history.root.as_ref().unwrap().create_child("0002").unwrap();
    let (parsed, empty_counts) = observed(&fixture);
    let parsed = parsed.unwrap();
    assert_eq!(empty_counts.reads, counts.reads + 1);
    assert_eq!(empty_counts.decoded, counts.decoded);
    assert_eq!(empty_counts.requested, counts.requested);
    assert_eq!(empty_counts.computed, counts.computed);
    assert!(parsed.reservation_pending() && parsed.empty_tail);
    empty
        .write_atomic(
            "observation.nrt",
            &encode(&Observation::ordinary(), MAX_RECORD_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let (refused, counts) = observed(&fixture);
    assert_eq!(
        refused.err().unwrap().to_string(),
        "dispatch material exists without its authorization"
    );
    assert_eq!(
        counts.requested, 0,
        "no eager first-row hash before empty suffix validation"
    );
    assert_eq!(counts.computed, 0);
    std::fs::remove_file(empty.path().join("observation.nrt")).unwrap();
    let (retried, counts) = observed(&fixture);
    retried.unwrap();
    assert_eq!(counts, empty_counts);
    assert_eq!(
        first
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        dispatch
    );
    assert!(!first.wallet_path().exists());
    assert!(empty.entries(1).unwrap().is_empty());
}
