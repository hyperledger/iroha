//! Canonical AMX identity, Begin matching and monetary effects with actual heap observations.
// The existing input graph and independent canonical frame oracle are acquired before observation.
// The standalone target and cfg(test)-only Model unit module each have one allocator owner.
// Observation grants no proof or monetary authority. Parent-side oracles may warm shared
// process state; the measured operation starts on a fresh worker thread, not a cold process.
#![allow(
    unsafe_code,
    reason = "isolated test allocator forwards every original System allocation contract"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
    marker::PhantomData,
};

use iroha_crypto::Hash;
use iroha_data_model::sumeragi_amx::{
    AMX_TRANSACTION_DOMAIN, AmxBeginV1, AmxError, AmxLegV1, AmxTransactionV1, MAX_AMX_LEG_BYTES,
    MAX_AMX_PARTICIPANTS, MIN_AMX_PARTICIPANTS,
};
use iroha_model_base::topology::DataSpaceId;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    // Each allocation entry point has its own observable count.
    static REQUESTS: Cell<[usize; 3]> = const { Cell::new([0; 3]) };
    // One fixed per-thread ledger. Allocator callbacks never allocate or assert.
    static PHYSICAL: Cell<Option<PhysicalSnapshot>> = const { Cell::new(None) };
}

struct TrackingAllocator;
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn record_request(route: usize) {
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        let _ = REQUESTS.try_with(|requests| {
            let mut counts = requests.get();
            counts[route] = counts[route].saturating_add(1);
            requests.set(counts);
        });
    }
}

// Allocation identity is observed at the existing test allocator, never by
// exposing a private BigInt backend or manufacturing a second Quantity graph.
const PHYSICAL_EVENTS: usize = 128;
#[derive(Clone, Copy)]
struct PhysicalEvent {
    route: usize,
    pointer: usize,
    size: usize,
    align: usize,
    retired: bool,
}
const EMPTY_EVENT: PhysicalEvent = PhysicalEvent {
    route: 0,
    pointer: 0,
    size: 0,
    align: 0,
    retired: false,
};

/// Fixed-capacity original allocation/lifetime observations on the current test thread.
#[derive(Clone, Copy)]
pub struct PhysicalSnapshot {
    events: [PhysicalEvent; PHYSICAL_EVENTS],
    count: usize,
    overflow: bool,
}
impl PhysicalSnapshot {
    const EMPTY: Self = Self {
        events: [EMPTY_EVENT; PHYSICAL_EVENTS],
        count: 0,
        overflow: false,
    };

    /// The exact number of `alloc`, `alloc_zeroed` and `realloc` entry points observed.
    pub(crate) fn requests(&self) -> [usize; 3] {
        assert!(!self.overflow, "physical allocation observation overflow");
        let mut counts = [0; 3];
        for event in &self.events[..self.count] {
            if event.route < 3 {
                counts[event.route] += 1;
            }
        }
        counts
    }

    /// The sole successful still-live native allocation with this original layout.
    pub(crate) fn single_live_pointer(&self, layout: Layout) -> Option<usize> {
        assert!(!self.overflow, "physical allocation observation overflow");
        let mut result = None;
        for event in &self.events[..self.count] {
            if event.route < 2
                && event.pointer != 0
                && event.size == layout.size()
                && event.align == layout.align()
                && self.retirements(event.pointer) == 0
            {
                if result.is_some() {
                    return None;
                }
                result = Some(event.pointer);
            }
        }
        result
    }

    /// Matching original-pointer deallocations or reallocations, without dereferencing it.
    pub(crate) fn retirements(&self, pointer: usize) -> usize {
        assert!(!self.overflow, "physical allocation observation overflow");
        self.events[..self.count]
            .iter()
            .filter(|event| event.retired && event.pointer == pointer)
            .count()
    }
}

/// Same-thread RAII observation; the fixed ledger owns no value or proof authority.
pub struct PhysicalObservation {
    ledger: &'static std::thread::LocalKey<Cell<Option<PhysicalSnapshot>>>,
    // Raw-pointer marker prevents moving this thread-local observation to another thread.
    _same_thread: PhantomData<*mut ()>,
}
impl PhysicalObservation {
    /// Start one nonnested observation, with no heap allocation.
    pub(crate) fn start() -> Self {
        assert!(
            PHYSICAL.with(Cell::get).is_none(),
            "nested physical allocation observation"
        );
        PHYSICAL.with(|state| state.set(Some(PhysicalSnapshot::EMPTY)));
        Self {
            ledger: &PHYSICAL,
            _same_thread: PhantomData,
        }
    }
    /// A stable position in this same original fixed ledger.
    pub(crate) fn checkpoint(&self) -> usize {
        self.snapshot().count
    }
    /// Copy the fixed observation ledger without heap allocation.
    pub(crate) fn snapshot(&self) -> PhysicalSnapshot {
        let snapshot = self
            .ledger
            .with(Cell::get)
            .expect("original physical observation active");
        assert!(
            !snapshot.overflow,
            "physical allocation observation overflow"
        );
        snapshot
    }
    /// Only original events since a previously captured position.
    pub(crate) fn since(&self, checkpoint: usize) -> PhysicalSnapshot {
        let snapshot = self.snapshot();
        assert!(checkpoint <= snapshot.count);
        let mut result = PhysicalSnapshot::EMPTY;
        result.count = snapshot.count - checkpoint;
        result.events[..result.count].copy_from_slice(&snapshot.events[checkpoint..snapshot.count]);
        result
    }
}
impl Drop for PhysicalObservation {
    fn drop(&mut self) {
        let _ = self.ledger.try_with(|state| state.set(None));
    }
}
fn record_physical(route: usize, pointer: *mut u8, layout: Layout, retired: bool) {
    let _ = PHYSICAL.try_with(|state| {
        if let Some(mut snapshot) = state.get() {
            if snapshot.count == PHYSICAL_EVENTS {
                snapshot.overflow = true;
            } else {
                snapshot.events[snapshot.count] = PhysicalEvent {
                    route,
                    pointer: pointer as usize,
                    size: layout.size(),
                    align: layout.align(),
                    retired,
                };
                snapshot.count += 1;
            }
            state.set(Some(snapshot));
        }
    });
}

// SAFETY: each route forwards the original pointer, layout and operation to System unchanged.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_request(0);
        // SAFETY: preserve the caller's original allocation contract.
        let pointer = unsafe { System.alloc(layout) };
        record_physical(0, pointer, layout, false);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_request(1);
        // SAFETY: preserve the caller's original zeroed allocation contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record_physical(1, pointer, layout, false);
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_request(2);
        // SAFETY: preserve the live System allocation and requested replacement size.
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        record_physical(2, pointer, layout, !replacement.is_null());
        replacement
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout belong to the original matching System allocation.
        record_physical(3, pointer, layout, true);
        unsafe { System.dealloc(pointer, layout) }
    }
}

/// Observe actual allocator requests on this thread without retaining a pointer ledger.
/// The caller prepares all input/oracle graphs first; a guard resets observation on unwind.
pub fn measured<T>(operation: impl FnOnce() -> T) -> (T, [usize; 3]) {
    struct StopTracking;
    impl Drop for StopTracking {
        fn drop(&mut self) {
            TRACKING.with(|tracking| tracking.set(false));
        }
    }
    assert!(!TRACKING.with(Cell::get), "nested allocation observation");
    REQUESTS.with(|requests| requests.set([0; 3]));
    TRACKING.with(|tracking| tracking.set(true));
    let stop = StopTracking;
    let result = operation();
    drop(stop);
    (result, REQUESTS.with(Cell::get))
}

// Thread infrastructure and the parent-owned input/oracle precede observation.
fn measured_fresh_thread<T: Send>(operation: impl FnOnce() -> T + Send) -> (T, [usize; 3]) {
    std::thread::scope(|scope| {
        scope
            .spawn(|| measured(operation))
            .join()
            .expect("fresh allocation-observer worker panicked")
    })
}

fn transaction(count: usize, bytes: usize) -> AmxTransactionV1 {
    AmxTransactionV1 {
        legs: (1..=count)
            .map(|id| AmxLegV1 {
                dataspace: DataSpaceId::new(u64::try_from(id).unwrap()),
                payload: vec![0xAC; bytes],
            })
            .collect(),
        deadline: 50,
        nonce: [9; 32],
    }
}

// Deliberately retain the original allocating canonical-frame oracle outside observation.
fn reference(transaction: &AmxTransactionV1) -> ([u8; 32], Vec<u8>) {
    let bytes = norito::encode_canonical(transaction).unwrap();
    let id = Hash::new_from_chunks(&[AMX_TRANSACTION_DOMAIN, &bytes]).into();
    (id, bytes)
}

fn original_begin(transaction: &AmxTransactionV1, tx: [u8; 32]) -> AmxBeginV1 {
    AmxBeginV1 {
        tx,
        participants: transaction.legs.iter().map(|leg| leg.dataspace).collect(),
        deadline: transaction.deadline,
    }
}

fn graph_pointers(transaction: &AmxTransactionV1) -> (usize, [usize; MAX_AMX_PARTICIPANTS]) {
    (
        transaction.legs.as_ptr() as usize,
        std::array::from_fn(|index| {
            transaction
                .legs
                .get(index)
                .map_or(0, |leg| leg.payload.as_ptr() as usize)
        }),
    )
}

#[test]
fn physical_observer_tracks_original_layout_and_retirement_without_allocating() {
    let observation = PhysicalObservation::start();
    let before = observation.checkpoint();
    let layout = Layout::from_size_align(19, 8).unwrap();
    // SAFETY: test owns the original successful allocation and frees it with its exact layout.
    let pointer = unsafe { std::alloc::alloc(layout) };
    assert!(!pointer.is_null());
    let original = observation
        .since(before)
        .single_live_pointer(layout)
        .unwrap();
    assert_eq!(original, pointer as usize);
    assert_eq!(observation.since(before).requests(), [1, 0, 0]);
    assert_eq!(observation.snapshot().retirements(original), 0);
    // SAFETY: this is the same still-live original allocation and layout.
    unsafe { std::alloc::dealloc(pointer, layout) };
    assert_eq!(observation.snapshot().retirements(original), 1);
    assert!(observation.snapshot().single_live_pointer(layout).is_none());
    let before = observation.checkpoint();
    // SAFETY: preserve the original zeroed allocation across successful realloc;
    // on failure the original remains live and is freed with its original layout.
    unsafe {
        let zero = std::alloc::alloc_zeroed(layout);
        assert!(!zero.is_null());
        let grown = std::alloc::realloc(zero, layout, 31);
        if grown.is_null() {
            std::alloc::dealloc(zero, layout);
            panic!("allocator refused physical observer self-control");
        }
        assert_eq!(observation.since(before).requests(), [0, 1, 1]);
        assert_eq!(observation.since(before).retirements(zero as usize), 1);
        std::alloc::dealloc(grown, Layout::from_size_align(31, 8).unwrap());
    }
    let before_original = observation.checkpoint();
    let original = vec![7_u8; 23];
    let original_pointer = original.as_ptr() as usize;
    let before_clone = observation.checkpoint();
    let cloned = original.clone();
    let cloned_pointer = cloned.as_ptr() as usize;
    assert_ne!(cloned_pointer, original_pointer);
    assert_eq!(observation.since(before_clone).requests(), [1, 0, 0]);
    assert_eq!(
        observation
            .since(before_original)
            .retirements(original_pointer),
        0
    );
    drop(cloned);
    assert_eq!(
        observation.since(before_clone).retirements(cloned_pointer),
        1
    );
    assert_eq!(
        observation
            .since(before_original)
            .retirements(original_pointer),
        0
    );
    drop(original);
    assert_eq!(
        observation
            .since(before_original)
            .retirements(original_pointer),
        1
    );
    drop(observation);
    let panic = std::panic::catch_unwind(|| {
        let _observation = PhysicalObservation::start();
        panic!("physical observer unwind");
    });
    assert!(panic.is_err());
    assert!(PHYSICAL.with(Cell::get).is_none());
}

#[test]
fn observer_counts_all_three_allocation_routes_and_resets_after_unwind() {
    let ((), count) = measured(|| {
        // SAFETY: every successful original allocation is freed with its exact final layout.
        // A failed realloc keeps the original pointer alive and frees it before refusing.
        unsafe {
            let layout = Layout::from_size_align(16, 8).unwrap();
            let pointer = std::alloc::alloc(layout);
            assert!(!pointer.is_null());
            black_box(pointer);
            let grown = std::alloc::realloc(pointer, layout, 32);
            if grown.is_null() {
                std::alloc::dealloc(pointer, layout);
                panic!("allocator refused observer self-test");
            }
            black_box(grown);
            std::alloc::dealloc(grown, Layout::from_size_align(32, 8).unwrap());
            let zero = std::alloc::alloc_zeroed(layout);
            assert!(!zero.is_null());
            assert_eq!(*zero, 0);
            black_box(zero);
            std::alloc::dealloc(zero, layout);
        }
    });
    assert_eq!(count, [1, 1, 1]);
    let panic = std::panic::catch_unwind(|| measured(|| panic!("allocation observer unwind")));
    assert!(panic.is_err());
    assert!(!TRACKING.with(Cell::get));
    assert_eq!(measured(|| black_box(7)).1, [0; 3]);
}

#[test]
fn transaction_id_streaming_matches_canonical_frames_without_heap_allocations() {
    assert!(
        !norito::debug_trace_enabled(),
        "opt-in codec diagnostics are separate coverage"
    );
    for count in [MIN_AMX_PARTICIPANTS, MAX_AMX_PARTICIPANTS] {
        for bytes in [0, 1, MAX_AMX_LEG_BYTES] {
            let transaction = transaction(count, bytes);
            let (expected, original_frame) = reference(&transaction);
            let pointers = graph_pointers(&transaction);
            for alternate_flags in [false, true] {
                let (actual, requests) = measured_fresh_thread(|| {
                    let _layout = alternate_flags.then(|| {
                        norito::core::DecodeFlagsGuard::enter(
                            norito::core::default_encode_flags()
                                ^ norito::core::header_flags::COMPACT_LEN,
                        )
                    });
                    black_box(&transaction).id()
                });
                assert_eq!(
                    requests, [0; 3],
                    "the complete canonical id may retain no heap scratch"
                );
                assert_eq!(actual.unwrap(), expected);
                assert_eq!(graph_pointers(&transaction), pointers);
            }
            assert!(norito::encode_canonical(&transaction).unwrap() == original_frame);
        }
    }
}

#[test]
fn begin_matches_borrows_original_graph_without_heap_allocations() {
    assert!(
        !norito::debug_trace_enabled(),
        "opt-in codec diagnostics are separate coverage"
    );
    for count in [MIN_AMX_PARTICIPANTS, MAX_AMX_PARTICIPANTS] {
        for bytes in [0, 1, MAX_AMX_LEG_BYTES] {
            let transaction = transaction(count, bytes);
            let (expected, original_frame) = reference(&transaction);
            let begin = original_begin(&transaction, expected);
            let pointers = graph_pointers(&transaction);
            let participants = begin.participants.as_ptr();
            let (matched, requests) =
                measured_fresh_thread(|| black_box(&begin).matches(black_box(&transaction)));
            assert!(matched);
            assert_eq!(
                requests, [0; 3],
                "matching may not reconstruct an encoded id or Begin Vec"
            );
            assert_eq!(begin.tx, expected);
            assert_eq!(begin.deadline, transaction.deadline);
            assert_eq!(graph_pointers(&transaction), pointers);
            assert_eq!(begin.participants.as_ptr(), participants);
            assert!(norito::encode_canonical(&transaction).unwrap() == original_frame);
        }
    }
}

#[test]
fn malformed_transactions_and_substituted_begins_refuse_without_heap_allocations() {
    let transaction = transaction(MIN_AMX_PARTICIPANTS, 1);
    let (expected, original_frame) = reference(&transaction);
    let begin = original_begin(&transaction, expected);
    let pointers = graph_pointers(&transaction);
    let participants = begin.participants.as_ptr();
    for altered in [
        AmxBeginV1 {
            tx: [0; 32],
            ..begin.clone()
        },
        AmxBeginV1 {
            deadline: 51,
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![DataSpaceId::new(1), DataSpaceId::new(3)],
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![DataSpaceId::new(2), DataSpaceId::new(1)],
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![DataSpaceId::new(1)],
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![
                DataSpaceId::new(1),
                DataSpaceId::new(2),
                DataSpaceId::new(3),
            ],
            ..begin.clone()
        },
    ] {
        let (matched, requests) =
            measured_fresh_thread(|| altered.matches(black_box(&transaction)));
        assert!(!matched);
        assert_eq!(requests, [0; 3]);
    }
    let mut duplicate = transaction.clone();
    duplicate.legs[1].dataspace = duplicate.legs[0].dataspace;
    let mut descending = transaction.clone();
    descending.legs.reverse();
    let mut zero_deadline = transaction.clone();
    zero_deadline.deadline = 0;
    let malformed = [
        (transaction_with_count(1), "participant count out of range"),
        (
            transaction_with_count(MAX_AMX_PARTICIPANTS + 1),
            "participant count out of range",
        ),
        (
            duplicate,
            "legs are not in strictly increasing dataspace order",
        ),
        (
            descending,
            "legs are not in strictly increasing dataspace order",
        ),
        (zero_deadline, "deadline must be a positive height"),
        (oversized_transaction(), "leg payload exceeds its bound"),
    ];
    for (malformed, reason) in malformed {
        let ((id, matched), requests) = measured_fresh_thread(|| {
            (
                black_box(&malformed).id(),
                begin.matches(black_box(&malformed)),
            )
        });
        assert_eq!(id, Err(AmxError::Transaction(reason)));
        assert!(!matched);
        assert_eq!(requests, [0; 3]);
    }
    assert_eq!(graph_pointers(&transaction), pointers);
    assert_eq!(begin.participants.as_ptr(), participants);
    assert!(norito::encode_canonical(&transaction).unwrap() == original_frame);
}

fn transaction_with_count(count: usize) -> AmxTransactionV1 {
    transaction(count, 1)
}

fn oversized_transaction() -> AmxTransactionV1 {
    transaction(MIN_AMX_PARTICIPANTS, MAX_AMX_LEG_BYTES + 1)
}

fn monetary_account(seed: u8, members: usize) -> iroha_data_model::account::AccountId {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};
    let key = |index: usize| {
        let mut bytes = [seed; 32];
        bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
        KeyPair::from_seed(bytes.to_vec(), Algorithm::Ed25519)
            .public_key()
            .clone()
    };
    if members == 0 {
        AccountId::new(key(0))
    } else {
        AccountId::new_multisig(
            MultisigPolicy::new(
                u16::try_from(members).unwrap(),
                (0..members)
                    .map(|index| MultisigMember::new(key(index), 1).unwrap())
                    .collect(),
            )
            .unwrap(),
        )
    }
}

// Observe every retained compact-key backing and the member Vec without copying either.
fn monetary_account_pointers(
    account: &iroha_data_model::account::AccountId,
) -> (usize, [usize; 64]) {
    use iroha_data_model::account::AccountController;
    match account.controller() {
        AccountController::Single(key) => (
            0,
            std::array::from_fn(|index| {
                if index == 0 {
                    key.try_to_bytes().unwrap().1.as_ptr() as usize
                } else {
                    0
                }
            }),
        ),
        AccountController::Multisig(policy) => {
            assert!(policy.members().len() <= 64);
            (
                policy.members().as_ptr() as usize,
                std::array::from_fn(|index| {
                    policy.members().get(index).map_or(0, |member| {
                        member.public_key().try_to_bytes().unwrap().1.as_ptr() as usize
                    })
                }),
            )
        }
    }
}

fn monetary_reference(
    leg: &iroha_data_model::sumeragi_amx::AmxTransferLegV1,
) -> ([u8; 32], Vec<u8>) {
    let frame = norito::encode_canonical(leg).unwrap();
    let hash = Hash::new_from_chunks(&[b"iroha:native-amx-transfer:v1", &[0], &frame]).into();
    (hash, frame)
}

#[test]
fn native_transfer_effects_stream_exact_monetary_fields_without_heap_allocations() {
    use iroha_data_model::{
        asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
        sumeragi_amx::{AmxTransferLegV1, native_transfer_effects_hash},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::{
        bigint::BigInt,
        numeric::{Numeric, Quantity},
    };
    assert!(
        !norito::debug_trace_enabled(),
        "opt-in codec diagnostics are separate coverage"
    );
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("native", "effects").unwrap(),
        "currency".parse().unwrap(),
    );
    let other_definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("native", "effects").unwrap(),
        "other".parse().unwrap(),
    );
    let mut largest = [0xff; 64];
    largest[63] = 0x7f;
    let wide = Quantity::from_canonical_numeric(
        Numeric::try_new(BigInt::from_twos_bytes(&largest).unwrap(), 28).unwrap(),
    )
    .unwrap();
    assert_eq!(wide.mantissa().bit_len(), 511);
    assert_eq!(wide.scale(), 28);
    for (source_members, destination_members) in [(0, 0), (1, 64), (64, 1)] {
        for amount in [Quantity::zero(), u128::MAX.into(), wide.clone()] {
            let leg = AmxTransferLegV1 {
                source: AssetId::with_scope(
                    definition.clone(),
                    monetary_account(1, source_members),
                    AssetBalanceScope::Dataspace(DataSpaceId::new(u64::MAX)),
                ),
                destination: monetary_account(2, destination_members),
                amount,
            };
            let (expected, frame) = monetary_reference(&leg);
            assert!(frame.len() <= MAX_AMX_LEG_BYTES);
            let source = monetary_account_pointers(leg.source.account());
            let destination = monetary_account_pointers(&leg.destination);
            let amount = std::ptr::from_ref(leg.amount.mantissa());
            for alternate_flags in [false, true] {
                let (actual, requests) = measured_fresh_thread(|| {
                    let _layout = alternate_flags.then(|| {
                        norito::core::DecodeFlagsGuard::enter(
                            norito::core::default_encode_flags()
                                ^ norito::core::header_flags::COMPACT_LEN,
                        )
                    });
                    native_transfer_effects_hash(black_box(&leg))
                });
                assert_eq!(
                    requests, [0; 3],
                    "effects hashing must not allocate a frame or nested serializer scratch"
                );
                assert_eq!(actual.unwrap(), expected);
                assert_eq!(monetary_account_pointers(leg.source.account()), source);
                assert_eq!(monetary_account_pointers(&leg.destination), destination);
                assert_eq!(std::ptr::from_ref(leg.amount.mantissa()), amount);
            }
            assert!(norito::encode_canonical(&leg).unwrap() == frame);
            // Every substitution and its independent oracle are prepared before observation.
            let mut substitutions = [
                leg.clone(),
                leg.clone(),
                leg.clone(),
                leg.clone(),
                leg.clone(),
            ];
            substitutions[0].source = AssetId::with_scope(
                definition.clone(),
                leg.source.account().clone(),
                AssetBalanceScope::Global,
            );
            substitutions[1].source = AssetId::with_scope(
                other_definition.clone(),
                leg.source.account().clone(),
                *leg.source.scope(),
            );
            substitutions[2].source = AssetId::with_scope(
                definition.clone(),
                monetary_account(3, source_members),
                *leg.source.scope(),
            );
            substitutions[3].destination = monetary_account(4, destination_members);
            substitutions[4].amount = if leg.amount.is_zero() {
                Quantity::one()
            } else {
                Quantity::zero()
            };
            for changed in substitutions {
                let (changed_hash, changed_frame) = monetary_reference(&changed);
                assert_ne!(changed_hash, expected);
                let (actual, requests) =
                    measured_fresh_thread(|| native_transfer_effects_hash(black_box(&changed)));
                assert_eq!(actual.unwrap(), changed_hash);
                assert_eq!(requests, [0; 3]);
                assert!(norito::encode_canonical(&changed).unwrap() == changed_frame);
            }
        }
    }
}
