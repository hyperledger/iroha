//! Allocation and wire-parity checks for exact-length nested serialization.
use norito::core::{
    DecodeFlagsGuard, Encoder, Error, NoritoSerialize, SerializePayload, header_flags,
    serialize_to_buffer,
};
use norito::{decode_canonical, encode_canonical, verify_exact_frame};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    collections::BTreeMap,
};
#[path = "fixed_frame.rs"]
mod fixed_frame;
struct TrackingAllocator;
thread_local! {
    static REFUSE_SIZE: Cell<usize> = const { Cell::new(0) };
    static MATCHES_BEFORE_REFUSAL: Cell<usize> = const { Cell::new(usize::MAX) };
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REQUESTED_ALLOCATION_BYTES: Cell<usize> = const { Cell::new(0) };
    static LARGE_ALLOCATION_THRESHOLD: Cell<usize> = const { Cell::new(usize::MAX) };
    static LARGE_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSE_SIZE.with(|size| size.get() == layout.size())
            && MATCHES_BEFORE_REFUSAL.with(|remaining| {
                let current = remaining.get();
                if current == 0 {
                    true
                } else {
                    remaining.set(current - 1);
                    false
                }
            })
        {
            return core::ptr::null_mut();
        }
        TRACKING.with(|tracking| {
            if tracking.get() {
                ALLOCATIONS.with(|allocations| allocations.set(allocations.get() + 1));
                REQUESTED_ALLOCATION_BYTES
                    .with(|bytes| bytes.set(bytes.get().saturating_add(layout.size())));
                LARGE_ALLOCATION_THRESHOLD.with(|threshold| {
                    if layout.size() >= threshold.get() {
                        LARGE_ALLOCATIONS
                            .with(|allocations| allocations.set(allocations.get() + 1));
                    }
                });
            }
        });
        // SAFETY: this allocator delegates the request unchanged to System.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        TRACKING.with(|tracking| {
            if tracking.get() {
                ALLOCATIONS.with(|allocations| allocations.set(allocations.get() + 1));
                REQUESTED_ALLOCATION_BYTES
                    .with(|bytes| bytes.set(bytes.get().saturating_add(layout.size())));
            }
        });
        // SAFETY: the original zeroed request is delegated unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` came from the matching System allocation.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        TRACKING.with(|tracking| {
            if tracking.get() {
                ALLOCATIONS.with(|allocations| allocations.set(allocations.get() + 1));
                REQUESTED_ALLOCATION_BYTES
                    .with(|bytes| bytes.set(bytes.get().saturating_add(new_size)));
                LARGE_ALLOCATION_THRESHOLD.with(|threshold| {
                    if new_size >= threshold.get() {
                        LARGE_ALLOCATIONS
                            .with(|allocations| allocations.set(allocations.get() + 1));
                    }
                });
            }
        });
        // SAFETY: `ptr` and `layout` came from System and `new_size` is forwarded.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
fn allocations_during(operation: impl FnOnce()) -> usize {
    TRACKING.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    operation();
    TRACKING.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(Cell::get)
}
fn large_allocations_during(threshold: usize, operation: impl FnOnce()) -> usize {
    TRACKING.with(|tracking| tracking.set(false));
    LARGE_ALLOCATION_THRESHOLD.with(|current| current.set(threshold));
    LARGE_ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    operation();
    TRACKING.with(|tracking| tracking.set(false));
    LARGE_ALLOCATION_THRESHOLD.with(|current| current.set(usize::MAX));
    LARGE_ALLOCATIONS.with(Cell::get)
}
struct ExactBlob(Vec<u8>);

impl SerializePayload for ExactBlob {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        SerializePayload::serialize(&self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        SerializePayload::encoded_len_hint(&self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        SerializePayload::encoded_len_exact(&self.0)
    }
}
struct UnknownBlob(Vec<u8>);

impl SerializePayload for UnknownBlob {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        SerializePayload::serialize(&self.0, writer)
    }
}
#[derive(NoritoSerialize)]
struct ExactInner {
    payload: ExactBlob,
}
#[derive(NoritoSerialize)]
struct UnknownInner {
    payload: UnknownBlob,
}
#[derive(NoritoSerialize)]
struct ExactOuter {
    inner: ExactInner,
}
#[derive(NoritoSerialize)]
struct UnknownOuter {
    inner: UnknownInner,
}
#[derive(NoritoSerialize)]
enum ExactEnum {
    Payload(ExactBlob),
}
#[derive(NoritoSerialize)]
enum UnknownEnum {
    Payload(UnknownBlob),
}
fn bare_bytes(value: &dyn SerializePayload, flags: u8) -> Vec<u8> {
    let _guard = DecodeFlagsGuard::enter(flags);
    let mut bytes = Vec::new();
    serialize_to_buffer(value, &mut bytes).expect("serialize test value");
    bytes
}
#[test]
fn exact_and_unknown_field_paths_have_identical_wire_bytes() {
    let flags = [0, header_flags::COMPACT_LEN];
    for flags in flags {
        assert_eq!(
            bare_bytes(
                &ExactOuter {
                    inner: ExactInner {
                        payload: ExactBlob(vec![0xA5; 1_025]),
                    },
                },
                flags,
            ),
            bare_bytes(
                &UnknownOuter {
                    inner: UnknownInner {
                        payload: UnknownBlob(vec![0xA5; 1_025]),
                    },
                },
                flags,
            ),
            "struct wire changed for flags {flags:#04x}",
        );
        assert_eq!(
            bare_bytes(&ExactEnum::Payload(ExactBlob(vec![0x5A; 1_025])), flags),
            bare_bytes(&UnknownEnum::Payload(UnknownBlob(vec![0x5A; 1_025])), flags,),
            "enum wire changed for flags {flags:#04x}",
        );
    }
}
#[test]
fn large_exact_nested_box_streams_without_temporary_allocation() {
    let flags = header_flags::COMPACT_LEN;
    let value = Box::new(ExactOuter {
        inner: ExactInner {
            payload: ExactBlob(vec![0xC3; 1024 * 1024]),
        },
    });
    let _guard = DecodeFlagsGuard::enter(flags);
    let exact_len = SerializePayload::encoded_len_exact(&value).expect("exact boxed length");
    let mut output = Vec::with_capacity(exact_len);
    // Initialize thread-local state and the serializer before measuring.
    let mut warm = Vec::with_capacity(exact_len);
    serialize_to_buffer(&value, &mut warm).expect("warm exact serialization");
    drop(warm);
    let allocations = allocations_during(|| {
        assert_eq!(SerializePayload::encoded_len_exact(&value), Some(exact_len));
        serialize_to_buffer(&value, &mut output).expect("stream exact boxed value");
    });
    assert_eq!(output.len(), exact_len);
    assert_eq!(allocations, 0, "exact nested serialization allocated");
}
#[test]
fn canonical_decode_does_not_allocate_a_second_frame_sized_buffer() {
    const PAYLOAD_BYTES: usize = 1024 * 1024;
    let value = vec![0xA5_u8; PAYLOAD_BYTES];
    let frame = encode_canonical(&value).expect("encode canonical allocation fixture");
    let mut decoded = None;
    // Initialize this test's allocator bookkeeping before measuring. The one
    // admitted large allocation is the decoded `Vec<u8>` itself; canonical
    // verification must compare directly against `frame` rather than allocate
    // another frame-sized vector.
    let _ = large_allocations_during(usize::MAX, || {});
    let large_allocations = large_allocations_during(PAYLOAD_BYTES / 2, || {
        decoded =
            Some(decode_canonical::<Vec<u8>>(&frame).expect("decode canonical allocation fixture"));
    });
    assert_eq!(decoded.as_deref(), Some(value.as_slice()));
    assert_eq!(
        large_allocations, 1,
        "canonical verification allocated another frame-sized buffer"
    );
}
#[test]
fn exact_frame_verification_does_not_allocate_an_output_sized_buffer() {
    const PAYLOAD_BYTES: usize = 1024 * 1024;
    let value = vec![0x5A_u8; PAYLOAD_BYTES];
    let frame = norito::core::to_bytes(&value).expect("encode exact-frame allocation fixture");
    let _ = large_allocations_during(usize::MAX, || {});
    let large_allocations = large_allocations_during(PAYLOAD_BYTES / 2, || {
        verify_exact_frame(&value, &frame).expect("verify exact allocation fixture");
    });
    assert_eq!(
        large_allocations, 0,
        "exact-frame verification allocated an output-sized buffer"
    );
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(align(64))]
struct AlignedBtreeValue([u64; 8]);

fn assert_btree_allocation_census<K: Ord, V>(make: impl Fn(usize) -> (K, V)) {
    for entries in [0, 1, 2, 5, 6, 10, 11, 12, 13, 31, 64, 256] {
        for order in 0..3 {
            let mut map = BTreeMap::new();
            REQUESTED_ALLOCATION_BYTES.with(|bytes| bytes.set(0));
            let requests = allocations_during(|| {
                for ordinal in 0..entries {
                    let index = match order {
                        0 => ordinal,
                        1 => entries - 1 - ordinal,
                        _ => (ordinal * 257) % entries,
                    };
                    let (key, value) = make(index);
                    assert!(map.insert(key, value).is_none());
                }
            });
            let requested = REQUESTED_ALLOCATION_BYTES.with(Cell::get);
            assert_eq!(map.len(), entries);
            if entries <= 11 {
                assert_eq!(
                    requests,
                    usize::from(entries != 0),
                    "one actual root leaf through eleven entries"
                );
            } else {
                assert!(
                    requests >= 3,
                    "the twelfth distinct key splits the leaf and creates an internal root"
                );
            }
            let bound = norito::core::owned_btree_allocation_bytes::<K, V>(entries).unwrap();
            assert!(
                requested <= bound,
                "entries={entries} order={order} actual={requested} bound={bound}"
            );
        }
    }
}

#[test]
fn btree_owner_charge_covers_physical_leaf_and_split_requests() {
    assert_btree_allocation_census(|index| {
        (u16::try_from(index).unwrap(), u32::try_from(index).unwrap())
    });
    // Match the metadata node's two-word Name and one-word Json owners.
    assert_btree_allocation_census(|index| ([index as u64, 0], index));
    // Exercise padding independently of pointer alignment and field order.
    assert_btree_allocation_census(|index| {
        (
            AlignedBtreeValue([index as u64; 8]),
            AlignedBtreeValue([0; 8]),
        )
    });
}

#[cfg(feature = "json")]
#[test]
fn json_value_parser_charge_covers_physical_graph_requests_at_leaf_and_split_boundaries() {
    use norito::json::{JsonPreflightLimits, Value};
    let limits = norito::DecodeLimits::new(
        1 << 20,
        1 << 20,
        1 << 20,
        1 << 20,
        norito::core::MAX_VALUE_NESTING_DEPTH,
    );
    // Warm both allocator and decoder bookkeeping before observing any original graph.
    let _ = allocations_during(|| {});
    norito::core::with_decode_limits_measured(limits, || norito::json::from_slice::<Value>(b"{}"))
        .0
        .unwrap();
    for entries in [0, 1, 2, 5, 6, 10, 11, 12, 13, 31, 64, 256] {
        for order in 0..3 {
            let fields = (0..entries)
                .map(|ordinal| {
                    let index = match order {
                        0 => ordinal,
                        1 => entries - 1 - ordinal,
                        _ => (ordinal * 257) % entries,
                    };
                    format!("\"k{index}\":0")
                })
                .collect::<Vec<_>>()
                .join(",");
            let body = format!("{{\"full\":{{{fields}}},\"empty\":{{}},\"items\":[\"a\\nb\",0]}}");
            let profile = norito::json::preflight_slice(
                body.as_bytes(),
                JsonPreflightLimits::from_decode_limits(body.len(), limits),
            )
            .unwrap();
            let nodes = norito::core::owned_btree_allocation_bytes::<String, Value>(entries)
                .unwrap()
                + norito::core::owned_btree_allocation_bytes::<String, Value>(3).unwrap();
            assert_eq!(profile.object_btree_allocation_bytes(), nodes);
            let graph = nodes
                + profile.string_capacity_bytes()
                + profile.array_entries() * core::mem::size_of::<Value>();
            let mut physical = 0;
            let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
                // Scope construction belongs to the measuring harness. Begin tracking only after
                // its budget is active, retaining every original payload and parser-frame request.
                let mut decoded = None;
                REQUESTED_ALLOCATION_BYTES.with(|bytes| bytes.set(0));
                allocations_during(|| {
                    decoded = Some(norito::json::from_slice::<Value>(body.as_bytes()));
                });
                physical = REQUESTED_ALLOCATION_BYTES.with(Cell::get);
                decoded.unwrap()
            });
            value.unwrap();
            assert!(
                usage.total_allocated_bytes() >= graph,
                "entries={entries} order={order} graph={graph} measured={}",
                usage.total_allocated_bytes()
            );
            assert!(
                physical <= usage.total_allocated_bytes(),
                "entries={entries} order={order} physical={physical} measured={}",
                usage.total_allocated_bytes()
            );
        }
    }
}
#[path = "exact_field_streaming_allocations/nominal_text.rs"]
mod nominal_text;

#[path = "exact_field_streaming_allocations/prepared_scope.rs"]
mod prepared_scope;

#[path = "exact_field_streaming_allocations/field_destination.rs"]
mod field_destination;

#[path = "exact_field_streaming_allocations/budget_context.rs"]
mod budget_context;

#[path = "exact_field_streaming_allocations/decode_local_refusal.rs"]
mod decode_local_refusal;

#[path = "exact_field_streaming_allocations/prepared_sequence.rs"]
mod prepared_sequence;

#[path = "exact_field_streaming_allocations/prepared_option.rs"]
mod prepared_option;

#[path = "exact_field_streaming_allocations/prepared_string.rs"]
mod prepared_string;
