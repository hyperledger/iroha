//! Canonical numeric payload parity and an isolated census of temporary allocation requests.
// The allocator hook belongs only to this registered integration test process.
#![allow(unsafe_code)]

use iroha_allocation::{AllocationBudget, ChargedBufferError};
use iroha_primitives::{
    bigint::BigInt,
    numeric::{
        MAX_DECIMAL_SCALE, MAX_MANTISSA_BYTES, Numeric, PreparedQuantityDecode, Quantity,
        QuantityDecodeAdmissionError,
    },
    numeric_abi::{
        DecimalValueV1, IntValueV1, NumericAbiError, PreparedNumericFrameV1, QuantityValueV1,
    },
};
use norito::{
    SerializePayload,
    core::{DecodeFlagsGuard, DecodeFromSlice, Encoder, header_flags},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Requests {
    active: bool,
    alloc: usize,
    zeroed: usize,
    realloc: usize,
}
thread_local! {
    static REFUSED_SIZE: Cell<Option<usize>> = const { Cell::new(None) };
    static DEALLOCATIONS: Cell<(Option<usize>, usize)> = const { Cell::new((None, 0)) };
    static REQUESTS: Cell<Requests> = const { Cell::new(Requests {
        active: false, alloc: 0, zeroed: 0, realloc: 0,
    }) };
}
fn request(kind: u8) {
    let _ = REQUESTS.try_with(|cell| {
        let mut value = cell.get();
        if value.active {
            match kind {
                0 => value.alloc += 1,
                1 => value.zeroed += 1,
                2 => value.realloc += 1,
                _ => unreachable!(),
            }
            cell.set(value);
        }
    });
}
struct TrackingAllocator;
// SAFETY: requests are recorded before delegating unchanged to System. No
// observation callback allocates; each deallocation uses its original layout.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        request(0);
        if REFUSED_SIZE.try_with(Cell::get).unwrap_or(None) == Some(layout.size()) {
            return core::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        request(1);
        if REFUSED_SIZE.try_with(Cell::get).unwrap_or(None) == Some(layout.size()) {
            return core::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        request(2);
        if REFUSED_SIZE.try_with(Cell::get).unwrap_or(None) == Some(size) {
            return core::ptr::null_mut();
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
        let _ = DEALLOCATIONS.try_with(|cell| {
            let (size, count) = cell.get();
            if size == Some(layout.size()) {
                cell.set((size, count + 1));
            }
        });
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
struct Stop;
impl Drop for Stop {
    fn drop(&mut self) {
        REQUESTS.with(|cell| {
            let mut value = cell.get();
            value.active = false;
            cell.set(value);
        });
    }
}
fn measured<T>(operation: impl FnOnce() -> T) -> (T, Requests) {
    REQUESTS.with(|cell| {
        assert!(!cell.get().active, "allocation observations cannot nest");
        cell.set(Requests {
            active: true,
            ..Requests::default()
        });
    });
    let stop = Stop;
    let result = operation();
    drop(stop);
    (result, REQUESTS.with(Cell::get))
}
fn literal_body(bytes: &[u8], scale: Option<u8>) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + bytes.len() + usize::from(scale.is_some()));
    body.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
    body.extend_from_slice(bytes);
    if let Some(scale) = scale {
        body.push(scale);
    }
    body
}
fn assert_body_without_requests(value: &dyn SerializePayload, expected: &[u8]) {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        // Input owners, expected literal bytes, TLS and the original writer are
        // constructed outside the measurement. First and repeated payload
        // serialization/exact-length queries are both observed.
        for _ in 0..2 {
            let mut bytes = [0xa5; 69];
            let ((length, unused, result), requests) = measured(|| {
                let length = value.encoded_len_exact();
                let mut output = bytes.as_mut_slice();
                let result = value.serialize(&mut Encoder::new(&mut output));
                (length, output.len(), result)
            });
            result.unwrap();
            let used = bytes.len() - unused;
            assert_eq!(length, Some(expected.len()));
            assert_eq!(&bytes[..used], expected);
            assert!(bytes[used..].iter().all(|byte| *byte == 0xa5));
            assert_eq!(
                requests,
                Requests::default(),
                "numeric body allocated scratch"
            );
        }
    }
}
fn assert_prepared_without_digit_requests<'value>(
    prepare: impl Fn() -> PreparedNumericFrameV1<'value>,
    literal_frame: &[u8],
) {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for _ in 0..2 {
            let ((prepared, first_len, repeated_len), requests) = measured(|| {
                let prepared = prepare();
                let first_len = prepared.frame_len();
                let repeated_len = prepared.frame_len();
                (prepared, first_len, repeated_len)
            });
            assert_eq!(
                requests,
                Requests::default(),
                "borrowed preparation copied native digits"
            );
            assert_eq!(first_len, literal_frame.len());
            assert_eq!(repeated_len, literal_frame.len());
            let (frame, requests) = measured(|| prepared.encode_frame());
            let frame = frame.unwrap();
            // Count the existing nominal frame-name String and exact output Vec.
            // This is not a fully funded native frame/output custody claim.
            assert_eq!(
                requests,
                Requests {
                    active: false,
                    alloc: 2,
                    zeroed: 0,
                    realloc: 0
                }
            );
            assert_eq!(frame, literal_frame);
        }
    }
}
fn assert_integer(bytes: &[u8]) {
    let source = BigInt::from_twos_bytes(bytes).unwrap();
    let value = IntValueV1::try_new(source.clone()).unwrap();
    let expected = literal_body(bytes, None);
    assert_body_without_requests(&value, &expected);
    let frame = value.encode_frame().unwrap();
    assert_eq!(
        frame,
        norito::core::frame_bare_with_header_flags::<IntValueV1>(&expected, 0).unwrap(),
    );
    assert_eq!(IntValueV1::decode_frame(&frame), Ok(value.clone()));
    assert_eq!(
        value.as_int(),
        &source,
        "serialization mutated the original clone"
    );
    let literal_frame =
        norito::core::frame_bare_with_header_flags::<IntValueV1>(&expected, 0).unwrap();
    assert_prepared_without_digit_requests(
        || IntValueV1::prepare_frame(&source).unwrap(),
        &literal_frame,
    );
    assert_eq!(value.as_int(), &source);
}
fn assert_scaled(bytes: &[u8], scale: u8) {
    let source = BigInt::from_twos_bytes(bytes).unwrap();
    let numeric = Numeric::try_new(source.clone(), u32::from(scale)).unwrap();
    assert_eq!(numeric.mantissa(), &source);
    assert_eq!(numeric.scale(), u32::from(scale));
    let value = DecimalValueV1::new(numeric.clone());
    let expected = literal_body(bytes, Some(scale));
    assert_body_without_requests(&value, &expected);
    let frame = value.encode_frame().unwrap();
    assert_eq!(
        frame,
        norito::core::frame_bare_with_header_flags::<DecimalValueV1>(&expected, 0).unwrap(),
    );
    assert_eq!(DecimalValueV1::decode_frame(&frame), Ok(value.clone()));
    assert_eq!(value.as_numeric(), &numeric);
    let literal_frame =
        norito::core::frame_bare_with_header_flags::<DecimalValueV1>(&expected, 0).unwrap();
    assert_prepared_without_digit_requests(
        || DecimalValueV1::prepare_frame(&numeric),
        &literal_frame,
    );
    assert_eq!(value.as_numeric(), &numeric);
    if !source.is_negative() {
        let quantity = QuantityValueV1::new(Quantity::from_canonical_numeric(numeric).unwrap());
        assert_body_without_requests(&quantity, &expected);
        let frame = quantity.encode_frame().unwrap();
        assert_eq!(
            frame,
            norito::core::frame_bare_with_header_flags::<QuantityValueV1>(&expected, 0).unwrap(),
        );
        assert_eq!(QuantityValueV1::decode_frame(&frame), Ok(quantity.clone()));
        assert_eq!(quantity.as_quantity().mantissa(), &source);
        assert_eq!(quantity.as_quantity().scale(), u32::from(scale));
        let literal_frame =
            norito::core::frame_bare_with_header_flags::<QuantityValueV1>(&expected, 0).unwrap();
        assert_prepared_without_digit_requests(
            || QuantityValueV1::prepare_frame(quantity.as_quantity()),
            &literal_frame,
        );
        assert_eq!(quantity.as_quantity().mantissa(), &source);
        assert_eq!(quantity.as_quantity().scale(), u32::from(scale));
    }
}
fn assert_hook_positive_control() {
    let layout = Layout::array::<u8>(13).unwrap();
    let ((grown, zeroed), requests) = measured(|| {
        // SAFETY: both small original allocations and the nonzero resize are
        // owned below. These direct calls exercise all three request hooks,
        // including their pre-System request counts, after body measurements.
        unsafe {
            let first = std::alloc::alloc(layout);
            let zeroed = std::alloc::alloc_zeroed(layout);
            assert!(!first.is_null() && !zeroed.is_null());
            let grown = std::alloc::realloc(first, layout, 29);
            assert!(!grown.is_null());
            (std::hint::black_box(grown), std::hint::black_box(zeroed))
        }
    });
    assert_eq!(
        requests,
        Requests {
            active: false,
            alloc: 1,
            zeroed: 1,
            realloc: 1
        }
    );
    // SAFETY: pointers are the original System-owned outputs above and layouts
    // match their exact final allocations; neither pointer escapes this test.
    unsafe {
        assert!(
            std::slice::from_raw_parts(zeroed, 13)
                .iter()
                .all(|byte| *byte == 0)
        );
        std::alloc::dealloc(grown, Layout::array::<u8>(29).unwrap());
        std::alloc::dealloc(zeroed, layout);
    }
}
fn assert_prepared_neighbors_reject_without_requests() {
    let mut above = [0; MAX_MANTISSA_BYTES + 1];
    above[MAX_MANTISSA_BYTES - 1] = 0x80;
    let mut below = [0xff; MAX_MANTISSA_BYTES + 1];
    below[MAX_MANTISSA_BYTES - 1] = 0x7f;
    for bytes in [&above, &below] {
        let source = BigInt::from_twos_bytes(bytes).unwrap();
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            for _ in 0..2 {
                let (result, requests) = measured(|| IntValueV1::prepare_frame(&source));
                assert_eq!(requests, Requests::default());
                assert_eq!(result.err(), Some(NumericAbiError::MantissaOverflow));
            }
        }
    }
}
fn assert_native_clone_positive_control() {
    let source = BigInt::one();
    let (copy, requests) = measured(|| std::hint::black_box(source.clone()));
    assert_eq!(
        requests,
        Requests {
            active: false,
            alloc: 1,
            zeroed: 0,
            realloc: 0
        }
    );
    assert_eq!(copy, source);
}
#[test]
fn numeric_body_and_length_queries_allocate_no_temporary_storage() {
    assert_eq!(MAX_MANTISSA_BYTES, 64);
    assert_eq!(MAX_DECIMAL_SCALE, 28);
    for bytes in [
        &[][..],
        &[0x01],
        &[0xff],
        &[0x7f],
        &[0x80, 0x00],
        &[0x80],
        &[0x7f, 0xff],
    ] {
        assert_integer(bytes);
    }
    // Independent literal two's-complement controls pin every byte boundary,
    // including every logical limb boundary and the exact signed512 endpoints.
    for width in 1..=MAX_MANTISSA_BYTES {
        let mut maximum = vec![0xff; width];
        maximum[width - 1] = 0x7f;
        let mut minimum = vec![0; width];
        minimum[width - 1] = 0x80;
        assert_integer(&maximum);
        assert_integer(&minimum);
        if width < MAX_MANTISSA_BYTES {
            let mut successor = vec![0; width + 1];
            successor[width - 1] = 0x80;
            let mut predecessor = vec![0xff; width + 1];
            predecessor[width - 1] = 0x7f;
            assert_integer(&successor);
            assert_integer(&predecessor);
        }
    }
    let mut maximum = [0xff; MAX_MANTISSA_BYTES];
    maximum[MAX_MANTISSA_BYTES - 1] = 0x7f;
    let mut minimum = [0; MAX_MANTISSA_BYTES];
    minimum[MAX_MANTISSA_BYTES - 1] = 0x80;
    for scale in 0..=MAX_DECIMAL_SCALE {
        for bytes in [&[0x01][..], &[0xff], &maximum, &minimum] {
            assert_scaled(bytes, u8::try_from(scale).unwrap());
        }
    }
    assert_scaled(&[], 0);
    assert_prepared_neighbors_reject_without_requests();
    assert_native_clone_positive_control();
    assert_hook_positive_control();
}

fn with_refused_size<T>(bytes: usize, operation: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSED_SIZE.with(|cell| cell.set(None));
        }
    }
    assert!(REFUSED_SIZE.with(Cell::get).is_none());
    REFUSED_SIZE.with(|cell| cell.set(Some(bytes)));
    let reset = Reset;
    let value = operation();
    drop(reset);
    value
}
fn observed_deallocations() -> usize {
    DEALLOCATIONS.with(|cell| cell.get().1)
}
fn with_deallocations<T>(bytes: usize, operation: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DEALLOCATIONS.with(|cell| cell.set((None, cell.get().1)));
        }
    }
    assert!(DEALLOCATIONS.with(|cell| cell.get().0).is_none());
    DEALLOCATIONS.with(|cell| cell.set((Some(bytes), 0)));
    let reset = Reset;
    let value = operation();
    let count = observed_deallocations();
    drop(reset);
    (value, count)
}
fn quantity_payload(value: &Quantity) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut bytes))
        .unwrap();
    bytes
}

#[test]
fn one_pass_quantity_allocates_only_final_digits_and_preserves_allocator_refusal_order() {
    let mut maximum = [0xff; MAX_MANTISSA_BYTES];
    maximum[MAX_MANTISSA_BYTES - 1] = 0x7f;
    let maximum = Quantity::from_canonical_numeric(
        Numeric::try_new(BigInt::from_twos_bytes(&maximum).unwrap(), 0).unwrap(),
    )
    .unwrap();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for source in [
            Quantity::from(0_u32),
            Quantity::from(1_u32),
            maximum.clone(),
        ] {
            let bytes = quantity_payload(&source);
            let layout = source.admission_clone_layout().unwrap();
            let pool = AllocationBudget::new(layout.size());
            let limits =
                norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
            let context = norito::core::DecodeBudgetContext::new(limits);
            let (result, requests) = context
                .with(|| measured(|| PreparedQuantityDecode::try_decode_payload(&bytes, &pool)));
            let owner = result.unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(owner.get(), &source);
            assert!(owner.belongs_to(&pool));
            assert_eq!(
                requests,
                Requests {
                    active: false,
                    alloc: usize::from(layout.size() != 0),
                    zeroed: 0,
                    realloc: 0
                }
            );
            assert_eq!(pool.reserved_bytes(), layout.size());
            assert_eq!(
                context.consumed_allocated_bytes(),
                u64::try_from(layout.size()).unwrap()
            );
            drop(owner);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let source = Quantity::from(1_u32);
        let valid = quantity_payload(&source);
        let mut late = valid.clone();
        let end = late.len();
        late[end - core::mem::size_of::<u32>()..]
            .copy_from_slice(&(MAX_DECIMAL_SCALE + 1).to_le_bytes());
        let original = (late.as_ptr(), late.len());
        let layout = source.admission_clone_layout().unwrap();
        let pool = AllocationBudget::new(layout.size());
        let limits =
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
        let context = norito::core::DecodeBudgetContext::new(limits);
        let (failure, requests) = with_refused_size(layout.size(), || {
            context.with(|| measured(|| PreparedQuantityDecode::try_decode_payload(&late, &pool)))
        });
        assert_eq!(
            requests,
            Requests {
                active: false,
                alloc: 1,
                zeroed: 0,
                realloc: 0
            }
        );
        let failure = failure
            .err()
            .expect("genuine native-digit request must refuse");
        assert!(matches!(failure,
            QuantityDecodeAdmissionError::Allocation(ChargedBufferError::Allocator { requested_bytes })
            if requested_bytes == layout.size()
        ));
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(
            context.consumed_allocated_bytes(),
            u64::try_from(layout.size()).unwrap()
        );
        let (retry, requests) =
            context.with(|| measured(|| PreparedQuantityDecode::try_decode_payload(&valid, &pool)));
        let retry = retry.unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(retry.get(), &source);
        assert_eq!(
            requests,
            Requests {
                active: false,
                alloc: 1,
                zeroed: 0,
                realloc: 0
            }
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            u64::try_from(2 * layout.size()).unwrap()
        );
        drop(retry);
        let expected = Quantity::decode_from_slice(&late).unwrap_err();
        let (failure, freed) = with_deallocations(layout.size(), || {
            context.with(|| PreparedQuantityDecode::try_decode_payload(&late, &pool))
        });
        let failure = failure.err().expect("original late scale still refuses");
        let QuantityDecodeAdmissionError::Codec(actual) = failure else {
            panic!("original late scalar")
        };
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(freed, 1, "admitted digits are reclaimed on scalar refusal");
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "diagnostic String custody remains separate"
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            u64::try_from(3 * layout.size()).unwrap()
        );
        assert_eq!((late.as_ptr(), late.len()), original);
    }
    let unwind =
        std::panic::catch_unwind(|| with_refused_size(7, || panic!("refusal guard unwind")));
    assert!(unwind.is_err());
    assert!(REFUSED_SIZE.with(Cell::get).is_none());
    let unwind =
        std::panic::catch_unwind(|| with_deallocations(7, || panic!("deallocation guard unwind")));
    assert!(unwind.is_err());
    assert!(DEALLOCATIONS.with(|cell| cell.get().0).is_none());
    assert_hook_positive_control();
}

#[test]
fn one_pass_quantity_drop_deallocates_before_original_release_wake() {
    use iroha_allocation::release::ReleaseRegistration;
    use std::{
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };
    struct Check {
        pool: AllocationBudget,
    }
    impl Wake for Check {
        fn wake(self: Arc<Self>) {
            assert_eq!(
                observed_deallocations(),
                1,
                "native digits are gone before refund wake"
            );
            assert_eq!(
                self.pool.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
        }
    }
    let _flags = DecodeFlagsGuard::enter(0);
    let mut maximum = [0xff; MAX_MANTISSA_BYTES];
    maximum[MAX_MANTISSA_BYTES - 1] = 0x7f;
    let source = Quantity::from_canonical_numeric(
        Numeric::try_new(BigInt::from_twos_bytes(&maximum).unwrap(), 0).unwrap(),
    )
    .unwrap();
    let bytes = quantity_payload(&source);
    let layout = source.admission_clone_layout().unwrap();
    let registration_layout = ReleaseRegistration::allocation_layout();
    let pool = AllocationBudget::new(layout.size() + registration_layout.size());
    let mut prepaid = pool.try_reserve(registration_layout).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
    drop(prepaid);
    let owner = PreparedQuantityDecode::try_decode_payload(&bytes, &pool)
        .unwrap_or_else(|error| panic!("{error}"));
    let refusal = pool.try_reserve(layout).unwrap_err();
    let iroha_allocation::AllocationRefusal::Capacity { release: wait, .. } = refusal else {
        panic!("original live value must occupy the finite pool")
    };
    let waker = Waker::from(Arc::new(Check { pool: pool.clone() }));
    assert_eq!(
        registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    let (unwind, freed) = with_deallocations(layout.size(), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owner = owner;
            panic!("one-pass Quantity owner interrupted")
        }))
    });
    assert!(unwind.is_err());
    assert_eq!(freed, 1);
    assert_eq!(
        registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    registration.cancel();
    drop((wait, registration));
    assert_eq!(pool.reserved_bytes(), 0);
}
