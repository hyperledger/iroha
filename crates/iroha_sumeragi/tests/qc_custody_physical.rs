//! Actual exact-layout allocation refusal and zero-extra-heap complete QC controls.
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_sumeragi::{
    message::{Qc, VoteKind},
    qc_custody::{PreparedQc, QcCustodyError},
    types::{AggregateSignature, Bitmap, EpochId, Hash32, SIGNATURE_LEN},
};
use norito::core::{DecodeLimits, SequenceSpan};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
struct Observer;
thread_local! {static FAIL:Cell<Option<Layout>>=const{Cell::new(None)};static SKIP:Cell<usize>=const{Cell::new(0)};static COUNT:Cell<Option<usize>>=const{Cell::new(None)};}
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1))
            }
        });
        if FAIL
            .try_with(|slot| {
                if slot.get() == Some(layout) {
                    SKIP.with(|skip| {
                        if skip.get() != 0 {
                            skip.set(skip.get() - 1);
                            false
                        } else {
                            slot.set(None);
                            true
                        }
                    })
                } else {
                    false
                }
            })
            .unwrap_or(false)
        {
            return std::ptr::null_mut();
        }
        // SAFETY: forward the exact original requested layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: return the actual original pointer/layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let _ = COUNT.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1))
            }
        });
        // SAFETY: preserve the live original allocation and requested new size.
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static GLOBAL: Observer = Observer;
fn run<T>(layout: Option<Layout>, skip: usize, body: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL.with(|v| v.set(None));
            SKIP.with(|v| v.set(0));
            COUNT.with(|v| v.set(None));
        }
    }
    assert!(COUNT.with(|v| v.replace(Some(0))).is_none());
    FAIL.with(|v| v.set(layout));
    SKIP.with(|v| v.set(skip));
    let guard = Reset;
    let value = body();
    let n = COUNT.with(|v| v.get().unwrap());
    if layout.is_some() {
        assert!(
            FAIL.with(Cell::get).is_none(),
            "actual selected layout request must occur"
        );
        assert_eq!(SKIP.with(Cell::get), 0);
    }
    drop(guard);
    (value, n)
}
fn frame() -> Vec<u8> {
    norito::encode_canonical(&Qc {
        kind: VoteKind::Commit,
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 2,
            context: Hash32([3; 32]),
        },
        height: 4,
        view: 5,
        block_hash: Hash32([6; 32]),
        result: Hash32([7; 32]),
        signers: Bitmap::from_bytes(vec![0x7; 4]),
        agg_sig: AggregateSignature([8; SIGNATURE_LEN]),
    })
    .unwrap()
}
fn source(bytes: &[u8], pool: &AllocationBudget) -> (ChargedBuffer<u8>, SequenceSpan) {
    let mut value = ChargedBuffer::new(bytes.len() + 1, pool).unwrap();
    value.push_reserved(0xa5);
    for b in bytes {
        value.push_reserved(*b);
    }
    (
        value,
        SequenceSpan {
            start: 1,
            end: bytes.len() + 1,
        },
    )
}
fn limits() -> DecodeLimits {
    DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64)
}
#[test]
fn every_actual_qc_control_layout_refusal_keeps_original_input_and_reclaims_retired_prefix() {
    let bytes = frame();
    let layouts = PreparedQc::control_layouts();
    for index in 0..layouts.len() {
        let pool = AllocationBudget::new(1 << 20);
        let (input, range) = source(&bytes, &pool);
        let floor = pool.reserved_bytes();
        let ptr = input.as_slice().as_ptr();
        let hash = norito::core::crc64_fallback(input.as_slice());
        // Two original protocol counter controls can have identical layouts.
        // Select their genuine request ordinal, never assume layout uniqueness.
        let skip = layouts[..index]
            .iter()
            .filter(|layout| **layout == layouts[index])
            .count();
        let (refused, requests) = run(Some(layouts[index]), skip, || {
            PreparedQc::new(&input, range, &pool)
        });
        assert!(refused.is_err());
        assert!(requests > index);
        assert_eq!(pool.reserved_bytes(), floor);
        assert_eq!(input.as_slice().as_ptr(), ptr);
        assert_eq!(norito::core::crc64_fallback(input.as_slice()), hash);
        drop(refused);
        let mut ready = PreparedQc::new(&input, range, &pool).unwrap();
        ready.prepare(&input, range, limits()).unwrap();
        let owner = ready.finish().unwrap();
        assert!(owner.belongs_to(&pool));
        drop(owner);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(input);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn actual_qc_bitmap_allocator_refusal_preserves_controls_and_same_source_retry() {
    let bytes = frame();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&bytes, &pool);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let floor = pool.reserved_bytes();
    let ptr = input.as_slice().as_ptr();
    let (refused, requests) = run(Some(Layout::array::<u8>(4).unwrap()), 0, || {
        decoder.prepare(&input, range, limits())
    });
    assert_eq!(requests, 1);
    assert!(matches!(
        refused,
        Err(QcCustodyError::Decode(
            norito::core::PreparedDecodeError::Destination(
                iroha_sumeragi::qc_custody::QcFieldError::BitmapBacking(
                    iroha_allocation::ChargedBufferFromChargeError::Allocator { layout }
                )
            )
        )) if layout == Layout::array::<u8>(4).unwrap()
    ));
    assert_eq!(pool.reserved_bytes(), floor + 4);
    assert_eq!(input.as_slice().as_ptr(), ptr);
    // A fresh charge cannot be reacquired at this shrunken limit. The exact
    // original admitted charge must survive physical refusal and fund retry.
    pool.set_limit_bytes(floor);
    let (preparation, requests) = run(None, 0, || decoder.prepare(&input, range, limits()));
    preparation.unwrap();
    assert_eq!(requests, 1);
    assert_eq!(pool.reserved_bytes(), floor + 4);
    let (owner, requests) = run(None, 0, || decoder.finish().unwrap());
    assert_eq!(requests, 0);
    assert!(owner.belongs_to(&pool));
    let held = pool.reserved_bytes();
    let (other, requests) = run(None, 0, || owner.clone());
    assert_eq!(requests, 0);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), held);
    drop(other);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn complete_qc_decode_has_only_original_bitmap_allocation_then_publication_and_sharing_allocate_nothing()
 {
    let bytes = frame();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&bytes, &pool);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let (preparation, requests) = run(None, 0, || decoder.prepare(&input, range, limits()));
    preparation.unwrap();
    assert_eq!(
        requests, 1,
        "nine-field parse and exact frame comparison allocate only actual bitmap Vec"
    );
    let (owner, requests) = run(None, 0, || decoder.finish().unwrap());
    assert_eq!(requests, 0);
    assert_eq!(norito::encode_canonical(owner.get()).unwrap(), bytes);
    drop(owner);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn actual_original_qc_source_allocation_failure_refunds_only_its_own_charge() {
    let bytes = frame();
    let pool = AllocationBudget::new(1 << 20);
    let layout = Layout::array::<u8>(bytes.len()).unwrap();
    let (result, requests) = run(Some(layout), 0, || {
        ChargedBuffer::<u8>::new(bytes.len(), &pool)
    });
    assert_eq!(requests, 1);
    assert!(
        matches!(result,Err(ChargedBufferError::Allocator{requested_bytes})if requested_bytes==layout.size())
    );
    assert_eq!(pool.reserved_bytes(), 0);
    let mut input = ChargedBuffer::new(bytes.len(), &pool).unwrap();
    for byte in &bytes {
        input.push_reserved(*byte);
    }
    let range = SequenceSpan {
        start: 0,
        end: bytes.len(),
    };
    let mut ready = PreparedQc::new(&input, range, &pool).unwrap();
    ready.prepare(&input, range, limits()).unwrap();
    drop(ready.finish().unwrap());
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn actual_bitmap_allocator_error_chain_borrows_same_cause_and_keeps_original_credit() {
    use iroha_sumeragi::qc_custody::QcFieldError;
    use norito::core::PreparedDecodeError;
    use std::error::Error as _;
    let bytes = frame();
    let pool = AllocationBudget::new(1 << 20);
    let (input, range) = source(&bytes, &pool);
    let mut decoder = PreparedQc::new(&input, range, &pool).unwrap();
    let occupied = pool.reserved_bytes();
    let layout = Layout::array::<u8>(4).unwrap();
    let (result, requests) = run(Some(layout), 0, || decoder.prepare(&input, range, limits()));
    assert_eq!(requests, 1);
    let error = result.unwrap_err();
    let QcCustodyError::Decode(original) = &error else {
        panic!("actual prepared allocator refusal");
    };
    let linked = error
        .source()
        .unwrap()
        .downcast_ref::<PreparedDecodeError<QcFieldError>>()
        .unwrap();
    assert!(std::ptr::eq(linked, original));
    let PreparedDecodeError::Destination(original_field) = linked else {
        panic!("actual field refused");
    };
    let field = linked
        .source()
        .unwrap()
        .downcast_ref::<QcFieldError>()
        .unwrap();
    assert!(std::ptr::eq(field, original_field));
    let QcFieldError::BitmapBacking(original_backing) = field else {
        panic!("same original admitted layout");
    };
    let backing = field
        .source()
        .unwrap()
        .downcast_ref::<iroha_allocation::ChargedBufferFromChargeError>()
        .unwrap();
    assert!(std::ptr::eq(backing, original_backing));
    assert!(
        matches!(backing,iroha_allocation::ChargedBufferFromChargeError::Allocator{layout:actual}if *actual==layout)
    );
    assert_eq!(pool.reserved_bytes(), occupied + layout.size());
    pool.set_limit_bytes(occupied);
    let (result, requests) = run(None, 0, || decoder.prepare(&input, range, limits()));
    result.unwrap();
    assert_eq!(requests, 1);
    assert!(std::ptr::eq(
        field
            .source()
            .unwrap()
            .downcast_ref::<iroha_allocation::ChargedBufferFromChargeError>()
            .unwrap(),
        original_backing
    ));
    let owner = decoder.finish().unwrap();
    assert!(owner.belongs_to(&pool));
    drop(error);
    drop(owner);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
