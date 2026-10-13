//! Observe the native allocation itself, rather than only a payload destructor.
use bytes::{Bytes, BytesMut};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    panic::{catch_unwind, AssertUnwindSafe},
};

thread_local! {
    static WATCH: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static POINTER: Cell<usize> = const { Cell::new(0) };
    static FREED: Cell<bool> = const { Cell::new(false) };
    static FAIL: Cell<bool> = const { Cell::new(false) };
    static OWNER_DROPS: Cell<usize> = const { Cell::new(0) };
    static TOKEN_DROPS: Cell<usize> = const { Cell::new(0) };
    static AS_REFS: Cell<usize> = const { Cell::new(0) };
    static FREE_AFTER_OWNER: Cell<bool> = const { Cell::new(false) };
}

struct ObservedAllocator;
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let watched = WATCH
            .try_with(|watch| watch.get() == (layout.size(), layout.align()))
            .unwrap_or(false);
        if watched && FAIL.try_with(Cell::get).unwrap_or(false) {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        if watched && !pointer.is_null() {
            POINTER.with(|slot| slot.set(pointer as usize));
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let watched = POINTER
            .try_with(|slot| slot.get() == pointer as usize)
            .unwrap_or(false);
        unsafe { System.dealloc(pointer, layout) };
        if watched {
            FREE_AFTER_OWNER.with(|slot| slot.set(OWNER_DROPS.with(Cell::get) == 1));
            FREED.with(|slot| slot.set(true));
        }
    }
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

struct Payload {
    bytes: [u8; 64],
    panic_as_ref: bool,
    panic_drop: bool,
}
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        AS_REFS.with(|slot| slot.set(slot.get() + 1));
        // Inline data must already reside in its final allocation, not the
        // constructor's stack. No pointer into the old owner may escape.
        let base = POINTER.with(Cell::get);
        let layout = Bytes::owner_with_reclaim_layout::<Payload, Token>();
        let data = self.bytes.as_ptr() as usize;
        assert!(base != 0 && data >= base && data + self.bytes.len() <= base + layout.size());
        assert!(!self.panic_as_ref, "owned AsRef fault");
        &self.bytes
    }
}
impl Drop for Payload {
    fn drop(&mut self) {
        OWNER_DROPS.with(|slot| slot.set(slot.get() + 1));
        assert!(
            !FREED.with(Cell::get),
            "owner must precede its native control deallocation"
        );
        assert!(!self.panic_drop, "owned Drop fault");
    }
}
struct Token(u64);
impl Drop for Token {
    fn drop(&mut self) {
        assert_eq!(self.0, 0x51);
        if POINTER.with(Cell::get) != 0 {
            assert!(
                FREED.with(Cell::get),
                "credit must follow physical control deallocation"
            );
            assert!(FREE_AFTER_OWNER.with(Cell::get));
        }
        TOKEN_DROPS.with(|slot| slot.set(slot.get() + 1));
    }
}
fn start() {
    let layout = Bytes::owner_with_reclaim_layout::<Payload, Token>();
    WATCH.with(|slot| slot.set((layout.size(), layout.align())));
    POINTER.with(|slot| slot.set(0));
    FREED.with(|slot| slot.set(false));
    FAIL.with(|slot| slot.set(false));
    OWNER_DROPS.with(|slot| slot.set(0));
    TOKEN_DROPS.with(|slot| slot.set(0));
    AS_REFS.with(|slot| slot.set(0));
    FREE_AFTER_OWNER.with(|slot| slot.set(false));
}
fn payload(panic_as_ref: bool, panic_drop: bool) -> Payload {
    Payload {
        bytes: [0x5a; 64],
        panic_as_ref,
        panic_drop,
    }
}
fn owned() -> Bytes {
    Bytes::try_from_owner_with_reclaim(payload(false, false), Token(0x51))
        .unwrap_or_else(|_| panic!("native control allocation"))
}
fn released() {
    assert!(FREED.with(Cell::get));
    assert!(FREE_AFTER_OWNER.with(Cell::get));
    assert_eq!(OWNER_DROPS.with(Cell::get), 1);
    assert_eq!(TOKEN_DROPS.with(Cell::get), 1);
    WATCH.with(|slot| slot.set((0, 0)));
}
#[test]
fn original_control_is_freed_before_credit_returns() {
    start();
    let bytes = owned();
    assert_eq!(bytes.as_ref(), &[0x5a; 64]);
    assert_eq!(AS_REFS.with(Cell::get), 1);
    drop(bytes);
    released();
}
#[test]
fn last_clone_and_slice_reclaim_exact_native_control() {
    start();
    let bytes = owned();
    let clone = bytes.clone();
    let slice = bytes.slice(7..39);
    drop(bytes);
    drop(clone);
    assert!(!FREED.with(Cell::get));
    assert_eq!(TOKEN_DROPS.with(Cell::get), 0);
    assert_eq!(slice.as_ref(), &[0x5a; 32]);
    drop(slice);
    released();
}
#[test]
fn truncated_owned_empty_value_keeps_the_original_allocation() {
    start();
    let mut bytes = owned();
    bytes.truncate(0);
    let clone = bytes.clone();
    let static_empty = bytes.slice(..);
    drop(bytes);
    assert!(!FREED.with(Cell::get));
    drop(clone);
    released();
    assert!(static_empty.is_empty());
    drop(static_empty);
}
#[test]
fn vec_conversion_frees_original_before_releasing_its_credit() {
    start();
    let bytes = owned();
    let vec: Vec<u8> = bytes.into();
    released();
    assert_eq!(vec, [0x5a; 64]);
}
#[test]
fn mutable_conversion_frees_original_before_releasing_its_credit() {
    start();
    let bytes = owned();
    let mutable: BytesMut = bytes.into();
    released();
    assert_eq!(mutable.as_ref(), &[0x5a; 64]);
}
#[test]
fn refusal_returns_both_unchanged_owners_without_running_user_code() {
    start();
    FAIL.with(|slot| slot.set(true));
    let Err((original, token)) =
        Bytes::try_from_owner_with_reclaim(payload(false, false), Token(0x51))
    else {
        panic!("allocator refusal");
    };
    assert_eq!(original.bytes, [0x5a; 64]);
    assert_eq!(token.0, 0x51);
    assert_eq!(AS_REFS.with(Cell::get), 0);
    assert_eq!(OWNER_DROPS.with(Cell::get), 0);
    assert_eq!(TOKEN_DROPS.with(Cell::get), 0);
    assert_eq!(POINTER.with(Cell::get), 0);
    FAIL.with(|slot| slot.set(false));
    WATCH.with(|slot| slot.set((0, 0)));
    drop(original);
    drop(token);
    assert_eq!(OWNER_DROPS.with(Cell::get), 1);
    assert_eq!(TOKEN_DROPS.with(Cell::get), 1);
}
#[test]
fn panicking_as_ref_still_reclaims_before_refunding() {
    start();
    let failure = catch_unwind(AssertUnwindSafe(|| {
        let _ = Bytes::try_from_owner_with_reclaim(payload(true, false), Token(0x51));
    }));
    assert!(failure.is_err());
    released();
}
#[test]
fn panicking_owner_drop_still_reclaims_before_refunding() {
    start();
    let bytes = Bytes::try_from_owner_with_reclaim(payload(false, true), Token(0x51))
        .unwrap_or_else(|_| panic!("native control allocation"));
    assert!(catch_unwind(AssertUnwindSafe(|| drop(bytes))).is_err());
    released();
}
