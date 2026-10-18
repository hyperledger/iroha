//! Explicit schema identities composed independently of Rust source locations.
//!
//! Typed readers and writers share this single frame identity contract.
//! Payload codecs remain independent; schema inspection never selects a frame hash.

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, LinkedList, VecDeque},
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    rc::Rc,
    sync::Arc,
};

/// A declared nominal identity and its single root-frame projection.
///
/// Generic parents compose [`Self::nominal_name`], never [`Self::frame_name`].
/// For example, borrowed strings share the `String` root frame while a vector
/// of borrowed strings retains its distinct nominal element identity. Names
/// are protocol declarations: they must not be inferred from `type_name`,
/// `module_path`, or an alias registry.
///
/// This trait has no serialization bound, so phantom markers and typed hashes
/// can declare identities without making the marker serializable.
pub trait NoritoSchema {
    /// Canonical nominal identity, including ordered type, const and erased lifetime slots.
    fn nominal_name() -> String;

    /// Borrow the exact declared nominal identity when it is a literal.
    ///
    /// This must equal `nominal_name()` byte for byte. Generic compositions and
    /// erased lifetime slots remain explicit and return `None` unless their
    /// complete declared identity is independently available as one literal.
    fn static_nominal_name() -> Option<&'static str> {
        None
    }

    /// The single identity advertised by a frame containing this root type.
    fn frame_name() -> String {
        Self::nominal_name()
    }

    /// Return a declared literal frame identity without allocating, when available.
    ///
    /// This must equal `frame_name()` byte for byte. A literal nominal name
    /// does not grant authority to replace a separately declared root projection.
    fn static_frame_name() -> Option<&'static str> {
        None
    }
}

/// Resolve a declared nominal identity without copying an available literal.
///
/// This is nominal identity, never a root-frame projection. Dynamic generic
/// compositions retain their existing owned construction and its allocation
/// obligations; a borrowed result provides no admission for any other scratch.
#[must_use]
pub fn nominal_name<T: NoritoSchema + ?Sized>() -> Cow<'static, str> {
    T::static_nominal_name().map_or_else(|| Cow::Owned(T::nominal_name()), Cow::Borrowed)
}

/// Compute the fixed domain-separated digest of a declared root-frame identity.
///
/// This function is not an overridable part of the identity declaration. Each
/// thread memoizes the digest per type, so typed readers and writers do not
/// rebuild generic names or rerun SHA-256 on every frame. The memo returns the
/// exact bytes computed from the declared identity; frame identities are protocol
/// constants, so an implementation must return the same name on every call.
pub fn frame_hash<T: NoritoSchema + ?Sized>() -> [u8; 16] {
    frame_hash_memo::cached(uncached_frame_hash::<T>)
}

/// Compute the frame digest directly from the declared identity, bypassing the memo.
fn uncached_frame_hash<T: NoritoSchema + ?Sized>() -> [u8; 16] {
    if let Some(name) = T::static_frame_name() {
        crate::core::schema_hash_for_name(name)
    } else {
        crate::core::schema_hash_for_name(&T::frame_name())
    }
}

/// Bounded per-thread memo of computed frame digests.
///
/// The key is the address of the monomorphized digest function of one type. Live
/// functions with different code occupy different addresses. Functions folded by
/// the compiler or linker have identical code and references, and therefore identical
/// results; a type instantiated in several codegen units merely uses several slots.
/// The memo is a fixed direct-mapped table: it never allocates, and a slot conflict
/// only recomputes the same digest.
mod frame_hash_memo {
    use std::cell::Cell;

    const SLOTS: usize = 256;

    #[derive(Clone, Copy)]
    struct Slot {
        key: usize,
        hash: [u8; 16],
    }

    const EMPTY: Slot = Slot {
        key: 0,
        hash: [0; 16],
    };

    thread_local! {
        static MEMO: [Cell<Slot>; SLOTS] = const { [const { Cell::new(EMPTY) }; SLOTS] };
    }

    fn index(key: usize) -> usize {
        // Function addresses are aligned; mix higher bits into the slot index.
        ((key >> 4) ^ (key >> 12)) & (SLOTS - 1)
    }

    pub(super) fn cached(compute: fn() -> [u8; 16]) -> [u8; 16] {
        // A function address is never zero, so zero marks an empty slot.
        let key = compute as usize;
        let slot = index(key);
        let hit = MEMO
            .try_with(|memo| {
                let entry = memo[slot].get();
                (entry.key == key).then_some(entry.hash)
            })
            .ok()
            .flatten();
        if let Some(hash) = hit {
            return hash;
        }
        // Compute outside any borrow so a re-entrant identity remains valid.
        let hash = compute();
        let _ = MEMO.try_with(|memo| memo[slot].set(Slot { key, hash }));
        hash
    }
}

/// Compose a named constructor with ordered nominal type or const arguments.
///
/// Each argument must already be a canonical identity or a Rust primitive
/// const literal. Empty argument lists leave the constructor unchanged.
pub fn generic_name(constructor: &str, arguments: &[String]) -> String {
    if arguments.is_empty() {
        constructor.to_owned()
    } else {
        format!("{constructor}<{}>", arguments.join(", "))
    }
}

macro_rules! nominal {
    ($($ty:ty => $name:literal),+ $(,)?) => {$(
        impl NoritoSchema for $ty {
            fn nominal_name() -> String { $name.to_owned() }
            fn static_nominal_name() -> Option<&'static str> { Some($name) }
        }
    )+};
}
nominal! {
    () => "()", bool => "bool", char => "char",
    u8 => "u8", u16 => "u16", u32 => "u32", u64 => "u64", u128 => "u128", usize => "usize",
    i8 => "i8", i16 => "i16", i32 => "i32", i64 => "i64", i128 => "i128", isize => "isize",
    f32 => "f32", f64 => "f64", str => "str", String => "alloc::string::String",
    NonZeroU16 => "core::num::nonzero::NonZero<u16>",
    NonZeroU32 => "core::num::nonzero::NonZero<u32>",
    NonZeroU64 => "core::num::nonzero::NonZero<u64>",
}

macro_rules! unary {
    ($($ty:ident => $name:literal),+ $(,)?) => {$(
        impl<T: NoritoSchema> NoritoSchema for $ty<T> {
            fn nominal_name() -> String { generic_name($name, &[T::nominal_name()]) }
        }
    )+};
}
unary! {
    Box => "alloc::boxed::Box", Rc => "alloc::rc::Rc", Arc => "alloc::sync::Arc",
    Cell => "core::cell::Cell", RefCell => "core::cell::RefCell",
    Option => "core::option::Option", Vec => "alloc::vec::Vec",
    VecDeque => "alloc::collections::vec_deque::VecDeque",
    LinkedList => "alloc::collections::linked_list::LinkedList",
    BinaryHeap => "alloc::collections::binary_heap::BinaryHeap",
    BTreeSet => "alloc::collections::btree::set::BTreeSet",
    HashSet => "std::collections::hash::set::HashSet",
}

impl<T: NoritoSchema + ?Sized> NoritoSchema for PhantomData<T> {
    fn nominal_name() -> String {
        generic_name("core::marker::PhantomData", &[T::nominal_name()])
    }
}

macro_rules! binary {
    ($($ty:ident => $name:literal),+ $(,)?) => {$(
        impl<T: NoritoSchema, U: NoritoSchema> NoritoSchema for $ty<T, U> {
            fn nominal_name() -> String {
                generic_name($name, &[T::nominal_name(), U::nominal_name()])
            }
        }
    )+};
}
binary! {
    Result => "core::result::Result",
    BTreeMap => "alloc::collections::btree::map::BTreeMap",
    HashMap => "std::collections::hash::map::HashMap",
}

impl<T: NoritoSchema, const N: usize> NoritoSchema for [T; N] {
    fn nominal_name() -> String {
        format!("[{}; {N}]", T::nominal_name())
    }
}

impl<T: NoritoSchema> NoritoSchema for &T {
    fn nominal_name() -> String {
        format!("&{}", T::nominal_name())
    }
}

macro_rules! string_projection {
    ($($ty:ty => $name:literal),+ $(,)?) => {$(
        impl NoritoSchema for $ty {
            fn nominal_name() -> String { $name.to_owned() }
            fn static_nominal_name() -> Option<&'static str> { Some($name) }
            fn frame_name() -> String { String::nominal_name() }
        }
    )+};
}
string_projection! {
    &str => "&str",
    Cow<'_, str> => "alloc::borrow::Cow<'_, str>",
    Box<str> => "alloc::boxed::Box<str>",
}

macro_rules! tuple {
    ($($ty:ident),+) => {
        impl<$($ty: NoritoSchema),+> NoritoSchema for ($($ty,)+) {
            fn nominal_name() -> String {
                format!("({})", [$($ty::nominal_name()),+].join(", "))
            }
        }
    };
}
tuple!(A, B);
tuple!(A, B, C);
tuple!(A, B, C, D);
tuple!(A, B, C, D, E);
tuple!(A, B, C, D, E, F);
tuple!(A, B, C, D, E, F, G);
tuple!(A, B, C, D, E, F, G, H);
tuple!(A, B, C, D, E, F, G, H, I);
tuple!(A, B, C, D, E, F, G, H, I, J);
tuple!(A, B, C, D, E, F, G, H, I, J, K);
tuple!(A, B, C, D, E, F, G, H, I, J, K, L);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SamplePayload;

    fn assert_memoized<T: NoritoSchema + ?Sized>() {
        let expected = crate::core::schema_hash_for_name(&T::frame_name());
        assert_eq!(uncached_frame_hash::<T>(), expected);
        for _ in 0..3 {
            assert_eq!(frame_hash::<T>(), expected, "{}", T::frame_name());
        }
    }

    #[test]
    fn memoized_frame_hash_matches_uncached_digest_for_literal_and_generic_identities() {
        // Literal identities, including a string root projection and a derived record.
        assert_memoized::<u32>();
        assert_memoized::<String>();
        assert_memoized::<&str>();
        assert_memoized::<Box<str>>();
        assert_memoized::<SamplePayload>();
        // Composed generic identities build their names only on a memo miss.
        assert_memoized::<Vec<u32>>();
        assert_memoized::<Option<String>>();
        assert_memoized::<(u8, String)>();
        assert_memoized::<[u16; 4]>();
        assert_memoized::<HashMap<String, Vec<u8>>>();
        assert_memoized::<Vec<SamplePayload>>();
        assert_eq!(
            frame_hash::<u32>(),
            crate::core::schema_hash_for_name("u32"),
            "the memo must not alter the V1 type-name digest"
        );
        assert_eq!(frame_hash::<&str>(), frame_hash::<String>());
        assert_ne!(frame_hash::<Vec<u32>>(), frame_hash::<Vec<u64>>());
    }

    #[test]
    fn frame_hash_memo_is_per_thread_and_survives_slot_conflicts() {
        let main = (
            frame_hash::<Vec<u8>>(),
            frame_hash::<BTreeMap<u8, String>>(),
        );
        let other = std::thread::spawn(|| {
            (
                frame_hash::<Vec<u8>>(),
                frame_hash::<BTreeMap<u8, String>>(),
            )
        })
        .join()
        .expect("frame hash thread");
        assert_eq!(main, other);
        // Many distinct generic identities overwrite direct-mapped slots; every
        // lookup still returns the declared digest.
        macro_rules! arrays {
            ($($len:literal),+) => {$(
                assert_memoized::<[u8; $len]>();
                assert_memoized::<Option<[u64; $len]>>();
            )+};
        }
        arrays!(
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
        );
        assert_memoized::<Vec<u8>>();
        assert_eq!(frame_hash::<Vec<u8>>(), main.0);
    }
}
