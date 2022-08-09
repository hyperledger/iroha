//! Const-string related implementation and structs.
#![allow(
    clippy::std_instead_of_core,
    clippy::undocumented_unsafe_blocks,
    clippy::arithmetic
)]

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::{Borrow, ToOwned},
    boxed::Box,
    str::from_utf8_unchecked,
    string::String,
};
use core::{
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    convert::TryFrom,
    fmt,
    hash::{Hash, Hasher},
    mem::{size_of, ManuallyDrop},
    ops::Deref,
    ptr::NonNull,
    slice::{from_raw_parts, from_raw_parts_mut},
};
#[cfg(feature = "std")]
use std::{borrow::Borrow, str::from_utf8_unchecked};

use derive_more::{DebugCustom, Display};
use iroha_schema::{IntoSchema, MetaMap};
use parity_scale_codec::{WrapperTypeDecode, WrapperTypeEncode};
use serde::{
    de::{Deserialize, Deserializer, Error, Visitor},
    ser::{Serialize, Serializer},
};

const MAX_INLINED_STRING_LEN: usize = 2 * size_of::<usize>() - 1;

/// Immutable inlinable string.
/// Strings shorter than 15/7/3 bytes (in 64/32/16-bit architecture) are inlined.
/// Union represents const-string variants: inlined or boxed.
/// Distinction between variants are achieved by tagging most significant bit of field `len`:
/// - for inlined variant MSB of `len` is always equal to 1, it's enforced by `InlinedString` constructor;
/// - for boxed variant MSB of `len` is always equal to 0, it's enforced by the fact
/// that `Box` and `Vec` never allocate more than`isize::MAX bytes`.
/// For little-endian 64bit architecture memory layout of [`Self`] is following:
///
/// ```text
/// +---------+-------+---------+----------+----------------+
/// | Bits    | 0..63 | 64..118 | 119..126 | 127            |
/// +---------+-------+---------+----------+----------------+
/// | Inlined | payload         | len      | tag (always 1) |
/// +---------+-------+---------+----------+----------------+
/// | Box     | ptr   | len                | tag (always 0) |
/// +---------+-------+--------------------+----------------+
/// ```
#[derive(Display, DebugCustom)]
#[display(fmt = "{}", "&**self")]
#[debug(fmt = "{:?}", "&**self")]
#[repr(C)]
pub union ConstString {
    inlined: InlinedString,
    boxed: ManuallyDrop<BoxedString>,
}

impl ConstString {
    /// Return the length of this [`Self`], in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        if self.is_inlined() {
            self.inlined().len()
        } else {
            self.boxed().len()
        }
    }

    /// Return `true` if [`Self`] is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Construct empty [`Self`].
    #[inline]
    pub const fn new() -> Self {
        Self {
            inlined: InlinedString::new(),
        }
    }

    /// Return `true` if [`Self`] is inlined.
    #[inline]
    pub const fn is_inlined(&self) -> bool {
        // SAFETY: access to the MSB is always safe regardless of the correct variant.
        self.inlined().is_inlined()
    }

    #[allow(unsafe_code)]
    #[inline]
    const fn inlined(&self) -> &InlinedString {
        // SAFETY: safe to access if `is_inlined` == `true`.
        unsafe { &self.inlined }
    }

    #[allow(unsafe_code)]
    #[inline]
    fn boxed(&self) -> &BoxedString {
        // SAFETY: safe to access if `is_inlined` == `false`.
        unsafe { &self.boxed }
    }
}

impl<T: ?Sized> AsRef<T> for ConstString
where
    InlinedString: AsRef<T>,
    BoxedString: AsRef<T>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        if self.is_inlined() {
            self.inlined().as_ref()
        } else {
            self.boxed().as_ref()
        }
    }
}

impl Deref for ConstString {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Borrow<str> for ConstString {
    fn borrow(&self) -> &str {
        self.as_ref()
    }
}

impl Hash for ConstString {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

impl Ord for ConstString {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&**self, &**other)
    }
}

/// Can't be derived.
impl PartialOrd for ConstString {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ConstString {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(&**self, &**other)
    }
}

macro_rules! impl_eq {
    ($($ty:ty),*) => {$(
        impl PartialEq<$ty> for ConstString {
            // Not possible to write macro uniformly for different types otherwise.
            #[allow(clippy::string_slice, clippy::deref_by_slicing)]
            #[inline]
            fn eq(&self, other: &$ty) -> bool {
                PartialEq::eq(&self[..], &other[..])
            }
        }

        impl PartialEq<ConstString> for $ty {
            // Not possible to write macro uniformly for different types otherwise.
            #[allow(clippy::string_slice, clippy::deref_by_slicing)]
            #[inline]
            fn eq(&self, other: &ConstString) -> bool {
                PartialEq::eq(&self[..], &other[..])
            }
        }
    )*};
}

impl_eq!(String, str, &str);

/// Can't be derived.
impl Eq for ConstString {}

impl<T> From<T> for ConstString
where
    T: TryInto<InlinedString>,
    <T as TryInto<InlinedString>>::Error: Into<BoxedString>,
{
    #[inline]
    fn from(value: T) -> Self {
        match value.try_into() {
            Ok(inlined) => Self { inlined },
            Err(value) => Self {
                boxed: ManuallyDrop::new(value.into()),
            },
        }
    }
}

impl Clone for ConstString {
    fn clone(&self) -> Self {
        if self.is_inlined() {
            Self {
                inlined: *self.inlined(),
            }
        } else {
            Self {
                boxed: ManuallyDrop::new(self.boxed().clone()),
            }
        }
    }
}

impl Drop for ConstString {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.is_inlined() {
            // SAFETY: safe because`is_inlined` == `false`.
            unsafe {
                ManuallyDrop::drop(&mut self.boxed);
            }
        }
    }
}

impl Serialize for ConstString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self)
    }
}

impl<'de> Deserialize<'de> for ConstString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(ConstStringVisitor)
    }
}

struct ConstStringVisitor;

impl<'de> Visitor<'de> for ConstStringVisitor {
    type Value = ConstString;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(v.into())
    }

    fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(v.into())
    }
}

impl WrapperTypeEncode for ConstString {}

impl WrapperTypeDecode for ConstString {
    type Wrapped = String;
}

impl IntoSchema for ConstString {
    fn type_name() -> String {
        String::type_name()
    }
    fn schema(map: &mut MetaMap) {
        String::schema(map);
    }
}

#[derive(DebugCustom)]
#[debug(fmt = "{:?}", "&**self")]
#[repr(C)]
struct BoxedString {
    #[cfg(target_endian = "little")]
    ptr: NonNull<u8>,
    len: usize,
    #[cfg(target_endian = "big")]
    ptr: NonNull<u8>,
}

impl BoxedString {
    #[inline]
    const fn len(&self) -> usize {
        self.len
    }

    #[allow(unsafe_code)]
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: created from `Box<[u8]>`.
        unsafe { from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    #[allow(unsafe_code)]
    #[inline]
    fn from_boxed_slice(slice: Box<[u8]>) -> Self {
        let len = slice.len();
        // SAFETY: `Box::into_raw` returns properly aligned and non-null pointers.
        let ptr = unsafe { NonNull::new_unchecked(Box::into_raw(slice).cast::<u8>()) };
        Self { ptr, len }
    }
}

impl AsRef<str> for BoxedString {
    #[allow(unsafe_code)]
    #[inline]
    fn as_ref(&self) -> &str {
        // SAFETY: created from valid utf-8
        unsafe { from_utf8_unchecked(self.as_bytes()) }
    }
}

impl Deref for BoxedString {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Clone for BoxedString {
    /// Properly clone [`Self`] into new allocation.
    fn clone(&self) -> Self {
        Self::from_boxed_slice(self.as_bytes().to_owned().into_boxed_slice())
    }
}

impl From<&str> for BoxedString {
    #[allow(unsafe_code)]
    #[inline]
    fn from(value: &str) -> Self {
        Self::from_boxed_slice(value.as_bytes().to_owned().into_boxed_slice())
    }
}

impl From<String> for BoxedString {
    #[inline]
    fn from(value: String) -> Self {
        Self::from_boxed_slice(value.into_bytes().into_boxed_slice())
    }
}

impl Drop for BoxedString {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: created from `Box<[u8]>`.
        unsafe {
            let _dropped = Box::<[_]>::from_raw(from_raw_parts_mut(self.ptr.as_ptr(), self.len));
        }
    }
}

/// `BoxedString` is `Send` because the data they
/// reference is unaliased. Aliasing invariant is enforced by
/// creation of `BoxedString`.
#[allow(unsafe_code)]
unsafe impl Send for BoxedString {}

/// `BoxedString` is `Sync` because the data they
/// reference is unaliased. Aliasing invariant is enforced by
/// creation of `BoxedString`.
#[allow(unsafe_code)]
unsafe impl Sync for BoxedString {}

#[derive(Clone, Copy)]
#[repr(C)]
struct InlinedString {
    #[cfg(target_endian = "little")]
    payload: [u8; MAX_INLINED_STRING_LEN],
    /// MSB is always 1 to distinguish inlined variant.
    len: u8,
    #[cfg(target_endian = "big")]
    payload: [u8; MAX_INLINED_STRING_LEN],
}

impl InlinedString {
    #[inline]
    const fn len(self) -> usize {
        (self.len - 128) as usize
    }

    #[inline]
    const fn is_inlined(self) -> bool {
        self.len >= 128
    }

    #[inline]
    const fn new() -> Self {
        Self {
            payload: [0; MAX_INLINED_STRING_LEN],
            // Set MSB to mark inlined variant.
            len: 128,
        }
    }
}

impl AsRef<str> for InlinedString {
    #[allow(unsafe_code)]
    #[inline]
    fn as_ref(&self) -> &str {
        // SAFETY: created from valid utf-8.
        unsafe { core::str::from_utf8_unchecked(&self.payload[..self.len()]) }
    }
}

impl<'value> TryFrom<&'value str> for InlinedString {
    type Error = &'value str;

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    fn try_from(value: &'value str) -> Result<Self, Self::Error> {
        let len = value.len();
        if len > MAX_INLINED_STRING_LEN {
            return Err(value);
        }
        let mut inlined = Self::new();
        inlined.payload.as_mut()[..len].copy_from_slice(value.as_bytes());
        // Truncation won't happen because we checked that the length shorter than `MAX_INLINED_STRING_LEN`.
        // Addition here because we set MSB of len field in `Self::new` to mark inlined variant.
        inlined.len += len as u8;
        Ok(inlined)
    }
}

impl TryFrom<String> for InlinedString {
    type Error = String;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match Self::try_from(value.as_str()) {
            Ok(inlined) => Ok(inlined),
            Err(_) => Err(value),
        }
    }
}

#[allow(clippy::restriction)]
#[cfg(test)]
mod tests {
    use super::*;

    mod layout {
        use core::mem::{align_of, size_of};

        use super::*;

        #[test]
        fn const_string_layout() {
            assert_eq!(size_of::<ConstString>(), size_of::<Box<str>>());
            assert_eq!(align_of::<ConstString>(), align_of::<Box<str>>());
        }
    }

    mod api {
        use super::*;

        #[test]
        fn const_string_is_inlined() {
            run_with_strings(|string| {
                let len = string.len();
                let const_string = ConstString::from(string);
                let is_inlined = len <= MAX_INLINED_STRING_LEN;
                assert_eq!(const_string.is_inlined(), is_inlined, "with len {}", len);
            });
        }

        #[test]
        fn const_string_len() {
            run_with_strings(|string| {
                let len = string.len();
                let const_string = ConstString::from(string);
                assert_eq!(const_string.len(), len);
            });
        }

        #[test]
        fn const_string_deref() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(&*const_string, &*string);
            });
        }

        #[test]
        fn const_string_from_string() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.clone());
                assert_eq!(const_string, string);
            });
        }

        #[test]
        fn const_string_from_str() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(const_string, string);
            });
        }

        #[test]
        fn const_string_clone() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string);
                let const_string_clone = const_string.clone();
                assert_eq!(const_string, const_string_clone);
            });
        }
    }

    mod integration {
        use std::collections::hash_map::DefaultHasher;

        use parity_scale_codec::Encode;

        use super::*;

        #[test]
        fn const_string_hash() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.clone());
                let mut string_hasher = DefaultHasher::new();
                let mut const_string_hasher = DefaultHasher::new();
                string.hash(&mut string_hasher);
                const_string.hash(&mut const_string_hasher);
                assert_eq!(const_string_hasher.finish(), string_hasher.finish());
            });
        }

        #[test]
        fn const_string_eq_string() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(const_string, string);
                assert_eq!(string, const_string);
            });
        }

        #[test]
        fn const_string_eq_str() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(const_string, string.as_str());
                assert_eq!(string.as_str(), const_string);
            });
        }

        #[test]
        fn const_string_eq_const_string() {
            run_with_strings(|string| {
                let const_string_1 = ConstString::from(string.as_str());
                let const_string_2 = ConstString::from(string.as_str());
                assert_eq!(const_string_1, const_string_2);
                assert_eq!(const_string_2, const_string_1);
            });
        }

        #[test]
        fn const_string_cmp() {
            run_with_strings(|string_1| {
                run_with_strings(|string_2| {
                    let const_string_1 = ConstString::from(string_1.as_str());
                    let const_string_2 = ConstString::from(string_2.as_str());
                    assert!(
                        ((const_string_1 <= const_string_2) && (string_1 <= string_2))
                            || ((const_string_1 >= const_string_2) && (string_1 >= string_2))
                    );
                    assert!(
                        ((const_string_2 >= const_string_1) && (string_2 >= string_1))
                            || ((const_string_2 <= const_string_1) && (string_2 <= string_1))
                    );
                });
            });
        }

        #[test]
        fn const_string_scale_encode() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(const_string.encode(), string.encode());
            });
        }

        #[test]
        fn const_string_serde_serialize() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(
                    serde_json::to_string(&const_string).expect("valid"),
                    serde_json::to_string(&string).expect("valid"),
                );
            });
        }
    }

    fn run_with_strings(f: impl Fn(String)) {
        [
            // 0-byte
            "",
            // 1-byte
            "?",
            // 2-bytes
            "??",
            "Δ",
            // 3-bytes
            "???",
            "?Δ",
            "ン",
            // 4-bytes
            "????",
            "??Δ",
            "ΔΔ",
            "?ン",
            "🔥",
            // 7-bytes
            "???????",
            "???🔥",
            "Δ?🔥",
            "ン?ン",
            // 8-bytes
            "????????",
            "ΔΔΔΔ",
            "Δンン",
            "🔥🔥",
            // 15-bytes
            "???????????????",
            "?????????????Δ",
            "????????????ン",
            "???????????🔥",
            "Δ?🔥Δンン",
            // 16-bytes
            "????????????????",
            "????????Δンン",
            "ΔΔΔΔΔΔΔΔ",
            "🔥🔥🔥🔥",
            // 30-bytes
            "??????????????????????????????",
            "??????????????????????????ΔΔ",
            "Δ?🔥ΔンンΔ?🔥Δンン",
            // 31-bytes
            "???????????????????????Δンン",
            "Δ?🔥Δンン🔥🔥🔥🔥",
            "???????????????ΔΔΔΔΔΔΔΔ",
        ]
        .into_iter()
        .map(str::to_owned)
        .for_each(f)
    }
}
