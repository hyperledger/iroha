//! Fixed-size strings with inlining for short values.
//!
//! This module defines [`ConstString`], a union that stores short strings
//! inline within the structure and falls back to heap allocation for longer
//! ones. It is intended for data that never changes after construction but
//! needs to be stored compactly or serialized efficiently.
use core::{
    borrow::Borrow,
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    convert::TryFrom,
    fmt,
    hash::{Hash, Hasher},
    mem::{ManuallyDrop, size_of},
    ops::Deref,
    ptr::NonNull,
    slice::from_raw_parts,
    str::from_utf8_unchecked,
};
use derive_more::{Debug, Display};
use iroha_schema::{Ident, IntoSchema, MetaMap, TypeId};
use norito::{
    DeserializePayload, SerializePayload, core as ncore,
    json::{self, JsonDeserialize, JsonSerialize},
};
use std::{
    borrow::ToOwned as _,
    boxed::Box,
    string::{String, ToString as _},
};
const MAX_INLINED_STRING_LEN: usize = 2 * size_of::<usize>() - 1;
/// Immutable inlinable string.
///
/// Strings shorter than 15/7/3 bytes (in 64/32/16-bit architecture) are inlined.
/// Union represents const-string variants: inlined or boxed.
/// Distinction between variants are achieved by tagging most significant bit of field `len`:
/// - for inlined variant MSB of `len` is always equal to 1, it's enforced by `InlinedString` constructor;
/// - for boxed variant MSB of `len` is always equal to 0, it's enforced by the fact
///   that `Box` and `Vec` never allocate more than`isize::MAX bytes`.
///   For little-endian 64bit architecture memory layout of [`Self`] is following:
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
#[derive(Display)]
#[display("{}", &**self)]
#[repr(C)]
pub union ConstString {
    inlined: InlinedString,
    boxed: ManuallyDrop<BoxedString>,
}
impl norito::NoritoSchema for ConstString {
    fn nominal_name() -> String {
        "iroha_primitives::conststr::ConstString".to_owned()
    }
}
impl ConstString {
    /// Exact optional backing requested when decoding this borrowed text.
    ///
    /// Inline strings require no heap allocation. This plan shares the concrete
    /// representation threshold with the fallible decoder; it validates no text.
    #[must_use]
    pub fn decode_allocation_layout(value: &str) -> Option<std::alloc::Layout> {
        (value.len() > MAX_INLINED_STRING_LEN).then(|| {
            std::alloc::Layout::array::<u8>(value.len()).expect("existing borrowed text layout")
        })
    }

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

    /// Retain one borrowed string under the active decode-allocation budget.
    ///
    /// Short values remain inline and allocate nothing. Longer values reserve their exact byte
    /// length before using the fallible raw allocator, so parser clients do not hide a source-sized
    /// `String` clone behind an ordinary infallible conversion.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit or allocation error when the exact retained
    /// destination cannot be admitted.
    #[doc(hidden)]
    #[allow(unsafe_code)]
    pub fn try_from_str_for_decode(value: &str) -> Result<Self, ncore::Error> {
        if let Ok(inlined) = InlinedString::try_from(value) {
            return Ok(Self { inlined });
        }

        let len = value.len();
        ncore::reserve_decode_allocation(len)?;
        let layout = std::alloc::Layout::array::<u8>(len)
            .map_err(|_| ncore::Error::AllocationFailed { bytes: u64::MAX })?;
        // SAFETY: `layout` is non-zero because every value that reaches this
        // branch is longer than the inline capacity. Null is rejected before
        // any write or ownership conversion.
        let allocation = unsafe { std::alloc::alloc(layout) };
        let allocation =
            NonNull::new(allocation).ok_or_else(|| ncore::Error::AllocationFailed {
                bytes: u64::try_from(len).unwrap_or(u64::MAX),
            })?;
        // SAFETY: the allocation has exactly `len` writable bytes and the
        // source slice has the same length. All bytes are initialized before
        // converting the allocation into its unique boxed owner.
        unsafe {
            core::ptr::copy_nonoverlapping(value.as_ptr(), allocation.as_ptr(), len);
        }
        // SAFETY: `allocation` came from the global allocator with the exact
        // `[u8]` layout above and is now fully initialized and uniquely owned.
        let bytes = unsafe {
            Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                allocation.as_ptr(),
                len,
            ))
        };
        Ok(Self {
            boxed: ManuallyDrop::new(BoxedString::from_boxed_slice(bytes)),
        })
    }
    /// Return `true` if [`Self`] is inlined.
    #[inline]
    pub const fn is_inlined(&self) -> bool {
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
        (**self).hash(state);
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
impl fmt::Debug for ConstString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
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
impl JsonSerialize for ConstString {
    fn json_serialize(&self, out: &mut String) {
        json::write_json_string(self.as_ref(), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(self.as_ref(), out)
    }
}
impl JsonDeserialize for ConstString {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        parser.parse_string().map(Into::into)
    }
}

impl SerializePayload for ConstString {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        <&str as SerializePayload>::serialize(&self.as_ref(), writer)
    }
}

impl<'a> DeserializePayload<'a> for ConstString {
    fn deserialize(archived: &'a ncore::Archived<Self>) -> Self {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        if let Ok(value) = <&str as DeserializePayload>::try_deserialize(archived.cast::<&str>()) {
            return value.into();
        }
        if let Ok(value) =
            <String as DeserializePayload>::try_deserialize(archived.cast::<String>())
        {
            return value.as_str().into();
        }
        if let Ok(payload) = ncore::payload_slice_from_ptr(ptr)
            && let Ok((value, _used)) = ncore::decode_field_canonical::<String>(payload)
        {
            return value.as_str().into();
        }
        let string = String::deserialize(archived.cast::<String>());
        string.as_str().into()
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for ConstString {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let (decoded, used) = <String as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((ConstString::from(decoded), used))
    }
}
// darling doesn't support unions, so this can't be derived
impl TypeId for ConstString {
    fn id() -> Ident {
        "ConstString".to_string()
    }
}
impl IntoSchema for ConstString {
    fn type_name() -> Ident {
        "String".to_string()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            if !map.contains_key::<String>() {
                <String as iroha_schema::IntoSchema>::update_schema_map(map);
            }
            if let Some(schema) = map.get::<String>() {
                map.insert::<Self>(schema.clone());
            }
        }
    }
}
#[derive(Debug)]
#[debug("{:?}", &**self)]
#[repr(C)]
struct BoxedString {
    #[cfg(target_endian = "little")]
    ptr: NonNull<u8>,
    len: usize,
    #[cfg(target_endian = "big")]
    ptr: NonNull<u8>,
}
impl Default for BoxedString {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
        }
    }
}
impl Default for ConstString {
    fn default() -> Self {
        Self::new()
    }
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
            let _dropped = Box::<[_]>::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.ptr.as_ptr(),
                self.len,
            ));
        }
    }
}
/// `BoxedString` is `Send` because the data they reference is unaliased. Aliasing invariant is
/// enforced by creation of `BoxedString`.
#[allow(unsafe_code)]
unsafe impl Send for BoxedString {}
/// `BoxedString` is `Sync` because the data they reference is unaliased. Aliasing invariant is
/// enforced by creation of `BoxedString`.
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
        Self::try_from(value.as_str()).ok().ok_or(value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    mod layout {
        use super::*;
        use core::mem::{align_of, size_of};
        // Verify that `ConstString` occupies the same space as a boxed string.
        #[test]
        fn const_string_layout() {
            assert_eq!(size_of::<ConstString>(), size_of::<Box<str>>());
            assert_eq!(align_of::<ConstString>(), align_of::<Box<str>>());
        }
    }
    mod api {
        use super::*;
        // Strings up to the inline limit should be stored without heap allocation.
        #[test]
        fn const_string_is_inlined() {
            run_with_strings(|string| {
                let len = string.len();
                let const_string = ConstString::from(string);
                let is_inlined = len <= MAX_INLINED_STRING_LEN;
                assert_eq!(const_string.is_inlined(), is_inlined, "with len {len}");
            });
        }
        // Length reported by `ConstString` should match the source string.
        #[test]
        fn const_string_len() {
            run_with_strings(|string| {
                let len = string.len();
                let const_string = ConstString::from(string);
                assert_eq!(const_string.len(), len);
            });
        }
        // Dereferencing should yield the original string slice.
        #[test]
        fn const_string_deref() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(&*const_string, &*string);
            });
        }

        #[test]
        fn rejected_inline_owned_string_retains_its_original_allocation() {
            let value = "x".repeat(MAX_INLINED_STRING_LEN + 1);
            let pointer = value.as_ptr();
            let capacity = value.capacity();
            let Err(rejected) = InlinedString::try_from(value) else {
                panic!("oversized string must be returned for boxed storage");
            };
            assert_eq!(rejected.as_ptr(), pointer);
            assert_eq!(rejected.capacity(), capacity);
            assert_eq!(rejected, "x".repeat(MAX_INLINED_STRING_LEN + 1));
        }

        // Conversion from `String` should preserve the value.
        #[test]
        fn const_string_from_string() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.clone());
                assert_eq!(const_string, string);
            });
        }
        // Conversion from `&str` should preserve the value.
        #[test]
        fn const_string_from_str() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(const_string, string);
            });
        }

        #[test]
        fn decode_constructor_inlines_or_charges_the_exact_retained_bytes() {
            fn limits(bytes: usize) -> ncore::DecodeLimits {
                ncore::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
            }

            let inline = "inline";
            let (decoded, usage) = ncore::with_decode_limits_measured(limits(0), || {
                ConstString::try_from_str_for_decode(inline)
            });
            assert_eq!(decoded.expect("inline string"), inline);
            assert_eq!(usage.total_allocated_bytes(), 0);

            let boxed = "x".repeat(MAX_INLINED_STRING_LEN + 1);
            let (decoded, usage) = ncore::with_decode_limits_measured(limits(boxed.len()), || {
                ConstString::try_from_str_for_decode(&boxed)
            });
            assert_eq!(decoded.expect("exact boxed string"), boxed);
            assert_eq!(usage.total_allocated_bytes(), boxed.len());

            let (rejected, usage) =
                ncore::with_decode_limits_measured(limits(boxed.len() - 1), || {
                    ConstString::try_from_str_for_decode(&boxed)
                });
            assert!(matches!(
                rejected,
                Err(ncore::Error::TotalAllocationExceeded { .. })
            ));
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
        // Cloning should produce an identical `ConstString`.
        #[test]
        #[allow(clippy::redundant_clone)]
        fn const_string_clone() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string);
                let const_string_clone = const_string.clone();
                assert_eq!(const_string, const_string_clone);
            });
        }
    }
    mod integration {
        use super::*;
        use norito::codec::{Decode, Encode};
        use std::collections::hash_map::DefaultHasher;
        // Hash output should match that of the original string.
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
        // Comparison with `String` should behave symmetrically.
        #[test]
        fn const_string_eq_string() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(const_string, string);
                assert_eq!(string, const_string);
            });
        }
        // Comparison with `&str` should behave symmetrically.
        #[test]
        fn const_string_eq_str() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                assert_eq!(const_string, string.as_str());
                assert_eq!(string.as_str(), const_string);
            });
        }
        // Two `ConstString` values from the same data should be equal.
        #[test]
        fn const_string_eq_const_string() {
            run_with_strings(|string| {
                let const_string_1 = ConstString::from(string.as_str());
                let const_string_2 = ConstString::from(string.as_str());
                assert_eq!(const_string_1, const_string_2);
                assert_eq!(const_string_2, const_string_1);
            });
        }
        // Ordering between `ConstString`s should mirror ordering of source strings.
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
        // Norito encoding then decoding should reproduce the original value.
        #[test]
        fn const_string_norito_roundtrip() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                let decoded = ConstString::decode(&mut const_string.encode().as_slice()).unwrap();
                assert_eq!(decoded, const_string);
            });
        }
        // Norito JSON serialization should match the plain string and round-trip.
        #[test]
        fn const_string_json_roundtrip() {
            run_with_strings(|string| {
                let const_string = ConstString::from(string.as_str());
                let json = norito::json::to_json(&const_string).expect("valid");
                assert_eq!(json, norito::json::to_json(&string).expect("valid"));
                let parsed: ConstString = norito::json::from_json(&json).expect("valid");
                assert_eq!(parsed, const_string);
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
        .for_each(f);
    }
}

#[cfg(test)]
mod decode_layout_tests {
    use super::*;
    #[test]
    fn decode_layout_matches_the_concrete_inline_threshold() {
        for length in 0..=64 {
            let text = "x".repeat(length);
            let value = ConstString::try_from_str_for_decode(&text).unwrap();
            let layout = ConstString::decode_allocation_layout(&text);
            assert_eq!(layout.is_none(), value.is_inlined());
            if let Some(layout) = layout {
                assert_eq!(layout.size(), value.len());
            }
        }
    }
}
