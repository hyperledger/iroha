//! Const-string related implementation and structs.
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, str::from_boxed_utf8_unchecked, string::String, vec::Vec};
use core::{
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    convert::{AsRef, From, TryFrom},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    mem::{size_of, ManuallyDrop},
    ops::Deref,
};
#[cfg(feature = "std")]
use std::str::from_boxed_utf8_unchecked;

use iroha_schema::{IntoSchema, MetaMap};
use parity_scale_codec::{Encode, Output};
use serde::{Serialize, Serializer};

const MAX_INLINED_STRING_LEN: usize = 2 * size_of::<usize>() - 1;

/// Immutable inlinable string.
/// Strings shorter than 15/7/3 bytes (depending on architecture 64/32/16 bit pointer width) are inlined.
#[derive(Clone)]
pub struct ConstString(ConstStringData);

impl ConstString {
    /// Returns the length of this [`ConstString`], in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if [`ConstString`] is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// Returns `true` if [`ConstString`] data is inlined.
    #[inline]
    pub const fn is_inlined(&self) -> bool {
        self.0.is_inlined()
    }

    /// Construct empty [`ConstString`].
    #[inline]
    pub const fn new() -> Self {
        Self(ConstStringData::new())
    }
}

impl Deref for ConstString {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T: ?Sized> AsRef<T> for ConstString
where
    ConstStringData: AsRef<T>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}

impl<T: Into<ConstStringData>> From<T> for ConstString {
    #[inline]
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Display for ConstString {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", &self[..])
    }
}

impl Debug for ConstString {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", &self[..])
    }
}

impl Hash for ConstString {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

impl PartialOrd for ConstString {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        PartialOrd::partial_cmp(&self[..], &other[..])
    }
}

impl Ord for ConstString {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&self[..], &other[..])
    }
}

impl PartialEq for ConstString {
    #[inline]
    fn eq(&self, other: &ConstString) -> bool {
        PartialEq::eq(&self[..], &other[..])
    }
}

macro_rules! impl_eq {
    ($($ty:ty,)*) => {
        impl_eq!($($ty),*);
    };
    ($($ty:ty),*) => {$(
        impl PartialEq<$ty> for ConstString {
            #[allow(clippy::string_slice)]
            #[inline]
            fn eq(&self, other: &$ty) -> bool {
                PartialEq::eq(&self[..], &other[..])
            }
        }

        impl PartialEq<ConstString> for $ty {
            #[allow(clippy::string_slice)]
            #[inline]
            fn eq(&self, other: &ConstString) -> bool {
                PartialEq::eq(&self[..], &other[..])
            }
        }
    )*};
}

impl_eq!(String, str, &str);

impl Eq for ConstString {}

impl Serialize for ConstString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self)
    }
}

impl Encode for ConstString {
    fn size_hint(&self) -> usize {
        self.as_bytes().size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.as_bytes().encode_to(dest)
    }

    fn encode(&self) -> Vec<u8> {
        self.as_bytes().encode()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.as_bytes().using_encoded(f)
    }
}

impl IntoSchema for ConstString {
    fn type_name() -> String {
        String::type_name()
    }
    fn schema(map: &mut MetaMap) {
        String::schema(map);
    }
}

/// Union representing const-string variants: inlined or boxed.
/// Distinction between variants are achieved by setting least significant bit for inlined variant.
/// Boxed variant should have have 4/3/2 (depending on architecture 64/32/16 bit pointer width) trailing zeros due to pointer alignment.
#[repr(C)]
union ConstStringData {
    inlined: InlinedString,
    boxed: ManuallyDrop<BoxedString>,
}

impl ConstStringData {
    #[inline]
    const fn is_inlined(&self) -> bool {
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
    const fn boxed(&self) -> &ManuallyDrop<BoxedString> {
        // SAFETY: safe to access if `is_inlined` == `false`.
        unsafe { &self.boxed }
    }

    #[inline]
    fn len(&self) -> usize {
        if self.is_inlined() {
            self.inlined().len()
        } else {
            self.boxed().len()
        }
    }

    #[inline]
    const fn new() -> Self {
        Self {
            inlined: InlinedString::new(),
        }
    }
}

impl<T: ?Sized> AsRef<T> for ConstStringData
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

impl<T> From<T> for ConstStringData
where
    T: TryInto<InlinedString>,
    <T as TryInto<InlinedString>>::Error: Into<BoxedString>,
{
    #[inline]
    fn from(value: T) -> Self {
        match value.try_into() {
            Ok(inlined) => Self { inlined },
            Err(value) => Self {
                boxed: core::mem::ManuallyDrop::new(value.into()),
            },
        }
    }
}

impl Clone for ConstStringData {
    fn clone(&self) -> Self {
        if self.is_inlined() {
            Self {
                inlined: *self.inlined(),
            }
        } else {
            Self {
                boxed: self.boxed().clone(),
            }
        }
    }
}

impl Drop for ConstStringData {
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

#[derive(Clone, Debug)]
#[repr(transparent)]
struct BoxedString(Box<str>);

impl BoxedString {
    #[inline]
    const fn len(&self) -> usize {
        self.0.len()
    }
}

impl AsRef<str> for BoxedString {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<&str> for BoxedString {
    #[allow(unsafe_code)]
    #[inline]
    fn from(value: &str) -> Self {
        let payload = value.as_bytes().to_vec().into_boxed_slice();
        // SAFETY: correct string.
        Self(unsafe { from_boxed_utf8_unchecked(payload) })
    }
}

impl From<String> for BoxedString {
    #[inline]
    fn from(value: String) -> Self {
        Self(value.into_boxed_str())
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct InlinedString {
    #[cfg(target_endian = "big")]
    payload: [u8; MAX_INLINED_STRING_LEN],
    /// Least-significant bit is always 1 to distinguish inlined variant.  
    len: u8,
    #[cfg(target_endian = "little")]
    payload: [u8; MAX_INLINED_STRING_LEN],
}

impl InlinedString {
    #[inline]
    const fn len(self) -> usize {
        (self.len >> 1_u8) as usize
    }

    #[inline]
    const fn is_inlined(self) -> bool {
        self.len % 2 > 0
    }

    #[inline]
    const fn new() -> Self {
        Self {
            payload: [0; MAX_INLINED_STRING_LEN],
            // Set least-significant bit to mark inlined variant.
            len: 1,
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
        // Set least-significant bit to mark inlined variant.
        inlined.len += (len << 1_usize) as u8;
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

impl Debug for InlinedString {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("InlinedString")
            .field("len", &self.len())
            .field("payload", &self.as_ref())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use std::collections::hash_map::DefaultHasher;

    use super::*;

    fn run_with_strings(f: impl Fn(String)) {
        [0, 1, 7, 8, 15, 16, 30]
            .into_iter()
            // utf-8 encodes ascii characters in single byte
            .map(|len| "x".repeat(len))
            .for_each(f)
    }

    #[test]
    fn const_string_layout() {
        assert_eq!(size_of::<ConstString>(), size_of::<Box<str>>());
        assert_eq!(align_of::<ConstString>(), align_of::<Box<str>>());
    }

    #[test]
    fn const_string_new() {
        let const_string = ConstString::new();
        assert_eq!(const_string, "");
        assert_eq!(const_string.len(), 0);
    }

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

    #[test]
    fn const_string_display() {
        run_with_strings(|string| {
            let const_string = ConstString::from(string.clone());
            assert_eq!(format!("{const_string}"), string);
        });
    }

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
    fn const_string_eq_const_str() {
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
}
