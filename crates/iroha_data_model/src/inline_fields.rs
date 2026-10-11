//! One model-private destination for generated records with original inline leaves.
//!
//! Copy values remain in their containing record. This kernel provides neither
//! physical custody for an owning child nor signature, source or finality authority.

use crate::NetworkId;
use iroha_crypto::HashOf;
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, Error, FieldDestination,
};
use std::{convert::Infallible, num::NonZeroU64};

/// Destination shared by the actual header, confidential digest and pulse walks.
pub struct InlineFields;
impl FieldDestination for InlineFields {
    type Error = Infallible;
}

/// Closed crate-private set of original inline leaves and generated Copy records.
pub trait InlineLeaf: Sized + Copy {
    /// Decode one complete payload with the leaf's original error ordering.
    fn read(bytes: &[u8]) -> Result<Self, Error>;

    /// Enter exactly the original field scope before decoding its payload.
    fn read_field(field: CanonicalField<'_, Self>) -> Result<Self, DecodeIntoError<Infallible>> {
        field.with_payload(|bytes| Self::read(bytes).map_err(DecodeIntoError::Codec))
    }
}

impl<const INDEX: usize, T: InlineLeaf> DecodeField<INDEX, T> for InlineFields {
    type Value = T;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<Self::Value, DecodeIntoError<Self::Error>> {
        // The derived record owns prefixes/order, and each original field owns
        // its byte-array or logical depth/flags behavior. No prefix is reparsed.
        T::read_field(field)
    }
}

macro_rules! inline_slice_leaf {
    ($($ty:ty),+ $(,)?) => {
        $(impl InlineLeaf for $ty {
            fn read(bytes: &[u8]) -> Result<Self, Error> {
                let (value, used) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
                if used != bytes.len() {
                    return Err(Error::LengthMismatch);
                }
                Ok(value)
            }
        })+
    };
}
inline_slice_leaf!(u16, u32, u64, NonZeroU64);

impl<const N: usize> InlineLeaf for [u8; N] {
    fn read(bytes: &[u8]) -> Result<Self, Error> {
        // The generated raw byte-array field already requires exactly N bytes.
        bytes.try_into().map_err(|_| Error::LengthMismatch)
    }
    fn read_field(field: CanonicalField<'_, Self>) -> Result<Self, DecodeIntoError<Infallible>> {
        // Direct record byte-array fields are already exactly bounded. Inside
        // an Option, the original array decoder also accepts/checks its framed
        // array representation and has a specific logical count/error order.
        // Alignment one requires no scratch in either case. Preserve that sole
        // kernel instead of rejecting a malformed length before its real cause.
        field.decode_owned().map_err(DecodeIntoError::Codec)
    }
}

fn original_complete_leaf<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: for<'de> norito::core::DeserializePayload<'de> + norito::core::SerializePayload,
{
    let (value, used) = norito::core::decode_field_canonical::<T>(bytes)?;
    if used != bytes.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(value)
}

impl<T> InlineLeaf for HashOf<T> {
    fn read(bytes: &[u8]) -> Result<Self, Error> {
        original_complete_leaf(bytes)
    }
    fn read_field(field: CanonicalField<'_, Self>) -> Result<Self, DecodeIntoError<Infallible>> {
        // The sole archived Hash kernel delegates to [u8; 32] before checking
        // its marker. Alignment one avoids scratch, and the existing field
        // decoder preserves malformed framed-array/limit error precedence.
        // Do not wrap this in with_payload: that would enter its scope twice.
        field.decode_owned().map_err(DecodeIntoError::Codec)
    }
}

impl InlineLeaf for NetworkId {
    fn read(bytes: &[u8]) -> Result<Self, Error> {
        original_complete_leaf(bytes)
    }
    fn read_field(field: CanonicalField<'_, Self>) -> Result<Self, DecodeIntoError<Infallible>> {
        field.decode_owned().map_err(DecodeIntoError::Codec)
    }
}

impl<T> InlineLeaf for Option<T>
where
    T: InlineLeaf + for<'de> norito::core::DeserializePayload<'de> + norito::core::SerializePayload,
{
    fn read(bytes: &[u8]) -> Result<Self, Error> {
        // Direct leaf reading retains the original owning transport decoder.
        // Prepared generated walks use read_field below, so they never copy
        // this Option or its child into archived alignment scratch.
        original_complete_leaf(bytes)
    }
    fn read_field(field: CanonicalField<'_, Self>) -> Result<Self, DecodeIntoError<Infallible>> {
        // This is the same sole Option prefix, child scope and child-before-
        // trailing-byte order used by ordinary decoding. None visits no child.
        field.decode_optional(T::read_field)
    }
}

/// One canonical field's visitation state, distinct from its decoded value.
///
/// An optional value may be decoded as `None`; that never means the field was
/// omitted. This inline state owns only its original value and grants no custody.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DecodedField<T> {
    /// The canonical walk has not decoded this field.
    #[default]
    Missing,
    /// The complete field was decoded, including any explicit optional absence.
    Decoded(T),
}
impl<T> DecodedField<T> {
    /// Whether the canonical walk has not decoded this field.
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
    /// Borrow the original decoded value without changing field visitation.
    pub const fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Missing => None,
            Self::Decoded(value) => Some(value),
        }
    }
    /// Move the original decoded value, preserving explicit optional absence.
    pub fn into_value(self) -> Option<T> {
        match self {
            Self::Missing => None,
            Self::Decoded(value) => Some(value),
        }
    }
    /// Move the original decoded value and reset this reusable field to missing.
    pub fn take(&mut self) -> Option<T> {
        std::mem::replace(self, Self::Missing).into_value()
    }
}

#[cfg(test)]
mod decoded_field_tests {
    use super::DecodedField;

    #[test]
    fn canonical_field_visitation_preserves_explicit_none_and_original_value_retirement() {
        let mut field = DecodedField::<Option<u8>>::default();
        assert!(field.is_missing());
        assert_eq!(field.as_ref(), None);
        assert_eq!(field.take(), None);
        field = DecodedField::Decoded(None);
        assert!(!field.is_missing());
        assert_eq!(field.as_ref(), Some(&None));
        assert_eq!(field.take(), Some(None));
        assert!(field.is_missing());
        assert_eq!(DecodedField::Decoded(Some(7)).into_value(), Some(Some(7)));
        assert_eq!(DecodedField::<Option<u8>>::Missing.into_value(), None);

        struct Original<'a>(&'a std::cell::Cell<u8>);
        impl Drop for Original<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let retired = std::cell::Cell::new(0);
        let mut owner = DecodedField::<Original<'_>>::default();
        assert!(owner.is_missing());
        owner = DecodedField::Decoded(Original(&retired));
        let original = owner.take().expect("the same original decoded owner");
        assert!(owner.is_missing());
        drop(owner);
        assert_eq!(retired.get(), 0);
        drop(original);
        assert_eq!(retired.get(), 1);
    }
}
