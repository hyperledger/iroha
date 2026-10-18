//! Original generated Copy field/closed-enum kernels without archived alignment copies.

use crate::{
    message::VoteKind,
    types::{AggregateSignature, EpochId, Hash32},
};
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields,
    DecodeValueDestination, DecodeValueFields, EnumFieldDestination, FieldDestination,
};
use std::convert::Infallible;

pub(super) trait Inline: Copy {
    fn read(bytes: &[u8]) -> Result<Self, norito::Error>;
    fn field(value: CanonicalField<'_, Self>) -> Result<Self, DecodeIntoError<Infallible>> {
        value.with_payload(|bytes| Self::read(bytes).map_err(DecodeIntoError::Codec))
    }
}
pub(super) struct Fields;
impl FieldDestination for Fields {
    type Error = Infallible;
}
impl EnumFieldDestination for Fields {
    fn begin_variant(&mut self, _variant: u32) -> Result<(), Infallible> {
        Ok(())
    }
}
impl DecodeValueDestination<VoteKind> for Fields {
    fn restore_value(&mut self, value: VoteKind) {
        // The original closed unit enum is Copy and owns no allocation. Preserve
        // its unchanged final-framing refusal without inventing child custody.
        let _ = value;
    }
}
impl<const INDEX: usize, T: Inline> DecodeField<INDEX, T> for Fields {
    type Value = T;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Infallible>> {
        T::field(field)
    }
}
pub(super) fn read_field<T: Inline>(
    field: CanonicalField<'_, T>,
) -> Result<T, DecodeIntoError<Infallible>> {
    T::field(field)
}
impl Inline for u64 {
    fn read(bytes: &[u8]) -> Result<Self, norito::Error> {
        let (value, used) = Self::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(value)
    }
}
impl<const N: usize> Inline for [u8; N] {
    fn read(bytes: &[u8]) -> Result<Self, norito::Error> {
        bytes.try_into().map_err(|_| norito::Error::LengthMismatch)
    }
    fn field(value: CanonicalField<'_, Self>) -> Result<Self, DecodeIntoError<Infallible>> {
        // The shared generated raw-array specialization supplies exactly the
        // original tuple-field raw bytes, without a second framed-array route.
        value.decode_owned().map_err(DecodeIntoError::Codec)
    }
}
impl Inline for Hash32 {
    fn read(bytes: &[u8]) -> Result<Self, norito::Error> {
        let ((value,), used) =
            Self::decode_fields(bytes, &mut Fields).map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(Self(value))
    }
}
impl Inline for AggregateSignature {
    fn read(bytes: &[u8]) -> Result<Self, norito::Error> {
        let ((value,), used) =
            Self::decode_fields(bytes, &mut Fields).map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(Self(value))
    }
}
impl Inline for EpochId {
    fn read(bytes: &[u8]) -> Result<Self, norito::Error> {
        let ((epoch, context), used) =
            Self::decode_fields(bytes, &mut Fields).map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(Self { epoch, context })
    }
}
impl Inline for VoteKind {
    fn read(bytes: &[u8]) -> Result<Self, norito::Error> {
        let (value, used) =
            Self::decode_value_fields(bytes, &mut Fields).map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(value)
    }
}
