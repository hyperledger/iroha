//! Derived canonical field traversal shared by owned and prepared destinations.
//!
//! A destination controls custody only. The generated walk owns field order,
//! prefixes and complete consumption; complete framed canonical authentication
//! still requires the canonical frame verifier after the destination is filled.

use super::*;

/// Exact codec failure or a caller-owned destination refusal during one field walk.
#[derive(Debug)]
pub enum DecodeIntoError<E> {
    /// The unchanged canonical parser rejected or locally refused the original bytes.
    Codec(Error),
    /// The original prepared destination refused; no protocol classification is implied.
    Destination(E),
}
impl<E> From<Error> for DecodeIntoError<E> {
    fn from(error: Error) -> Self {
        Self::Codec(error)
    }
}
impl<E: std::fmt::Display> std::fmt::Display for DecodeIntoError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::Destination(error) => error.fmt(f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for DecodeIntoError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Destination(error) => Some(error),
        }
    }
}
impl DecodeIntoError<std::convert::Infallible> {
    /// Recover the sole original codec cause from an ordinary owned field walk.
    pub fn into_codec(self) -> Error {
        match self {
            Self::Codec(error) => error,
            Self::Destination(never) => match never {},
        }
    }
}

/// Destination-wide original refusal type shared by every field in one record.
pub trait FieldDestination {
    /// Local custody failure, kept distinct from canonical byte errors.
    type Error;
}
/// Receive one field selected by the record's sole derived positional traversal.
pub trait DecodeField<const INDEX: usize, T>: FieldDestination {
    /// Result retained by the generated walk; prepared writers normally return `()`.
    type Value;
    /// Decode into existing destination storage or return its original refusal.
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<Self::Value, DecodeIntoError<Self::Error>>;
}
/// Generated positional record kernel shared by ordinary and prepared decoding.
pub trait DecodeRecordFields<D: FieldDestination> {
    /// Field results; prepared destinations can make this a tuple of zero-sized values.
    type Values;
    /// Walk the original canonical field order with the currently advertised layout.
    ///
    /// Field and record bounds are checked by the sole shared framing kernel.
    /// The caller must install the original advertised frame flags and decode scope.
    fn decode_fields(
        bytes: &[u8],
        destination: &mut D,
    ) -> Result<(Self::Values, usize), DecodeIntoError<D::Error>>;
}

/// Materialize an opted-in enum or a whole-value-validated record from its sole
/// generated field traversal.
///
/// Each destination field must yield its actual declared type. The generated
/// walk checks complete framing before calling the original consuming validation
/// hook exactly once and returns that hook's actual, possibly normalized value.
/// A span-only or `()` destination cannot satisfy this materialization contract.
/// This does not authenticate a complete canonical frame or grant physical graph
/// custody. Enums return materialized children on later sibling `Result` errors
/// through [`DecodeVariantField::restore_variant_field`] and the complete actual
/// enum on final framing errors through [`DecodeValueDestination::restore_value`].
/// In particular, an allocating or consuming hook may drop a partially
/// reconstructed value on error; its original resource ownership remains the
/// caller's responsibility.
pub trait DecodeValueFields<D: FieldDestination>: Sized {
    /// Walk and reconstruct the actual value under the advertised payload scope.
    fn decode_value_fields(
        bytes: &[u8],
        destination: &mut D,
    ) -> Result<(Self, usize), DecodeIntoError<D::Error>>;
}

/// Receive an actual materialized value rejected by its final payload framing.
///
/// The generated enum has already constructed its original `Self` when final
/// framing fails. Returning that complete value preserves its own `Drop` and
/// child destruction order, including enums whose fields cannot be moved out.
/// This does not certify framing, semantic validity or physical graph custody.
pub trait DecodeValueDestination<T>: FieldDestination {
    /// Retain or drop the exact constructed value without changing its error.
    ///
    /// A retaining destination must use existing admitted storage and preserve
    /// every backing and charge without allocating or panicking. Ordinary
    /// [`OwnedFields`] explicitly drops the entire actual value. This covers
    /// final framing `Result` errors before a consuming validation hook; a hook
    /// error cannot return the value it consumed. Panic custody is not certified.
    fn restore_value(&mut self, value: T);
}

/// Destination receiving a known original enum discriminant before its fields.
pub trait EnumFieldDestination: FieldDestination {
    /// Select a valid declared variant, including unit variants.
    ///
    /// Unknown tags are rejected by the generated canonical parser before this
    /// callback. A local refusal remains distinct from a canonical byte error.
    fn begin_variant(&mut self, variant: u32) -> Result<(), Self::Error>;
}

/// Materialize one actual field of an original enum variant.
///
/// `VARIANT` is the original canonical u32 discriminant; `INDEX` is the field's
/// position within that variant. Direct byte arrays retain the ordinary enum's
/// raw-array specialization; other children use their canonical value framing.
pub trait DecodeVariantField<const VARIANT: u32, const INDEX: usize, T>:
    EnumFieldDestination
{
    /// Decode the complete original field into its actual declared type.
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Self::Error>>;

    /// Receive this exact materialized child after a later sibling error.
    ///
    /// The sole generated traversal moves the original `T`, without cloning,
    /// back to its original variant/field destination and returns the unchanged
    /// error. Earlier siblings are restored in reverse local order, matching
    /// ordinary owning destruction on this path. A complete enum rejected by
    /// final framing is returned through [`DecodeValueDestination`] instead.
    ///
    /// A retaining destination must use already admitted storage, preserve the
    /// child's original backing and charges, and neither allocate nor panic.
    /// Ordinary [`OwnedFields`] explicitly drops the returned value. This is a
    /// `Result` rollback contract, not a panic guard. A consuming whole-value
    /// validation hook owns `Self`; if it fails, its consumed children cannot be
    /// restored through this method. No complete frame or custody is certified.
    fn restore_variant_field(&mut self, value: T);
}

/// Ordinary custody implementation used by the same generated record traversal.
pub struct OwnedFields;
impl FieldDestination for OwnedFields {
    type Error = std::convert::Infallible;
}
impl<T> DecodeValueDestination<T> for OwnedFields {
    fn restore_value(&mut self, value: T) {
        drop(value);
    }
}
impl<const INDEX: usize, T> DecodeField<INDEX, T> for OwnedFields {
    type Value = T;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Self::Error>> {
        field.decode_owned().map_err(DecodeIntoError::Codec)
    }
}

impl EnumFieldDestination for OwnedFields {
    fn begin_variant(&mut self, _variant: u32) -> Result<(), Self::Error> {
        Ok(())
    }
}
impl<const VARIANT: u32, const INDEX: usize, T> DecodeVariantField<VARIANT, INDEX, T>
    for OwnedFields
{
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Self::Error>> {
        field.decode_owned().map_err(DecodeIntoError::Codec)
    }

    fn restore_variant_field(&mut self, value: T) {
        drop(value);
    }
}

/// A borrowed canonical field frame with the record's declared field type.
///
/// Construction is restricted to the shared framing functions. This does not
/// certify semantic validity: a prepared destination must use that type's
/// canonical decoder and the final filled record must pass exact frame checking.
/// It cannot outlive the actual input slice or expose an archived raw pointer.
pub struct CanonicalField<'a, T> {
    bytes: &'a [u8],
    decode: fn(&[u8]) -> Result<T, Error>,
    byte_array: bool,
}
impl<T> CanonicalField<'_, T> {
    /// Borrow the exact field payload after its canonical prefix was checked.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Decode with the same owning leaf used before destination support.
    pub fn decode_owned(self) -> Result<T, Error> {
        (self.decode)(self.bytes)
    }
    /// Run a prepared type decoder inside the same logical field/depth context.
    ///
    /// Unlike owned decoding this does not call an untrusted archived decoder;
    /// both borrow the field in place. The supplied operation must consume/check the
    /// complete field and use its prepared storage. Fixed byte arrays keep the
    /// existing raw-field behavior and do not acquire an extra depth or budget.
    pub fn with_payload<R, E>(
        self,
        decode: impl FnOnce(&[u8]) -> Result<R, DecodeIntoError<E>>,
    ) -> Result<R, DecodeIntoError<E>> {
        if self.byte_array {
            return decode(self.bytes);
        }
        check_decode_field_length(
            u64::try_from(self.bytes.len()).map_err(|_| Error::LengthMismatch)?,
        )?;
        let _depth = DecodeDepthGuard::enter()?;
        let _flags = enter_field_codec_flags();
        let _context = PayloadCtxGuard::enter(self.bytes);
        let _boundary = FieldDecodeBoundaryGuard::enter(FieldDecodeBoundary::Canonical);
        decode(self.bytes)
    }
}

/// Borrow the active original record slice; used only by generated owned decoding.
#[doc(hidden)]
pub fn with_context_fields<R>(
    ptr: *const u8,
    body: impl for<'a> FnOnce(&'a [u8]) -> R,
) -> Result<R, Error> {
    Ok(body(payload_slice_from_ptr(ptr)?))
}
/// Read a normal positional field using the sole canonical prefix kernel.
#[doc(hidden)]
pub fn framed_field<'a, T>(
    payload: &'a [u8],
    offset: &mut usize,
) -> Result<CanonicalField<'a, T>, Error>
where
    T: for<'de> crate::DeserializePayload<'de> + crate::SerializePayload,
{
    let (bytes, next) = take_length_prefixed_field(payload, *offset)?;
    *offset = next;
    Ok(canonical_field_from_slice(bytes))
}
/// Keep the owning leaf relation shared by normal fields and sequence elements.
pub(super) fn canonical_field_from_slice<T>(bytes: &[u8]) -> CanonicalField<'_, T>
where
    T: for<'de> crate::DeserializePayload<'de> + crate::SerializePayload,
{
    CanonicalField {
        bytes,
        decode: |bytes| {
            let (value, used) = decode_field_canonical::<T>(bytes)?;
            if used != bytes.len() {
                return Err(Error::LengthMismatch);
            }
            Ok(value)
        },
        byte_array: false,
    }
}
/// Read a fixed byte-array field using its exact existing raw payload geometry.
#[doc(hidden)]
pub fn framed_byte_array_field<'a, const N: usize>(
    payload: &'a [u8],
    offset: &mut usize,
) -> Result<CanonicalField<'a, [u8; N]>, Error> {
    let (bytes, next) = take_length_prefixed_field(payload, *offset)?;
    if bytes.len() != N {
        return Err(Error::LengthMismatch);
    }
    *offset = next;
    Ok(CanonicalField {
        bytes,
        decode: |bytes| bytes.try_into().map_err(|_| Error::LengthMismatch),
        byte_array: true,
    })
}

/// A prepared record whose canonical payload can be inspected without extraction.
///
/// Implementations must retain all original initialized backing when resetting.
/// Serialization must borrow exactly the filled fields in their canonical order;
/// the declared wire type supplies the identity and alignment, never this owner.
pub trait PreparedRecordDestination<T>: FieldDestination + SerializePayload {
    /// Clear validity/initialized-prefix metadata without replacing, dropping or
    /// refunding any prepared backing. Called before every attempt and on failure.
    fn reset(&mut self);
}
