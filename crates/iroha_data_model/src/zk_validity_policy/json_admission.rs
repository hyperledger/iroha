//! One declaration-owned JSON field relation with original-pool ZK destinations.

use std::fmt;

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use norito::json::{self, JsonDeserialize};

use super::ZkValidityPolicyV1;

/// Original JSON/resource failure or exact physical admission refusal.
#[derive(Debug, thiserror::Error)]
pub enum ZkPolicyJsonAdmissionError {
    /// Original syntax, scalar or cumulative decoder cause.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// Original finite-pool or admitted allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}

/// Exact typed ZK projection and custody of every original verifying-key string.
///
/// The immutable value drops before its original charges and charged ledger.
/// Semantic policy validation and authenticated publication remain the caller's
/// responsibility. Enclosing record/source/error scratch is separately owned.
pub struct AdmittedZkValidityPolicy {
    value: ZkValidityPolicyV1,
    charges: ChargedBuffer<AllocationCharge>,
}
impl AdmittedZkValidityPolicy {
    /// Construct the protocol's allocation-free empty projection in this pool.
    /// This is only the documented default for an absent optional policy, never
    /// a substitute for an explicit malformed parameter or monetary authority.
    ///
    /// # Errors
    /// Preserves the original custody refusal; no input decoding is performed.
    pub fn try_protocol_default(
        budget: &AllocationBudget,
    ) -> Result<Self, ZkPolicyJsonAdmissionError> {
        let charges = ChargedBuffer::new(0, budget)?;
        Ok(Self {
            value: ZkValidityPolicyV1::protocol_default(),
            charges,
        })
    }

    /// Decode into original funded fields without cloning or restaging JSON.
    ///
    /// # Errors
    /// Preserves original JSON/resource/refusal identity and retires partial fields.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, ZkPolicyJsonAdmissionError> {
        let count = <ZkValidityPolicyV1 as Field<AdmittedDestination<'_>>>::MAX_CHARGES;
        let mut destination = AdmittedDestination {
            budget,
            charges: ChargedBuffer::new(count, budget)?,
        };
        let value = ZkValidityPolicyV1::decode_field(parser, &mut destination)?;
        Ok(Self {
            value,
            charges: destination.charges,
        })
    }
    /// Borrow exact typed fields without separating their original custody.
    #[must_use]
    pub fn get(&self) -> &ZkValidityPolicyV1 {
        &self.value
    }
    /// Check original finite-pool identity for the ledger and every retained field.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.charges.belongs_to(budget)
            && self
                .charges
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
    /// Count actual original field allocations, excluding ledger backing.
    #[must_use]
    pub fn allocation_count(&self) -> usize {
        self.charges.as_slice().len()
    }
    /// Transfer exact original fields and their already funded ledger.
    ///
    /// # Safety
    /// The recipient must retain immutable original allocations until destroying
    /// them before each original charge, with no growth/clone/escape. It separately
    /// admits its enclosing control/record and any replacement ledger backing.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(
        self,
    ) -> (ZkValidityPolicyV1, ChargedBuffer<AllocationCharge>) {
        (self.value, self.charges)
    }
}
impl fmt::Debug for AdmittedZkValidityPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AdmittedZkValidityPolicy")
            .field(self.get())
            .finish()
    }
}

pub(super) trait Destination {
    type Error: From<json::Error>;
    type KeyText: AsRef<str>;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::KeyText>, Self::Error>;
    fn parse_string(&mut self, parser: &mut json::Parser<'_>) -> Result<String, Self::Error>;
}
pub(super) struct OrdinaryDestination;
impl Destination for OrdinaryDestination {
    type Error = json::Error;
    type KeyText = String;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a>, Self::Error> {
        parser.parse_key()
    }
    fn parse_string(&mut self, parser: &mut json::Parser<'_>) -> Result<String, Self::Error> {
        parser.parse_string()
    }
}
struct AdmittedText(ChargedBuffer<u8>);
impl AsMut<[u8]> for AdmittedText {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl AsRef<str> for AdmittedText {
    fn as_ref(&self) -> &str {
        core::str::from_utf8(self.0.as_slice()).expect("shared JSON string kernel emits UTF-8")
    }
}
fn admit_text(
    length: usize,
    budget: &AllocationBudget,
) -> Result<AdmittedText, ZkPolicyJsonAdmissionError> {
    let mut text = ChargedBuffer::new(length, budget)?;
    for _ in 0..length {
        text.push_reserved(0);
    }
    Ok(AdmittedText(text))
}
struct AdmittedDestination<'a> {
    budget: &'a AllocationBudget,
    charges: ChargedBuffer<AllocationCharge>,
}
impl Destination for AdmittedDestination<'_> {
    type Error = ZkPolicyJsonAdmissionError;
    type KeyText = AdmittedText;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::KeyText>, Self::Error> {
        parser.parse_key_with_buffer(|length| admit_text(length, self.budget))
    }
    #[allow(unsafe_code)]
    fn parse_string(&mut self, parser: &mut json::Parser<'_>) -> Result<String, Self::Error> {
        let text = parser.parse_string_with_buffer(|length| admit_text(length, self.budget))?;
        // SAFETY: parser produced UTF-8 into this exact charged backing. The
        // private field relation moves the String into one immutable projection;
        // all partial Strings drop before this destination's ledger on failure.
        let (text, charge) = unsafe { text.0.into_allocation_parts() };
        let value = unsafe { String::from_utf8_unchecked(text) };
        self.charges.push_reserved(charge);
        Ok(value)
    }
}
pub(super) trait Field<D: Destination>: Sized {
    // Calculated from the same source field declarations as the decoder, not a
    // hand-maintained constant. Optional fields reserve their possible leaves.
    const MAX_CHARGES: usize;
    fn decode_field(parser: &mut json::Parser<'_>, destination: &mut D) -> Result<Self, D::Error>;
}
macro_rules! scalar_field {
    ($($type:ty),+ $(,)?) => { $(impl<D: Destination> Field<D> for $type {
        const MAX_CHARGES: usize = 0;
        fn decode_field(parser: &mut json::Parser<'_>, _destination: &mut D) -> Result<Self, D::Error> { Ok(<Self as JsonDeserialize>::json_deserialize(parser)?) }
    })+ };
}
scalar_field!(bool, u32, u64);
impl<D: Destination> Field<D> for String {
    const MAX_CHARGES: usize = 1;
    fn decode_field(parser: &mut json::Parser<'_>, destination: &mut D) -> Result<Self, D::Error> {
        destination.parse_string(parser)
    }
}
impl<T: Field<D>, D: Destination> Field<D> for Option<T> {
    const MAX_CHARGES: usize = T::MAX_CHARGES;
    fn decode_field(parser: &mut json::Parser<'_>, destination: &mut D) -> Result<Self, D::Error> {
        if parser.try_consume_null()? {
            Ok(None)
        } else {
            Ok(Some(T::decode_field(parser, destination)?))
        }
    }
}
// Every current ZK field is required, including the explicitly #[norito(required)]
// Option fields. This macro is invoked from the existing policy-section field
// declaration, and keeps one duplicate/unknown/missing-field relation for both
// ordinary and admitted destinations. New fields must implement Field, exposing
// their physical ownership rather than silently falling through to ordinary decode.
macro_rules! record_json {
    ($name:ident { $($field:ident: $type:ty),+ $(,)? }) => {
        impl<D: $crate::zk_validity_policy::json_admission::Destination>
            $crate::zk_validity_policy::json_admission::Field<D> for $name
        {
            const MAX_CHARGES: usize = 0 $(+ <$type as $crate::zk_validity_policy::json_admission::Field<D>>::MAX_CHARGES)+;
            fn decode_field(parser: &mut norito::json::Parser<'_>, destination: &mut D) -> Result<Self, D::Error> {
                use $crate::zk_validity_policy::json_admission::Field as _;
                parser.skip_ws(); parser.preflight_object_entries()?; parser.expect(b'{')?; parser.skip_ws();
                $(let mut $field: Option<$type> = None;)+
                if !parser.try_consume_char(b'}')? {
                    loop {
                        parser.skip_ws(); let key = destination.parse_key(parser)?;
                        let text = match &key { norito::json::KeyRef::Borrowed(text) => *text, norito::json::KeyRef::Owned(text) => text.as_ref() };
                        match text {
                            $(stringify!($field) => {
                                if $field.is_some() { return Err(norito::json::Error::duplicate_field(stringify!($field)).into()); }
                                $field = Some(<$type>::decode_field(parser, destination)?);
                            },)+
                            _ => return Err(norito::json::Error::unknown_field(text).into()),
                        }
                        parser.skip_ws(); if parser.try_consume_char(b',')? { continue; } parser.expect(b'}')?; break;
                    }
                }
                Ok(Self { $($field: $field.ok_or_else(|| norito::json::Error::missing_field(stringify!($field)))?,)+ })
            }
        }
        impl norito::json::JsonDeserialize for $name {
            fn json_deserialize(parser: &mut norito::json::Parser<'_>) -> Result<Self, norito::json::Error> {
                use $crate::zk_validity_policy::json_admission::Field as _;
                Self::decode_field(parser, &mut $crate::zk_validity_policy::json_admission::OrdinaryDestination)
            }
        }
    };
}
pub(super) use record_json;

#[cfg(test)]
mod tests;
