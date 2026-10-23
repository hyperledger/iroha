//! One crypto-policy JSON field kernel with ordinary and original-pool destinations.

use std::{alloc::Layout, fmt};

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use norito::json::{self, JsonDeserialize};

use super::{Algorithm, CryptoAdmissionPolicyV1};

/// Original JSON/resource cause or exact physical admission refusal.
#[derive(Debug, thiserror::Error)]
pub enum CryptoPolicyJsonAdmissionError {
    /// The original parser, validation or enclosing decoder refusal.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// The original finite-pool or already admitted allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}

/// Immutable decoded crypto policy with custody of its exact algorithm array.
///
/// The value is stored inline and drops before its original allocation charge.
/// There is no Clone, mutation or safe extraction. The enclosing owner must fund
/// its own record/control, source and diagnostic storage; this leaf is neither a
/// signed-genesis capability nor permission to publish a parameter update.
pub struct AdmittedCryptoAdmissionPolicy {
    value: CryptoAdmissionPolicyV1,
    charge: AllocationCharge,
}
impl AdmittedCryptoAdmissionPolicy {
    /// Decode directly from the caller's parser and unchanged cumulative context.
    ///
    /// String keys and algorithm text use the same original finite pool; their
    /// temporary backing retires after each field. The sole Norito array/string
    /// kernels perform lexical decoding without a Value tree or reserialization.
    ///
    /// # Errors
    /// Returns the exact original JSON or physical admission cause.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, CryptoPolicyJsonAdmissionError> {
        decode_record(parser, &mut AdmittedDestination { budget })
    }

    /// Borrow the validated value without separating its original custody.
    #[must_use]
    pub fn get(&self) -> &CryptoAdmissionPolicyV1 {
        &self.value
    }

    /// Check the exact original finite-pool identity of the retained array.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.charge.belongs_to(budget)
    }

    /// Move the original array and its exact charge into an enclosing admitted graph.
    ///
    /// # Safety
    /// The recipient must keep this exact array immutable, without clone/growth or
    /// escape, until it is destroyed before this original charge. Its own storage
    /// and charge-ledger backing must already be funded; this move acquires nothing.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(self) -> (CryptoAdmissionPolicyV1, AllocationCharge) {
        (self.value, self.charge)
    }
}
impl fmt::Debug for AdmittedCryptoAdmissionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AdmittedCryptoAdmissionPolicy")
            .field(self.get())
            .finish()
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
        core::str::from_utf8(self.0.as_slice()).expect("the sole JSON string kernel emits UTF-8")
    }
}
fn admit_text(
    length: usize,
    budget: &AllocationBudget,
) -> Result<AdmittedText, CryptoPolicyJsonAdmissionError> {
    // Parser::parse_string_with_buffer already reserves the cumulative decoder
    // demand before invoking this physical destination. Do not charge it twice.
    let mut text = ChargedBuffer::new(length, budget)?;
    for _ in 0..length {
        text.push_reserved(0);
    }
    Ok(AdmittedText(text))
}

trait Destination {
    type Error: From<json::Error>;
    type Text: AsRef<str>;
    type Algorithms;
    type Output;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::Text>, Self::Error>;
    fn parse_algorithms(
        &mut self,
        parser: &mut json::Parser<'_>,
    ) -> Result<Self::Algorithms, Self::Error>;
    fn finish(&mut self, algorithms: Self::Algorithms) -> Result<Self::Output, Self::Error>;
}
struct OrdinaryDestination;
impl Destination for OrdinaryDestination {
    type Error = json::Error;
    type Text = String;
    type Algorithms = Vec<Algorithm>;
    type Output = CryptoAdmissionPolicyV1;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a>, Self::Error> {
        parser.parse_key()
    }
    fn parse_algorithms(
        &mut self,
        parser: &mut json::Parser<'_>,
    ) -> Result<Self::Algorithms, Self::Error> {
        Vec::<Algorithm>::json_deserialize(parser)
    }
    fn finish(&mut self, algorithms: Self::Algorithms) -> Result<Self::Output, Self::Error> {
        CryptoAdmissionPolicyV1::new(algorithms)
            .map_err(|error| json::Error::Message(error.to_string()))
    }
}
struct AdmittedDestination<'a> {
    budget: &'a AllocationBudget,
}
impl Destination for AdmittedDestination<'_> {
    type Error = CryptoPolicyJsonAdmissionError;
    type Text = AdmittedText;
    type Algorithms = ChargedBuffer<Algorithm>;
    type Output = AdmittedCryptoAdmissionPolicy;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::Text>, Self::Error> {
        parser.parse_key_with_buffer(|length| admit_text(length, self.budget))
    }
    fn parse_algorithms(
        &mut self,
        parser: &mut json::Parser<'_>,
    ) -> Result<Self::Algorithms, Self::Error> {
        parser.parse_array_with(
            |entries| {
                let bytes = entries
                    .checked_mul(core::mem::size_of::<Algorithm>())
                    .ok_or(json::Error::DecodeResourceLimit)?;
                norito::core::reserve_decode_allocation(bytes)
                    .map_err(json::Error::from_decode_resource)?;
                Ok::<_, Self::Error>(ChargedBuffer::new(entries, self.budget)?)
            },
            |parser| {
                let text =
                    parser.parse_string_with_buffer(|length| admit_text(length, self.budget))?;
                text.as_ref().parse::<Algorithm>().map_err(|_| {
                    json::Error::Message(format!("unknown algorithm '{}'", text.as_ref())).into()
                })
            },
            |output, algorithm| output.push_reserved(algorithm),
        )
    }
    #[allow(unsafe_code)]
    fn finish(&mut self, algorithms: Self::Algorithms) -> Result<Self::Output, Self::Error> {
        // SAFETY: move the original fixed array and charge together into the
        // private owner; its value always drops before its original charge.
        let (algorithms, charge) = unsafe { algorithms.into_allocation_parts() };
        let owner = AdmittedCryptoAdmissionPolicy {
            value: CryptoAdmissionPolicyV1 {
                allowed_algorithms: algorithms,
            },
            charge,
        };
        owner
            .get()
            .validate()
            .map_err(|error| json::Error::Message(error.to_string()))?;
        debug_assert_eq!(
            owner.charge.layout(),
            Layout::array::<Algorithm>(owner.value.allowed_algorithms.capacity())
                .expect("admitted exact array")
        );
        Ok(owner)
    }
}

pub(super) fn decode_ordinary(
    parser: &mut json::Parser<'_>,
) -> Result<CryptoAdmissionPolicyV1, json::Error> {
    decode_record(parser, &mut OrdinaryDestination)
}

// The former named-field derive's relation remains one kernel: object preflight,
// duplicate/unknown rejection before value parsing, then declaration-order missing
// fields and semantic policy validation. Both destinations execute these steps.
fn decode_record<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &mut D,
) -> Result<D::Output, D::Error> {
    parser.skip_ws();
    parser.preflight_object_entries()?;
    parser.expect(b'{')?;
    parser.skip_ws();
    let mut algorithms = None;
    if !parser.try_consume_char(b'}')? {
        loop {
            parser.skip_ws();
            let key = destination.parse_key(parser)?;
            let text = match &key {
                json::KeyRef::Borrowed(text) => *text,
                json::KeyRef::Owned(text) => text.as_ref(),
            };
            match text {
                "allowed_algorithms" => {
                    if algorithms.is_some() {
                        return Err(json::Error::duplicate_field("allowed_algorithms").into());
                    }
                    algorithms = Some(destination.parse_algorithms(parser)?);
                }
                _ => return Err(json::Error::unknown_field(text).into()),
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.expect(b'}')?;
            break;
        }
    }
    destination.finish(algorithms.ok_or_else(|| json::Error::missing_field("allowed_algorithms"))?)
}

#[cfg(test)]
mod tests;
