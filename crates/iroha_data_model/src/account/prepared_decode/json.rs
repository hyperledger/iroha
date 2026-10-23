//! Direct I105 JSON leaf ingress using the sole prefix/radix/controller decoder.

use std::alloc::Layout;

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_crypto::{
    Algorithm, ChargedPublicKey, PreparedPublicKeyDecode, PublicKeyDecodeAdmissionError,
};
use norito::json;

use super::{ChargedAccount, ControllerCustody, MemberParts, bind_single};
use crate::account::{
    AccountAddressError, AccountController, AccountId, MultisigMember, MultisigPolicy,
    address::{
        self,
        decode::{BufferDestination, Destination, Work},
    },
    curve::CurveId,
};

/// Original JSON refusal or an independent original-pool/physical refusal.
#[derive(Debug, thiserror::Error)]
pub enum AccountJsonAdmissionError {
    /// Exact original syntax, key capability or cumulative decoder cause.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// Original finite pool or allocator rejected exact temporary/retained backing.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}

/// Original address failure or exact original-pool refusal for borrowed I105 input.
#[derive(Debug, thiserror::Error)]
pub enum AccountLiteralAdmissionError {
    /// Original address syntax, key capability or cumulative decoder failure.
    #[error(transparent)]
    Address(#[from] AccountAddressError),
    /// Original finite-pool or physical allocation refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}
impl From<AccountLiteralAdmissionError> for AccountJsonAdmissionError {
    fn from(error: AccountLiteralAdmissionError) -> Self {
        match error {
            AccountLiteralAdmissionError::Allocation(error) => Self::Allocation(error),
            AccountLiteralAdmissionError::Address(error) => Self::Json(match error {
                AccountAddressError::UnsupportedImplementation(original) => {
                    json::Error::UnsupportedFeature(original.algorithm.as_static_str())
                }
                error if error.is_decode_resource_limit() => {
                    address::map_account_address_json_error(error)
                }
                _ => crate::account::invalid_account_id_json(),
            }),
        }
    }
}
struct Text(ChargedBuffer<u8>);
impl AsMut<[u8]> for Text {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl ChargedAccount {
    /// Decode canonical I105 directly from the original JSON cursor and pool.
    ///
    /// String unescaping, radix/checksum work, numeric-prefix ambiguity checks,
    /// canonical re-encoding and controller parsing share ordinary kernels. Every
    /// temporary allocation uses this original pool before use. The returned
    /// immutable owner retains exactly the compact key/member allocations; all
    /// temporary storage has retired. Source bytes, enclosing records, controls
    /// and whole-document boundaries remain the caller's responsibility.
    ///
    /// # Errors
    /// Preserves original observer/capability errors and physical refusal. No
    /// default account or partially decoded account is returned on failure.
    pub(crate) fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, AccountJsonAdmissionError> {
        let text = parser.parse_string_with_buffer(|length| {
            let mut buffer = ChargedBuffer::new(length, budget)?;
            for _ in 0..length {
                buffer.push_reserved(0);
            }
            Ok::<_, AccountJsonAdmissionError>(Text(buffer))
        })?;
        let literal = std::str::from_utf8(text.0.as_slice())
            .map_err(|_| crate::account::invalid_account_id_json())?;
        crate::account::reserve_account_literal_json_decode(literal.len())?;
        address::decode::account_literal(literal, &Admitted { budget }).map_err(Into::into)
    }

    /// Decode borrowed I105 text with an explicit chain-prefix policy.
    ///
    /// This is the original-pool counterpart of `AccountAddress::parse_encoded`.
    /// `None` accepts the unambiguous canonical embedded chain and does not read
    /// the node's configured chain discriminant. No JSON string or ordinary
    /// account is staged. The caller owns the borrowed source and enclosing state.
    ///
    /// # Errors
    /// Preserves the exact address error or original physical allocation refusal.
    pub fn try_from_encoded(
        input: &str,
        expected_discriminant: Option<u16>,
        budget: &AllocationBudget,
    ) -> Result<Self, AccountLiteralAdmissionError> {
        address::decode::encoded_literal(input, expected_discriminant, &Admitted { budget })
    }

    /// Borrow the account while retaining the exact backing and original charges.
    pub fn get(&self) -> &AccountId {
        &self.value
    }

    /// Whether every controller backing still belongs to the exact original pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.custody.belongs_to(budget)
    }

    /// Transfer unchanged controller storage and its exact original custody.
    ///
    /// # Safety
    /// Immediately bind both fields into a move-only immutable owner that destroys
    /// the account before its custody on all paths. Do not mutate or move backing
    /// elsewhere while its charge stays behind. Ordinary clones need new custody.
    #[allow(unsafe_code)]
    pub(crate) unsafe fn into_allocation_parts(self) -> (AccountId, ControllerCustody) {
        (self.value, self.custody)
    }
}

struct Admitted<'a> {
    budget: &'a AllocationBudget,
}
struct Members {
    values: ChargedBuffer<MultisigMember>,
    keys: ChargedBuffer<AllocationCharge>,
}
fn logical<T>(capacity: usize) -> Result<(), AccountLiteralAdmissionError> {
    let layout =
        Layout::array::<T>(capacity).map_err(|_| AccountAddressError::DecodeResourceLimit)?;
    norito::core::reserve_decode_allocation(layout.size())
        .map_err(AccountAddressError::from_decode_error)?;
    Ok(())
}
impl BufferDestination for Admitted<'_> {
    type Error = AccountLiteralAdmissionError;
    fn buffer<T>(&self, capacity: usize) -> Result<Work<T>, Self::Error> {
        logical::<T>(capacity)?;
        Ok(Work::admitted(ChargedBuffer::new(capacity, self.budget)?))
    }
}
impl Destination for Admitted<'_> {
    type Key = ChargedPublicKey;
    type Members = Members;
    type Controller = ChargedAccount;
    fn is_resource(error: &Self::Error) -> bool {
        match error {
            AccountLiteralAdmissionError::Allocation(_) => true,
            AccountLiteralAdmissionError::Address(error) => error.is_decode_resource_limit(),
        }
    }
    fn encoded_error(error: Self::Error) -> Self::Error {
        match error {
            Self::Error::Address(AccountAddressError::MissingI105Sentinel) => {
                AccountAddressError::UnsupportedAddressFormat.into()
            }
            other => other,
        }
    }
    fn key(&self, algorithm: Algorithm, payload: &[u8]) -> Result<Self::Key, Self::Error> {
        algorithm
            .require_implementation(iroha_crypto::CryptoOperation::ParsePublicKey)
            .map_err(AccountAddressError::UnsupportedImplementation)?;
        PreparedPublicKeyDecode::try_from_material_for_decode(algorithm, payload, self.budget)
            .map_err(|error| match error {
                PublicKeyDecodeAdmissionError::Codec(error) => {
                    AccountLiteralAdmissionError::Address(AccountAddressError::from_decode_error(
                        error,
                    ))
                }
                PublicKeyDecodeAdmissionError::Allocation(error) => {
                    AccountLiteralAdmissionError::Allocation(error)
                }
            })
    }
    fn members(&self, count: usize) -> Result<Self::Members, Self::Error> {
        logical::<MultisigMember>(count)?;
        logical::<AllocationCharge>(count)?;
        // The partial values retire before their per-key custody; no key exists yet.
        let values = ChargedBuffer::new(count, self.budget)?;
        let keys = ChargedBuffer::new(count, self.budget)?;
        Ok(Members { values, keys })
    }
    #[allow(unsafe_code)]
    fn push(
        &self,
        members: &mut Self::Members,
        _curve: CurveId,
        weight: u16,
        key: Self::Key,
    ) -> Result<(), Self::Error> {
        // SAFETY: the constructor either destroys the key before returning its
        // error, or the existing allocation is immediately paired with this charge
        // in the value-first Members owner. Capacity was selected before key decode.
        let (key, charge) = unsafe { key.into_allocation_parts() };
        let member =
            MultisigMember::new(key, weight).map_err(AccountAddressError::InvalidMultisigPolicy)?;
        members.values.push_reserved(member);
        members.keys.push_reserved(charge);
        Ok(())
    }
    fn single(&self, _curve: CurveId, key: Self::Key) -> Result<Self::Controller, Self::Error> {
        Ok(bind_single(key))
    }
    fn multisig(
        &self,
        version: u8,
        threshold: u16,
        members: Self::Members,
    ) -> Result<Self::Controller, Self::Error> {
        MultisigPolicy::validate_canonical_members(
            version,
            threshold,
            members
                .values
                .as_slice()
                .iter()
                .map(|member| (member.public_key(), member.weight())),
        )
        .map_err(AccountAddressError::InvalidMultisigPolicy)?;
        let mut parts = MemberParts::new(members.values, members.keys);
        let values = parts
            .members
            .take()
            .expect("new MemberParts owns its member array");
        let policy = MultisigPolicy::from_serialized(version, threshold, values)
            .map_err(AccountAddressError::InvalidMultisigPolicy)?;
        Ok(ChargedAccount {
            value: AccountId {
                controller: AccountController::Multisig(policy),
            },
            custody: ControllerCustody::Multisig {
                members: parts.charge,
                keys: parts.keys,
            },
        })
    }
}

#[cfg(test)]
mod tests;
