//! One canonical original-pool controller decoder shared by native payment evidence owners.
//!
//! Partial member storage, keys, spans and actual allocation charges survive local refusal.
//! This internal value decoder authenticates no ledger state. Its caller owns original immutable
//! bytes, canonical workspace, root framing and final stream comparison.

use super::{AccountController, AccountId, MultisigMember, MultisigPolicy};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_crypto::{
    ChargedPublicKey, PreparedPublicKeyDecode, PublicKey, PublicKeyDecodeAdmissionError,
};
use norito::core::{self as ncore, DecodeIntoError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum AccountDecodeError {
    #[error(transparent)]
    Multisig(#[from] super::MultisigPolicyError),
    #[error(transparent)]
    Codec(#[from] norito::Error),
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    #[error("canonical account destination: {0}")]
    Invariant(&'static str),
}
use AccountDecodeError as Error;
impl From<DecodeIntoError<Error>> for Error {
    fn from(error: DecodeIntoError<Error>) -> Self {
        match error {
            DecodeIntoError::Codec(error) => Self::Codec(error),
            DecodeIntoError::Destination(error) => error,
        }
    }
}
impl From<PublicKeyDecodeAdmissionError> for Error {
    fn from(error: PublicKeyDecodeAdmissionError) -> Self {
        match error {
            PublicKeyDecodeAdmissionError::Codec(error) => Self::Codec(error),
            PublicKeyDecodeAdmissionError::Allocation(error) => Self::Allocation(error),
        }
    }
}
impl From<ncore::SequenceAdmissionError> for Error {
    fn from(error: ncore::SequenceAdmissionError) -> Self {
        match error {
            ncore::SequenceAdmissionError::Codec(error) => Self::Codec(error),
            ncore::SequenceAdmissionError::Allocation(error) => Self::Allocation(error),
        }
    }
}
impl From<ncore::RetainedSequenceError> for Error {
    fn from(error: ncore::RetainedSequenceError) -> Self {
        match error {
            ncore::RetainedSequenceError::Admission(error) => error.into(),
            ncore::RetainedSequenceError::SourceMismatch => {
                Self::Invariant("original member sequence changed")
            }
            ncore::RetainedSequenceError::Incomplete => {
                Self::Invariant("unfinished member sequence")
            }
        }
    }
}
fn destination(error: Error) -> DecodeIntoError<Error> {
    match error {
        Error::Codec(error) => DecodeIntoError::Codec(error),
        error => DecodeIntoError::Destination(error),
    }
}
pub(crate) enum ControllerCustody {
    Single(AllocationCharge),
    Multisig {
        members: AllocationCharge,
        keys: ChargedBuffer<AllocationCharge>,
    },
}
impl ControllerCustody {
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        match self {
            Self::Single(charge) => charge.belongs_to(budget),
            Self::Multisig { members, keys } => {
                members.belongs_to(budget)
                    && keys.belongs_to(budget)
                    && keys
                        .as_slice()
                        .iter()
                        .all(|charge| charge.belongs_to(budget))
            }
        }
    }
    pub(crate) fn bytes(&self) -> Option<usize> {
        match self {
            Self::Single(charge) => Some(charge.layout().size()),
            Self::Multisig { members, keys } => {
                let ledger = std::alloc::Layout::array::<AllocationCharge>(keys.capacity())
                    .ok()?
                    .size();
                keys.as_slice()
                    .iter()
                    .try_fold(members.layout().size().checked_add(ledger)?, |sum, key| {
                        sum.checked_add(key.layout().size())
                    })
            }
        }
    }
}
pub(crate) struct ChargedAccount {
    pub(crate) value: AccountId,
    pub(crate) custody: ControllerCustody,
}
struct ChargedMember {
    value: MultisigMember,
    pub(crate) charge: AllocationCharge,
}
pub(crate) struct ChargedPolicy {
    pub(crate) value: MultisigPolicy,
    custody: ControllerCustody,
}

fn field<T, R>(
    bytes: &[u8],
    offset: &mut usize,
    read: impl FnOnce(&[u8]) -> Result<R, Error>,
) -> Result<R, Error>
where
    T: for<'de> norito::DeserializePayload<'de> + norito::SerializePayload,
{
    ncore::framed_field::<T>(bytes, offset)?
        .with_payload(|bytes| read(bytes).map_err(destination))
        .map_err(Error::from)
}
fn scalar<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: for<'de> ncore::DecodeFromSlice<'de>,
{
    let (value, used) = T::decode_from_slice(bytes)?;
    finish(bytes, used)?;
    Ok(value)
}
fn finish(bytes: &[u8], used: usize) -> Result<(), Error> {
    if used != bytes.len() {
        return Err(norito::Error::LengthMismatch.into());
    }
    ncore::finish_context_fields(bytes.as_ptr(), used)?;
    Ok(())
}
fn tag(bytes: &[u8]) -> Result<u32, Error> {
    let raw = bytes.get(..4).ok_or(norito::Error::LengthMismatch)?;
    Ok(u32::from_le_bytes(
        raw.try_into().map_err(|_| norito::Error::LengthMismatch)?,
    ))
}
fn invalid_tag() -> Error {
    norito::Error::Message("invalid enum discriminant".into()).into()
}
pub(crate) struct AccountDestination {
    pub(crate) complete: Option<ChargedAccount>,
    pub(crate) key: Option<ChargedPublicKey>,
    pub(crate) policy: PolicyDestination,
}
impl AccountDestination {
    pub(crate) fn new(budget: &AllocationBudget) -> Self {
        Self {
            complete: None,
            key: None,
            policy: PolicyDestination::new(budget),
        }
    }
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.key.as_ref().is_none_or(|key| key.belongs_to(budget))
            && self.policy.belongs_to(budget)
            && self
                .complete
                .as_ref()
                .is_none_or(|account| account.custody.belongs_to(budget))
    }
    pub(crate) fn decode(
        &mut self,
        bytes: &[u8],
        budget: &AllocationBudget,
        cached: Option<&AccountId>,
    ) -> Result<(), Error> {
        let cached = cached.or_else(|| self.complete.as_ref().map(|account| &account.value));
        let mut offset = 4;
        match tag(bytes)? {
            0 => {
                let original = ncore::framed_field::<PublicKey>(bytes, &mut offset)?;
                original.with_payload(|bytes| {
                    if let Some(account) = cached {
                        PreparedPublicKeyDecode::recheck_payload(
                            bytes,
                            account.try_signatory().ok_or_else(|| {
                                destination(Error::Invariant("original account controller changed"))
                            })?,
                        )
                        .map_err(DecodeIntoError::Codec)?;
                    } else if let Some(key) = self.key.as_ref() {
                        PreparedPublicKeyDecode::recheck_payload(bytes, key.get())
                            .map_err(DecodeIntoError::Codec)?;
                    } else {
                        self.key = Some(
                            PreparedPublicKeyDecode::try_decode_payload(bytes, budget)
                                .map_err(|error| destination(error.into()))?,
                        );
                    }
                    Ok(())
                })?;
                finish(bytes, offset)?;
                if cached.is_some() {
                    return Ok(());
                }
                let key = self
                    .key
                    .take()
                    .ok_or(Error::Invariant("missing original account key"))?;
                self.complete = Some(bind_single(key));
            }
            1 => {
                let policy = cached
                    .map(|account| match account.controller() {
                        AccountController::Multisig(policy) => Ok(policy),
                        _ => Err(Error::Invariant("original account controller changed")),
                    })
                    .transpose()?;
                field::<MultisigPolicy, _>(bytes, &mut offset, |bytes| {
                    self.policy.decode(bytes, budget, policy)
                })?;
                finish(bytes, offset)?;
                if cached.is_some() {
                    return Ok(());
                }
                let policy = self
                    .policy
                    .complete
                    .take()
                    .ok_or(Error::Invariant("missing original multisig policy"))?;
                self.complete = Some(ChargedAccount {
                    value: AccountId {
                        controller: AccountController::Multisig(policy.value),
                    },
                    custody: policy.custody,
                });
            }
            _ => return Err(invalid_tag()),
        }
        Ok(())
    }
}
#[allow(unsafe_code)]
fn bind_single(key: ChargedPublicKey) -> ChargedAccount {
    // SAFETY: immediately transfer both fields into one immutable value-first
    // owner. Constructing AccountId/Single only moves the existing compact Box.
    let (key, charge) = unsafe { key.into_allocation_parts() };
    ChargedAccount {
        value: AccountId {
            controller: AccountController::Single(key),
        },
        custody: ControllerCustody::Single(charge),
    }
}
pub(crate) struct PolicyDestination {
    complete: Option<ChargedPolicy>,
    pub(crate) members: MembersDestination,
}
impl PolicyDestination {
    fn new(budget: &AllocationBudget) -> Self {
        Self {
            complete: None,
            members: MembersDestination::new(budget),
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.members.belongs_to(budget)
            && self
                .complete
                .as_ref()
                .is_none_or(|policy| policy.custody.belongs_to(budget))
    }
    fn decode(
        &mut self,
        bytes: &[u8],
        budget: &AllocationBudget,
        cached: Option<&MultisigPolicy>,
    ) -> Result<(), Error> {
        let cached = cached.or_else(|| self.complete.as_ref().map(|policy| &policy.value));
        let mut offset = 0;
        let version = field::<u8, _>(bytes, &mut offset, scalar::<u8>)?;
        let threshold = field::<u16, _>(bytes, &mut offset, scalar::<u16>)?;
        field::<Vec<MultisigMember>, _>(bytes, &mut offset, |bytes| {
            self.members
                .decode(bytes, budget, cached.map(MultisigPolicy::members))
        })?;
        finish(bytes, offset)?;
        if cached.is_some() {
            return Ok(());
        }
        let original = self
            .members
            .members
            .as_ref()
            .ok_or(Error::Invariant("missing original member values"))?;
        MultisigPolicy::validate_canonical_members(
            version,
            threshold,
            original
                .as_slice()
                .iter()
                .map(|member| (member.public_key(), member.weight())),
        )
        .map_err(policy_error)?;
        let members = self
            .members
            .members
            .take()
            .ok_or(Error::Invariant("missing original member values"))?;
        let keys = self
            .members
            .keys
            .take()
            .ok_or(Error::Invariant("missing original member ledger"))?;
        self.complete = Some(MemberParts::new(members, keys).finish(version, threshold)?);
        Ok(())
    }
}
pub(crate) struct MembersDestination {
    pub(crate) members: Option<ChargedBuffer<MultisigMember>>,
    pub(crate) keys: Option<ChargedBuffer<AllocationCharge>>,
    pub(crate) key: Option<ChargedPublicKey>,
    spans: ncore::RetainedElementSequence,
}
impl MembersDestination {
    pub(crate) fn new(budget: &AllocationBudget) -> Self {
        Self {
            members: None,
            keys: None,
            key: None,
            spans: ncore::RetainedElementSequence::new(budget),
        }
    }

    /// Exact original member-span backing size for crate tests.
    #[cfg(test)]
    pub(crate) fn span_allocation_bytes(&self) -> Option<usize> {
        self.spans.allocation_bytes()
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.spans.belongs_to(budget)
            && self
                .members
                .as_ref()
                .is_none_or(|members| members.belongs_to(budget))
            && self.keys.as_ref().is_none_or(|keys| {
                keys.belongs_to(budget) && keys.as_slice().iter().all(|key| key.belongs_to(budget))
            })
            && self.key.as_ref().is_none_or(|key| key.belongs_to(budget))
    }
    pub(crate) fn decode(
        &mut self,
        bytes: &[u8],
        budget: &AllocationBudget,
        cached: Option<&[MultisigMember]>,
    ) -> Result<(), Error> {
        self.spans.prepare(bytes)?;
        let prepared = self.spans.as_prepared(bytes)?;
        if prepared.used() != bytes.len() {
            return Err(norito::Error::LengthMismatch.into());
        }
        let count = prepared.len();
        if cached.is_some_and(|members| members.len() != count) {
            return Err(Error::Invariant("original member count changed"));
        }
        prepared.decode_elements::<MultisigMember, Error>(|index, field| {
            if let Some(members) = cached {
                return field.with_payload(|bytes| {
                    member(bytes, budget, &mut self.key, Some(&members[index]))
                        .map(|_| ())
                        .map_err(destination)
                });
            }
            if self.members.is_none() {
                self.members = Some(
                    ChargedBuffer::new(count, budget).map_err(|error| destination(error.into()))?,
                );
            }
            if self.keys.is_none() {
                self.keys = Some(
                    ChargedBuffer::new(count, budget).map_err(|error| destination(error.into()))?,
                );
            }
            let members = self
                .members
                .as_mut()
                .ok_or_else(|| destination(Error::Invariant("missing member destination")))?;
            let keys = self
                .keys
                .as_mut()
                .ok_or_else(|| destination(Error::Invariant("missing member ledger")))?;
            if members.as_slice().len() != keys.as_slice().len()
                || members.capacity() != count
                || keys.capacity() != count
            {
                return Err(destination(Error::Invariant(
                    "original member/charge destination changed",
                )));
            }
            if index < members.as_slice().len() {
                return field.with_payload(|bytes| {
                    member(
                        bytes,
                        budget,
                        &mut self.key,
                        Some(&members.as_slice()[index]),
                    )
                    .map(|_| ())
                    .map_err(destination)
                });
            }
            if index != members.as_slice().len() {
                return Err(destination(Error::Invariant(
                    "original member order changed",
                )));
            }
            let member = field
                .with_payload(|bytes| {
                    member(bytes, budget, &mut self.key, None).map_err(destination)
                })?
                .ok_or_else(|| destination(Error::Invariant("missing new member value")))?;
            members.push_reserved(member.value);
            keys.push_reserved(member.charge);
            Ok(())
        })?;
        if cached.is_none() && count == 0 {
            if self.members.is_none() {
                self.members = Some(ChargedBuffer::new(0, budget)?);
            }
            if self.keys.is_none() {
                self.keys = Some(ChargedBuffer::new(0, budget)?);
            }
        }
        Ok(())
    }
}
pub(crate) struct MemberParts {
    pub(crate) members: Option<Vec<MultisigMember>>,
    pub(crate) charge: AllocationCharge,
    pub(crate) keys: ChargedBuffer<AllocationCharge>,
}
impl MemberParts {
    #[allow(unsafe_code)]
    pub(crate) fn new(
        members: ChargedBuffer<MultisigMember>,
        keys: ChargedBuffer<AllocationCharge>,
    ) -> Self {
        // SAFETY: immediately pair original canonical values with their actual
        // member allocation and each key charge, without callbacks or clones.
        let (members, charge) = unsafe { members.into_allocation_parts() };
        Self {
            members: Some(members),
            charge,
            keys,
        }
    }
    pub(crate) fn finish(mut self, version: u8, threshold: u16) -> Result<ChargedPolicy, Error> {
        let members = self
            .members
            .take()
            .ok_or(Error::Invariant("missing original member values"))?;
        let value =
            MultisigPolicy::from_serialized(version, threshold, members).map_err(policy_error)?;
        Ok(ChargedPolicy {
            value,
            custody: ControllerCustody::Multisig {
                members: self.charge,
                keys: self.keys,
            },
        })
    }
}
struct KeyParts {
    key: Option<PublicKey>,
    pub(crate) charge: AllocationCharge,
}
fn member(
    bytes: &[u8],
    budget: &AllocationBudget,
    retained: &mut Option<ChargedPublicKey>,
    cached: Option<&MultisigMember>,
) -> Result<Option<ChargedMember>, Error> {
    let mut offset = 0;
    let key = ncore::framed_field::<PublicKey>(bytes, &mut offset)?;
    key.with_payload(|bytes| {
        if let Some(member) = cached {
            PreparedPublicKeyDecode::recheck_payload(bytes, member.public_key())
                .map_err(DecodeIntoError::Codec)?;
        } else if let Some(key) = retained.as_ref() {
            PreparedPublicKeyDecode::recheck_payload(bytes, key.get())
                .map_err(DecodeIntoError::Codec)?;
        } else {
            *retained = Some(
                PreparedPublicKeyDecode::try_decode_payload(bytes, budget)
                    .map_err(|error| destination(error.into()))?,
            );
        }
        Ok(())
    })?;
    let weight = field::<u16, _>(bytes, &mut offset, scalar::<u16>)?;
    finish(bytes, offset)?;
    if cached.is_some() {
        return Ok(None);
    }
    let original = retained
        .as_ref()
        .ok_or(Error::Invariant("missing original member key"))?;
    MultisigMember::validate_components(original.get(), weight).map_err(policy_error)?;
    let key = retained
        .take()
        .ok_or(Error::Invariant("missing original member key"))?;
    bind_member(key, weight).map(Some)
}
#[allow(unsafe_code)]
fn bind_member(key: ChargedPublicKey, weight: u16) -> Result<ChargedMember, Error> {
    // SAFETY: keep the complete checked key and charge paired through the sole
    // original member relation. Its failure consumes/destroys key before refund.
    let (key, charge) = unsafe { key.into_allocation_parts() };
    let mut parts = KeyParts {
        key: Some(key),
        charge,
    };
    let key = parts
        .key
        .take()
        .ok_or(Error::Invariant("missing original member key"))?;
    let value = MultisigMember::new(key, weight).map_err(policy_error)?;
    Ok(ChargedMember {
        value,
        charge: parts.charge,
    })
}
fn policy_error(error: crate::account::MultisigPolicyError) -> Error {
    // DM33 restores only the discarded intrinsic cause's old diagnostic allocation.
    if cfg!(all(test, sumeragi_model_mutation = "DM33")) {
        return norito::Error::Message(error.to_string()).into();
    }
    Error::Multisig(error)
}
