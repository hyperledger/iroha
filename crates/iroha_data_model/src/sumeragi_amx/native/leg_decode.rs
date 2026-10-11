//! One-pass original-pool custody for the closed canonical native AMX leg.
//!
//! Each concrete allocation is admitted where canonical traversal reaches it.
//! There is no whole-frame preview, quota reset or unfunded token bank. Original
//! input and diagnostic Strings remain enclosing-owner obligations. The completed
//! owner keeps the actual canonical counter controls and graph for a Worker borrow.
//! Partial destinations retain their exact backing across original Worker retry.
//! Multisig semantic failures retain the original Copy cause without a diagnostic
//! allocation. Ordinary codec errors and final Core diagnostics remain separate.
//! TODO: fund remaining diagnostic Strings without changing canonical error ordering.

use super::AmxTransferLegV1;
use crate::{
    account::{AccountController, AccountId, MultisigMember, MultisigPolicy},
    asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES,
};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_crypto::{
    ChargedPublicKey, Hash, PreparedPublicKeyDecode, PublicKey, PublicKeyDecodeAdmissionError,
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::{
    ChargedQuantity, PreparedQuantityDecode, Quantity, QuantityDecodeAdmissionError,
};
use norito::core::{
    self as ncore, CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields,
    FieldDestination, PreparedDecodeError, PreparedDecodeScopeError, PreparedDecodeWorkspace,
    PreparedRecordDestination,
};
use std::fmt;

/// Original parser cause or local original-pool refusal, never a protocol vote.
#[derive(Debug, thiserror::Error)]
pub enum AmxLegDecodeErrorV1 {
    /// The original fixed transfer payload bound was exceeded.
    #[error("{0}")]
    Record(&'static str),
    /// Original canonical multisig relation, retaining every dynamic cause field.
    /// This intrinsic rejection owns no diagnostic allocation or retry provenance.
    #[error(transparent)]
    Multisig(#[from] crate::account::MultisigPolicyError),
    /// Original canonical field, cumulative work or scalar validation cause.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Canonical attempt cause captured before its original scopes retired.
    #[error(transparent)]
    Decode(ncore::DecodeAttemptError),
    /// Original physically prepared counter-control failure.
    #[error(transparent)]
    Scope(#[from] PreparedDecodeScopeError),
    /// Original pool admission/release cause or genuine allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// A closed source/destination invariant changed without a protocol rejection.
    #[error("native AMX leg destination: {0}")]
    Invariant(&'static str),
}
use AmxLegDecodeErrorV1 as Error;
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
impl From<QuantityDecodeAdmissionError> for Error {
    fn from(error: QuantityDecodeAdmissionError) -> Self {
        match error {
            QuantityDecodeAdmissionError::Codec(error) => Self::Codec(error),
            QuantityDecodeAdmissionError::Allocation(error) => Self::Allocation(error),
            QuantityDecodeAdmissionError::Incomplete => {
                Self::Invariant("unfinished native Quantity")
            }
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

/// One complete immutable leg whose canonical values are destroyed before all refunds.
///
/// The member Vec, each compact key, native Quantity digits and key-ledger
/// buffers retain their actual original-pool charges. Transient span scratch is
/// already reclaimed on return. This is an inline move-only owner; no shared
/// shell, mutation, replacement or extraction API can detach that graph.
/// Ordinary clones made from the borrow are separate unfunded graphs.
pub struct AllocatedAmxTransferLegV1 {
    value: AmxTransferLegV1,
    source: ControllerCustody,
    destination: ControllerCustody,
    amount: AllocationCharge,
}
impl fmt::Debug for AllocatedAmxTransferLegV1 {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_tuple("AllocatedAmxTransferLegV1")
            .field(self.canonical())
            .finish()
    }
}
impl AllocatedAmxTransferLegV1 {
    /// Borrow the exact canonical transfer without separating its funding.
    #[must_use]
    pub fn canonical(&self) -> &AmxTransferLegV1 {
        &self.value
    }
    /// Check all real retained allocations, including the key-ledger buffers.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.source.belongs_to(budget)
            && self.destination.belongs_to(budget)
            && self.amount.belongs_to(budget)
    }
    /// Exact retained layout sum, excluding already-destroyed span scratch.
    #[must_use]
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.source
            .bytes()?
            .checked_add(self.destination.bytes()?)?
            .checked_add(self.amount.layout().size())
    }
}

/// A completed canonical attempt with its original physical counter controls.
///
/// The graph is declared first so its actual nested values and ledgers retire
/// before the workspace refunds either counter control. No extraction, clone,
/// replacement or re-entry API separates these owners.
pub struct CompletedAmxTransferLegDecodeV1 {
    leg: AllocatedAmxTransferLegV1,
    workspace: PreparedDecodeWorkspace,
}
impl fmt::Debug for CompletedAmxTransferLegDecodeV1 {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_tuple("CompletedAmxTransferLegDecodeV1")
            .field(self.canonical())
            .finish()
    }
}
impl CompletedAmxTransferLegDecodeV1 {
    /// Borrow the same completed canonical graph without decoder work.
    #[must_use]
    pub fn canonical(&self) -> &AmxTransferLegV1 {
        self.leg.canonical()
    }
    /// Require all graph and workspace allocations to retain this original pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.leg.belongs_to(budget) && self.workspace.belongs_to(budget)
    }
    /// Exact retained graph and physical counter layouts, without retired scratch.
    #[must_use]
    pub fn allocation_bytes(&self) -> Option<usize> {
        PreparedDecodeWorkspace::allocation_layouts()
            .iter()
            .try_fold(self.leg.allocation_bytes()?, |sum, layout| {
                sum.checked_add(layout.size())
            })
    }
}

enum ControllerCustody {
    Single(AllocationCharge),
    Multisig {
        members: AllocationCharge,
        keys: ChargedBuffer<AllocationCharge>,
    },
}
impl ControllerCustody {
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
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
    fn bytes(&self) -> Option<usize> {
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
struct ChargedAccount {
    value: AccountId,
    custody: ControllerCustody,
}
struct ChargedAsset {
    value: AssetId,
    custody: ControllerCustody,
}
struct ChargedMember {
    value: MultisigMember,
    charge: AllocationCharge,
}
struct ChargedPolicy {
    value: MultisigPolicy,
    custody: ControllerCustody,
}

/// One original occurrence's move-only partial destination and canonical controls.
///
/// No input borrow escapes a synchronous decode. The caller owns the immutable
/// signed frame; every re-entry checks its physical slice and full byte identity.
/// Completed fields, partial members, scratch and native digits survive refusal.
/// Enclosing cumulative quotas remain consumed through the canonical workspace.
/// This owner authenticates bytes only; it grants no execution authority.
pub struct PendingAmxTransferLegDecodeV1 {
    destination: LegDestination,
    workspace: Option<PreparedDecodeWorkspace>,
    source: LegSource,
}
struct LegSource {
    address: usize,
    length: usize,
    hash: Option<Hash>,
}
impl LegSource {
    fn matches(&self, source: &[u8]) -> bool {
        self.address == source.as_ptr() as usize
            && self.length == source.len()
            && self.hash == Some(Hash::new(source))
    }
}
impl PendingAmxTransferLegDecodeV1 {
    /// Bind an immutable original frame and pool without planning its graph.
    #[must_use]
    pub fn new(source: &[u8], budget: &AllocationBudget) -> Self {
        Self {
            destination: LegDestination::new(budget),
            workspace: None,
            source: LegSource {
                address: source.as_ptr() as usize,
                length: source.len(),
                hash: (!source.is_empty() && source.len() <= MAX_RESULT_PREIMAGE_BYTES)
                    .then(|| Hash::new(source)),
            },
        }
    }
    /// Original signed slice identity; it is diagnostic, never dereferenced.
    #[must_use]
    pub fn original_source_identity(&self) -> (usize, usize) {
        (self.source.address, self.source.length)
    }
    /// All actual partial graph, scratch and control allocations use this pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.destination.belongs_to(budget)
            && self
                .workspace
                .as_ref()
                .is_none_or(|workspace| workspace.belongs_to(budget))
    }
    /// Fill the same destination and return the original cause on refusal.
    ///
    /// Completed fields are borrowed, not decoded into replacement allocations.
    /// The sole canonical root rechecks the full frame by stream comparison and
    /// gives each re-entry a distinct attempt identity. The enclosing original
    /// cumulative scopes are neither replaced nor replenished.
    ///
    /// # Errors
    /// Preserves the parser, original release generation and allocator cause.
    /// All previously admitted destination backing survives an error.
    pub fn decode(&mut self, source: &[u8]) -> Result<(), Error> {
        if source.is_empty() || source.len() > MAX_RESULT_PREIMAGE_BYTES {
            return Err(Error::Record(
                "native AMX transfer payload exceeds its canonical bound",
            ));
        }
        if !self.source.matches(source) {
            return Err(Error::Invariant("original native AMX leg source changed"));
        }
        if self.workspace.is_none() {
            let mut reservation = self
                .destination
                .budget
                .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
                .map_err(ChargedBufferError::from)?;
            self.workspace = Some(PreparedDecodeWorkspace::from_reservation(
                &self.destination.budget,
                &mut reservation,
            )?);
        }
        self.workspace
            .as_mut()
            .ok_or(Error::Invariant("missing native AMX controls"))?
            .decode_canonical_into::<AmxTransferLegV1, _>(
                source,
                norito::canonical_decode_limits(source.len()),
                &mut self.destination,
            )
            .map_err(|error| match error {
                PreparedDecodeError::Codec(error) => Error::Decode(error),
                PreparedDecodeError::Destination(error) => error,
                PreparedDecodeError::Scope(error) => Error::Scope(error),
            })
    }
    /// Decode and move the original graph out after full canonical success.
    ///
    /// # Errors
    /// Refusal keeps this partial owner unchanged. Success retires only transient
    /// scratch and moves the graph plus original controls into the completed owner.
    pub fn try_decode_retained(
        &mut self,
        source: &[u8],
    ) -> Result<CompletedAmxTransferLegDecodeV1, Error> {
        self.decode(source)?;
        let replacement = LegDestination::new(&self.destination.budget);
        let destination = std::mem::replace(&mut self.destination, replacement);
        let leg = destination.finish()?;
        let workspace = self
            .workspace
            .take()
            .ok_or(Error::Invariant("missing native AMX controls"))?;
        Ok(CompletedAmxTransferLegDecodeV1 { leg, workspace })
    }
    /// Move a complete graph while retiring only its canonical controls.
    ///
    /// # Errors
    /// Returns the original cause and retains partial backing in this owner.
    pub fn try_decode(&mut self, source: &[u8]) -> Result<AllocatedAmxTransferLegV1, Error> {
        let CompletedAmxTransferLegDecodeV1 { leg, workspace: _ } =
            self.try_decode_retained(source)?;
        Ok(leg)
    }
}

struct LegDestination {
    complete: Option<AllocatedAmxTransferLegV1>,
    source: AssetDestination,
    receiver: AccountDestination,
    amount: Option<PreparedQuantityDecode>,
    budget: AllocationBudget,
    valid: bool,
}
impl LegDestination {
    fn new(budget: &AllocationBudget) -> Self {
        Self {
            source: AssetDestination::new(budget),
            receiver: AccountDestination::new(budget),
            amount: None,
            complete: None,
            budget: budget.clone(),
            valid: false,
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self.source.belongs_to(budget)
            && self.receiver.belongs_to(budget)
            && self
                .amount
                .as_ref()
                .is_none_or(|amount| amount.belongs_to(budget))
            && self
                .complete
                .as_ref()
                .is_none_or(|leg| leg.belongs_to(budget))
    }
    fn finish(mut self) -> Result<AllocatedAmxTransferLegV1, Error> {
        if !self.valid {
            return Err(Error::Invariant("unfinished native AMX leg"));
        }
        self.complete
            .take()
            .ok_or(Error::Invariant("missing native AMX leg"))
    }
}
impl FieldDestination for LegDestination {
    type Error = Error;
}
impl ncore::SerializePayload for LegDestination {
    fn serialize(&self, encoder: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        if !self.valid {
            return Err(norito::Error::LengthMismatch);
        }
        ncore::SerializePayload::serialize(
            self.complete
                .as_ref()
                .ok_or(norito::Error::LengthMismatch)?
                .canonical(),
            encoder,
        )
    }
}
impl PreparedRecordDestination<AmxTransferLegV1> for LegDestination {
    fn reset(&mut self) {
        self.valid = false;
    }
}
impl DecodeField<0, AssetId> for LegDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, AssetId>,
    ) -> Result<(), DecodeIntoError<Error>> {
        let cached = self.complete.as_ref().map(|leg| &leg.canonical().source);
        field.with_payload(|bytes| {
            self.source
                .decode(bytes, &self.budget, cached)
                .map_err(destination)
        })
    }
}
impl DecodeField<1, AccountId> for LegDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, AccountId>,
    ) -> Result<(), DecodeIntoError<Error>> {
        if self.complete.is_none() && self.source.complete.is_none() {
            return Err(destination(Error::Invariant(
                "native AMX leg source order changed",
            )));
        }
        let cached = self
            .complete
            .as_ref()
            .map(|leg| &leg.canonical().destination);
        field.with_payload(|bytes| {
            self.receiver
                .decode(bytes, &self.budget, cached)
                .map_err(destination)
        })
    }
}
impl DecodeField<2, Quantity> for LegDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Quantity>,
    ) -> Result<(), DecodeIntoError<Error>> {
        if self.complete.is_some() {
            field.with_payload(|bytes| {
                PreparedQuantityDecode::recheck_payload(bytes).map_err(DecodeIntoError::Codec)
            })?;
        } else {
            if self.source.complete.is_none() || self.receiver.complete.is_none() {
                return Err(destination(Error::Invariant(
                    "native AMX leg amount order changed",
                )));
            }
            field.with_payload(|bytes| {
                PreparedQuantityDecode::decode_payload_retained(
                    bytes,
                    &self.budget,
                    &mut self.amount,
                )
                .map_err(|error| destination(error.into()))
            })?;
            let amount = self
                .amount
                .take()
                .ok_or_else(|| destination(Error::Invariant("missing native Quantity")))?;
            let amount = match amount.finish() {
                Ok(amount) => amount,
                Err(amount) => {
                    self.amount = Some(amount);
                    return Err(destination(Error::Invariant("unfinished native Quantity")));
                }
            };
            let source =
                self.source.complete.take().ok_or_else(|| {
                    destination(Error::Invariant("missing native AMX leg source"))
                })?;
            let receiver = self.receiver.complete.take().ok_or_else(|| {
                destination(Error::Invariant("missing native AMX leg destination"))
            })?;
            self.complete = Some(bind_leg(source, receiver, amount));
        }
        self.valid = true;
        Ok(())
    }
}

#[allow(unsafe_code)]
fn bind_leg(
    source: ChargedAsset,
    destination: ChargedAccount,
    amount: ChargedQuantity,
) -> AllocatedAmxTransferLegV1 {
    // SAFETY: all following operations are infallible moves into one private
    // value-first owner. No field clone, validation or callback can intervene.
    let (amount, amount_charge) = unsafe { amount.into_allocation_parts() };
    AllocatedAmxTransferLegV1 {
        value: AmxTransferLegV1 {
            source: source.value,
            destination: destination.value,
            amount,
        },
        source: source.custody,
        destination: destination.custody,
        amount: amount_charge,
    }
}
struct AssetDestination {
    complete: Option<ChargedAsset>,
    account: AccountDestination,
    definition: Option<AssetDefinitionId>,
    scope: Option<AssetBalanceScope>,
}
struct AssetDestinationFields<'destination> {
    account: &'destination mut AccountDestination,
    definition: &'destination mut Option<AssetDefinitionId>,
    scope: &'destination mut Option<AssetBalanceScope>,
}
struct AssetFields<'destination, 'pool, 'cached> {
    destination: AssetDestinationFields<'destination>,
    budget: &'pool AllocationBudget,
    cached: Option<&'cached AssetId>,
}
impl FieldDestination for AssetFields<'_, '_, '_> {
    type Error = Error;
}
impl DecodeField<0, AccountId> for AssetFields<'_, '_, '_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, AccountId>,
    ) -> Result<(), DecodeIntoError<Error>> {
        field.with_payload(|bytes| {
            self.destination
                .account
                .decode(bytes, self.budget, self.cached.map(AssetId::account))
                .map_err(destination)
        })
    }
}
impl DecodeField<1, AssetDefinitionId> for AssetFields<'_, '_, '_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, AssetDefinitionId>,
    ) -> Result<(), DecodeIntoError<Error>> {
        let definition = field.with_payload(|bytes| {
            let (original, used) =
                <[u8; 16] as ncore::DecodeFromSlice<'_>>::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            ncore::finish_context_fields(bytes.as_ptr(), used)?;
            AssetDefinitionId::from_uuid_bytes(original)
                .map_err(|error| DecodeIntoError::Codec(norito::Error::Message(error.to_string())))
        })?;
        if self.cached.is_none() {
            *self.destination.definition = Some(definition);
        }
        Ok(())
    }
}
impl DecodeField<2, AssetBalanceScope> for AssetFields<'_, '_, '_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, AssetBalanceScope>,
    ) -> Result<(), DecodeIntoError<Error>> {
        let scope = field.with_payload(|bytes| scope(bytes).map_err(destination))?;
        if self.cached.is_none() {
            *self.destination.scope = Some(scope);
        }
        Ok(())
    }
}
impl AssetDestination {
    fn new(budget: &AllocationBudget) -> Self {
        Self {
            complete: None,
            account: AccountDestination::new(budget),
            definition: None,
            scope: None,
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.account.belongs_to(budget)
            && self
                .complete
                .as_ref()
                .is_none_or(|value| value.custody.belongs_to(budget))
    }
    fn decode(
        &mut self,
        bytes: &[u8],
        budget: &AllocationBudget,
        cached: Option<&AssetId>,
    ) -> Result<(), Error> {
        let cached = cached.or_else(|| self.complete.as_ref().map(|asset| &asset.value));
        let mut fields = AssetFields {
            destination: AssetDestinationFields {
                account: &mut self.account,
                definition: &mut self.definition,
                scope: &mut self.scope,
            },
            budget,
            cached,
        };
        let (_, used) = AssetId::decode_fields(bytes, &mut fields)?;
        finish(bytes, used)?;
        if cached.is_some() {
            return Ok(());
        }
        let account = self
            .account
            .complete
            .take()
            .ok_or(Error::Invariant("missing asset account"))?;
        let definition = self
            .definition
            .take()
            .ok_or(Error::Invariant("missing asset definition"))?;
        let scope = self
            .scope
            .take()
            .ok_or(Error::Invariant("missing asset scope"))?;
        self.complete = Some(ChargedAsset {
            value: AssetId::with_scope(definition, account.value, scope),
            custody: account.custody,
        });
        Ok(())
    }
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
struct AccountDestination {
    complete: Option<ChargedAccount>,
    key: Option<ChargedPublicKey>,
    policy: PolicyDestination,
}
impl AccountDestination {
    fn new(budget: &AllocationBudget) -> Self {
        Self {
            complete: None,
            key: None,
            policy: PolicyDestination::new(budget),
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.key.as_ref().is_none_or(|key| key.belongs_to(budget))
            && self.policy.belongs_to(budget)
            && self
                .complete
                .as_ref()
                .is_none_or(|account| account.custody.belongs_to(budget))
    }
    fn decode(
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
struct PolicyDestination {
    complete: Option<ChargedPolicy>,
    members: MembersDestination,
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
struct MembersDestination {
    members: Option<ChargedBuffer<MultisigMember>>,
    keys: Option<ChargedBuffer<AllocationCharge>>,
    key: Option<ChargedPublicKey>,
    spans: ncore::RetainedElementSequence,
}
impl MembersDestination {
    fn new(budget: &AllocationBudget) -> Self {
        Self {
            members: None,
            keys: None,
            key: None,
            spans: ncore::RetainedElementSequence::new(budget),
        }
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
    fn decode(
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
struct MemberParts {
    members: Option<Vec<MultisigMember>>,
    charge: AllocationCharge,
    keys: ChargedBuffer<AllocationCharge>,
}
impl MemberParts {
    #[allow(unsafe_code)]
    fn new(members: ChargedBuffer<MultisigMember>, keys: ChargedBuffer<AllocationCharge>) -> Self {
        // SAFETY: immediately pair original canonical values with their actual
        // member allocation and each key charge, without callbacks or clones.
        let (members, charge) = unsafe { members.into_allocation_parts() };
        Self {
            members: Some(members),
            charge,
            keys,
        }
    }
    fn finish(mut self, version: u8, threshold: u16) -> Result<ChargedPolicy, Error> {
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
    charge: AllocationCharge,
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
fn scope(bytes: &[u8]) -> Result<AssetBalanceScope, Error> {
    let mut offset = 4;
    let scope = match tag(bytes)? {
        0 => AssetBalanceScope::Global,
        1 => AssetBalanceScope::Dataspace(field::<DataSpaceId, _>(bytes, &mut offset, |bytes| {
            let mut offset = 0;
            let value = field::<u64, _>(bytes, &mut offset, scalar::<u64>)?;
            finish(bytes, offset)?;
            Ok(DataSpaceId::new(value))
        })?),
        _ => return Err(invalid_tag()),
    };
    finish(bytes, offset)?;
    Ok(scope)
}

#[cfg(test)]
mod tests;
