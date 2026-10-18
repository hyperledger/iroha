//! Exact physical custody for a canonical complete FASTPQ effect tape.
//!
//! This parser grants no source authority. The caller retains the original frame and
//! prepared canonical controls and authenticates the complete outer record. Every
//! actual effect/member vector, compact key and Quantity digit allocation is charged
//! before allocation and survives a later field refusal. No encoded-byte multiplier
//! or decoded-object authority replaces the original pool.

use super::*;
use crate::account::prepared_decode::{AccountDecodeError, AccountDestination, ControllerCustody};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_primitives::numeric::{
    ChargedQuantity, PreparedQuantityDecode, QuantityDecodeAdmissionError,
};
use norito::core::{
    self as ncore, CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields,
    FieldDestination,
};

mod fixed;
use fixed::Fixed;

/// Original canonical failure or exact local allocation refusal from one tape destination.
#[derive(Debug, thiserror::Error)]
pub enum FastpqEffectsDecodeError {
    /// Canonical malformed field, preserving the original diagnostic.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Intrinsic canonical controller error, with no allocated replacement diagnostic.
    #[error(transparent)]
    Controller(#[from] crate::account::MultisigPolicyError),
    /// The original finite pool or allocator refused the concrete backing.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// This local operation's explicit effect-count allowance is insufficient.
    /// It does not reject native execution or alter the certified source commitment.
    #[error("FASTPQ tape has {actual} effects; local operation admits {maximum}")]
    EffectLimit {
        /// Exact canonical sequence count, before element allocation.
        actual: usize,
        /// The unchanged caller's finite operation bound.
        maximum: usize,
    },
    /// Original destination/source identity or ordering changed.
    #[error("FASTPQ tape destination: {0}")]
    Invariant(&'static str),
}
use FastpqEffectsDecodeError as Error;
impl From<AccountDecodeError> for Error {
    fn from(error: AccountDecodeError) -> Self {
        match error {
            AccountDecodeError::Codec(error) => Self::Codec(error),
            AccountDecodeError::Multisig(error) => Self::Controller(error),
            AccountDecodeError::Allocation(error) => Self::Allocation(error),
            AccountDecodeError::Invariant(error) => Self::Invariant(error),
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
impl From<ncore::RetainedSequenceError> for Error {
    fn from(error: ncore::RetainedSequenceError) -> Self {
        match error {
            ncore::RetainedSequenceError::Admission(ncore::SequenceAdmissionError::Codec(
                error,
            )) => Self::Codec(error),
            ncore::RetainedSequenceError::Admission(ncore::SequenceAdmissionError::Allocation(
                error,
            )) => Self::Allocation(error),
            ncore::RetainedSequenceError::SourceMismatch => {
                Self::Invariant("original tape sequence changed")
            }
            ncore::RetainedSequenceError::Incomplete => Self::Invariant("unfinished tape sequence"),
        }
    }
}
impl From<DecodeIntoError<Error>> for Error {
    fn from(error: DecodeIntoError<Error>) -> Self {
        match error {
            DecodeIntoError::Codec(error) => Self::Codec(error),
            DecodeIntoError::Destination(error) => error,
        }
    }
}
fn destination(error: Error) -> DecodeIntoError<Error> {
    match error {
        Error::Codec(error) => DecodeIntoError::Codec(error),
        error => DecodeIntoError::Destination(error),
    }
}
fn finish(bytes: &[u8], used: usize) -> Result<(), Error> {
    if bytes.len() != used {
        return Err(norito::Error::LengthMismatch.into());
    }
    ncore::finish_context_fields(bytes.as_ptr(), used)?;
    Ok(())
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
fn tag(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or(norito::Error::LengthMismatch)?
            .try_into()
            .map_err(|_| norito::Error::LengthMismatch)?,
    ))
}
fn invalid_tag() -> Error {
    norito::Error::Message("invalid enum discriminant".into()).into()
}

struct EffectCustody {
    parser: Option<EffectDestination>,
    accounts: [Option<ControllerCustody>; 2],
    quantities: [Option<AllocationCharge>; 5],
}
impl EffectCustody {
    fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.parser
            .as_ref()
            .is_none_or(|parser| parser.belongs_to(pool))
            && self
                .accounts
                .iter()
                .flatten()
                .all(|owner| owner.belongs_to(pool))
            && self
                .quantities
                .iter()
                .flatten()
                .all(|owner| owner.belongs_to(pool))
    }
    fn bytes(&self) -> Option<usize> {
        let bytes = self
            .accounts
            .iter()
            .flatten()
            .try_fold(0usize, |n, c| n.checked_add(c.bytes()?))?;
        self.quantities
            .iter()
            .flatten()
            .try_fold(bytes, |n, c| n.checked_add(c.layout().size()))
    }
}
struct ChargedEffect {
    value: FastpqExecutionEffectV1,
    custody: EffectCustody,
}

/// Complete immutable tape with the actual effect Vec and every nested allocation charge.
///
/// No Clone, mutable borrow, decoder or extraction API can detach this custody. The
/// canonical DTO borrow is evidence transport only and must still be authenticated.
pub struct AllocatedFastpqEffectsV1 {
    value: FastpqExecutionEffectsV1,
    effects: AllocationCharge,
    ledger: ChargedBuffer<EffectCustody>,
}
impl AllocatedFastpqEffectsV1 {
    /// Borrow the exact canonical graph whose allocations remain retained here.
    #[must_use]
    pub fn canonical(&self) -> &FastpqExecutionEffectsV1 {
        &self.value
    }
    /// Check every physical allocation retains the selected original finite pool.
    #[must_use]
    pub fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.effects.belongs_to(pool)
            && self.ledger.belongs_to(pool)
            && self
                .ledger
                .as_slice()
                .iter()
                .all(|owner| owner.belongs_to(pool))
    }
    /// Exact retained backing, excluding transient spans retired at completion.
    #[must_use]
    pub fn allocation_bytes(&self) -> Option<usize> {
        let bytes = self.effects.layout().size().checked_add(
            std::alloc::Layout::array::<EffectCustody>(self.ledger.capacity())
                .ok()?
                .size(),
        )?;
        self.ledger
            .as_slice()
            .iter()
            .try_fold(bytes, |n, c| n.checked_add(c.bytes()?))
    }
}
struct ChargedBalance {
    value: FastpqExecutionBalanceV1,
    custody: ControllerCustody,
}
struct BalanceDestination {
    account: AccountDestination,
    complete: Option<ChargedBalance>,
}
impl BalanceDestination {
    fn new(pool: &AllocationBudget) -> Self {
        Self {
            account: AccountDestination::new(pool),
            complete: None,
        }
    }
    fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.account.belongs_to(pool)
            && self
                .complete
                .as_ref()
                .is_none_or(|v| v.custody.belongs_to(pool))
    }
    fn decode(
        &mut self,
        bytes: &[u8],
        pool: &AllocationBudget,
        cached: Option<&FastpqExecutionBalanceV1>,
    ) -> Result<(), Error> {
        let cached = cached.or_else(|| self.complete.as_ref().map(|v| &v.value));
        let mut fields = BalanceFields {
            account: &mut self.account,
            pool,
            cached,
        };
        let ((asset, (), scope), used) =
            FastpqExecutionBalanceV1::decode_fields(bytes, &mut fields)?;
        finish(bytes, used)?;
        if cached.is_none() {
            let account = self
                .account
                .complete
                .take()
                .ok_or(Error::Invariant("missing balance account"))?;
            self.complete = Some(ChargedBalance {
                value: FastpqExecutionBalanceV1 {
                    asset,
                    account: account.value,
                    scope,
                },
                custody: account.custody,
            });
        }
        Ok(())
    }
}
struct BalanceFields<'a> {
    account: &'a mut AccountDestination,
    pool: &'a AllocationBudget,
    cached: Option<&'a FastpqExecutionBalanceV1>,
}
impl FieldDestination for BalanceFields<'_> {
    type Error = Error;
}
impl DecodeField<0, FastpqExecutionAssetV1> for BalanceFields<'_> {
    type Value = FastpqExecutionAssetV1;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, FastpqExecutionAssetV1>,
    ) -> Result<Self::Value, DecodeIntoError<Error>> {
        field.with_payload(|bytes| Fixed::decode(bytes).map_err(destination))
    }
}
impl DecodeField<1, AccountId> for BalanceFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, AccountId>,
    ) -> Result<(), DecodeIntoError<Error>> {
        field.with_payload(|bytes| {
            self.account
                .decode(bytes, self.pool, self.cached.map(|v| &v.account))
                .map_err(|e| destination(e.into()))
        })
    }
}
impl DecodeField<2, AssetBalanceScope> for BalanceFields<'_> {
    type Value = AssetBalanceScope;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, AssetBalanceScope>,
    ) -> Result<Self::Value, DecodeIntoError<Error>> {
        field.with_payload(|bytes| Fixed::decode(bytes).map_err(destination))
    }
}
#[derive(Default)]
struct QuantityDestination {
    pending: Option<PreparedQuantityDecode>,
    complete: Option<ChargedQuantity>,
}
impl QuantityDestination {
    fn decode(&mut self, bytes: &[u8], pool: &AllocationBudget, cached: bool) -> Result<(), Error> {
        if cached || self.complete.is_some() {
            PreparedQuantityDecode::recheck_payload(bytes)?;
            return Ok(());
        }
        PreparedQuantityDecode::decode_payload_retained(bytes, pool, &mut self.pending)?;
        let quantity = self
            .pending
            .take()
            .ok_or(Error::Invariant("missing Quantity destination"))?;
        match quantity.finish() {
            Ok(value) => self.complete = Some(value),
            Err(value) => {
                self.pending = Some(value);
                return Err(Error::Invariant("unfinished Quantity destination"));
            }
        }
        Ok(())
    }
    fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.pending.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.complete.as_ref().is_none_or(|v| v.belongs_to(pool))
    }
}
struct EffectDestination {
    balances: [BalanceDestination; 2],
    quantities: [QuantityDestination; 5],
    retired: Option<FastpqExecutionAssetV1>,
}
impl EffectDestination {
    fn new(pool: &AllocationBudget) -> Self {
        Self {
            balances: std::array::from_fn(|_| BalanceDestination::new(pool)),
            quantities: std::array::from_fn(|_| QuantityDestination::default()),
            retired: None,
        }
    }
    fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.balances.iter().all(|v| v.belongs_to(pool))
            && self.quantities.iter().all(|v| v.belongs_to(pool))
    }
    fn decode(
        &mut self,
        bytes: &[u8],
        pool: &AllocationBudget,
        cached: Option<&FastpqExecutionEffectV1>,
    ) -> Result<Option<ChargedEffect>, Error> {
        let mut fields = EffectFields {
            destination: self,
            pool,
            cached,
        };
        let ((ordinal, authority_digest, authorization_context, kind), used) =
            FastpqExecutionEffectV1::decode_fields(bytes, &mut fields)?;
        finish(bytes, used)?;
        if cached.is_some() {
            return Ok(None);
        }
        let (kind, custody) = self.finish_kind(kind)?;
        Ok(Some(ChargedEffect {
            value: FastpqExecutionEffectV1 {
                ordinal,
                authority_digest,
                authorization_context,
                kind,
            },
            custody,
        }))
    }
    fn decode_kind(
        &mut self,
        bytes: &[u8],
        pool: &AllocationBudget,
        cached: Option<&FastpqExecutionEffectKindV1>,
    ) -> Result<u32, Error> {
        let kind = tag(bytes)?;
        if cached.is_some_and(|original| match original {
            FastpqExecutionEffectKindV1::Transfer(_) => kind != 0,
            FastpqExecutionEffectKindV1::Mint(_) => kind != 1,
            FastpqExecutionEffectKindV1::Burn(_) => kind != 2,
            FastpqExecutionEffectKindV1::Retire(_) => kind != 3,
        }) {
            return Err(Error::Invariant("original effect variant changed"));
        }
        let mut offset = 4;
        match kind {
            0 => field::<FastpqExecutionTransferV1, _>(bytes, &mut offset, |bytes| {
                let mut fields = KindFields {
                    destination: self,
                    pool,
                    cached,
                    quantity_offset: 2,
                };
                let (_, used) = FastpqExecutionTransferV1::decode_fields(bytes, &mut fields)?;
                finish(bytes, used)
            })?,
            1 | 2 => field::<FastpqExecutionSupplyChangeV1, _>(bytes, &mut offset, |bytes| {
                let mut fields = KindFields {
                    destination: self,
                    pool,
                    cached,
                    quantity_offset: 1,
                };
                let (_, used) = FastpqExecutionSupplyChangeV1::decode_fields(bytes, &mut fields)?;
                finish(bytes, used)
            })?,
            3 => {
                self.retired = Some(field::<FastpqExecutionAssetV1, _>(
                    bytes,
                    &mut offset,
                    Fixed::decode,
                )?)
            }
            _ => return Err(invalid_tag()),
        }
        finish(bytes, offset)?;
        Ok(kind)
    }
    #[allow(unsafe_code)]
    fn finish_kind(
        &mut self,
        kind: u32,
    ) -> Result<(FastpqExecutionEffectKindV1, EffectCustody), Error> {
        let mut custody = EffectCustody {
            parser: None,
            accounts: [None, None],
            quantities: std::array::from_fn(|_| None),
        };
        if kind == 3 {
            return Ok((
                FastpqExecutionEffectKindV1::Retire(
                    self.retired
                        .take()
                        .ok_or(Error::Invariant("missing retired asset"))?,
                ),
                custody,
            ));
        }
        let balances = if kind == 0 { 2 } else { 1 };
        if self.balances[..balances]
            .iter()
            .any(|v| v.complete.is_none())
            || self.quantities.iter().any(|v| v.complete.is_none())
        {
            return Err(Error::Invariant("incomplete effect fields"));
        }
        // SAFETY: the checked complete fields move directly into one value-first private
        // aggregate; all subsequent moves are infallible and no user callback intervenes.
        let mut quantities = self.quantities.iter_mut().enumerate().map(|(i, q)| {
            let (value, charge) = unsafe {
                q.complete
                    .take()
                    .expect("checked complete Quantity")
                    .into_allocation_parts()
            };
            custody.quantities[i] = Some(charge);
            value
        });
        let amount = quantities.next().expect("five quantities");
        let before = quantities.next().expect("five quantities");
        let after = quantities.next().expect("five quantities");
        let other_before = quantities.next().expect("five quantities");
        let other_after = quantities.next().expect("five quantities");
        let source = self.balances[0]
            .complete
            .take()
            .expect("checked complete balance");
        custody.accounts[0] = Some(source.custody);
        let value = if kind == 0 {
            let destination = self.balances[1]
                .complete
                .take()
                .expect("checked complete destination");
            custody.accounts[1] = Some(destination.custody);
            FastpqExecutionEffectKindV1::Transfer(FastpqExecutionTransferV1 {
                source: source.value,
                destination: destination.value,
                amount,
                source_before: before,
                source_after: after,
                destination_before: other_before,
                destination_after: other_after,
            })
        } else {
            let value = FastpqExecutionSupplyChangeV1 {
                balance: source.value,
                amount,
                balance_before: before,
                balance_after: after,
                supply_before: other_before,
                supply_after: other_after,
            };
            if kind == 1 {
                FastpqExecutionEffectKindV1::Mint(value)
            } else {
                FastpqExecutionEffectKindV1::Burn(value)
            }
        };
        Ok((value, custody))
    }
}
struct EffectFields<'a> {
    destination: &'a mut EffectDestination,
    pool: &'a AllocationBudget,
    cached: Option<&'a FastpqExecutionEffectV1>,
}
impl FieldDestination for EffectFields<'_> {
    type Error = Error;
}
impl DecodeField<0, u32> for EffectFields<'_> {
    type Value = u32;
    fn decode_field(&mut self, f: CanonicalField<'_, u32>) -> Result<u32, DecodeIntoError<Error>> {
        f.with_payload(|b| Fixed::decode(b).map_err(destination))
    }
}
impl<const I: usize> DecodeField<I, Hash> for EffectFields<'_> {
    type Value = Hash;
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, Hash>,
    ) -> Result<Hash, DecodeIntoError<Error>> {
        f.with_payload(|b| Fixed::decode(b).map_err(destination))
    }
}
impl DecodeField<3, FastpqExecutionEffectKindV1> for EffectFields<'_> {
    type Value = u32;
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, FastpqExecutionEffectKindV1>,
    ) -> Result<u32, DecodeIntoError<Error>> {
        f.with_payload(|b| {
            self.destination
                .decode_kind(b, self.pool, self.cached.map(|v| &v.kind))
                .map_err(destination)
        })
    }
}
struct KindFields<'a> {
    destination: &'a mut EffectDestination,
    pool: &'a AllocationBudget,
    cached: Option<&'a FastpqExecutionEffectKindV1>,
    quantity_offset: usize,
}
impl FieldDestination for KindFields<'_> {
    type Error = Error;
}
impl<const I: usize> DecodeField<I, FastpqExecutionBalanceV1> for KindFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, FastpqExecutionBalanceV1>,
    ) -> Result<(), DecodeIntoError<Error>> {
        let cached = self.cached.map(|v| match v {
            FastpqExecutionEffectKindV1::Transfer(v) => {
                if I == 0 {
                    &v.source
                } else {
                    &v.destination
                }
            }
            FastpqExecutionEffectKindV1::Mint(v) | FastpqExecutionEffectKindV1::Burn(v) => {
                &v.balance
            }
            FastpqExecutionEffectKindV1::Retire(_) => unreachable!("variant was checked"),
        });
        let target = self
            .destination
            .balances
            .get_mut(I)
            .ok_or_else(|| destination(Error::Invariant("balance field order")))?;
        f.with_payload(|b| target.decode(b, self.pool, cached).map_err(destination))
    }
}
impl<const I: usize> DecodeField<I, Quantity> for KindFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, Quantity>,
    ) -> Result<(), DecodeIntoError<Error>> {
        let index = I
            .checked_sub(self.quantity_offset)
            .ok_or_else(|| destination(Error::Invariant("quantity field order")))?;
        let target = self
            .destination
            .quantities
            .get_mut(index)
            .ok_or_else(|| destination(Error::Invariant("quantity field index")))?;
        f.with_payload(|b| {
            target
                .decode(b, self.pool, self.cached.is_some())
                .map_err(destination)
        })
    }
}

/// Retained partial tape destination for a single immutable original field occurrence.
///
/// The caller supplies its original prepared canonical field context and controls.
/// Successful parsing still needs a complete outer frame comparison and authenticated
/// native source join. A refusal never manufactures a completed source or proof.
pub struct PendingFastpqEffectsDecodeV1 {
    pool: AllocationBudget,
    source: Option<(usize, usize, Hash)>,
    context_source: Option<(usize, usize, Hash)>,
    spans: ncore::RetainedElementSequence,
    effects: Option<ChargedBuffer<FastpqExecutionEffectV1>>,
    ledger: Option<ChargedBuffer<EffectCustody>>,
    current: EffectDestination,
    context: Option<FastpqExecutionEffectContextV1>,
    complete: bool,
    max_effects: usize,
}
impl PendingFastpqEffectsDecodeV1 {
    /// Bind an original finite pool and operation cap without decoding or allocating.
    #[must_use]
    pub fn new(pool: &AllocationBudget, max_effects: usize) -> Self {
        Self {
            pool: pool.clone(),
            source: None,
            context_source: None,
            spans: ncore::RetainedElementSequence::new(pool),
            effects: None,
            ledger: None,
            current: EffectDestination::new(pool),
            context: None,
            complete: false,
            max_effects,
        }
    }
    /// Whether every partial physical destination remains with this original pool.
    #[must_use]
    pub fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.pool.same_pool(pool)
            && self.spans.belongs_to(pool)
            && self.current.belongs_to(pool)
            && self.effects.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.ledger.as_ref().is_none_or(|v| {
                v.belongs_to(pool) && v.as_slice().iter().all(|c| c.belongs_to(pool))
            })
    }
    /// Fill the original partial destination inside the enclosing canonical context.
    /// # Errors
    /// Returns the unchanged canonical/physical cause while preserving allocated prefixes.
    pub fn decode_payload(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let identity = (bytes.as_ptr() as usize, bytes.len(), Hash::new(bytes));
        if self.source.is_some_and(|source| source != identity) {
            return Err(Error::Invariant("original tape bytes changed"));
        }
        self.source = Some(identity);
        self.complete = false;
        let result = (|| {
            let ((context, ()), used) = FastpqExecutionEffectsV1::decode_fields(bytes, self)?;
            finish(bytes, used)?;
            self.context = Some(context);
            Ok(())
        })();
        self.complete = result.is_ok();
        result
    }
    /// Whether the last complete canonical traversal filled every destination.
    /// This does not authenticate execution or the enclosing source record.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete && self.context.is_some() && self.effects.is_some() && self.ledger.is_some()
    }
    /// Consume only a complete tape; incomplete attempts keep their original custody.
    /// # Errors
    /// Returns the unchanged pending owner when its original canonical tape is incomplete.
    #[allow(unsafe_code)]
    pub fn finish(mut self) -> Result<AllocatedFastpqEffectsV1, Self> {
        if !self.is_complete() {
            return Err(self);
        }
        // Completed fields retain their own original recheck spans during retry;
        // the full tape is now complete, so retire only those transient parsers.
        for custody in self
            .ledger
            .as_mut()
            .expect("complete ledger")
            .as_mut_slice()
        {
            custody.parser = None;
        }
        // SAFETY: final values and their concrete charge immediately join the value-first
        // immutable owner. The per-effect charge ledger moves with them; no clone occurs.
        let (effects, charge) = unsafe {
            self.effects
                .take()
                .expect("complete effects")
                .into_allocation_parts()
        };
        Ok(AllocatedFastpqEffectsV1 {
            value: FastpqExecutionEffectsV1 {
                context: self.context.take().expect("complete context"),
                effects,
            },
            effects: charge,
            ledger: self.ledger.take().expect("complete ledger"),
        })
    }
}
impl FieldDestination for PendingFastpqEffectsDecodeV1 {
    type Error = Error;
}
impl DecodeField<0, FastpqExecutionEffectContextV1> for PendingFastpqEffectsDecodeV1 {
    type Value = FastpqExecutionEffectContextV1;
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, FastpqExecutionEffectContextV1>,
    ) -> Result<Self::Value, DecodeIntoError<Error>> {
        let identity = (
            f.bytes().as_ptr() as usize,
            f.bytes().len(),
            Hash::new(f.bytes()),
        );
        if self.context_source.is_some_and(|source| source != identity) {
            return Err(destination(Error::Invariant(
                "original tape context changed",
            )));
        }
        self.context_source = Some(identity);
        let context = f.with_payload(|b| Fixed::decode(b).map_err(destination))?;
        self.context = Some(context);
        Ok(context)
    }
}
impl DecodeField<1, Vec<FastpqExecutionEffectV1>> for PendingFastpqEffectsDecodeV1 {
    type Value = ();
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, Vec<FastpqExecutionEffectV1>>,
    ) -> Result<(), DecodeIntoError<Error>> {
        f.with_payload(|bytes| {
            let (count, _) = ncore::inspect_seq_len_slice(bytes)?;
            if count > self.max_effects {
                return Err(destination(Error::EffectLimit {
                    actual: count,
                    maximum: self.max_effects,
                }));
            }
            self.spans
                .prepare(bytes)
                .map_err(|e| destination(e.into()))?;
            let prepared = self
                .spans
                .as_prepared(bytes)
                .map_err(|e| destination(e.into()))?;
            if prepared.used() != bytes.len() || prepared.len() > self.max_effects {
                return Err(DecodeIntoError::Codec(norito::Error::LengthMismatch));
            }
            let count = prepared.len();
            if self.effects.is_none() {
                self.effects =
                    Some(ChargedBuffer::new(count, &self.pool).map_err(|e| destination(e.into()))?);
            }
            if self.ledger.is_none() {
                self.ledger =
                    Some(ChargedBuffer::new(count, &self.pool).map_err(|e| destination(e.into()))?);
            }
            let effects = self.effects.as_mut().expect("retained effects");
            let ledger = self.ledger.as_mut().expect("retained charges");
            if effects.capacity() != count
                || ledger.capacity() != count
                || effects.as_slice().len() != ledger.as_slice().len()
            {
                return Err(destination(Error::Invariant(
                    "effect/charge backing changed",
                )));
            }
            prepared.decode_elements::<FastpqExecutionEffectV1, Error>(|index, field| {
                let cached = effects.as_slice().get(index);
                if index > effects.as_slice().len() {
                    return Err(destination(Error::Invariant(
                        "effect sequence skipped original index",
                    )));
                }
                if let Some(cached) = cached {
                    let parser = ledger.as_mut_slice()[index]
                        .parser
                        .as_mut()
                        .ok_or_else(|| {
                            destination(Error::Invariant("missing original effect parser"))
                        })?;
                    field.with_payload(|b| {
                        parser
                            .decode(b, &self.pool, Some(cached))
                            .map_err(destination)
                    })?;
                } else {
                    let mut effect = field
                        .with_payload(|b| {
                            self.current
                                .decode(b, &self.pool, None)
                                .map_err(destination)
                        })?
                        .ok_or_else(|| destination(Error::Invariant("missing original effect")))?;
                    effect.custody.parser = Some(std::mem::replace(
                        &mut self.current,
                        EffectDestination::new(&self.pool),
                    ));
                    effects.push_reserved(effect.value);
                    ledger.push_reserved(effect.custody);
                }
                Ok(())
            })?;
            self.complete = true;
            Ok(())
        })
    }
}

struct EffectSlice<'a>(&'a [FastpqExecutionEffectV1]);
impl norito::SerializePayload for EffectSlice<'_> {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        ncore::write_element_sequence::<FastpqExecutionEffectV1, _>(writer, self.0.iter())
    }
}
#[derive(norito::Encode)]
struct TapeView<'a> {
    context: FastpqExecutionEffectContextV1,
    effects: EffectSlice<'a>,
}
impl norito::SerializePayload for PendingFastpqEffectsDecodeV1 {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        if !self.complete {
            return Err(norito::Error::LengthMismatch);
        }
        let value = TapeView {
            context: self.context.ok_or(norito::Error::LengthMismatch)?,
            effects: EffectSlice(
                self.effects
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?
                    .as_slice(),
            ),
        };
        norito::SerializePayload::serialize(&value, writer)
    }
}
impl ncore::PreparedRecordDestination<FastpqExecutionEffectsV1> for PendingFastpqEffectsDecodeV1 {
    fn reset(&mut self) {
        self.complete = false;
    }
}

#[cfg(test)]
mod tests;

/// Decode one fixed manifest payload inside the caller's canonical field context.
/// This allocation-free shape check grants no authenticated source authority.
/// # Errors
/// Preserves the original canonical field/enum/scalar failure.
pub fn decode_fastpq_source_manifest_payload_v1(
    bytes: &[u8],
) -> Result<crate::fastpq::FastpqOrdinarySourceStatementManifestV1, Error> {
    Fixed::decode(bytes)
}
/// Decode one fixed execution-entry payload inside the caller's canonical field context.
/// This allocation-free shape check grants no authenticated source authority.
/// # Errors
/// Preserves the original canonical field/enum/scalar failure.
pub fn decode_fastpq_source_entry_payload_v1(
    bytes: &[u8],
) -> Result<FastpqSourceExecutionEntryV1, Error> {
    Fixed::decode(bytes)
}
/// Decode one fixed statement-leaf payload inside the caller's canonical field context.
/// This allocation-free shape check grants no authenticated source authority.
/// # Errors
/// Preserves the original canonical field/enum/scalar failure.
pub fn decode_fastpq_source_leaf_payload_v1(
    bytes: &[u8],
) -> Result<crate::fastpq::FastpqOrdinarySourceStatementLeafV1, Error> {
    Fixed::decode(bytes)
}

/// Decode the canonical fixed manifest frame using the caller's already funded controls.
/// No nested heap storage, alignment copy or authority object is constructed.
/// # Errors
/// Preserves canonical resource provenance and the original destination cause.
pub fn decode_fastpq_source_manifest_frame_v1(
    bytes: &[u8],
    workspace: &mut ncore::PreparedDecodeWorkspace,
) -> Result<crate::fastpq::FastpqOrdinarySourceStatementManifestV1, ncore::PreparedDecodeError<Error>>
{
    let mut destination = fixed::ManifestDestination::default();
    workspace.decode_canonical_into::<crate::fastpq::FastpqOrdinarySourceStatementManifestV1, _>(
        bytes,
        norito::canonical_decode_limits(bytes.len()),
        &mut destination,
    )?;
    destination.value().ok_or_else(|| {
        ncore::PreparedDecodeError::Destination(Error::Invariant("missing complete manifest"))
    })
}
