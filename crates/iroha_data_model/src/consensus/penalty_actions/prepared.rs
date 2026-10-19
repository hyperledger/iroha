//! Retained original source, canonical leaf decoders and exact action graph allocations.

use super::{Funded, NposPenaltyActions, Storage};
use crate::{
    account::{
        AccountId,
        prepared_decode::{AccountDecodeError, AccountDestination, ControllerCustody},
    },
    consensus::{
        NposConsensusSlashAction, NposMarkConsensusEvidenceAppliedAction, NposPenaltyAction,
    },
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedBufferError,
    ChargedShared, PrepaidSharedError,
};
use iroha_crypto::{
    ChargedPublicKey, Hash, PreparedPublicKeyDecode, PublicKey, PublicKeyDecodeAdmissionError,
};
use iroha_model_base::{peer::PeerId, topology::LaneId};
use iroha_primitives::numeric::{
    ChargedQuantity, PreparedQuantityDecode, Quantity, QuantityDecodeAdmissionError,
};
use norito::core::{
    self as ncore, CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError,
    DecodeRecordFields, FieldDestination, SequenceSpan,
};
use std::alloc::Layout;

/// Canonical input failure or exact original physical penalty-action custody refusal.
#[derive(Debug, thiserror::Error)]
pub enum NposPenaltyActionsCustodyError {
    /// Caller changed the original allocation pool.
    #[error("penalty actions belong to another original pool")]
    ForeignPool,
    /// Full original source address, length, bytes or selected field changed.
    #[error("penalty actions changed their complete original source")]
    SourceChanged,
    /// The enclosing canonical frame has not installed its advertised layout.
    #[error("penalty actions require their original advertised layout")]
    MissingLayout,
    /// Retry changed the original advertised layout.
    #[error("penalty actions changed their original advertised layout")]
    LayoutChanged,
    /// Original classified canonical or cumulative decode refusal.
    #[error(transparent)]
    Decode(#[from] ncore::DecodeAttemptError),
    /// Canonical cause retained while the enclosing attempt classifies it.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Intrinsic controller validation failure.
    #[error(transparent)]
    Controller(#[from] crate::account::MultisigPolicyError),
    /// Original pool or allocator refused a concrete backing.
    #[error(transparent)]
    Buffer(#[from] ChargedBufferError),
    /// Original pool refused the immutable control.
    #[error(transparent)]
    ControlAdmission(#[from] AllocationRefusal),
    /// Physical allocator refused the prepaid immutable control.
    #[error(transparent)]
    ControlAllocation(#[from] PrepaidSharedError),
    /// The original destination is incomplete or its field order changed.
    #[error("penalty action destination: {0}")]
    Invariant(&'static str),
}
use NposPenaltyActionsCustodyError as Error;
impl From<AccountDecodeError> for Error {
    fn from(e: AccountDecodeError) -> Self {
        match e {
            AccountDecodeError::Codec(e) => Self::Codec(e),
            AccountDecodeError::Multisig(e) => Self::Controller(e),
            AccountDecodeError::Allocation(e) => Self::Buffer(e),
            AccountDecodeError::Invariant(e) => Self::Invariant(e),
        }
    }
}
impl From<PublicKeyDecodeAdmissionError> for Error {
    fn from(e: PublicKeyDecodeAdmissionError) -> Self {
        match e {
            PublicKeyDecodeAdmissionError::Codec(e) => Self::Codec(e),
            PublicKeyDecodeAdmissionError::Allocation(e) => Self::Buffer(e),
        }
    }
}
impl From<QuantityDecodeAdmissionError> for Error {
    fn from(e: QuantityDecodeAdmissionError) -> Self {
        match e {
            QuantityDecodeAdmissionError::Codec(e) => Self::Codec(e),
            QuantityDecodeAdmissionError::Allocation(e) => Self::Buffer(e),
            QuantityDecodeAdmissionError::Incomplete => {
                Self::Invariant("unfinished original quantity")
            }
        }
    }
}
impl From<ncore::RetainedSequenceError> for Error {
    fn from(e: ncore::RetainedSequenceError) -> Self {
        match e {
            ncore::RetainedSequenceError::Admission(ncore::SequenceAdmissionError::Codec(e)) => {
                Self::Codec(e)
            }
            ncore::RetainedSequenceError::Admission(ncore::SequenceAdmissionError::Allocation(
                e,
            )) => Self::Buffer(e),
            ncore::RetainedSequenceError::SourceMismatch => Self::SourceChanged,
            ncore::RetainedSequenceError::Incomplete => {
                Self::Invariant("unfinished original action sequence")
            }
        }
    }
}
impl From<DecodeIntoError<Error>> for Error {
    fn from(e: DecodeIntoError<Error>) -> Self {
        match e {
            DecodeIntoError::Codec(e) => Self::Codec(e),
            DecodeIntoError::Destination(e) => e,
        }
    }
}
fn destination(e: Error) -> DecodeIntoError<Error> {
    match e {
        Error::Codec(e) => DecodeIntoError::Codec(e),
        e => DecodeIntoError::Destination(e),
    }
}
fn finish(bytes: &[u8], used: usize) -> Result<(), Error> {
    if bytes.len() != used {
        return Err(norito::Error::LengthMismatch.into());
    }
    ncore::finish_context_fields(bytes.as_ptr(), used)?;
    Ok(())
}
fn scalar<T: for<'a> DecodeFromSlice<'a>>(bytes: &[u8]) -> Result<T, Error> {
    let (value, used) = T::decode_from_slice(bytes)?;
    finish(bytes, used)?;
    Ok(value)
}
struct Inline;
impl FieldDestination for Inline {
    type Error = Error;
}
impl<const I: usize, T: for<'a> DecodeFromSlice<'a>> DecodeField<I, T> for Inline {
    type Value = T;
    fn decode_field(&mut self, f: CanonicalField<'_, T>) -> Result<T, DecodeIntoError<Error>> {
        f.with_payload(|b| scalar(b).map_err(destination))
    }
}

pub(super) struct ActionCustody {
    peer: Option<AllocationCharge>,
    controller: Option<ControllerCustody>,
    quantity: Option<AllocationCharge>,
    parser: Option<ActionDestination>,
}
impl ActionCustody {
    pub(super) fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.peer.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.controller.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.quantity.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.parser.as_ref().is_none_or(|v| v.belongs_to(pool))
    }
    fn empty() -> Self {
        Self {
            peer: None,
            controller: None,
            quantity: None,
            parser: None,
        }
    }
}
struct ActionDestination {
    peer: Option<ChargedPublicKey>,
    account: AccountDestination,
    quantity_pending: Option<PreparedQuantityDecode>,
    quantity: Option<ChargedQuantity>,
}
impl ActionDestination {
    fn new(pool: &AllocationBudget) -> Self {
        Self {
            peer: None,
            account: AccountDestination::new(pool),
            quantity_pending: None,
            quantity: None,
        }
    }
    fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.peer.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.account.belongs_to(pool)
            && self
                .quantity_pending
                .as_ref()
                .is_none_or(|v| v.belongs_to(pool))
            && self.quantity.as_ref().is_none_or(|v| v.belongs_to(pool))
    }
    #[allow(unsafe_code)]
    fn decode(
        &mut self,
        bytes: &[u8],
        pool: &AllocationBudget,
        cached: Option<&NposPenaltyAction>,
    ) -> Result<Option<(NposPenaltyAction, ActionCustody)>, Error> {
        let tag = u32::from_le_bytes(
            bytes
                .get(..4)
                .ok_or(norito::Error::LengthMismatch)?
                .try_into()
                .map_err(|_| norito::Error::LengthMismatch)?,
        );
        let mut offset = 4;
        match tag {
            0 => {
                let cached = match cached {
                    Some(NposPenaltyAction::ConsensusSlash(v)) => Some(v),
                    None => None,
                    _ => return Err(Error::SourceChanged),
                };
                let field = ncore::framed_field::<NposConsensusSlashAction>(bytes, &mut offset)?;
                let (evidence_key, signer, (), lane_id, (), slash_id, ()) =
                    field.with_payload(|b| {
                        let mut fields = SlashFields {
                            destination: self,
                            pool,
                            cached,
                        };
                        let (values, used) =
                            NposConsensusSlashAction::decode_fields(b, &mut fields)?;
                        finish(b, used).map_err(destination)?;
                        Ok(values)
                    })?;
                finish(bytes, offset)?;
                if cached.is_some() {
                    return Ok(None);
                }
                let account = self
                    .account
                    .complete
                    .take()
                    .ok_or(Error::Invariant("missing original controller"))?;
                let peer = self
                    .peer
                    .take()
                    .ok_or(Error::Invariant("missing original peer"))?;
                let quantity = self
                    .quantity
                    .take()
                    .ok_or(Error::Invariant("missing original amount"))?;
                // SAFETY: all three checked complete leaves move immediately into this
                // private value-first aggregate; subsequent moves are infallible.
                let (peer, peer_charge) = unsafe { peer.into_allocation_parts() };
                let (amount, quantity_charge) = unsafe { quantity.into_allocation_parts() };
                Ok(Some((
                    NposPenaltyAction::ConsensusSlash(NposConsensusSlashAction {
                        evidence_key,
                        signer,
                        peer_id: PeerId::new(peer),
                        lane_id,
                        validator: account.value,
                        slash_id,
                        amount,
                    }),
                    ActionCustody {
                        peer: Some(peer_charge),
                        controller: Some(account.custody),
                        quantity: Some(quantity_charge),
                        parser: None,
                    },
                )))
            }
            1 => {
                if cached.is_some_and(|v| {
                    !matches!(v, NposPenaltyAction::MarkConsensusEvidenceApplied(_))
                }) {
                    return Err(Error::SourceChanged);
                }
                let field = ncore::framed_field::<NposMarkConsensusEvidenceAppliedAction>(
                    bytes,
                    &mut offset,
                )?;
                let (evidence_key, height) = field.with_payload(|b| {
                    let (values, used) =
                        NposMarkConsensusEvidenceAppliedAction::decode_fields(b, &mut Inline)?;
                    finish(b, used).map_err(destination)?;
                    Ok(values)
                })?;
                finish(bytes, offset)?;
                Ok(cached.is_none().then_some((
                    NposPenaltyAction::MarkConsensusEvidenceApplied(
                        NposMarkConsensusEvidenceAppliedAction {
                            evidence_key,
                            height,
                        },
                    ),
                    ActionCustody::empty(),
                )))
            }
            _ => Err(norito::Error::Message("invalid enum discriminant".into()).into()),
        }
    }
}
struct PeerFields<'a> {
    destination: &'a mut ActionDestination,
    pool: &'a AllocationBudget,
    cached: Option<&'a PeerId>,
}
impl FieldDestination for PeerFields<'_> {
    type Error = Error;
}
impl DecodeField<0, PublicKey> for PeerFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, PublicKey>,
    ) -> Result<(), DecodeIntoError<Error>> {
        f.with_payload(|b| {
            let cached = self
                .cached
                .map(PeerId::public_key)
                .or_else(|| self.destination.peer.as_ref().map(ChargedPublicKey::get));
            if let Some(key) = cached {
                PreparedPublicKeyDecode::recheck_payload(b, key)?;
            } else {
                self.destination.peer = Some(
                    PreparedPublicKeyDecode::try_decode_payload(b, self.pool)
                        .map_err(|e| destination(e.into()))?,
                );
            }
            Ok(())
        })
    }
}
struct SlashFields<'a> {
    destination: &'a mut ActionDestination,
    pool: &'a AllocationBudget,
    cached: Option<&'a NposConsensusSlashAction>,
}
impl FieldDestination for SlashFields<'_> {
    type Error = Error;
}
impl<const I: usize> DecodeField<I, Hash> for SlashFields<'_> {
    type Value = Hash;
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, Hash>,
    ) -> Result<Hash, DecodeIntoError<Error>> {
        f.with_payload(|b| scalar(b).map_err(destination))
    }
}
impl DecodeField<1, u32> for SlashFields<'_> {
    type Value = u32;
    fn decode_field(&mut self, f: CanonicalField<'_, u32>) -> Result<u32, DecodeIntoError<Error>> {
        f.with_payload(|b| scalar(b).map_err(destination))
    }
}
impl DecodeField<2, PeerId> for SlashFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, PeerId>,
    ) -> Result<(), DecodeIntoError<Error>> {
        f.with_payload(|b| {
            let mut fields = PeerFields {
                destination: self.destination,
                pool: self.pool,
                cached: self.cached.map(|v| &v.peer_id),
            };
            let (_, used) = PeerId::decode_fields(b, &mut fields)?;
            finish(b, used).map_err(destination)
        })
    }
}
impl DecodeField<3, LaneId> for SlashFields<'_> {
    type Value = LaneId;
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, LaneId>,
    ) -> Result<LaneId, DecodeIntoError<Error>> {
        f.with_payload(|b| {
            let ((lane,), used) = LaneId::decode_fields(b, &mut Inline)?;
            finish(b, used).map_err(destination)?;
            Ok(LaneId::new(lane))
        })
    }
}
impl DecodeField<4, AccountId> for SlashFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, AccountId>,
    ) -> Result<(), DecodeIntoError<Error>> {
        f.with_payload(|b| {
            self.destination
                .account
                .decode(b, self.pool, self.cached.map(|v| &v.validator))
                .map_err(|e| destination(e.into()))
        })
    }
}
impl DecodeField<6, Quantity> for SlashFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        f: CanonicalField<'_, Quantity>,
    ) -> Result<(), DecodeIntoError<Error>> {
        f.with_payload(|b| {
            if self.cached.is_some() || self.destination.quantity.is_some() {
                PreparedQuantityDecode::recheck_payload(b)?;
                return Ok(());
            }
            PreparedQuantityDecode::decode_payload_retained(
                b,
                self.pool,
                &mut self.destination.quantity_pending,
            )
            .map_err(|e| destination(e.into()))?;
            let pending = self.destination.quantity_pending.take().ok_or_else(|| {
                destination(Error::Invariant("missing original amount destination"))
            })?;
            match pending.finish() {
                Ok(value) => self.destination.quantity = Some(value),
                Err(pending) => {
                    self.destination.quantity_pending = Some(pending);
                    return Err(destination(Error::Invariant("unfinished original amount")));
                }
            }
            Ok(())
        })
    }
}

/// Source-bound move-only destination for the original canonical action sequence.
///
/// Partial graph backing and leaf charges survive every local refusal. The caller
/// retains the funded input and canonical decode context and authenticates the
/// entire containing frame. This owner grants no penalty or consensus authority.
pub struct PreparedNposPenaltyActions {
    address: usize,
    length: usize,
    hash: Hash,
    span: SequenceSpan,
    flags: u8,
    count: usize,
    pool: AllocationBudget,
    spans: ncore::RetainedElementSequence,
    values: Option<ChargedBuffer<NposPenaltyAction>>,
    custody: Option<ChargedBuffer<ActionCustody>>,
    current: ActionDestination,
    complete: bool,
}
impl PreparedNposPenaltyActions {
    /// Inspect the original complete sequence framing without allocating a graph.
    /// # Errors
    /// Rejects a foreign pool, missing layout, invalid range or canonical framing.
    pub fn from_source(
        input: &ChargedBuffer<u8>,
        span: SequenceSpan,
        pool: &AllocationBudget,
    ) -> Result<Self, Error> {
        if !input.belongs_to(pool) {
            return Err(Error::ForeignPool);
        }
        let flags = ncore::effective_decode_flags().ok_or(Error::MissingLayout)?;
        let bytes = span
            .get(input.as_slice())
            .map_err(|_| Error::SourceChanged)?;
        let count = ncore::classify_decode_attempt(|| {
            let (count, used) = ncore::inspect_element_sequence(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            Ok(count)
        })?;
        Ok(Self {
            address: input.as_slice().as_ptr().addr(),
            length: input.as_slice().len(),
            hash: Hash::new(input.as_slice()),
            span,
            flags,
            count,
            pool: pool.clone(),
            spans: ncore::RetainedElementSequence::new(pool),
            values: None,
            custody: None,
            current: ActionDestination::new(pool),
            complete: false,
        })
    }
    fn check(&self, input: &ChargedBuffer<u8>) -> Result<(), Error> {
        if !input.belongs_to(&self.pool) {
            return Err(Error::ForeignPool);
        }
        if !cfg!(all(test, sumeragi_model_mutation = "DM46"))
            && (input.as_slice().as_ptr().addr() != self.address
                || input.as_slice().len() != self.length
                || Hash::new(input.as_slice()) != self.hash)
        {
            return Err(Error::SourceChanged);
        }
        if ncore::effective_decode_flags().ok_or(Error::MissingLayout)? != self.flags {
            return Err(Error::LayoutChanged);
        }
        Ok(())
    }
    /// Whether every retained partial owner belongs to this exact finite pool.
    #[must_use]
    pub fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.pool.same_pool(pool)
            && self.spans.belongs_to(pool)
            && self.current.belongs_to(pool)
            && self.values.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.custody.as_ref().is_none_or(|v| {
                v.belongs_to(pool) && v.as_slice().iter().all(|v| v.belongs_to(pool))
            })
    }
    /// Exact fixed action and per-action custody array layouts, excluding leaf/control storage.
    /// # Errors
    /// Rejects impossible native array geometry before allocation.
    pub fn backing_layouts(&self) -> Result<[Layout; 2], AllocationRefusal> {
        Ok([
            Layout::array::<NposPenaltyAction>(self.count)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<ActionCustody>(self.count)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
        ])
    }
    /// Borrow only the fully initialized original prefix.
    /// # Errors
    /// Rejects changed source, pool or advertised layout.
    pub fn initialized<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
    ) -> Result<&'a [NposPenaltyAction], Error> {
        self.check(input)?;
        Ok(self.values.as_ref().map_or(&[], ChargedBuffer::as_slice))
    }
    /// Resume actual charged arrays and leaf decoders without replacing completed custody.
    /// # Errors
    /// Preserves original physical or classified canonical refusal and partial storage.
    pub fn prepare(&mut self, input: &ChargedBuffer<u8>) -> Result<(), Error> {
        self.check(input)?;
        if self.complete {
            return Ok(());
        }
        if cfg!(all(test, sumeragi_model_mutation = "DM47")) {
            self.current = ActionDestination::new(&self.pool);
        }
        ncore::classify_decode_attempt(|| {
            let result = self.prepare_inner(input);
            match result {
                Err(Error::Codec(e)) => Err(e),
                other => Ok(other),
            }
        })?
    }
    fn prepare_inner(&mut self, input: &ChargedBuffer<u8>) -> Result<(), Error> {
        let bytes = self
            .span
            .get(input.as_slice())
            .map_err(|_| Error::SourceChanged)?;
        self.spans.prepare(bytes)?;
        let sequence = self.spans.as_prepared(bytes)?;
        if sequence.used() != bytes.len() || sequence.len() != self.count {
            return Err(norito::Error::LengthMismatch.into());
        }
        if self.values.is_none() {
            self.values = Some(ChargedBuffer::new(self.count, &self.pool)?);
        }
        if self.custody.is_none() {
            self.custody = Some(ChargedBuffer::new(self.count, &self.pool)?);
        }
        let values = self.values.as_mut().expect("original action backing");
        let custody = self
            .custody
            .as_mut()
            .expect("original action custody backing");
        sequence.decode_elements::<NposPenaltyAction, Error>(|index, field| {
            if let Some(value) = values.as_slice().get(index) {
                let parser = custody.as_mut_slice()[index]
                    .parser
                    .as_mut()
                    .ok_or_else(|| {
                        destination(Error::Invariant("missing original action parser"))
                    })?;
                field.with_payload(|b| {
                    parser
                        .decode(b, &self.pool, Some(value))
                        .map_err(destination)
                })?;
            } else {
                if index != values.as_slice().len() {
                    return Err(destination(Error::Invariant("skipped original action")));
                }
                let (value, mut owner) = field
                    .with_payload(|b| {
                        self.current
                            .decode(b, &self.pool, None)
                            .map_err(destination)
                    })?
                    .ok_or_else(|| destination(Error::Invariant("missing original action")))?;
                owner.parser = Some(std::mem::replace(
                    &mut self.current,
                    ActionDestination::new(&self.pool),
                ));
                values.push_reserved(value);
                custody.push_reserved(owner);
            }
            Ok(())
        })?;
        self.complete = true;
        Ok(())
    }
    /// Transfer the complete graph into its exact original immutable control.
    /// # Errors
    /// Returns the same partial/complete owner unchanged on every refusal.
    #[expect(
        clippy::result_large_err,
        reason = "refusal retains the original partial graph"
    )]
    pub fn finish(
        mut self,
        input: &ChargedBuffer<u8>,
    ) -> Result<NposPenaltyActions, (Self, Error)> {
        if let Err(e) = self.check(input) {
            return Err((self, e));
        }
        if !self.complete {
            return Err((self, Error::Invariant("unfinished original actions")));
        }
        let mut reservation = match self
            .pool
            .try_reserve(NposPenaltyActions::allocation_layout())
        {
            Ok(v) => v,
            Err(e) => return Err((self, e.into())),
        };
        // Acquire the immutable control before retiring retry parsers or moving any graph.
        let shell = match ChargedShared::<Funded>::reserve_from(&mut reservation) {
            Ok(v) => v,
            Err(e) => return Err((self, e.into())),
        };
        let mut custody = self
            .custody
            .take()
            .expect("complete original action custody");
        for owner in custody.as_mut_slice() {
            owner.parser = None;
        }
        let values = self.values.take().expect("complete original actions");
        Ok(NposPenaltyActions {
            storage: Storage::Admitted(shell.initialize(Funded { values, custody })),
        })
    }
}

#[cfg(test)]
mod tests;
