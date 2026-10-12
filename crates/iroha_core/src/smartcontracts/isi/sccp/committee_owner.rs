//! Original-pool custody of one immutable SCCP committee generation claim.
//!
//! Sharing retains the exact key/member/account allocations and their original credits.
//! Decoded claims require explicit admission; this owner does not authenticate finality.
//! Table nodes, publication and snapshot decode scratch remain separate obligations.

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, ChargedShared, PrepaidBufferError, PrepaidSharedError, RetainedPayload,
};
use iroha_crypto::Algorithm;
use iroha_data_model::{
    account::AccountId,
    nexus::PublicLaneValidatorRecord,
    sccp::{
        committee::{
            SccpCommitteeGenerationV1, SccpGenerationEndV1, SccpGenerationError,
            SccpGenerationMemberV1, SccpGenerationStartV1,
        },
        params::SccpParametersV1,
    },
    sumeragi::epoch::ValidatorEpochContextV1,
};
use iroha_model_base::topology::LaneId;
use norito::{
    core::{Encoder, SerializePayload},
    json::{self, JsonSerialize},
};
use std::{alloc::Layout, fmt, ops::Deref};

/// Structural refusal is distinct from original local allocation refusal.
#[derive(Debug, thiserror::Error)]
pub enum CommitteeOwnerError {
    /// Canonical generation creation or stored shape is invalid.
    #[error(transparent)]
    Invalid(#[from] SccpGenerationError),
    /// The finite original pool cannot admit the complete graph and shell.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The allocator refused an exact already prepaid allocation.
    #[error("SCCP generation allocator refused {requested_bytes} prepaid bytes")]
    Allocator {
        /// Exact failed allocation size.
        requested_bytes: usize,
    },
    /// Preserve the original decode-resource error, including private admission provenance.
    #[error(transparent)]
    DecodeResource(norito::core::Error),
    /// An internal allocation plan does not match its materialization.
    #[error("SCCP generation allocation invariant: {0}")]
    Invariant(&'static str),
}

impl CommitteeOwnerError {
    fn account(error: norito::core::Error) -> Self {
        if error.is_decode_resource_limit() {
            Self::DecodeResource(error)
        } else {
            Self::Invalid(SccpGenerationError::Field("members"))
        }
    }
    fn buffer(error: PrepaidBufferError) -> Self {
        match error {
            PrepaidBufferError::Allocation(ChargedBufferError::Admission(error)) => {
                Self::Admission(error)
            }
            PrepaidBufferError::Allocation(ChargedBufferError::Allocator { requested_bytes }) => {
                Self::Allocator { requested_bytes }
            }
            PrepaidBufferError::Reservation(_) => Self::Invariant("buffer reservation"),
        }
    }
}

/// An immutable canonical generation backed by its original finite execution pool.
///
/// There is no decoder, mutable borrow or extraction method. Clones share the original
/// allocation; a separately admitted clone is required to change lifecycle fields.
#[derive(Clone)]
pub struct RetainedSccpCommitteeGeneration {
    owner: ChargedShared<RetainedPayload<SccpCommitteeGenerationV1>>,
}

impl RetainedSccpCommitteeGeneration {
    /// Borrow the canonical claim without detaching its allocation custody.
    pub fn record(&self) -> &SccpCommitteeGenerationV1 {
        self.owner.get()
    }

    /// Check both the shell and every nested charge against this exact pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.owner.belongs_to(budget) && self.owner.deref().belongs_to(budget)
    }

    /// Original retained graph, ledger and shared-shell bytes; no new capacity is acquired.
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.owner
            .allocation_bytes()?
            .checked_add(Self::shared_layout().size())
    }

    fn shared_layout() -> Layout {
        ChargedShared::<RetainedPayload<SccpCommitteeGenerationV1>>::allocation_layout()
    }

    /// Admit a structurally validated decoded claim; its provenance remains unauthenticated.
    ///
    /// # Errors
    /// Rejects malformed claims or any original local allocation refusal before publication.
    pub fn admit_claim(
        source: &SccpCommitteeGenerationV1,
        budget: &AllocationBudget,
    ) -> Result<Self, CommitteeOwnerError> {
        source.validate()?;
        Self::copy_record(source, source.end, source.dest_cleared_lc, budget)
    }

    /// Create a funded record directly from the original epoch and borrowed resolved seats.
    ///
    /// The caller supplies the authenticated epoch and G6's original source-cut bindings in
    /// committee order. This function checks that each supplied record names that exact peer;
    /// it cannot replace the caller's complete G6 tenure lookup or authenticate finality.
    ///
    /// # Errors
    /// Rejects malformed credentials, reordered bindings, invalid creation facts or resources.
    pub fn admit_new(
        start: SccpGenerationStartV1,
        parameters: &SccpParametersV1,
        epoch: &ValidatorEpochContextV1,
        members: &[Option<&PublicLaneValidatorRecord>],
        budget: &AllocationBudget,
    ) -> Result<Self, CommitteeOwnerError> {
        if !iroha_data_model::block::consensus::is_valid_committee_size(epoch.committee.len())
            || members.len() != epoch.committee.len()
        {
            return Err(SccpGenerationError::Field("members").into());
        }
        // Exact protocol maximum, held on the stack; never an uncharged temporary Vec.
        let mut keys = [[0u8; 48]; 31];
        for (index, seat) in epoch.committee.iter().enumerate() {
            let (algorithm, bytes) = seat
                .validator
                .public_key()
                .try_to_bytes()
                .map_err(|_| SccpGenerationError::Field("keys"))?;
            if algorithm != Algorithm::BlsNormal {
                return Err(SccpGenerationError::Field("keys").into());
            }
            keys[index] = bytes
                .try_into()
                .map_err(|_| SccpGenerationError::Field("keys"))?;
            if members[index].is_some_and(|record| record.peer_id != seat.validator) {
                return Err(SccpGenerationError::Field("original_member_peer").into());
            }
        }
        let members = MemberSource::Records(members);
        let keys = &keys[..epoch.committee.len()];
        let mut construction = Construction::new(keys.len(), members, budget)?;
        let keys = construction.keys(keys)?;
        let members = construction.members(members)?;
        let record =
            SccpCommitteeGenerationV1::from_owned_parts(start, parameters, epoch, keys, members)?;
        construction.finish(record)
    }

    /// Admit a separate immutable lifecycle version, preserving creation facts and the source.
    ///
    /// End and clearance are write-once: an existing value cannot be removed or changed.
    /// Repeating the same values shares the original owner without allocating.
    ///
    /// # Errors
    /// Rejects a foreign pool, rewritten lifecycle fact, invalid shape or resource refusal.
    pub fn with_lifecycle(
        &self,
        end: Option<SccpGenerationEndV1>,
        cleared: Option<u64>,
        budget: &AllocationBudget,
    ) -> Result<Self, CommitteeOwnerError> {
        if !self.belongs_to(budget) {
            return Err(CommitteeOwnerError::Invariant("foreign lifecycle pool"));
        }
        let source = self.record();
        if (source.end.is_some() && source.end != end)
            || (source.dest_cleared_lc.is_some() && source.dest_cleared_lc != cleared)
        {
            return Err(SccpGenerationError::Field("immutable_lifecycle").into());
        }
        if source.end == end && source.dest_cleared_lc == cleared {
            return Ok(self.clone());
        }
        Self::copy_record(source, end, cleared, budget)
    }

    fn copy_record(
        source: &SccpCommitteeGenerationV1,
        end: Option<SccpGenerationEndV1>,
        cleared: Option<u64>,
        budget: &AllocationBudget,
    ) -> Result<Self, CommitteeOwnerError> {
        let members = MemberSource::Claims(&source.members);
        let mut construction = Construction::new(source.keys.len(), members, budget)?;
        let keys = construction.keys(&source.keys)?;
        let members = construction.members(members)?;
        let record = SccpCommitteeGenerationV1 {
            generation: source.generation,
            committee_root: source.committee_root,
            keys,
            members,
            cause: source.cause,
            start_height: source.start_height,
            start_timestamp_ms: source.start_timestamp_ms,
            start_lc: source.start_lc,
            validity_ms: source.validity_ms,
            deadline_ms: source.deadline_ms,
            grace_ms: source.grace_ms,
            progress_cap_ms: source.progress_cap_ms,
            liable_until_lc: source.liable_until_lc,
            dest_cleared_lc: cleared,
            end,
        };
        record.validate()?;
        construction.finish(record)
    }
}

#[derive(Clone, Copy)]
enum MemberSource<'a> {
    Claims(&'a [Option<SccpGenerationMemberV1>]),
    Records(&'a [Option<&'a PublicLaneValidatorRecord>]),
}
impl<'a> MemberSource<'a> {
    fn len(self) -> usize {
        match self {
            Self::Claims(value) => value.len(),
            Self::Records(value) => value.len(),
        }
    }
    fn get(self, index: usize) -> Option<(LaneId, &'a AccountId, u64)> {
        match self {
            Self::Claims(value) => value[index]
                .as_ref()
                .map(|member| (member.lane_id, &member.validator, member.activation_height)),
            Self::Records(value) => value[index]
                .map(|member| (member.lane_id, &member.validator, member.activation_height)),
        }
    }
}

/// Declared before any payload locals, so normal refusal drops all payloads before credits.
struct Construction<'a> {
    budget: &'a AllocationBudget,
    reservation: AllocationReservation,
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Construction<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(charges) = self.charges.take() {
                std::mem::forget(charges);
            }
        }
    }
}
impl<'a> Construction<'a> {
    fn new(
        count: usize,
        members: MemberSource<'_>,
        budget: &'a AllocationBudget,
    ) -> Result<Self, CommitteeOwnerError> {
        let keys =
            Layout::array::<[u8; 48]>(count).map_err(|_| AllocationRefusal::DemandOverflow)?;
        let bindings = Layout::array::<Option<SccpGenerationMemberV1>>(members.len())
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        let mut bytes = keys
            .size()
            .checked_add(bindings.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut count = 2usize;
        for index in 0..members.len() {
            if let Some((_, account, _)) = members.get(index) {
                let mut overflow = false;
                account
                    .for_each_admission_clone_layout(|layout| {
                        if let (Some(next), Some(charges)) =
                            (bytes.checked_add(layout.size()), count.checked_add(1))
                        {
                            bytes = next;
                            count = charges;
                        } else {
                            overflow = true;
                        }
                    })
                    .map_err(CommitteeOwnerError::account)?;
                if overflow {
                    return Err(AllocationRefusal::DemandOverflow.into());
                }
            }
        }
        let ledger = Layout::array::<AllocationCharge>(count)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        let total = bytes
            .checked_add(ledger.size())
            .and_then(|value| {
                value.checked_add(RetainedSccpCommitteeGeneration::shared_layout().size())
            })
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_bytes(total)?;
        let charges = ChargedBuffer::from_reservation(count, &mut reservation)
            .map_err(CommitteeOwnerError::buffer)?;
        Ok(Self {
            budget,
            reservation,
            charges: Some(charges),
        })
    }
    fn retain(&mut self, charge: AllocationCharge) -> Result<(), CommitteeOwnerError> {
        if let Err(charge) = self
            .charges
            .as_mut()
            .expect("construction ledger")
            .try_push(charge)
        {
            // Never refund backing whose payload may still be in a caller's local variable.
            std::mem::forget(charge);
            return Err(CommitteeOwnerError::Invariant("charge count"));
        }
        Ok(())
    }
    #[allow(
        unsafe_code,
        reason = "exact prepaid Vec backing moves into an immutable retained canonical field"
    )]
    fn vector<T>(&mut self, buffer: ChargedBuffer<T>) -> Result<Vec<T>, CommitteeOwnerError> {
        // SAFETY: no caller grows or exports this allocation; finish retains its exact ledger.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        self.retain(charge)?;
        Ok(values)
    }
    fn keys(&mut self, keys: &[[u8; 48]]) -> Result<Vec<[u8; 48]>, CommitteeOwnerError> {
        let mut buffer = ChargedBuffer::from_reservation(keys.len(), &mut self.reservation)
            .map_err(CommitteeOwnerError::buffer)?;
        for key in keys {
            buffer
                .try_push(*key)
                .map_err(|_| CommitteeOwnerError::Invariant("key count"))?;
        }
        self.vector(buffer)
    }
    fn account(&mut self, account: &AccountId) -> Result<AccountId, CommitteeOwnerError> {
        let mut error = None;
        account
            .for_each_admission_clone_layout(|layout| {
                if error.is_some() {
                    return;
                }
                match self.reservation.try_split(layout) {
                    Ok(charge) => {
                        error = self.retain(charge).err();
                    }
                    Err(_) => {
                        error = Some(CommitteeOwnerError::Invariant("account reservation"));
                    }
                }
            })
            .map_err(CommitteeOwnerError::account)?;
        if let Some(error) = error {
            return Err(error);
        }
        account
            .try_clone_for_admission()
            .map_err(CommitteeOwnerError::account)
    }
    fn members(
        &mut self,
        source: MemberSource<'_>,
    ) -> Result<Vec<Option<SccpGenerationMemberV1>>, CommitteeOwnerError> {
        let mut buffer = ChargedBuffer::from_reservation(source.len(), &mut self.reservation)
            .map_err(CommitteeOwnerError::buffer)?;
        for index in 0..source.len() {
            let member = match source.get(index) {
                None => None,
                Some((lane_id, validator, activation_height)) => Some(SccpGenerationMemberV1 {
                    lane_id,
                    validator: self.account(validator)?,
                    activation_height,
                }),
            };
            buffer
                .try_push(member)
                .map_err(|_| CommitteeOwnerError::Invariant("member count"))?;
        }
        self.vector(buffer)
    }
    #[allow(
        unsafe_code,
        reason = "bind every exact canonical allocation to its original prepaid ledger"
    )]
    fn finish(
        mut self,
        record: SccpCommitteeGenerationV1,
    ) -> Result<RetainedSccpCommitteeGeneration, CommitteeOwnerError> {
        let charges = self.charges.as_ref().expect("construction ledger");
        if self.reservation.remaining_bytes()
            != RetainedSccpCommitteeGeneration::shared_layout().size()
            || charges.as_slice().len() != charges.capacity()
        {
            // The argument must be destroyed before self releases its credits.
            drop(record);
            return Err(CommitteeOwnerError::Invariant("complete graph demand"));
        }
        let charges = self.charges.take().expect("construction ledger");
        // SAFETY: keys, members and every account buffer were allocated at their exact prepaid
        // layout above and moved unchanged into record. It exposes no mutation or extraction.
        let retained = match unsafe { RetainedPayload::try_new(record, charges, self.budget) } {
            Ok(retained) => retained,
            Err((record, charges, _)) => {
                // Foreign custody is an invariant failure; retain it even if destruction
                // unwinds rather than refund storage whose reclamation is unproven.
                std::mem::forget(charges);
                drop(record);
                return Err(CommitteeOwnerError::Invariant("original graph pool"));
            }
        };
        match ChargedShared::from_reservation(retained, &mut self.reservation) {
            Ok(owner) => Ok(RetainedSccpCommitteeGeneration { owner }),
            Err((retained, error)) => {
                drop(retained);
                Err(match error {
                    PrepaidSharedError::Allocator { requested_bytes } => {
                        CommitteeOwnerError::Allocator { requested_bytes }
                    }
                    PrepaidSharedError::Reservation(_) => {
                        CommitteeOwnerError::Invariant("shared shell reservation")
                    }
                })
            }
        }
    }
}

impl Deref for RetainedSccpCommitteeGeneration {
    type Target = SccpCommitteeGenerationV1;
    fn deref(&self) -> &Self::Target {
        self.record()
    }
}
impl fmt::Debug for RetainedSccpCommitteeGeneration {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.record().fmt(out)
    }
}
impl PartialEq for RetainedSccpCommitteeGeneration {
    fn eq(&self, other: &Self) -> bool {
        self.record() == other.record()
    }
}
impl Eq for RetainedSccpCommitteeGeneration {}
impl norito::NoritoSchema for RetainedSccpCommitteeGeneration {
    fn nominal_name() -> String {
        <SccpCommitteeGenerationV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <SccpCommitteeGenerationV1 as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedSccpCommitteeGeneration {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.record().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.record().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.record().encoded_len_exact()
    }
}
impl JsonSerialize for RetainedSccpCommitteeGeneration {
    fn json_serialize(&self, out: &mut String) {
        self.record().json_serialize(out)
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.record().json_serialize_to(out)
    }
}

#[cfg(test)]
#[path = "committee_owner/tests.rs"]
mod tests;
