//! Original funded SCCP committee payload with independent lifecycle scalars.
//!
//! Current/undo readers share only immutable key/account allocations. No decoder or mutable
//! body escape creates custody. Snapshot DTOs require explicit original-pool admission.
//! TODO: fund enclosing ordinary MV map nodes and snapshot source maps at their owners.

use std::{alloc::Layout, fmt, ops::Deref};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, ChargedShared, PrepaidBufferError, PrepaidSharedError, RetainedPayload,
};
use iroha_data_model::{
    account::AccountId,
    sccp::generation::{
        SccpCommitteeGenerationV1, SccpGenerationCauseV1, SccpGenerationEndV1,
        SccpGenerationMemberV1,
    },
};
use iroha_model_base::topology::LaneId;
use norito::{
    core::{Encoder, PayloadRef, SerializePayload},
    json::{self, JsonSerialize},
};

/// Structural rejection stays distinct from original local allocation refusal.
#[derive(Debug, thiserror::Error)]
pub enum GenerationRecordError {
    /// Invalid canonical record or construction relation.
    #[error("invalid SCCP generation: {0}")]
    Invalid(&'static str),
    /// Original configured execution pool refused admission.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The physical allocator refused an already admitted allocation.
    #[error("SCCP generation allocation unavailable ({bytes} bytes)")]
    Allocator {
        /// Exact requested size.
        bytes: usize,
    },
    /// Canonical account cloning failed; logical resource failures remain identifiable.
    #[error(transparent)]
    Account(#[from] norito::core::Error),
}

/// Borrowed immutable registration fields, before any funded copy.
#[derive(Clone, Copy)]
pub(super) struct MemberRef<'a> {
    pub(super) lane_id: LaneId,
    pub(super) validator: &'a AccountId,
    pub(super) activation_height: u64,
}

/// World value retaining original committee allocations through COW, undo and publication.
#[derive(Clone)]
pub struct RetainedSccpGeneration {
    body: ChargedShared<RetainedPayload<SccpCommitteeGenerationV1>>,
    /// First authenticated destination clearance; copied independently in each MV version.
    pub dest_cleared_lc: Option<u64>,
    /// Original transition end; copied independently in each MV version.
    pub end: Option<SccpGenerationEndV1>,
}

#[derive(Default)]
struct Demand {
    bytes: usize,
    charges: usize,
}
impl Demand {
    fn total_bytes(&self) -> Result<usize, GenerationRecordError> {
        let ledger = Layout::array::<AllocationCharge>(self.charges)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        let shell =
            ChargedShared::<RetainedPayload<SccpCommitteeGenerationV1>>::allocation_layout();
        self.bytes
            .checked_add(ledger.size())
            .and_then(|n| n.checked_add(shell.size()))
            .ok_or_else(|| AllocationRefusal::DemandOverflow.into())
    }
    fn add(&mut self, layout: Layout) -> Result<(), GenerationRecordError> {
        self.bytes = self
            .bytes
            .checked_add(layout.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        self.charges = self
            .charges
            .checked_add(1)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(())
    }
    fn array<T>(&mut self, n: usize) -> Result<(), GenerationRecordError> {
        self.add(Layout::array::<T>(n).map_err(|_| AllocationRefusal::DemandOverflow)?)
    }
}
fn prepaid_error(error: PrepaidBufferError) -> GenerationRecordError {
    match error {
        PrepaidBufferError::Allocation(ChargedBufferError::Allocator { requested_bytes }) => {
            GenerationRecordError::Allocator {
                bytes: requested_bytes,
            }
        }
        PrepaidBufferError::Allocation(ChargedBufferError::Admission(original)) => original.into(),
        PrepaidBufferError::Reservation(_) => {
            GenerationRecordError::Invalid("original reservation mismatch")
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionCheckpoint {
    NestedAccount,
    BeforeSharedShell,
}
#[cfg(test)]
thread_local! {
    static CONSTRUCTION_UNWIND: std::cell::Cell<Option<ConstructionCheckpoint>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn construction_checkpoint(stage: ConstructionCheckpoint) {
    if CONSTRUCTION_UNWIND.with(|requested| requested.get() == Some(stage)) {
        CONSTRUCTION_UNWIND.with(|requested| requested.set(None));
        panic!("controlled partial construction unwind at {stage:?}");
    }
}

// The partial canonical body drops before its original allocation ledger, including
// when a later physical allocation, validation or caller unwinds. No blanket leak is
// necessary: all partially constructed owned fields remain inside this one owner.
struct Construction<'a, T> {
    body: T,
    charges: ChargedBuffer<AllocationCharge>,
    budget: &'a AllocationBudget,
    reservation: AllocationReservation,
}
impl<'a, T> Construction<'a, T> {
    /// Move the complete private graph directly into its immutable ledger owner.
    /// The checked constructor only compares pool identities: it invokes no user code,
    /// allocation, formatting, assertions or other panic-capable operation between these
    /// field moves and the retained owner. Refusal destroys the body before its ledger.
    #[allow(
        unsafe_code,
        reason = "all body backings were admitted once under the original pool"
    )]
    fn into_payload(
        self,
    ) -> Result<(RetainedPayload<T>, AllocationReservation), GenerationRecordError> {
        // SAFETY: every body allocation has its exact charge; no mutable escape exists.
        let payload = unsafe { RetainedPayload::try_new(self.body, self.charges, self.budget) }
            .map_err(|(body, charges, _)| {
                drop(body);
                drop(charges);
                GenerationRecordError::Invalid("foreign original pool")
            })?;
        Ok((payload, self.reservation))
    }

    fn new_prepaid(
        demand: Demand,
        budget: &'a AllocationBudget,
        prepaid: &mut AllocationReservation,
        body: T,
    ) -> Result<Self, GenerationRecordError> {
        if !prepaid.belongs_to(budget) {
            return Err(GenerationRecordError::Invalid(
                "foreign original reservation",
            ));
        }
        let bytes = demand.total_bytes()?;
        let mut reservation = prepaid
            .try_partition_bytes(bytes)
            .map_err(|_| GenerationRecordError::Invalid("incomplete original reservation"))?;
        let charges = ChargedBuffer::from_reservation(demand.charges, &mut reservation)
            .map_err(prepaid_error)?;
        Ok(Self {
            body,
            charges,
            budget,
            reservation,
        })
    }
    fn retain(&mut self, charge: AllocationCharge) -> Result<(), GenerationRecordError> {
        if let Err(charge) = self.charges.try_push(charge) {
            // account() reserves before cloning; this charge owns no allocation yet.
            drop(charge);
            return Err(GenerationRecordError::Invalid("charge ledger mismatch"));
        }
        Ok(())
    }
    #[allow(
        unsafe_code,
        reason = "exact prepaid backing moves into a private immutable model field"
    )]
    fn vector<U>(&mut self, values: ChargedBuffer<U>) -> Result<Vec<U>, GenerationRecordError> {
        // SAFETY: the caller moves this backing into the immutable body and never grows it.
        let (values, charge) = unsafe { values.into_allocation_parts() };
        if let Err(charge) = self.charges.try_push(charge) {
            // Unlike account prepayment, this charge already owns this exact backing.
            drop(values);
            drop(charge);
            return Err(GenerationRecordError::Invalid("charge ledger mismatch"));
        }
        Ok(values)
    }
    fn account(&mut self, source: &AccountId) -> Result<AccountId, GenerationRecordError> {
        let mut failed = None;
        source.for_each_admission_clone_layout(|layout| {
            if failed.is_some() {
                return;
            }
            match self.reservation.try_split(layout) {
                Ok(charge) => failed = self.retain(charge).err(),
                Err(_) => failed = Some(GenerationRecordError::Invalid("account demand changed")),
            }
        })?;
        if let Some(error) = failed {
            return Err(error);
        }
        let account = source.try_clone_for_admission()?;
        #[cfg(test)]
        construction_checkpoint(ConstructionCheckpoint::NestedAccount);
        Ok(account)
    }
}

impl RetainedSccpGeneration {
    /// Admit a snapshot/test DTO as a new graph in the original pool, without granting authority.
    ///
    /// # Errors
    /// Invalid structure, original capacity refusal or fallible physical/account allocation.
    pub(crate) fn admit(
        source: &SccpCommitteeGenerationV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationRecordError> {
        let mut reservation = budget.try_reserve_bytes(Self::admission_demand(source)?)?;
        Self::admit_prepaid(source, budget, &mut reservation)
    }

    fn snapshot_members(
        source: &SccpCommitteeGenerationV1,
    ) -> Result<[Option<MemberRef<'_>>; 31], GenerationRecordError> {
        if !source.is_well_formed() {
            return Err(GenerationRecordError::Invalid("record structure"));
        }
        let mut members = [None; 31];
        for (slot, source) in members.iter_mut().zip(&source.members) {
            *slot = source.as_ref().map(|member| MemberRef {
                lane_id: member.lane_id,
                validator: &member.validator,
                activation_height: member.activation_height,
            });
        }
        Ok(members)
    }

    /// Exact complete snapshot payload demand; decoding remains a claim, not authority.
    pub(crate) fn admission_demand(
        source: &SccpCommitteeGenerationV1,
    ) -> Result<usize, GenerationRecordError> {
        let members = Self::snapshot_members(source)?;
        Self::allocation_demand(&source.keys, &members[..source.members.len()])
    }

    /// Restore one DTO from its partition of an aggregate original snapshot reservation.
    pub(crate) fn admit_prepaid(
        source: &SccpCommitteeGenerationV1,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, GenerationRecordError> {
        let members = Self::snapshot_members(source)?;
        Self::from_members_prepaid(
            source,
            &source.keys,
            &members[..source.members.len()],
            budget,
            reservation,
        )
    }

    /// Create the actual generation from borrowed keys and original staking registrations.
    /// Only scalar fields are read from `metadata`; its vectors are never copied.
    pub(super) fn from_members(
        metadata: &SccpCommitteeGenerationV1,
        keys: &[[u8; 48]],
        members: &[Option<MemberRef<'_>>],
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationRecordError> {
        let demand = Self::demand(keys, members)?;
        let mut reservation = budget.try_reserve_bytes(demand.total_bytes()?)?;
        Self::from_members_prepaid(metadata, keys, members, budget, &mut reservation)
    }

    fn demand(
        keys: &[[u8; 48]],
        members: &[Option<MemberRef<'_>>],
    ) -> Result<Demand, GenerationRecordError> {
        if !iroha_data_model::block::consensus::is_valid_committee_size(keys.len())
            || keys.len() != members.len()
        {
            return Err(GenerationRecordError::Invalid("committee geometry"));
        }
        let mut demand = Demand::default();
        demand.array::<[u8; 48]>(keys.len())?;
        demand.array::<Option<SccpGenerationMemberV1>>(members.len())?;
        for member in members.iter().flatten() {
            let mut error = None;
            member.validator.for_each_admission_clone_layout(|layout| {
                if error.is_none() {
                    error = demand.add(layout).err();
                }
            })?;
            if let Some(error) = error {
                return Err(error);
            }
        }
        Ok(demand)
    }

    /// Exact complete data, nested-account, ledger and shared-shell demand of a new record.
    pub(super) fn allocation_demand(
        keys: &[[u8; 48]],
        members: &[Option<MemberRef<'_>>],
    ) -> Result<usize, GenerationRecordError> {
        Self::demand(keys, members)?.total_bytes()
    }

    /// Construct from one partition of the caller's aggregate original-pool reservation.
    pub(super) fn from_members_prepaid(
        metadata: &SccpCommitteeGenerationV1,
        keys: &[[u8; 48]],
        members: &[Option<MemberRef<'_>>],
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, GenerationRecordError> {
        let demand = Self::demand(keys, members)?;
        let body = SccpCommitteeGenerationV1 {
            generation: metadata.generation,
            committee_root: metadata.committee_root,
            keys: Vec::new(),
            members: Vec::new(),
            cause: metadata.cause,
            start_height: metadata.start_height,
            start_timestamp_ms: metadata.start_timestamp_ms,
            start_lc: metadata.start_lc,
            validity_ms: metadata.validity_ms,
            deadline_ms: metadata.deadline_ms,
            grace_ms: metadata.grace_ms,
            progress_cap_ms: metadata.progress_cap_ms,
            liable_until_lc: metadata.liable_until_lc,
            dest_cleared_lc: None,
            end: None,
        };
        let mut construction = Construction::new_prepaid(demand, budget, reservation, body)?;
        let mut key_buffer =
            ChargedBuffer::from_reservation(keys.len(), &mut construction.reservation)
                .map_err(prepaid_error)?;
        for key in keys {
            key_buffer
                .try_push(*key)
                .map_err(|_| GenerationRecordError::Invalid("key count changed"))?;
        }
        construction.body.keys = construction.vector(key_buffer)?;
        let mut member_buffer =
            ChargedBuffer::from_reservation(members.len(), &mut construction.reservation)
                .map_err(prepaid_error)?;
        for member in members {
            let value = match member {
                None => None,
                Some(member) => Some(SccpGenerationMemberV1 {
                    lane_id: member.lane_id,
                    validator: construction.account(member.validator)?,
                    activation_height: member.activation_height,
                }),
            };
            member_buffer
                .try_push(value)
                .map_err(|_| GenerationRecordError::Invalid("member count changed"))?;
        }
        construction.body.members = construction.vector(member_buffer)?;
        if !construction.body.is_well_formed() {
            return Err(GenerationRecordError::Invalid(
                "constructed record structure",
            ));
        }
        let (payload, mut reservation) = construction.into_payload()?;
        #[cfg(test)]
        construction_checkpoint(ConstructionCheckpoint::BeforeSharedShell);
        let body = ChargedShared::from_reservation(payload, &mut reservation).map_err(
            |(payload, error)| {
                drop(payload);
                match error {
                    PrepaidSharedError::Allocator { requested_bytes } => {
                        GenerationRecordError::Allocator {
                            bytes: requested_bytes,
                        }
                    }
                    PrepaidSharedError::Reservation(_) => {
                        GenerationRecordError::Invalid("shared shell reservation")
                    }
                }
            },
        )?;
        if reservation.remaining_bytes() != 0 {
            return Err(GenerationRecordError::Invalid("unused generation demand"));
        }
        let result = Self {
            body,
            dest_cleared_lc: metadata.dest_cleared_lc,
            end: metadata.end,
        };
        if !result.is_well_formed() {
            return Err(GenerationRecordError::Invalid("lifecycle structure"));
        }
        Ok(result)
    }
    /// Inclusive liability over the original immutable deadlines and local lifecycle scalars.
    #[must_use]
    pub fn is_liable(&self, current: u64, lc: u64) -> bool {
        self.generation == current
            || lc <= self.liable_until_lc
            || lc
                <= self.dest_cleared_lc.map_or_else(
                    || self.liable_until_lc.saturating_add(self.progress_cap_ms),
                    |cleared| cleared.saturating_add(self.grace_ms),
                )
    }
    /// Structural key/deadline checks; this grants no committee authority.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.body.get().is_well_formed()
            && self.dest_cleared_lc.is_none_or(|lc| lc >= self.start_lc)
            && self.end.is_none_or(|end| {
                end.end_height >= self.start_height
                    && end.end_timestamp_ms >= self.start_timestamp_ms
                    && end.next_committee_root != [0; 32]
                    && (1..=iroha_data_model::sumeragi_finality::certified_result::MAX_VALIDITY_MS)
                        .contains(&end.successor_validity_ms)
            })
    }
}
impl Deref for RetainedSccpGeneration {
    type Target = SccpCommitteeGenerationV1;
    fn deref(&self) -> &Self::Target {
        self.body.get()
    }
}
impl fmt::Debug for RetainedSccpGeneration {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("RetainedSccpGeneration")
            .field("body", self.body.get())
            .field("end", &self.end)
            .field("dest_cleared_lc", &self.dest_cleared_lc)
            .finish()
    }
}
impl PartialEq for RetainedSccpGeneration {
    fn eq(&self, other: &Self) -> bool {
        self.body.get() == other.body.get()
            && self.end == other.end
            && self.dest_cleared_lc == other.dest_cleared_lc
    }
}
impl Eq for RetainedSccpGeneration {}
impl norito::NoritoSchema for RetainedSccpGeneration {
    fn nominal_name() -> String {
        <SccpCommitteeGenerationV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <SccpCommitteeGenerationV1 as norito::NoritoSchema>::frame_name()
    }
}

#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct RecordView<'a> {
    generation: u64,
    committee_root: [u8; 32],
    keys: PayloadRef<'a, Vec<[u8; 48]>>,
    members: PayloadRef<'a, Vec<Option<SccpGenerationMemberV1>>>,
    cause: SccpGenerationCauseV1,
    start_height: u64,
    start_timestamp_ms: u64,
    start_lc: u64,
    validity_ms: u64,
    deadline_ms: u64,
    grace_ms: u64,
    progress_cap_ms: u64,
    liable_until_lc: u64,
    dest_cleared_lc: Option<u64>,
    end: Option<SccpGenerationEndV1>,
}
impl RetainedSccpGeneration {
    fn view(&self) -> RecordView<'_> {
        RecordView {
            generation: self.generation,
            committee_root: self.committee_root,
            keys: PayloadRef(&self.keys),
            members: PayloadRef(&self.members),
            cause: self.cause,
            start_height: self.start_height,
            start_timestamp_ms: self.start_timestamp_ms,
            start_lc: self.start_lc,
            validity_ms: self.validity_ms,
            deadline_ms: self.deadline_ms,
            grace_ms: self.grace_ms,
            progress_cap_ms: self.progress_cap_ms,
            liable_until_lc: self.liable_until_lc,
            dest_cleared_lc: self.dest_cleared_lc,
            end: self.end,
        }
    }
}
impl SerializePayload for RetainedSccpGeneration {
    fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.view().serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.view().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.view().encoded_len_exact()
    }
}
impl JsonSerialize for RetainedSccpGeneration {
    fn json_serialize(&self, out: &mut String) {
        self.view().json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.view().json_serialize_to(out)
    }
}

#[cfg(test)]
mod tests {
    //! Original-pool lifetime, exact refusal and canonical lifecycle controls.
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use norito::codec::{DecodeAll, Encode};

    fn claim() -> SccpCommitteeGenerationV1 {
        let mut keys: Vec<[u8; 48]> = (1..=4)
            .map(|seed| {
                let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap();
                key.public_key()
                    .try_to_bytes()
                    .unwrap()
                    .1
                    .try_into()
                    .unwrap()
            })
            .collect();
        keys.sort();
        let validator = AccountId::new(
            KeyPair::try_from_seed(vec![7; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        SccpCommitteeGenerationV1 {
            generation: 1,
            committee_root: iroha_data_model::sumeragi_finality::certified_result::committee_root(
                &keys,
            )
            .unwrap(),
            keys,
            members: vec![
                Some(SccpGenerationMemberV1 {
                    lane_id: LaneId::SINGLE,
                    validator,
                    activation_height: 1,
                }),
                None,
                None,
                None,
            ],
            cause: SccpGenerationCauseV1::Genesis,
            start_height: 1,
            start_timestamp_ms: 100,
            start_lc: 100,
            validity_ms: 10,
            deadline_ms: 110,
            grace_ms: 5,
            progress_cap_ms: 10,
            liable_until_lc: 115,
            dest_cleared_lc: None,
            end: None,
        }
    }
    #[test]
    fn original_generation_allocations_follow_clones_and_retire_at_final_reader() {
        let source = claim();
        let budget = AllocationBudget::new(1024 * 1024);
        let original = RetainedSccpGeneration::admit(&source, &budget).unwrap();
        let bytes = budget.reserved_bytes();
        assert!(bytes > 0);
        let current = original.clone();
        assert!(ChargedShared::ptr_eq(&original.body, &current.body));
        assert_eq!(original.keys.as_ptr(), current.keys.as_ptr());
        assert_eq!(original.members.as_ptr(), current.members.as_ptr());
        assert!(current.body.belongs_to(&budget));
        assert!(current.body.get().is_well_formed());
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(original);
        assert_eq!(budget.reserved_bytes(), bytes);
        assert_eq!(current.keys, source.keys);
        drop(current);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn original_capacity_refusal_leaves_source_and_pool_unchanged_then_retries() {
        let source = claim();
        let unchanged = source.clone();
        let budget = AllocationBudget::new(1024 * 1024);
        let measured = RetainedSccpGeneration::admit(&source, &budget).unwrap();
        let bytes = budget.reserved_bytes();
        drop(measured);
        budget.set_limit_bytes(bytes - 1);
        assert!(matches!(
            RetainedSccpGeneration::admit(&source, &budget),
            Err(GenerationRecordError::Admission(
                AllocationRefusal::ExceedsLimit { .. }
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(source, unchanged);
        budget.set_limit_bytes(bytes);
        let retry = RetainedSccpGeneration::admit(&source, &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(retry);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn independent_end_and_clearance_preserve_undo_and_exact_model_encoding() {
        let source = claim();
        let budget = AllocationBudget::new(1024 * 1024);
        let previous = RetainedSccpGeneration::admit(&source, &budget).unwrap();
        let bytes = budget.reserved_bytes();
        let mut next = previous.clone();
        next.end = Some(SccpGenerationEndV1 {
            end_height: 2,
            end_timestamp_ms: 105,
            next_committee_root: source.committee_root,
            successor_validity_ms: 10,
        });
        next.dest_cleared_lc = Some(118);
        assert!(previous.end.is_none());
        assert!(previous.dest_cleared_lc.is_none());
        assert!(next.is_well_formed());
        let mut expected = source.clone();
        expected.end = next.end;
        expected.dest_cleared_lc = next.dest_cleared_lc;
        assert_eq!(previous.encode(), source.encode());
        assert_eq!(next.encode(), expected.encode());
        let decoded = SccpCommitteeGenerationV1::decode_all(&mut next.encode().as_slice()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(
            norito::json::to_json(&next).unwrap(),
            norito::json::to_json(&expected).unwrap()
        );
        assert_eq!(budget.reserved_bytes(), bytes);
        assert!(next.is_liable(2, 123));
        assert!(!next.is_liable(2, 124));
        assert!(previous.is_liable(2, 125));
        let restored = RetainedSccpGeneration::admit(&decoded, &budget).unwrap();
        assert_eq!(restored, next);
        assert!(!ChargedShared::ptr_eq(&restored.body, &next.body));
        drop((previous, next, restored));
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn malformed_claims_and_layout_overflow_do_not_acquire_credits() {
        let budget = AllocationBudget::new(1024 * 1024);
        let mut source = claim();
        source.members.pop();
        assert!(RetainedSccpGeneration::admit(&source, &budget).is_err());
        let mut source = claim();
        source.committee_root[0] ^= 1;
        assert!(RetainedSccpGeneration::admit(&source, &budget).is_err());
        let mut source = claim();
        source.dest_cleared_lc = Some(99);
        assert!(RetainedSccpGeneration::admit(&source, &budget).is_err());
        assert!(
            Demand::default()
                .array::<SccpGenerationMemberV1>(usize::MAX)
                .is_err()
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn unwind_drops_final_retained_reader_before_refunding_its_graph() {
        let budget = AllocationBudget::new(1024 * 1024);
        let retained = RetainedSccpGeneration::admit(&claim(), &budget).unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _reader = retained;
                panic!("drop the original completed owner during unwind");
            }))
            .is_err()
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn aggregate_generation_reservation_moves_exact_credit_and_rejects_foreign_or_short_source() {
        let source = claim();
        let budget = AllocationBudget::new(1024 * 1024);
        let bytes = RetainedSccpGeneration::admission_demand(&source).unwrap();
        let mut original = budget.try_reserve_bytes(bytes * 2).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes * 2);
        let first = RetainedSccpGeneration::admit_prepaid(&source, &budget, &mut original).unwrap();
        assert_eq!(original.remaining_bytes(), bytes);
        assert_eq!(budget.reserved_bytes(), bytes * 2);
        let second =
            RetainedSccpGeneration::admit_prepaid(&source, &budget, &mut original).unwrap();
        assert_eq!(original.remaining_bytes(), 0);
        drop(original);
        assert_eq!(budget.reserved_bytes(), bytes * 2);
        drop(first);
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(second);
        assert_eq!(budget.reserved_bytes(), 0);
        let other = AllocationBudget::new(1024 * 1024);
        let mut foreign = other.try_reserve_bytes(bytes).unwrap();
        assert!(matches!(
            RetainedSccpGeneration::admit_prepaid(&source, &budget, &mut foreign),
            Err(GenerationRecordError::Invalid(
                "foreign original reservation"
            ))
        ));
        assert_eq!(foreign.remaining_bytes(), bytes);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut short = budget.try_reserve_bytes(bytes - 1).unwrap();
        assert!(matches!(
            RetainedSccpGeneration::admit_prepaid(&source, &budget, &mut short),
            Err(GenerationRecordError::Invalid(
                "incomplete original reservation"
            ))
        ));
        assert_eq!(short.remaining_bytes(), bytes - 1);
    }
    fn partial_unwind(stage: ConstructionCheckpoint) {
        use iroha_data_model::account::{MultisigMember, MultisigPolicy};
        let mut source = claim();
        source.members[0].as_mut().unwrap().validator = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                [101_u8, 102]
                    .into_iter()
                    .map(|seed| {
                        MultisigMember::new(
                            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                                .unwrap()
                                .public_key()
                                .clone(),
                            1,
                        )
                        .unwrap()
                    })
                    .collect(),
            )
            .unwrap(),
        );
        let expected = source.encode();
        let budget = AllocationBudget::new(1024 * 1024);
        let original = RetainedSccpGeneration::admit(&source, &budget).unwrap();
        let bytes = budget.reserved_bytes();
        CONSTRUCTION_UNWIND.with(|requested| requested.set(Some(stage)));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _candidate = RetainedSccpGeneration::admit(&source, &budget).unwrap();
        }));
        assert!(
            unwind.is_err(),
            "the actual construction checkpoint must unwind"
        );
        assert!(
            CONSTRUCTION_UNWIND.with(|requested| requested.get().is_none()),
            "the intended nested allocation/publication stage was reached"
        );
        assert_eq!(
            budget.reserved_bytes(),
            bytes,
            "every partial payload retired before its exact credit refund"
        );
        assert_eq!(original.encode(), expected);
        assert_eq!(source.encode(), expected);
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn partial_generation_nested_account_unwind_refunds_only_retired_graph() {
        partial_unwind(ConstructionCheckpoint::NestedAccount);
    }

    #[test]
    fn complete_generation_unwind_before_shared_shell_preserves_original_reader() {
        partial_unwind(ConstructionCheckpoint::BeforeSharedShell);
    }
}
