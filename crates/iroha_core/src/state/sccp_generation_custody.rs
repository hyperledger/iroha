//! Original-pool custody for immutable SCCP generation records.
//!
//! MV copies clone only a charged shared handle. The canonical record, its Norito
//! schema and its JSON projection do not acquire a wrapper or an alternate wire.

use crate::smartcontracts::isi::sccp::generation::{
    SccpCommitteeGenerationV1, SccpGenerationEndV1, SccpGenerationMemberV1,
};
use concread::bptree::{
    AllocationDemand, ClonePlanning, NodeCloning, NodeFunding, PlanningError, Prepaid,
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedShared, PrepaidBufferError, PrepaidSharedError, RetainedPayload,
};
use iroha_data_model::account::AccountId;
use iroha_model_base::topology::LaneId;
use mv::storage::AdmittedStorageError;
use norito::core::{Encoder, SerializePayload};
use std::{alloc::Layout, fmt, mem::ManuallyDrop, ops::Deref};

/// A local allocation or codec refusal, never an inactive finality header.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GenerationAdmissionError {
    /// Original map/payload pool refusal.
    #[error(transparent)]
    Storage(#[from] AdmittedStorageError),
    /// The inherited decoder or physical allocator refused a nested account.
    #[error("SCCP generation decode resources: {0}")]
    Codec(norito::core::DecodeResourceError),
    /// The source record or exact allocation plan was inconsistent.
    #[error("invalid SCCP generation source")]
    Invalid,
}

fn overflow() -> GenerationAdmissionError {
    AdmittedStorageError::Allocation(AllocationRefusal::DemandOverflow).into()
}
fn codec(error: norito::core::Error) -> GenerationAdmissionError {
    error.decode_resource_error().map_or(
        GenerationAdmissionError::Invalid,
        GenerationAdmissionError::Codec,
    )
}
fn prepaid(error: PrepaidBufferError) -> GenerationAdmissionError {
    match error {
        PrepaidBufferError::Reservation(_) => GenerationAdmissionError::Invalid,
        PrepaidBufferError::Allocation(iroha_allocation::ChargedBufferError::Admission(e)) => {
            AdmittedStorageError::Allocation(e).into()
        }
        PrepaidBufferError::Allocation(iroha_allocation::ChargedBufferError::Allocator {
            requested_bytes,
        }) => {
            GenerationAdmissionError::Codec(norito::core::DecodeResourceError::AllocationFailed {
                bytes: u64::try_from(requested_bytes).unwrap_or(u64::MAX),
            })
        }
    }
}
fn shared(error: PrepaidSharedError) -> GenerationAdmissionError {
    match error {
        PrepaidSharedError::Reservation(_) => GenerationAdmissionError::Invalid,
        PrepaidSharedError::Allocator { requested_bytes } => {
            GenerationAdmissionError::Codec(norito::core::DecodeResourceError::AllocationFailed {
                bytes: u64::try_from(requested_bytes).unwrap_or(u64::MAX),
            })
        }
    }
}

/// A borrowed G6 registration, resolved before any retained account is cloned.
#[derive(Clone, Copy)]
pub(crate) struct MemberRef<'a> {
    pub(crate) lane_id: LaneId,
    pub(crate) validator: &'a AccountId,
    pub(crate) activation_height: u64,
}

enum GenerationGraph {
    Constructed(RetainedPayload<SccpCommitteeGenerationV1>),
    Decoded(DecodedGeneration),
}
struct DecodedGeneration {
    record: ManuallyDrop<SccpCommitteeGenerationV1>,
    // Cumulative Norito allocation usage is a conservative retained upper bound;
    // it is not relabelled as an exact per-allocation layout ledger.
    allowance: ManuallyDrop<AllocationReservation>,
}
impl Drop for DecodedGeneration {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: immutable private fields cannot escape. A destructor unwind
        // conservatively retains the prepaid allowance.
        unsafe {
            ManuallyDrop::drop(&mut self.record);
            ManuallyDrop::drop(&mut self.allowance);
        }
    }
}
impl GenerationGraph {
    fn canonical(&self) -> &SccpCommitteeGenerationV1 {
        match self {
            Self::Constructed(p) => p.get(),
            Self::Decoded(p) => &p.record,
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        match self {
            Self::Constructed(p) => p.belongs_to(budget),
            Self::Decoded(p) => p.allowance.belongs_to(budget),
        }
    }
}
/// Immutable canonical record with original allocation custody.
/// Cloning this value allocates neither a graph nor a shared control.
pub struct RetainedGeneration(ChargedShared<GenerationGraph>);
impl Clone for RetainedGeneration {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Deref for RetainedGeneration {
    type Target = SccpCommitteeGenerationV1;
    fn deref(&self) -> &Self::Target {
        self.0.canonical()
    }
}
impl fmt::Debug for RetainedGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(f)
    }
}
impl PartialEq for RetainedGeneration {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}
impl Eq for RetainedGeneration {}

impl RetainedGeneration {
    /// Check both the actual shared control and retained graph against the original pool.
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget) && GenerationGraph::belongs_to(&self.0, budget)
    }

    /// Decode one exact snapshot record from borrowed lower-case hex under the
    /// original map pool. The surrounding snapshot JSON owner remains separate.
    /// No canonical DTO or intermediate map is created before admission.
    pub(crate) fn decode_snapshot_hex(
        source: &str,
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationAdmissionError> {
        Self::decode_snapshot_hex_checked(source, budget, true)
    }
    fn decode_snapshot_hex_checked(
        source: &str,
        budget: &AllocationBudget,
        validate: bool,
    ) -> Result<Self, GenerationAdmissionError> {
        use norito::codec::DecodeAll as _;
        if source.len() % 2 != 0 {
            return Err(GenerationAdmissionError::Invalid);
        }
        let byte_count = source.len() / 2;
        let mut bytes = ChargedBuffer::new(byte_count, budget)
            .map_err(|e| prepaid(PrepaidBufferError::Allocation(e)))?;
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        for pair in source.as_bytes().chunks_exact(2) {
            bytes.push_reserved(
                (nibble(pair[0]).ok_or(GenerationAdmissionError::Invalid)? << 4)
                    | nibble(pair[1]).ok_or(GenerationAdmissionError::Invalid)?,
            );
        }
        let control = ChargedShared::<GenerationGraph>::allocation_layout()
            .size()
            .checked_add(norito::core::DecodeBudgetContext::allocation_layout().size())
            .ok_or_else(overflow)?;
        let mut control = budget
            .try_reserve_bytes(control)
            .map_err(AdmittedStorageError::Allocation)?;
        let shell = ChargedShared::<GenerationGraph>::reserve_from(&mut control).map_err(shared)?;
        // Admit an upper allowance before decode. A concurrent limit/usage change
        // can refuse this original attempt; it cannot replenish an outer scope.
        let available = budget.limit_bytes().saturating_sub(budget.reserved_bytes());
        let allowance = budget
            .try_reserve_bytes(available)
            .map_err(AdmittedStorageError::Allocation)?;
        let limits =
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, available, usize::MAX);
        let context = norito::core::DecodeBudgetContext::from_reservation(limits, &mut control)
            .map_err(shared)?;
        // Record is declared after its allowance, so all partial decode paths
        // free owned data first. Every active outer scope still observes decode.
        let record = context
            .with(|| SccpCommitteeGenerationV1::decode_all(&mut bytes.as_slice()))
            .map_err(codec)?;
        let record = DecodedGeneration {
            record: ManuallyDrop::new(record),
            allowance: ManuallyDrop::new(allowance),
        };
        norito::codec::verify_exact_payload(&*record.record, bytes.as_slice()).map_err(codec)?;
        if validate && !record.record.is_well_formed() {
            return Err(GenerationAdmissionError::Invalid);
        }
        let used = usize::try_from(context.consumed_allocated_bytes()).map_err(|_| overflow())?;
        let mut record = record;
        let retained = record
            .allowance
            .try_partition_bytes(used)
            .map_err(|_| GenerationAdmissionError::Invalid)?;
        // Replace only unused pre-admitted allowance, after exact successful decode.
        let unused = std::mem::replace(&mut *record.allowance, retained);
        drop(unused);
        Ok(Self(shell.initialize(GenerationGraph::Decoded(record))))
    }

    /// Copy one already validated source into independent, completely prepaid custody.
    pub(crate) fn try_copy(
        source: &SccpCommitteeGenerationV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationAdmissionError> {
        if !source.is_well_formed() {
            return Err(GenerationAdmissionError::Invalid);
        }
        Self::copy_with(source, source.end, source.dest_cleared_lc, budget)
    }

    /// End this generation without mutating any current/undo/read owner.
    pub(crate) fn with_end(
        &self,
        end: SccpGenerationEndV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationAdmissionError> {
        Self::copy_with(self, Some(end), self.dest_cleared_lc, budget)
    }

    /// Retain destination progress without repricing or mutating the old graph.
    pub(crate) fn with_progress(
        &self,
        clock: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationAdmissionError> {
        Self::copy_with(self, self.end, Some(clock), budget)
    }

    fn copy_with(
        source: &SccpCommitteeGenerationV1,
        end: Option<SccpGenerationEndV1>,
        cleared: Option<u64>,
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationAdmissionError> {
        if source.members.len() > 31 {
            return Err(GenerationAdmissionError::Invalid);
        }
        let mut members = [None; 31];
        for (slot, member) in members.iter_mut().zip(&source.members) {
            *slot = member.as_ref().map(|m| MemberRef {
                lane_id: m.lane_id,
                validator: &m.validator,
                activation_height: m.activation_height,
            });
        }
        Self::try_build(
            SccpCommitteeGenerationV1 {
                generation: source.generation,
                committee_root: source.committee_root,
                keys: Vec::new(),
                members: Vec::new(),
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
            },
            &source.keys,
            &members[..source.members.len()],
            budget,
        )
    }

    /// Materialize the exact canonical fields from bounded borrowed sources.
    /// `scalars` must contain no allocated keys or members. All nested account
    /// layouts, two exact Vec backings, charge ledger and shared control are
    /// admitted together before any of those allocations is created.
    pub(crate) fn try_build(
        mut scalars: SccpCommitteeGenerationV1,
        keys: &[[u8; 48]],
        members: &[Option<MemberRef<'_>>],
        budget: &AllocationBudget,
    ) -> Result<Self, GenerationAdmissionError> {
        if scalars.keys.capacity() != 0
            || scalars.members.capacity() != 0
            || !(4..=31).contains(&keys.len())
            || members.len() != keys.len()
        {
            return Err(GenerationAdmissionError::Invalid);
        }
        let keys_layout = Layout::array::<[u8; 48]>(keys.len()).map_err(|_| overflow())?;
        let members_layout = Layout::array::<Option<SccpGenerationMemberV1>>(members.len())
            .map_err(|_| overflow())?;
        let mut count = 2usize;
        let mut bytes = keys_layout
            .size()
            .checked_add(members_layout.size())
            .ok_or_else(overflow)?;
        let mut over = false;
        for member in members.iter().flatten() {
            member
                .validator
                .for_each_admission_clone_layout(|layout| {
                    match (count.checked_add(1), bytes.checked_add(layout.size())) {
                        (Some(n), Some(b)) => {
                            count = n;
                            bytes = b;
                        }
                        _ => over = true,
                    }
                })
                .map_err(codec)?;
        }
        if over {
            return Err(overflow());
        }
        let ledger_layout = Layout::array::<AllocationCharge>(count).map_err(|_| overflow())?;
        let bytes = bytes
            .checked_add(ledger_layout.size())
            .and_then(|b| {
                b.checked_add(ChargedShared::<GenerationGraph>::allocation_layout().size())
            })
            .ok_or_else(overflow)?;
        let mut reservation = budget
            .try_reserve_bytes(bytes)
            .map_err(AdmittedStorageError::Allocation)?;
        // Declared first: every partially initialized account/Vec drops before its ledger.
        let mut ledger =
            ChargedBuffer::from_reservation(count, &mut reservation).map_err(prepaid)?;
        let shell = ChargedShared::reserve_from(&mut reservation).map_err(shared)?;
        let mut owned_keys =
            ChargedBuffer::from_reservation(keys.len(), &mut reservation).map_err(prepaid)?;
        let mut owned_members =
            ChargedBuffer::from_reservation(members.len(), &mut reservation).map_err(prepaid)?;
        for key in keys {
            owned_keys.push_reserved(*key);
        }
        for member in members {
            let owned = match member {
                None => None,
                Some(member) => {
                    let mut mismatch = false;
                    member
                        .validator
                        .for_each_admission_clone_layout(|layout| {
                            match reservation.try_split(layout) {
                                Ok(charge) => ledger.push_reserved(charge),
                                Err(_) => mismatch = true,
                            }
                        })
                        .map_err(codec)?;
                    if mismatch {
                        return Err(GenerationAdmissionError::Invalid);
                    }
                    Some(SccpGenerationMemberV1 {
                        lane_id: member.lane_id,
                        validator: member.validator.try_clone_for_admission().map_err(codec)?,
                        activation_height: member.activation_height,
                    })
                }
            };
            owned_members.push_reserved(owned);
        }
        // SAFETY: each exact backing and its unique charge move together; the
        // immutable RetainedPayload below forbids extraction or mutation.
        #[allow(unsafe_code)]
        let (keys, key_charge) = unsafe { owned_keys.into_allocation_parts() };
        #[allow(unsafe_code)]
        let (members, member_charge) = unsafe { owned_members.into_allocation_parts() };
        ledger.push_reserved(key_charge);
        ledger.push_reserved(member_charge);
        scalars.keys = keys;
        scalars.members = members;
        // SAFETY: the two exact Vec backings and every AccountId clone layout
        // are retained exactly once, and scalars has no other owned allocation.
        #[allow(unsafe_code)]
        let payload = unsafe { RetainedPayload::try_new(scalars, ledger, budget) }.map_err(
            |(record, charges, _)| {
                drop(record);
                drop(charges);
                GenerationAdmissionError::Invalid
            },
        )?;
        if !payload.get().is_well_formed() {
            return Err(GenerationAdmissionError::Invalid);
        }
        Ok(Self(
            shell.initialize(GenerationGraph::Constructed(payload)),
        ))
    }
}

impl SerializePayload for RetainedGeneration {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.deref().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.deref().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.deref().encoded_len_exact()
    }
}
impl norito::NoritoSchema for RetainedGeneration {
    fn nominal_name() -> String {
        <SccpCommitteeGenerationV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <SccpCommitteeGenerationV1 as norito::NoritoSchema>::frame_name()
    }
}
impl norito::json::JsonSerialize for RetainedGeneration {
    fn json_serialize(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(self.deref(), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(self.deref(), out)
    }
}

/// Node policy copies only inline keys and immutable original graph handles.
pub struct GenerationPolicy(AllocationReservation);
impl NodeFunding for GenerationPolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
        self.0
            .try_split(layout)
            .expect("complete original generation node plan")
    }
}
macro_rules! inline_clone {
    ($value:ty) => {
        impl NodeCloning<u64, $value> for GenerationPolicy {
            fn clone_key(&mut self, key: &u64) -> u64 {
                *key
            }
            fn clone_value(&mut self, value: &$value) -> $value {
                value.clone()
            }
        }
        impl ClonePlanning<u64, $value> for GenerationPolicy {
            fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
            fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
        }
    };
}
inline_clone!(RetainedGeneration);
inline_clone!(Option<RetainedGeneration>);
impl mv::storage::AdmittedStoragePolicy for GenerationPolicy {
    fn from_admission(admission: AllocationReservation) -> Self {
        Self(admission)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}
/// Exact generation map mode: no production Untracked fallback exists.
pub type GenerationMode = Prepaid<GenerationPolicy>;
/// Current and undo maps backed by the original configured execution pool.
pub type GenerationStorage = mv::storage::Storage<u64, RetainedGeneration, GenerationMode>;

#[cfg(test)]
#[path = "sccp_generation_custody/tests.rs"]
mod tests;

/// Fixture-only malformed record construction preserves snapshot rejection tests.
/// It uses the actual map's pool and is absent from production builds.
#[cfg(test)]
pub(crate) trait GenerationFixtureStorage {
    fn insert(&mut self, key: u64, record: SccpCommitteeGenerationV1)
    -> Option<RetainedGeneration>;
    fn remove(&mut self, key: u64) -> Option<RetainedGeneration>;
}
#[cfg(test)]
fn fixture(record: &SccpCommitteeGenerationV1, budget: &AllocationBudget) -> RetainedGeneration {
    use norito::codec::Encode as _;
    RetainedGeneration::decode_snapshot_hex_checked(&hex::encode(record.encode()), budget, false)
        .unwrap()
}
#[cfg(test)]
impl GenerationFixtureStorage for GenerationStorage {
    fn insert(
        &mut self,
        key: u64,
        record: SccpCommitteeGenerationV1,
    ) -> Option<RetainedGeneration> {
        let owner = fixture(&record, self.allocation_budget());
        self.try_with_admitted_block(|block| {
            block.try_insert_admitted(key, owner).map_err(|(_, e)| e)
        })
        .unwrap()
    }
    fn remove(&mut self, key: u64) -> Option<RetainedGeneration> {
        self.try_with_admitted_block(|block| block.try_remove_admitted(key).map_err(|(_, e)| e))
            .unwrap()
    }
}
#[cfg(test)]
impl GenerationFixtureStorage for mv::storage::Block<'_, u64, RetainedGeneration, GenerationMode> {
    fn insert(
        &mut self,
        key: u64,
        record: SccpCommitteeGenerationV1,
    ) -> Option<RetainedGeneration> {
        let owner = fixture(&record, self.allocation_budget());
        self.try_insert_admitted(key, owner)
            .map_err(|(_, e)| e)
            .unwrap()
    }
    fn remove(&mut self, key: u64) -> Option<RetainedGeneration> {
        self.try_remove_admitted(key).map_err(|(_, e)| e).unwrap()
    }
}

/// Test-only acquisition of this exact generation map's admitted writer pair.
/// The returned block retains the original pool's refund scope until both locks release.
#[cfg(test)]
pub(crate) trait GenerationFixtureBlock {
    /// Acquire the ordinary current/undo writers without acquiring other World fields.
    fn block(&self) -> mv::storage::Block<'_, u64, RetainedGeneration, GenerationMode>;
}
#[cfg(test)]
impl GenerationFixtureBlock for GenerationStorage {
    fn block(&self) -> mv::storage::Block<'_, u64, RetainedGeneration, GenerationMode> {
        let scope = self
            .allocation_budget()
            .try_owned_refund_scope()
            .expect("fixture generation original refund scope");
        let mut slot = self
            .try_block_acquisition_owned(&scope)
            .expect("fixture generation original pool");
        slot.try_initialize(mv::BlockMode::Ordinary)
            .expect("fixture generation original current/undo writers");
        slot.into_block()
    }
}

/// Test-only ordinary publication of this exact admitted generation writer pair.
#[cfg(test)]
pub(crate) trait GenerationFixtureCommit {
    /// Prepare and install the original pair before releasing its refund scope.
    fn commit(self);
}
#[cfg(test)]
impl GenerationFixtureCommit for mv::storage::Block<'_, u64, RetainedGeneration, GenerationMode> {
    fn commit(self) {
        use mv::BlockPublication as _;

        let mut publication = self.publication_slot();
        publication.prepare_publication();
        publication.publish_prepared();
    }
}

#[cfg(test)]
impl GenerationFixtureStorage
    for mv::storage::Transaction<'_, u64, RetainedGeneration, GenerationMode>
{
    fn insert(
        &mut self,
        key: u64,
        record: SccpCommitteeGenerationV1,
    ) -> Option<RetainedGeneration> {
        let owner = fixture(&record, self.allocation_budget());
        self.try_insert_admitted(key, owner)
            .map_err(|(_, e)| e)
            .unwrap()
    }
    fn remove(&mut self, key: u64) -> Option<RetainedGeneration> {
        self.try_remove_admitted(key).map_err(|(_, e)| e).unwrap()
    }
}

#[cfg(test)]
#[test]
fn fixture_transaction_keeps_original_pool_and_ordinary_apply_rollback() {
    use crate::smartcontracts::isi::sccp::test_support::sample_generation;

    let budget = AllocationBudget::new(1 << 20);
    let storage = GenerationStorage::try_new_admitted(budget.clone()).unwrap();
    let record = sample_generation(1, 1);
    let mut block = storage.block();
    {
        let mut transaction = block.try_transaction_admitted().unwrap();
        assert!(transaction.insert(1, record.clone()).is_none());
        let retained = transaction.get(&1).unwrap();
        assert!(retained.belongs_to(&budget));
        assert_eq!(&**retained, &record);
        transaction.apply();
    }
    {
        let mut transaction = block.try_transaction_admitted().unwrap();
        let removed = transaction.remove(1).unwrap();
        assert!(removed.belongs_to(&budget));
        assert_eq!(&*removed, &record);
        assert!(transaction.get(&1).is_none());
        // Abandon the child: its original parent roots must survive unchanged.
    }
    assert_eq!(block.get(&1).map(|retained| &**retained), Some(&record));
    block.commit();
    assert_eq!(
        storage.view().get(&1).map(|retained| &**retained),
        Some(&record)
    );
}
