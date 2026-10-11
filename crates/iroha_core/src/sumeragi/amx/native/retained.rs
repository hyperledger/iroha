//! Immutable native AMX graph custody, including exact original-pool allocation charges.
//!
//! Current/undo/reader clones share the same original graph. Mutation constructs a separately
//! prepaid candidate before touching monetary state; no public mutation or allocation escape
//! is available after publication.

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, ChargedShared, PrepaidBufferError, RetainedPayload,
};
use iroha_crypto::PublicKey;
use iroha_data_model::{
    account::AccountId,
    sumeragi::epoch::{ValidatorCommitteeMemberV1, ValidatorEpochContextV1},
    sumeragi_amx::{
        AmxForeignInstanceV1, AmxHeldDecisionV1, AmxParticipantStateV1, AmxPreparedEntryV1,
        AmxTransferEscrowV1, AmxTransferLegV1, NativeAmxParticipantStateV1,
    },
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::numeric::Quantity;
use norito::{
    core::{Encoder, SerializePayload},
    json::{self, JsonSerialize},
};
use std::{alloc::Layout, fmt};

/// A typed local refusal, separate from deterministic AMX proof or monetary policy rejection.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GraphError {
    /// The original finite State pool refused the complete candidate.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The inherited codec scope refused canonical validation before a candidate existed.
    #[error("native AMX codec validation refused: {0}")]
    Codec(norito::core::DecodeResourceError),
    /// The allocator refused an exact already admitted allocation.
    #[error("native AMX allocator refused {bytes} prepaid bytes")]
    Allocator {
        /// Exact requested bytes, already admitted by the original finite pool.
        bytes: usize,
    },
    /// A source/planner invariant changed; the original committed owner is retained.
    #[error("native AMX graph invariant: {0}")]
    Invalid(String),
}
impl From<iroha_data_model::sumeragi_amx::AmxError> for GraphError {
    fn from(error: iroha_data_model::sumeragi_amx::AmxError) -> Self {
        match error {
            iroha_data_model::sumeragi_amx::AmxError::Resource(resource) => Self::Codec(resource),
            invalid => Self::Invalid(invalid.to_string()),
        }
    }
}
fn codec_clone_error(error: norito::core::Error) -> GraphError {
    match error {
        norito::core::Error::AllocationFailed { bytes } => GraphError::Allocator {
            bytes: usize::try_from(bytes).unwrap_or(usize::MAX),
        },
        invalid => invalid.decode_resource_error().map_or_else(
            || GraphError::Invalid(invalid.to_string()),
            GraphError::Codec,
        ),
    }
}
fn quantity_clone_error(error: iroha_primitives::bigint::BigIntAdmissionCloneError) -> GraphError {
    match error {
        iroha_primitives::bigint::BigIntAdmissionCloneError::Allocator { requested_bytes } => {
            GraphError::Allocator {
                bytes: requested_bytes,
            }
        }
        iroha_primitives::bigint::BigIntAdmissionCloneError::LayoutOverflow => {
            AllocationRefusal::DemandOverflow.into()
        }
        invalid => GraphError::Invalid(invalid.to_string()),
    }
}
impl From<ChargedBufferError> for GraphError {
    fn from(error: ChargedBufferError) -> Self {
        match error {
            ChargedBufferError::Admission(error) => Self::Admission(error),
            ChargedBufferError::Allocator { requested_bytes } => Self::Allocator {
                bytes: requested_bytes,
            },
        }
    }
}
impl From<PrepaidBufferError> for GraphError {
    fn from(error: PrepaidBufferError) -> Self {
        match error {
            PrepaidBufferError::Allocation(error) => error.into(),
            PrepaidBufferError::Reservation(error) => Self::Invalid(error.to_string()),
        }
    }
}

/// Move-only genuine global context retaining every copied roster/key/PoP allocation.
/// This admission grants no authority; the caller still verifies the original H2.
pub(super) struct RetainedGlobalSource {
    #[cfg(not(all(test, sumeragi_core_mutation = "HC219")))]
    value: RetainedPayload<AmxForeignInstanceV1>,
    #[cfg(all(test, sumeragi_core_mutation = "HC219"))]
    value: AmxForeignInstanceV1,
}
impl RetainedGlobalSource {
    #[allow(
        unsafe_code,
        reason = "the exact context copier moves each physical allocation with its original ledger into an immutable returned owner"
    )]
    pub(super) fn admit(
        instance: [u8; 32],
        context: &ValidatorEpochContextV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GraphError> {
        #[cfg(all(test, sumeragi_core_mutation = "HC219"))]
        {
            let _ = budget;
            return Ok(Self {
                value: AmxForeignInstanceV1 {
                    instance,
                    current: context.clone(),
                    previous: None,
                },
            });
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC219")))]
        {
            let mut demand = Demand::default();
            demand.context(context)?;
            let mut construction = Construction::new_with_control(demand, budget, 0)?;
            let current = construction.context(context, budget)?;
            let value = AmxForeignInstanceV1 {
                instance,
                current,
                previous: None,
            };
            let charges = construction
                .charges
                .take()
                .expect("returned context ledger");
            if construction.reservation.remaining_bytes() != 0
                || charges.as_slice().len() != charges.capacity()
            {
                drop(value);
                drop(charges);
                return Err(GraphError::Invalid(
                    "returned context exact demand changed".into(),
                ));
            }
            // SAFETY: the shared copier prepaid the exact committee Vec, compact key
            // boxes and PoP Vecs, all unchanged/private. RetainedPayload drops every
            // actual allocation before its same-pool ledger, including unwind/refusal.
            let value = unsafe { RetainedPayload::try_new(value, charges, budget) }.map_err(
                |(value, charges, error)| {
                    drop(value);
                    drop(charges);
                    GraphError::Invalid(error.to_string())
                },
            )?;
            Ok(Self { value })
        }
    }
    pub(super) fn canonical(&self) -> &AmxForeignInstanceV1 {
        #[cfg(all(test, sumeragi_core_mutation = "HC219"))]
        {
            &self.value
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC219")))]
        {
            self.value.get()
        }
    }
    #[cfg(test)]
    pub(super) fn allocation_bytes(&self) -> Option<usize> {
        #[cfg(all(test, sumeragi_core_mutation = "HC219"))]
        {
            Some(0)
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC219")))]
        {
            self.value.allocation_bytes()
        }
    }
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        #[cfg(all(test, sumeragi_core_mutation = "HC219"))]
        {
            let _ = budget;
            false
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC219")))]
        {
            self.value.belongs_to(budget)
        }
    }
}

/// Original initial registration inputs lent until complete World admission.
pub(super) struct RegistrationSource<'a> {
    pub(super) dataspace: iroha_model_base::topology::DataSpaceId,
    pub(super) global: &'a RetainedGlobalSource,
    pub(super) global_genesis: &'a [u8],
    pub(super) global_successor: &'a [u8],
    pub(super) global_chain_label: &'a [u8],
    pub(super) custody: &'a AccountId,
}

impl fmt::Debug for RetainedGlobalSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.canonical().fmt(formatter)
    }
}

/// Canonical World participant value whose shared graph is admitted only by this module.
#[derive(Clone, Default)]
pub struct RetainedNativeAmx {
    owner: Option<ChargedShared<RetainedPayload<NativeAmxParticipantStateV1>>>,
    // Execution authority is original runtime provenance, never a serialized snapshot claim.
    authenticated: bool,
}
impl RetainedNativeAmx {
    /// Construct the initially empty graph directly from the still-retained global context.
    /// No ordinary epoch clone or uncharged canonical temporary is created.
    pub(super) fn admit_registration(
        source: RegistrationSource<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, GraphError> {
        if !source.global.belongs_to(budget) {
            return Err(GraphError::Invalid(
                "returned global context belongs to another original pool".into(),
            ));
        }
        let global = source.global.canonical();
        NativeAmxParticipantStateV1::validate_initial_sources(
            global,
            source.global_genesis,
            source.global_successor,
            source.global_chain_label,
        )
        .map_err(GraphError::from)?;
        let mut demand = Demand::default();
        demand.array::<u8>(source.global_genesis.len())?;
        demand.array::<u8>(source.global_successor.len())?;
        demand.array::<u8>(source.global_chain_label.len())?;
        demand.account(source.custody)?;
        demand.context(&global.current)?;
        if let Some(previous) = &global.previous {
            demand.context(previous)?;
        }
        demand.array::<AmxPreparedEntryV1>(0)?;
        demand.array::<AmxHeldDecisionV1>(0)?;
        demand.array::<AmxTransferEscrowV1>(0)?;
        let mut construction = Construction::new(demand, budget)?;
        let global_genesis = construction.bytes(source.global_genesis)?;
        let global_successor = construction.bytes(source.global_successor)?;
        let global_chain_label = construction.bytes(source.global_chain_label)?;
        let custody = construction.account(source.custody)?;
        let current = construction.context(&global.current, budget)?;
        let previous = global
            .previous
            .as_ref()
            .map(|previous| construction.context(previous, budget))
            .transpose()?;
        let global = AmxForeignInstanceV1 {
            instance: global.instance,
            current,
            previous,
        };
        let prepared = construction.buffer::<AmxPreparedEntryV1>(0)?;
        let prepared = construction.vector(prepared)?;
        let held = construction.buffer::<AmxHeldDecisionV1>(0)?;
        let held = construction.vector(held)?;
        let escrows = construction.buffer::<AmxTransferEscrowV1>(0)?;
        let value = NativeAmxParticipantStateV1 {
            global_genesis,
            global_successor,
            global_chain_label,
            participant: AmxParticipantStateV1 {
                dataspace: source.dataspace,
                global,
                global_height: 0,
                prepared,
                held,
            },
            custody,
            escrows: construction.vector(escrows)?,
        };
        Candidate {
            value: Some(value),
            construction,
            budget: budget.clone(),
        }
        .finish()
    }
    #[cfg(test)]
    pub(super) fn allocation_bytes(&self) -> Option<usize> {
        let owner = self.owner.as_ref()?;
        owner.allocation_bytes()?.checked_add(
            ChargedShared::<RetainedPayload<NativeAmxParticipantStateV1>>::allocation_layout()
                .size(),
        )
    }
    /// Borrow immutable canonical authority without copying its nested allocations.
    pub(crate) fn canonical(&self) -> Option<&NativeAmxParticipantStateV1> {
        self.owner.as_ref().map(|owner| owner.get())
    }
    /// Check the exact original finite pool, rather than its configured byte limit.
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.owner
            .as_ref()
            .is_none_or(|owner| owner.belongs_to(budget))
    }
    /// Borrow this already-authenticated original parent source for local outbound capture.
    /// Decoded snapshots and equivalent foreign pools cannot supply this runtime capability.
    /// The returned claim still needs original carrier certification before relaying.
    pub(crate) fn authenticated_parent_source(
        &self,
        budget: &AllocationBudget,
    ) -> Option<&NativeAmxParticipantStateV1> {
        (self.authenticated && self.belongs_to(budget))
            .then(|| self.canonical())
            .flatten()
    }
    pub(super) const fn is_authenticated(&self) -> bool {
        self.authenticated
    }
    /// Issued only after genuine signed-genesis/H2 authentication or an original transition.
    pub(super) fn authenticate(mut self) -> Self {
        self.authenticated = true;
        self
    }
    /// Admit an immutable restored claim; this alone grants no history authentication.
    pub(crate) fn admit(
        source: &NativeAmxParticipantStateV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GraphError> {
        Candidate::copy(source, budget, 0, 0, None, None)?.finish()
    }
}
impl fmt::Debug for RetainedNativeAmx {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.canonical().fmt(out)
    }
}
impl PartialEq for RetainedNativeAmx {
    fn eq(&self, other: &Self) -> bool {
        self.canonical() == other.canonical()
    }
}
impl Eq for RetainedNativeAmx {}
impl norito::NoritoSchema for RetainedNativeAmx {
    fn nominal_name() -> String {
        <Option<NativeAmxParticipantStateV1> as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <Option<NativeAmxParticipantStateV1> as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedNativeAmx {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.canonical().map(NativeRef).serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.canonical().map(NativeRef).encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.canonical().map(NativeRef).encoded_len_exact()
    }
}
// A transparent borrowed payload preserves Option<T>'s exact canonical codec without cloning
// the funded graph or applying a derived tuple/newtype field wrapper.
struct NativeRef<'a>(&'a NativeAmxParticipantStateV1);
impl SerializePayload for NativeRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
impl JsonSerialize for RetainedNativeAmx {
    fn json_serialize(&self, out: &mut String) {
        out.push_str("{\"value\":");
        self.canonical().json_serialize(out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"value\":")?;
            self.canonical().json_serialize_to(out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

#[derive(Default)]
struct Demand {
    bytes: usize,
    charges: usize,
}
impl Demand {
    fn add(&mut self, layout: Layout) -> Result<(), GraphError> {
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
    fn array<T>(&mut self, count: usize) -> Result<(), GraphError> {
        self.add(Layout::array::<T>(count).map_err(|_| AllocationRefusal::DemandOverflow)?)
    }
    fn key(&mut self, key: &PublicKey) -> Result<(), GraphError> {
        self.add(key.retained_allocation_layout())
    }
    fn account(&mut self, account: &AccountId) -> Result<(), GraphError> {
        let mut result = Ok(());
        account
            .for_each_admission_clone_layout(|layout| {
                if result.is_ok() {
                    result = self.add(layout);
                }
            })
            .map_err(|error| GraphError::Invalid(error.to_string()))?;
        result
    }
    fn quantity(&mut self, quantity: &Quantity) -> Result<(), GraphError> {
        self.add(
            quantity
                .admission_clone_layout()
                .map_err(|error| GraphError::Invalid(error.to_string()))?,
        )
    }
    fn context(&mut self, source: &ValidatorEpochContextV1) -> Result<(), GraphError> {
        // Generation identity derives from this sole BLS roster and the fixed authorization.
        // Exhaustive fields make new owned epoch/credential storage require accounting review.
        let ValidatorEpochContextV1 {
            da_layout: _,
            version: _,
            network_id: _,
            mode: _,
            authorization: _,
            committee,
            leader_seed: _,
        } = source;
        self.array::<ValidatorCommitteeMemberV1>(committee.len())?;
        for ValidatorCommitteeMemberV1 {
            validator,
            proof_of_possession,
        } in committee
        {
            self.key(validator.public_key())?;
            self.array::<u8>(proof_of_possession.len())?;
        }
        Ok(())
    }
    fn escrow(&mut self, source: &AmxTransferEscrowV1) -> Result<(), GraphError> {
        self.escrow_input(EscrowInput {
            tx: source.tx,
            effects_hash: source.effects_hash,
            leg: &source.leg,
            custody: &source.custody,
            settled: source.settled,
        })
    }
    fn escrow_input(&mut self, source: EscrowInput<'_>) -> Result<(), GraphError> {
        self.account(source.leg.source.account())?;
        self.account(&source.leg.destination)?;
        self.quantity(&source.leg.amount)?;
        self.account(source.custody)
    }
}

struct Construction {
    reservation: AllocationReservation,
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Construction {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(charges) = self.charges.take()
        {
            // Payload destruction may have unwound: uncertain reclamation is never retry credit.
            std::mem::forget(charges);
        }
    }
}
impl Construction {
    fn new(demand: Demand, budget: &AllocationBudget) -> Result<Self, GraphError> {
        Self::new_with_control(
            demand,
            budget,
            ChargedShared::<RetainedPayload<NativeAmxParticipantStateV1>>::allocation_layout()
                .size(),
        )
    }
    fn new_with_control(
        mut demand: Demand,
        budget: &AllocationBudget,
        control_bytes: usize,
    ) -> Result<Self, GraphError> {
        let ledger = Layout::array::<AllocationCharge>(demand.charges)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        demand.bytes = demand
            .bytes
            .checked_add(ledger.size())
            .and_then(|bytes| bytes.checked_add(control_bytes))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_bytes(demand.bytes)?;
        let charges = ChargedBuffer::from_reservation(demand.charges, &mut reservation)?;
        Ok(Self {
            reservation,
            charges: Some(charges),
        })
    }
    fn retain(&mut self, charge: AllocationCharge) -> Result<(), GraphError> {
        if let Err(charge) = self
            .charges
            .as_mut()
            .expect("original AMX ledger")
            .try_push(charge)
        {
            std::mem::forget(charge);
            return Err(GraphError::Invalid(
                "original AMX ledger capacity changed".into(),
            ));
        }
        Ok(())
    }
    fn buffer<T>(&mut self, count: usize) -> Result<ChargedBuffer<T>, GraphError> {
        ChargedBuffer::from_reservation(count, &mut self.reservation).map_err(Into::into)
    }
    #[allow(
        unsafe_code,
        reason = "audited exact buffers retain original ledger until immutable payload destruction"
    )]
    fn vector<T>(&mut self, buffer: ChargedBuffer<T>) -> Result<Vec<T>, GraphError> {
        // SAFETY: callers preserve the exact Vec allocation/capacity in private candidate fields.
        // Only fixed-capacity insertion, retain and fixed-size edits precede immutable publication.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        self.retain(charge)?;
        Ok(values)
    }
    fn account(&mut self, source: &AccountId) -> Result<AccountId, GraphError> {
        let mut result = Ok(());
        source
            .for_each_admission_clone_layout(|layout| {
                if result.is_ok() {
                    result = self
                        .reservation
                        .try_split(layout)
                        .map_err(|error| GraphError::Invalid(error.to_string()))
                        .and_then(|charge| self.retain(charge));
                }
            })
            .map_err(|error| GraphError::Invalid(error.to_string()))?;
        result?;
        source.try_clone_for_admission().map_err(codec_clone_error)
    }
    fn quantity(&mut self, source: &Quantity) -> Result<Quantity, GraphError> {
        let layout = source
            .admission_clone_layout()
            .map_err(|error| GraphError::Invalid(error.to_string()))?;
        let charge = self
            .reservation
            .try_split(layout)
            .map_err(|error| GraphError::Invalid(error.to_string()))?;
        self.retain(charge)?;
        source
            .try_clone_for_admission()
            .map_err(quantity_clone_error)
    }
    #[allow(
        unsafe_code,
        reason = "compact credential moves unchanged into the private canonical graph"
    )]
    fn key(
        &mut self,
        source: &PublicKey,
        budget: &AllocationBudget,
    ) -> Result<PublicKey, GraphError> {
        let charge = self
            .reservation
            .try_split(source.retained_allocation_layout())
            .map_err(|error| GraphError::Invalid(error.to_string()))?;
        let key = source
            .try_clone_from_charge(budget, charge)
            .map_err(|(charge, error)| {
                drop(charge);
                match error {
                    iroha_crypto::PublicKeyAllocationError::Allocation(
                        iroha_allocation::ChargedBufferFromChargeError::Allocator { layout },
                    ) => GraphError::Allocator {
                        bytes: layout.size(),
                    },
                    invalid => GraphError::Invalid(invalid.to_string()),
                }
            })?;
        // SAFETY: the exact key is immutable and its original charge enters this graph ledger.
        let (key, charge) = unsafe { key.into_allocation_parts() };
        self.retain(charge)?;
        Ok(key)
    }
    fn context(
        &mut self,
        source: &ValidatorEpochContextV1,
        budget: &AllocationBudget,
    ) -> Result<ValidatorEpochContextV1, GraphError> {
        let ValidatorEpochContextV1 {
            da_layout,
            version,
            network_id,
            mode,
            authorization,
            committee: source_committee,
            leader_seed,
        } = source;
        let mut committee = self.buffer(source_committee.len())?;
        for ValidatorCommitteeMemberV1 {
            validator,
            proof_of_possession,
        } in source_committee
        {
            let validator = PeerId::new(self.key(validator.public_key(), budget)?);
            let mut proof = self.buffer(proof_of_possession.len())?;
            proof
                .append(proof_of_possession)
                .map_err(|error| GraphError::Invalid(error.to_string()))?;
            committee.push_reserved(ValidatorCommitteeMemberV1 {
                validator,
                proof_of_possession: self.vector(proof)?,
            });
        }
        Ok(ValidatorEpochContextV1 {
            da_layout: *da_layout,
            version: *version,
            network_id: *network_id,
            mode: *mode,
            authorization: *authorization,
            committee: self.vector(committee)?,
            leader_seed: *leader_seed,
        })
    }
    fn escrow(&mut self, source: &AmxTransferEscrowV1) -> Result<AmxTransferEscrowV1, GraphError> {
        self.escrow_input(EscrowInput {
            tx: source.tx,
            effects_hash: source.effects_hash,
            leg: &source.leg,
            custody: &source.custody,
            settled: source.settled,
        })
    }
    fn escrow_input(&mut self, source: EscrowInput<'_>) -> Result<AmxTransferEscrowV1, GraphError> {
        let account = self.account(source.leg.source.account())?;
        Ok(AmxTransferEscrowV1 {
            tx: source.tx,
            effects_hash: source.effects_hash,
            leg: AmxTransferLegV1 {
                source: iroha_data_model::asset::AssetId::with_scope(
                    source.leg.source.definition().clone(),
                    account,
                    *source.leg.source.scope(),
                ),
                destination: self.account(&source.leg.destination)?,
                amount: self.quantity(&source.leg.amount)?,
            },
            custody: self.account(source.custody)?,
            settled: source.settled,
        })
    }
    fn bytes(&mut self, source: &[u8]) -> Result<Vec<u8>, GraphError> {
        let mut buffer = self.buffer(source.len())?;
        buffer
            .append(source)
            .map_err(|error| GraphError::Invalid(error.to_string()))?;
        self.vector(buffer)
    }
}

/// A borrowed new record; all actual account/quantity copies occur only after graph admission.
#[derive(Clone, Copy)]
pub(super) struct EscrowInput<'a> {
    pub(super) tx: [u8; 32],
    pub(super) effects_hash: [u8; 32],
    pub(super) leg: &'a AmxTransferLegV1,
    pub(super) custody: &'a AccountId,
    pub(super) settled: Option<iroha_data_model::sumeragi_amx::AmxOutcomeV1>,
}

/// Private mutable candidate; payload fields destroy before original ledger refunds.
/// Its methods are available only to the native AMX owner while no World effects are published.
pub(super) struct Candidate {
    pub(super) value: Option<NativeAmxParticipantStateV1>,
    construction: Construction,
    budget: AllocationBudget,
}
impl Candidate {
    /// Prepay a complete canonical successor, with exact insertion capacity and an optional
    /// already authenticated/fixed monetary record. All copied credentials/accounts/quantities
    /// and backing/control allocations belong to this same original State pool.
    pub(super) fn copy(
        source: &NativeAmxParticipantStateV1,
        budget: &AllocationBudget,
        prepared_extra: usize,
        held_extra: usize,
        escrow: Option<EscrowInput<'_>>,
        next_context: Option<&ValidatorEpochContextV1>,
    ) -> Result<Self, GraphError> {
        source.validate().map_err(GraphError::from)?;
        let prepared_count = source
            .participant
            .prepared
            .len()
            .checked_add(prepared_extra)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let held_count = source
            .participant
            .held
            .len()
            .checked_add(held_extra)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let escrow_count = source
            .escrows
            .len()
            .checked_add(usize::from(escrow.is_some()))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut demand = Demand::default();
        demand.array::<u8>(source.global_genesis.len())?;
        demand.array::<u8>(source.global_successor.len())?;
        demand.array::<u8>(source.global_chain_label.len())?;
        let current_source = next_context.unwrap_or(&source.participant.global.current);
        let previous_source = if next_context.is_some() {
            Some(&source.participant.global.current)
        } else {
            source.participant.global.previous.as_ref()
        };
        demand.account(&source.custody)?;
        demand.context(current_source)?;
        if let Some(previous) = previous_source {
            demand.context(previous)?;
        }
        demand.array::<AmxPreparedEntryV1>(prepared_count)?;
        demand.array::<AmxHeldDecisionV1>(held_count)?;
        demand.array::<AmxTransferEscrowV1>(escrow_count)?;
        for record in &source.escrows {
            demand.escrow(record)?;
        }
        if let Some(record) = escrow {
            demand.escrow_input(record)?;
        }
        let mut construction = Construction::new(demand, budget)?;
        let global_genesis = construction.bytes(&source.global_genesis)?;
        let global_successor = construction.bytes(&source.global_successor)?;
        let global_chain_label = construction.bytes(&source.global_chain_label)?;
        let custody = construction.account(&source.custody)?;
        let current = construction.context(current_source, budget)?;
        let previous = previous_source
            .map(|previous| construction.context(previous, budget))
            .transpose()?;
        let mut prepared = construction.buffer(prepared_count)?;
        for entry in &source.participant.prepared {
            prepared.push_reserved(*entry);
        }
        let prepared = construction.vector(prepared)?;
        let mut held = construction.buffer(held_count)?;
        for entry in &source.participant.held {
            held.push_reserved(*entry);
        }
        let held = construction.vector(held)?;
        let participant = AmxParticipantStateV1 {
            dataspace: source.participant.dataspace,
            global: AmxForeignInstanceV1 {
                instance: source.participant.global.instance,
                current,
                previous,
            },
            global_height: source.participant.global_height,
            prepared,
            held,
        };
        let mut escrows = construction.buffer(escrow_count)?;
        for record in &source.escrows {
            escrows.push_reserved(construction.escrow(record)?);
        }
        if let Some(record) = escrow {
            escrows.push_reserved(construction.escrow_input(record)?);
        }
        // The optional record is inert until its native escrow operation returns Yes.
        // Keep it last during construction; the handler places it into canonical tx order.
        let value = NativeAmxParticipantStateV1 {
            global_genesis,
            global_successor,
            global_chain_label,
            participant,
            custody,
            escrows: construction.vector(escrows)?,
        };
        Ok(Self {
            value: Some(value),
            construction,
            budget: budget.clone(),
        })
    }
    #[allow(
        unsafe_code,
        reason = "private exact-capacity native candidate transfers all original graph allocations into immutable custody"
    )]
    pub(super) fn finish(mut self) -> Result<RetainedNativeAmx, GraphError> {
        self.value
            .as_ref()
            .expect("original AMX candidate")
            .validate()
            .map_err(GraphError::from)?;
        let value = self.value.take().expect("original AMX candidate");
        let charges = self
            .construction
            .charges
            .take()
            .expect("original AMX ledger");
        // SAFETY: only fixed-capacity insert/retain/order and fixed-size fields changed; every
        // canonical backing/key/account/quantity remains private with its exact original charge.
        let owner = unsafe { RetainedPayload::try_new(value, charges, &self.budget) }.map_err(
            |(value, charges, error)| {
                drop(value);
                drop(charges);
                GraphError::Invalid(error.to_string())
            },
        )?;
        let owner = ChargedShared::from_reservation(owner, &mut self.construction.reservation)
            .map_err(|(owner, error)| {
                drop(owner);
                match error {
                    iroha_allocation::PrepaidSharedError::Allocator { requested_bytes } => {
                        GraphError::Allocator {
                            bytes: requested_bytes,
                        }
                    }
                    invalid => GraphError::Invalid(invalid.to_string()),
                }
            })?;
        if self.construction.reservation.remaining_bytes() != 0 {
            return Err(GraphError::Invalid(
                "native AMX exact demand was not consumed".into(),
            ));
        }
        Ok(RetainedNativeAmx {
            owner: Some(owner),
            authenticated: false,
        })
    }
}
