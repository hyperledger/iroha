//! Original AMX proof custody carried by the canonical instruction storage itself.
//!
//! The storage choice introduces no wire tag or alternate instruction type. A borrow is the
//! actual registered Prepare, Relay or Settle value; cloning `InstructionBox` retains its original
//! graph and finite-pool charges. Ordinary envelope and receiving decoder allocations are separate.

use std::{alloc::Layout, fmt, mem::ManuallyDrop};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedShared, PrepaidBufferError, PrepaidSharedError, RetainedPayload,
};
use iroha_model_base::topology::DataSpaceId;

use super::{
    Instruction, InstructionBox, InstructionStorage,
    sumeragi_amx::{PrepareAmxV1, RelayAmxPreparedV1, SettleAmxV1},
};
use crate::sumeragi_amx::{
    AllocatedAmxRecordProofV1, AmxLegV1, AmxRecordProofV1, AmxRecordV1, AmxTransactionV1,
    streamed_transaction_id,
};

/// Actual local refusal before moving the original proof into its immutable instruction owner.
#[derive(Debug, thiserror::Error)]
pub enum AmxInstructionAdmissionErrorV1 {
    /// The source is from a different finite pool or is not the selected canonical record kind.
    #[error("AMX instruction source or original pool differs")]
    Source,
    /// Original finite-pool admission, including its exact release observation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Inherited cumulative canonical decoder allowance refused an actual layout.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// A prepaid destination allocation or exact private plan split refused.
    #[error(transparent)]
    Buffer(#[from] PrepaidBufferError),
    /// The real shared shell allocation refused its exact admitted layout.
    #[error(transparent)]
    Shared(#[from] PrepaidSharedError),
}
use AmxInstructionAdmissionErrorV1 as Error;

/// One selected instruction and its exact move-only proof, retained through local refusal.
///
/// The original transaction is borrowed for Prepare until completion. No extraction, source
/// replacement or Clone exists. Completion returns only the typed cause while this owner keeps
/// the canonical graph available for the next genuine admission attempt.
#[must_use = "dropping this job abandons the original pending AMX instruction"]
pub struct PendingAmxInstructionV1<'a> {
    source: Option<AllocatedAmxRecordProofV1>,
    action: Action<'a>,
}
impl fmt::Debug for PendingAmxInstructionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAmxInstructionV1")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}
impl PendingAmxInstructionV1<'_> {
    /// Borrow the original source for identity and custody observations. Completed jobs have
    /// no source; refusal never replaces this graph or changes its original pool.
    pub fn source(&self) -> Option<&AllocatedAmxRecordProofV1> {
        self.source.as_ref()
    }

    /// Complete admission into the actual registered instruction without an unfunded copy.
    ///
    /// # Errors
    /// Refuses kind, original-pool, cumulative quota, capacity or physical allocation while
    /// retaining the same source. An already completed job refuses without another allocation.
    pub fn complete(&mut self, budget: &AllocationBudget) -> Result<InstructionBox, Error> {
        into_instruction(self, budget)
    }
}

pub(super) enum AmxInstruction {
    Relay(RelayAmxPreparedV1),
    Prepare(PrepareAmxV1),
    Settle(SettleAmxV1),
}
impl AmxInstruction {
    fn registered(&self) -> &dyn Instruction {
        match self {
            Self::Relay(value) => value,
            Self::Prepare(value) => value,
            Self::Settle(value) => value,
        }
    }
}

/// Both ledgers survive until every actual instruction field is destroyed. On unwind no
/// uncertain reclamation becomes admission credit; built-in field destruction is never skipped.
pub(super) struct FundedAmxInstruction {
    graph: ManuallyDrop<RetainedPayload<AmxInstruction>>,
    additional: ManuallyDrop<ChargedBuffer<AllocationCharge>>,
}
impl Drop for FundedAmxInstruction {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: exactly one owner destroys the immutable graph first. Its original proof
        // ledger refunds only after destruction. Additional Prepare fields retain their own
        // ledger throughout that destruction; a panic conservatively retains that ledger.
        unsafe { ManuallyDrop::drop(&mut self.graph) };
        #[cfg(not(all(test, sumeragi_model_mutation = "DM3")))]
        unsafe {
            ManuallyDrop::drop(&mut self.additional)
        };
        // DM3 deliberately retains the real additional ledger after its fields were destroyed.
        // The exact original pool never receives its final credit; production always drops it.
    }
}

pub(super) struct SharedAmxInstruction(ChargedShared<FundedAmxInstruction>);
impl Clone for SharedAmxInstruction {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl SharedAmxInstruction {
    pub(super) fn registered(&self) -> &dyn Instruction {
        self.0.graph.get().registered()
    }
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget)
            && self.0.graph.belongs_to(budget)
            && self.0.additional.belongs_to(budget)
            && self
                .0
                .additional
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
    pub(super) fn allocation_bytes(&self) -> Option<usize> {
        let ledger = Layout::array::<AllocationCharge>(self.0.additional.capacity())
            .ok()?
            .size();
        self.0.additional.as_slice().iter().try_fold(
            self.0
                .graph
                .allocation_bytes()?
                .checked_add(ledger)?
                .checked_add(ChargedShared::<FundedAmxInstruction>::allocation_layout().size())?,
            |bytes, charge| bytes.checked_add(charge.layout().size()),
        )
    }
}
impl fmt::Debug for SharedAmxInstruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedAmxInstruction")
            .field("registered", &self.registered().id())
            .finish_non_exhaustive()
    }
}

impl InstructionBox {
    /// Observe funding of the retained native AMX proof and its instruction storage only.
    /// Other instructions and ordinary envelope/decoder allocations do not gain this claim.
    pub fn amx_proof_admitted_to(&self, budget: &AllocationBudget) -> bool {
        match &self.0 {
            InstructionStorage::Amx(owner) => owner.belongs_to(budget),
            _ => false,
        }
    }
    /// Actual proof, Prepare field, ledger and shared-shell layouts, counted once per owner.
    /// This is not encoded size, a fee amount, or funding for the enclosing transaction.
    pub fn amx_proof_allocation_bytes(&self) -> Option<usize> {
        match &self.0 {
            InstructionStorage::Amx(owner) => owner.allocation_bytes(),
            _ => None,
        }
    }
}

impl AllocatedAmxRecordProofV1 {
    /// Select Relay while retaining one original Prepared record in a resumable owner.
    pub fn into_relay(self) -> PendingAmxInstructionV1<'static> {
        PendingAmxInstructionV1 {
            source: Some(self),
            action: Action::Relay,
        }
    }
    /// Select customer-authorized Prepare and borrow its original transaction until admission.
    /// Every new leg array is physically prepaid before copying; this grants no debit authority.
    pub fn into_prepare(
        self,
        dataspace: DataSpaceId,
        transaction: &AmxTransactionV1,
    ) -> PendingAmxInstructionV1<'_> {
        PendingAmxInstructionV1 {
            source: Some(self),
            action: Action::Prepare(dataspace, transaction),
        }
    }
    /// Select Settle while retaining one original Decision record in a resumable owner.
    pub fn into_settle(self, dataspace: DataSpaceId) -> PendingAmxInstructionV1<'static> {
        PendingAmxInstructionV1 {
            source: Some(self),
            action: Action::Settle(dataspace),
        }
    }
}

enum Action<'a> {
    Relay,
    Prepare(DataSpaceId, &'a AmxTransactionV1),
    Settle(DataSpaceId),
}
impl Action<'_> {
    fn demand(&self, proof: &AmxRecordProofV1) -> Result<(usize, usize), Error> {
        let mut bytes = ChargedShared::<FundedAmxInstruction>::allocation_layout().size();
        let mut count = 0usize;
        match (self, &proof.record) {
            (Self::Relay, AmxRecordV1::Prepared(_))
            | (Self::Settle(_), AmxRecordV1::Decision(_)) => {}
            (Self::Prepare(_, transaction), AmxRecordV1::Begin(begin)) => {
                transaction.validate().map_err(|_| Error::Source)?;
                if streamed_transaction_id(transaction)? != begin.tx
                    || transaction.deadline != begin.deadline
                    || transaction
                        .legs
                        .iter()
                        .map(|leg| leg.dataspace)
                        .ne(begin.participants.iter().copied())
                {
                    return Err(Error::Source);
                }
                count = transaction
                    .legs
                    .len()
                    .checked_add(1)
                    .ok_or(AllocationRefusal::DemandOverflow)?;
                bytes = bytes
                    .checked_add(
                        Layout::array::<AmxLegV1>(transaction.legs.len())
                            .map_err(|_| AllocationRefusal::DemandOverflow)?
                            .size(),
                    )
                    .ok_or(AllocationRefusal::DemandOverflow)?;
                for leg in &transaction.legs {
                    bytes = bytes
                        .checked_add(
                            Layout::array::<u8>(leg.payload.len())
                                .map_err(|_| AllocationRefusal::DemandOverflow)?
                                .size(),
                        )
                        .ok_or(AllocationRefusal::DemandOverflow)?;
                }
            }
            _ => return Err(Error::Source),
        }
        let ledger = Layout::array::<AllocationCharge>(count)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        bytes = bytes
            .checked_add(ledger.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok((bytes, count))
    }
}

enum PreparedAction {
    Relay,
    Prepare(DataSpaceId, AmxTransactionV1),
    Settle(DataSpaceId),
}

fn into_instruction(
    job: &mut PendingAmxInstructionV1<'_>,
    budget: &AllocationBudget,
) -> Result<InstructionBox, Error> {
    // Every fallible operation precedes the one source move. A mutable borrowed owner makes
    // refusal bounded: the typed error contains no inline proof graph or unfunded error Box.
    let proof = job.source.as_ref().ok_or(Error::Source)?;
    if !proof.belongs_to(budget) {
        return Err(Error::Source);
    }
    let (bytes, count) = job.action.demand(proof.canonical())?;
    norito::core::reserve_decode_allocation(bytes)?;
    let mut reservation = budget.try_reserve_bytes(bytes)?;
    let mut construction = Construction::new(count, &mut reservation)?;
    let shell = ChargedShared::<FundedAmxInstruction>::reserve_from(&mut reservation)?;
    let action = match &job.action {
        Action::Relay => PreparedAction::Relay,
        Action::Settle(dataspace) => PreparedAction::Settle(*dataspace),
        Action::Prepare(dataspace, transaction) => PreparedAction::Prepare(
            *dataspace,
            construction.transaction(transaction, &mut reservation)?,
        ),
    };
    if reservation.remaining_bytes() != 0 || construction.charges().as_slice().len() != count {
        // The detached Prepare fields precede their ledger's normal destruction.
        drop(action);
        return Err(Error::Source);
    }
    let proof = if let Some(proof) = job.source.take() {
        proof
    } else {
        drop(action);
        return Err(Error::Source);
    };
    // The private mapper only changes the outer type. Retain additional credit conservatively
    // if this infallible move unwinds: captured destination fields must die before their ledger.
    let additional = ManuallyDrop::new(construction.finish());
    #[allow(unsafe_code)]
    let graph = unsafe {
        proof.into_retained().map_payload(|proof| match action {
            PreparedAction::Relay => AmxInstruction::Relay(RelayAmxPreparedV1 { proof }),
            PreparedAction::Settle(dataspace) => AmxInstruction::Settle(SettleAmxV1 {
                dataspace,
                decision: proof,
            }),
            PreparedAction::Prepare(dataspace, transaction) => {
                AmxInstruction::Prepare(PrepareAmxV1 {
                    dataspace,
                    transaction,
                    begin: proof,
                })
            }
        })
    };
    let owner = shell.initialize(FundedAmxInstruction {
        graph: ManuallyDrop::new(graph),
        additional,
    });
    Ok(InstructionBox(InstructionStorage::Amx(
        SharedAmxInstruction(owner),
    )))
}

struct Construction {
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Construction {
    fn new(count: usize, reservation: &mut AllocationReservation) -> Result<Self, Error> {
        Ok(Self {
            charges: Some(ChargedBuffer::from_reservation(count, reservation)?),
        })
    }
    fn charges(&self) -> &ChargedBuffer<AllocationCharge> {
        self.charges.as_ref().expect("original ledger")
    }
    #[allow(unsafe_code)]
    fn take<T>(&mut self, buffer: ChargedBuffer<T>) -> Vec<T> {
        // SAFETY: the private fixed-capacity fields move immediately into the immutable Prepare
        // graph. The construction guard predates every detached field and outlives destruction.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        self.charges
            .as_mut()
            .expect("original ledger")
            .push_reserved(charge);
        values
    }
    fn transaction(
        &mut self,
        source: &AmxTransactionV1,
        reservation: &mut AllocationReservation,
    ) -> Result<AmxTransactionV1, Error> {
        let mut legs = ChargedBuffer::<AmxLegV1>::from_reservation(source.legs.len(), reservation)?;
        for leg in &source.legs {
            let mut payload =
                ChargedBuffer::<u8>::from_reservation(leg.payload.len(), reservation)?;
            payload
                .append(&leg.payload)
                .expect("exact original leg payload length");
            legs.push_reserved(AmxLegV1 {
                dataspace: leg.dataspace,
                payload: self.take(payload),
            });
        }
        Ok(AmxTransactionV1 {
            legs: self.take(legs),
            deadline: source.deadline,
            nonce: source.nonce,
        })
    }
    fn finish(mut self) -> ChargedBuffer<AllocationCharge> {
        self.charges.take().expect("original ledger")
    }
}
impl Drop for Construction {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(charges) = self.charges.take()
        {
            std::mem::forget(charges);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_amx_instruction_streamed_id_matches_bounded_canonical_transactions() {
        use crate::sumeragi_amx::{MAX_AMX_LEG_BYTES, MAX_AMX_PARTICIPANTS, MIN_AMX_PARTICIPANTS};
        use norito::schema::identity::NoritoSchema;
        assert!(
            std::mem::size_of::<AmxInstructionAdmissionErrorV1>() <= 128,
            "refusal contains the typed cause without an inline source graph"
        );
        assert_eq!(
            AmxTransactionV1::static_frame_name(),
            Some("iroha_data_model::sumeragi_amx::AmxTransactionV1")
        );
        assert_eq!(
            AmxLegV1::static_frame_name(),
            Some("iroha_data_model::sumeragi_amx::AmxLegV1")
        );
        for count in [MIN_AMX_PARTICIPANTS, MAX_AMX_PARTICIPANTS] {
            for bytes in [0, 1, MAX_AMX_LEG_BYTES] {
                let transaction = AmxTransactionV1 {
                    legs: (1..=count)
                        .map(|id| AmxLegV1 {
                            dataspace: DataSpaceId::new(u64::try_from(id).unwrap()),
                            payload: vec![0xAC; bytes],
                        })
                        .collect(),
                    deadline: 100,
                    nonce: [9; 32],
                };
                transaction.validate().unwrap();
                let original_frame = norito::encode_canonical(&transaction).unwrap();
                let original: [u8; 32] = iroha_crypto::Hash::new_from_chunks(&[
                    crate::sumeragi_amx::AMX_TRANSACTION_DOMAIN,
                    &original_frame,
                ])
                .into();
                let limits =
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
                let streamed = norito::with_decode_limits_scope(limits, || {
                    streamed_transaction_id(&transaction)
                })
                .unwrap();
                assert_eq!(
                    streamed, original,
                    "exact canonical ID for {count} bounded legs of {bytes} bytes"
                );
            }
        }
    }

    #[test]
    fn original_amx_prepare_identity_preserves_retained_graph_and_exact_pool_credit() {
        let (transaction, proof, pool) = crate::sumeragi_amx::allocated_amx_instruction_fixture();
        let original_proof = original_pointers(proof.canonical());
        let instruction = proof
            .into_prepare(transaction.legs[0].dataspace, &transaction)
            .complete(&pool)
            .unwrap();
        let retained = actual_instruction_layout_bytes(&instruction);
        assert_eq!(pool.reserved_bytes(), retained);
        pool.set_limit_bytes(retained);
        let source = instruction.as_any().downcast_ref::<PrepareAmxV1>().unwrap();
        let original_legs = source.transaction.legs.as_ptr();
        let original_payloads: [_; 2] =
            std::array::from_fn(|index| source.transaction.legs[index].payload.as_ptr());
        let frame = norito::encode_canonical(&source.transaction).unwrap();
        let expected: [u8; 32] = iroha_crypto::Hash::new_from_chunks(&[
            crate::sumeragi_amx::AMX_TRANSACTION_DOMAIN,
            &frame,
        ])
        .into();
        let AmxRecordV1::Begin(begin) = &source.begin.record else {
            panic!("original fixture Begin");
        };
        let original_participants = begin.participants.as_ptr();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let id = norito::with_decode_limits_scope(limits, || {
            assert!(begin.matches(&source.transaction));
            source.transaction.id()
        })
        .unwrap();
        assert_eq!(id, expected);
        assert_eq!(source.transaction.legs.as_ptr(), original_legs);
        assert_eq!(begin.participants.as_ptr(), original_participants);
        assert_eq!(original_pointers(&source.begin), original_proof);
        for (index, original) in original_payloads.into_iter().enumerate() {
            assert_eq!(source.transaction.legs[index].payload.as_ptr(), original);
        }
        assert!(instruction.amx_proof_admitted_to(&pool));
        assert_eq!(pool.reserved_bytes(), retained);
        drop(instruction);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    fn original_pointers(proof: &AmxRecordProofV1) -> [usize; 5] {
        let AmxRecordV1::Begin(begin) = &proof.record else {
            panic!("fixture original Begin");
        };
        [
            proof.block.consensus_header.as_ptr() as usize,
            proof.block.commit_qc.as_ptr() as usize,
            proof.block.result_preimage.as_ptr() as usize,
            proof.write.siblings.as_ptr() as usize,
            begin.participants.as_ptr() as usize,
        ]
    }

    fn actual_proof_layout_bytes(proof: &AmxRecordProofV1) -> usize {
        let AmxRecordV1::Begin(begin) = &proof.record else {
            panic!("fixture original Begin");
        };
        assert!(
            !proof.write.siblings.is_empty(),
            "fixture includes actual unrelated writes"
        );
        assert_eq!(
            proof.block.consensus_header.capacity(),
            proof.block.consensus_header.len()
        );
        assert_eq!(
            proof.block.commit_qc.capacity(),
            proof.block.commit_qc.len()
        );
        assert_eq!(
            proof.block.result_preimage.capacity(),
            proof.block.result_preimage.len()
        );
        assert_eq!(proof.write.siblings.capacity(), proof.write.siblings.len());
        assert_eq!(begin.participants.capacity(), begin.participants.len());
        // The complete closed canonical graph has exactly five actual heap fields.
        Layout::array::<u8>(proof.block.consensus_header.capacity())
            .unwrap()
            .size()
            + Layout::array::<u8>(proof.block.commit_qc.capacity())
                .unwrap()
                .size()
            + Layout::array::<u8>(proof.block.result_preimage.capacity())
                .unwrap()
                .size()
            + Layout::array::<[u8; 32]>(proof.write.siblings.capacity())
                .unwrap()
                .size()
            + Layout::array::<DataSpaceId>(begin.participants.capacity())
                .unwrap()
                .size()
            + Layout::array::<AllocationCharge>(5).unwrap().size()
    }

    fn actual_instruction_layout_bytes(instruction: &InstructionBox) -> usize {
        let original = instruction.as_any().downcast_ref::<PrepareAmxV1>().unwrap();
        assert_eq!(
            original.transaction.legs.capacity(),
            original.transaction.legs.len()
        );
        for leg in &original.transaction.legs {
            assert_eq!(leg.payload.capacity(), leg.payload.len());
        }
        actual_proof_layout_bytes(&original.begin)
            + Layout::array::<AmxLegV1>(original.transaction.legs.capacity())
                .unwrap()
                .size()
            + original
                .transaction
                .legs
                .iter()
                .map(|leg| Layout::array::<u8>(leg.payload.capacity()).unwrap().size())
                .sum::<usize>()
            + Layout::array::<AllocationCharge>(original.transaction.legs.len() + 1)
                .unwrap()
                .size()
            + ChargedShared::<FundedAmxInstruction>::allocation_layout().size()
    }

    #[test]
    fn original_amx_instruction_clone_retains_exact_graph_and_pool_through_last_reader() {
        let (transaction, proof, pool) = crate::sumeragi_amx::allocated_amx_instruction_fixture();
        let original = original_pointers(proof.canonical());
        let proof_bytes = actual_proof_layout_bytes(proof.canonical());
        assert_eq!(pool.reserved_bytes(), proof_bytes);
        let instruction = proof
            .into_prepare(transaction.legs[0].dataspace, &transaction)
            .complete(&pool)
            .unwrap();
        let bytes = actual_instruction_layout_bytes(&instruction);
        assert_eq!(pool.reserved_bytes(), bytes);
        let clone = instruction.clone();
        let source = clone.as_any().downcast_ref::<PrepareAmxV1>().unwrap();
        assert_eq!(original_pointers(&source.begin), original);
        assert_eq!(instruction, clone);
        assert_eq!(
            norito::encode_canonical(&instruction).unwrap(),
            norito::encode_canonical(&clone).unwrap()
        );
        assert!(clone.amx_proof_admitted_to(&pool));
        assert_eq!(pool.reserved_bytes(), bytes);
        drop(instruction);
        assert_eq!(
            pool.reserved_bytes(),
            bytes,
            "a remaining actual reader retains every charge"
        );
        assert_eq!(
            original_pointers(&clone.as_any().downcast_ref::<PrepareAmxV1>().unwrap().begin),
            original
        );
        drop(clone);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn original_amx_instruction_admits_complete_actual_layouts_before_copy_and_retries_same_pool() {
        let (transaction, proof, pool) = crate::sumeragi_amx::allocated_amx_instruction_fixture();
        let source_bytes = actual_proof_layout_bytes(proof.canonical());
        assert_eq!(proof.allocation_bytes(), Some(source_bytes));
        assert_eq!(
            pool.reserved_bytes(),
            source_bytes,
            "scratch is destroyed, complete proof backing stays charged"
        );
        let original = original_pointers(proof.canonical());
        // Compute each actual destination type independently, never use Action::demand.
        let additional = Layout::array::<AmxLegV1>(transaction.legs.len())
            .unwrap()
            .size()
            + transaction
                .legs
                .iter()
                .map(|leg| Layout::array::<u8>(leg.payload.len()).unwrap().size())
                .sum::<usize>()
            + Layout::array::<AllocationCharge>(transaction.legs.len() + 1)
                .unwrap()
                .size()
            + ChargedShared::<FundedAmxInstruction>::allocation_layout().size();
        let configured = pool.limit_bytes();
        let mut pending = proof.into_prepare(transaction.legs[0].dataspace, &transaction);
        pool.set_limit_bytes(source_bytes + additional - 1);
        let cause = pending.complete(&pool).unwrap_err();
        let Error::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = cause
        else {
            panic!("complete actual layouts must refuse before materialization: {cause:?}");
        };
        assert_eq!(requested_bytes, additional);
        assert_eq!(reserved_bytes, source_bytes);
        assert_eq!(limit_bytes, source_bytes + additional - 1);
        assert_eq!(
            pool.try_reserve_bytes(additional).unwrap_err(),
            AllocationRefusal::Capacity {
                requested_bytes,
                reserved_bytes,
                limit_bytes,
                release,
            }
        );
        assert_eq!(pool.reserved_bytes(), source_bytes);
        assert_eq!(
            original_pointers(pending.source().unwrap().canonical()),
            original
        );
        let foreign = AllocationBudget::new(configured);
        assert!(matches!(pending.complete(&foreign), Err(Error::Source)));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(pool.reserved_bytes(), source_bytes);
        pool.set_limit_bytes(configured);
        let instruction = pending.complete(&pool).unwrap();
        assert!(pending.source().is_none());
        let bytes = actual_instruction_layout_bytes(&instruction);
        assert_eq!(bytes, source_bytes + additional);
        assert_eq!(instruction.amx_proof_allocation_bytes(), Some(bytes));
        assert_eq!(pool.reserved_bytes(), bytes);
        assert_eq!(
            original_pointers(
                &instruction
                    .as_any()
                    .downcast_ref::<PrepareAmxV1>()
                    .unwrap()
                    .begin
            ),
            original
        );
        drop(instruction);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn original_amx_instruction_last_owner_destroys_fields_and_refunds_exact_ledger() {
        let (transaction, proof, pool) = crate::sumeragi_amx::allocated_amx_instruction_fixture();
        let source_bytes = actual_proof_layout_bytes(proof.canonical());
        let instruction = proof
            .into_prepare(transaction.legs[0].dataspace, &transaction)
            .complete(&pool)
            .unwrap();
        let bytes = actual_instruction_layout_bytes(&instruction);
        assert!(bytes > source_bytes);
        let clone = instruction.clone();
        assert_eq!(pool.reserved_bytes(), bytes);
        drop(instruction);
        assert_eq!(pool.reserved_bytes(), bytes);
        drop(clone);
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "the last owner returns every exact proof, additional ledger and shared shell charge"
        );
    }
}
