//! One original-pool portable proof destination, shared by bounded consumers.
//!
//! Actual wire, committee, compact public-key and PoP allocations retire before
//! their exact charge ledger. Nested decoder/verifier graphs remain obligations
//! of the integrating caller; this destination grants no certificate authority.

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedBufferError,
};
use iroha_data_model::{
    block::SharedSignedBlock,
    sumeragi_finality::{FinalityValidator, MAX_FINALITY_BLOCK_BYTES, SumeragiFinalityProof},
};
use std::{alloc::Layout, io::Write as _, time::Instant};

/// Failure to construct a portable destination from the original finite owner.
#[derive(Debug, thiserror::Error)]
pub enum ProofDestinationError {
    /// The original deadline expired between bounded destination operations.
    #[error("proof destination deadline expired")]
    Deadline,
    /// Canonical source extent or shape is invalid.
    #[error("proof destination canonical source differs")]
    Source,
    /// Exact original pool admission refused before allocation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Actual fixed backing admission or allocator refusal.
    #[error(transparent)]
    Buffer(#[from] ChargedBufferError),
    /// Exact prepaid compact-key allocator or source-custody refusal.
    #[error(transparent)]
    Key(#[from] iroha_crypto::PublicKeyAllocationError),
}

fn check(deadline: Instant) -> Result<(), ProofDestinationError> {
    if Instant::now() >= deadline {
        Err(ProofDestinationError::Deadline)
    } else {
        Ok(())
    }
}

// Field drop order reclaims the proof's actual Vec allocations before refunding their charges.
pub(super) struct OwnedProof {
    pub(super) proof: SumeragiFinalityProof,
    charges: ChargedBuffer<AllocationCharge>,
}
impl OwnedProof {
    pub(super) fn new(
        block: &SharedSignedBlock,
        members: &[iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1],
        budget: &AllocationBudget,
        deadline: Instant,
    ) -> Result<Self, ProofDestinationError> {
        let mut original = ProofPreparation::default();
        original.complete(block, members, budget, deadline)?;
        Ok(original
            .construction
            .expect("completed proof destination")
            .owned)
    }
}

// The retrying caller retains this construction; one-shot consumers use the same kernel
// and retire incomplete work normally. No new authority or alternative decoder is exposed.
#[derive(Default)]
pub(super) struct ProofPreparation {
    construction: Option<Construction>,
}
struct Construction {
    // A PoP allocated before its key must retire before the proof's original charge ledger.
    pop: Option<Vec<u8>>,
    owned: OwnedProof,
    block: SharedSignedBlock,
    // Comparison-only original immutable slice identity, never signature authority.
    members_address: usize,
    member_count: usize,
    wire_len: usize,
    wire_complete: bool,
}
impl ProofPreparation {
    pub(super) fn complete(
        &mut self,
        block: &SharedSignedBlock,
        members: &[iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1],
        budget: &AllocationBudget,
        deadline: Instant,
    ) -> Result<&OwnedProof, ProofDestinationError> {
        check(deadline)?;
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        if self.construction.is_none() {
            let length = norito::canonical_frame_len(block.as_ref())
                .map_err(|_| ProofDestinationError::Source)?
                .checked_add(1)
                .ok_or(ProofDestinationError::Source)?;
            if length > MAX_FINALITY_BLOCK_BYTES
                || members.is_empty()
                || members.len() > iroha_sumeragi::types::MAX_COMMITTEE_SIZE
            {
                return Err(ProofDestinationError::Source);
            }
            let count = members
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(2))
                .ok_or(ProofDestinationError::Admission(
                    AllocationRefusal::DemandOverflow,
                ))?;
            let charges =
                ChargedBuffer::new(count, budget).map_err(ProofDestinationError::Buffer)?;
            self.construction = Some(Construction {
                pop: None,
                owned: OwnedProof {
                    proof: SumeragiFinalityProof {
                        block_header: block.header(),
                        block_wire: Vec::new(),
                        committee: Vec::new(),
                    },
                    charges,
                },
                block: block.clone(),
                members_address: members.as_ptr() as usize,
                member_count: members.len(),
                wire_len: length,
                wire_complete: false,
            });
        }
        let original = self
            .construction
            .as_mut()
            .expect("original proof construction");
        if !std::ptr::eq(original.block.as_ref(), block.as_ref())
            || original.members_address != members.as_ptr() as usize
            || original.member_count != members.len()
            || !original.owned.charges.belongs_to(budget)
        {
            return Err(ProofDestinationError::Source);
        }
        original.fill(members, budget, deadline)?;
        Ok(&original.owned)
    }
}
impl Construction {
    #[allow(unsafe_code)]
    fn fill(
        &mut self,
        members: &[iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1],
        budget: &AllocationBudget,
        deadline: Instant,
    ) -> Result<(), ProofDestinationError> {
        let Self {
            pop,
            owned,
            block,
            wire_len,
            wire_complete,
            ..
        } = self;
        if !*wire_complete {
            if owned.proof.block_wire.capacity() == 0 {
                owned.proof.block_wire = charged_vec::<u8>(*wire_len, budget, &mut owned.charges)?;
            }
            check(deadline)?;
            // A rejected partial encoder can retry without allocating or appending twice.
            owned.proof.block_wire.clear();
            let mut writer = FixedVecWriter {
                bytes: &mut owned.proof.block_wire,
                maximum: *wire_len,
            };
            writer
                .write_all(&[iroha_data_model::block::SignedBlock::WIRE_VERSION])
                .map_err(|_| ProofDestinationError::Source)?;
            norito::core::write_canonical_to_writer(block.as_ref(), &mut writer)
                .map_err(|_| ProofDestinationError::Source)?;
            if owned.proof.block_wire.len() != *wire_len {
                return Err(ProofDestinationError::Source);
            }
            *wire_complete = true;
        }
        check(deadline)?;
        if owned.proof.committee.capacity() == 0 {
            owned.proof.committee =
                charged_vec::<FinalityValidator>(members.len(), budget, &mut owned.charges)?;
        }
        while owned.proof.committee.len() < members.len() {
            check(deadline)?;
            let member = &members[owned.proof.committee.len()];
            if pop.is_none() {
                let mut original = charged_vec::<u8>(
                    member.proof_of_possession.len(),
                    budget,
                    &mut owned.charges,
                )?;
                original.extend_from_slice(&member.proof_of_possession);
                *pop = Some(original);
            }
            #[cfg(test)]
            super::cursor::probe_pending_key(
                block.header().height().get(),
                owned.proof.committee.len(),
                members.len(),
                member
                    .validator
                    .public_key()
                    .retained_allocation_layout()
                    .size(),
                owned.proof.block_wire.as_ptr() as usize,
                pop.as_ref().expect("original PoP").as_ptr() as usize,
            );
            #[cfg(all(test, sumeragi_core_mutation = "HC213"))]
            let key = member.validator.public_key().clone();
            #[cfg(not(all(test, sumeragi_core_mutation = "HC213")))]
            let key = {
                let original_key = member.validator.public_key();
                let layout = original_key.retained_allocation_layout();
                let mut reservation = budget
                    .try_reserve(layout)
                    .map_err(ProofDestinationError::Admission)?;
                let charge = reservation
                    .try_split(layout)
                    .expect("exact admitted key layout");
                let retained = original_key
                    .try_clone_from_charge(budget, charge)
                    .map_err(|(_original_charge, error)| ProofDestinationError::Key(error))?;
                // SAFETY: the compact key moves directly into this private owned proof.
                // Its graph and pending PoP retire before this exact original charge ledger.
                let (key, charge) = unsafe { retained.into_allocation_parts() };
                owned.charges.push_reserved(charge);
                key
            };
            owned.proof.committee.push(FinalityValidator {
                public_key: key,
                proof_of_possession: pop.take().expect("original complete PoP"),
            });
        }
        Ok(())
    }
}

fn charged_vec<T>(
    capacity: usize,
    budget: &AllocationBudget,
    charges: &mut ChargedBuffer<AllocationCharge>,
) -> Result<Vec<T>, ProofDestinationError> {
    let layout = Layout::array::<T>(capacity)
        .map_err(|_| ProofDestinationError::Admission(AllocationRefusal::DemandOverflow))?;
    let charge = budget
        .try_reserve(layout)
        .map_err(ProofDestinationError::Admission)?
        .try_split(layout)
        .expect("exact admitted destination layout");
    let mut values = Vec::new();
    values.try_reserve_exact(capacity).map_err(|_| {
        ProofDestinationError::Buffer(ChargedBufferError::Allocator {
            requested_bytes: layout.size(),
        })
    })?;
    charges.push_reserved(charge);
    Ok(values)
}
struct FixedVecWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}
impl std::io::Write for FixedVecWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("native proof exceeds counted extent"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
