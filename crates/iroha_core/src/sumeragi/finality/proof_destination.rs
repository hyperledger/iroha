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
use iroha_version::Version as _;
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
    _charges: ChargedBuffer<AllocationCharge>,
}
impl OwnedProof {
    #[allow(unsafe_code)]
    pub(super) fn new(
        block: &SharedSignedBlock,
        members: &[iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1],
        budget: &AllocationBudget,
        deadline: Instant,
    ) -> Result<Self, ProofDestinationError> {
        check(deadline)?;
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
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
        let charge_count = members
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_add(2))
            .ok_or(ProofDestinationError::Admission(
                AllocationRefusal::DemandOverflow,
            ))?;
        let mut charges =
            ChargedBuffer::new(charge_count, budget).map_err(ProofDestinationError::Buffer)?;
        let mut wire = charged_vec::<u8>(length, budget, &mut charges)?;
        check(deadline)?;
        {
            let mut writer = FixedVecWriter {
                bytes: &mut wire,
                maximum: length,
            };
            writer
                .write_all(&[block.version()])
                .map_err(|_| ProofDestinationError::Source)?;
            norito::core::write_canonical_to_writer(block.as_ref(), &mut writer)
                .map_err(|_| ProofDestinationError::Source)?;
        }
        if wire.len() != length {
            return Err(ProofDestinationError::Source);
        }
        check(deadline)?;
        let mut committee = charged_vec::<FinalityValidator>(members.len(), budget, &mut charges)?;
        for member in members {
            check(deadline)?;
            let mut pop =
                charged_vec::<u8>(member.proof_of_possession.len(), budget, &mut charges)?;
            pop.extend_from_slice(&member.proof_of_possession);
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
                // SAFETY: this closed move-only proof immediately retains the exact
                // compact key charge. Proof fields retire before the ledger, and no
                // mutable access or uncharged move-out is exposed by its consumers.
                let (key, charge) = unsafe { retained.into_allocation_parts() };
                charges.push_reserved(charge);
                key
            };
            committee.push(FinalityValidator {
                public_key: key,
                proof_of_possession: pop,
            });
        }
        Ok(Self {
            proof: SumeragiFinalityProof {
                block_header: block.header(),
                block_wire: wire,
                committee,
            },
            _charges: charges,
        })
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
