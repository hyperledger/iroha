//! Original-pool scratch for the canonical signed RS16 availability verifier.

use std::alloc::Layout;

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, AllocationReservation, AllocatorRefusal, ChargedBuffer,
    ChargedBufferFromChargeError,
};
use iroha_data_model::sumeragi_finality::MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES;
use iroha_sumeragi::{
    availability::AvailabilityFrame,
    crypto::Crypto,
    message::BlockHeader,
    types::{Hash32, HeightConfig},
};

use super::{ChainReadError, VerificationReadError, retained_query_authority::invariant};
use crate::execution_attempt::ExecutionDeferred;

struct Scratch {
    codeword: ChargedBuffer<u8>,
    workspace: ChargedBuffer<u16>,
}

impl Scratch {
    fn demand(codeword: usize, workspace: usize) -> Result<usize, AllocationRefusal> {
        let codeword =
            Layout::array::<u8>(codeword).map_err(|_| AllocationRefusal::DemandOverflow)?;
        let workspace =
            Layout::array::<u16>(workspace).map_err(|_| AllocationRefusal::DemandOverflow)?;
        codeword
            .size()
            .checked_add(workspace.size())
            .ok_or(AllocationRefusal::DemandOverflow)
    }

    fn from_reservation(
        codeword: usize,
        workspace: usize,
        budget: &AllocationBudget,
        original: &mut AllocationReservation,
    ) -> Result<Self, ExecutionDeferred> {
        // `verify` reserves from this same pool; the check keeps any later caller honest.
        if !original.belongs_to(budget) {
            return Err(invariant());
        }
        Self::demand(codeword, workspace)?;
        Ok(Self {
            codeword: zeroed(codeword, original)?,
            workspace: zeroed(workspace, original)?,
        })
    }
}

fn zeroed<T: Copy + Default>(
    count: usize,
    original: &mut AllocationReservation,
) -> Result<ChargedBuffer<T>, ExecutionDeferred> {
    let layout = Layout::array::<T>(count).map_err(|_| AllocationRefusal::DemandOverflow)?;
    let charge = original.try_split(layout).map_err(|_| invariant())?;
    let mut buffer = ChargedBuffer::try_from_charge(count, charge).map_err(|(charge, error)| {
        drop(charge);
        match error {
            original @ ChargedBufferFromChargeError::Allocator { .. } => {
                AllocatorRefusal::try_from(original)
                    .expect("matched original exact scratch allocator refusal")
                    .into()
            }
            _ => invariant(),
        }
    })?;
    for _ in 0..count {
        buffer.push_reserved(T::default());
    }
    Ok(buffer)
}

/// Run the shared signature and payload relations with exactly prepaid RS16 scratch.
/// Authentication and the portable bound precede the caller's logical admission;
/// both physical buffers retain their original charges until deallocation.
pub(super) fn verify(
    instance: Hash32,
    config: &HeightConfig,
    header: &BlockHeader,
    availability: &AvailabilityFrame,
    payload: &[u8],
    crypto: &dyn Crypto,
    budget: &AllocationBudget,
    admit: &mut dyn FnMut(usize) -> Result<(), ExecutionDeferred>,
) -> Result<(), VerificationReadError> {
    #[cfg(all(test, sumeragi_core_mutation = "HC959"))]
    let substituted_pool = AllocationBudget::new(budget.limit_bytes());
    #[cfg(all(test, sumeragi_core_mutation = "HC959"))]
    let budget = &substituted_pool;
    let malformed = |reason| {
        VerificationReadError::Source(ChainReadError::Malformed {
            height: header.height,
            reason,
        })
    };
    let verified = iroha_sumeragi::availability::verify_availability(
        instance,
        config,
        header,
        availability.as_slice(),
        crypto,
    )
    .map_err(|error| malformed(format!("signed availability: {error:?}")))?;
    let shape = verified.shape();
    let bytes = Scratch::demand(shape.encoded_bytes(), shape.workspace_words())
        .map_err(|_| malformed("availability scratch length overflow".into()))?;
    if bytes > MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES {
        return Err(VerificationReadError::Deferred(
            AllocationRefusal::ExceedsLimit {
                requested_bytes: bytes,
                limit_bytes: MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES,
            }
            .into(),
        ));
    }
    admit(bytes).map_err(VerificationReadError::Deferred)?;
    let mut original = budget
        .try_reserve_bytes(bytes)
        .map_err(|error| VerificationReadError::Deferred(error.into()))?;
    let mut scratch = Scratch::from_reservation(
        shape.encoded_bytes(),
        shape.workspace_words(),
        budget,
        &mut original,
    )
    .map_err(VerificationReadError::Deferred)?;
    debug_assert_eq!(original.remaining_bytes(), 0);
    verified
        .verify_payload(
            payload,
            scratch.codeword.as_mut_slice(),
            scratch.workspace.as_mut_slice(),
            crypto,
        )
        .map_err(|error| malformed(format!("availability payload: {error:?}")))
}

#[cfg(test)]
mod tests;
