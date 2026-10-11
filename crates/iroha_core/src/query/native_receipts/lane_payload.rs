//! Original archive-byte ownership for an independently committed complete lane payload.
//!
//! Only the lane field and the complete ordinary-write root acquire authority here. Casting
//! values have their own consumers. No World snapshot, embedded committee or supplied root can
//! create this owner; the selected carrier is an opaque original committed execution receipt.

mod authority;
pub(crate) use authority::{LaneAuthority, LaneAuthorityRead};
mod custody;
mod select;
pub(crate) use custody::LaneCustodyView;

use std::ops::Range;

use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBuffer, PrepaidBufferError};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    block::BlockHeader,
    sumeragi_finality::{NativeLaneStateProof, NativeLaneStateProofError},
};

use super::ordinary_writes::{WriteDecodeError, decode_projection};
#[cfg(test)]
use crate::sumeragi::certified_chain::CommittedBlock;

/// Source corruption is distinct from retryable refusal of the original read pool.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LanePayloadError {
    #[error("lane context source differs from its original carrier or pool")]
    Source,
    #[error("lane context differs from the original certified execution")]
    Commitment,
    #[error(transparent)]
    Codec(#[from] norito::Error),
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    #[error(transparent)]
    Materialization(#[from] PrepaidBufferError),
    #[error(transparent)]
    Proof(#[from] NativeLaneStateProofError),
}
impl LanePayloadError {
    /// A local ceiling or allocator refusal preserves the original source. Ceiling refusal
    /// may require local reconfiguration; it is never proof that committed history is invalid.
    pub(crate) fn is_local_refusal(&self) -> bool {
        fn admission(error: &AllocationRefusal) -> bool {
            matches!(
                error,
                AllocationRefusal::ExceedsLimit { .. } | AllocationRefusal::Capacity { .. }
            )
        }
        fn materialization(error: &iroha_allocation::ChargedBufferError) -> bool {
            match error {
                iroha_allocation::ChargedBufferError::Admission(error) => admission(error),
                iroha_allocation::ChargedBufferError::Allocator { .. } => true,
            }
        }
        match self {
            Self::Codec(error) => error.is_decode_resource_limit(),
            Self::Admission(error) => admission(error),
            Self::Materialization(PrepaidBufferError::Allocation(error)) => materialization(error),
            Self::Proof(original) => original.is_local_refusal(),
            _ => false,
        }
    }
}
impl From<WriteDecodeError> for LanePayloadError {
    fn from(error: WriteDecodeError) -> Self {
        match error {
            WriteDecodeError::ForeignPool | WriteDecodeError::PlanChanged => Self::Source,
            WriteDecodeError::Codec(error) => Self::Codec(error),
            WriteDecodeError::Admission(error) => Self::Admission(error),
            WriteDecodeError::Materialization(error) => Self::Materialization(error),
        }
    }
}

/// One immutable original source and carrier selection retained through authentication refusal.
pub(crate) struct LanePayloadRead {
    bytes: ChargedBuffer<u8>,
    budget: AllocationBudget,
    network: NetworkId,
    height: u64,
    carrier: HashOf<BlockHeader>,
    ordinary_root: Hash,
}
impl LanePayloadRead {
    /// Pin the caller's original byte/pool owners and an already authenticated carrier. No read,
    /// graph decode, clone or allocation occurs here, and the selection cannot change on retry.
    #[cfg(test)]
    pub(crate) fn new(
        bytes: ChargedBuffer<u8>,
        budget: AllocationBudget,
        network: NetworkId,
        committed: &CommittedBlock,
    ) -> Self {
        Self {
            bytes,
            budget,
            network,
            height: committed.height(),
            carrier: committed.block().hash(),
            ordinary_root: committed.commitment().execution.ordinary_writes_root,
        }
    }

    /// Pin the exact source to a chronological receipt already authenticated by its original
    /// native prefix. The enclosing reader must finish/recheck the captured State interval.
    pub(crate) fn from_verified(
        bytes: ChargedBuffer<u8>,
        budget: AllocationBudget,
        network: NetworkId,
        verified: &crate::state::VerifiedNativeExecutionCarrier,
    ) -> Self {
        Self {
            bytes,
            budget,
            network,
            height: verified.block().header().height().get(),
            carrier: verified.block().hash(),
            ordinary_root: verified.ordinary_writes_root(),
        }
    }

    fn authenticate_range(&self) -> Result<Range<usize>, LanePayloadError> {
        let projection = decode_projection(&self.bytes, &self.budget)?;
        if projection.carrier_height != self.height || projection.carrier_hash != self.carrier {
            return Err(LanePayloadError::Source);
        }
        let proof = NativeLaneStateProof::from_witness(projection.witness.get(), &self.budget)?;
        if !proof.verify(self.network, self.height, self.ordinary_root)
            || !proof.matches_state_payload(self.network, self.height, projection.lane_payload)?
        {
            return Err(LanePayloadError::Commitment);
        }
        // The decoder borrows a contiguous field of these exact bytes. Preserve its offset,
        // never its address across a move, and validate the bounds before exposing the owner.
        let start = (projection.lane_payload.as_ptr() as usize)
            .checked_sub(self.bytes.as_slice().as_ptr() as usize)
            .ok_or(LanePayloadError::Source)?;
        let end = start
            .checked_add(projection.lane_payload.len())
            .ok_or(LanePayloadError::Source)?;
        if self.bytes.as_slice().get(start..end) != Some(projection.lane_payload) {
            return Err(LanePayloadError::Source);
        }
        Ok(start..end)
    }

    /// Authenticate complete original lane bytes and write root without decoding a lane graph.
    /// Every failure returns this same immutable source/selection; no fallback source is opened.
    #[expect(
        clippy::result_large_err,
        reason = "return the original funded source and pinned carrier without allocating on refusal"
    )]
    pub(crate) fn authenticate(self) -> Result<LanePayload, (Self, LanePayloadError)> {
        match self.authenticate_range() {
            Ok(range) => Ok(LanePayload {
                bytes: self.bytes,
                range,
                network: self.network,
                height: self.height,
                carrier: self.carrier,
            }),
            Err(error) => Err((self, error)),
        }
    }
}

/// Authenticated complete lane payload borrowing no World guard and owning its original bytes.
/// This supplies historical values only. The enclosing offence reader must retain/recheck the
/// original State cut and exact staking provenance before publishing monetary attribution.
pub(crate) struct LanePayload {
    bytes: ChargedBuffer<u8>,
    range: Range<usize>,
    network: NetworkId,
    height: u64,
    carrier: HashOf<BlockHeader>,
}
impl LanePayload {
    /// Original canonical lane payload, without a second frame or decoded graph.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.bytes.as_slice()[self.range.clone()]
    }
    /// Borrow one original creation record by incarnation; retirement may remove it later.
    pub(crate) fn lane_record(
        &self,
        incarnation: &[u8; 32],
    ) -> Result<Option<&[u8]>, LanePayloadError> {
        select::lane(self.payload(), incarnation).map_err(LanePayloadError::Codec)
    }
    /// Borrow original sparse signer custody without decoding or copying its vector.
    pub(crate) fn custody_record(
        &self,
        incarnation: &[u8; 32],
    ) -> Result<Option<LaneCustodyView<'_>>, LanePayloadError> {
        select::custody(self.payload(), incarnation)?
            .map(LaneCustodyView::parse)
            .transpose()
            .map_err(LanePayloadError::Codec)
    }
    /// Exact authenticated network and global carrier selection.
    pub(crate) fn carrier(&self) -> (NetworkId, u64, HashOf<BlockHeader>) {
        (self.network, self.height, self.carrier)
    }
    /// Original physical read pool; callers cannot relabel an equal-sized foreign pool.
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.bytes.belongs_to(budget)
    }
}

#[cfg(test)]
mod tests;
