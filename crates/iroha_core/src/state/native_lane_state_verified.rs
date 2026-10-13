//! Read-only authentication of the original global lane state through native certified history.
use super::{State, WorldReadOnly};
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::BlockHeader, sumeragi_finality::SumeragiLaneStateCommitment,
    sumeragi_lanes::SumeragiLaneState,
};
use std::sync::Arc;

/// Read-only complete global lane state, tied to one stable State publication.
/// It is not a lane signing capability; `LaneRunner` owns admission and consensus execution.
pub struct VerifiedSumeragiLaneState<'state> {
    source: &'state State,
    generation: u64,
    height: u64,
    carrier: HashOf<BlockHeader>,
    lanes: Arc<SumeragiLaneState>,
}
impl std::fmt::Debug for VerifiedSumeragiLaneState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedSumeragiLaneState")
            .field("height", &self.height)
            .field("carrier", &self.carrier)
            .field("lanes", &self.lanes)
            .finish_non_exhaustive()
    }
}
impl VerifiedSumeragiLaneState<'_> {
    /// The exact certified global poststate.
    pub fn lanes(&self) -> &SumeragiLaneState {
        &self.lanes
    }
    /// Global height which committed this state.
    pub fn height(&self) -> u64 {
        self.height
    }
    /// Exact global carrier identity.
    pub fn carrier(&self) -> HashOf<BlockHeader> {
        self.carrier
    }
    /// Whether this receipt still describes the observed State publication.
    pub fn is_current(&self, state: &State) -> bool {
        std::ptr::eq(self.source, state)
            && super::is_stable_state_view_generation(
                self.generation,
                state.state_view_generation(),
            )
    }
}
impl State {
    /// Verify the complete live global lane state against original native carriers and archives.
    /// No MV guard is held during I/O. A concurrent publication returns `None` so callers retry
    /// from a fresh cut; missing or conflicting durable source fails closed.
    /// # Errors
    /// Rejects malformed history, unanchored or substituted state, missing archive data and I/O.
    pub fn verified_sumeragi_lane_state(
        &self,
    ) -> Result<Option<VerifiedSumeragiLaneState<'_>>, Attempt<String>> {
        let generation = self.state_view_generation();
        if !generation.is_multiple_of(2) {
            return Ok(None);
        }
        let (height, carrier, network, expected) = {
            let view = self.view();
            let Some(carrier) = view.block_hashes.last().copied() else {
                return Ok(None);
            };
            let height = view.block_hashes.len() as u64;
            let expected = SumeragiLaneStateCommitment::from_state_encoding(
                view.network_id,
                height,
                view.world().sumeragi_lanes(),
            )
            .map_err(|error| error.to_string())?;
            (height, carrier, view.network_id, expected)
        };
        if height < 2
            || !super::is_stable_state_view_generation(generation, self.state_view_generation())
        {
            return Ok(None);
        }
        let result: Result<Arc<SumeragiLaneState>, Attempt<String>> = (|| {
            let archive =
                crate::query::native_context_archive::NativeContextArchive::open_existing(
                    &self.kura,
                    self.ivm_execution_budget(),
                    self.kura.native_context_archive_max_bytes(),
                )
                .map_err(archive_attempt)?;
            let state_bound = u64::try_from(self.kura.native_context_archive_max_bytes().get())
                .map_err(|_| "lane archive bound overflow")?;
            let block_bound = iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES as u64;
            let retained = block_bound
                .checked_add(state_bound)
                .and_then(|per| per.checked_mul(height))
                .ok_or("native history bound overflow")?;
            let mut verifier =
                super::native_execution_evidence::NativeExecutionEvidenceVerifier::new(
                    self.chain_id_ref().clone(),
                    network,
                    super::native_execution_evidence::NativeExecutionEvidenceLimits {
                        max_carriers: height,
                        max_carrier_bytes: block_bound,
                        max_context_bytes: state_bound,
                        max_retained_bytes: retained,
                    },
                )?;
            for next in 1..=height {
                let index = usize::try_from(next)
                    .ok()
                    .and_then(std::num::NonZeroUsize::new)
                    .ok_or("native carrier index overflow")?;
                let block = self
                    .kura
                    .get_block(index, &self.ivm_execution_budget())
                    .map_err(|error| error.map_rejection(|error| error.to_string()))?
                    .ok_or_else(|| format!("native carrier {next} is unavailable"))?;
                if next == height && block.hash() != carrier {
                    return Err("native history differs from State tip".into());
                }
                let bytes = archive.read_exact(next, block.hash()).map_err(|error| {
                    archive_attempt(error).map_rejection(|error| {
                        format!("required historical native lane state source {next}: {error}")
                    })
                })?;
                verifier.push_height(block, bytes.as_slice())?;
            }
            archive.recheck_namespace().map_err(archive_attempt)?;
            let lanes = verifier.into_current_lanes()?;
            if SumeragiLaneStateCommitment::from_state_encoding(network, height, &lanes)
                .map_err(|error| error.to_string())?
                != expected
            {
                return Err("complete certified lane state differs from State publication".into());
            }
            Ok(lanes)
        })();
        if !super::is_stable_state_view_generation(generation, self.state_view_generation()) {
            return Ok(None);
        }
        Ok(Some(VerifiedSumeragiLaneState {
            source: self,
            generation,
            height,
            carrier,
            lanes: result?,
        }))
    }
}

// Preserve an actual original archive refusal before rendering permanent source diagnostics.
fn archive_attempt(
    error: crate::query::native_context_archive::NativeContextArchiveError,
) -> Attempt<String> {
    use crate::query::native_context_archive::NativeContextArchiveError as Error;
    match error {
        Error::Allocation(iroha_allocation::ChargedBufferError::Admission(original)) => {
            Attempt::Deferred(original.into())
        }
        Error::Allocation(iroha_allocation::ChargedBufferError::Allocator { .. }) => {
            Attempt::Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
        }
        Error::Codec(error) => {
            crate::execution_attempt::norito_decode_attempt_error(error, |error| error.to_string())
        }
        error => Attempt::Rejected(error.to_string()),
    }
}
