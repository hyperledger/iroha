//! Availability authority from the original native State and authenticated historical carriers.
//!
//! Stored lane/body artifacts never select their own epoch, committee, layout or instance.
//! Historical lane incarnations are recovered from the original context archive and complete
//! certified prefix, including after retirement removes them from the current World projection.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use parking_lot::Mutex;
use std::{io, sync::Arc};

use iroha_data_model::{
    NetworkId,
    sumeragi_finality::{ScheduledConfig, ScheduledSlot},
};
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::types::{Hash32, HeightConfig};

use super::{
    availability_schedule::AvailabilitySchedule,
    certified_chain::{CertifiedChain, committed_block},
    crypto::BlsCrypto,
    lanes::{
        incarnation_instance,
        registry::{LaneStoreAuthorities, LaneStoreAuthority},
    },
};
use crate::{
    query::native_receipts::lane_payload::{LaneAuthority, LanePayloadError},
    state::{State, StateReadOnly, WorldReadOnly},
};

pub(super) mod history;
mod selection;
use history::HistoryScan;

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn pending(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, reason)
}

/// Resolve global authority under one immutable configured instance and original State owner.
pub struct NativeGlobalAvailability {
    state: Arc<State>,
    instance: Hash32,
    crypto: Arc<BlsCrypto>,
}
impl NativeGlobalAvailability {
    /// Bind the supplied instance to State's authenticated signed genesis and configured chain.
    /// Genesis must already be applied; its hash is the exact network identifier.
    ///
    /// # Errors
    /// Genesis cannot be authenticated, or the supplied instance does not name that genesis.
    pub fn new(
        state: Arc<State>,
        instance: Hash32,
        crypto: Arc<BlsCrypto>,
    ) -> Result<Self, Attempt<io::Error>> {
        let expected = {
            let view = state.view();
            CertifiedChain::new(&view)
                .map_err(|error| {
                    if cfg!(all(test, sumeragi_core_mutation = "HC47")) {
                        invalid(error).into()
                    } else {
                        error.map_rejection(invalid)
                    }
                })?
                .instance()
        };
        if expected != instance {
            return Err(invalid("global availability instance differs from State").into());
        }
        Ok(Self {
            state,
            instance,
            crypto,
        })
    }

    fn resolve(&self, height: u64) -> Result<Option<ScheduledConfig>, Attempt<io::Error>> {
        if height <= 1 {
            return Ok(None);
        }
        let view = self.state.view();
        if view.kura().native_consensus_gate().is_closed() {
            return Err(
                io::Error::other("native storage gate is closed; restart is required").into(),
            );
        }
        let tip = view
            .native_execution_tip()
            .ok_or_else(|| pending("original native execution is not published"))?;
        if tip.height() != view.height() as u64
            || Some(tip.iroha_hash()) != view.latest_block_hash()
        {
            return Err(
                invalid("native execution tip differs from captured State publication").into(),
            );
        }
        if height > tip.height() {
            return match view.world().consensus_schedule().get(height) {
                Some(ScheduledSlot::Ready(config)) => Ok(Some(config.clone())),
                Some(ScheduledSlot::PendingBoundary { .. }) | None => Ok(None),
            };
        }
        // The original native tip in this same view authenticates execution ancestry. This
        // reader verifies each parent core hash, R, Iroha hash and executed-frame binding;
        // local CommitQC bytes are deliberately not the source of deterministic authority.
        let parent = committed_block(&view, height - 1).map_err(|error| {
            if cfg!(all(test, sumeragi_core_mutation = "HC47")) {
                invalid(error).into()
            } else {
                error.map_rejection(invalid)
            }
        })?;
        if parent
            .header()
            .is_some_and(|header| header.instance != self.instance)
        {
            return Err(invalid("historical global instance differs").into());
        }
        // The requested body is never the source of its own parameters or authority.
        match &parent.commitment().schedule.next {
            ScheduledSlot::Ready(config) if config.height == height => Ok(Some(config.clone())),
            _ => Err(invalid("certified parent has no exact next-height authority").into()),
        }
    }
}
impl AvailabilitySchedule for NativeGlobalAvailability {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        let Some(scheduled) = self.resolve(height)? else {
            return Ok(None);
        };
        let config = scheduled.height_config().map_err(invalid)?;
        self.crypto
            .admit_committee(scheduled.epoch.committee.iter().map(|member| {
                (
                    member.validator.public_key(),
                    member.proof_of_possession.as_slice(),
                )
            }))
            .map_err(|(index, error)| {
                invalid(format!("historical global member {index}: {error}"))
            })?;
        Ok(Some(config))
    }
}

/// Lane authority pinned to the native State's network, chain and actual BLS admission owner.
pub struct NativeLaneStoreAuthorities {
    state: Arc<State>,
    crypto: Arc<BlsCrypto>,
    scan: Mutex<Option<HistoryScan>>,
}
impl NativeLaneStoreAuthorities {
    /// Use State's original archive pool and the same BLS owner as the lane stores.
    #[must_use]
    pub fn new(state: Arc<State>, crypto: Arc<BlsCrypto>) -> Self {
        Self {
            state,
            crypto,
            scan: Mutex::new(None),
        }
    }

    fn historical_record(
        &self,
        lane: LaneId,
        incarnation: [u8; 32],
    ) -> Result<Option<LaneAuthority>, Attempt<io::Error>> {
        let mut pending_scan = self
            .scan
            .try_lock()
            .ok_or_else(|| pending("native authority scan is busy"))?;
        if pending_scan
            .as_ref()
            .is_some_and(|scan| !scan.matches(lane, &incarnation))
        {
            // A cancelled/evicted caller must not strand the original refused read forever.
            // Progress its exact owner first; no new request can replace it on refusal.
            if let Err(error) = pending_scan
                .as_mut()
                .expect("original pending scan")
                .complete()
            {
                if error.io_kind() != io::ErrorKind::WouldBlock {
                    *pending_scan = None;
                }
                return Err(error);
            }
            // This completed result belongs to the cancelled request. Explicitly abandon it,
            // returning its source/config charges before admitting the newly requested owner.
            *pending_scan = None;
        }
        if pending_scan.is_none() {
            *pending_scan = HistoryScan::open(&self.state, lane, incarnation)?;
        }
        let Some(scan) = pending_scan.as_mut() else {
            return Ok(None);
        };
        if let Err(error) = scan.complete() {
            if error.io_kind() != io::ErrorKind::WouldBlock {
                // A terminally rejected prefix grants no authority. Do not leave its poisoned
                // verifier occupying the sole retry slot for unrelated incarnation requests.
                *pending_scan = None;
            }
            return Err(error);
        }
        if !crate::state::is_stable_state_view_generation(
            scan.generation(),
            self.state.state_view_generation(),
        ) {
            // This completed prefix belongs to a different publication cut. A new lookup
            // starts against the new original cut; no authority has escaped this attempt.
            *pending_scan = None;
            return Err(pending("native State publication changed during authority lookup").into());
        }
        Ok(pending_scan
            .take()
            .expect("completed original scan")
            .finish())
    }
}

struct PinnedLaneAvailability {
    instance: Hash32,
    authority: LaneAuthority,
}
impl AvailabilitySchedule for PinnedLaneAvailability {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        Ok(self
            .authority
            .config()
            .epoch
            .contains(height)
            .then(|| self.authority.config().clone()))
    }
}
impl LaneStoreAuthorities for NativeLaneStoreAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
        let network: NetworkId = *self.state.network_id_ref();
        let expected = incarnation_instance(
            &*self.crypto,
            &network,
            &self.state.chain_id_ref().to_string(),
            lane,
            incarnation,
        );
        if expected != instance {
            return Err(invalid(
                "requested lane instance differs from native network and incarnation",
            )
            .into());
        }
        let Some(authority) = self.historical_record(lane, *incarnation)? else {
            return Ok(None);
        };
        if authority.lane() != lane {
            return Err(invalid("selected original authority names another lane").into());
        }
        admit_lane_authority(&self.crypto, &authority)?;
        Ok(Some(LaneStoreAuthority {
            schedule: Arc::new(PinnedLaneAvailability {
                instance,
                authority,
            }),
        }))
    }
}

// The fixed native geometry bounds this borrowed credential view. Original PoPs stay in
// the creation frame. TODO(S8): fund BLS parsing/cache and schedule-returned config clones;
// the source/config owner here does not account for those independent allocations.
fn admit_lane_authority(
    crypto: &BlsCrypto,
    authority: &LaneAuthority,
) -> Result<(), Attempt<io::Error>> {
    let mut members: [Option<(iroha_crypto::PublicKey, &[u8])>;
        iroha_data_model::block::consensus::MAX_VALIDATORS_PER_HEIGHT] =
        std::array::from_fn(|_| None);
    let mut count = 0;
    authority
        .visit_members(|key, proof| {
            let slot = members.get_mut(count).ok_or(LanePayloadError::Source)?;
            let key = iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::BlsNormal, key)
                .map_err(|_| LanePayloadError::Source)?;
            *slot = Some((key, proof));
            count += 1;
            Ok(())
        })
        .map_err(history::payload_error)?;
    crypto
        .admit_committee(
            members[..count]
                .iter()
                .flatten()
                .map(|(key, proof)| (key, *proof)),
        )
        .map_err(|(index, error)| invalid(format!("historical lane member {index}: {error}")))?;
    Ok(())
}

#[cfg(test)]
#[path = "runtime_availability/tests.rs"]
pub(in crate::sumeragi) mod tests;
