//! Canonical result projection with derivable successor epochs omitted from the wire.

use super::{
    ChainParamsRecord, ExecutionCommitment, ExecutionResultCommitment,
    FinalizedGlobalThresholdBeaconPulseV1, NativeLaneStateProof, ScheduleOutcome,
};
use crate::{
    sumeragi::epoch::{
        ValidatorCommitteeMemberV1, ValidatorEpochBoundaryV1, ValidatorEpochContextV1,
    },
    sumeragi_finality::{ScheduledConfig, ScheduledSlot},
};
use norito::{Archived, DeserializePayload, SerializePayload};

// The same generic projection owns decoding/schema and borrows encoding. Borrowed delegates
// the exact payload of its referent, so counting and streaming never clone credentials.
#[derive(SerializePayload, DeserializePayload, iroha_schema::IntoSchema)]
pub(super) struct ResultWire<E, S, B, L> {
    height: u64,
    execution: E,
    schedule: S,
    beacon: B,
    native_lanes: L,
}

#[derive(SerializePayload, DeserializePayload, iroha_schema::IntoSchema)]
pub(super) struct ScheduleWire<C, B> {
    height: u64,
    current: C,
    boundary: B,
    next: SlotWire,
    after_next: SlotWire,
}

#[derive(Clone, Copy, SerializePayload, DeserializePayload, iroha_schema::IntoSchema)]
enum SlotWire {
    Ready {
        height: u64,
        params: ChainParamsRecord,
    },
    PendingBoundary {
        height: u64,
        boundary_height: u64,
        predecessor_context_id: [u8; 32],
        params: ChainParamsRecord,
    },
}

pub(super) type OwnedResult = ResultWire<
    ExecutionCommitment,
    ScheduleWire<ValidatorEpochContextV1, Option<ValidatorEpochBoundaryV1>>,
    Option<FinalizedGlobalThresholdBeaconPulseV1>,
    NativeLaneStateProof,
>;

struct Borrowed<'a, T>(&'a T);

impl<T: SerializePayload> SerializePayload for Borrowed<'_, T> {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.0.serialize(encoder)
    }
}

impl SlotWire {
    fn project(
        slot: &ScheduledSlot,
        authorized: &ValidatorEpochContextV1,
    ) -> Result<Self, norito::Error> {
        Ok(match slot {
            ScheduledSlot::Ready(config) => {
                // Never normalize a contradictory graph into an apparently valid result.
                // This is an allocation-free equality check, not a second crypto validator.
                if &config.epoch != authorized {
                    return Err(norito::Error::NonCanonicalEncoding);
                }
                Self::Ready {
                    height: config.height,
                    params: config.params,
                }
            }
            ScheduledSlot::PendingBoundary {
                height,
                boundary_height,
                predecessor_context_id,
                params,
            } => Self::PendingBoundary {
                height: *height,
                boundary_height: *boundary_height,
                predecessor_context_id: *predecessor_context_id,
                params: *params,
            },
        })
    }

    fn expand(self, authorized: &ValidatorEpochContextV1) -> Result<ScheduledSlot, norito::Error> {
        Ok(match self {
            Self::Ready { height, params } => {
                // Cloning owns real Vec/key/PoP buffers. Charge every byte before allocating,
                // preserving all outer decode counters even when a second slot is refused.
                norito::core::reserve_decode_allocation(epoch_clone_bytes(authorized)?)?;
                ScheduledSlot::Ready(ScheduledConfig {
                    height,
                    epoch: authorized.clone(),
                    params,
                })
            }
            Self::PendingBoundary {
                height,
                boundary_height,
                predecessor_context_id,
                params,
            } => ScheduledSlot::PendingBoundary {
                height,
                boundary_height,
                predecessor_context_id,
                params,
            },
        })
    }
}

/// Exact additional owned storage created by one epoch clone. Exhaustive destructuring makes
/// a future epoch/credential field addition require an explicit allocation-accounting review.
fn epoch_clone_bytes(epoch: &ValidatorEpochContextV1) -> Result<usize, norito::Error> {
    let ValidatorEpochContextV1 {
        da_layout: _,
        version: _,
        network_id: _,
        mode: _,
        authorization: _,
        committee,
        leader_seed: _,
    } = epoch;
    let mut bytes = committee
        .len()
        .checked_mul(core::mem::size_of::<ValidatorCommitteeMemberV1>())
        .ok_or(norito::Error::LengthMismatch)?;
    for ValidatorCommitteeMemberV1 {
        validator,
        proof_of_possession,
    } in committee
    {
        bytes = bytes
            .checked_add(validator.public_key().retained_allocation_layout().size())
            .and_then(|bytes| bytes.checked_add(proof_of_possession.len()))
            .ok_or(norito::Error::LengthMismatch)?;
    }
    Ok(bytes)
}

impl SerializePayload for ExecutionResultCommitment {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        let authorized = self
            .schedule
            .boundary
            .as_ref()
            .map_or(&self.schedule.current, |boundary| &boundary.next);
        let schedule = ScheduleWire {
            height: self.schedule.height,
            current: Borrowed(&self.schedule.current),
            boundary: Borrowed(&self.schedule.boundary),
            next: SlotWire::project(&self.schedule.next, authorized)?,
            after_next: SlotWire::project(&self.schedule.after_next, authorized)?,
        };
        ResultWire {
            height: self.height,
            execution: Borrowed(&self.execution),
            schedule,
            beacon: Borrowed(&self.beacon),
            native_lanes: Borrowed(&self.native_lanes),
        }
        .serialize(encoder)
    }
}

impl<'de> DeserializePayload<'de> for ExecutionResultCommitment {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical execution result")
    }

    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, norito::Error> {
        let wire = OwnedResult::try_deserialize(archived.cast())?;
        let authorized = wire
            .schedule
            .boundary
            .as_ref()
            .map_or(&wire.schedule.current, |boundary| &boundary.next);
        let next = wire.schedule.next.expand(authorized)?;
        let after_next = wire.schedule.after_next.expand(authorized)?;
        Ok(Self {
            height: wire.height,
            execution: wire.execution,
            schedule: ScheduleOutcome {
                height: wire.schedule.height,
                current: wire.schedule.current,
                boundary: wire.schedule.boundary,
                next,
                after_next,
            },
            beacon: wire.beacon,
            native_lanes: wire.native_lanes,
        })
    }
}

#[cfg(test)]
mod tests;
