//! Allocation-free G2/G4/G5/G7 transition decisions over original execution facts.
//!
//! These values are not authorities. The production writer supplies roots and times from
//! its retained native schedule and execution tip, then funds every resulting owner before
//! publishing. Local resource refusal is deliberately outside this deterministic planner.

use iroha_data_model::sccp::{
    committee::{SccpGenerationCauseV1, SccpGenerationEndV1, SccpGenerationStartV1},
    events::SccpFinalityDegradedReasonV1 as Degraded,
};

/// One hour of liability-clock slack after a chain halt (§3.9, §4.8).
pub(super) const SCCP_LC_SLACK_MS: u64 = 3_600_000;

/// Fixed projection of the original open generation; no key/member graph is copied.
#[derive(Clone, Copy, Debug)]
pub(super) struct CurrentGeneration {
    pub generation: u64,
    pub committee_root: [u8; 32],
    pub start_height: u64,
    pub start_timestamp_ms: u64,
    pub start_lc: u64,
    pub ended: bool,
}

/// Original current and authorized successor roots, already checked against height/mode.
#[derive(Clone, Copy, Debug)]
pub(super) struct HeightFacts {
    pub height: u64,
    pub timestamp_ms: u64,
    pub liability_clock: u64,
    pub committee_root: [u8; 32],
    pub next_committee_root: [u8; 32],
    pub boundary: bool,
    pub parent: Option<(u64, u64)>,
    pub heartbeat_ms: u64,
    pub validity_ms: u64,
}

/// One immutable close/create pair. A resync and a rotation can both occur at one height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Change {
    pub end: SccpGenerationEndV1,
    pub start: SccpGenerationStartV1,
}

/// Signing generation is selected after resync and before the optional rotation (G5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GenerationPlan {
    pub resync: Option<Change>,
    pub rotation: Option<Change>,
    pub signing_generation: u64,
}

/// Determine G2/G7 exactly, leaving existing generation deadlines unchanged.
pub(super) fn plan(
    current: CurrentGeneration,
    facts: HeightFacts,
) -> Result<GenerationPlan, Degraded> {
    if current.generation == 0
        || current.start_height == 0
        || current.start_height > facts.height
        || current.start_timestamp_ms > facts.timestamp_ms
        || current.start_lc > facts.liability_clock
        || facts.liability_clock > facts.timestamp_ms
        || current.ended
    {
        return Err(Degraded::InconsistentGenerationState);
    }
    if facts.height == 0
        || facts.heartbeat_ms == 0
        || facts.validity_ms == 0
        || (!facts.boundary && facts.next_committee_root != facts.committee_root)
    {
        return Err(Degraded::InvalidHeightInputs);
    }
    let mut generation = current.generation;
    let mut start_timestamp = current.start_timestamp_ms;
    let resync = if current.committee_root != facts.committee_root {
        let (parent_height, parent_time) = facts.parent.ok_or(Degraded::MissingParentTip)?;
        if parent_height.checked_add(1) != Some(facts.height)
            || parent_height < current.start_height
            || parent_time < current.start_timestamp_ms
            || parent_time > facts.timestamp_ms
        {
            return Err(Degraded::InconsistentGenerationState);
        }
        generation = generation
            .checked_add(1)
            .ok_or(Degraded::ArithmeticOverflow)?;
        start_timestamp = facts.timestamp_ms;
        Some(Change {
            end: SccpGenerationEndV1 {
                end_height: parent_height,
                end_timestamp_ms: parent_time,
                next_committee_root: facts.committee_root,
                successor_validity_ms: facts.validity_ms,
            },
            start: SccpGenerationStartV1 {
                generation,
                cause: SccpGenerationCauseV1::Resync,
                height: facts.height,
                timestamp_ms: facts.timestamp_ms,
                liability_clock: facts.liability_clock,
            },
        })
    } else {
        None
    };
    let signing_generation = generation;
    let key_change = facts.boundary && facts.next_committee_root != facts.committee_root;
    let heartbeat_at = start_timestamp
        .checked_add(facts.heartbeat_ms)
        .ok_or(Degraded::ArithmeticOverflow)?;
    let rotation = if key_change || facts.timestamp_ms >= heartbeat_at {
        Some(Change {
            end: SccpGenerationEndV1 {
                end_height: facts.height,
                end_timestamp_ms: facts.timestamp_ms,
                next_committee_root: facts.next_committee_root,
                successor_validity_ms: facts.validity_ms,
            },
            start: SccpGenerationStartV1 {
                generation: generation
                    .checked_add(1)
                    .ok_or(Degraded::ArithmeticOverflow)?,
                cause: if key_change {
                    SccpGenerationCauseV1::KeyChange
                } else {
                    SccpGenerationCauseV1::Heartbeat
                },
                height: facts
                    .height
                    .checked_add(1)
                    .ok_or(Degraded::ArithmeticOverflow)?,
                timestamp_ms: facts.timestamp_ms,
                liability_clock: facts.liability_clock,
            },
        })
    } else {
        None
    };
    Ok(GenerationPlan {
        resync,
        rotation,
        signing_generation,
    })
}

/// S0 arithmetic; invalid original coordinates degrade SCCP instead of inventing a clock.
pub(super) fn liability_clock(
    height: u64,
    timestamp_ms: u64,
    parent: Option<(u64, u64)>,
    previous_lc: u64,
    heartbeat_ms: u64,
    slack_ms: u64,
) -> Result<u64, Degraded> {
    if height == 1 {
        return Ok(timestamp_ms);
    }
    let (parent_height, parent_time) = parent.ok_or(Degraded::MissingParentTip)?;
    if height == 0
        || parent_height.checked_add(1) != Some(height)
        || previous_lc > parent_time
        || parent_time > timestamp_ms
    {
        return Err(Degraded::InconsistentGenerationState);
    }
    let cap = heartbeat_ms
        .checked_add(slack_ms)
        .ok_or(Degraded::ArithmeticOverflow)?;
    previous_lc
        .checked_add((timestamp_ms - parent_time).min(cap))
        .ok_or(Degraded::ArithmeticOverflow)
}

#[cfg(test)]
#[path = "generation_plan/tests.rs"]
mod tests;
