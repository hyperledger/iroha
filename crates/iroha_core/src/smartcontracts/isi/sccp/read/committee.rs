//! Allocation-preserving projections of committed SCCP generation discovery metadata.

use super::{SccpReadError, store};
use crate::{
    smartcontracts::isi::sccp::generation_record::RetainedSccpGeneration, state::WorldReadOnly,
};
use iroha_data_model::sccp::generation::{
    SccpGenerationCauseV1, SccpGenerationEndV1, SccpGenerationMemberV1,
};
use iroha_sccp::api::SccpGenerationV1;
use norito::core::{Encoder, PayloadRef, SerializePayload};
use norito::json::{self, JsonSerialize};

/// Immutable response sharing the source's original funded key/member allocations.
/// Serialization borrows the graph; decoding a wire record cannot create this owner.
#[derive(Debug)]
pub struct RetainedSccpGenerationView {
    generation: RetainedSccpGeneration,
    liable: bool,
}
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct View<'a> {
    generation: u64,
    committee_root: [u8; 32],
    keys: PayloadRef<'a, Vec<[u8; 48]>>,
    members: PayloadRef<'a, Vec<Option<SccpGenerationMemberV1>>>,
    cause: SccpGenerationCauseV1,
    start_height: u64,
    start_timestamp_ms: u64,
    start_lc: u64,
    validity_ms: u64,
    deadline_ms: u64,
    grace_ms: u64,
    progress_cap_ms: u64,
    liable_until_lc: u64,
    dest_cleared_lc: Option<u64>,
    end: Option<SccpGenerationEndV1>,
    liable: bool,
}
impl RetainedSccpGenerationView {
    fn view(&self) -> View<'_> {
        View {
            generation: self.generation.generation,
            committee_root: self.generation.committee_root,
            keys: PayloadRef(&self.generation.keys),
            members: PayloadRef(&self.generation.members),
            cause: self.generation.cause,
            start_height: self.generation.start_height,
            start_timestamp_ms: self.generation.start_timestamp_ms,
            start_lc: self.generation.start_lc,
            validity_ms: self.generation.validity_ms,
            deadline_ms: self.generation.deadline_ms,
            grace_ms: self.generation.grace_ms,
            progress_cap_ms: self.generation.progress_cap_ms,
            liable_until_lc: self.generation.liable_until_lc,
            dest_cleared_lc: self.generation.dest_cleared_lc,
            end: self.generation.end,
            liable: self.liable,
        }
    }
}
impl norito::NoritoSchema for RetainedSccpGenerationView {
    fn nominal_name() -> String {
        <SccpGenerationV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <SccpGenerationV1 as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedSccpGenerationView {
    fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.view().serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.view().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.view().encoded_len_exact()
    }
}
impl JsonSerialize for RetainedSccpGenerationView {
    fn json_serialize(&self, out: &mut String) {
        self.view().json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.view().json_serialize_to(out)
    }
}

/// Read a retained generation without cloning its original key/account graph.
///
/// # Errors
/// Rejects zero, absent, and pruned generations distinctly.
pub fn committee(
    world: &(impl WorldReadOnly + ?Sized),
    generation: u64,
) -> Result<RetainedSccpGenerationView, SccpReadError> {
    if generation == 0 {
        return Err(SccpReadError::Invalid("generation must be positive".into()));
    }
    let current = *store::committee_current::get(world);
    let record = store::committee_generations::get(world, &generation).ok_or_else(|| {
        if generation < current {
            SccpReadError::Pruned("committee generation".into())
        } else {
            SccpReadError::NotFound("committee generation".into())
        }
    })?;
    Ok(RetainedSccpGenerationView {
        generation: record.clone(),
        liable: record.is_liable(current, *store::liability_clock::get(world)),
    })
}

/// Read the generation selected by the same committed World view.
///
/// # Errors
/// Returns not found before initialization or when the selected record is absent.
pub fn current_committee(
    world: &(impl WorldReadOnly + ?Sized),
) -> Result<RetainedSccpGenerationView, SccpReadError> {
    let current = *store::committee_current::get(world);
    if current == 0 {
        return Err(SccpReadError::NotFound("current committee".into()));
    }
    committee(world, current)
}

#[cfg(test)]
mod tests;
