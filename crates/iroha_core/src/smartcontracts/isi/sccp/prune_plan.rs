//! Allocation-free native retention and destination-progress selection (§4.8, §4.11).
//!
//! These read-only plans authenticate no source and grant no deletion authority. The caller
//! must supply the committed pending-forgery source and original admitted storage owners.

use iroha_data_model::sccp::committee::SccpCommitteeGenerationV1;

/// Maximum generation deletions in one post-execution pass (§4.11).
pub const MAX_GENERATION_DELETIONS: usize = 8;
/// Maximum completed anchor-root deletions in one post-execution pass (§4.11).
pub const MAX_ANCHOR_DELETIONS: usize = 8;
/// Maximum ended, uncleared generations visited by L5 in one pass (§4.8).
pub const MAX_CLEARANCE_VISITS: usize = 64;
/// Number of parent consensus anchors in one completed chunk (§4.2.1).
pub const ANCHORS_PER_CHUNK: u128 = 4_096;

/// Fixed stack storage for an ascending bounded selection, never deletion authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection<const N: usize> {
    ids: [u64; N],
    len: usize,
}

impl<const N: usize> Selection<N> {
    fn new() -> Self {
        Self {
            ids: [0; N],
            len: 0,
        }
    }
    fn push(&mut self, id: u64) {
        self.ids[self.len] = id;
        self.len += 1;
    }
    /// Borrow only the selected identifiers, in original ascending order.
    pub fn as_slice(&self) -> &[u64] {
        &self.ids[..self.len]
    }
}

/// The committed forgery source's answer for one candidate generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingForgery {
    /// A complete original source establishes no pending penalty for this generation.
    Clear,
    /// At least one recorded penalty for this generation is still pending.
    Pending,
    /// The original source is unavailable; absence cannot be inferred.
    Unavailable,
}

/// Missing custody or malformed ordering prevents a complete native selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    /// The caller did not establish the pending-forgery predicate.
    PendingForgeryUnavailable,
    /// The supplied native records are not strictly ascending.
    NonAscending,
}

/// Select at most eight old, no-longer-liable generations with no pending penalty.
/// Gaps and an earlier still-liable generation never hide a later eligible record.
///
/// # Errors
/// Refuses non-ascending input or a candidate without its original pending-forgery answer.
pub fn generations<'a>(
    records: impl IntoIterator<Item = &'a SccpCommitteeGenerationV1>,
    current_generation: u64,
    liability_clock: u64,
    mut pending: impl FnMut(u64) -> PendingForgery,
) -> Result<Selection<MAX_GENERATION_DELETIONS>, SelectionError> {
    let mut selected = Selection::new();
    let mut previous = None;
    for record in records {
        if previous.is_some_and(|previous| previous >= record.generation) {
            return Err(SelectionError::NonAscending);
        }
        previous = Some(record.generation);
        if record.generation >= current_generation
            || record.liable_at(current_generation, liability_clock)
        {
            continue;
        }
        match pending(record.generation) {
            PendingForgery::Clear => selected.push(record.generation),
            PendingForgery::Pending => continue,
            PendingForgery::Unavailable => return Err(SelectionError::PendingForgeryUnavailable),
        }
        if selected.len == MAX_GENERATION_DELETIONS {
            break;
        }
    }
    Ok(selected)
}

/// Select at most eight completed chunk roots wholly before every retained generation.
/// Missing retained-generation context retains everything; the open chunk is always excluded.
/// Arithmetic is widened so a forged large index cannot wrap into an old chunk.
///
/// # Errors
/// Refuses non-ascending chunk indices.
pub fn anchors(
    chunk_indices: impl IntoIterator<Item = u64>,
    minimum_retained_start_height: Option<u64>,
    open_chunk_index: u64,
) -> Result<Selection<MAX_ANCHOR_DELETIONS>, SelectionError> {
    let mut selected = Selection::new();
    let Some(minimum) = minimum_retained_start_height else {
        return Ok(selected);
    };
    let mut previous = None;
    for chunk in chunk_indices {
        if previous.is_some_and(|previous| previous >= chunk) {
            return Err(SelectionError::NonAscending);
        }
        previous = Some(chunk);
        let last_height = (u128::from(chunk) + 1) * ANCHORS_PER_CHUNK;
        if chunk < open_chunk_index && last_height < u128::from(minimum) {
            selected.push(chunk);
            if selected.len == MAX_ANCHOR_DELETIONS {
                break;
            }
        }
    }
    Ok(selected)
}

/// One external network's replicated L5 progress input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationProgress {
    /// This network has no non-Retired route revision.
    Irrelevant,
    /// A relevant network has no active inbound light client.
    Unavailable,
    /// Finalized source time read from the active inbound light-client head.
    Finalized(u64),
}

/// Select clearances among only the first 64 ended, uncleared generations.
/// A blocked record consumes one visit; progress must be strictly past every deadline.
/// No relevant network makes clearance immediate, without inventing a finalized checkpoint.
///
/// # Errors
/// Refuses non-ascending input.
pub fn clearances<'a>(
    records: impl IntoIterator<Item = &'a SccpCommitteeGenerationV1>,
    progress: &[DestinationProgress; 3],
) -> Result<Selection<MAX_CLEARANCE_VISITS>, SelectionError> {
    let mut selected = Selection::new();
    let mut previous = None;
    let mut visited = 0;
    for record in records {
        if previous.is_some_and(|previous| previous >= record.generation) {
            return Err(SelectionError::NonAscending);
        }
        previous = Some(record.generation);
        if record.end.is_none() || record.dest_cleared_lc.is_some() {
            continue;
        }
        visited += 1;
        if progress.iter().all(|network| match network {
            DestinationProgress::Irrelevant => true,
            DestinationProgress::Unavailable => false,
            DestinationProgress::Finalized(time) => *time > record.deadline_ms,
        }) {
            selected.push(record.generation);
        }
        if visited == MAX_CLEARANCE_VISITS {
            break;
        }
    }
    Ok(selected)
}

#[cfg(test)]
#[path = "prune_plan/tests.rs"]
mod tests;
