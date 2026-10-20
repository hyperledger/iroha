//! Reconstruct both proof-status images from the original canonical history.
//!
//! TODO: admit reconstruction scratch through the original snapshot resource
//! owner together with the remaining infallible derived-index reconstruction.

use super::{World, ownership_index_restore};

/// Preserve predecessor memberships and redundant source touches.
pub(super) fn rebuild(world: &mut World) {
    let by_status =
        ownership_index_restore::members(&world.proofs.history(), |_, record| Some(record.status));
    world.proofs_by_status = by_status;
}

#[cfg(test)]
mod tests;
