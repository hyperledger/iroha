//! The height-progress ticket of the governance block-start pass (lifecycle decision E).
//!
//! An admitted Parliament sortition request waits for the native pulse of its frozen exact
//! slot. On an idle chain, carriers must still advance the height towards that slot: each
//! pass derives at most one [`AdvanceToNativeSlotV1`] ticket from the original parent and,
//! when it is due, consumes it as G1's first positioned item (cost one). The ticket is
//! derived, never stored as an independently mutable singleton, so it has no codec here.
//!
//! ```text
//! target_height = minimum unresolved requested slot > parent.height
//! cursor_height = parent.height
//! ticket_height = parent.height + 1
//! due_ms        = parent.timestamp_ms + committed_block_cadence_ms   (checked)
//! ```
//!
//! The ticket includes the final step to the target (`cursor_height < h <= target_height`);
//! consuming it advances the cursor exactly one height. At the target the request produces
//! no further ticket, even if its pulse is missing; another admitted future request may
//! supply the next one. All requests through the nearest target coalesce into one ticket,
//! whose target is immutable; a successor ticket may choose a newly nearer request. No
//! request's frozen slot changes.
//!
//! TODO: the Core integration derives the ticket in the unified due-item iterator (G1,
//! `governance_due`, the keeper's `next_governance_progress_at_ms` and the read-only
//! `/schedule` projection) and records its consumption in the `NativeSlotAdvanced` receipt,
//! whose committed form is defined with that receipt.

/// Why a height-progress ticket is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdvanceToNativeSlotErrorV1 {
    /// The ticket height is not the height after the cursor.
    #[error("the ticket height must be the cursor height plus one")]
    NotNextHeight,
    /// The ticket height is beyond the target.
    #[error("the ticket height must not exceed the target height")]
    BeyondTarget,
}

/// The one height-progress ticket of a pass, derived from the original parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdvanceToNativeSlotV1 {
    /// The nearest unresolved requested native slot above the parent height; immutable for
    /// this ticket.
    pub target_height: u64,
    /// The parent height.
    pub cursor_height: u64,
    /// The height the ticket advances to: the parent height plus one.
    pub ticket_height: u64,
}

impl AdvanceToNativeSlotV1 {
    /// The ticket of the pass of block `parent_height + 1` towards the nearest unresolved
    /// requested slot `nearest_requested_slot`, or `None` when that slot is not above the
    /// parent (no request is waiting for a later height) or the next height overflows.
    #[must_use]
    pub fn derive_v1(parent_height: u64, nearest_requested_slot: u64) -> Option<Self> {
        if nearest_requested_slot <= parent_height {
            return None;
        }
        Some(Self {
            target_height: nearest_requested_slot,
            cursor_height: parent_height,
            ticket_height: parent_height.checked_add(1)?,
        })
    }

    /// Check `cursor_height < ticket_height <= target_height` with
    /// `ticket_height = cursor_height + 1`.
    ///
    /// # Errors
    /// The [`AdvanceToNativeSlotErrorV1`] of the violated rule.
    pub fn validate(&self) -> Result<(), AdvanceToNativeSlotErrorV1> {
        if self.cursor_height.checked_add(1) != Some(self.ticket_height) {
            return Err(AdvanceToNativeSlotErrorV1::NotNextHeight);
        }
        if self.ticket_height > self.target_height {
            return Err(AdvanceToNativeSlotErrorV1::BeyondTarget);
        }
        Ok(())
    }

    /// Whether consuming the ticket reaches the target: the final advancing step, after
    /// which this request supplies no further ticket.
    #[must_use]
    pub const fn reaches_target(&self) -> bool {
        self.ticket_height == self.target_height
    }

    /// When a ticket derived from a parent of time `parent_timestamp_ms` is due:
    /// `parent_timestamp_ms + block_cadence_ms`, or `None` on overflow.
    #[must_use]
    pub const fn due_ms(parent_timestamp_ms: u64, block_cadence_ms: u64) -> Option<u64> {
        parent_timestamp_ms.checked_add(block_cadence_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_advances_one_height_towards_the_nearest_slot() {
        let ticket = AdvanceToNativeSlotV1::derive_v1(100, 103).expect("waiting request");
        assert_eq!(
            ticket,
            AdvanceToNativeSlotV1 {
                target_height: 103,
                cursor_height: 100,
                ticket_height: 101,
            }
        );
        assert_eq!(ticket.validate(), Ok(()));
        assert!(!ticket.reaches_target());
        // The final step reaches the target and is still a ticket.
        let last = AdvanceToNativeSlotV1::derive_v1(102, 103).expect("final step");
        assert_eq!(last.validate(), Ok(()));
        assert!(last.reaches_target());
        // At or past the slot there is no ticket, whether or not its pulse arrived.
        assert_eq!(AdvanceToNativeSlotV1::derive_v1(103, 103), None);
        assert_eq!(AdvanceToNativeSlotV1::derive_v1(104, 103), None);
        assert_eq!(AdvanceToNativeSlotV1::derive_v1(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn malformed_tickets_are_refused_and_due_times_are_checked() {
        let ticket = AdvanceToNativeSlotV1::derive_v1(100, 103).expect("ticket");
        let mut skipping = ticket;
        skipping.ticket_height = 102;
        assert_eq!(
            skipping.validate(),
            Err(AdvanceToNativeSlotErrorV1::NotNextHeight)
        );
        let mut overflowing = ticket;
        overflowing.cursor_height = u64::MAX;
        assert_eq!(
            overflowing.validate(),
            Err(AdvanceToNativeSlotErrorV1::NotNextHeight)
        );
        let mut beyond = ticket;
        beyond.target_height = 100;
        assert_eq!(
            beyond.validate(),
            Err(AdvanceToNativeSlotErrorV1::BeyondTarget)
        );
        assert_eq!(
            AdvanceToNativeSlotV1::due_ms(1_000_000, 1_000),
            Some(1_001_000)
        );
        assert_eq!(AdvanceToNativeSlotV1::due_ms(u64::MAX, 1), None);
        assert!(
            !AdvanceToNativeSlotErrorV1::BeyondTarget
                .to_string()
                .is_empty()
        );
    }
}
