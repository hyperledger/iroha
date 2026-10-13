//! The one seam through which SCCP calls Parliament-owned functions (`specs/sccp.md` §10.1,
//! §10.2; `specs/parliament_private_ballot_design.md` §11).
//!
//! SCCP reads nothing else of the Parliament's ballot: it parses no certificate internals and
//! never calls the ballot code directly. Until the Parliament workstream provides the functions,
//! they fail closed: the binding ballot and positioned pass are unavailable, so the launch
//! gate stays closed. Unavailable latency is never read as zero or due work as empty.
//!
//! TODO: Parliament workstream (`iroha_core::governance::parliament::sccp_interface`): replace
//! these seams with calls into that module once it exists.

/// Return whether the qualified post-quantum binding ballot is active on the chain (§10.2).
///
/// While it is false the SCCP launch gate is closed: no route is registered and the genesis
/// parameters hold, with no interim governance.
///
/// TODO: Parliament workstream (`iroha_core::governance::parliament::sccp_interface`): the
/// stub returns `false` until the ballot profile is qualified and active.
#[must_use]
pub const fn parliament_binding_ballot_available() -> bool {
    false
}

/// Return the worst-case latency of one full-track SCCP Parliament attempt to a terminal
/// outcome, in milliseconds, or `None` while no qualified bound exists (§4.1, §10.1).
///
/// `None` never means zero: the lower bound of `fast_pause_hold_ms` is deferred, not met.
///
/// TODO: Parliament workstream (`iroha_core::governance::parliament::sccp_interface`): the
/// stub returns `None` until the committed ballot windows give a qualified bound.
#[must_use]
pub const fn parliament_sccp_attempt_latency_ms() -> Option<u64> {
    None
}

/// Observe the original parent's G1–G3 due-work set at a candidate height and time.
/// # Errors
/// TODO: Parliament must supply its deterministic bounded due iterator and carried-pulse
/// relation. Until then, unavailability is never interpreted as an empty due-work set.
pub(crate) fn governance_due(_: u64, _: u64) -> Result<bool, super::keepalive::DueWorkUnavailable> {
    Err(super::keepalive::DueWorkUnavailable)
}

/// Source-bound prefix of the one shared G1/G2a pass, before SCCP rank-three work.
/// No public constructor can assert that external work was empty or supply a fresh budget.
pub(crate) struct SccpG2aPrefix {
    source: mv::BlockPublicationIdentity,
    header: iroha_data_model::block::BlockHeader,
    remaining: u32,
    next_position: u32,
}

impl SccpG2aPrefix {
    /// Consume one cost-one position only in the same original block and remaining budget.
    pub(super) fn take_reconciliation_position(
        &mut self,
        state: &crate::state::StateBlock<'_>,
    ) -> Result<Option<u32>, super::keepalive::DueWorkUnavailable> {
        if self.source != state.world.sccp_reconciliations.publication_identity()
            || self.header != state._curr_block
        {
            return Err(super::keepalive::DueWorkUnavailable);
        }
        if self.remaining == 0 {
            return Ok(None);
        }
        let position = self.next_position;
        self.next_position = position
            .checked_add(1)
            .ok_or(super::keepalive::DueWorkUnavailable)?;
        self.remaining -= 1;
        Ok(Some(position))
    }
}

/// Execute the SCCP segment only after the same original owner completed the external prefix.
/// # Errors
/// TODO: Parliament's positioned G1/G2a owner must issue the source-bound remaining budget,
/// merge equal-rank due keys, and consume the resulting cursor before G2b/G3. Until that
/// owner exists this returns unavailability, even if external state appears empty.
pub(crate) fn with_sccp_g2a_prefix<E: std::fmt::Debug>(
    _: &mut crate::state::StateBlock<'_>,
    _: impl FnOnce(
        &mut crate::state::StateBlock<'_>,
        &mut SccpG2aPrefix,
    ) -> Result<(), crate::state::StateBlockStartError<E>>,
) -> Result<(), crate::state::StateBlockStartError<E>> {
    Err(
        crate::state::StateBlockStartError::GovernanceDueUnavailable(
            super::keepalive::DueWorkUnavailable,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binding_ballot_is_unavailable_until_the_parliament_provides_it() {
        assert!(!parliament_binding_ballot_available());
    }

    #[test]
    fn the_attempt_latency_is_unavailable_and_never_zero() {
        assert_eq!(parliament_sccp_attempt_latency_ms(), None);
    }

    #[test]
    fn an_absent_due_owner_never_asserts_an_empty_set() {
        for (height, time) in [(1, 0), (2, 1_000), (u64::MAX, u64::MAX)] {
            assert_eq!(
                governance_due(height, time),
                Err(super::super::keepalive::DueWorkUnavailable)
            );
        }
    }

    #[test]
    fn an_unavailable_shared_prefix_never_runs_reconciliation_work() {
        use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};
        let state = blank_state();
        let mut block = state.block(header(2));
        let result = with_sccp_g2a_prefix::<()>(&mut block, |_, _| {
            panic!("an absent Parliament prefix must not issue reconciliation budget")
        });
        assert!(matches!(
            result,
            Err(crate::state::StateBlockStartError::GovernanceDueUnavailable(_))
        ));
    }
}
