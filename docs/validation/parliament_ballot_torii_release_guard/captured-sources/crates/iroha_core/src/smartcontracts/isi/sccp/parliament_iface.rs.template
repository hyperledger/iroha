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
    pub(super) fn take_rank_three_position(
        &mut self,
        state: &crate::state::StateBlock<'_>,
    ) -> Result<Option<u32>, super::keepalive::DueWorkUnavailable> {
        if self.source != state.world.sccp_reconciliations.publication_identity()
            || self.header != state._curr_block
        {
            return Err(super::keepalive::DueWorkUnavailable);
        }
        if self.remaining == 0 && self.next_position != 0 {
            return Ok(None);
        }
        let position = self.next_position;
        self.next_position = position
            .checked_add(1)
            .ok_or(super::keepalive::DueWorkUnavailable)?;
        self.remaining = self.remaining.saturating_sub(1);
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

/// The original pass after G2b/G2c and all Parliament enactments. Its budget is
/// inherited from the same owner; SCCP cannot create a replacement cursor.
pub(crate) struct SccpG3Prefix {
    source: mv::BlockPublicationIdentity,
    header: iroha_data_model::block::BlockHeader,
    remaining: u32,
    next_position: u32,
}
impl SccpG3Prefix {
    pub(super) fn take_enactment_position(
        &mut self,
        state: &crate::state::StateBlock<'_>,
    ) -> Result<Option<u32>, super::keepalive::DueWorkUnavailable> {
        if self.source != state.world.sccp_reconciliations.publication_identity()
            || self.header != state._curr_block
        {
            return Err(super::keepalive::DueWorkUnavailable);
        }
        if self.remaining < 4 && self.next_position != 0 {
            return Ok(None);
        }
        let position = self.next_position;
        self.next_position = position
            .checked_add(1)
            .ok_or(super::keepalive::DueWorkUnavailable)?;
        self.remaining = self.remaining.saturating_sub(4);
        Ok(Some(position))
    }
}
/// TODO: the Parliament owner must carry the original remaining budget through all
/// intervening phases and issue this continuation after its last due enactment.
pub(crate) fn with_sccp_g3_prefix<E: std::fmt::Debug>(
    _: &mut crate::state::StateBlock<'_>,
    _: impl FnOnce(
        &mut crate::state::StateBlock<'_>,
        &mut SccpG3Prefix,
    ) -> Result<(), crate::state::StateBlockStartError<E>>,
) -> Result<(), crate::state::StateBlockStartError<E>> {
    Err(
        crate::state::StateBlockStartError::GovernanceDueUnavailable(
            super::keepalive::DueWorkUnavailable,
        ),
    )
}

/// Borrowed original parent draw. The external owner enforces the 8 MiB / 65,536
/// citizen ceiling and samples without replacement; fields cannot be asserted by callers.
pub(super) struct PauseDraw<'a, 'world> {
    source: &'a crate::state::WorldBlock<'world>,
    pulse_id: [u8; 32],
    sequence: u64,
    seed: [u8; 32],
    pub(super) members: [Option<&'a iroha_data_model::account::AccountId>; 27],
    pub(super) count: usize,
    pub(super) unavailable:
        Option<iroha_data_model::sccp::events::SccpPausePanelUnavailableReasonV1>,
}
impl<'world> PauseDraw<'_, 'world> {
    pub(super) fn matches(
        &self,
        world: &crate::state::WorldBlock<'world>,
        pulse: [u8; 32],
        sequence: u64,
        seed: [u8; 32],
    ) -> bool {
        core::ptr::eq(self.source, world)
            && self.pulse_id == pulse
            && self.sequence == sequence
            && self.seed == seed
    }
}
/// TODO: supply the Parliament-owned canonical parent citizen snapshot and existing draw.
/// Unavailable dependency is a governance-local wait, not an empty candidate population.
pub(super) fn pause_draw<'a, 'world>(
    _: &'a crate::state::WorldBlock<'world>,
    _: [u8; 32],
    _: u64,
    _: [u8; 32],
    _: usize,
) -> Result<PauseDraw<'a, 'world>, super::keepalive::DueWorkUnavailable> {
    Err(super::keepalive::DueWorkUnavailable)
}

/// Eligibility for exactly one borrowed World, panel graph and observation time.
/// Only the external Parliament owner may issue it; no DATA constructor exists.
pub(super) struct PauseEligibility<'a, W: crate::state::WorldReadOnly + ?Sized> {
    world: &'a W,
    panel: &'a super::pause_record::PausePanelBody,
    time: u64,
    members: u32,
}
impl<W: crate::state::WorldReadOnly + ?Sized> PauseEligibility<'_, W> {
    pub(super) fn for_original(
        &self,
        world: &W,
        panel: &super::pause_record::PausePanelBody,
        time: u64,
    ) -> Result<u32, super::Error> {
        if !core::ptr::eq(self.world, world)
            || !core::ptr::eq(self.panel, panel)
            || time != self.time
        {
            return Err(super::Error::InvariantViolation(
                "SCCP eligibility observation changed source".into(),
            ));
        }
        Ok(self.members)
    }
}
/// Read citizenship, bond, slash, suspension and active-account eligibility at the exact
/// observation. TODO: connect the Parliament-owned eligible-citizen producer once landed.
pub(super) fn pause_eligibility<'a, W: crate::state::WorldReadOnly + ?Sized>(
    _: &'a W,
    _: &'a super::pause_record::PausePanelBody,
    _: u64,
) -> Result<PauseEligibility<'a, W>, super::Error> {
    Err(super::Error::InvariantViolation(
        "SCCP Parliament citizen eligibility is unavailable".into(),
    ))
}

/// Approving Policy Jury opening, bound to the original effect transaction and certificate.
pub(super) struct PolicyJuryOpening<'a, 'block, 'state> {
    source: &'a crate::state::StateTransaction<'block, 'state>,
    header: iroha_data_model::block::BlockHeader,
    certificate: [u8; 32],
    effect: [u8; 32],
    anchor: iroha_data_model::governance::GovernanceAnchorV1,
}
impl<'block, 'state> PolicyJuryOpening<'_, 'block, 'state> {
    pub(super) fn for_original(
        &self,
        state: &crate::state::StateTransaction<'block, 'state>,
        cause: super::controls::ControlCauseV1,
    ) -> Result<iroha_data_model::governance::GovernanceAnchorV1, super::Error> {
        if !core::ptr::eq(self.source, state)
            || self.header != state._curr_block
            || self.certificate != cause.certificate_id
            || self.effect != cause.effect_hash
        {
            return Err(super::Error::InvariantViolation(
                "SCCP Policy Jury opening changed source".into(),
            ));
        }
        Ok(self.anchor)
    }
}
/// TODO: Parliament must supply the actual Policy Jury casting-open anchor of this
/// certificate. Its timestamp, metadata or a caller-supplied anchor cannot substitute it.
pub(super) fn policy_jury_casting_open<'a, 'block, 'state>(
    _: &'a crate::state::StateTransaction<'block, 'state>,
    _: super::controls::ControlCauseV1,
) -> Result<PolicyJuryOpening<'a, 'block, 'state>, super::Error> {
    Err(super::Error::InvariantViolation(
        "SCCP Policy Jury casting-open source is unavailable".into(),
    ))
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

    #[test]
    fn unavailable_pause_authorities_never_supply_an_empty_draw_or_a_fresh_pass() {
        use crate::smartcontracts::isi::sccp::test_support::{
            blank_state, header, sample_pause_panel,
        };
        let state = blank_state();
        let mut block = state.block(header(2));
        assert!(pause_draw(&block.world, [1; 32], 1, [2; 32], 9).is_err());
        let panel = super::super::pause_record::RetainedSccpPausePanel::admit(
            &sample_pause_panel(1),
            &state.ivm_execution_budget(),
        )
        .unwrap();
        assert!(pause_eligibility(&block.world, &panel, 8000).is_err());
        let result = with_sccp_g3_prefix::<()>(&mut block, |_, _| {
            panic!("absent original Parliament continuation cannot enact a fast pause")
        });
        assert!(matches!(
            result,
            Err(crate::state::StateBlockStartError::GovernanceDueUnavailable(_))
        ));
    }
}
