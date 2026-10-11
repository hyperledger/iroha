//! The one seam through which SCCP calls Parliament-owned functions (`specs/sccp.md` §10.1,
//! §10.2; `specs/parliament_private_ballot_design.md` §11).
//!
//! SCCP reads nothing else of the Parliament's ballot: it parses no certificate internals and
//! never calls the ballot code directly. Until the Parliament workstream provides the functions,
//! both are documented stubs that fail closed: the binding ballot is unavailable, so the launch
//! gate stays closed, and the attempt latency is unavailable, which is never read as zero.
//!
//! TODO: Parliament workstream (`iroha_core::governance::parliament::sccp_interface`): replace
//! both stubs with calls into that module once it exists.

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
}
