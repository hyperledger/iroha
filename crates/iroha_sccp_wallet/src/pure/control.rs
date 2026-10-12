//! Two-track destination pause policy and authenticated control proofs (§5.1.6, §7.1).
//!
//! The higher control nonce wins. Fast pauses expire at destination time; Parliament pauses
//! remain until changed. Every newer committed control must be proven and applied before a
//! finalization. A missing proof is a fetch failure, never permission to skip that control.

use super::bundle::{
    BundleError, CertificateUseV1, DestinationContextV1, VerifiedCertificateV1,
    verify_certificate_bundle,
};
use core::fmt;
use iroha_sccp::{
    api::SccpControlProofBundleV1,
    v1::{
        control::applied_fast_pause_until_ms, destination::ControlProofV1, proof::verify_control,
    },
};

/// Full applied pause state from the selected destination observation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DestinationControlStateV1 {
    /// Last applied nonce; zero before the first control.
    pub control_nonce: u64,
    /// Persistent Parliament flag.
    pub parliament_paused: bool,
    /// Destination-time fast-pause expiry.
    pub fast_pause_until_ms: u64,
}
impl DestinationControlStateV1 {
    /// Effective pause at the given destination time; equality means the fast pause expired.
    #[must_use]
    pub const fn paused_at(&self, now_ms: u64) -> bool {
        self.parliament_paused || now_ms < self.fast_pause_until_ms
    }
}
/// Taira's newest committed control, still an untrusted observation until its proof verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TairaControlV1 {
    /// Strictly increasing destination-control nonce.
    pub control_nonce: u64,
    /// Persistent Parliament flag committed by the control.
    pub parliament_paused: bool,
    /// Fast-pause expiry committed by the control.
    pub fast_pause_until_ms: u64,
}
impl TairaControlV1 {
    /// Effective pause that this control would leave at destination time.
    #[must_use]
    pub const fn paused_at(&self, now_ms: u64) -> bool {
        self.parliament_paused || now_ms < self.fast_pause_until_ms
    }
}
/// Source of the newest nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlSourceV1 {
    /// Destination's applied state is current.
    Destination,
    /// Taira has a newer committed control.
    Taira,
}
/// Newest effective pause, evaluated at the chosen destination time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NewestControlV1 {
    /// Its nonce.
    pub control_nonce: u64,
    /// Whether it currently pauses minting.
    pub paused: bool,
    /// Where the highest nonce was observed.
    pub source: ControlSourceV1,
}
/// Select the higher nonce and evaluate its complete pause state.
#[must_use]
pub fn newest_control(
    destination: &DestinationControlStateV1,
    taira: Option<&TairaControlV1>,
    now_ms: u64,
) -> NewestControlV1 {
    match taira {
        Some(taira) if taira.control_nonce > destination.control_nonce => NewestControlV1 {
            control_nonce: taira.control_nonce,
            paused: taira.paused_at(now_ms),
            source: ControlSourceV1::Taira,
        },
        _ => NewestControlV1 {
            control_nonce: destination.control_nonce,
            paused: destination.paused_at(now_ms),
            source: ControlSourceV1::Destination,
        },
    }
}
/// The newest observed control leaves minting paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NewestControlIsPause {
    /// The control that blocks recording.
    pub newest: NewestControlV1,
}
impl fmt::Display for NewestControlIsPause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the newest destination control (nonce {}) pauses minting",
            self.newest.control_nonce
        )
    }
}
impl std::error::Error for NewestControlIsPause {}
/// Refuse recording while the newest observed control leaves minting paused.
///
/// # Errors
/// Returns `NewestControlIsPause` for an effective Parliament or fast pause.
pub fn check_may_record(
    destination: &DestinationControlStateV1,
    taira: Option<&TairaControlV1>,
    now_ms: u64,
) -> Result<(), NewestControlIsPause> {
    let newest = newest_control(destination, taira, now_ms);
    if newest.paused {
        Err(NewestControlIsPause { newest })
    } else {
        Ok(())
    }
}
/// Required next step before minting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreFinalizeActionV1 {
    /// The applied state is current and allows minting.
    Finalize,
    /// Prove and apply this newer control first; never finalize if obtaining its proof fails.
    ApplyControl {
        /// Nonce of the committed control.
        control_nonce: u64,
        /// Whether it leaves minting paused at the selected destination time.
        paused: bool,
    },
    /// The applied state is current and pauses minting.
    Paused,
}
/// Require the newest control before any finalization, including a recorded resume.
#[must_use]
pub fn plan_before_finalize(
    destination: &DestinationControlStateV1,
    taira: Option<&TairaControlV1>,
    now_ms: u64,
) -> PreFinalizeActionV1 {
    match taira {
        Some(taira) if taira.control_nonce > destination.control_nonce => {
            PreFinalizeActionV1::ApplyControl {
                control_nonce: taira.control_nonce,
                paused: taira.paused_at(now_ms),
            }
        }
        _ if destination.paused_at(now_ms) => PreFinalizeActionV1::Paused,
        _ => PreFinalizeActionV1::Finalize,
    }
}
/// A current control proof cannot be applied to the selected destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlBundleError {
    /// Its target network or revision differs from the destination's.
    WrongDeployment,
    /// Certificate or inclusion verification failed.
    Bundle(BundleError),
    /// Its nonce is not above the applied nonce.
    Stale,
}
impl fmt::Display for ControlBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongDeployment => {
                f.write_str("control bundle targets another network or revision")
            }
            Self::Bundle(e) => write!(f, "control bundle: {e}"),
            Self::Stale => f.write_str("control nonce is not above the applied nonce"),
        }
    }
}
impl std::error::Error for ControlBundleError {}
impl From<BundleError> for ControlBundleError {
    fn from(e: BundleError) -> Self {
        Self::Bundle(e)
    }
}
/// A control verified for a single destination; fields cannot be replaced after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedControlBundleV1 {
    pub(super) certificate: VerifiedCertificateV1,
    pub(super) control: ControlProofV1,
    leaf: [u8; 32],
}
impl VerifiedControlBundleV1 {
    /// Whether this proof traverses the history accumulator.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.control.block.height < self.certificate.header().height()
    }
    /// Whether the entry point uses a stored checkpoint.
    #[must_use]
    pub const fn is_checkpoint(&self) -> bool {
        self.certificate.is_checkpoint()
    }
    /// Exact nonce that will be applied.
    #[must_use]
    pub const fn control_nonce(&self) -> u64 {
        self.control.control_nonce
    }
    /// Recomputed leaf committed by the verified path.
    #[must_use]
    pub const fn leaf(&self) -> &[u8; 32] {
        &self.leaf
    }
    /// Full destination state this control leaves when applied at `now_ms`, including the clamp.
    #[must_use]
    pub fn applied_state(&self, now_ms: u64) -> DestinationControlStateV1 {
        DestinationControlStateV1 {
            control_nonce: self.control.control_nonce,
            parliament_paused: self.control.parliament_paused != 0,
            fast_pause_until_ms: applied_fast_pause_until_ms(
                self.control.fast_pause_until_ms,
                now_ms,
            ),
        }
    }
    /// Whether minting may follow after this control is applied at the selected destination time.
    #[must_use]
    pub fn finalize_allowed_after_apply(&self, now_ms: u64) -> bool {
        !self.applied_state(now_ms).paused_at(now_ms)
    }
}
/// Verify the certificate, complete control leaf, target and freshness before paying to apply it.
///
/// # Errors
/// Returns the first failed target, certificate, inclusion, field or freshness check.
pub fn verify_control_bundle(
    bundle: &SccpControlProofBundleV1,
    context: &DestinationContextV1<'_>,
    applied: &DestinationControlStateV1,
    usage: CertificateUseV1,
) -> Result<VerifiedControlBundleV1, ControlBundleError> {
    bundle.check_shape().map_err(BundleError::Shape)?;
    if bundle.network != context.destination.network
        || bundle.revision != context.destination.route_revision
    {
        return Err(ControlBundleError::WrongDeployment);
    }
    let certificate = verify_certificate_bundle(&bundle.certificate, context, usage)?;
    let control = bundle.control_proof();
    let leaf = verify_control(
        certificate.header(),
        &control,
        &context.taira_network_id,
        &context.destination,
    )
    .map_err(BundleError::Proof)?;
    if control.control_nonce <= applied.control_nonce {
        return Err(ControlBundleError::Stale);
    }
    Ok(VerifiedControlBundleV1 {
        certificate,
        control,
        leaf,
    })
}
#[cfg(test)]
mod tests;
