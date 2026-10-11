//! Closed startup diagnostics shared by the main process owner and bounded background work.

use super::readiness;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Phase {
    Selection,
    InitialReadiness,
    Bootstrap,
    Carrier0,
    Carrier1,
    Carrier2,
    Carrier3,
    Catalog,
    Restart,
    Receipt,
    PromotedCatalog,
    ProviderAdvertisement,
    Discovery,
    CustodyRenewal,
    ProgramAdmission,
    CustodyMaterial,
    StreamTokenRevision,
    CarrierPeers,
}
impl Phase {
    fn description(self) -> &'static str {
        match self {
            Self::ProgramAdmission => {
                "verifying the installed runtime and opening its control session"
            }
            Self::Selection => "retaining the original generated service selection",
            Self::InitialReadiness => "proving the original readiness transaction",
            Self::Bootstrap => "recovering and advancing the original native service bootstrap",
            Self::CustodyMaterial => "retaining current native custody material",
            Self::StreamTokenRevision => "preparing the current stream-token runtime revision",
            Self::Carrier0 => "confirming the original bootstrap carrier on validator 0",
            Self::Carrier1 => "confirming the original bootstrap carrier on validator 1",
            Self::Carrier2 => "confirming the original bootstrap carrier on validator 2",
            Self::Carrier3 => "confirming the original bootstrap carrier on validator 3",
            Self::CarrierPeers => {
                "confirming the original bootstrap carrier on all four validators"
            }
            Self::Catalog => "publishing the exact generated gateway catalog",
            Self::Restart => "restarting the owned validators with the retained service revision",
            Self::Receipt => "reproving the same readiness transaction after restart",
            Self::PromotedCatalog => "checking the exact promoted catalog after restart",
            Self::ProviderAdvertisement => "publishing the original provider advertisement",
            Self::Discovery => "authenticating current native provider and signer discovery",
            Self::CustodyRenewal => "recovering and advancing the exact bounded custody renewal",
        }
    }
}

#[derive(Default)]
pub(super) struct Progress {
    phase: AtomicU8,
    pub(super) readiness: readiness::Progress,
}
impl Progress {
    pub(super) fn enter(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Release);
    }
    fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            1 => Phase::InitialReadiness,
            2 => Phase::Bootstrap,
            3 => Phase::Carrier0,
            4 => Phase::Carrier1,
            5 => Phase::Carrier2,
            6 => Phase::Carrier3,
            7 => Phase::Catalog,
            8 => Phase::Restart,
            9 => Phase::Receipt,
            10 => Phase::PromotedCatalog,
            11 => Phase::ProviderAdvertisement,
            12 => Phase::Discovery,
            13 => Phase::CustodyRenewal,
            14 => Phase::ProgramAdmission,
            15 => Phase::CustodyMaterial,
            16 => Phase::StreamTokenRevision,
            17 => Phase::CarrierPeers,
            _ => Phase::Selection,
        }
    }
    pub(super) fn deadline(&self) -> Failure {
        self.failure(Cause::Deadline)
    }
    pub(super) fn unconfirmed(&self) -> Failure {
        self.failure(Cause::Unconfirmed)
    }
    pub(super) fn cancelled(&self) -> Failure {
        self.failure(Cause::Cancelled)
    }
    fn failure(&self, cause: Cause) -> Failure {
        Failure::Activation {
            phase: self.phase(),
            cause,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    Deadline,
    Cancelled,
    Unconfirmed,
}

/// No remote body or arbitrary error string can enter retained startup status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Readiness(readiness::Failure),
    ObservationExpired,
    ValidatorExited,
    Bootstrap(crate::managed::ManagedBootstrapFailure),
    Activation { phase: Phase, cause: Cause },
}
impl From<readiness::Failure> for Failure {
    fn from(value: readiness::Failure) -> Self {
        Self::Readiness(value)
    }
}
impl Failure {
    pub(super) fn message(self) -> String {
        match self {
            Self::Readiness(failure) => failure.message(),
            Self::Bootstrap(reason) => reason.to_string(),
            Self::ValidatorExited => "a supervised validator exited; inspect its retained log".into(),
            Self::ObservationExpired => "generated service readiness observation expired; fresh authenticated activation is required".into(),
            Self::Activation { phase, cause } => {
                let cause = match cause {
                    Cause::Deadline => "startup deadline expired",
                    Cause::Cancelled => "startup was cancelled",
                    Cause::Unconfirmed => "startup could not be confirmed",
                };
                format!("{cause} while {}", phase.description())
            }
        }
    }
}
