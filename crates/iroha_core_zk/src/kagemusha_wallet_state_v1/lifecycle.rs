//! Typed native preparation with durable request identity, before irreversible Advance.
//!
//! Foreign callers provide intent and exact original objects only. The same installed
//! native owner implements preparation and proof verification. Native source selection,
//! nonce/time observations and map custody never cross the foreign request boundary.
//! Preparation records use the existing incarnation-bound archive and are not completion
//! authority. Only the existing Advance lookup and commit paths can report completion.

use super::*;

mod request;
pub use request::{ChargeOriginalsV1, OperationActionV1, OperationRequestV1, REQUEST_MAX_BYTES};

mod dispatch;
pub use dispatch::CreditProjectionV1;
pub(super) use dispatch::intake::{
    BATCH_BYTES as INTAKE_BATCH_BYTES, DRAFT_BYTES as INTAKE_DRAFT_BYTES,
    DRAFT_OBJECTS as INTAKE_DRAFT_OBJECTS,
};
mod intent;
pub(crate) use intent::ArchiveIntentV1;
pub use intent::NativeIntentV1;

/// Upper bound for a persisted native preparation plan, including exact local originals.
pub const PREPARATION_MAX_BYTES: usize = REQUEST_MAX_BYTES + KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1;

/// Source-selected request progress, keeping preparation distinct from irreversible Advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatusV1 {
    /// No request mapping exists under the current source-selected manifest.
    Unknown,
    /// Exact intent/choices are retained, but Advance has not selected an outcome.
    Preparing,
    /// Existing authoritative Advance lookup result, including its distinct Pending state.
    Outcome(Completion),
}

/// Actual selected source, supplied exclusively by the coordinator under its owner lock.
/// The optional fold is the source-bound record already read by the coordinator.
pub struct PreparationSourceV1<'a> {
    pub(super) released: &'a ReleasedStep,
    pub(super) folded: Option<&'a KagemushaWalletFoldRecordV1>,
}

impl PreparationSourceV1<'_> {
    /// Exact released state, credential and original completion.
    #[must_use]
    pub const fn released(&self) -> &ReleasedStep {
        self.released
    }

    /// Exact retained source fold, when available; preparation must fully verify it.
    #[must_use]
    pub const fn folded(&self) -> Option<&KagemushaWalletFoldRecordV1> {
        self.folded
    }
}

/// Mandatory preparation capability on the coordinator's installed proof owner.
///
/// Implementations use `PreparationV1` and the installed exact source producers. They
/// must obtain local maps, quota usage, recorded Request custody and monotonic observations
/// from the same exclusive native owner. No foreign callback supplies any of these values.
/// This trait does not install a provider or grant authority to structural validation.
pub trait NativePreparation: NativeProofs {
    /// One native derivation retained only inside the coordinator call that made it.
    /// The coordinator consumes it at most once through `prove_preparation`; it is never
    /// stored, persisted, shared or reused by another call, and grants no Advance authority.
    type Prepared;

    /// Select and canonically encode all native choices needed to reproduce this request,
    /// and return the derivation made from those exact bytes for proving in this call.
    /// No payment receipt may be signed or Advance performed here. Include the fresh nonce,
    /// original time observation, local map witnesses and exact retained objects in the plan.
    /// The coordinator durably publishes it before invoking `prove_preparation`.
    ///
    /// # Errors
    /// Refuse unavailable source custody, invalid original inputs, missing fold or artifacts.
    fn plan_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
    ) -> Result<(Vec<u8>, Self::Prepared), Error>;

    /// Decode and validate a bounded canonical plan against this exact request/source on
    /// fresh custody, and return its derivation for proving in this call. This runs on
    /// restart reads, recovered batches and speculative or retried entries; never on a plan
    /// made in this call. The opaque bytes use the installed operation's fixed native schema,
    /// never a caller-selected recipe.
    ///
    /// # Errors
    /// Reject noncanonical, foreign, incomplete or changed local choices and source bindings.
    fn validate_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        plan: &[u8],
    ) -> Result<Self::Prepared, Error>;

    /// Produce the exact sigma and frozen transition from an already durable native plan.
    /// Consume a derivation made in this call from these exact plan bytes; never derive
    /// again and take no custody. Reuse the existing `PreparationV1` relations. Do not
    /// resample nonce/time, reselect originals or sign a payment receipt. The existing
    /// coordinator verifies this result in full and performs the sole irreversible Advance
    /// after durable capsule retention.
    ///
    /// # Errors
    /// Refuse a derivation bound to other plan bytes, source or installation, missing
    /// original proving artifacts, invalid witnesses or proof failures.
    fn prove_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        prepared: Self::Prepared,
        plan: &[u8],
    ) -> Result<FrozenTransition, Error>;
}
