//! Local application admission for a first Prepare, retained with exact execution custody.
//!
//! These values have no wire decoder. The executor supplies its own immutable admission
//! owner; the consensus core supplies the signing source and authenticates any held PQC.

use crate::{
    crypto::SigningError,
    types::{EpochId, Hash32},
};

/// Exact signing request constructed only by the consensus core from its current round.
/// The certified bit is backed by a matching `PrepareQC` held by that same core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrepareSigningRequest {
    pub(crate) instance: Hash32,
    pub(crate) epoch: EpochId,
    pub(crate) height: u64,
    pub(crate) view: u64,
    pub(crate) block_hash: Hash32,
    pub(crate) result: Hash32,
    pub(crate) certified: bool,
}
impl PrepareSigningRequest {
    /// Exact consensus instance.
    pub fn instance(&self) -> Hash32 {
        self.instance
    }
    /// Authenticated scheduling context.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }
    /// Height being prepared.
    pub fn height(&self) -> u64 {
        self.height
    }
    /// View of this first Prepare attempt.
    pub fn view(&self) -> u64 {
        self.view
    }
    /// Exact original available-body hash.
    pub fn block_hash(&self) -> Hash32 {
        self.block_hash
    }
    /// Exact authenticated execution commitment.
    pub fn result(&self) -> Hash32 {
        self.result
    }
    /// Whether the core genuinely holds a matching `PrepareQC`.
    pub fn certified(&self) -> bool {
        self.certified
    }
}

/// Trusted application-local admission, checked immediately before a first signature.
///
/// Implementations bind the complete source above to their original execution owner.
/// Native time-sensitive execution reads its injected clock here; a refusal is local
/// and must never become deterministic invalidity. Implementations must be nonblocking.
/// There is deliberately no decoded policy object or default permissive implementation.
pub trait PrepareAdmission: Send + Sync + core::fmt::Debug {
    /// Deterministic commitment bound by this original execution owner.
    fn result(&self) -> Hash32;
    /// Check this exact first-signing request against the retained original execution.
    ///
    /// # Errors
    /// A local source mismatch or temporary freshness/resource refusal.
    fn check(&self, request: &PrepareSigningRequest) -> Result<(), SigningError>;
}

/// Shared local admission retaining its original concrete allocation and charge.
/// Clone only retains that same owner; no codec or untrusted policy constructor exists.
#[derive(Clone)]
pub struct ExecutionAdmission(iroha_allocation::shared::ErasedShared<dyn PrepareAdmission>);
impl ExecutionAdmission {
    /// Transfer a trusted application's already-owned admission without allocating.
    pub fn from_owner(owner: iroha_allocation::shared::ErasedShared<dyn PrepareAdmission>) -> Self {
        Self(owner)
    }
    /// Deterministic commitment bound by the original retained owner.
    pub fn result(&self) -> Hash32 {
        self.0.result()
    }
    /// Check immediately before the corresponding first signature.
    ///
    /// # Errors
    /// The retained application owner refused this exact request.
    pub fn check(&self, request: &PrepareSigningRequest) -> Result<(), SigningError> {
        self.0.check(request)
    }
}
impl core::fmt::Debug for ExecutionAdmission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ExecutionAdmission")
            .field(&&*self.0)
            .finish()
    }
}
impl PartialEq for ExecutionAdmission {
    fn eq(&self, other: &Self) -> bool {
        iroha_allocation::shared::ErasedShared::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ExecutionAdmission {}
