//! Original application custody checked at a fresh proposal's first signature.
//!
//! Admission has no wire decoder. Restart must reacquire it from the original available
//! body unless a genuine certificate or authenticated successful signature already exists.

use crate::{
    availability::PayloadBytes,
    crypto::SigningError,
    types::{EpochId, Hash32},
};

/// Exact fresh proposal source constructed by the consensus core after RS16 authoring.
#[derive(Clone, Debug)]
pub struct ProposalSigningRequest {
    pub(crate) instance: Hash32,
    pub(crate) epoch: EpochId,
    pub(crate) height: u64,
    pub(crate) view: u64,
    pub(crate) block_hash: Hash32,
    pub(crate) payload_hash: Hash32,
    pub(crate) parent_hash: Hash32,
    pub(crate) parent_result: Hash32,
    pub(crate) attachments_digest: Hash32,
    pub(crate) certified: bool,
    pub(crate) payload: PayloadBytes,
}
impl ProposalSigningRequest {
    /// Original consensus instance.
    pub fn instance(&self) -> Hash32 {
        self.instance
    }
    /// Original authenticated epoch.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }
    /// Height of this proposal.
    pub fn height(&self) -> u64 {
        self.height
    }
    /// View of this proposal.
    pub fn view(&self) -> u64 {
        self.view
    }
    /// Final available-body identity, including authenticated availability.
    pub fn block_hash(&self) -> Hash32 {
        self.block_hash
    }
    /// Commitment to the original application payload.
    pub fn payload_hash(&self) -> Hash32 {
        self.payload_hash
    }
    /// Original certified parent identity.
    pub fn parent_hash(&self) -> Hash32 {
        self.parent_hash
    }
    /// Original certified parent result.
    pub fn parent_result(&self) -> Hash32 {
        self.parent_result
    }
    /// Exact proposal attachment commitment.
    pub fn attachments_digest(&self) -> Hash32 {
        self.attachments_digest
    }
    /// Whether this core holds a genuine matching `PrepareQC`.
    pub fn certified(&self) -> bool {
        self.certified
    }
    /// Original paid application bytes; cloning the request retains their same owner.
    pub fn payload(&self) -> &PayloadBytes {
        &self.payload
    }
}

/// Trusted nonblocking application check for the exact original fresh proposal source.
pub trait ProposalAdmissionOwner: Send + Sync + core::fmt::Debug {
    /// Check source binding and current local publication admission immediately before signing.
    ///
    /// # Errors
    /// Original-source mismatch or a local clock/resource refusal; never block invalidity.
    fn check(&self, request: &ProposalSigningRequest) -> Result<(), SigningError>;
}

/// Retained paid original application owner, with no decoded or permissive constructor.
#[derive(Clone)]
pub struct ProposalAdmission(iroha_allocation::shared::ErasedShared<dyn ProposalAdmissionOwner>);
impl ProposalAdmission {
    /// Transfer the application's existing concrete owner and original charge.
    pub fn from_owner(
        owner: iroha_allocation::shared::ErasedShared<dyn ProposalAdmissionOwner>,
    ) -> Self {
        Self(owner)
    }
    /// Recheck the exact fresh source at the actual first-signing boundary.
    ///
    /// # Errors
    /// The original application owner refused this request.
    pub fn check(&self, request: &ProposalSigningRequest) -> Result<(), SigningError> {
        self.0.check(request)
    }
}
impl core::fmt::Debug for ProposalAdmission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ProposalAdmission")
            .field(&&*self.0)
            .finish()
    }
}
impl PartialEq for ProposalAdmission {
    fn eq(&self, other: &Self) -> bool {
        iroha_allocation::shared::ErasedShared::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ProposalAdmission {}

/// Original nonempty builder output and its application-owned publication admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltPayload {
    /// Original funded bytes carried through control and RS16 authoring without replacement.
    pub payload: PayloadBytes,
    /// Owner retained through final signing, local refusal and retry.
    pub admission: ProposalAdmission,
}
