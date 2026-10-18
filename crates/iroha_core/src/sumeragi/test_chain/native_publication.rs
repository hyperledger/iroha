//! Certified fixtures retain the same funded joining owner as a live native lane driver.

use std::sync::Arc;

use iroha_allocation::AllocationBudget;

use crate::sumeragi::{
    driver::{DriverError, PublicationSession},
    lanes::store::FileLaneBlockStore,
};

/// One physical original publication owner for a certified fixture's native lane store.
///
/// Retain this owner across every append to the same store. Admission binds once on the
/// existing driver joiner before this constructor returns; no token or append bypass is
/// exposed. Dropping the fixture closes new admission, drains existing permits and joins
/// that original thread. Pending native publication remains available for genuine restart.
#[must_use = "retain the original publication owner until all fixture appends finish"]
pub struct NativeLanePublication {
    _original: PublicationSession,
}

impl NativeLanePublication {
    /// Bind the original store and its exact allocation pool before native publication.
    ///
    /// # Errors
    /// Foreign pool, exhausted original admission, repeated binding or joiner startup failure.
    pub fn start(
        store: Arc<FileLaneBlockStore>,
        budget: &AllocationBudget,
    ) -> Result<Self, DriverError> {
        PublicationSession::try_start(store, budget).map(|original| Self {
            _original: original,
        })
    }
}
