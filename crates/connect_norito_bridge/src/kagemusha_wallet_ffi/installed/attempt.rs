//! Move-only ownership of one genuine loaded installation before registry admission.
//! An opaque allocation carries ownership only; it grants no ID/capacity reservation.
use super::*;

/// Opaque Native-created installation attempt. Foreign callers must not construct,
/// copy, inspect or dereference it; exact pointer custody lasts until consuming zero ack.
pub struct WalletInstallationAttempt {
    owner: Option<Arc<open::RuntimeOwner>>,
}
impl WalletInstallationAttempt {
    pub(super) fn new(owner: Arc<open::RuntimeOwner>) -> Self {
        Self { owner: Some(owner) }
    }
    pub(super) fn register(&mut self, selected: &Mutex<Registry>) -> Result<u64> {
        let owner = self.owner.as_ref().ok_or(Failure::code(CLOSED))?;
        let handle = open::register_owned_runtime(selected, owner)?;
        // The single existing registry now owns this SAME runtime and binding.
        drop(self.owner.take());
        Ok(handle)
    }
    pub(super) fn close(&mut self) -> Result<()> {
        let owner = self.owner.as_ref().ok_or(Failure::code(CLOSED))?;
        owner.closing.begin();
        open::close(Arc::clone(owner))?;
        drop(self.owner.take());
        Ok(())
    }
}

#[cfg(test)]
mod tests;
