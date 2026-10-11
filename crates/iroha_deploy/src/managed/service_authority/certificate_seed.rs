//! One joined bootstrap advance can lend immutable native carrier certificates to new cursors.
//! The certificate is neither a fresh quorum nor a current-state or wallet-operation verdict.

use super::{AuthorityProfile, ServiceAuthority};
use crate::{
    localnet::service_authorities::ValidatedServiceProfile,
    managed::{
        Result,
        native_operation::{MAX_CHECKPOINT_BYTES, checkpoint_bytes, invalid},
    },
    verify::finality::FinalityVerifier,
};
use iroha_crypto::Hash;
use iroha_fs::{FileSnapshot, PrivateDirectory, RetainedFile};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Empty outside the one joined advance; existing and standalone owners keep their recipe.
#[derive(Default)]
pub(super) struct Scope {
    selected: Mutex<Option<Arc<Progress>>>,
}
struct Progress {
    original: Arc<ValidatedServiceProfile>,
    live: AtomicBool,
    // One successful immutable receipt, independent of the number of purposes or providers.
    newest: Mutex<Option<Arc<Certificate>>>,
}
struct Certificate {
    verifier: FinalityVerifier,
    // Native consensus header and certified execution result, independent of QC witnesses.
    decision: Hash,
    directory: PrivateDirectory,
    file: RetainedFile,
    snapshot: FileSnapshot,
    digest: Hash,
}

/// The root's guard outlives all scoped worker joins and clears the seed on every exit.
pub(in crate::managed) struct ScopeGuard<'a> {
    owner: &'a Scope,
    progress: Option<Arc<Progress>>,
}
impl Drop for ScopeGuard<'_> {
    fn drop(&mut self) {
        if let Some(progress) = self.progress.take() {
            progress.live.store(false, Ordering::Release);
            // A panic cannot leave a reusable certificate lease behind.
            let mut selected = self
                .owner
                .selected
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if selected
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &progress))
            {
                *selected = None;
            }
        }
    }
}

/// Read-only exact receipt custody retained until the fresh observation has closed.
pub(in crate::managed) struct Seed {
    progress: Arc<Progress>,
    certificate: Arc<Certificate>,
}
impl Seed {
    pub(in crate::managed) fn verifier(&self) -> FinalityVerifier {
        self.certificate.verifier.clone()
    }
    pub(in crate::managed) fn revalidate(&self) -> Result<()> {
        if !self.progress.live.load(Ordering::Acquire) {
            return Err(invalid("bootstrap certificate scope has ended"));
        }
        self.certificate.revalidate()
    }
}
impl Certificate {
    fn retain(directory: &PrivateDirectory, verifier: &FinalityVerifier) -> Result<Self> {
        let directory = directory.retain()?;
        let file = directory.open_retained_private("carrier.nrt")?;
        let snapshot = file.snapshot()?;
        let bytes = directory.read("carrier.nrt", MAX_CHECKPOINT_BYTES)?;
        let digest = Hash::new(bytes.as_slice());
        if digest != Hash::new(checkpoint_bytes(verifier)?) || file.snapshot()? != snapshot {
            return Err(invalid("native carrier certificate changed during capture"));
        }
        let decision = verifier
            .verified_tip_ref()
            .map_err(|_| invalid("native carrier has no authenticated execution decision"))?
            .context_id();
        let certificate = Self {
            verifier: verifier.clone(),
            decision,
            directory,
            file,
            snapshot,
            digest,
        };
        certificate.revalidate()?;
        Ok(certificate)
    }
    fn revalidate(&self) -> Result<()> {
        self.directory.revalidate()?;
        if self.file.snapshot()? != self.snapshot {
            return Err(invalid(
                "original native carrier certificate custody changed",
            ));
        }
        let bytes = self.directory.read("carrier.nrt", MAX_CHECKPOINT_BYTES)?;
        if Hash::new(bytes.as_slice()) != self.digest || self.file.snapshot()? != self.snapshot {
            return Err(invalid("original native carrier certificate bytes changed"));
        }
        self.directory.revalidate()?;
        Ok(())
    }
}
impl Progress {
    fn require_authority(&self, authority: &ServiceAuthority) -> Result<()> {
        let AuthorityProfile::Shared(original) = &authority.profile else {
            return Err(invalid(
                "bootstrap certificate has no shared original owner",
            ));
        };
        if !self.live.load(Ordering::Acquire)
            || !Arc::ptr_eq(original, &self.original)
            || authority.config.network_id != self.original.config.network_id
            || authority.config.chain != self.original.config.chain
            || authority.genesis != self.original.genesis
        {
            return Err(invalid(
                "bootstrap certificate belongs to another original network",
            ));
        }
        authority.validate_profile()
    }
}
impl Scope {
    pub(super) fn inherit(&self, parent: &Self) -> Result<()> {
        if norito::core::decode_limits_active() {
            return Ok(());
        }
        let progress = parent.current()?;
        *self
            .selected
            .lock()
            .map_err(|_| invalid("bootstrap certificate owner failed"))? = progress;
        Ok(())
    }
    fn current(&self) -> Result<Option<Arc<Progress>>> {
        if norito::core::decode_limits_active() {
            return Ok(None);
        }
        Ok(self
            .selected
            .lock()
            .map_err(|_| invalid("bootstrap certificate owner failed"))?
            .as_ref()
            .filter(|progress| progress.live.load(Ordering::Acquire))
            .cloned())
    }
}
impl ServiceAuthority {
    /// Begin only at the joined live advance, never at recovery or a standalone producer.
    pub(in crate::managed) fn begin_certificate_scope(&self) -> Result<ScopeGuard<'_>> {
        let owner = &self.certificate_scope;
        if norito::core::decode_limits_active() {
            return Ok(ScopeGuard {
                owner,
                progress: None,
            });
        }
        let AuthorityProfile::Shared(original) = &self.profile else {
            return Ok(ScopeGuard {
                owner,
                progress: None,
            });
        };
        self.validate_profile()?;
        let mut selected = owner
            .selected
            .lock()
            .map_err(|_| invalid("bootstrap certificate owner failed"))?;
        if selected.is_some() {
            return Err(invalid("bootstrap certificate scope is already selected"));
        }
        let progress = Arc::new(Progress {
            original: Arc::clone(original),
            live: AtomicBool::new(true),
            newest: Mutex::new(None),
        });
        *selected = Some(Arc::clone(&progress));
        Ok(ScopeGuard {
            owner,
            progress: Some(progress),
        })
    }

    /// Borrow an original immutable receipt only after the selected child cursor is absent.
    pub(in crate::managed) fn certificate_seed(&self) -> Result<Option<Seed>> {
        let Some(progress) = self.certificate_scope.current()? else {
            return Ok(None);
        };
        progress.require_authority(self)?;
        let certificate = progress
            .newest
            .lock()
            .map_err(|_| invalid("bootstrap certificate owner failed"))?
            .clone();
        let Some(certificate) = certificate else {
            return Ok(None);
        };
        let seed = Seed {
            progress,
            certificate,
        };
        seed.revalidate()?;
        self.validate_profile()?;
        Ok(Some(seed))
    }

    /// Publish only after the original replay authenticated exact successful wallet inclusion.
    /// The stored file is create-only carrier evidence; mutable observation files are excluded.
    pub(in crate::managed) fn remember_certificate(
        &self,
        directory: &PrivateDirectory,
        verifier: &FinalityVerifier,
    ) -> Result<()> {
        let Some(progress) = self.certificate_scope.current()? else {
            return Ok(());
        };
        progress.require_authority(self)?;
        if verifier.checkpoint().network_id() != self.config.network_id
            || verifier.checkpoint().chain_id() != self.config.chain.as_str()
        {
            return Err(invalid(
                "native carrier certificate belongs to another network",
            ));
        }
        let candidate = Arc::new(Certificate::retain(directory, verifier)?);
        // Never hold this small selection mutex across native file or HTTP work.
        let mut newest = progress
            .newest
            .lock()
            .map_err(|_| invalid("bootstrap certificate owner failed"))?;
        if let Some(previous) = newest.as_ref() {
            let before = previous.verifier.checkpoint();
            let after = verifier.checkpoint();
            if before.height() == after.height() && previous.decision != candidate.decision {
                return Err(invalid(
                    "native carrier certificates disagree at one height",
                ));
            }
            if before.height() >= after.height() {
                drop(newest);
                return progress.require_authority(self);
            }
        }
        let displaced = newest.replace(candidate);
        drop(newest);
        // Final certificate/file-handle destruction also stays outside the selection mutex.
        drop(displaced);
        progress.require_authority(self)
    }
}

#[cfg(test)]
#[path = "certificate_seed/tests.rs"]
mod tests;
