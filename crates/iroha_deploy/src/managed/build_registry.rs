//! Operation-scoped prepared archive registries shared by Kagami and Mochi.
//!
//! Remote private environments retain their independently authenticated parent registry. Fresh
//! generated localnets select only their original provider material; that intent is joined to
//! fresh native discovery before the storage owner permits any provider request.

use super::{Error, InstalledRuntime, ManagedStore, Result};
use crate::bootstrap::{BootstrapError, ParentFinalityStore};
use iroha::config::Config;
use iroha_storage_client::musubi_archive_fetch::{
    MusubiArchiveDiscoveryErrorV1, PreparedMusubiArchiveFetchConfigV1,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

mod generated_local;
pub(super) use generated_local::{GeneratedServiceObservation, observe_generated_service};

/// Shared native discovery freshness for registry consumers and managed service observations.
pub(super) const DISCOVERY_FRESHNESS: Duration = Duration::from_secs(30);

impl ManagedStore {
    /// Resolve the original registry binding for a package with external dependencies.
    ///
    /// The returned configuration belongs to the registry network. Its prepared transport owns
    /// the exclusive, separately advancing discovery journal through every derived archive client.
    /// Managed readiness observations use a distinct purpose and finality journal, so keeping an
    /// archive client alive cannot prevent the local runtime from refreshing its native evidence.
    /// Generated local TLS roots and addresses come only from the validated original profile;
    /// fresh native admission, advert and signer custody remain mandatory before provider I/O.
    /// Standard localnets and private environments without a signed parent registry return `None`.
    /// Complete cache hits still require this binding and retained discovery custody. A private
    /// parent's retained release is authenticated first; an unavailable retained release may
    /// require a bounded checkpoint fetch. Provider discovery runs only on archive requests.
    /// Each build supplies its own bounded deadline; reopening never reissues original keys,
    /// certificates, admission intervals or signed network releases.
    /// # Errors
    /// Invalid retained profile, changed release, unavailable custody, elapsed deadline, or a
    /// concurrent registry operation for this generation.
    pub fn build_registry(
        &self,
        runtime: &InstalledRuntime,
        name: &str,
        deadline: Instant,
    ) -> Result<Option<(Config, PreparedMusubiArchiveFetchConfigV1)>> {
        super::native_operation::require_deadline(deadline)?;
        if let Some(context) = super::remote::build_registry_context(self, runtime, name, deadline)?
        {
            let finality = ParentFinalityStore::open(&context.finality_path, &context.bootstrap)
                .map_err(|error| Error::Invalid(error.to_string()))?;
            let finality = Mutex::new(finality);
            let config = context.parent;
            let selected = config.clone();
            let transport = PreparedMusubiArchiveFetchConfigV1::from_account_registry(
                config.clone(),
                Arc::new(move |provider| {
                    check_deadline(deadline)?;
                    let mut finality = finality.try_lock().map_err(|error| match error {
                        std::sync::TryLockError::WouldBlock => {
                            MusubiArchiveDiscoveryErrorV1::Unavailable
                        }
                        std::sync::TryLockError::Poisoned(_) => {
                            MusubiArchiveDiscoveryErrorV1::Rejected
                        }
                    })?;
                    let result = finality.discover_build_provider(
                        &context.bootstrap,
                        &selected,
                        provider,
                        deadline,
                    );
                    check_deadline(deadline)?;
                    result.map_err(|error| match error {
                        BootstrapError::Busy | BootstrapError::Io(_) => {
                            MusubiArchiveDiscoveryErrorV1::Unavailable
                        }
                        _ => MusubiArchiveDiscoveryErrorV1::Rejected,
                    })
                }),
                DISCOVERY_FRESHNESS,
            )
            .map_err(|_| Error::Invalid("cannot prepare retained parent build registry".into()))?;
            super::native_operation::require_deadline(deadline)?;
            return Ok(Some((config, transport)));
        }
        generated_local::prepare(self.prepared(name)?, deadline)
    }
}

fn check_deadline(deadline: Instant) -> std::result::Result<(), MusubiArchiveDiscoveryErrorV1> {
    if Instant::now() >= deadline {
        Err(MusubiArchiveDiscoveryErrorV1::Deadline)
    } else {
        Ok(())
    }
}
