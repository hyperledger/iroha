//! Bounded native SDK retrieval followed by independently anchored release authentication.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use iroha::http::{MAX_PUBLIC_READ_BYTES, PublicHttpClient, PublicHttpError};

use super::{
    AuthenticatedBootstrap, BootstrapError, MAX_RELEASE_CHECKPOINT_BYTES, ReleaseCheckpointStore,
    profile::InstalledNetworkProfile,
};

/// Maximum downloaded checkpoint frame, also constrained by the canonical archive's native reader.
pub const MAX_DOWNLOADED_CHECKPOINT_BYTES: usize =
    if MAX_RELEASE_CHECKPOINT_BYTES < MAX_PUBLIC_READ_BYTES {
        MAX_RELEASE_CHECKPOINT_BYTES
    } else {
        MAX_PUBLIC_READ_BYTES
    };

/// Failure to retrieve and authenticate one installed network's checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointReadError {
    /// Credential-free bounded HTTP retrieval failed.
    #[error(transparent)]
    Http(#[from] PublicHttpError),
    /// The independently signed artifact, local clock or durable watermark was invalid.
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
}

/// Reusable native HTTP context containing no ledger signer or response-selected authority.
#[derive(Clone, Debug, Default)]
pub struct CheckpointTransport {
    client: PublicHttpClient,
}

impl CheckpointTransport {
    /// Retain the native SDK's credential-free lazy HTTPS transport.
    /// Native transport construction occurs during retrieval and can fail there.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: PublicHttpClient::new(),
        }
    }

    /// Use an explicitly injected SDK public-read owner; installation trust remains separate.
    pub fn with_client(client: PublicHttpClient) -> Self {
        Self { client }
    }

    /// Fetch once from the exact installed URL, then authenticate and durably retain its release.
    /// The local verification time is sampled after retrieval. This never reports fresh readiness.
    ///
    /// # Errors
    /// URL/deadline/response bounds, signature, clock, network, native checkpoint or custody failure.
    pub fn fetch_and_authenticate(
        &self,
        profile: &InstalledNetworkProfile,
        store: &ReleaseCheckpointStore,
        deadline: Instant,
    ) -> Result<AuthenticatedBootstrap, CheckpointReadError> {
        self.fetch_with_clock(profile, store, deadline, || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|duration| u64::try_from(duration.as_millis()).ok())
                .ok_or(BootstrapError::Invalid("local bootstrap clock is invalid"))
        })
    }

    /// Read the original result-bearing global G1 and genuine H2 from one approved root.
    /// Transport is credential-free; only the shared native prefix verifier establishes trust.
    pub(super) fn fetch_amx_pair(
        &self,
        bootstrap: &AuthenticatedBootstrap,
        deadline: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), CheckpointReadError> {
        let root: url::Url = bootstrap
            .release()
            .torii_roots
            .first()
            .ok_or(BootstrapError::Invalid(
                "selected AMX parent has no approved endpoint",
            ))?
            .parse()
            .map_err(|_| BootstrapError::Invalid("invalid approved AMX parent endpoint"))?;
        let read = |height: u64| -> Result<Vec<u8>, CheckpointReadError> {
            let route = iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY
                .path()
                .replace("{height}", &height.to_string());
            let url = root
                .join(route.trim_start_matches('/'))
                .map_err(|_| BootstrapError::Invalid("invalid exact AMX source route"))?;
            let bytes =
                self.client
                    .get_norito_bytes_blocking(&url, deadline, MAX_PUBLIC_READ_BYTES)?;
            let proof: iroha_data_model::sumeragi_finality::SumeragiFinalityProof =
                norito::decode_canonical_with_limits(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
                .map_err(|_| BootstrapError::Invalid("invalid canonical AMX source proof"))?;
            if proof.height() != height {
                return Err(BootstrapError::Invalid(
                    "AMX source proof differs from requested height",
                )
                .into());
            }
            proof.decode_checked().map_err(|_| {
                BootstrapError::Invalid("invalid AMX source framing or certificate")
            })?;
            if Instant::now() >= deadline {
                return Err(PublicHttpError::Deadline.into());
            }
            Ok(proof.block_wire)
        };
        Ok((read(1)?, read(2)?))
    }

    fn fetch_with_clock(
        &self,
        profile: &InstalledNetworkProfile,
        store: &ReleaseCheckpointStore,
        deadline: Instant,
        now: impl FnOnce() -> Result<u64, BootstrapError>,
    ) -> Result<AuthenticatedBootstrap, CheckpointReadError> {
        let bytes = self.client.get_bytes_blocking(
            profile.checkpoint_url(),
            deadline,
            MAX_DOWNLOADED_CHECKPOINT_BYTES,
        )?;
        let observed_at = now()?;
        if Instant::now() >= deadline {
            return Err(PublicHttpError::Deadline.into());
        }
        Ok(store.authenticate(profile.release_trust(), &bytes, observed_at)?)
    }
}

#[cfg(test)]
mod tests;
