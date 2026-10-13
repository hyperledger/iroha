//! Strict Torii ownership checks for the production stream-token runtime.
use super::{
    StreamTokenAdmissionCaptureV1, StreamTokenApprovedCustodyAnchorV1, StreamTokenIssuer,
    StreamTokenSignerClientV1, StreamTokenStateObserverClientV1,
};
use iroha_config::parameters::actual::{SorafsTokenConfig, Torii as ToriiConfig};
use iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionQualificationV1;
use iroha_data_model::{NetworkId, sorafs::reputation::derive_stream_token_gateway_id_v1};
use std::sync::Arc;
/// Reject missing, unexpected, or drifting production admission ownership.
pub fn preflight_admission_capture(
    network_id: &NetworkId,
    config: &ToriiConfig,
    runtime_deps: &crate::ToriiRuntimeDeps,
) -> Result<(), String> {
    let tokens = &config.sorafs_storage.stream_tokens;
    let capture = runtime_deps.sorafs_stream_token_admission_capture.as_ref();
    if !tokens.enabled {
        return if capture.is_none() {
            Ok(())
        } else {
            Err(
                "stream-token admission capture is unexpected while stream tokens are disabled"
                    .to_owned(),
            )
        };
    }
    let capture = capture.ok_or_else(|| {
        "enabled stream tokens require a deployment-owned admission capture".to_owned()
    })?;
    let handle = tokens
        .admission_provider_handle
        .as_deref()
        .ok_or_else(|| "enabled stream tokens require an admission provider handle".to_owned())?;
    let revision = tokens
        .admission_provider_revision
        .ok_or_else(|| "enabled stream tokens require an admission provider revision".to_owned())?;
    let policy_digest = tokens.admission_provider_policy_digest.ok_or_else(|| {
        "enabled stream tokens require an admission provider policy digest".to_owned()
    })?;
    let compliance = config.sorafs_gateway.compliance.as_ref().ok_or_else(|| {
        "enabled stream tokens require a governed gateway compliance identity".to_owned()
    })?;
    let gateway_id = derive_stream_token_gateway_id_v1(network_id, &compliance.gateway_id)
        .map_err(|_| "configured stream-token gateway identity is invalid".to_owned())?;
    let qualification = StreamTokenGatewayAdmissionQualificationV1 {
        gateway_id,
        revision,
        policy_digest,
        max_pending: tokens.admission_max_pending,
        max_tracked_tokens: tokens.admission_max_tracked_tokens,
        lease_ttl_ms: tokens.admission_lease_ttl_ms,
    };
    capture
        .validate_expected_binding(
            handle,
            qualification,
            tokens.admission_reconcile_max_items,
            std::time::Duration::from_millis(tokens.admission_operation_timeout_ms),
        )
        .map_err(|_| {
            "stream-token admission capture is substituted, stale, test-marked, unavailable, or unstable"
                .to_owned()
        })
}
/// Enforce authenticated-operator issuance before constructing any signer dependency.
pub fn validate_issuer_operator_signatures(
    config: &SorafsTokenConfig,
    operator_signatures_enabled: bool,
) -> Result<(), &'static str> {
    if config.enabled && !operator_signatures_enabled {
        Err("enabled stream-token issuance requires torii.operator_signatures.enabled")
    } else {
        Ok(())
    }
}
impl crate::ToriiRuntimeDeps {
    /// Attach the configured opaque signer client; responses remain untrusted.
    #[must_use]
    pub fn with_sorafs_stream_token_signer_client(
        mut self,
        client: Arc<dyn StreamTokenSignerClientV1>,
    ) -> Self {
        self.sorafs_stream_token_signer_client = Some(client);
        self
    }
    /// Attach the separately configured read-only signed-observation transport.
    #[must_use]
    pub fn with_sorafs_stream_token_state_observer(
        mut self,
        observer: Arc<dyn StreamTokenStateObserverClientV1>,
    ) -> Self {
        self.sorafs_stream_token_state_observer = Some(observer);
        self
    }
    /// Attach independent approved finalized role state, never a provider-supplied bootstrap.
    #[must_use]
    pub fn with_sorafs_stream_token_approved_anchor(
        mut self,
        anchor: StreamTokenApprovedCustodyAnchorV1,
    ) -> Self {
        self.sorafs_stream_token_approved_anchor = Some(anchor);
        self
    }
    /// Attach the qualified deployment-owned stream-token admission capture.
    #[must_use]
    pub fn with_sorafs_stream_token_admission_capture(
        mut self,
        capture: Arc<StreamTokenAdmissionCaptureV1>,
    ) -> Self {
        self.sorafs_stream_token_admission_capture = Some(capture);
        self
    }
}
impl crate::AppState {
    /// Clone the production stream-token admission capture.
    pub(crate) fn stream_token_admission_capture(
        &self,
    ) -> Option<Arc<StreamTokenAdmissionCaptureV1>> {
        self.stream_token_admission_capture.clone()
    }
    /// Clone the configured stream-token issuer.
    pub(crate) fn stream_token_issuer(&self) -> Option<Arc<StreamTokenIssuer>> {
        self.stream_token_issuer.clone()
    }
    #[cfg(test)]
    pub(crate) fn stream_token_concurrency(&self) -> &super::StreamTokenConcurrencyTracker {
        &self.stream_token_concurrency
    }
    #[cfg(test)]
    pub(crate) fn stream_token_quota(&self) -> &super::StreamTokenQuotaTracker {
        &self.stream_token_quota
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[should_panic(
        expected = "enabled stream-token issuance requires torii.operator_signatures.enabled"
    )]
    fn enabled_issuer_requires_operator_signatures() {
        let config = SorafsTokenConfig {
            enabled: true,
            ..Default::default()
        };
        validate_issuer_operator_signatures(&config, false)
            .expect("enabled stream-token issuance requires torii.operator_signatures.enabled");
    }
}
