//! Fail-closed Torii boundary for native Bootle/Lantern blind issuance.
//!
//! The HTTP surface accepts only the fixed first-release `ILA1`, `ILQ1`, and `ILR1` wires. Issuer
//! keys and authentication policy are supplied by an explicitly qualified deployment runtime
//! provider and never enter node configuration or response diagnostics.
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{
        HeaderMap, HeaderValue, Request, StatusCode,
        header::{
            ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
            PRAGMA, RETRY_AFTER, TRANSFER_ENCODING, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
        },
    },
    response::{IntoResponse, Response},
};
use base64::{Engine as _, encoded_len, engine::general_purpose::URL_SAFE_NO_PAD};
use iroha_config::parameters::{ProductionRuntimeHandleError, validate_production_runtime_handle};
use iroha_core::state::{State as CoreState, StateReadOnly, WorldReadOnly};
use iroha_core_privacy::privacy_engines::bootle_lantern::{
    codec::{
        BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1, BLIND_ISSUANCE_REQUEST_BYTES_V1,
        BLIND_ISSUANCE_RESPONSE_BYTES_V1,
    },
    issuer::{
        BootleLanternBlindIssuanceRequestV1, BootleLanternBlindIssuanceResponseV1,
        BootleLanternFileIssuanceStoreV1, BootleLanternIssuanceAuthorizationV1,
        BootleLanternIssuanceClaimV1, BootleLanternIssuanceErrorV1,
        BootleLanternIssuancePreflightV1, BootleLanternIssuanceStoreConfigV1,
        BootleLanternIssuanceStoreErrorV1, BootleLanternIssuanceStoreV1,
        MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1,
        MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1,
        issuer_validate_blind_issuance_request_encoded_v1,
        issuer_validate_cached_blind_issuance_response_encoded_v1,
        issuer_validate_prepared_blind_issuance_authorization_v1,
    },
};
use iroha_data_model::privacy::{
    BootleLanternIssuerPolicyLifecycleV1, BootleLanternIssuerPolicyV1,
    PrivacyCompiledProfileResultV1, PrivacyIssuerIdV1, PrivacyPolicyIdV1, PrivacyProtocolIdV1,
    PrivacyStatementContextV1, PrivacyTransactionIntentDigestV1,
};
use iroha_panic_hook::catch_unwind_suppressed;
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::{
    collections::BTreeSet,
    fmt,
    hint::black_box,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
/// Canonical authorization endpoint.
pub const BOOTLE_LANTERN_ISSUANCE_AUTHORIZE_PATH_V1: &str =
    "/v1/privacy/bootle-lantern/issuance/authorize";
/// Canonical one-shot issuance endpoint.
pub const BOOTLE_LANTERN_ISSUANCE_ISSUE_PATH_V1: &str = "/v1/privacy/bootle-lantern/issuance/issue";
/// Sole request and successful-response media type.
pub const BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1: &str = "application/x-norito";
/// Maximum decoded opaque bearer credential.
pub const BOOTLE_LANTERN_ISSUANCE_AUTHENTICATION_MAX_BYTES_V1: usize = 4_096;
/// Exact `ILA1` authorization response length exposed by the authorize endpoint.
pub const BOOTLE_LANTERN_ISSUANCE_AUTHORIZATION_RESPONSE_BYTES_V1: usize = 320;
/// Exact `ILA1 || ILQ1` request length accepted by the issue endpoint.
pub const BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1: usize = 71_896;
/// Exact `ILR1` response length exposed by the issue endpoint.
pub const BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1: usize = 3_176;
const _: () = assert!(
    BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1
        == BOOTLE_LANTERN_ISSUANCE_AUTHORIZATION_RESPONSE_BYTES_V1
);
const _: () = assert!(
    BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1 + BLIND_ISSUANCE_REQUEST_BYTES_V1
        == BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1
);
const _: () =
    assert!(BLIND_ISSUANCE_RESPONSE_BYTES_V1 == BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1);
const AUTHORIZE_BINDING_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.issuance-authorize-api.v1";
const ISSUE_BINDING_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.issuance-issue-api.v1";
const CONTEXT_INTENT_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.issuance-context-intent.v1";
const WWW_AUTHENTICATE_VALUE_V1: &str = "Bearer realm=\"iroha-bootle-lantern-issuance\"";
/// Non-secret, config-backed runtime policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootleLanternIssuanceRuntimeConfigV1 {
    /// Durable one-shot authorization store directory.
    pub state_dir: PathBuf,
    /// Exact non-zero bound on concurrent native issuance operations.
    pub max_inflight: usize,
    /// Exact governed issuer identity.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Exact governed issuer-policy identity.
    pub policy_id: PrivacyPolicyIdV1,
    /// Number of heights added to the committed issue height.
    pub authorization_lifetime_blocks: u64,
    /// Maximum retained authorization records.
    pub max_records: usize,
    /// Maximum reserved canonical store bytes.
    pub max_total_bytes: u64,
    /// Terminal record retention in committed blocks.
    pub terminal_retention_blocks: u64,
    /// Exact deployment-owned provider-registry handle.
    pub runtime_provider_registry_handle: String,
    /// Exact non-zero provider policy revision.
    pub runtime_provider_registry_revision: u64,
    /// Exact non-zero provider policy digest.
    pub runtime_provider_registry_policy_digest: [u8; 32],
}
impl BootleLanternIssuanceRuntimeConfigV1 {
    /// Validate every public input before resolving private providers or opening state.
    ///
    /// # Errors
    ///
    /// Returns [`BootleLanternIssuanceApiErrorV1::ConfigurationInvalid`] for any incomplete,
    /// test-marked, unbounded, or internally inconsistent configuration.
    pub fn validate(&self) -> Result<(), BootleLanternIssuanceApiErrorV1> {
        if !self.state_dir.is_absolute()
            || self.state_dir.as_os_str().is_empty()
            || self.state_dir.parent().is_none()
            || self.max_inflight == 0
            || self.max_inflight
                > iroha_config::parameters::defaults::torii::privacy_bootle_lantern_issuer::MAX_INFLIGHT_HARD
            || self.issuer_id.is_zero()
            || self.policy_id.is_zero()
            || self.authorization_lifetime_blocks == 0
            || self.authorization_lifetime_blocks
                > MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1
            || self.runtime_provider_registry_revision == 0
            || self.runtime_provider_registry_policy_digest == [0; 32]
        {
            return Err(BootleLanternIssuanceApiErrorV1::ConfigurationInvalid);
        }
        validate_production_runtime_handle(&self.runtime_provider_registry_handle).map_err(
            |error| match error {
                ProductionRuntimeHandleError::InvalidSyntax
                | ProductionRuntimeHandleError::TestMarked => {
                    BootleLanternIssuanceApiErrorV1::ConfigurationInvalid
                }
            },
        )?;
        self.store_config()?;
        Ok(())
    }
    fn store_config(
        &self,
    ) -> Result<BootleLanternIssuanceStoreConfigV1, BootleLanternIssuanceApiErrorV1> {
        BootleLanternIssuanceStoreConfigV1::new(
            self.max_records,
            self.max_total_bytes,
            self.terminal_retention_blocks,
        )
        .map_err(|_| BootleLanternIssuanceApiErrorV1::ConfigurationInvalid)
    }
}
impl From<&iroha_config::parameters::actual::ToriiBootleLanternIssuer>
    for BootleLanternIssuanceRuntimeConfigV1
{
    fn from(value: &iroha_config::parameters::actual::ToriiBootleLanternIssuer) -> Self {
        Self {
            state_dir: value.state_dir.clone(),
            max_inflight: value.max_inflight.get(),
            issuer_id: value.issuer_id,
            policy_id: value.policy_id,
            authorization_lifetime_blocks: value.authorization_lifetime_blocks,
            max_records: value.max_records,
            max_total_bytes: value.max_total_bytes,
            terminal_retention_blocks: value.terminal_retention_blocks,
            runtime_provider_registry_handle: value.runtime_provider_registry_handle.clone(),
            runtime_provider_registry_revision: value.runtime_provider_registry_revision,
            runtime_provider_registry_policy_digest: value.runtime_provider_registry_policy_digest,
        }
    }
}
/// Exact public inputs projected to the deployment provider registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootleLanternIssuanceRuntimeProviderBindingsV1 {
    issuer_id: PrivacyIssuerIdV1,
    policy_id: PrivacyPolicyIdV1,
    authorization_lifetime_blocks: u64,
}
impl BootleLanternIssuanceRuntimeProviderBindingsV1 {
    /// Construct validated public bindings.
    ///
    /// # Errors
    ///
    /// Rejects zero identities and an invalid authorization lifetime.
    pub fn try_new(
        issuer_id: PrivacyIssuerIdV1,
        policy_id: PrivacyPolicyIdV1,
        authorization_lifetime_blocks: u64,
    ) -> Result<Self, BootleLanternIssuanceApiErrorV1> {
        if issuer_id.is_zero()
            || policy_id.is_zero()
            || authorization_lifetime_blocks == 0
            || authorization_lifetime_blocks > MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1
        {
            return Err(BootleLanternIssuanceApiErrorV1::ConfigurationInvalid);
        }
        Ok(Self {
            issuer_id,
            policy_id,
            authorization_lifetime_blocks,
        })
    }
    fn from_config(
        config: &BootleLanternIssuanceRuntimeConfigV1,
    ) -> Result<Self, BootleLanternIssuanceApiErrorV1> {
        Self::try_new(
            config.issuer_id,
            config.policy_id,
            config.authorization_lifetime_blocks,
        )
    }
    /// Exact governed issuer identity.
    #[must_use]
    pub const fn issuer_id(&self) -> PrivacyIssuerIdV1 {
        self.issuer_id
    }
    /// Exact governed policy identity.
    #[must_use]
    pub const fn policy_id(&self) -> PrivacyPolicyIdV1 {
        self.policy_id
    }
    /// Exact authorization lifetime.
    #[must_use]
    pub const fn authorization_lifetime_blocks(&self) -> u64 {
        self.authorization_lifetime_blocks
    }
}
/// Public identity of one independently administered provider policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootleLanternIssuanceRuntimeProviderQualificationV1 {
    /// Non-zero provider policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact provider policy.
    pub policy_digest: [u8; 32],
}
impl BootleLanternIssuanceRuntimeProviderQualificationV1 {
    /// Construct a public provider qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            revision,
            policy_digest,
        }
    }
    fn is_valid(self) -> bool {
        self.revision != 0 && self.policy_digest != [0; 32]
    }
}
/// Stable redacted provider-registry failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootleLanternIssuanceRuntimeProviderRegistryErrorV1 {
    /// Provider control plane is unavailable.
    Unavailable,
    /// Provider policy is stale or revoked.
    StaleOrRevoked,
    /// Exact public bindings were rejected.
    RejectedBindings,
}
/// Authenticated issuance action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootleLanternIssuanceActionV1 {
    /// Mint one `ILA1` authorization.
    Authorize,
    /// Consume one `ILA1` with one `ILQ1` request.
    Issue,
}
/// Stable authenticated principal decision returned by the private provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootleLanternIssuanceAuthenticatedPrincipalV1 {
    /// Non-zero stable digest of the principal, independent of bearer rotation.
    pub principal_digest: [u8; 32],
    /// First committed height at which this decision is valid.
    pub issued_at_height: u64,
    /// Inclusive last committed height at which this decision is valid.
    pub expires_at_height: u64,
}
/// Stable redacted authentication failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootleLanternIssuanceAuthenticationErrorV1 {
    /// Authentication failed without exposing provider details.
    Denied,
    /// Authentication authority is unavailable.
    Unavailable,
}
/// Runtime-only action- and body-bound authentication authority.
pub trait BootleLanternIssuanceAuthenticatorV1: Send + Sync {
    /// Authenticate opaque bearer bytes for one exact request binding.
    ///
    /// # Errors
    ///
    /// Returns `Denied` when the credential does not authorize the exact action and
    /// request binding, or `Unavailable` when the authentication authority cannot respond.
    fn authenticate(
        &self,
        opaque_credential: &[u8],
        action: BootleLanternIssuanceActionV1,
        request_binding: [u8; 32],
        committed_height: u64,
    ) -> Result<
        BootleLanternIssuanceAuthenticatedPrincipalV1,
        BootleLanternIssuanceAuthenticationErrorV1,
    >;
}
/// Stable redacted native issuer-cryptography-provider failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootleLanternIssuerCryptoProviderErrorV1 {
    /// Input was not the canonical request for the selected policy.
    InvalidRequest,
    /// Issuer key and governed public policy differ.
    PolicyMismatch,
    /// Issuer randomness or key service is unavailable.
    Unavailable,
}
impl From<BootleLanternIssuanceErrorV1> for BootleLanternIssuerCryptoProviderErrorV1 {
    fn from(error: BootleLanternIssuanceErrorV1) -> Self {
        use BootleLanternIssuanceErrorV1 as CoreError;
        match error {
            CoreError::IssuerKeyPolicyMismatch
            | CoreError::InvalidIssuerPolicy
            | CoreError::IssuerPolicyNotActive => Self::PolicyMismatch,
            CoreError::IssuanceStoreFailed
            | CoreError::RandomnessUnavailable
            | CoreError::RandomnessUnhealthy
            | CoreError::IssuerKeyGenerationExhausted
            | CoreError::AuthorizationIdExhausted
            | CoreError::PreimageSamplingExhausted => Self::Unavailable,
            _ => Self::InvalidRequest,
        }
    }
}
/// Runtime-only native issuer cryptography boundary.
///
/// Implementations hold the issuer trapdoor inside an isolated qualified provider, which may be
/// software, remote, or hardware backed, but never a replay store. Torii is the sole authority for authorization registration,
/// request preflight, atomic claim, completion, and irreversible failure.
pub trait BootleLanternIssuerCryptoProviderV1: Send + Sync {
    /// Exact stable issuer identity served by this provider.
    fn issuer_id(&self) -> PrivacyIssuerIdV1;
    /// Exact stable policy identity served by this provider.
    fn policy_id(&self) -> PrivacyPolicyIdV1;
    /// Generate one native `ILA1` candidate without replay-state mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid authorization request, a mismatch between
    /// the issuer key and governed policy, or unavailable issuer randomness or key service.
    fn prepare_authorization(
        &self,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        requester_authorization_digest: [u8; 32],
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> Result<BootleLanternIssuanceAuthorizationV1, BootleLanternIssuerCryptoProviderErrorV1>;
    /// Verify the exact request and issuer-key binding without randomness.
    ///
    /// # Errors
    ///
    /// Returns an error if the request or authorization is invalid, the issuer key
    /// does not match the governed policy, or the key service is unavailable.
    fn validate_request(
        &self,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        authorization: &BootleLanternIssuanceAuthorizationV1,
        request_bytes: &[u8],
        current_height: u64,
    ) -> Result<[u8; 32], BootleLanternIssuerCryptoProviderErrorV1>;
    /// Independently revalidate and issue one `ILR1` after Torii's exact claim.
    ///
    /// # Errors
    ///
    /// Returns an error if revalidation rejects the request or issuer-policy binding,
    /// or if issuer randomness or the key service is unavailable.
    fn issue_validated(
        &self,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        authorization: &BootleLanternIssuanceAuthorizationV1,
        request_bytes: &[u8],
        current_height: u64,
    ) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuerCryptoProviderErrorV1>;
}
/// Runtime-only private dependencies returned by one coherent registry resolve.
pub struct BootleLanternIssuanceRuntimeSecretsV1 {
    /// Native issuer cryptography provider holding the isolated trapdoor boundary.
    pub issuer_provider: Arc<dyn BootleLanternIssuerCryptoProviderV1>,
    /// Opaque bearer authentication authority.
    pub authenticator: Arc<dyn BootleLanternIssuanceAuthenticatorV1>,
}
impl fmt::Debug for BootleLanternIssuanceRuntimeSecretsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootleLanternIssuanceRuntimeSecretsV1([REDACTED])")
    }
}
/// Deployment-owned factory for the complete private issuance dependency set.
pub trait BootleLanternIssuanceRuntimeProviderRegistryV1: Send + Sync + fmt::Debug {
    /// Exact stable non-secret registry handle.
    fn handle(&self) -> &str;
    /// Current independently administered public qualification.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider control plane is unavailable or its policy
    /// is stale or revoked.
    fn qualification(
        &self,
    ) -> Result<
        BootleLanternIssuanceRuntimeProviderQualificationV1,
        BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
    >;
    /// Resolve one coherent secret set for exact public bindings.
    ///
    /// # Errors
    ///
    /// Returns an error if the control plane is unavailable, its policy is stale
    /// or revoked, or it rejects the exact public bindings.
    fn resolve(
        &self,
        bindings: &BootleLanternIssuanceRuntimeProviderBindingsV1,
    ) -> Result<
        BootleLanternIssuanceRuntimeSecretsV1,
        BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
    >;
}
#[derive(Clone)]
struct QualifiedProviderRegistryV1 {
    handle: String,
    qualification: BootleLanternIssuanceRuntimeProviderQualificationV1,
    inner: Arc<dyn BootleLanternIssuanceRuntimeProviderRegistryV1>,
}
impl fmt::Debug for QualifiedProviderRegistryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedProviderRegistryV1")
            .field("handle", &self.handle)
            .field("qualification", &self.qualification)
            .finish_non_exhaustive()
    }
}
impl QualifiedProviderRegistryV1 {
    fn resolve(
        config: &BootleLanternIssuanceRuntimeConfigV1,
        registry: Option<Arc<dyn BootleLanternIssuanceRuntimeProviderRegistryV1>>,
        bindings: &BootleLanternIssuanceRuntimeProviderBindingsV1,
    ) -> Result<(Self, BootleLanternIssuanceRuntimeSecretsV1), BootleLanternIssuanceApiErrorV1>
    {
        let inner = registry.ok_or(BootleLanternIssuanceApiErrorV1::ProviderMissing)?;
        let observed_handle = catch_unwind_suppressed(|| inner.handle().to_owned())
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        validate_production_runtime_handle(&observed_handle)
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderMismatch)?;
        if observed_handle != config.runtime_provider_registry_handle {
            return Err(BootleLanternIssuanceApiErrorV1::ProviderMismatch);
        }
        let qualification = catch_unwind_suppressed(|| inner.qualification())
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        let expected = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            config.runtime_provider_registry_revision,
            config.runtime_provider_registry_policy_digest,
        );
        if !qualification.is_valid() || qualification != expected {
            return Err(BootleLanternIssuanceApiErrorV1::ProviderMismatch);
        }
        let secrets = catch_unwind_suppressed(|| inner.resolve(bindings))
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        let qualified = Self {
            handle: config.runtime_provider_registry_handle.clone(),
            qualification,
            inner,
        };
        qualified.assert_current()?;
        Ok((qualified, secrets))
    }
    fn assert_current(&self) -> Result<(), BootleLanternIssuanceApiErrorV1> {
        let observed_handle = catch_unwind_suppressed(|| self.inner.handle().to_owned())
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        let current = catch_unwind_suppressed(|| self.inner.qualification())
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        if observed_handle != self.handle || !current.is_valid() || current != self.qualification {
            return Err(BootleLanternIssuanceApiErrorV1::ProviderDrift);
        }
        Ok(())
    }
}
/// Stable failure categories for runtime construction and operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BootleLanternIssuanceApiErrorV1 {
    /// Public runtime configuration is invalid.
    #[error("Bootle/Lantern issuance configuration is invalid")]
    ConfigurationInvalid,
    /// Required private provider registry was not supplied.
    #[error("Bootle/Lantern issuance provider registry is missing")]
    ProviderMissing,
    /// Registry identity or qualification differs from configuration.
    #[error("Bootle/Lantern issuance provider registry does not match configuration")]
    ProviderMismatch,
    /// Registry or one private provider is unavailable.
    #[error("Bootle/Lantern issuance provider is unavailable")]
    ProviderUnavailable,
    /// Registry identity or qualification changed during an operation.
    #[error("Bootle/Lantern issuance provider qualification drifted")]
    ProviderDrift,
    /// Committed capability, chain, or policy state is unavailable or invalid.
    #[error("Bootle/Lantern issuance committed policy is unavailable")]
    PolicyUnavailable,
    /// Durable issuance state could not be opened or mutated safely.
    #[error("Bootle/Lantern issuance durable state is unavailable")]
    DurableStateUnavailable,
    /// Request authentication failed.
    #[error("Bootle/Lantern issuance authentication failed")]
    Unauthorized,
    /// Request media type is missing, ambiguous, or unsupported.
    #[error("Bootle/Lantern issuance request media type is unsupported")]
    UnsupportedMediaType,
    /// Client does not accept the sole canonical response representation.
    #[error("Bootle/Lantern issuance response media type is not acceptable")]
    NotAcceptable,
    /// Canonical request body exceeds the endpoint's exact first-release size.
    #[error("Bootle/Lantern issuance request body is too large")]
    PayloadTooLarge,
    /// The configured native-issuance concurrency budget is exhausted.
    #[error("Bootle/Lantern issuance concurrency budget is exhausted")]
    TooManyRequests,
    /// Canonical request or authorization validation failed.
    #[error("Bootle/Lantern issuance request is invalid")]
    InvalidRequest,
    /// One-shot authorization state conflicts with this operation.
    #[error("Bootle/Lantern issuance authorization state conflicts")]
    StateConflict,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedIssuanceSnapshotV1 {
    committed_height: u64,
    canonical_genesis_hash: [u8; 32],
    context: PrivacyStatementContextV1,
    policy: BootleLanternIssuerPolicyV1,
}
struct IssuanceLinearizationGuardV1<'a> {
    provider_registry: &'a QualifiedProviderRegistryV1,
    committed_state: Option<(&'a CoreState, &'a BootleLanternIssuanceRuntimeConfigV1)>,
}
impl<'a> IssuanceLinearizationGuardV1<'a> {
    fn runtime(
        provider_registry: &'a QualifiedProviderRegistryV1,
        state: &'a CoreState,
        config: &'a BootleLanternIssuanceRuntimeConfigV1,
    ) -> Self {
        Self {
            provider_registry,
            committed_state: Some((state, config)),
        }
    }
    #[cfg(test)]
    fn provider_only(provider_registry: &'a QualifiedProviderRegistryV1) -> Self {
        Self {
            provider_registry,
            committed_state: None,
        }
    }
    fn assert_current(
        &self,
        expected: &CommittedIssuanceSnapshotV1,
        minimum_committed_height: u64,
        authorization_expires_at_height: Option<u64>,
        principal_expires_at_height: u64,
    ) -> Result<u64, BootleLanternIssuanceApiErrorV1> {
        self.provider_registry.assert_current()?;
        let current_height = if let Some((state, config)) = self.committed_state {
            let current = committed_snapshot_v1(state, config)?;
            self.provider_registry.assert_current()?;
            if current.committed_height < expected.committed_height
                || current.committed_height < minimum_committed_height
                || current.canonical_genesis_hash != expected.canonical_genesis_hash
                || current.context != expected.context
                || current.policy != expected.policy
            {
                return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
            }
            current.committed_height
        } else if expected.committed_height < minimum_committed_height {
            return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
        } else {
            expected.committed_height
        };
        if current_height > principal_expires_at_height {
            return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
        }
        if authorization_expires_at_height
            .is_some_and(|expires_at_height| current_height > expires_at_height)
        {
            return Err(BootleLanternIssuanceApiErrorV1::StateConflict);
        }
        Ok(current_height)
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IssuanceValidationLeaseKeyV1 {
    authorization_id: [u8; 32],
    authorization_digest: [u8; 32],
}
struct IssuanceValidationLeaseRegistryV1 {
    max_entries: usize,
    entries: Mutex<BTreeSet<IssuanceValidationLeaseKeyV1>>,
}
impl IssuanceValidationLeaseRegistryV1 {
    fn try_acquire(
        self: &Arc<Self>,
        key: IssuanceValidationLeaseKeyV1,
    ) -> Result<IssuanceValidationLeaseV1, BootleLanternIssuanceApiErrorV1> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        if entries.contains(&key) {
            return Err(BootleLanternIssuanceApiErrorV1::StateConflict);
        }
        if entries.len() >= self.max_entries {
            return Err(BootleLanternIssuanceApiErrorV1::TooManyRequests);
        }
        entries.insert(key);
        drop(entries);
        Ok(IssuanceValidationLeaseV1 {
            registry: Arc::clone(self),
            key,
        })
    }
    #[cfg(test)]
    fn active_count(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}
struct IssuanceValidationLeaseV1 {
    registry: Arc<IssuanceValidationLeaseRegistryV1>,
    key: IssuanceValidationLeaseKeyV1,
}
impl fmt::Debug for IssuanceValidationLeaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuanceValidationLeaseV1")
            .field("key", &"[REDACTED]")
            .finish()
    }
}
impl Drop for IssuanceValidationLeaseV1 {
    fn drop(&mut self) {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.remove(&self.key);
    }
}
struct IssuanceAdmissionV1 {
    inflight: Arc<Semaphore>,
    validation_leases: Arc<IssuanceValidationLeaseRegistryV1>,
}
impl IssuanceAdmissionV1 {
    fn new(max_inflight: usize) -> Self {
        Self {
            inflight: Arc::new(Semaphore::new(max_inflight)),
            validation_leases: Arc::new(IssuanceValidationLeaseRegistryV1 {
                max_entries: max_inflight,
                entries: Mutex::new(BTreeSet::new()),
            }),
        }
    }
    fn try_acquire_global(&self) -> Result<OwnedSemaphorePermit, BootleLanternIssuanceApiErrorV1> {
        Arc::clone(&self.inflight)
            .try_acquire_owned()
            .map_err(|_| BootleLanternIssuanceApiErrorV1::TooManyRequests)
    }
    fn try_acquire_validation(
        &self,
        _global_permit: &OwnedSemaphorePermit,
        key: IssuanceValidationLeaseKeyV1,
    ) -> Result<IssuanceValidationLeaseV1, BootleLanternIssuanceApiErrorV1> {
        self.validation_leases.try_acquire(key)
    }
}
fn validation_lease_key_v1(
    authorization: &BootleLanternIssuanceAuthorizationV1,
) -> IssuanceValidationLeaseKeyV1 {
    IssuanceValidationLeaseKeyV1 {
        authorization_id: authorization.authorization_id(),
        authorization_digest: authorization.authorization_digest(),
    }
}
fn bind_authenticated_issue_and_acquire_validation_lease_v1(
    admission: &IssuanceAdmissionV1,
    global_permit: &OwnedSemaphorePermit,
    authentication: Result<
        BootleLanternIssuanceAuthenticatedPrincipalV1,
        BootleLanternIssuanceApiErrorV1,
    >,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    committed_height: u64,
    authorization_lifetime_blocks: u64,
) -> Result<
    (
        BootleLanternIssuanceAuthenticatedPrincipalV1,
        IssuanceValidationLeaseV1,
    ),
    BootleLanternIssuanceApiErrorV1,
> {
    let principal = authentication?;
    if !constant_time_equal_32_v1(
        authorization.requester_authorization_digest(),
        principal.principal_digest,
    ) || authorization.issued_at_height() == 0
        || authorization.issued_at_height() > committed_height
        || authorization.expires_at_height() < authorization.issued_at_height()
        || authorization
            .expires_at_height()
            .checked_sub(authorization.issued_at_height())
            != Some(authorization_lifetime_blocks)
    {
        return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
    }
    let lease =
        admission.try_acquire_validation(global_permit, validation_lease_key_v1(authorization))?;
    Ok((principal, lease))
}
/// Torii-owned native issuance runtime.
pub struct BootleLanternIssuanceToriiRuntimeV1 {
    config: BootleLanternIssuanceRuntimeConfigV1,
    state: Arc<CoreState>,
    provider_registry: QualifiedProviderRegistryV1,
    issuer_provider: Arc<dyn BootleLanternIssuerCryptoProviderV1>,
    authenticator: Arc<dyn BootleLanternIssuanceAuthenticatorV1>,
    store: Arc<BootleLanternFileIssuanceStoreV1>,
    admission: IssuanceAdmissionV1,
}
impl fmt::Debug for BootleLanternIssuanceToriiRuntimeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootleLanternIssuanceToriiRuntimeV1")
            .field("issuer_id", &self.config.issuer_id)
            .field("policy_id", &self.config.policy_id)
            .field("state_dir", &self.config.state_dir)
            .field("max_inflight", &self.config.max_inflight)
            .field("private_providers", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl BootleLanternIssuanceToriiRuntimeV1 {
    /// Validate governance and provider identity, then open and recover the durable store.
    ///
    /// Recovery irreversibly fails every processing record observed at open; pruning runs only
    /// after recovery at the same authoritative committed height.
    ///
    /// # Errors
    ///
    /// Fails closed before serving if configuration, provider qualification,
    /// committed privacy state, issuer binding, or durable state is invalid.
    pub fn open(
        config: BootleLanternIssuanceRuntimeConfigV1,
        state: Arc<CoreState>,
        provider_registry: Option<Arc<dyn BootleLanternIssuanceRuntimeProviderRegistryV1>>,
    ) -> Result<Self, BootleLanternIssuanceApiErrorV1> {
        config.validate()?;
        let bindings = BootleLanternIssuanceRuntimeProviderBindingsV1::from_config(&config)?;
        let (provider_registry, secrets) =
            QualifiedProviderRegistryV1::resolve(&config, provider_registry, &bindings)?;
        let provider_ids = catch_unwind_suppressed(|| {
            (
                secrets.issuer_provider.issuer_id(),
                secrets.issuer_provider.policy_id(),
            )
        })
        .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        if provider_ids.0 != config.issuer_id || provider_ids.1 != config.policy_id {
            return Err(BootleLanternIssuanceApiErrorV1::ProviderMismatch);
        }
        let snapshot = committed_snapshot_v1(&state, &config)?;
        provider_registry.assert_current()?;
        let store = Arc::new(
            BootleLanternFileIssuanceStoreV1::open(&config.state_dir, config.store_config()?)
                .map_err(|_| BootleLanternIssuanceApiErrorV1::DurableStateUnavailable)?,
        );
        store
            .recover_processing_v1(snapshot.committed_height)
            .map_err(|_| BootleLanternIssuanceApiErrorV1::DurableStateUnavailable)?;
        store
            .prune_v1(snapshot.committed_height)
            .map_err(|_| BootleLanternIssuanceApiErrorV1::DurableStateUnavailable)?;
        provider_registry.assert_current()?;
        let admission = IssuanceAdmissionV1::new(config.max_inflight);
        Ok(Self {
            config,
            state,
            provider_registry,
            issuer_provider: secrets.issuer_provider,
            authenticator: secrets.authenticator,
            store,
            admission,
        })
    }
    /// Exact non-secret configuration used by this runtime.
    #[must_use]
    pub fn config(&self) -> &BootleLanternIssuanceRuntimeConfigV1 {
        &self.config
    }
    fn authenticate(
        &self,
        credential: &BootleLanternIssuanceCredentialV1,
        action: BootleLanternIssuanceActionV1,
        request_binding: [u8; 32],
        committed_height: u64,
    ) -> Result<BootleLanternIssuanceAuthenticatedPrincipalV1, BootleLanternIssuanceApiErrorV1>
    {
        self.provider_registry.assert_current()?;
        let principal = call_authenticator_v1(
            self.authenticator.as_ref(),
            credential.as_bytes(),
            action,
            request_binding,
            committed_height,
        )?;
        self.provider_registry.assert_current()?;
        validate_authenticated_principal_v1(principal, committed_height)?;
        Ok(principal)
    }
    fn authorize(
        &self,
        credential: &BootleLanternIssuanceCredentialV1,
        _global_permit: &OwnedSemaphorePermit,
    ) -> Result<Vec<u8>, BootleLanternIssuanceApiErrorV1> {
        self.provider_registry.assert_current()?;
        let snapshot = committed_snapshot_v1(&self.state, &self.config)?;
        let request_binding = request_binding_v1(
            AUTHORIZE_BINDING_DOMAIN_V1,
            &[],
            snapshot.committed_height,
            snapshot.canonical_genesis_hash,
        )?;
        let principal = self.authenticate(
            credential,
            BootleLanternIssuanceActionV1::Authorize,
            request_binding,
            snapshot.committed_height,
        )?;
        let expires_at_height = snapshot
            .committed_height
            .checked_add(self.config.authorization_lifetime_blocks)
            .ok_or(BootleLanternIssuanceApiErrorV1::InvalidRequest)?;
        if principal.expires_at_height < expires_at_height {
            return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
        }
        self.store
            .prune_v1(snapshot.committed_height)
            .map_err(|_| BootleLanternIssuanceApiErrorV1::DurableStateUnavailable)?;
        let guard = IssuanceLinearizationGuardV1::runtime(
            &self.provider_registry,
            &self.state,
            &self.config,
        );
        prepare_and_register_authorization_v1(
            &guard,
            self.issuer_provider.as_ref(),
            self.store.as_ref(),
            &snapshot,
            principal.principal_digest,
            expires_at_height,
            principal.expires_at_height,
        )
    }
    fn issue(
        &self,
        credential: &BootleLanternIssuanceCredentialV1,
        body: &[u8],
        global_permit: &OwnedSemaphorePermit,
    ) -> Result<Vec<u8>, BootleLanternIssuanceApiErrorV1> {
        if body.len() != BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1 {
            return Err(BootleLanternIssuanceApiErrorV1::InvalidRequest);
        }
        let (authorization_bytes, request_bytes) =
            body.split_at(BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1);
        let authorization = BootleLanternIssuanceAuthorizationV1::decode_exact(authorization_bytes)
            .map_err(|_| BootleLanternIssuanceApiErrorV1::InvalidRequest)?;
        self.provider_registry.assert_current()?;
        let snapshot = committed_snapshot_v1(&self.state, &self.config)?;
        let request_binding = request_binding_v1(
            ISSUE_BINDING_DOMAIN_V1,
            body,
            snapshot.committed_height,
            snapshot.canonical_genesis_hash,
        )?;
        let (principal, _validation_lease) =
            bind_authenticated_issue_and_acquire_validation_lease_v1(
                &self.admission,
                global_permit,
                self.authenticate(
                    credential,
                    BootleLanternIssuanceActionV1::Issue,
                    request_binding,
                    snapshot.committed_height,
                ),
                &authorization,
                snapshot.committed_height,
                self.config.authorization_lifetime_blocks,
            )?;
        let guard = IssuanceLinearizationGuardV1::runtime(
            &self.provider_registry,
            &self.state,
            &self.config,
        );
        issue_registered_request_v1(
            &guard,
            self.issuer_provider.as_ref(),
            self.store.as_ref(),
            &snapshot,
            &authorization,
            request_bytes,
            principal.expires_at_height,
        )
    }
}
fn prepare_and_register_authorization_v1(
    guard: &IssuanceLinearizationGuardV1<'_>,
    issuer_provider: &dyn BootleLanternIssuerCryptoProviderV1,
    store: &dyn BootleLanternIssuanceStoreV1,
    snapshot: &CommittedIssuanceSnapshotV1,
    principal_digest: [u8; 32],
    expires_at_height: u64,
    principal_expires_at_height: u64,
) -> Result<Vec<u8>, BootleLanternIssuanceApiErrorV1> {
    for _ in 0..MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1 {
        guard.assert_current(
            snapshot,
            snapshot.committed_height,
            Some(expires_at_height),
            principal_expires_at_height,
        )?;
        let authorization = call_issuer_provider_v1(|| {
            issuer_provider.prepare_authorization(
                &snapshot.context,
                snapshot.canonical_genesis_hash,
                &snapshot.policy,
                principal_digest,
                snapshot.committed_height,
                expires_at_height,
            )
        })?;
        guard.assert_current(
            snapshot,
            snapshot.committed_height,
            Some(expires_at_height),
            principal_expires_at_height,
        )?;
        validate_authorization_output_fields_v1(
            authorization.requester_authorization_digest(),
            authorization.issued_at_height(),
            authorization.expires_at_height(),
            principal_digest,
            snapshot.committed_height,
            expires_at_height,
        )?;
        issuer_validate_prepared_blind_issuance_authorization_v1(
            &snapshot.context,
            snapshot.canonical_genesis_hash,
            &snapshot.policy,
            &authorization,
        )
        .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        let bytes = authorization
            .encode()
            .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?;
        if bytes.len() != BOOTLE_LANTERN_ISSUANCE_AUTHORIZATION_RESPONSE_BYTES_V1 {
            return Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable);
        }
        match BootleLanternIssuanceAuthorizationV1::decode_exact(&bytes) {
            Ok(decoded) if decoded == authorization => {}
            Ok(_) | Err(_) => {
                return Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable);
            }
        }
        guard.assert_current(
            snapshot,
            snapshot.committed_height,
            Some(expires_at_height),
            principal_expires_at_height,
        )?;
        match store.register_fresh_v1(
            authorization.authorization_id(),
            authorization.authorization_digest(),
            authorization.issued_at_height(),
            authorization.expires_at_height(),
        ) {
            Ok(()) => {
                guard.assert_current(
                    snapshot,
                    snapshot.committed_height,
                    Some(expires_at_height),
                    principal_expires_at_height,
                )?;
                return Ok(bytes);
            }
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists) => {}
            Err(_) => return Err(BootleLanternIssuanceApiErrorV1::DurableStateUnavailable),
        }
    }
    Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable)
}
fn issue_registered_request_v1(
    guard: &IssuanceLinearizationGuardV1<'_>,
    issuer_provider: &dyn BootleLanternIssuerCryptoProviderV1,
    store: &dyn BootleLanternIssuanceStoreV1,
    snapshot: &CommittedIssuanceSnapshotV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    principal_expires_at_height: u64,
) -> Result<Vec<u8>, BootleLanternIssuanceApiErrorV1> {
    let mut current_height = guard.assert_current(
        snapshot,
        snapshot.committed_height,
        None,
        principal_expires_at_height,
    )?;
    let request_max = u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1)
        .map_err(|_| BootleLanternIssuanceApiErrorV1::InvalidRequest)?;
    let request = BootleLanternBlindIssuanceRequestV1::decode_exact(request_bytes, request_max)
        .map_err(|_| BootleLanternIssuanceApiErrorV1::InvalidRequest)?;
    let request_digest = request.request_digest();
    match store.preflight_v1(
        authorization.authorization_id(),
        authorization.authorization_digest(),
        request_digest,
        current_height,
    ) {
        Ok(BootleLanternIssuancePreflightV1::Completed(response_bytes)) => {
            let canonical = validate_cached_response_bytes_v1(
                snapshot,
                authorization,
                request_bytes,
                &response_bytes,
            )?;
            guard.assert_current(snapshot, current_height, None, principal_expires_at_height)?;
            return Ok(canonical);
        }
        Ok(BootleLanternIssuancePreflightV1::Fresh) => {}
        Err(error) => return Err(map_store_replay_error_v1(error)),
    }
    let locally_validated_digest = issuer_validate_blind_issuance_request_encoded_v1(
        &snapshot.context,
        snapshot.canonical_genesis_hash,
        &snapshot.policy,
        authorization,
        request_bytes,
        current_height,
    )
    .map_err(map_public_request_error_v1)?;
    if !constant_time_equal_32_v1(locally_validated_digest, request_digest) {
        return Err(BootleLanternIssuanceApiErrorV1::InvalidRequest);
    }
    current_height = guard.assert_current(
        snapshot,
        current_height,
        Some(authorization.expires_at_height()),
        principal_expires_at_height,
    )?;
    let provider_validated_digest = call_issuer_provider_v1(|| {
        issuer_provider.validate_request(
            &snapshot.context,
            snapshot.canonical_genesis_hash,
            &snapshot.policy,
            authorization,
            request_bytes,
            current_height,
        )
    })?;
    current_height = guard.assert_current(
        snapshot,
        current_height,
        Some(authorization.expires_at_height()),
        principal_expires_at_height,
    )?;
    if !constant_time_equal_32_v1(provider_validated_digest, request_digest) {
        return Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable);
    }
    current_height = guard.assert_current(
        snapshot,
        current_height,
        Some(authorization.expires_at_height()),
        principal_expires_at_height,
    )?;
    match store.claim_v1(
        authorization.authorization_id(),
        authorization.authorization_digest(),
        request_digest,
        current_height,
    ) {
        Ok(BootleLanternIssuanceClaimV1::Completed(response_bytes)) => {
            let canonical = validate_cached_response_bytes_v1(
                snapshot,
                authorization,
                request_bytes,
                &response_bytes,
            )?;
            guard.assert_current(snapshot, current_height, None, principal_expires_at_height)?;
            return Ok(canonical);
        }
        Ok(BootleLanternIssuanceClaimV1::Fresh) => {}
        Err(error) => return Err(map_store_replay_error_v1(error)),
    }
    let issue_height = match guard.assert_current(
        snapshot,
        current_height,
        Some(authorization.expires_at_height()),
        principal_expires_at_height,
    ) {
        Ok(height) => height,
        Err(error) => {
            return Err(fail_claim_or_durable_v1(
                store,
                authorization,
                request_digest,
                current_height,
                error,
            ));
        }
    };
    let response = match call_issuer_provider_v1(|| {
        issuer_provider.issue_validated(
            &snapshot.context,
            snapshot.canonical_genesis_hash,
            &snapshot.policy,
            authorization,
            request_bytes,
            issue_height,
        )
    }) {
        Ok(response) => response,
        Err(error) => {
            return Err(fail_claim_or_durable_v1(
                store,
                authorization,
                request_digest,
                issue_height,
                error,
            ));
        }
    };
    let response_validated_height = match guard.assert_current(
        snapshot,
        issue_height,
        Some(authorization.expires_at_height()),
        principal_expires_at_height,
    ) {
        Ok(height) => height,
        Err(error) => {
            return Err(fail_claim_or_durable_v1(
                store,
                authorization,
                request_digest,
                issue_height,
                error,
            ));
        }
    };
    let bytes = match response.encode() {
        Ok(bytes) if bytes.len() == BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1 => bytes,
        _ => {
            return Err(fail_claim_or_durable_v1(
                store,
                authorization,
                request_digest,
                response_validated_height,
                BootleLanternIssuanceApiErrorV1::ProviderUnavailable,
            ));
        }
    };
    if issuer_validate_cached_blind_issuance_response_encoded_v1(
        &snapshot.context,
        snapshot.canonical_genesis_hash,
        &snapshot.policy,
        authorization,
        request_bytes,
        &bytes,
    )
    .is_err()
    {
        return Err(fail_claim_or_durable_v1(
            store,
            authorization,
            request_digest,
            response_validated_height,
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable,
        ));
    }
    let completion_height = match guard.assert_current(
        snapshot,
        response_validated_height,
        Some(authorization.expires_at_height()),
        principal_expires_at_height,
    ) {
        Ok(height) => height,
        Err(error) => {
            return Err(fail_claim_or_durable_v1(
                store,
                authorization,
                request_digest,
                response_validated_height,
                error,
            ));
        }
    };
    if store
        .complete_v1(
            authorization.authorization_id(),
            authorization.authorization_digest(),
            request_digest,
            &bytes,
            completion_height,
        )
        .is_err()
    {
        let _ = store.fail_v1(
            authorization.authorization_id(),
            authorization.authorization_digest(),
            request_digest,
            completion_height,
        );
        return Err(BootleLanternIssuanceApiErrorV1::DurableStateUnavailable);
    }
    guard.assert_current(
        snapshot,
        completion_height,
        None,
        principal_expires_at_height,
    )?;
    Ok(bytes)
}
fn fail_claim_or_durable_v1(
    store: &dyn BootleLanternIssuanceStoreV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_digest: [u8; 32],
    current_height: u64,
    primary_error: BootleLanternIssuanceApiErrorV1,
) -> BootleLanternIssuanceApiErrorV1 {
    match store.fail_v1(
        authorization.authorization_id(),
        authorization.authorization_digest(),
        request_digest,
        current_height,
    ) {
        Ok(()) => primary_error,
        Err(_) => BootleLanternIssuanceApiErrorV1::DurableStateUnavailable,
    }
}
fn committed_snapshot_v1(
    state: &CoreState,
    config: &BootleLanternIssuanceRuntimeConfigV1,
) -> Result<CommittedIssuanceSnapshotV1, BootleLanternIssuanceApiErrorV1> {
    let view = state.view();
    let capabilities = view
        .privacy_capability_snapshot_v1()
        .map_err(|_| BootleLanternIssuanceApiErrorV1::PolicyUnavailable)?;
    capabilities
        .validate()
        .map_err(|_| BootleLanternIssuanceApiErrorV1::PolicyUnavailable)?;
    let row = capabilities
        .protocols
        .iter()
        .find(|row| row.protocol_id == PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1)
        .ok_or(BootleLanternIssuanceApiErrorV1::PolicyUnavailable)?;
    let profile = match row.compiled_profile {
        PrivacyCompiledProfileResultV1::Available(profile) => profile,
        PrivacyCompiledProfileResultV1::Unavailable(_) => {
            return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
        }
    };
    let activation = view
        .qualified_privacy_activation_v1(PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1)
        .map_err(|_| BootleLanternIssuanceApiErrorV1::PolicyUnavailable)?;
    let committed_height = capabilities.committed_height;
    if committed_height == 0
        || committed_height
            != u64::try_from(view.height())
                .map_err(|_| BootleLanternIssuanceApiErrorV1::PolicyUnavailable)?
    {
        return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
    }
    let canonical_genesis_hash = view
        .block_hashes()
        .first()
        .map(|hash| *hash.as_ref())
        .filter(|hash| *hash != [0; 32])
        .ok_or(BootleLanternIssuanceApiErrorV1::PolicyUnavailable)?;
    if view.network_id().as_bytes() != &canonical_genesis_hash {
        return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
    }
    let policy = view
        .world()
        .privacy_bootle_lantern_issuer_policy_v1(config.issuer_id, config.policy_id)
        .map_err(|_| BootleLanternIssuanceApiErrorV1::PolicyUnavailable)?;
    if policy.issuer_id != config.issuer_id
        || policy.policy_id != config.policy_id
        || policy.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active
        || policy.validate().is_err()
    {
        return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
    }
    let context = PrivacyStatementContextV1 {
        network_id: *view.network_id(),
        action_index: 0,
        transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(context_intent_digest_v1(
            view.network_id().as_bytes(),
            canonical_genesis_hash,
            policy.record_digest.as_bytes(),
        )?),
        parameter_id: activation.parameter_id,
        parameter_digest: activation.parameter_digest,
        verifier_digest: activation.verifier_digest,
        statement_schema_digest: activation.statement_schema_digest,
        engine_manifest_digest: activation.engine_manifest_digest,
    };
    if profile.parameter_id != context.parameter_id
        || profile.parameter_digest != context.parameter_digest
        || profile.verifier_digest != context.verifier_digest
        || profile.statement_schema_digest != context.statement_schema_digest
        || profile.engine_manifest_digest != context.engine_manifest_digest
        || context
            .validate(&capabilities.consensus_policy.current_limits)
            .is_err()
    {
        return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
    }
    Ok(CommittedIssuanceSnapshotV1 {
        committed_height,
        canonical_genesis_hash,
        context,
        policy,
    })
}
fn context_intent_digest_v1(
    network_id: &[u8; 32],
    canonical_genesis_hash: [u8; 32],
    policy_record_digest: &[u8; 32],
) -> Result<[u8; 32], BootleLanternIssuanceApiErrorV1> {
    let mut hasher = Sha256::new();
    hash_frame_v1(&mut hasher, CONTEXT_INTENT_DOMAIN_V1)?;
    hash_frame_v1(&mut hasher, network_id)?;
    hash_frame_v1(&mut hasher, &canonical_genesis_hash)?;
    hash_frame_v1(&mut hasher, policy_record_digest)?;
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable);
    }
    Ok(digest)
}
fn request_binding_v1(
    domain: &[u8],
    body: &[u8],
    committed_height: u64,
    canonical_genesis_hash: [u8; 32],
) -> Result<[u8; 32], BootleLanternIssuanceApiErrorV1> {
    let mut hasher = Sha256::new();
    hash_frame_v1(&mut hasher, domain)?;
    hash_frame_v1(&mut hasher, &committed_height.to_be_bytes())?;
    hash_frame_v1(&mut hasher, &canonical_genesis_hash)?;
    hash_frame_v1(&mut hasher, body)?;
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(BootleLanternIssuanceApiErrorV1::InvalidRequest);
    }
    Ok(digest)
}
fn hash_frame_v1(hasher: &mut Sha256, value: &[u8]) -> Result<(), BootleLanternIssuanceApiErrorV1> {
    let length =
        u64::try_from(value.len()).map_err(|_| BootleLanternIssuanceApiErrorV1::InvalidRequest)?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}
fn constant_time_equal_32_v1(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut difference = 0_u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}
fn validate_authenticated_principal_v1(
    principal: BootleLanternIssuanceAuthenticatedPrincipalV1,
    committed_height: u64,
) -> Result<(), BootleLanternIssuanceApiErrorV1> {
    if principal.principal_digest == [0; 32]
        || principal.issued_at_height == 0
        || principal.issued_at_height > committed_height
        || principal.expires_at_height < committed_height
        || principal.expires_at_height < principal.issued_at_height
    {
        return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
    }
    Ok(())
}
fn validate_authorization_output_fields_v1(
    actual_principal_digest: [u8; 32],
    actual_issued_at_height: u64,
    actual_expires_at_height: u64,
    expected_principal_digest: [u8; 32],
    expected_issued_at_height: u64,
    expected_expires_at_height: u64,
) -> Result<(), BootleLanternIssuanceApiErrorV1> {
    if !constant_time_equal_32_v1(actual_principal_digest, expected_principal_digest)
        || actual_issued_at_height != expected_issued_at_height
        || actual_expires_at_height != expected_expires_at_height
    {
        return Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable);
    }
    Ok(())
}
fn call_issuer_provider_v1<T>(
    operation: impl FnOnce() -> Result<T, BootleLanternIssuerCryptoProviderErrorV1>,
) -> Result<T, BootleLanternIssuanceApiErrorV1> {
    catch_unwind_suppressed(operation)
        .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?
        .map_err(map_provider_error_v1)
}
fn call_authenticator_v1(
    authenticator: &dyn BootleLanternIssuanceAuthenticatorV1,
    opaque_credential: &[u8],
    action: BootleLanternIssuanceActionV1,
    request_binding: [u8; 32],
    committed_height: u64,
) -> Result<BootleLanternIssuanceAuthenticatedPrincipalV1, BootleLanternIssuanceApiErrorV1> {
    catch_unwind_suppressed(|| {
        authenticator.authenticate(opaque_credential, action, request_binding, committed_height)
    })
    .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?
    .map_err(|error| match error {
        BootleLanternIssuanceAuthenticationErrorV1::Denied => {
            BootleLanternIssuanceApiErrorV1::Unauthorized
        }
        BootleLanternIssuanceAuthenticationErrorV1::Unavailable => {
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        }
    })
}
fn map_provider_error_v1(
    error: BootleLanternIssuerCryptoProviderErrorV1,
) -> BootleLanternIssuanceApiErrorV1 {
    match error {
        BootleLanternIssuerCryptoProviderErrorV1::InvalidRequest => {
            BootleLanternIssuanceApiErrorV1::InvalidRequest
        }
        BootleLanternIssuerCryptoProviderErrorV1::PolicyMismatch => {
            BootleLanternIssuanceApiErrorV1::PolicyUnavailable
        }
        BootleLanternIssuerCryptoProviderErrorV1::Unavailable => {
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        }
    }
}
fn map_public_request_error_v1(
    error: BootleLanternIssuanceErrorV1,
) -> BootleLanternIssuanceApiErrorV1 {
    use BootleLanternIssuanceErrorV1 as CoreError;
    match error {
        CoreError::IssuerKeyPolicyMismatch
        | CoreError::InvalidIssuerPolicy
        | CoreError::IssuerPolicyNotActive => BootleLanternIssuanceApiErrorV1::PolicyUnavailable,
        CoreError::AuthorizationNotYetValid
        | CoreError::AuthorizationExpired
        | CoreError::AuthorizationBusy
        | CoreError::AuthorizationConsumed => BootleLanternIssuanceApiErrorV1::StateConflict,
        CoreError::IssuanceStoreFailed
        | CoreError::RandomnessUnavailable
        | CoreError::RandomnessUnhealthy
        | CoreError::IssuerKeyGenerationExhausted
        | CoreError::AuthorizationIdExhausted
        | CoreError::PreimageSamplingExhausted => {
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        }
        _ => BootleLanternIssuanceApiErrorV1::InvalidRequest,
    }
}
fn map_store_replay_error_v1(
    error: BootleLanternIssuanceStoreErrorV1,
) -> BootleLanternIssuanceApiErrorV1 {
    match error {
        BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed
        | BootleLanternIssuanceStoreErrorV1::AuthorizationNotYetValid
        | BootleLanternIssuanceStoreErrorV1::AuthorizationExpired
        | BootleLanternIssuanceStoreErrorV1::Busy => BootleLanternIssuanceApiErrorV1::StateConflict,
        BootleLanternIssuanceStoreErrorV1::InvalidInput => {
            BootleLanternIssuanceApiErrorV1::InvalidRequest
        }
        BootleLanternIssuanceStoreErrorV1::ConfigurationInvalid
        | BootleLanternIssuanceStoreErrorV1::AuthorizationExists
        | BootleLanternIssuanceStoreErrorV1::CapacityExceeded
        | BootleLanternIssuanceStoreErrorV1::StoreAlreadyOpen
        | BootleLanternIssuanceStoreErrorV1::UnsupportedPlatform
        | BootleLanternIssuanceStoreErrorV1::Corrupt
        | BootleLanternIssuanceStoreErrorV1::Backend => {
            BootleLanternIssuanceApiErrorV1::DurableStateUnavailable
        }
    }
}
fn validate_cached_response_bytes_v1(
    snapshot: &CommittedIssuanceSnapshotV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<Vec<u8>, BootleLanternIssuanceApiErrorV1> {
    if response_bytes.len() != BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1 {
        return Err(BootleLanternIssuanceApiErrorV1::DurableStateUnavailable);
    }
    let response = issuer_validate_cached_blind_issuance_response_encoded_v1(
        &snapshot.context,
        snapshot.canonical_genesis_hash,
        &snapshot.policy,
        authorization,
        request_bytes,
        response_bytes,
    )
    .map_err(|_| BootleLanternIssuanceApiErrorV1::DurableStateUnavailable)?;
    let canonical = response
        .encode()
        .map_err(|_| BootleLanternIssuanceApiErrorV1::DurableStateUnavailable)?;
    if canonical.as_slice() != response_bytes {
        return Err(BootleLanternIssuanceApiErrorV1::DurableStateUnavailable);
    }
    Ok(canonical)
}
struct BootleLanternIssuanceCredentialV1 {
    bytes: Vec<u8>,
}
impl BootleLanternIssuanceCredentialV1 {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for BootleLanternIssuanceCredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootleLanternIssuanceCredentialV1([REDACTED])")
    }
}
impl Drop for BootleLanternIssuanceCredentialV1 {
    fn drop(&mut self) {
        erase_bytes_v1(&mut self.bytes);
    }
}
fn erase_bytes_v1(bytes: &mut [u8]) {
    bytes.fill(0);
    black_box(bytes);
}
fn mark_authorization_sensitive_v1(headers: &mut HeaderMap) {
    for (name, value) in headers.iter_mut() {
        if name == AUTHORIZATION {
            value.set_sensitive(true);
        }
    }
}
fn parse_bearer_v1(
    headers: &HeaderMap,
) -> Result<BootleLanternIssuanceCredentialV1, BootleLanternIssuanceApiErrorV1> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .ok_or(BootleLanternIssuanceApiErrorV1::Unauthorized)?;
    let encoded = value
        .strip_prefix("Bearer ")
        .ok_or(BootleLanternIssuanceApiErrorV1::Unauthorized)?;
    let encoded_max = encoded_len(BOOTLE_LANTERN_ISSUANCE_AUTHENTICATION_MAX_BYTES_V1, false)
        .ok_or(BootleLanternIssuanceApiErrorV1::Unauthorized)?;
    if encoded.is_empty()
        || encoded.len() > encoded_max
        || encoded
            .bytes()
            .any(|byte| byte == b'=' || byte.is_ascii_whitespace())
    {
        return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
    }
    // Decode into a fixed, pre-zeroed allocation so even a decoder error over
    // a valid secret prefix is explicitly erased instead of being dropped in
    // an opaque base64-owned temporary.
    let mut decoded = vec![0_u8; BOOTLE_LANTERN_ISSUANCE_AUTHENTICATION_MAX_BYTES_V1];
    let written = match URL_SAFE_NO_PAD.decode_slice(encoded, &mut decoded) {
        Ok(written) => written,
        Err(_) => {
            erase_bytes_v1(&mut decoded);
            return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
        }
    };
    decoded.truncate(written);
    if decoded.is_empty() {
        erase_bytes_v1(&mut decoded);
        return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
    }
    // `base64` correctly validates the alphabet and padding policy, while the
    // round trip below rejects alternate trailing-bit representations. The
    // re-encoded credential is secret too, so erase its scratch allocation on
    // both success and failure.
    let canonical_len = match encoded_len(decoded.len(), false) {
        Some(canonical_len) => canonical_len,
        None => {
            erase_bytes_v1(&mut decoded);
            return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
        }
    };
    let mut canonical = vec![0_u8; canonical_len];
    let canonical_matches = URL_SAFE_NO_PAD
        .encode_slice(&decoded, &mut canonical)
        .is_ok_and(|canonical_written| {
            canonical_written == canonical.len() && canonical.as_slice() == encoded.as_bytes()
        });
    erase_bytes_v1(&mut canonical);
    if !canonical_matches {
        erase_bytes_v1(&mut decoded);
        return Err(BootleLanternIssuanceApiErrorV1::Unauthorized);
    }
    Ok(BootleLanternIssuanceCredentialV1::new(decoded))
}
fn validate_transport_headers_v1(
    headers: &HeaderMap,
    exact_body_bytes: usize,
) -> Result<(), BootleLanternIssuanceApiErrorV1> {
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    let exact_content_type = content_types
        .next()
        .filter(|_| content_types.next().is_none())
        .is_some_and(|value| {
            value.as_bytes() == BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1.as_bytes()
        });
    if !exact_content_type || headers.get_all(CONTENT_ENCODING).iter().next().is_some() {
        return Err(BootleLanternIssuanceApiErrorV1::UnsupportedMediaType);
    }
    let mut accepts = headers.get_all(ACCEPT).iter();
    let exact_accept = accepts
        .next()
        .filter(|_| accepts.next().is_none())
        .is_some_and(|value| {
            value.as_bytes() == BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1.as_bytes()
        });
    if !exact_accept {
        return Err(BootleLanternIssuanceApiErrorV1::NotAcceptable);
    }
    if headers.get_all(TRANSFER_ENCODING).iter().next().is_some() {
        return Err(BootleLanternIssuanceApiErrorV1::InvalidRequest);
    }
    let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
    let content_length = content_lengths
        .next()
        .filter(|_| content_lengths.next().is_none())
        .ok_or(BootleLanternIssuanceApiErrorV1::InvalidRequest)?;
    let encoded_length = content_length.as_bytes();
    if encoded_length.is_empty()
        || (encoded_length != b"0"
            && (encoded_length[0] == b'0' || !encoded_length.iter().all(u8::is_ascii_digit)))
    {
        return Err(BootleLanternIssuanceApiErrorV1::InvalidRequest);
    }
    let parsed_length = match content_length
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        Some(parsed_length) => parsed_length,
        None => return Err(BootleLanternIssuanceApiErrorV1::PayloadTooLarge),
    };
    let exact_body_bytes = u64::try_from(exact_body_bytes)
        .map_err(|_| BootleLanternIssuanceApiErrorV1::InvalidRequest)?;
    if parsed_length > exact_body_bytes {
        return Err(BootleLanternIssuanceApiErrorV1::PayloadTooLarge);
    }
    if parsed_length != exact_body_bytes {
        return Err(BootleLanternIssuanceApiErrorV1::InvalidRequest);
    }
    Ok(())
}
async fn collect_exact_body_v1(
    body: Body,
    exact_bytes: usize,
) -> Result<Bytes, BootleLanternIssuanceApiErrorV1> {
    let bytes = axum::body::to_bytes(body, exact_bytes)
        .await
        .map_err(|error| {
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            while let Some(current) = source {
                if current.is::<http_body_util::LengthLimitError>() {
                    return BootleLanternIssuanceApiErrorV1::PayloadTooLarge;
                }
                source = current.source();
            }
            BootleLanternIssuanceApiErrorV1::InvalidRequest
        })?;
    if bytes.len() != exact_bytes {
        return Err(BootleLanternIssuanceApiErrorV1::InvalidRequest);
    }
    Ok(bytes)
}
fn hardened_response_v1(mut response: Response) -> Response {
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}
fn success_response_v1(bytes: Vec<u8>) -> Response {
    let (content_length, expected_magic) = match bytes.len() {
        BOOTLE_LANTERN_ISSUANCE_AUTHORIZATION_RESPONSE_BYTES_V1 => {
            (HeaderValue::from_static("320"), b"ILA1".as_slice())
        }
        BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1 => {
            (HeaderValue::from_static("3176"), b"ILR1".as_slice())
        }
        _ => {
            return error_response_v1(BootleLanternIssuanceApiErrorV1::ProviderUnavailable);
        }
    };
    if !bytes.starts_with(expected_magic) {
        return error_response_v1(BootleLanternIssuanceApiErrorV1::ProviderUnavailable);
    }
    let mut response = (StatusCode::OK, bytes).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1),
    );
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, content_length);
    hardened_response_v1(response)
}
fn error_response_v1(error: BootleLanternIssuanceApiErrorV1) -> Response {
    let (status, code) = match error {
        BootleLanternIssuanceApiErrorV1::Unauthorized => {
            (StatusCode::UNAUTHORIZED, "privacy_issuance_unauthorized")
        }
        BootleLanternIssuanceApiErrorV1::UnsupportedMediaType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "privacy_issuance_unsupported_media_type",
        ),
        BootleLanternIssuanceApiErrorV1::NotAcceptable => (
            StatusCode::NOT_ACCEPTABLE,
            "privacy_issuance_not_acceptable",
        ),
        BootleLanternIssuanceApiErrorV1::PayloadTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "privacy_issuance_payload_too_large",
        ),
        BootleLanternIssuanceApiErrorV1::TooManyRequests => (
            StatusCode::TOO_MANY_REQUESTS,
            "privacy_issuance_capacity_exhausted",
        ),
        BootleLanternIssuanceApiErrorV1::InvalidRequest
        | BootleLanternIssuanceApiErrorV1::ConfigurationInvalid => {
            (StatusCode::BAD_REQUEST, "privacy_issuance_invalid_request")
        }
        BootleLanternIssuanceApiErrorV1::StateConflict => {
            (StatusCode::CONFLICT, "privacy_issuance_state_conflict")
        }
        BootleLanternIssuanceApiErrorV1::ProviderMissing
        | BootleLanternIssuanceApiErrorV1::ProviderMismatch
        | BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        | BootleLanternIssuanceApiErrorV1::ProviderDrift
        | BootleLanternIssuanceApiErrorV1::PolicyUnavailable
        | BootleLanternIssuanceApiErrorV1::DurableStateUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "privacy_issuance_unavailable",
        ),
    };
    let response_format = if status == StatusCode::NOT_ACCEPTABLE {
        crate::utils::ResponseFormat::Json
    } else {
        crate::utils::ResponseFormat::Norito
    };
    let envelope = iroha_torii_shared::ErrorEnvelope::new(code, code);
    let mut response =
        crate::utils::respond_with_status_and_format(status, envelope, response_format);
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static(WWW_AUTHENTICATE_VALUE_V1),
        );
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    }
    hardened_response_v1(response)
}
/// Return the hardened fail-closed response used when issuance is not configured.
///
/// Keeping the canonical routes mounted while returning this response avoids
/// exposing node-local configuration through route discovery.
#[must_use]
pub fn bootle_lantern_issuance_unavailable_response_v1() -> Response {
    error_response_v1(BootleLanternIssuanceApiErrorV1::ProviderUnavailable)
}
async fn execute_admitted_blocking_v1<F>(
    permit: OwnedSemaphorePermit,
    operation: F,
) -> Result<Vec<u8>, BootleLanternIssuanceApiErrorV1>
where
    F: FnOnce(&OwnedSemaphorePermit) -> Result<Vec<u8>, BootleLanternIssuanceApiErrorV1>
        + Send
        + 'static,
{
    crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
        move || operation(&permit),
    ))
    .await
    .map_err(|_| BootleLanternIssuanceApiErrorV1::ProviderUnavailable)?
}
/// Handle `POST` authorization requests with an exact empty body.
pub async fn handle_post_bootle_lantern_issuance_authorize(
    State(runtime): State<Arc<BootleLanternIssuanceToriiRuntimeV1>>,
    mut request: Request<Body>,
) -> Response {
    mark_authorization_sensitive_v1(request.headers_mut());
    if let Err(error) = validate_transport_headers_v1(request.headers(), 0) {
        return error_response_v1(error);
    }
    let credential = match parse_bearer_v1(request.headers()) {
        Ok(credential) => credential,
        Err(error) => return error_response_v1(error),
    };
    let body = match collect_exact_body_v1(request.into_body(), 0).await {
        Ok(body) => body,
        Err(error) => return error_response_v1(error),
    };
    drop(body);
    let permit = match runtime.admission.try_acquire_global() {
        Ok(permit) => permit,
        Err(error) => return error_response_v1(error),
    };
    match execute_admitted_blocking_v1(permit, move |permit| runtime.authorize(&credential, permit))
        .await
    {
        Ok(bytes) => success_response_v1(bytes),
        Err(error) => error_response_v1(error),
    }
}
/// Handle `POST` issue requests containing exactly `ILA1 || ILQ1`.
pub async fn handle_post_bootle_lantern_issuance_issue(
    State(runtime): State<Arc<BootleLanternIssuanceToriiRuntimeV1>>,
    mut request: Request<Body>,
) -> Response {
    mark_authorization_sensitive_v1(request.headers_mut());
    if let Err(error) = validate_transport_headers_v1(
        request.headers(),
        BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
    ) {
        return error_response_v1(error);
    }
    let credential = match parse_bearer_v1(request.headers()) {
        Ok(credential) => credential,
        Err(error) => return error_response_v1(error),
    };
    let body = match collect_exact_body_v1(
        request.into_body(),
        BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
    )
    .await
    {
        Ok(body) => body,
        Err(error) => return error_response_v1(error),
    };
    let permit = match runtime.admission.try_acquire_global() {
        Ok(permit) => permit,
        Err(error) => return error_response_v1(error),
    };
    match execute_admitted_blocking_v1(permit, move |permit| {
        runtime.issue(&credential, &body, permit)
    })
    .await
    {
        Ok(bytes) => success_response_v1(bytes),
        Err(error) => error_response_v1(error),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use iroha_core_privacy::privacy_engines::bootle_lantern::issuer::{
        BootleLanternInMemoryIssuanceStoreV1, BootleLanternIssuerKeyPairV1,
        BootleLanternIssuerPolicyMetadataV1, holder_prepare_blind_issuance_with_rng_v1,
        issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1,
        issuer_prepare_blind_issuance_authorization_candidate_with_rng_v1,
        issuer_validate_blind_issuance_request_for_issuer_encoded_v1,
    };
    use iroha_data_model::privacy::{
        BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1, BootleLanternAllowedAttributeValuesV1,
        BootleLanternAttributeValueV1, PrivacyEngineManifestDigestV1, PrivacyParameterDigestV1,
        PrivacyParameterIdV1, PrivacyStatementSchemaDigestV1, PrivacyVerifierDigestV1,
    };
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    use std::{
        collections::VecDeque,
        sync::{
            Mutex, OnceLock,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        time::Duration,
    };
    fn raw(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn fixture_pattern_v1(length: usize, magics: &[(usize, &[u8])]) -> Vec<u8> {
        let mut bytes = (0..length)
            .map(|index| u8::try_from(index % 256).expect("index modulo 256 fits u8"))
            .collect::<Vec<_>>();
        for (offset, magic) in magics {
            let end = offset
                .checked_add(magic.len())
                .expect("fixture magic offset");
            bytes
                .get_mut(*offset..end)
                .expect("fixture magic fits body")
                .copy_from_slice(magic);
        }
        bytes
    }
    struct TestRng(u64);
    impl TestRng {
        const fn seeded(seed: u64) -> Self {
            Self(seed)
        }
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination)
                .expect("infallible deterministic test RNG");
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            for byte in destination {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0 as u8;
            }
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}
    fn valid_config() -> BootleLanternIssuanceRuntimeConfigV1 {
        BootleLanternIssuanceRuntimeConfigV1 {
            state_dir: PathBuf::from("/var/lib/iroha/privacy-bootle-lantern"),
            max_inflight: 2,
            issuer_id: PrivacyIssuerIdV1::new(raw(1)),
            policy_id: PrivacyPolicyIdV1::new(raw(2)),
            authorization_lifetime_blocks: 16,
            max_records: 1,
            max_total_bytes: 3_310,
            terminal_retention_blocks: 16,
            runtime_provider_registry_handle: "provider://iroha/privacy/bootle-primary".to_owned(),
            runtime_provider_registry_revision: 7,
            runtime_provider_registry_policy_digest: raw(3),
        }
    }
    fn provider_bindings() -> BootleLanternIssuanceRuntimeProviderBindingsV1 {
        BootleLanternIssuanceRuntimeProviderBindingsV1::from_config(&valid_config())
            .expect("valid bindings")
    }
    struct NativeOperationFixture {
        issuer: Arc<BootleLanternIssuerKeyPairV1>,
        snapshot: CommittedIssuanceSnapshotV1,
        authorization: BootleLanternIssuanceAuthorizationV1,
        request_bytes: Vec<u8>,
    }
    fn native_operation_fixture() -> &'static NativeOperationFixture {
        static FIXTURE: OnceLock<NativeOperationFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let mut key_rng = TestRng::seeded(0x6a09_e667_f3bc_c908);
            let issuer = Arc::new(
                BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
                    PrivacyParameterIdV1::new(raw(0x13)),
                    &mut key_rng,
                )
                .expect("native test issuer"),
            );
            let policy = issuer
                .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
                    issuer_id: valid_config().issuer_id,
                    policy_id: valid_config().policy_id,
                    epoch: 1,
                    required_disclosure_bitmap: 0b0000_0010,
                    allowed_values: (0..BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1)
                        .map(|index| BootleLanternAllowedAttributeValuesV1 {
                            values: if index == 1 {
                                vec![BootleLanternAttributeValueV1::new([1; 8])]
                            } else {
                                Vec::new()
                            },
                        })
                        .collect(),
                })
                .expect("native active policy");
            let network_id =
                iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                    iroha_data_model::block::BlockHeader,
                >::from_untyped_unchecked(
                    iroha_crypto::Hash::prehashed(raw(0x32)),
                ));
            let canonical_genesis_hash = *network_id.as_bytes();
            let context = PrivacyStatementContextV1 {
                network_id,
                action_index: 3,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(raw(0x21)),
                parameter_id: PrivacyParameterIdV1::new(raw(0x22)),
                parameter_digest: PrivacyParameterDigestV1::new(raw(0x23)),
                verifier_digest: PrivacyVerifierDigestV1::new(raw(0x24)),
                statement_schema_digest: PrivacyStatementSchemaDigestV1::new(raw(0x25)),
                engine_manifest_digest: PrivacyEngineManifestDigestV1::new(raw(0x26)),
            };
            let mut authorization_rng = TestRng::seeded(0x510e_527f_ade6_82d1);
            let authorization = issuer_prepare_blind_issuance_authorization_candidate_with_rng_v1(
                &issuer,
                &context,
                canonical_genesis_hash,
                &policy,
                raw(0x71),
                10,
                26,
                &mut authorization_rng,
            )
            .expect("store-free native authorization");
            let mut attributes = [[0_u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1];
            attributes[1] = [1; 8];
            let mut holder_rng = TestRng::seeded(0xbb67_ae85_84ca_a73b);
            let (request, _holder_state) = holder_prepare_blind_issuance_with_rng_v1(
                &context,
                canonical_genesis_hash,
                &policy,
                &authorization,
                attributes,
                &mut holder_rng,
            )
            .expect("native holder request");
            let request_bytes = request.encode().expect("canonical ILQ1");
            NativeOperationFixture {
                issuer,
                snapshot: CommittedIssuanceSnapshotV1 {
                    committed_height: 10,
                    canonical_genesis_hash,
                    context,
                    policy,
                },
                authorization,
                request_bytes,
            }
        })
    }
    struct NativeTestIssuerProvider {
        issuer: Arc<BootleLanternIssuerKeyPairV1>,
        authorization: BootleLanternIssuanceAuthorizationV1,
        issuer_id: PrivacyIssuerIdV1,
        policy_id: PrivacyPolicyIdV1,
        issue_rng: Mutex<TestRng>,
        prepare_calls: AtomicUsize,
        validate_calls: AtomicUsize,
        issue_calls: AtomicUsize,
        reject_issue: AtomicBool,
        panic_issue: AtomicBool,
        return_wrong_validation_digest: AtomicBool,
    }
    impl NativeTestIssuerProvider {
        fn from_fixture(fixture: &NativeOperationFixture) -> Self {
            Self {
                issuer: Arc::clone(&fixture.issuer),
                authorization: fixture.authorization.clone(),
                issuer_id: fixture.snapshot.policy.issuer_id,
                policy_id: fixture.snapshot.policy.policy_id,
                issue_rng: Mutex::new(TestRng::seeded(0x9b05_688c_2b3e_6c1f)),
                prepare_calls: AtomicUsize::new(0),
                validate_calls: AtomicUsize::new(0),
                issue_calls: AtomicUsize::new(0),
                reject_issue: AtomicBool::new(false),
                panic_issue: AtomicBool::new(false),
                return_wrong_validation_digest: AtomicBool::new(false),
            }
        }
    }
    impl BootleLanternIssuerCryptoProviderV1 for NativeTestIssuerProvider {
        fn issuer_id(&self) -> PrivacyIssuerIdV1 {
            self.issuer_id
        }
        fn policy_id(&self) -> PrivacyPolicyIdV1 {
            self.policy_id
        }
        fn prepare_authorization(
            &self,
            _context: &PrivacyStatementContextV1,
            _canonical_genesis_hash: [u8; 32],
            _policy: &BootleLanternIssuerPolicyV1,
            _requester_authorization_digest: [u8; 32],
            _issued_at_height: u64,
            _expires_at_height: u64,
        ) -> Result<BootleLanternIssuanceAuthorizationV1, BootleLanternIssuerCryptoProviderErrorV1>
        {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.authorization.clone())
        }
        fn validate_request(
            &self,
            context: &PrivacyStatementContextV1,
            canonical_genesis_hash: [u8; 32],
            policy: &BootleLanternIssuerPolicyV1,
            authorization: &BootleLanternIssuanceAuthorizationV1,
            request_bytes: &[u8],
            current_height: u64,
        ) -> Result<[u8; 32], BootleLanternIssuerCryptoProviderErrorV1> {
            self.validate_calls.fetch_add(1, Ordering::SeqCst);
            let digest = issuer_validate_blind_issuance_request_for_issuer_encoded_v1(
                &self.issuer,
                context,
                canonical_genesis_hash,
                policy,
                authorization,
                request_bytes,
                current_height,
            )
            .map_err(BootleLanternIssuerCryptoProviderErrorV1::from)?;
            if self.return_wrong_validation_digest.load(Ordering::SeqCst) {
                return Ok(raw(0xD1));
            }
            Ok(digest)
        }
        fn issue_validated(
            &self,
            context: &PrivacyStatementContextV1,
            canonical_genesis_hash: [u8; 32],
            policy: &BootleLanternIssuerPolicyV1,
            authorization: &BootleLanternIssuanceAuthorizationV1,
            request_bytes: &[u8],
            current_height: u64,
        ) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuerCryptoProviderErrorV1>
        {
            self.issue_calls.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.panic_issue.load(Ordering::SeqCst),
                "injected issuer-provider panic"
            );
            if self.reject_issue.load(Ordering::SeqCst) {
                return Err(BootleLanternIssuerCryptoProviderErrorV1::Unavailable);
            }
            issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1(
                &self.issuer,
                context,
                canonical_genesis_hash,
                policy,
                authorization,
                request_bytes,
                current_height,
                &mut *self.issue_rng.lock().expect("issue RNG lock"),
            )
            .map_err(BootleLanternIssuerCryptoProviderErrorV1::from)
        }
    }
    struct OperationRegistry {
        handle: String,
        qualifications: Mutex<VecDeque<BootleLanternIssuanceRuntimeProviderQualificationV1>>,
        fallback: BootleLanternIssuanceRuntimeProviderQualificationV1,
    }
    impl fmt::Debug for OperationRegistry {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("OperationRegistry")
                .field("handle", &self.handle)
                .finish_non_exhaustive()
        }
    }
    impl BootleLanternIssuanceRuntimeProviderRegistryV1 for OperationRegistry {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            BootleLanternIssuanceRuntimeProviderQualificationV1,
            BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
        > {
            Ok(self
                .qualifications
                .lock()
                .expect("operation qualification lock")
                .pop_front()
                .unwrap_or(self.fallback))
        }
        fn resolve(
            &self,
            _bindings: &BootleLanternIssuanceRuntimeProviderBindingsV1,
        ) -> Result<
            BootleLanternIssuanceRuntimeSecretsV1,
            BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
        > {
            panic!("operation tests construct an already-qualified registry")
        }
    }
    fn operation_registry(
        qualifications: impl IntoIterator<Item = BootleLanternIssuanceRuntimeProviderQualificationV1>,
    ) -> QualifiedProviderRegistryV1 {
        let config = valid_config();
        let expected = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            config.runtime_provider_registry_revision,
            config.runtime_provider_registry_policy_digest,
        );
        QualifiedProviderRegistryV1 {
            handle: config.runtime_provider_registry_handle.clone(),
            qualification: expected,
            inner: Arc::new(OperationRegistry {
                handle: config.runtime_provider_registry_handle,
                qualifications: Mutex::new(qualifications.into_iter().collect()),
                fallback: expected,
            }),
        }
    }
    fn register_fixture_authorization(
        store: &BootleLanternInMemoryIssuanceStoreV1,
        fixture: &NativeOperationFixture,
    ) {
        store
            .register_fresh_v1(
                fixture.authorization.authorization_id(),
                fixture.authorization.authorization_digest(),
                fixture.authorization.issued_at_height(),
                fixture.authorization.expires_at_height(),
            )
            .expect("register fixture authorization");
    }
    struct PanicIssuerProvider;
    impl BootleLanternIssuerCryptoProviderV1 for PanicIssuerProvider {
        fn issuer_id(&self) -> PrivacyIssuerIdV1 {
            valid_config().issuer_id
        }
        fn policy_id(&self) -> PrivacyPolicyIdV1 {
            valid_config().policy_id
        }
        fn prepare_authorization(
            &self,
            _context: &PrivacyStatementContextV1,
            _canonical_genesis_hash: [u8; 32],
            _policy: &BootleLanternIssuerPolicyV1,
            _requester_authorization_digest: [u8; 32],
            _issued_at_height: u64,
            _expires_at_height: u64,
        ) -> Result<BootleLanternIssuanceAuthorizationV1, BootleLanternIssuerCryptoProviderErrorV1>
        {
            panic!("issuer provider must not be reached during registry preflight tests")
        }
        fn validate_request(
            &self,
            _context: &PrivacyStatementContextV1,
            _canonical_genesis_hash: [u8; 32],
            _policy: &BootleLanternIssuerPolicyV1,
            _authorization: &BootleLanternIssuanceAuthorizationV1,
            _request_bytes: &[u8],
            _current_height: u64,
        ) -> Result<[u8; 32], BootleLanternIssuerCryptoProviderErrorV1> {
            panic!("issuer provider must not be reached during registry preflight tests")
        }
        fn issue_validated(
            &self,
            _context: &PrivacyStatementContextV1,
            _canonical_genesis_hash: [u8; 32],
            _policy: &BootleLanternIssuerPolicyV1,
            _authorization: &BootleLanternIssuanceAuthorizationV1,
            _request_bytes: &[u8],
            _current_height: u64,
        ) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuerCryptoProviderErrorV1>
        {
            panic!("issuer provider must not be reached during registry preflight tests")
        }
    }
    struct PanicAuthenticator;
    impl BootleLanternIssuanceAuthenticatorV1 for PanicAuthenticator {
        fn authenticate(
            &self,
            _opaque_credential: &[u8],
            _action: BootleLanternIssuanceActionV1,
            _request_binding: [u8; 32],
            _committed_height: u64,
        ) -> Result<
            BootleLanternIssuanceAuthenticatedPrincipalV1,
            BootleLanternIssuanceAuthenticationErrorV1,
        > {
            panic!("authenticator must not be reached during registry preflight tests")
        }
    }
    struct StartupRegistry {
        handle: String,
        qualifications: Mutex<VecDeque<BootleLanternIssuanceRuntimeProviderQualificationV1>>,
        qualification_calls: AtomicUsize,
        resolve_calls: AtomicUsize,
        allow_resolve: bool,
    }
    #[derive(Debug)]
    struct PanicHandleRegistry;
    impl BootleLanternIssuanceRuntimeProviderRegistryV1 for PanicHandleRegistry {
        fn handle(&self) -> &str {
            panic!("injected registry handle panic")
        }
        fn qualification(
            &self,
        ) -> Result<
            BootleLanternIssuanceRuntimeProviderQualificationV1,
            BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
        > {
            panic!("qualification must not follow a handle panic")
        }
        fn resolve(
            &self,
            _bindings: &BootleLanternIssuanceRuntimeProviderBindingsV1,
        ) -> Result<
            BootleLanternIssuanceRuntimeSecretsV1,
            BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
        > {
            panic!("resolve must not follow a handle panic")
        }
    }
    impl fmt::Debug for StartupRegistry {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("StartupRegistry")
                .field("handle", &self.handle)
                .field("private_providers", &"[REDACTED]")
                .finish_non_exhaustive()
        }
    }
    impl StartupRegistry {
        fn new(
            handle: impl Into<String>,
            qualifications: impl IntoIterator<
                Item = BootleLanternIssuanceRuntimeProviderQualificationV1,
            >,
            allow_resolve: bool,
        ) -> Self {
            Self {
                handle: handle.into(),
                qualifications: Mutex::new(qualifications.into_iter().collect()),
                qualification_calls: AtomicUsize::new(0),
                resolve_calls: AtomicUsize::new(0),
                allow_resolve,
            }
        }
    }
    impl BootleLanternIssuanceRuntimeProviderRegistryV1 for StartupRegistry {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            BootleLanternIssuanceRuntimeProviderQualificationV1,
            BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
        > {
            self.qualification_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .qualifications
                .lock()
                .expect("qualification lock")
                .pop_front()
                .expect("qualification must not be queried unexpectedly"))
        }
        fn resolve(
            &self,
            _bindings: &BootleLanternIssuanceRuntimeProviderBindingsV1,
        ) -> Result<
            BootleLanternIssuanceRuntimeSecretsV1,
            BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
        > {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            assert!(self.allow_resolve, "resolve must not be reached");
            Ok(BootleLanternIssuanceRuntimeSecretsV1 {
                issuer_provider: Arc::new(PanicIssuerProvider),
                authenticator: Arc::new(PanicAuthenticator),
            })
        }
    }
    fn exact_transport_headers(body_bytes: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1),
        );
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body_bytes.to_string()).expect("test body length header"),
        );
        headers
    }
    fn bearer_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(value).expect("test header"),
        );
        headers
    }
    #[test]
    fn runtime_config_requires_a_nonzero_hard_bounded_inflight_limit() {
        assert_eq!(valid_config().validate(), Ok(()));
        let mut zero = valid_config();
        zero.max_inflight = 0;
        assert_eq!(
            zero.validate(),
            Err(BootleLanternIssuanceApiErrorV1::ConfigurationInvalid)
        );
        let mut excessive = valid_config();
        excessive.max_inflight =
            iroha_config::parameters::defaults::torii::privacy_bootle_lantern_issuer::MAX_INFLIGHT_HARD
                + 1;
        assert_eq!(
            excessive.validate(),
            Err(BootleLanternIssuanceApiErrorV1::ConfigurationInvalid)
        );
    }
    #[test]
    fn transport_headers_require_exact_media_and_unambiguous_fixed_length_framing() {
        let headers = exact_transport_headers(0);
        assert_eq!(validate_transport_headers_v1(&headers, 0), Ok(()));
        let issue_headers = exact_transport_headers(BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1);
        assert_eq!(
            validate_transport_headers_v1(
                &issue_headers,
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
            ),
            Ok(())
        );
        for malformed in [
            "Application/X-Norito",
            "application/x-norito; charset=binary",
            "application/octet-stream",
            " application/x-norito",
        ] {
            let mut headers = exact_transport_headers(0);
            if let Ok(value) = HeaderValue::from_str(malformed) {
                headers.insert(CONTENT_TYPE, value);
                assert_eq!(
                    validate_transport_headers_v1(&headers, 0),
                    Err(BootleLanternIssuanceApiErrorV1::UnsupportedMediaType),
                    "accepted malformed content type {malformed:?}"
                );
            }
        }
        let mut duplicate = exact_transport_headers(0);
        duplicate.append(
            CONTENT_TYPE,
            HeaderValue::from_static(BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1),
        );
        assert_eq!(
            validate_transport_headers_v1(&duplicate, 0),
            Err(BootleLanternIssuanceApiErrorV1::UnsupportedMediaType)
        );
        let mut encoded = exact_transport_headers(0);
        encoded.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        assert_eq!(
            validate_transport_headers_v1(&encoded, 0),
            Err(BootleLanternIssuanceApiErrorV1::UnsupportedMediaType)
        );
        for malformed in [
            "*/*",
            "application/x-norito;q=1",
            "application/octet-stream",
        ] {
            let mut headers = exact_transport_headers(0);
            headers.insert(
                ACCEPT,
                HeaderValue::from_str(malformed).expect("test Accept header"),
            );
            assert_eq!(
                validate_transport_headers_v1(&headers, 0),
                Err(BootleLanternIssuanceApiErrorV1::NotAcceptable),
                "accepted noncanonical Accept {malformed:?}"
            );
        }
        let mut missing_accept = exact_transport_headers(0);
        missing_accept.remove(ACCEPT);
        assert_eq!(
            validate_transport_headers_v1(&missing_accept, 0),
            Err(BootleLanternIssuanceApiErrorV1::NotAcceptable)
        );
        let mut duplicate_accept = exact_transport_headers(0);
        duplicate_accept.append(
            ACCEPT,
            HeaderValue::from_static(BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1),
        );
        assert_eq!(
            validate_transport_headers_v1(&duplicate_accept, 0),
            Err(BootleLanternIssuanceApiErrorV1::NotAcceptable)
        );
        for malformed in ["00", "+0", " 0", "0, 0", "-1"] {
            let mut headers = exact_transport_headers(0);
            if let Ok(value) = HeaderValue::from_str(malformed) {
                headers.insert(CONTENT_LENGTH, value);
                assert_eq!(
                    validate_transport_headers_v1(&headers, 0),
                    Err(BootleLanternIssuanceApiErrorV1::InvalidRequest),
                    "accepted noncanonical Content-Length {malformed:?}"
                );
            }
        }
        let mut missing_length = exact_transport_headers(0);
        missing_length.remove(CONTENT_LENGTH);
        assert_eq!(
            validate_transport_headers_v1(&missing_length, 0),
            Err(BootleLanternIssuanceApiErrorV1::InvalidRequest)
        );
        let mut duplicate_length = exact_transport_headers(0);
        duplicate_length.append(CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert_eq!(
            validate_transport_headers_v1(&duplicate_length, 0),
            Err(BootleLanternIssuanceApiErrorV1::InvalidRequest)
        );
        let mut ambiguous_framing = exact_transport_headers(0);
        ambiguous_framing.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(
            validate_transport_headers_v1(&ambiguous_framing, 0),
            Err(BootleLanternIssuanceApiErrorV1::InvalidRequest)
        );
        let mut oversized_authorize = exact_transport_headers(0);
        oversized_authorize.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert_eq!(
            validate_transport_headers_v1(&oversized_authorize, 0),
            Err(BootleLanternIssuanceApiErrorV1::PayloadTooLarge)
        );
        let mut oversized_issue =
            exact_transport_headers(BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1);
        oversized_issue.insert(CONTENT_LENGTH, HeaderValue::from_static("71897"));
        assert_eq!(
            validate_transport_headers_v1(
                &oversized_issue,
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
            ),
            Err(BootleLanternIssuanceApiErrorV1::PayloadTooLarge)
        );
        let mut undersized_issue =
            exact_transport_headers(BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1);
        undersized_issue.insert(CONTENT_LENGTH, HeaderValue::from_static("71895"));
        assert_eq!(
            validate_transport_headers_v1(
                &undersized_issue,
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
            ),
            Err(BootleLanternIssuanceApiErrorV1::InvalidRequest)
        );
        oversized_issue.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(
            validate_transport_headers_v1(
                &oversized_issue,
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
            ),
            Err(BootleLanternIssuanceApiErrorV1::InvalidRequest),
            "ambiguous CL/TE framing is malformed even when CL is oversized"
        );
        let mut overflowing_length = exact_transport_headers(0);
        overflowing_length.insert(
            CONTENT_LENGTH,
            HeaderValue::from_static("184467440737095516160"),
        );
        assert_eq!(
            validate_transport_headers_v1(&overflowing_length, 0),
            Err(BootleLanternIssuanceApiErrorV1::PayloadTooLarge)
        );
    }
    #[test]
    fn missing_or_wrong_accept_is_rejected_before_any_protected_work() {
        let protected_work_calls = AtomicUsize::new(0);
        for (index, mut headers) in [exact_transport_headers(0), exact_transport_headers(0)]
            .into_iter()
            .enumerate()
        {
            if index == 0 {
                headers.remove(ACCEPT);
            } else {
                headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
            }
            let result = validate_transport_headers_v1(&headers, 0).map(|()| {
                protected_work_calls.fetch_add(1, Ordering::SeqCst);
            });
            assert_eq!(result, Err(BootleLanternIssuanceApiErrorV1::NotAcceptable));
        }
        assert_eq!(protected_work_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn bearer_parser_accepts_only_one_canonical_nonempty_base64url_value() {
        let mut canonical = bearer_headers("Bearer YQ");
        mark_authorization_sensitive_v1(&mut canonical);
        assert!(
            canonical
                .get(AUTHORIZATION)
                .is_some_and(HeaderValue::is_sensitive)
        );
        let credential = parse_bearer_v1(&canonical).expect("canonical bearer");
        assert_eq!(credential.as_bytes(), b"a");
        assert_eq!(
            format!("{credential:?}"),
            "BootleLanternIssuanceCredentialV1([REDACTED])"
        );
        for malformed in [
            "Bearer ",
            "bearer YQ",
            "Bearer YQ==",
            "Bearer YR",
            "Bearer Y Q",
            "Basic YQ",
        ] {
            assert_eq!(
                parse_bearer_v1(&bearer_headers(malformed)).unwrap_err(),
                BootleLanternIssuanceApiErrorV1::Unauthorized,
                "accepted malformed bearer {malformed:?}"
            );
        }
        let encoded_max = BOOTLE_LANTERN_ISSUANCE_AUTHENTICATION_MAX_BYTES_V1
            .div_ceil(3)
            .saturating_mul(4);
        let oversized = format!("Bearer {}", "A".repeat(encoded_max + 1));
        assert_eq!(
            parse_bearer_v1(&bearer_headers(&oversized)).unwrap_err(),
            BootleLanternIssuanceApiErrorV1::Unauthorized
        );
        let mut duplicate = bearer_headers("Bearer YQ");
        duplicate.append(AUTHORIZATION, HeaderValue::from_static("Bearer Yg"));
        mark_authorization_sensitive_v1(&mut duplicate);
        assert!(
            duplicate
                .get_all(AUTHORIZATION)
                .iter()
                .all(HeaderValue::is_sensitive)
        );
        assert_eq!(
            parse_bearer_v1(&duplicate).unwrap_err(),
            BootleLanternIssuanceApiErrorV1::Unauthorized
        );
    }
    #[tokio::test]
    async fn exact_body_collector_rejects_every_truncation_and_extension() {
        assert!(collect_exact_body_v1(Body::empty(), 0).await.is_ok());
        assert_eq!(
            collect_exact_body_v1(Body::from(vec![0_u8]), 0)
                .await
                .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::PayloadTooLarge
        );
        let exact = vec![0xA5; BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1];
        assert_eq!(
            collect_exact_body_v1(
                Body::from(exact.clone()),
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
            )
            .await
            .expect("exact issue body")
            .len(),
            BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1
        );
        assert_eq!(
            collect_exact_body_v1(
                Body::from(exact[..exact.len() - 1].to_vec()),
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
            )
            .await
            .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::InvalidRequest
        );
        let extended = vec![0xA5; BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1 + 1];
        assert_eq!(
            collect_exact_body_v1(
                Body::from(extended),
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
            )
            .await
            .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::PayloadTooLarge
        );
    }
    #[test]
    fn disabled_response_is_stable_and_hardened() {
        let response = bootle_lantern_issuance_unavailable_response_v1();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static(
                "no-store, no-cache, must-revalidate"
            ))
        );
        assert_eq!(
            response.headers().get(PRAGMA),
            Some(&HeaderValue::from_static("no-cache"))
        );
        assert_eq!(
            response.headers().get(X_CONTENT_TYPE_OPTIONS),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert!(response.headers().get(RETRY_AFTER).is_none());
    }
    #[tokio::test]
    async fn success_and_protocol_errors_use_the_documented_exact_status_and_length() {
        let mut authorization_bytes =
            vec![0_u8; BOOTLE_LANTERN_ISSUANCE_AUTHORIZATION_RESPONSE_BYTES_V1];
        authorization_bytes[..4].copy_from_slice(b"ILA1");
        let response = success_response_v1(authorization_bytes);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_LENGTH),
            Some(&HeaderValue::from_static("320"))
        );
        let mut issuance_bytes = vec![0_u8; BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1];
        issuance_bytes[..4].copy_from_slice(b"ILR1");
        let response = success_response_v1(issuance_bytes);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_LENGTH),
            Some(&HeaderValue::from_static("3176"))
        );
        assert_eq!(
            success_response_v1(vec![
                0_u8;
                BOOTLE_LANTERN_ISSUANCE_AUTHORIZATION_RESPONSE_BYTES_V1
            ])
            .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a correct-length authorization response with non-ILA1 magic must never leave Torii",
        );
        assert_eq!(
            success_response_v1(vec![0_u8; BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1])
                .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a correct-length issuance response with non-ILR1 magic must never leave Torii",
        );
        assert_eq!(
            error_response_v1(BootleLanternIssuanceApiErrorV1::UnsupportedMediaType).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            error_response_v1(BootleLanternIssuanceApiErrorV1::NotAcceptable).status(),
            StatusCode::NOT_ACCEPTABLE
        );
        assert_eq!(
            error_response_v1(BootleLanternIssuanceApiErrorV1::PayloadTooLarge).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let unauthorized = error_response_v1(BootleLanternIssuanceApiErrorV1::Unauthorized);
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized.headers().get(WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(WWW_AUTHENTICATE_VALUE_V1))
        );
        let throttled = error_response_v1(BootleLanternIssuanceApiErrorV1::TooManyRequests);
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            throttled.headers().get(RETRY_AFTER),
            Some(&HeaderValue::from_static("1"))
        );
        let throttled_bytes = throttled
            .into_body()
            .collect()
            .await
            .expect("collect throttled privacy issuance error")
            .to_bytes();
        let throttled_envelope: iroha_torii_shared::ErrorEnvelope =
            norito::decode_from_bytes(&throttled_bytes)
                .expect("decode throttled privacy issuance error");
        assert!(throttled_envelope.details.is_none());
        let typed = error_response_v1(BootleLanternIssuanceApiErrorV1::InvalidRequest);
        assert_eq!(
            typed.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/x-norito"))
        );
        let bytes = typed
            .into_body()
            .collect()
            .await
            .expect("collect typed privacy issuance error")
            .to_bytes();
        let envelope: iroha_torii_shared::ErrorEnvelope =
            norito::decode_from_bytes(&bytes).expect("decode typed privacy issuance error");
        assert_eq!(envelope.code(), "privacy_issuance_invalid_request");
        let unacceptable = error_response_v1(BootleLanternIssuanceApiErrorV1::NotAcceptable);
        assert_eq!(
            unacceptable.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
    }
    #[test]
    fn cross_sdk_fixture_bodies_bind_exact_lengths_magics_and_hashes() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../fixtures/privacy/bootle_lantern_issuance_client_v1.json"
        ))
        .expect("cross-SDK issuance fixture must parse");
        let bodies = fixture
            .get("bodies")
            .and_then(norito::json::Value::as_object)
            .expect("fixture bodies object");
        assert_eq!(
            bodies.get("pattern").and_then(norito::json::Value::as_str),
            Some("byte-at-index-equals-index-modulo-256-with-canonical-wire-magics"),
        );
        let cases: [(&str, &str, usize, &[(usize, &[u8])]); 3] = [
            (
                "authorization_response",
                "ILA1",
                BOOTLE_LANTERN_ISSUANCE_AUTHORIZATION_RESPONSE_BYTES_V1,
                &[(0_usize, b"ILA1".as_slice())][..],
            ),
            (
                "issue_request",
                "ILA1+ILQ1",
                BOOTLE_LANTERN_ISSUANCE_ISSUE_REQUEST_BYTES_V1,
                &[
                    (0_usize, b"ILA1".as_slice()),
                    (BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1, b"ILQ1".as_slice()),
                ][..],
            ),
            (
                "issue_response",
                "ILR1",
                BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1,
                &[(0_usize, b"ILR1".as_slice())][..],
            ),
        ];
        for (name, wire, expected_len, magics) in cases {
            let row = bodies
                .get(name)
                .and_then(norito::json::Value::as_object)
                .unwrap_or_else(|| panic!("fixture body row {name}"));
            assert_eq!(
                row.get("wire").and_then(norito::json::Value::as_str),
                Some(wire),
            );
            assert_eq!(
                row.get("length_bytes")
                    .and_then(norito::json::Value::as_u64),
                u64::try_from(expected_len).ok(),
            );
            let bytes = fixture_pattern_v1(expected_len, magics);
            for (offset, magic) in magics {
                assert_eq!(bytes.get(*offset..*offset + magic.len()), Some(*magic),);
            }
            let digest = hex::encode(Sha256::digest(&bytes));
            assert_eq!(
                row.get("pattern_sha256_hex")
                    .and_then(norito::json::Value::as_str),
                Some(digest.as_str()),
                "fixture body row {name} digest",
            );
        }
    }
    #[tokio::test]
    async fn error_responses_match_cross_sdk_fixture_byte_for_byte() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../fixtures/privacy/bootle_lantern_issuance_client_v1.json"
        ))
        .expect("cross-SDK issuance fixture must parse");
        let fixture_www_authenticate = fixture
            .get("transport")
            .and_then(norito::json::Value::as_object)
            .and_then(|transport| transport.get("unauthorized_www_authenticate"))
            .and_then(norito::json::Value::as_str)
            .expect("fixture unauthorized challenge");
        assert_eq!(fixture_www_authenticate, WWW_AUTHENTICATE_VALUE_V1);
        let errors = fixture
            .get("errors")
            .and_then(norito::json::Value::as_object)
            .expect("fixture errors object");
        let maximum_body_bytes = errors
            .get("maximum_body_bytes")
            .and_then(norito::json::Value::as_u64)
            .expect("fixture maximum error body bytes");
        let rows = errors
            .get("responses")
            .and_then(norito::json::Value::as_array)
            .expect("fixture error responses");
        assert_eq!(rows.len(), 8);
        for row in rows {
            let status = row
                .get("status")
                .and_then(norito::json::Value::as_u64)
                .expect("fixture error status");
            let expected_media_type = row
                .get("media_type")
                .and_then(norito::json::Value::as_str)
                .expect("fixture error media type");
            let expected_code = row
                .get("code")
                .and_then(norito::json::Value::as_str)
                .expect("fixture error code");
            let expected_body = row
                .get("body_hex")
                .and_then(norito::json::Value::as_str)
                .map_or_else(
                    || {
                        row.get("body_utf8")
                            .and_then(norito::json::Value::as_str)
                            .expect("fixture JSON error body")
                            .as_bytes()
                            .to_vec()
                    },
                    |value| hex::decode(value).expect("fixture error body hex"),
                );
            let error = match status {
                400 => BootleLanternIssuanceApiErrorV1::InvalidRequest,
                401 => BootleLanternIssuanceApiErrorV1::Unauthorized,
                406 => BootleLanternIssuanceApiErrorV1::NotAcceptable,
                409 => BootleLanternIssuanceApiErrorV1::StateConflict,
                413 => BootleLanternIssuanceApiErrorV1::PayloadTooLarge,
                415 => BootleLanternIssuanceApiErrorV1::UnsupportedMediaType,
                429 => BootleLanternIssuanceApiErrorV1::TooManyRequests,
                503 => BootleLanternIssuanceApiErrorV1::ProviderUnavailable,
                other => panic!("unexpected fixture error status {other}"),
            };
            let response = error_response_v1(error);
            assert_eq!(u64::from(response.status().as_u16()), status);
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_media_type),
                "fixture status {status} content type",
            );
            let expected_retry = row
                .get("retry_after_seconds")
                .and_then(norito::json::Value::as_u64)
                .map(|seconds| seconds.to_string());
            assert_eq!(
                response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
                expected_retry.as_deref(),
                "fixture status {status} Retry-After",
            );
            let expected_www_authenticate = row
                .get("www_authenticate")
                .and_then(norito::json::Value::as_str);
            assert_eq!(
                response
                    .headers()
                    .get(WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok()),
                expected_www_authenticate,
                "fixture status {status} WWW-Authenticate",
            );
            assert_eq!(
                expected_www_authenticate,
                (status == 401).then_some(fixture_www_authenticate),
                "only 401 may carry the canonical issuance challenge",
            );
            let actual_body = response
                .into_body()
                .collect()
                .await
                .expect("collect fixture error response")
                .to_bytes();
            assert_eq!(
                actual_body.as_ref(),
                expected_body.as_slice(),
                "fixture status {status} body bytes",
            );
            assert!(u64::try_from(actual_body.len()).is_ok_and(|len| len <= maximum_body_bytes));
            if expected_media_type == BOOTLE_LANTERN_ISSUANCE_CONTENT_TYPE_V1 {
                let envelope: iroha_torii_shared::ErrorEnvelope =
                    norito::decode_from_bytes(&actual_body).expect("canonical fixture envelope");
                assert_eq!(envelope.code(), expected_code);
                assert!(envelope.details.is_none());
            }
        }
    }
    #[test]
    fn admission_is_bounded_rejects_same_authorization_fanout_and_allows_distinct_authorizations() {
        let admission = IssuanceAdmissionV1::new(2);
        let first_permit = admission.try_acquire_global().expect("first global permit");
        let second_permit = admission
            .try_acquire_global()
            .expect("second global permit");
        assert_eq!(
            admission.try_acquire_global().unwrap_err(),
            BootleLanternIssuanceApiErrorV1::TooManyRequests
        );
        let fixture = native_operation_fixture();
        let first_key = validation_lease_key_v1(&fixture.authorization);
        let first_lease = admission
            .try_acquire_validation(&first_permit, first_key)
            .expect("first authorization lease");
        assert_eq!(
            admission
                .try_acquire_validation(&second_permit, first_key)
                .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::StateConflict
        );
        let mut second_authorization_rng = TestRng::seeded(0x243f_6a88_85a3_08d3);
        let second_authorization =
            issuer_prepare_blind_issuance_authorization_candidate_with_rng_v1(
                &fixture.issuer,
                &fixture.snapshot.context,
                fixture.snapshot.canonical_genesis_hash,
                &fixture.snapshot.policy,
                fixture.authorization.requester_authorization_digest(),
                fixture.authorization.issued_at_height(),
                fixture.authorization.expires_at_height(),
                &mut second_authorization_rng,
            )
            .expect("distinct authorization candidate");
        assert_ne!(
            second_authorization.authorization_id(),
            fixture.authorization.authorization_id()
        );
        let second_lease = admission
            .try_acquire_validation(
                &second_permit,
                validation_lease_key_v1(&second_authorization),
            )
            .expect("different authorizations may validate concurrently");
        assert_eq!(admission.validation_leases.active_count(), 2);
        drop((first_lease, second_lease, first_permit, second_permit));
        assert_eq!(admission.validation_leases.active_count(), 0);
        assert!(admission.try_acquire_global().is_ok());
    }
    #[test]
    fn one_authorization_lease_rejects_distinct_candidate_request_digests() {
        let fixture = native_operation_fixture();
        let first = BootleLanternBlindIssuanceRequestV1::decode_exact(
            &fixture.request_bytes,
            u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1).expect("fixed request length"),
        )
        .expect("first canonical request");
        let mut attributes = [[0_u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1];
        attributes[1] = [1; 8];
        let mut second_request_rng = TestRng::seeded(0x1319_8a2e_0370_7344);
        let (second, _holder_state) = holder_prepare_blind_issuance_with_rng_v1(
            &fixture.snapshot.context,
            fixture.snapshot.canonical_genesis_hash,
            &fixture.snapshot.policy,
            &fixture.authorization,
            attributes,
            &mut second_request_rng,
        )
        .expect("second canonical candidate request");
        assert_ne!(first.request_digest(), second.request_digest());
        let admission = IssuanceAdmissionV1::new(2);
        let first_permit = admission.try_acquire_global().expect("first permit");
        let second_permit = admission.try_acquire_global().expect("second permit");
        let key = validation_lease_key_v1(&fixture.authorization);
        let _lease = admission
            .try_acquire_validation(&first_permit, key)
            .expect("first request lease");
        assert_eq!(
            admission
                .try_acquire_validation(&second_permit, key)
                .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::StateConflict,
            "request-digest substitution must not bypass the per-authorization lease"
        );
    }
    #[test]
    fn denied_authentication_cannot_reserve_or_block_an_authorization_lease() {
        let fixture = native_operation_fixture();
        let admission = IssuanceAdmissionV1::new(1);
        let permit = admission.try_acquire_global().expect("global permit");
        assert_eq!(
            bind_authenticated_issue_and_acquire_validation_lease_v1(
                &admission,
                &permit,
                Err(BootleLanternIssuanceApiErrorV1::Unauthorized),
                &fixture.authorization,
                fixture.snapshot.committed_height,
                16,
            )
            .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::Unauthorized
        );
        assert_eq!(admission.validation_leases.active_count(), 0);
        let principal = BootleLanternIssuanceAuthenticatedPrincipalV1 {
            principal_digest: fixture.authorization.requester_authorization_digest(),
            issued_at_height: fixture.snapshot.committed_height,
            expires_at_height: fixture.authorization.expires_at_height(),
        };
        assert_eq!(
            bind_authenticated_issue_and_acquire_validation_lease_v1(
                &admission,
                &permit,
                Ok(BootleLanternIssuanceAuthenticatedPrincipalV1 {
                    principal_digest: raw(0xF1),
                    ..principal
                }),
                &fixture.authorization,
                fixture.snapshot.committed_height,
                16,
            )
            .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::Unauthorized
        );
        assert_eq!(admission.validation_leases.active_count(), 0);
        let (_principal, lease) = bind_authenticated_issue_and_acquire_validation_lease_v1(
            &admission,
            &permit,
            Ok(principal),
            &fixture.authorization,
            fixture.snapshot.committed_height,
            16,
        )
        .expect("legitimate holder is not blocked by denied authentication");
        assert_eq!(admission.validation_leases.active_count(), 1);
        drop(lease);
        assert_eq!(admission.validation_leases.active_count(), 0);
    }
    #[test]
    fn validation_lease_is_removed_on_error_and_unwind() {
        let admission = Arc::new(IssuanceAdmissionV1::new(1));
        let key = validation_lease_key_v1(&native_operation_fixture().authorization);
        let permit = admission.try_acquire_global().expect("error-path permit");
        let result: Result<(), BootleLanternIssuanceApiErrorV1> = (|| {
            let _lease = admission.try_acquire_validation(&permit, key)?;
            Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable)
        })();
        assert_eq!(
            result,
            Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable)
        );
        assert_eq!(admission.validation_leases.active_count(), 0);
        drop(permit);
        let unwind_admission = Arc::clone(&admission);
        let unwind = catch_unwind(AssertUnwindSafe(move || {
            let permit = unwind_admission
                .try_acquire_global()
                .expect("unwind-path permit");
            let _lease = unwind_admission
                .try_acquire_validation(&permit, key)
                .expect("unwind-path lease");
            panic!("injected validation panic");
        }));
        assert!(unwind.is_err());
        assert_eq!(admission.validation_leases.active_count(), 0);
        assert!(admission.try_acquire_global().is_ok());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_cannot_release_capacity_while_blocking_crypto_continues() {
        let admission = Arc::new(IssuanceAdmissionV1::new(1));
        let permit = admission.try_acquire_global().expect("blocking permit");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let task = tokio::spawn(execute_admitted_blocking_v1(permit, move |_| {
            let _ = started_tx.send(());
            release_rx.recv().expect("release blocking operation");
            Ok(Vec::new())
        }));
        started_rx
            .await
            .expect("blocking operation must start before cancellation");
        task.abort();
        assert_eq!(
            admission.try_acquire_global().unwrap_err(),
            BootleLanternIssuanceApiErrorV1::TooManyRequests,
            "request cancellation must not detach capacity from running crypto"
        );
        release_tx.send(()).expect("release blocking operation");
        let _reacquired = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match admission.try_acquire_global() {
                    Ok(permit) => break permit,
                    Err(BootleLanternIssuanceApiErrorV1::TooManyRequests) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected admission result: {error:?}"),
                }
            }
        })
        .await
        .expect("completed crypto must release capacity");
    }
    #[tokio::test]
    async fn blocking_panic_is_contained_and_releases_global_capacity() {
        let admission = IssuanceAdmissionV1::new(1);
        let permit = admission.try_acquire_global().expect("panic-path permit");
        assert_eq!(
            execute_admitted_blocking_v1(permit, move |_| {
                panic!("injected admitted blocking panic");
            })
            .await
            .unwrap_err(),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        assert!(admission.try_acquire_global().is_ok());
    }
    #[test]
    fn registry_startup_rejects_missing_unexpected_and_stale_providers_before_resolve() {
        let config = valid_config();
        let bindings = provider_bindings();
        assert_eq!(
            QualifiedProviderRegistryV1::resolve(&config, None, &bindings)
                .expect_err("missing registry"),
            BootleLanternIssuanceApiErrorV1::ProviderMissing
        );
        let unexpected = Arc::new(StartupRegistry::new(
            "provider://iroha/privacy/unexpected-primary",
            [],
            false,
        ));
        assert_eq!(
            QualifiedProviderRegistryV1::resolve(&config, Some(unexpected.clone()), &bindings,)
                .expect_err("unexpected registry"),
            BootleLanternIssuanceApiErrorV1::ProviderMismatch
        );
        assert_eq!(unexpected.qualification_calls.load(Ordering::SeqCst), 0);
        assert_eq!(unexpected.resolve_calls.load(Ordering::SeqCst), 0);
        let stale = Arc::new(StartupRegistry::new(
            config.runtime_provider_registry_handle.clone(),
            [BootleLanternIssuanceRuntimeProviderQualificationV1::new(
                config.runtime_provider_registry_revision + 1,
                config.runtime_provider_registry_policy_digest,
            )],
            false,
        ));
        assert_eq!(
            QualifiedProviderRegistryV1::resolve(&config, Some(stale.clone()), &bindings)
                .expect_err("stale registry"),
            BootleLanternIssuanceApiErrorV1::ProviderMismatch
        );
        assert_eq!(stale.qualification_calls.load(Ordering::SeqCst), 1);
        assert_eq!(stale.resolve_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn registry_qualification_and_resolve_panics_are_contained() {
        let config = valid_config();
        let bindings = provider_bindings();
        assert_eq!(
            QualifiedProviderRegistryV1::resolve(
                &config,
                Some(Arc::new(PanicHandleRegistry)),
                &bindings,
            )
            .expect_err("handle panic must be contained"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        let qualification_panic = Arc::new(StartupRegistry::new(
            config.runtime_provider_registry_handle.clone(),
            [],
            false,
        ));
        assert_eq!(
            QualifiedProviderRegistryV1::resolve(&config, Some(qualification_panic), &bindings,)
                .expect_err("qualification panic must be contained"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        let expected = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            config.runtime_provider_registry_revision,
            config.runtime_provider_registry_policy_digest,
        );
        let resolve_panic = Arc::new(StartupRegistry::new(
            config.runtime_provider_registry_handle.clone(),
            [expected],
            false,
        ));
        assert_eq!(
            QualifiedProviderRegistryV1::resolve(&config, Some(resolve_panic), &bindings)
                .expect_err("resolve panic must be contained"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
    }
    #[test]
    fn registry_startup_detects_qualification_drift_after_resolve() {
        let config = valid_config();
        let expected = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            config.runtime_provider_registry_revision,
            config.runtime_provider_registry_policy_digest,
        );
        let drifted = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            expected.revision + 1,
            raw(0xD1),
        );
        let registry = Arc::new(StartupRegistry::new(
            config.runtime_provider_registry_handle.clone(),
            [expected, drifted],
            true,
        ));
        assert_eq!(
            QualifiedProviderRegistryV1::resolve(
                &config,
                Some(registry.clone()),
                &provider_bindings(),
            )
            .expect_err("qualification drift"),
            BootleLanternIssuanceApiErrorV1::ProviderDrift
        );
        assert_eq!(registry.qualification_calls.load(Ordering::SeqCst), 2);
        assert_eq!(registry.resolve_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn authorization_collision_retries_are_exactly_bounded_and_leave_existing_state_untouched() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_fixture_authorization(&store, fixture);
        let registry = operation_registry([]);
        assert_eq!(
            prepare_and_register_authorization_v1(
                &IssuanceLinearizationGuardV1::provider_only(&registry),
                &provider,
                &store,
                &fixture.snapshot,
                fixture.authorization.requester_authorization_digest(),
                fixture.authorization.expires_at_height(),
                u64::MAX,
            )
            .expect_err("four repeated identifier collisions must fail closed"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        assert_eq!(
            provider.prepare_calls.load(Ordering::SeqCst),
            usize::try_from(MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1)
                .expect("fixed attempt count fits usize")
        );
        assert_eq!(
            store.preflight_v1(
                fixture.authorization.authorization_id(),
                fixture.authorization.authorization_digest(),
                raw(0x91),
                fixture.snapshot.committed_height,
            ),
            Ok(BootleLanternIssuancePreflightV1::Fresh)
        );
    }
    #[test]
    fn native_issue_completes_once_and_expired_retry_never_reenters_provider() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        let registry = operation_registry([]);
        let authorization_bytes = prepare_and_register_authorization_v1(
            &IssuanceLinearizationGuardV1::provider_only(&registry),
            &provider,
            &store,
            &fixture.snapshot,
            fixture.authorization.requester_authorization_digest(),
            fixture.authorization.expires_at_height(),
            u64::MAX,
        )
        .expect("one registered authorization");
        assert_eq!(
            BootleLanternIssuanceAuthorizationV1::decode_exact(&authorization_bytes)
                .expect("canonical registered authorization"),
            fixture.authorization
        );
        let first = issue_registered_request_v1(
            &IssuanceLinearizationGuardV1::provider_only(&registry),
            &provider,
            &store,
            &fixture.snapshot,
            &fixture.authorization,
            &fixture.request_bytes,
            u64::MAX,
        )
        .expect("first issue");
        assert_eq!(first.len(), BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1);
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 1);
        let expired_snapshot = CommittedIssuanceSnapshotV1 {
            committed_height: fixture.authorization.expires_at_height() + 100,
            canonical_genesis_hash: fixture.snapshot.canonical_genesis_hash,
            context: fixture.snapshot.context.clone(),
            policy: fixture.snapshot.policy.clone(),
        };
        let retry = issue_registered_request_v1(
            &IssuanceLinearizationGuardV1::provider_only(&registry),
            &provider,
            &store,
            &expired_snapshot,
            &fixture.authorization,
            &fixture.request_bytes,
            u64::MAX,
        )
        .expect("completed retry remains readable after expiry");
        assert_eq!(retry, first);
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn cached_response_is_not_returned_across_provider_qualification_drift() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_fixture_authorization(&store, fixture);
        let stable_registry = operation_registry([]);
        let first = issue_registered_request_v1(
            &IssuanceLinearizationGuardV1::provider_only(&stable_registry),
            &provider,
            &store,
            &fixture.snapshot,
            &fixture.authorization,
            &fixture.request_bytes,
            u64::MAX,
        )
        .expect("initial completed response");
        assert_eq!(first.len(), BOOTLE_LANTERN_ISSUANCE_ISSUE_RESPONSE_BYTES_V1);
        let config = valid_config();
        let expected = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            config.runtime_provider_registry_revision,
            config.runtime_provider_registry_policy_digest,
        );
        let drifted = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            expected.revision + 1,
            raw(0xD3),
        );
        let drift_registry = operation_registry([expected, drifted]);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&drift_registry),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("cached response must recheck qualification before return"),
            BootleLanternIssuanceApiErrorV1::ProviderDrift
        );
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn provider_validation_digest_substitution_fails_before_claim_and_rng() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        provider
            .return_wrong_validation_digest
            .store(true, Ordering::SeqCst);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_fixture_authorization(&store, fixture);
        let registry = operation_registry([]);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&registry),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("substituted provider digest"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 0);
        let request = BootleLanternBlindIssuanceRequestV1::decode_exact(
            &fixture.request_bytes,
            u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1).expect("fixed request length fits u32"),
        )
        .expect("canonical fixture request");
        assert_eq!(
            store.preflight_v1(
                fixture.authorization.authorization_id(),
                fixture.authorization.authorization_digest(),
                request.request_digest(),
                fixture.snapshot.committed_height,
            ),
            Ok(BootleLanternIssuancePreflightV1::Fresh)
        );
    }
    #[test]
    fn every_provider_failure_after_claim_is_irreversible() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        provider.reject_issue.store(true, Ordering::SeqCst);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_fixture_authorization(&store, fixture);
        let registry = operation_registry([]);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&registry),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("post-claim provider failure"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&registry),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("failed authorization can never return to fresh"),
            BootleLanternIssuanceApiErrorV1::StateConflict
        );
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn issuer_provider_panic_after_claim_is_contained_and_terminal() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        provider.panic_issue.store(true, Ordering::SeqCst);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_fixture_authorization(&store, fixture);
        let registry = operation_registry([]);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&registry),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("provider panic must be contained"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        provider.panic_issue.store(false, Ordering::SeqCst);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&registry),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("panic-claimed authorization must never return to fresh"),
            BootleLanternIssuanceApiErrorV1::StateConflict
        );
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn provider_qualification_drift_after_claim_fails_without_issuer_rng() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_fixture_authorization(&store, fixture);
        let config = valid_config();
        let expected = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            config.runtime_provider_registry_revision,
            config.runtime_provider_registry_policy_digest,
        );
        let drifted = BootleLanternIssuanceRuntimeProviderQualificationV1::new(
            expected.revision + 1,
            raw(0xD2),
        );
        let registry = operation_registry([expected, expected, expected, expected, drifted]);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&registry),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("post-claim qualification drift"),
            BootleLanternIssuanceApiErrorV1::ProviderDrift
        );
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&operation_registry([])),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("drifted claim is terminally failed"),
            BootleLanternIssuanceApiErrorV1::StateConflict
        );
    }
    #[test]
    fn corrupt_completed_response_is_never_returned_or_reissued() {
        let fixture = native_operation_fixture();
        let provider = NativeTestIssuerProvider::from_fixture(fixture);
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_fixture_authorization(&store, fixture);
        let request = BootleLanternBlindIssuanceRequestV1::decode_exact(
            &fixture.request_bytes,
            u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1).expect("fixed request length fits u32"),
        )
        .expect("canonical fixture request");
        assert_eq!(
            store.claim_v1(
                fixture.authorization.authorization_id(),
                fixture.authorization.authorization_digest(),
                request.request_digest(),
                fixture.snapshot.committed_height,
            ),
            Ok(BootleLanternIssuanceClaimV1::Fresh)
        );
        let mut response_rng = TestRng::seeded(0xa54f_f53a_5f1d_36f1);
        let mut substituted_response =
            issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1(
                &fixture.issuer,
                &fixture.snapshot.context,
                fixture.snapshot.canonical_genesis_hash,
                &fixture.snapshot.policy,
                &fixture.authorization,
                &fixture.request_bytes,
                fixture.snapshot.committed_height,
                &mut response_rng,
            )
            .expect("native response for cache substitution")
            .encode()
            .expect("canonical native response");
        *substituted_response
            .last_mut()
            .expect("fixed response is non-empty") ^= 1;
        store
            .complete_v1(
                fixture.authorization.authorization_id(),
                fixture.authorization.authorization_digest(),
                request.request_digest(),
                &substituted_response,
                fixture.snapshot.committed_height,
            )
            .expect("store accepts structurally canonical request-bound response bytes");
        assert_eq!(
            issue_registered_request_v1(
                &IssuanceLinearizationGuardV1::provider_only(&operation_registry([])),
                &provider,
                &store,
                &fixture.snapshot,
                &fixture.authorization,
                &fixture.request_bytes,
                u64::MAX,
            )
            .expect_err("corrupt cached response"),
            BootleLanternIssuanceApiErrorV1::DurableStateUnavailable
        );
        assert_eq!(provider.validate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.issue_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn authenticated_principal_height_and_digest_bounds_fail_closed() {
        let valid = BootleLanternIssuanceAuthenticatedPrincipalV1 {
            principal_digest: raw(0x71),
            issued_at_height: 9,
            expires_at_height: 11,
        };
        assert_eq!(validate_authenticated_principal_v1(valid, 10), Ok(()));
        for invalid in [
            BootleLanternIssuanceAuthenticatedPrincipalV1 {
                principal_digest: [0; 32],
                ..valid
            },
            BootleLanternIssuanceAuthenticatedPrincipalV1 {
                issued_at_height: 0,
                ..valid
            },
            BootleLanternIssuanceAuthenticatedPrincipalV1 {
                issued_at_height: 11,
                ..valid
            },
            BootleLanternIssuanceAuthenticatedPrincipalV1 {
                expires_at_height: 9,
                ..valid
            },
            BootleLanternIssuanceAuthenticatedPrincipalV1 {
                issued_at_height: 12,
                expires_at_height: 11,
                ..valid
            },
        ] {
            assert_eq!(
                validate_authenticated_principal_v1(invalid, 10),
                Err(BootleLanternIssuanceApiErrorV1::Unauthorized)
            );
        }
    }
    #[test]
    fn linearization_guard_rechecks_height_and_both_lifetimes_at_every_boundary() {
        let fixture = native_operation_fixture();
        let registry = operation_registry([]);
        let guard = IssuanceLinearizationGuardV1::provider_only(&registry);
        assert_eq!(
            guard.assert_current(
                &fixture.snapshot,
                fixture.snapshot.committed_height,
                Some(fixture.snapshot.committed_height),
                fixture.snapshot.committed_height,
            ),
            Ok(fixture.snapshot.committed_height)
        );
        assert_eq!(
            guard.assert_current(
                &fixture.snapshot,
                fixture.snapshot.committed_height + 1,
                None,
                u64::MAX,
            ),
            Err(BootleLanternIssuanceApiErrorV1::PolicyUnavailable)
        );
        assert_eq!(
            guard.assert_current(
                &fixture.snapshot,
                fixture.snapshot.committed_height,
                None,
                fixture.snapshot.committed_height - 1,
            ),
            Err(BootleLanternIssuanceApiErrorV1::Unauthorized)
        );
        assert_eq!(
            guard.assert_current(
                &fixture.snapshot,
                fixture.snapshot.committed_height,
                Some(fixture.snapshot.committed_height - 1),
                u64::MAX,
            ),
            Err(BootleLanternIssuanceApiErrorV1::StateConflict)
        );
    }
    #[test]
    fn authenticator_panic_is_contained_without_exposing_the_credential() {
        let credential = BootleLanternIssuanceCredentialV1::new(b"runtime-secret".to_vec());
        assert_eq!(
            call_authenticator_v1(
                &PanicAuthenticator,
                credential.as_bytes(),
                BootleLanternIssuanceActionV1::Issue,
                raw(0xA1),
                10,
            )
            .expect_err("authenticator panic must be contained"),
            BootleLanternIssuanceApiErrorV1::ProviderUnavailable
        );
        assert_eq!(
            format!("{credential:?}"),
            "BootleLanternIssuanceCredentialV1([REDACTED])"
        );
    }
    #[test]
    fn provider_authorization_output_must_match_every_expected_field() {
        let principal = raw(0x81);
        assert_eq!(
            validate_authorization_output_fields_v1(principal, 20, 36, principal, 20, 36),
            Ok(())
        );
        for actual in [
            (raw(0x82), 20, 36),
            (principal, 19, 36),
            (principal, 20, 35),
        ] {
            assert_eq!(
                validate_authorization_output_fields_v1(
                    actual.0, actual.1, actual.2, principal, 20, 36,
                ),
                Err(BootleLanternIssuanceApiErrorV1::ProviderUnavailable)
            );
        }
    }
    #[test]
    fn replay_conflict_and_substitution_errors_have_closed_mappings() {
        for error in [
            BootleLanternIssuanceStoreErrorV1::AuthorizationNotYetValid,
            BootleLanternIssuanceStoreErrorV1::AuthorizationExpired,
            BootleLanternIssuanceStoreErrorV1::Busy,
            BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed,
        ] {
            assert_eq!(
                map_store_replay_error_v1(error),
                BootleLanternIssuanceApiErrorV1::StateConflict
            );
        }
        for error in [
            BootleLanternIssuanceErrorV1::AuthorizationBindingMismatch,
            BootleLanternIssuanceErrorV1::AuthorizationWireInvalid,
            BootleLanternIssuanceErrorV1::BlindRequestWireInvalid,
        ] {
            assert_eq!(
                BootleLanternIssuerCryptoProviderErrorV1::from(error),
                BootleLanternIssuerCryptoProviderErrorV1::InvalidRequest
            );
        }
        assert_eq!(
            map_store_replay_error_v1(BootleLanternIssuanceStoreErrorV1::Corrupt),
            BootleLanternIssuanceApiErrorV1::DurableStateUnavailable
        );
        assert_eq!(
            map_provider_error_v1(BootleLanternIssuerCryptoProviderErrorV1::PolicyMismatch),
            BootleLanternIssuanceApiErrorV1::PolicyUnavailable
        );
    }
    #[test]
    fn request_bindings_are_action_body_height_and_genesis_separated() {
        let authorize = request_binding_v1(AUTHORIZE_BINDING_DOMAIN_V1, &[], 10, raw(1))
            .expect("authorize binding");
        for substituted in [
            request_binding_v1(ISSUE_BINDING_DOMAIN_V1, &[], 10, raw(1)),
            request_binding_v1(AUTHORIZE_BINDING_DOMAIN_V1, &[0], 10, raw(1)),
            request_binding_v1(AUTHORIZE_BINDING_DOMAIN_V1, &[], 11, raw(1)),
            request_binding_v1(AUTHORIZE_BINDING_DOMAIN_V1, &[], 10, raw(2)),
        ] {
            assert_ne!(authorize, substituted.expect("substituted binding"));
        }
    }
}
