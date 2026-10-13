//! Deterministic ACME automation harness for the SoraFS gateway.
use super::provider::{GatewayProviderBindingErrorV1, GatewayProviderBindingV1};
use blake3::Hasher;
use std::{
    fmt::{self, Debug},
    sync::Arc,
    time::{Duration, SystemTime},
};
use thiserror::Error;
/// Challenge profile describing which ACME flows must be exercised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeProfile {
    /// Whether DNS-01 challenges should be solved.
    pub dns01: bool,
    /// Whether TLS-ALPN-01 challenges should be solved.
    pub tls_alpn_01: bool,
}
impl Default for ChallengeProfile {
    fn default() -> Self {
        Self {
            dns01: true,
            tls_alpn_01: true,
        }
    }
}
/// Static configuration for ACME automation.
#[derive(Clone)]
pub struct AcmeConfig {
    /// Toggle automation behaviour.
    pub enabled: bool,
    /// Account email registered with the ACME provider.
    pub account_email: Option<String>,
    /// Directory URL (Let’s Encrypt, staging, custom).
    pub directory_url: String,
    /// Hostnames covered by the certificate.
    pub hostnames: Vec<String>,
    /// Identifier of the DNS provider plugin used for DNS-01 challenges.
    pub dns_provider_id: Option<String>,
    /// Renewal window applied before certificate expiry.
    pub renewal_window: Duration,
    /// Backoff applied after failures.
    pub retry_backoff: Duration,
    /// Maximum jitter applied to retry scheduling.
    pub retry_jitter: Duration,
    /// Challenge profile to exercise.
    pub challenge: ChallengeProfile,
}
impl Debug for AcmeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeConfig")
            .field("enabled", &self.enabled)
            .field(
                "account_email",
                &self.account_email.as_ref().map(|_| "<redacted>"),
            )
            .field("directory_url", &self.directory_url)
            .field("hostnames", &self.hostnames)
            .field("dns_provider_id", &self.dns_provider_id)
            .field("renewal_window", &self.renewal_window)
            .field("retry_backoff", &self.retry_backoff)
            .field("retry_jitter", &self.retry_jitter)
            .field("challenge", &self.challenge)
            .finish()
    }
}
impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            account_email: None,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            hostnames: vec![],
            dns_provider_id: None,
            renewal_window: Duration::from_hours(30 * 24), // 30 days
            retry_backoff: Duration::from_mins(30),        // 30 minutes
            retry_jitter: Duration::from_mins(5),          // up to 5 minutes
            challenge: ChallengeProfile::default(),
        }
    }
}
/// Certificate and key material emitted by ACME renewals.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificateBundle {
    /// PEM-encoded certificate chain.
    pub certificate_pem: String,
    /// PEM-encoded private key.
    pub private_key_pem: String,
    /// Optional ECH config blob emitted with the certificate.
    pub ech_config: Option<Vec<u8>>,
    /// Expiry timestamp of the certificate.
    pub not_after: SystemTime,
}
impl Debug for CertificateBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateBundle")
            .field("certificate_pem_bytes", &self.certificate_pem.len())
            .field("private_key_pem", &"<redacted>")
            .field("ech_config_bytes", &self.ech_config.as_ref().map(Vec::len))
            .field("not_after", &self.not_after)
            .finish()
    }
}
impl Drop for CertificateBundle {
    fn drop(&mut self) {
        scrub_acme_secret_string(&mut self.private_key_pem);
        if let Some(ech_config) = self.ech_config.as_mut() {
            ech_config.fill(0);
            let _ = std::hint::black_box(ech_config.as_slice());
        }
    }
}
fn scrub_acme_secret_string(value: &mut String) {
    if !value.is_empty() {
        let zeroes = "\0".repeat(value.len());
        value.replace_range(.., &zeroes);
        let _ = std::hint::black_box(value.as_bytes());
    }
}
/// Order descriptor passed to the ACME client implementation.
#[derive(Clone)]
pub struct CertificateOrder {
    /// Hostnames covered in the order.
    pub hostnames: Vec<String>,
    /// Account email derived from config.
    pub account_email: Option<String>,
    /// ACME directory URL.
    pub directory_url: String,
    /// DNS provider selected for DNS-01 automation.
    pub dns_provider_id: Option<String>,
    /// Challenge profile to satisfy.
    pub challenge: ChallengeProfile,
}
impl Debug for CertificateOrder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateOrder")
            .field("hostnames", &self.hostnames)
            .field(
                "account_email",
                &self.account_email.as_ref().map(|_| "<redacted>"),
            )
            .field("directory_url", &self.directory_url)
            .field("dns_provider_id", &self.dns_provider_id)
            .field("challenge", &self.challenge)
            .finish()
    }
}
/// Errors emitted by the ACME client implementation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AcmeClientError {
    /// Endpoint rejected the request permanently.
    #[error("acme provider rejected the certificate order")]
    Rejected,
    /// ACME server signalled a transient failure with optional retry hint.
    #[error("acme order temporarily rejected")]
    Temporary {
        /// Optional retry-after duration.
        retry_after: Option<Duration>,
    },
    /// Underlying transport or cryptographic failure.
    #[error("acme provider transport or cryptographic operation failed")]
    Transport,
}
/// Payload-free public identity reported by one runtime ACME provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeClientIdentityV1 {
    /// Stable provider contract handle; never a credential or endpoint token.
    pub provider_handle: String,
    /// Monotonic deployed adapter and public-policy revision.
    pub revision: u64,
    /// Digest of the exact non-secret provider policy.
    pub policy_digest: [u8; 32],
    /// Explicit marker set by test, mock, development, or placeholder clients.
    pub test_marked: bool,
}
/// Redacted failure returned when an ACME client cannot attest its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ACME client qualification failed")]
pub struct AcmeClientProbeError;
/// Runtime-injected ACME client backend.
///
/// Implementations own all provider credentials and transport state. Torii does
/// not provide a production fallback client.
pub trait AcmeClient: Send + Sync {
    /// Return the public identity of the provider that will execute orders.
    ///
    /// Provider diagnostics, credentials, and private material must remain
    /// behind this payload-free probe.
    ///
    /// # Errors
    ///
    /// Returns `AcmeClientProbeError` if the backend cannot provide its current
    /// public provider identity.
    fn qualification(&self) -> Result<AcmeClientIdentityV1, AcmeClientProbeError>;
    /// Place an order and return the resulting certificate bundle.
    ///
    /// # Errors
    ///
    /// Returns [`AcmeClientError`] when the ACME backend cannot fulfil the order.
    fn order_certificate(
        &self,
        order: &CertificateOrder,
    ) -> Result<CertificateBundle, AcmeClientError>;
}
impl<T> AcmeClient for Arc<T>
where
    T: AcmeClient + ?Sized,
{
    fn qualification(&self) -> Result<AcmeClientIdentityV1, AcmeClientProbeError> {
        (**self).qualification()
    }
    fn order_certificate(
        &self,
        order: &CertificateOrder,
    ) -> Result<CertificateBundle, AcmeClientError> {
        (**self).order_certificate(order)
    }
}
/// Errors surfaced by the automation harness.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AcmeAutomationError {
    /// The configured public provider binding is invalid.
    #[error("configured ACME client binding is invalid")]
    InvalidClientBinding,
    /// The runtime client could not prove that it is current and available.
    #[error("ACME client is unavailable or unqualified")]
    ClientUnavailable,
    /// The runtime client handle or public policy does not match configuration.
    #[error("ACME client was substituted")]
    ClientSubstituted,
    /// The runtime client revision differs from configuration.
    #[error("ACME client revision is stale")]
    ClientStale,
    /// Test, mock, development, and placeholder clients are forbidden.
    #[error("ACME client is test-marked")]
    ClientTestMarked,
    /// ACME client failure.
    #[error("acme client error: {0}")]
    Client(AcmeClientError),
}
#[derive(Debug, Default, Clone)]
struct AcmeState {
    bundle: Option<CertificateBundle>,
    last_success: Option<SystemTime>,
    last_error: Option<AcmeAutomationError>,
    next_attempt: Option<SystemTime>,
    attempts: u32,
}
impl AcmeState {
    fn record_success(&mut self, bundle: CertificateBundle, now: SystemTime) {
        self.bundle = Some(bundle);
        self.last_success = Some(now);
        self.last_error = None;
        self.attempts = 0;
        self.next_attempt = None;
    }
    fn record_failure(&mut self, error: AcmeAutomationError, retry_at: SystemTime) {
        self.last_error = Some(error);
        self.attempts = self.attempts.saturating_add(1);
        self.next_attempt = Some(retry_at);
    }
    fn certificate(&self) -> Option<&CertificateBundle> {
        self.bundle.as_ref()
    }
}
/// Deterministic ACME automation harness.
pub struct AcmeAutomation<C> {
    config: AcmeConfig,
    client_binding: GatewayProviderBindingV1,
    client: C,
    state: AcmeState,
}
impl<C> Debug for AcmeAutomation<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeAutomation")
            .field("config", &self.config)
            .field("client_binding", &self.client_binding)
            .field("client", &"<runtime-only>")
            .field("state", &self.state)
            .finish()
    }
}
impl<C> AcmeAutomation<C>
where
    C: AcmeClient,
{
    /// Construct an automation harness after qualifying its exact provider.
    ///
    /// # Errors
    ///
    /// Returns a payload-free error when the provider is unavailable,
    /// substituted, stale, invalid, or test-marked.
    pub fn try_new(
        config: AcmeConfig,
        client_binding: GatewayProviderBindingV1,
        client: C,
    ) -> Result<Self, AcmeAutomationError> {
        qualify_acme_client(&client_binding, &client)?;
        Ok(Self {
            config,
            client_binding,
            client,
            state: AcmeState::default(),
        })
    }
    /// Access the last known certificate bundle.
    #[must_use]
    pub fn certificate(&self) -> Option<&CertificateBundle> {
        self.state.certificate()
    }
    /// Returns the last error recorded by the automation loop.
    #[must_use]
    pub fn last_error(&self) -> Option<&AcmeAutomationError> {
        self.state.last_error.as_ref()
    }
    /// Execute the automation loop. Returns `Some(bundle)` when a renewal succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`AcmeAutomationError`] when the ACME backend reports a failure.
    pub fn process(
        &mut self,
        now: SystemTime,
    ) -> Result<Option<CertificateBundle>, AcmeAutomationError> {
        if !self.config.enabled {
            return Ok(None);
        }
        if let Some(next_attempt) = self.state.next_attempt {
            if now < next_attempt {
                return Ok(None);
            }
        }
        if !self.needs_renewal(now) {
            return Ok(None);
        }
        let order = CertificateOrder {
            hostnames: self.config.hostnames.clone(),
            account_email: self.config.account_email.clone(),
            directory_url: self.config.directory_url.clone(),
            dns_provider_id: self.config.dns_provider_id.clone(),
            challenge: self.config.challenge.clone(),
        };
        qualify_acme_client(&self.client_binding, &self.client)?;
        let result = self.client.order_certificate(&order);
        if let Err(error) = qualify_acme_client(&self.client_binding, &self.client) {
            drop(result);
            let retry_at = now + self.config.retry_backoff + self.compute_jitter();
            self.state.record_failure(error, retry_at);
            return Err(error);
        }
        match result {
            Ok(bundle) => {
                let deadline = self.next_deadline(&bundle);
                self.state.record_success(bundle.clone(), now);
                self.state.next_attempt = Some(deadline);
                Ok(Some(bundle))
            }
            Err(err) => {
                let retry_after = match &err {
                    AcmeClientError::Temporary { retry_after } => *retry_after,
                    _ => None,
                };
                let jitter = self.compute_jitter();
                let backoff_base = retry_after.unwrap_or(self.config.retry_backoff);
                let retry_at = now + backoff_base + jitter.min(self.config.retry_jitter);
                let error = AcmeAutomationError::Client(err);
                self.state.record_failure(error, retry_at);
                Err(error)
            }
        }
    }
    fn needs_renewal(&self, now: SystemTime) -> bool {
        self.state.bundle.as_ref().map_or(true, |bundle| {
            bundle
                .not_after
                .checked_sub(self.config.renewal_window)
                .map_or(true, |renew_at| now >= renew_at)
        })
    }
    fn next_deadline(&self, bundle: &CertificateBundle) -> SystemTime {
        bundle
            .not_after
            .checked_sub(self.config.renewal_window)
            .unwrap_or(bundle.not_after)
    }
    fn compute_jitter(&self) -> Duration {
        if self.config.retry_jitter.is_zero() {
            return Duration::ZERO;
        }
        let mut hasher = Hasher::new();
        for host in &self.config.hostnames {
            hasher.update(host.as_bytes());
        }
        hasher.update(&self.state.attempts.to_le_bytes());
        let hash = hasher.finalize();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&hash.as_bytes()[..8]);
        let spread = u64::from_le_bytes(buf);
        let max_ns = self
            .config
            .retry_jitter
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        if max_ns == 0 {
            return Duration::ZERO;
        }
        let jitter_ns = spread % (max_ns + 1);
        Duration::from_nanos(jitter_ns)
    }
    #[cfg(test)]
    /// Returns the scheduled next attempt for test verification.
    pub fn next_attempt(&self) -> Option<SystemTime> {
        self.state.next_attempt
    }
}
fn qualify_acme_client(
    expected: &GatewayProviderBindingV1,
    client: &dyn AcmeClient,
) -> Result<(), AcmeAutomationError> {
    let observed = client
        .qualification()
        .map_err(|_| AcmeAutomationError::ClientUnavailable)?;
    if observed.test_marked {
        return Err(AcmeAutomationError::ClientTestMarked);
    }
    let observed_binding = GatewayProviderBindingV1::try_new(
        observed.provider_handle,
        observed.revision,
        observed.policy_digest,
    )
    .map_err(|error| match error {
        GatewayProviderBindingErrorV1::TestMarkedHandle => AcmeAutomationError::ClientTestMarked,
        GatewayProviderBindingErrorV1::InvalidHandle
        | GatewayProviderBindingErrorV1::ZeroRevision
        | GatewayProviderBindingErrorV1::ZeroPolicyDigest => AcmeAutomationError::ClientUnavailable,
    })?;
    if observed_binding.provider_handle() != expected.provider_handle() {
        return Err(AcmeAutomationError::ClientSubstituted);
    }
    if observed_binding.revision() != expected.revision() {
        return Err(AcmeAutomationError::ClientStale);
    }
    if observed_binding.policy_digest() != expected.policy_digest() {
        return Err(AcmeAutomationError::ClientSubstituted);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    const TEST_PROVIDER_HANDLE: &str = "runtime://sorafs/gateway-acme/primary";
    const TEST_PROVIDER_REVISION: u64 = 7;
    const TEST_PROVIDER_POLICY_DIGEST: [u8; 32] = [0xA7; 32];
    #[derive(Debug)]
    struct MockClient {
        responses: Mutex<Vec<Result<CertificateBundle, AcmeClientError>>>,
        identity: Mutex<AcmeClientIdentityV1>,
        probe_available: AtomicBool,
        drift_revision_on_order: AtomicBool,
        drift_policy_on_order: AtomicBool,
        test_mark_on_order: AtomicBool,
        qualification_calls: AtomicUsize,
        order_calls: AtomicUsize,
    }
    impl MockClient {
        fn with_responses(responses: Vec<Result<CertificateBundle, AcmeClientError>>) -> Self {
            Self::with_identity(responses, expected_identity())
        }
        fn with_identity(
            responses: Vec<Result<CertificateBundle, AcmeClientError>>,
            identity: AcmeClientIdentityV1,
        ) -> Self {
            Self {
                responses: Mutex::new(responses),
                identity: Mutex::new(identity),
                probe_available: AtomicBool::new(true),
                drift_revision_on_order: AtomicBool::new(false),
                drift_policy_on_order: AtomicBool::new(false),
                test_mark_on_order: AtomicBool::new(false),
                qualification_calls: AtomicUsize::new(0),
                order_calls: AtomicUsize::new(0),
            }
        }
    }
    impl AcmeClient for MockClient {
        fn qualification(&self) -> Result<AcmeClientIdentityV1, AcmeClientProbeError> {
            self.qualification_calls.fetch_add(1, Ordering::SeqCst);
            if !self.probe_available.load(Ordering::SeqCst) {
                return Err(AcmeClientProbeError);
            }
            Ok(self
                .identity
                .lock()
                .expect("mock ACME identity lock poisoned")
                .clone())
        }
        fn order_certificate(
            &self,
            _order: &CertificateOrder,
        ) -> Result<CertificateBundle, AcmeClientError> {
            self.order_calls.fetch_add(1, Ordering::SeqCst);
            let response = self
                .responses
                .lock()
                .expect("mock response lock poisoned")
                .pop()
                .unwrap_or(Err(AcmeClientError::Transport));
            if self.drift_revision_on_order.swap(false, Ordering::SeqCst) {
                self.identity
                    .lock()
                    .expect("mock ACME identity lock poisoned")
                    .revision += 1;
            }
            if self.drift_policy_on_order.swap(false, Ordering::SeqCst) {
                self.identity
                    .lock()
                    .expect("mock ACME identity lock poisoned")
                    .policy_digest[0] ^= 0xFF;
            }
            if self.test_mark_on_order.swap(false, Ordering::SeqCst) {
                self.identity
                    .lock()
                    .expect("mock ACME identity lock poisoned")
                    .test_marked = true;
            }
            response
        }
    }
    fn expected_binding() -> GatewayProviderBindingV1 {
        GatewayProviderBindingV1::try_new(
            TEST_PROVIDER_HANDLE.to_owned(),
            TEST_PROVIDER_REVISION,
            TEST_PROVIDER_POLICY_DIGEST,
        )
        .expect("valid test ACME provider binding")
    }
    fn expected_identity() -> AcmeClientIdentityV1 {
        AcmeClientIdentityV1 {
            provider_handle: TEST_PROVIDER_HANDLE.to_owned(),
            revision: TEST_PROVIDER_REVISION,
            policy_digest: TEST_PROVIDER_POLICY_DIGEST,
            test_marked: false,
        }
    }
    fn automation(config: AcmeConfig, client: Arc<MockClient>) -> AcmeAutomation<Arc<MockClient>> {
        AcmeAutomation::try_new(config, expected_binding(), client)
            .expect("qualified ACME automation")
    }
    fn sample_bundle(valid_for: Duration, now: SystemTime) -> CertificateBundle {
        CertificateBundle {
            certificate_pem: "CERT".to_string(),
            private_key_pem: "SECRET-PRIVATE-KEY".to_string(),
            ech_config: None,
            not_after: now + valid_for,
        }
    }
    #[test]
    fn certificate_debug_redacts_private_key_material() {
        let bundle = sample_bundle(Duration::from_secs(60), SystemTime::now());
        let debug = format!("{bundle:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("SECRET-PRIVATE-KEY"));
    }
    #[test]
    fn acme_debug_surfaces_redact_contact_and_runtime_client_state() {
        let private_contact = "private-operator@example.test";
        let config = AcmeConfig {
            enabled: true,
            account_email: Some(private_contact.to_owned()),
            hostnames: vec!["gateway.example.test".to_owned()],
            ..AcmeConfig::default()
        };
        let order = CertificateOrder {
            hostnames: config.hostnames.clone(),
            account_email: config.account_email.clone(),
            directory_url: config.directory_url.clone(),
            dns_provider_id: config.dns_provider_id.clone(),
            challenge: config.challenge,
        };
        assert!(!format!("{config:?}").contains(private_contact));
        assert!(!format!("{order:?}").contains(private_contact));
        let client = Arc::new(MockClient::with_responses(vec![Ok(sample_bundle(
            Duration::from_secs(60),
            SystemTime::now(),
        ))]));
        let automation = automation(config, client);
        let debug = format!("{automation:?}");
        assert!(debug.contains("<runtime-only>"));
        assert!(!debug.contains(private_contact));
        assert!(!debug.contains("SECRET-PRIVATE-KEY"));
    }
    #[test]
    fn qualification_rejects_bad_clients_before_ordering() {
        let cases = [
            (
                AcmeClientIdentityV1 {
                    provider_handle: "runtime://sorafs/gateway-acme/secondary".to_owned(),
                    ..expected_identity()
                },
                AcmeAutomationError::ClientSubstituted,
            ),
            (
                AcmeClientIdentityV1 {
                    revision: TEST_PROVIDER_REVISION - 1,
                    ..expected_identity()
                },
                AcmeAutomationError::ClientStale,
            ),
            (
                AcmeClientIdentityV1 {
                    policy_digest: [0xB8; 32],
                    ..expected_identity()
                },
                AcmeAutomationError::ClientSubstituted,
            ),
            (
                AcmeClientIdentityV1 {
                    test_marked: true,
                    ..expected_identity()
                },
                AcmeAutomationError::ClientTestMarked,
            ),
            (
                AcmeClientIdentityV1 {
                    provider_handle: "runtime://sorafs/gateway-acme/dummy".to_owned(),
                    ..expected_identity()
                },
                AcmeAutomationError::ClientTestMarked,
            ),
            (
                AcmeClientIdentityV1 {
                    provider_handle: "kms gateway acme primary".to_owned(),
                    ..expected_identity()
                },
                AcmeAutomationError::ClientUnavailable,
            ),
            (
                AcmeClientIdentityV1 {
                    revision: 0,
                    ..expected_identity()
                },
                AcmeAutomationError::ClientUnavailable,
            ),
            (
                AcmeClientIdentityV1 {
                    policy_digest: [0; 32],
                    ..expected_identity()
                },
                AcmeAutomationError::ClientUnavailable,
            ),
        ];
        for (identity, expected_error) in cases {
            let client = Arc::new(MockClient::with_identity(Vec::new(), identity));
            let error = AcmeAutomation::try_new(
                AcmeConfig {
                    enabled: true,
                    ..AcmeConfig::default()
                },
                expected_binding(),
                Arc::clone(&client),
            )
            .expect_err("bad ACME client must fail startup");
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected_error),
            );
            assert_eq!(client.order_calls.load(Ordering::SeqCst), 0);
            assert_eq!(client.qualification_calls.load(Ordering::SeqCst), 1);
        }
        let unavailable = Arc::new(MockClient::with_responses(Vec::new()));
        unavailable.probe_available.store(false, Ordering::SeqCst);
        assert!(matches!(
            AcmeAutomation::try_new(
                AcmeConfig {
                    enabled: true,
                    ..AcmeConfig::default()
                },
                expected_binding(),
                Arc::clone(&unavailable),
            ),
            Err(AcmeAutomationError::ClientUnavailable)
        ));
        assert_eq!(unavailable.order_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn automation_renews_when_due() {
        let now = SystemTime::now();
        let client = Arc::new(MockClient::with_responses(vec![Ok(sample_bundle(
            Duration::from_hours(90 * 24),
            now,
        ))]));
        let config = AcmeConfig {
            enabled: true,
            hostnames: vec!["gateway.example.com".to_string()],
            ..AcmeConfig::default()
        };
        let mut automation = automation(config, client);
        let result = automation.process(now).expect("renewal");
        assert!(result.is_some());
        assert!(automation.certificate().is_some());
    }
    #[test]
    fn automation_waits_until_window() {
        let now = SystemTime::now();
        let bundle = sample_bundle(Duration::from_hours(90 * 24), now);
        let client = Arc::new(MockClient::with_responses(vec![Ok(bundle.clone())]));
        let config = AcmeConfig {
            enabled: true,
            hostnames: vec!["gateway.example.com".to_string()],
            ..AcmeConfig::default()
        };
        let mut automation = automation(config, client);
        let initial = automation.process(now).expect("initial renewal");
        assert!(initial.is_some());
        let later = now + Duration::from_hours(10 * 24);
        let result = automation.process(later).expect("no-op");
        assert!(result.is_none());
    }
    #[test]
    fn automation_backoff_on_error() {
        let now = SystemTime::now();
        let client = Arc::new(MockClient::with_responses(vec![Err(
            AcmeClientError::Temporary {
                retry_after: Some(Duration::from_mins(1)),
            },
        )]));
        let config = AcmeConfig {
            enabled: true,
            retry_backoff: Duration::from_secs(10),
            retry_jitter: Duration::from_secs(0),
            hostnames: vec!["gateway.example.com".to_string()],
            ..AcmeConfig::default()
        };
        let mut automation = automation(config, client);
        let err = automation.process(now).expect_err("expected failure");
        assert!(matches!(err, AcmeAutomationError::Client(_)));
        let retry_at = automation.next_attempt().expect("retry scheduled");
        assert!(retry_at >= now + Duration::from_mins(1));
    }
    #[test]
    fn automation_discards_certificate_when_provider_drifts_during_order() {
        for (drift, expected_error) in [
            ("revision", AcmeAutomationError::ClientStale),
            ("policy", AcmeAutomationError::ClientSubstituted),
            ("test-mark", AcmeAutomationError::ClientTestMarked),
        ] {
            let now = SystemTime::now();
            let client = Arc::new(MockClient::with_responses(vec![Ok(sample_bundle(
                Duration::from_hours(90 * 24),
                now,
            ))]));
            match drift {
                "revision" => client.drift_revision_on_order.store(true, Ordering::SeqCst),
                "policy" => client.drift_policy_on_order.store(true, Ordering::SeqCst),
                "test-mark" => client.test_mark_on_order.store(true, Ordering::SeqCst),
                _ => unreachable!("fixed test drift"),
            }
            let mut automation = automation(
                AcmeConfig {
                    enabled: true,
                    hostnames: vec!["gateway.example.com".to_owned()],
                    ..AcmeConfig::default()
                },
                Arc::clone(&client),
            );
            let error = automation
                .process(now)
                .expect_err("in-flight provider drift must discard returned key material");
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected_error)
            );
            assert!(automation.certificate().is_none());
            assert_eq!(client.order_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                client.qualification_calls.load(Ordering::SeqCst),
                3,
                "startup and operation pre/post identities must be checked"
            );
        }
    }
}
