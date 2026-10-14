//! Cross-module gateway policy tests.

use super::{
    policy::{GatewayPolicy, GatewayPolicyConfig, PolicyDecision, PolicyViolation, RequestContext},
    rate_limit::{ClientFingerprint, GatewayRateLimitConfig, GatewayRateLimiter},
};
use crate::sorafs::AdmissionRegistry;
use std::{
    sync::Arc,
    time::{Instant, SystemTime},
};
fn sample_fingerprint() -> ClientFingerprint {
    ClientFingerprint::from_identifier("gateway-test-client")
}
#[test]
fn policy_allows_when_envelope_not_required() {
    let config = GatewayPolicyConfig {
        require_manifest_envelope: false,
        enforce_admission: false,
        rate_limit: GatewayRateLimitConfig::disabled(),
    };
    let rate_limiter = GatewayRateLimiter::new(config.rate_limit);
    let policy = GatewayPolicy::new(config, None, rate_limiter);
    let fingerprint = sample_fingerprint();
    let ctx = RequestContext::new(&fingerprint, SystemTime::now(), Instant::now());
    assert_eq!(policy.evaluate(&ctx), PolicyDecision::Allow);
}
#[test]
fn policy_denies_when_manifest_required() {
    let config = GatewayPolicyConfig::default();
    let admission = Some(Arc::new(AdmissionRegistry::empty([0xA1; 32])));
    let policy = GatewayPolicy::new(config, admission, GatewayRateLimiter::new_default());
    let provider = [0xAA; 32];
    let fingerprint = sample_fingerprint();
    let ctx = RequestContext::new(&fingerprint, SystemTime::now(), Instant::now())
        .with_provider_id(&provider);
    assert_eq!(
        policy.evaluate(&ctx),
        PolicyDecision::Deny(PolicyViolation::ManifestEnvelopeMissing)
    );
}
#[test]
fn policy_fails_closed_without_admission_registry() {
    let config = GatewayPolicyConfig {
        require_manifest_envelope: false,
        enforce_admission: true,
        rate_limit: GatewayRateLimitConfig::disabled(),
    };
    let rate_limiter = GatewayRateLimiter::new(config.rate_limit);
    let policy = GatewayPolicy::new(config, None, rate_limiter);
    let fingerprint = sample_fingerprint();
    let ctx = RequestContext::new(&fingerprint, SystemTime::now(), Instant::now());
    assert_eq!(
        policy.evaluate(&ctx),
        PolicyDecision::Deny(PolicyViolation::AdmissionUnavailable)
    );
}
