//! Explicit admitted policy for registered-account reads of a provider's immutable objects.
//!
//! This capability grants neither provider administration nor signer-operation authority.
//! Absence disables account issuance. Admission revocation or expiry withdraws the policy.

use super::{CapabilityTlv, CapabilityType};
use crate::token::{
    STREAM_TOKEN_MAX_RATE_LIMIT_BYTES_V1, STREAM_TOKEN_MAX_REQUESTS_PER_MINUTE_V1,
    STREAM_TOKEN_MAX_STREAMS_V1, STREAM_TOKEN_MAX_TTL_SECS_V1,
};

/// Complete canonical capability frame limit.
pub const ACCOUNT_READ_CAPABILITY_MAX_BYTES_V1: usize = 2_048;

/// Governed provider-wide immutable-object read policy for registered network accounts.
///
/// HTTPS is mandatory. The exact DNS hostname and port select one origin; path prefixes,
/// wildcard hosts, IP literals, credentials and caller-chosen origins are not supported.
/// Transport owners independently authorize and pin the exact addresses; the capability does not
/// authorize access to private or local networks.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1")]
pub struct RegisteredAccountReadV1 {
    /// Canonical lowercase ASCII DNS name, without a trailing dot.
    pub https_host: String,
    /// Exact nonzero HTTPS port, preserved by every origin and transport consumer.
    pub https_port: u16,
    /// Maximum lifetime of an issued account token in seconds.
    pub ttl_secs: u64,
    /// Maximum concurrent streams in an issued account token.
    pub max_streams: u16,
    /// Maximum byte-rate budget in an issued account token.
    pub rate_limit_bytes: u64,
    /// Maximum request budget and account issuance quota per minute.
    pub requests_per_minute: u32,
}

/// Invalid, duplicate, or noncanonical account-read capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid registered-account read capability")]
pub struct AccountReadCapabilityError;

impl RegisteredAccountReadV1 {
    /// Validate the exact origin grammar and positive protocol-bounded token limits.
    /// # Errors
    /// Rejects ambiguous origins, IP literals, invalid DNS labels, and excessive limits.
    pub fn validate(&self) -> Result<(), AccountReadCapabilityError> {
        let host = &self.https_host;
        let mut labels = host.split('.');
        if host.is_empty()
            || host.len() > 253
            || !host.contains('.')
            || !labels.all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || !host
                .rsplit('.')
                .next()
                .is_some_and(|label| label.bytes().any(|b| b.is_ascii_lowercase()))
            || self.https_port == 0
            || !(1..=STREAM_TOKEN_MAX_TTL_SECS_V1).contains(&self.ttl_secs)
            || !(1..=STREAM_TOKEN_MAX_STREAMS_V1).contains(&self.max_streams)
            || !(1..=STREAM_TOKEN_MAX_RATE_LIMIT_BYTES_V1).contains(&self.rate_limit_bytes)
            || !(1..=STREAM_TOKEN_MAX_REQUESTS_PER_MINUTE_V1).contains(&self.requests_per_minute)
        {
            return Err(AccountReadCapabilityError);
        }
        Ok(())
    }

    /// Return the canonical HTTPS origin after validating all policy fields.
    /// # Errors
    /// Rejects invalid origin or limit fields.
    pub fn https_origin(&self) -> Result<String, AccountReadCapabilityError> {
        self.validate()?;
        Ok(if self.https_port == 443 {
            format!("https://{}", self.https_host)
        } else {
            format!("https://{}:{}", self.https_host, self.https_port)
        })
    }

    /// Encode the policy in the sole admitted capability layout.
    /// # Errors
    /// Rejects malformed policies or encoding beyond the finite capability bound.
    pub fn to_capability(&self) -> Result<CapabilityTlv, AccountReadCapabilityError> {
        self.validate()?;
        let payload = norito::encode_canonical(self).map_err(|_| AccountReadCapabilityError)?;
        if payload.len() > ACCOUNT_READ_CAPABILITY_MAX_BYTES_V1 {
            return Err(AccountReadCapabilityError);
        }
        Ok(CapabilityTlv {
            cap_type: CapabilityType::RegisteredAccountRead,
            payload,
        })
    }

    /// Decode one exact admitted policy; absence disables registered-account token issuance.
    /// # Errors
    /// Rejects duplicate, oversized, noncanonical or invalid policy payloads.
    pub fn from_capabilities(
        capabilities: &[CapabilityTlv],
    ) -> Result<Option<Self>, AccountReadCapabilityError> {
        let mut found = None;
        for capability in capabilities
            .iter()
            .filter(|c| c.cap_type == CapabilityType::RegisteredAccountRead)
        {
            if found.is_some() || capability.payload.len() > ACCOUNT_READ_CAPABILITY_MAX_BYTES_V1 {
                return Err(AccountReadCapabilityError);
            }
            let value: Self = norito::decode_canonical_with_limits(
                &capability.payload,
                norito::DecodeLimits::new(
                    32,
                    ACCOUNT_READ_CAPABILITY_MAX_BYTES_V1,
                    512,
                    16 * 1024,
                    8,
                ),
            )
            .map_err(|_| AccountReadCapabilityError)?;
            value.validate()?;
            found = Some(value);
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> RegisteredAccountReadV1 {
        RegisteredAccountReadV1 {
            https_host: "storage.example.com".into(),
            https_port: 443,
            ttl_secs: 60,
            max_streams: 1,
            rate_limit_bytes: 16 * 1024 * 1024,
            requests_per_minute: 60,
        }
    }
    #[test]
    fn canonical_policy_roundtrip_and_absence_are_explicit() {
        let p = policy();
        assert_eq!(p.https_origin().unwrap(), "https://storage.example.com");
        let cap = p.to_capability().unwrap();
        assert_eq!(
            RegisteredAccountReadV1::from_capabilities(std::slice::from_ref(&cap)).unwrap(),
            Some(p.clone())
        );
        assert_eq!(
            RegisteredAccountReadV1::from_capabilities(&[]).unwrap(),
            None
        );
        assert!(RegisteredAccountReadV1::from_capabilities(&[cap.clone(), cap]).is_err());
        let json = norito::json::to_json(&p).unwrap();
        assert_eq!(
            norito::json::from_str::<RegisteredAccountReadV1>(&json).unwrap(),
            p
        );
    }
    #[test]
    fn explicit_nondefault_https_ports_roundtrip_without_remapping() {
        for port in [1, 80, 8443, u16::MAX] {
            let mut p = policy();
            p.https_port = port;
            assert_eq!(
                p.https_origin().unwrap(),
                format!("https://storage.example.com:{port}")
            );
            let cap = p.to_capability().unwrap();
            assert_eq!(
                RegisteredAccountReadV1::from_capabilities(&[cap]).unwrap(),
                Some(p.clone())
            );
            let binary = norito::encode_canonical(&p).unwrap();
            assert_eq!(
                norito::decode_canonical::<RegisteredAccountReadV1>(&binary).unwrap(),
                p
            );
            let json = norito::json::to_json(&p).unwrap();
            assert_eq!(
                norito::json::from_str::<RegisteredAccountReadV1>(&json).unwrap(),
                p
            );
        }
    }
    #[test]
    fn ambiguous_hosts_and_unbounded_policies_are_rejected() {
        for host in [
            "",
            "localhost",
            "127.0.0.1",
            "[::1]",
            "EXAMPLE.com",
            "example.com.",
            "*.example.com",
            "a..example.com",
            "-a.example.com",
            "a-.example.com",
            "a/b.example.com",
            "user@example.com",
        ] {
            let mut p = policy();
            p.https_host = host.into();
            assert!(p.validate().is_err(), "{host}");
        }
        let mut p = policy();
        p.https_port = 0;
        assert!(p.validate().is_err());
        let mut p = policy();
        p.ttl_secs = STREAM_TOKEN_MAX_TTL_SECS_V1 + 1;
        assert!(p.validate().is_err());
        let mut cap = policy().to_capability().unwrap();
        cap.payload.push(0);
        assert!(RegisteredAccountReadV1::from_capabilities(&[cap]).is_err());
    }
}
