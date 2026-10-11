//! Bounded configuration parsing for explicit provider-selected enrollment service dependencies.

use super::*;
use iroha_data_model::kagemusha::*;
use std::result::Result;

mod worker;
pub use worker::KagemushaEnrollmentWorker;

/// Optional issuer configuration; absence disables enrollment serving.
#[derive(Clone, ReadConfig, norito::JsonDeserialize)]
pub struct KagemushaEnrollmentIssuer {
    /// Positive current generation of the complete configured route selection.
    pub revision: u64,
    /// Canonical lowercase nonzero 32-byte deployment identity.
    pub scope_hex: String,
    /// Existing owner-only journal directory; missing custody fails startup.
    pub journal_dir: PathBuf,
    /// Complete observation request timeout in milliseconds.
    #[config(default = "defaults::torii::kagemusha_enrollment::REQUEST_TIMEOUT_MS")]
    pub request_timeout_ms: u64,
    /// Maximum concurrent authenticated enrollment calls.
    #[config(default = "defaults::torii::kagemusha_enrollment::MAX_INFLIGHT")]
    pub max_inflight: usize,
    /// Nonempty provider/app route set; no default trust is provided.
    pub providers: Vec<KagemushaEnrollmentProvider>,
}

/// Exact canonical originals and runtime routing for a provider-selected application.
#[derive(Clone, ReadConfig, norito::JsonDeserialize)]
pub struct KagemushaEnrollmentProvider {
    /// Complete canonical eligibility-template frame, lowercase hex; unsigned selected DATA.
    pub eligibility_template_hex: String,
    /// Complete canonical Scheme frame, lowercase hex.
    pub scheme_hex: String,
    /// Complete canonical app-policy frame, lowercase hex.
    pub app_hex: String,
    /// Complete canonical enrollment-template frame, lowercase hex.
    pub enrollment_template_hex: String,
    /// Complete canonical rooted Enrollment certificate frame, lowercase hex.
    pub certificate_hex: String,
    /// Exact nonzero approved manifest identity, lowercase hex.
    pub manifest_digest_hex: String,
    /// Exact nonzero approved release identity, lowercase hex.
    pub release_digest_hex: String,
    /// Exact nonzero approved service-origin identity, lowercase hex.
    pub service_origin_digest_hex: String,
    /// Credential-free HTTPS middleware URL; no query, fragment or redirect substitution.
    pub observation_endpoint: String,
    /// Existing private transport credential file; raw secrets are not configuration leaves.
    pub observation_credential: PathBuf,
    /// Exact operator-selected local private verifier installation.
    pub worker: KagemushaEnrollmentWorker,
    /// Existing private file containing exactly one canonical 32-byte big-endian P-256 scalar.
    pub signer_private_key: PathBuf,
}

impl std::fmt::Debug for KagemushaEnrollmentIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KagemushaEnrollmentIssuer")
            .field("revision", &self.revision)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("max_inflight", &self.max_inflight)
            .field("providers", &self.providers.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for KagemushaEnrollmentProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KagemushaEnrollmentProvider")
            .finish_non_exhaustive()
    }
}

fn bounded_hex(text: &str, cap: usize) -> Result<Vec<u8>, &'static str> {
    if text.is_empty()
        || text.len() > cap.saturating_mul(2)
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("must be nonempty bounded canonical lowercase hex");
    }
    hex::decode(text).map_err(|_| "invalid original hex")
}

fn digest(text: &str) -> Result<[u8; 32], &'static str> {
    let value: [u8; 32] = bounded_hex(text, 32)?
        .try_into()
        .map_err(|_| "digest must contain exactly 32 bytes")?;
    if value == [0; 32] {
        return Err("digest must be nonzero");
    }
    Ok(value)
}

fn absolute_path(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("custody paths must be absolute without parent traversal");
    }
    Ok(())
}

fn endpoint(text: &str) -> Result<url::Url, &'static str> {
    if text.is_empty() || text.len() > 2048 {
        return Err("observation endpoint exceeds its bound");
    }
    let value = url::Url::parse(text).map_err(|_| "invalid observation endpoint")?;
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.query().is_some()
        || value.fragment().is_some()
        || value.as_str() != text
    {
        return Err("observation endpoint must be canonical credential-free HTTPS");
    }
    Ok(value)
}

impl KagemushaEnrollmentProvider {
    fn checked(self) -> Result<actual::KagemushaEnrollmentProvider, &'static str> {
        let eligibility = KagemushaEligibilityPolicyTemplateV1::decode_canonical(&bounded_hex(
            &self.eligibility_template_hex,
            KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1,
        )?)
        .map_err(|_| "invalid eligibility original")?;
        let scheme = KagemushaWalletSchemeV1::decode_canonical(
            &bounded_hex(&self.scheme_hex, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1)?,
            &eligibility.scheme_id,
        )
        .map_err(|_| "invalid selected Scheme original")?;
        let app = KagemushaWalletAppPolicyV1::decode_canonical(
            &bounded_hex(
                &self.app_hex,
                KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1,
            )?,
            &eligibility.scheme_id,
        )
        .map_err(|_| "invalid selected app original")?;
        let enrollment = KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(
            &bounded_hex(
                &self.enrollment_template_hex,
                KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1,
            )?,
            &eligibility.scheme_id,
        )
        .map_err(|_| "invalid selected enrollment original")?;
        enrollment
            .validate_for_app(&app)
            .map_err(|_| "app/enrollment selection differs")?;
        if scheme.network_id != eligibility.network_id {
            return Err("eligibility network differs from selected originals");
        }
        let certificate = KagemushaWalletSignerCertificateV1::decode_canonical(
            &bounded_hex(
                &self.certificate_hex,
                KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
            )?,
            &scheme,
        )
        .map_err(|_| "invalid selected signer certificate")?;
        certificate
            .verify_role(&scheme, KagemushaWalletSignerRoleV1::Enrollment)
            .map_err(|_| "selected certificate is not rooted Enrollment authority")?;
        let worker = self.worker.checked(&enrollment.platform)?;
        absolute_path(&self.signer_private_key)?;
        absolute_path(&self.observation_credential)?;
        Ok(actual::KagemushaEnrollmentProvider {
            eligibility,
            scheme,
            app,
            enrollment,
            certificate,
            manifest_digest: digest(&self.manifest_digest_hex)?,
            release_digest: digest(&self.release_digest_hex)?,
            service_origin_digest: digest(&self.service_origin_digest_hex)?,
            observation_endpoint: endpoint(&self.observation_endpoint)?,
            observation_credential: self.observation_credential,
            worker,
            signer_private_key: self.signer_private_key,
        })
    }
}

impl KagemushaEnrollmentIssuer {
    fn checked(self) -> Result<actual::KagemushaEnrollmentIssuer, &'static str> {
        if self.revision == 0
            || !(1..=60_000).contains(&self.request_timeout_ms)
            || !(1..=1024).contains(&self.max_inflight)
            || self.providers.is_empty()
            || self.providers.len() > 128
        {
            return Err(
                "revision must be positive and service limits and provider count must be bounded",
            );
        }
        absolute_path(&self.journal_dir)?;
        let scope = digest(&self.scope_hex)?;
        let mut keys = BTreeSet::new();
        let mut providers = Vec::with_capacity(self.providers.len());
        for provider in self.providers {
            let provider = provider.checked()?;
            let key = (
                provider.eligibility.authority.scope_digest(),
                provider.eligibility.scheme_id,
                provider
                    .app
                    .policy_digest()
                    .map_err(|_| "invalid app identity")?,
            );
            if !keys.insert(key) {
                return Err("duplicate provider/scheme/app route");
            }
            providers.push(provider);
        }
        Ok(actual::KagemushaEnrollmentIssuer {
            revision: self.revision,
            scope,
            journal_dir: self.journal_dir,
            request_timeout: Duration::from_millis(self.request_timeout_ms),
            max_inflight: self.max_inflight,
            providers,
        })
    }

    pub(super) fn parse(
        self,
        emitter: &mut Emitter<ParseError>,
    ) -> Option<actual::KagemushaEnrollmentIssuer> {
        match self.checked() {
            Ok(config) => Some(config),
            Err(error) => {
                emit_torii_config_error(emitter, format!("torii.kagemusha_enrollment: {error}"));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
