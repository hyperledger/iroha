//! Explicit issuer trust selection. Configuration is not a provider eligibility observation.

use iroha_data_model::kagemusha::{
    KagemushaEligibilityPolicyTemplateV1, KagemushaWalletAppPolicyV1,
    KagemushaWalletEnrollmentPolicyTemplateV1, KagemushaWalletSchemeV1,
    KagemushaWalletSignerCertificateV1,
};
use std::{path::PathBuf, time::Duration};
use url::Url;

mod worker;
pub use worker::KagemushaEnrollmentWorker;

/// Required deployment dependencies for the optional KAGEMUSHA enrollment service.
///
/// No default signer, worker or provider is selected. Runtime owners must authenticate
/// the configured custody and independently check current ledger registration and provider approval.
#[derive(Clone, PartialEq, Eq)]
pub struct KagemushaEnrollmentIssuer {
    /// Positive generation of this complete operator-selected route set.
    pub revision: u64,
    /// Permanent issuer deployment identity used by the durable journal.
    pub scope: [u8; 32],
    /// Existing private attempt journal. Ordinary startup must never create a missing store.
    pub journal_dir: PathBuf,
    /// Bound for one complete middleware observation request.
    pub request_timeout: Duration,
    /// Bound on concurrent authenticated enrollment requests.
    pub max_inflight: usize,
    /// Exact approved provider/app/scheme routes; matching is provisional until provider approval.
    pub providers: Vec<KagemushaEnrollmentProvider>,
}

/// One exact approved provider/app route and its independently configured native service owners.
#[derive(Clone, PartialEq, Eq)]
pub struct KagemushaEnrollmentProvider {
    /// Public unsigned asset-independent eligibility template; the authenticated issuer configuration selects it.
    pub eligibility: KagemushaEligibilityPolicyTemplateV1,
    /// Exact Scheme original, also required to match current ledger registration.
    pub scheme: KagemushaWalletSchemeV1,
    /// Exact approved platform application original.
    pub app: KagemushaWalletAppPolicyV1,
    /// Exact asset-independent platform evidence and lease template original.
    pub enrollment: KagemushaWalletEnrollmentPolicyTemplateV1,
    /// Rooted Enrollment-role public certificate, not private signing custody.
    pub certificate: KagemushaWalletSignerCertificateV1,
    /// Exact approved native artifact manifest identity.
    pub manifest_digest: [u8; 32],
    /// Exact approved installed release identity.
    pub release_digest: [u8; 32],
    /// Exact approved issuer service origin identity.
    pub service_origin_digest: [u8; 32],
    /// Credential-free HTTPS observation endpoint; redirect following is prohibited.
    pub observation_endpoint: Url,
    /// Existing private transport credential file, opened by the authenticated transport owner.
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
            .field("scope", &self.scope)
            .field("request_timeout", &self.request_timeout)
            .field("max_inflight", &self.max_inflight)
            .field("providers", &self.providers.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for KagemushaEnrollmentProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KagemushaEnrollmentProvider")
            .field("eligibility", &self.eligibility)
            .field("scheme", &self.scheme.scheme_id())
            .finish_non_exhaustive()
    }
}
