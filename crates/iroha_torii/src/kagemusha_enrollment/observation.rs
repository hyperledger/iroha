//! Bounded HTTPS eligibility observations under exact configured provider and credential custody.
//!
//! Transport success supplies response DATA only. Core independently verifies its current
//! policy, signature, request binding, expiry and single-use journal boundary.

use iroha_config::parameters::actual::KagemushaEnrollmentProvider;
use iroha_core::kagemusha_wallet_v1::enrollment_issuer::EnrollmentIssuerErrorV1 as Error;
use iroha_data_model::kagemusha::{
    KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1, KagemushaEligibilityObservationV1,
    KagemushaEligibilityRequestV1, KagemushaWalletAssetScopeV1,
};
use iroha_fs::{FileSnapshot, RetainedFile};
use reqwest::{
    StatusCode,
    blocking::{Client, ClientBuilder},
    header::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, HeaderValue},
};
use std::{
    io::{self, Read as _},
    path::{Component, Path},
    time::{Duration, Instant},
};
use url::Url;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Error>;
const MAX_CREDENTIAL: usize = 4096;
const MIME: &str = "application/x-norito";

/// One configured provider endpoint; redirects, ambient proxies and credential replacement reject.
pub(super) struct EligibilityObservationTransport {
    selected: KagemushaEnrollmentProvider,
    http: ObservationHttp,
}

impl EligibilityObservationTransport {
    /// Open an existing required credential. Call from the service's blocking runtime owner.
    pub(super) fn open(provider: &KagemushaEnrollmentProvider) -> Result<Self> {
        provider
            .eligibility
            .validate()
            .map_err(|_| Error::Invalid)?;
        Ok(Self {
            selected: provider.clone(),
            http: ObservationHttp::open(
                &provider.observation_endpoint,
                &provider.observation_credential,
                client_builder(),
            )?,
        })
    }

    /// Check retained custody even when no observation is currently being sent.
    pub(super) fn revalidate(&self, provider: &KagemushaEnrollmentProvider) -> Result<()> {
        if &self.selected != provider {
            return Err(Error::Selection);
        }
        self.http.credential.revalidate()
    }

    /// POST exactly one canonical scoped request, without retries or cached approval.
    pub(super) fn observe(
        &self,
        provider: &KagemushaEnrollmentProvider,
        asset: &KagemushaWalletAssetScopeV1,
        original: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.revalidate(provider)?;
        let policy = provider
            .eligibility
            .for_asset(asset)
            .map_err(|_| Error::Invalid)?;
        let request = KagemushaEligibilityRequestV1::decode_canonical(original, &policy)
            .map_err(|_| Error::Invalid)?;
        let observation = KagemushaEligibilityObservationV1 {
            version: 1,
            asset: asset.clone(),
            request,
        }
        .encode_canonical(&provider.eligibility)
        .map_err(|_| Error::Invalid)?;
        let response = self.http.observe(&observation, timeout)?;
        self.revalidate(provider)?;
        Ok(response)
    }
}

fn client_builder() -> ClientBuilder {
    Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
}

struct ObservationHttp {
    endpoint: Url,
    client: Client,
    credential: Credential,
}

impl ObservationHttp {
    fn open(endpoint: &Url, credential: &Path, builder: ClientBuilder) -> Result<Self> {
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.as_str().len() > 2048
        {
            return Err(Error::Selection);
        }
        Ok(Self {
            endpoint: endpoint.clone(),
            credential: Credential::open(credential)?,
            client: builder.build().map_err(|_| Error::Unavailable)?,
        })
    }

    fn observe(&self, original: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        if original.is_empty()
            || original.len() > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1
            || timeout.is_zero()
            || timeout > Duration::from_secs(60)
        {
            return Err(Error::Invalid);
        }
        let started = Instant::now();
        let authorization = self.credential.authorization()?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .timeout(timeout)
            .header(CONTENT_TYPE, MIME)
            .header(ACCEPT, MIME)
            .header(AUTHORIZATION, authorization)
            .body(original.to_vec())
            .send()
            .map_err(|_| Error::Unavailable)?;
        // A transport status is never a definitive enrollment decision. Only the exact
        // signed Norito response can say approved, frozen or not approved.
        if response.status() != StatusCode::OK {
            return Err(Error::Unavailable);
        }
        let mut media = response.headers().get_all(CONTENT_TYPE).iter();
        if media.next().and_then(|v| v.to_str().ok()) != Some(MIME)
            || media.next().is_some()
            || response.headers().contains_key(CONTENT_ENCODING)
            || response
                .content_length()
                .is_some_and(|n| n == 0 || n > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 as u64)
        {
            return Err(Error::Invalid);
        }
        let body = bounded_body(response)?;
        self.credential.revalidate()?;
        if started.elapsed() >= timeout {
            return Err(Error::Unavailable);
        }
        Ok(body)
    }
}

fn bounded_body(body: impl io::Read) -> Result<Vec<u8>> {
    let mut original = Vec::with_capacity(KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 + 1);
    body.take((KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 + 1) as u64)
        .read_to_end(&mut original)
        .map_err(|_| Error::Unavailable)?;
    if original.is_empty() || original.len() > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 {
        return Err(Error::Invalid);
    }
    Ok(original)
}

struct Credential {
    original: RetainedFile,
    snapshot: FileSnapshot,
}

impl Credential {
    fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(Error::Selection);
        }
        let original = RetainedFile::open_private(path).map_err(custody)?;
        let snapshot = original.snapshot().map_err(custody)?;
        let owner = Self { original, snapshot };
        owner.authorization()?;
        Ok(owner)
    }

    fn revalidate(&self) -> Result<()> {
        if self.original.snapshot().map_err(custody)? != self.snapshot {
            return Err(Error::Selection);
        }
        Ok(())
    }

    fn authorization(&self) -> Result<HeaderValue> {
        self.revalidate()?;
        let length = self.original.file().metadata().map_err(custody)?.len();
        if !(1..=MAX_CREDENTIAL as u64).contains(&length) {
            return Err(Error::Invalid);
        }
        let mut value = Zeroizing::new(vec![0_u8; length as usize + 7]);
        value[..7].copy_from_slice(b"Bearer ");
        iroha_fs::read_exact_at(self.original.file(), &mut value[7..], 0).map_err(custody)?;
        self.revalidate()?;
        if !value[7..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(b))
        {
            return Err(Error::Invalid);
        }
        let mut header = HeaderValue::from_bytes(&value).map_err(|_| Error::Invalid)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

fn custody(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => Error::Invalid,
        io::ErrorKind::PermissionDenied => Error::Selection,
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
mod tests;
