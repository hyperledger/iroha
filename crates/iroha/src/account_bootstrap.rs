//! Account-free network discovery for wallet creation and independently pinned faucet policy.

use std::{sync::Arc, time::Duration};

use eyre::{Result, WrapErr as _, eyre};
use iroha_data_model::{NetworkId, account::address::ChainDiscriminantGuard};
use iroha_torii_shared::{
    account_capabilities::{ACCOUNT_CAPABILITIES_MAX_BYTES_V1, AccountCapabilitiesV1},
    account_faucet_policy::{ACCOUNT_FAUCET_POLICY_MAX_BYTES, AccountFaucetAdvertisement},
    route_catalog,
};
use url::{Host, Url};

use crate::{
    client::AccountFaucetPolicyV1,
    http::{HttpTransport, Method, RequestBuilder as _, Response, StatusCode},
    http_default::{DefaultHttpTransport, DefaultRequestBuilder},
};

/// Public discovery returned a concrete HTTP failure before wallet preparation.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("wallet network discovery returned HTTP {status}")]
pub struct DiscoveryHttpError {
    /// HTTP status returned by the selected public endpoint.
    pub status: u16,
}

/// A public discovery context without a signer, account, guessed network identity or credentials.
///
/// The selected HTTPS origin is the initial trust anchor. Discovered exact identities and faucet
/// policy must be retained by the wallet and checked separately from prepared transactions.
#[derive(Clone, Debug)]
pub struct Client {
    endpoint: Url,
    timeout: Duration,
    transport: DefaultHttpTransport,
}

impl Client {
    /// Create a public discovery context for HTTPS or explicit loopback development.
    ///
    /// # Errors
    /// Rejects credentials, query/fragment components, non-loopback HTTP and zero deadlines.
    pub fn new(endpoint: Url, timeout: Duration) -> Result<Self> {
        validate_context(&endpoint, timeout)?;
        Ok(Self {
            endpoint,
            timeout,
            transport: DefaultHttpTransport::new(),
        })
    }

    /// Inject an explicitly owned transport for embedded applications and deterministic tests.
    ///
    /// # Errors
    /// Returns the same endpoint and deadline errors as [`Self::new`].
    pub fn with_transport(
        endpoint: Url,
        timeout: Duration,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self> {
        validate_context(&endpoint, timeout)?;
        Ok(Self {
            endpoint,
            timeout,
            transport: DefaultHttpTransport::from_shared(transport),
        })
    }

    /// Discover the exact network identity and admitted default signing algorithm without an account.
    ///
    /// # Errors
    /// Rejects transport, HTTP, representation, schema or inconsistent admission responses.
    pub async fn capabilities(&self) -> Result<AccountCapabilitiesV1> {
        let bytes = self
            .get(
                route_catalog::application_api::ACCOUNTS_CAPABILITIES_GET.path(),
                ACCOUNT_CAPABILITIES_MAX_BYTES_V1,
            )
            .await?;
        let policy: AccountCapabilitiesV1 = norito::json::from_slice(&bytes)
            .wrap_err("invalid account bootstrap capability response")?;
        validate_capabilities(&policy)?;
        Ok(policy)
    }

    /// Discover the faucet policy independently, requiring the wallet's already pinned identity.
    ///
    /// # Errors
    /// Rejects another genesis/profile, invalid authority/quantity, malformed responses or a disabled faucet.
    pub async fn faucet_policy(
        &self,
        network_id: NetworkId,
        network_prefix: u16,
    ) -> Result<AccountFaucetAdvertisement> {
        let bytes = self
            .get(
                route_catalog::application_api::ACCOUNTS_FAUCET_POLICY_GET.path(),
                ACCOUNT_FAUCET_POLICY_MAX_BYTES,
            )
            .await?;
        let _profile = ChainDiscriminantGuard::enter(network_prefix);
        let policy: AccountFaucetAdvertisement =
            norito::json::from_slice(&bytes).wrap_err("invalid public faucet policy response")?;
        if policy.schema_version != 1
            || policy.network_id != network_id
            || policy.network_prefix != network_prefix
        {
            return Err(eyre!(
                "faucet policy does not match the wallet's exact network identity"
            ));
        }
        AccountFaucetPolicyV1::try_new(
            policy.authority.clone(),
            policy.asset_definition_id.clone(),
            policy.amount.clone(),
        )?;
        Ok(policy)
    }

    async fn get(&self, route: &str, limit: usize) -> Result<Vec<u8>> {
        let base = self.endpoint.as_str().trim_end_matches('/');
        let url = Url::parse(&format!("{base}{route}"))?;
        let mut request = DefaultRequestBuilder::new(Method::GET, url)
            .with_transport(self.transport.clone())
            .header("Accept", "application/json")
            .timeout(self.timeout)
            .max_response_bytes(limit);
        if self.endpoint.scheme() == "http" {
            request = request.direct_loopback();
        }
        let response = request.build()?.send().await?;
        validate_response(response, limit).wrap_err_with(|| format!("GET {route}"))
    }
}

/// Validate the public account-service endpoint used by discovery and retained wallet custody.
///
/// # Errors
/// Rejects non-HTTPS endpoints except explicit loopback HTTP, embedded URL credentials,
/// query/fragment components, missing hosts, and URLs exceeding the 2,048-byte bound.
pub fn validate_endpoint(endpoint: &Url) -> Result<()> {
    let loopback = match endpoint.host() {
        Some(Host::Domain(host)) => host == "localhost",
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.host().is_none()
        || endpoint.as_str().len() > 2048
        || !(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback)
    {
        return Err(eyre!(
            "wallet account services require an HTTPS endpoint (or explicit loopback HTTP), no URL credentials/query/fragment, and a URL of at most 2048 bytes"
        ));
    }
    Ok(())
}

fn validate_context(endpoint: &Url, timeout: Duration) -> Result<()> {
    validate_endpoint(endpoint)?;
    if timeout.is_zero() {
        return Err(eyre!("wallet discovery requires a positive timeout"));
    }
    Ok(())
}

fn validate_capabilities(policy: &AccountCapabilitiesV1) -> Result<()> {
    if policy.schema_version != 1
        || policy.network_prefix == 0
        || policy.default_signing != "ed25519"
        || !policy
            .allowed_signing
            .iter()
            .any(|name| name == &policy.default_signing)
        || policy
            .allowed_signing
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || policy
            .allowed_signing
            .iter()
            .any(|name| name.parse::<iroha_crypto::Algorithm>().is_err())
    {
        return Err(eyre!(
            "network does not advertise the canonical first-release account signing policy"
        ));
    }
    Ok(())
}

fn validate_response(response: Response<Vec<u8>>, limit: usize) -> Result<Vec<u8>> {
    if response.status() != StatusCode::OK {
        return Err(DiscoveryHttpError {
            status: response.status().as_u16(),
        }
        .into());
    }
    let values = response
        .headers()
        .get_all("content-type")
        .iter()
        .collect::<Vec<_>>();
    let content_type = (values.len() == 1)
        .then(|| values[0].to_str().ok())
        .flatten();
    if !matches!(content_type, Some(value) if value.eq_ignore_ascii_case("application/json") || value.eq_ignore_ascii_case("application/json; charset=utf-8"))
    {
        return Err(eyre!(
            "wallet network discovery requires one canonical JSON content type"
        ));
    }
    if response.body().len() > limit {
        return Err(eyre!(
            "wallet network discovery response exceeds its size bound"
        ));
    }
    Ok(response.into_body())
}

#[cfg(test)]
#[path = "account_bootstrap_tests.rs"]
mod tests;
