//! SCCP client configuration: the file-only `[sccp]` table of spec §7 and §8.
//!
//! ```toml
//! [sccp]
//! request_timeout_ms = 10000          # one public-RPC request, then fail over
//! poll_interval_ms = 2000             # Torii and destination polling cadence
//! confirmation_timeout_ms = 900000    # give up waiting for a destination receipt
//! journal_dir = ""                    # empty: `sccp-journal` next to this file
//!
//! [sccp.endpoints]                    # empty lists select the compiled public lists
//! ethereum_execution = []
//! ethereum_beacon = []
//! bsc = []
//! ton_liteservers = []
//!
//! [[sccp.secret_headers]]             # optional, repeatable
//! endpoint = "https://rpc.example/key"
//! header = "x-api-key"
//! value_file = "secrets/rpc.key"      # owner-only file, relative to this file
//!
//! [[sccp.deployments]]                # pinned deployments per Taira NetworkId
//! network_id = "hash:…#…"             # canonical NetworkId literal
//! network = "ethereum-mainnet"        # profile key
//! revision = 1
//! address = "0x…"                     # EVM: 20 bytes
//! runtime_code_hash = "0x…"           # EVM: keccak256 of the runtime code
//! # TON instead: master_account = "0x…" and
//! # minter_code, wallet_code, bucket_code = { hash = "0x…", depth = N }
//! ```
//!
//! # Where the table lives
//!
//! The table lives in the ordinary `iroha` client configuration and is read by
//! `iroha::config::sccp::SccpClientConfigUser` with file provenance and strict unknown-key
//! checks. No environment variable overrides it. The wallet validates those retained values
//! with [`SccpClientConfig::from_user`]; it never loads a second configuration file.
//! Empty endpoint lists use the compiled public lists. Pinned deployments remain the trust
//! anchor for registry reads: unknown networks and mismatched deployments are refused.

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use iroha::config::sccp::{
    SccpClientConfigUser, SccpClientEndpointsUser, SccpClientSecretHeaderUser,
    SccpPinnedDeploymentEntry, SccpTonCodeEntry, defaults,
};
use iroha_config::parameters::{
    actual::{
        SccpLightClientKeeperEndpoints, SccpSecretHeader, SccpTonLiteserver,
        compiled_http_endpoints, compiled_ton_liteservers, parse_sccp_http_endpoint,
        parse_sccp_secret_header_name,
    },
    defaults as node_defaults,
};
use iroha_config_base::{WithOrigin, util::DurationMs};
use iroha_data_model::{
    NetworkId,
    bridge::SccpNetworkV1,
    sccp::deployment::{
        SccpDeploymentV1, SccpEvmDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1,
    },
};
use iroha_sccp_rpc::{EndpointSet, HttpConfig, HttpEndpointKind, endpoints::EndpointError};

/// Why the `[sccp]` table could not be read or is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The client config file could not be read or holds unknown or malformed `[sccp]` keys.
    Read(String),
    /// Values violate the `[sccp]` rules; one message per violation.
    Invalid(Vec<String>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(report) => write!(formatter, "cannot read the [sccp] table: {report}"),
            Self::Invalid(messages) => {
                write!(formatter, "invalid [sccp] table: {}", messages.join("; "))
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Pinned deployments: Taira `NetworkId` → network → revision → deployment.
pub type SccpPinnedDeploymentsV1 =
    BTreeMap<NetworkId, BTreeMap<SccpNetworkV1, BTreeMap<u32, SccpDeploymentV1>>>;

/// Why a deployment served by Torii is refused against the pins (§7.1 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinError {
    /// No deployment is pinned for this Taira network: the peer serves an unknown network.
    UnknownNetwork,
    /// No deployment is pinned for this network and revision.
    NotPinned,
    /// The served deployment differs from the pinned one.
    Mismatch,
}

impl fmt::Display for PinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownNetwork => "no SCCP deployment is pinned for this Taira network",
            Self::NotPinned => "no SCCP deployment is pinned for this network and revision",
            Self::Mismatch => "the served SCCP deployment differs from the pinned deployment",
        })
    }
}

impl std::error::Error for PinError {}

/// Effective `[sccp]` client configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpClientConfig {
    /// Timeout of one RPC request.
    pub request_timeout: Duration,
    /// Polling cadence.
    pub poll_interval: Duration,
    /// Longest wait for a destination receipt.
    pub confirmation_timeout: Duration,
    /// Journal directory.
    pub journal_dir: PathBuf,
    /// Effective endpoint lists (configured, or the compiled public lists).
    pub endpoints: SccpLightClientKeeperEndpoints,
    /// Secret request headers.
    pub secret_headers: Vec<SccpSecretHeader>,
    /// Pinned deployments.
    pub deployments: SccpPinnedDeploymentsV1,
}

impl SccpClientConfig {
    /// The HTTP transport limits of wallet requests.
    #[must_use]
    pub fn http_config(&self) -> HttpConfig {
        HttpConfig {
            request_timeout: self.request_timeout,
            ..HttpConfig::default()
        }
    }

    /// The endpoint list of `kind` with its secret headers.
    ///
    /// # Errors
    ///
    /// Returns the [`EndpointError`] of an invalid list or secret header.
    pub fn endpoint_set(&self, kind: HttpEndpointKind) -> Result<EndpointSet, EndpointError> {
        EndpointSet::new(
            kind.configured(&self.endpoints).iter().cloned(),
            &self.secret_headers,
        )
    }

    /// The deployment pinned for `(network_id, network, revision)`.
    #[must_use]
    pub fn pinned_deployment(
        &self,
        network_id: &NetworkId,
        network: SccpNetworkV1,
        revision: u32,
    ) -> Option<&SccpDeploymentV1> {
        self.deployments
            .get(network_id)?
            .get(&network)?
            .get(&revision)
    }

    /// Whether any deployment is pinned for `network_id` (§7.1 step 1 checks the Torii
    /// `network_id` against the pinned set).
    #[must_use]
    pub fn knows_network(&self, network_id: &NetworkId) -> bool {
        self.deployments.contains_key(network_id)
    }

    /// Refuse a deployment served by Torii unless it equals the pinned one.
    ///
    /// # Errors
    ///
    /// Returns the matching [`PinError`].
    pub fn check_deployment(
        &self,
        network_id: &NetworkId,
        network: SccpNetworkV1,
        revision: u32,
        served: &SccpDeploymentV1,
    ) -> Result<(), PinError> {
        if !self.knows_network(network_id) {
            return Err(PinError::UnknownNetwork);
        }
        let pinned = self
            .pinned_deployment(network_id, network, revision)
            .ok_or(PinError::NotPinned)?;
        if pinned == served {
            Ok(())
        } else {
            Err(PinError::Mismatch)
        }
    }
}

impl SccpClientConfig {
    /// Validate and resolve the table; `default_journal_dir` replaces an empty `journal_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] with every violation.
    pub fn from_user(
        user: SccpClientConfigUser,
        default_journal_dir: &Path,
    ) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        let mut nonzero = |value: DurationMs, name: &str, fallback: u64| {
            let value = value.get();
            if value.is_zero() {
                errors.push(format!("sccp.{name} must be nonzero"));
                Duration::from_millis(fallback)
            } else {
                value
            }
        };
        let request_timeout = nonzero(
            user.request_timeout_ms,
            "request_timeout_ms",
            defaults::REQUEST_TIMEOUT_MS,
        );
        let poll_interval = nonzero(
            user.poll_interval_ms,
            "poll_interval_ms",
            defaults::POLL_INTERVAL_MS,
        );
        let confirmation_timeout = nonzero(
            user.confirmation_timeout_ms,
            "confirmation_timeout_ms",
            defaults::CONFIRMATION_TIMEOUT_MS,
        );
        let journal_dir = if user.journal_dir.value().as_os_str().is_empty() {
            default_journal_dir.to_path_buf()
        } else {
            user.journal_dir.resolve_relative_path()
        };
        let endpoints = parse_endpoints(&user.endpoints, &mut errors);
        let secret_headers = parse_secret_headers(user.secret_headers, &mut errors);
        let deployments = parse_deployments(&user.deployments, &mut errors);
        if !errors.is_empty() {
            return Err(ConfigError::Invalid(errors));
        }
        Ok(SccpClientConfig {
            request_timeout,
            poll_interval,
            confirmation_timeout,
            journal_dir,
            endpoints,
            secret_headers,
            deployments,
        })
    }
}

fn parse_endpoints(
    user: &SccpClientEndpointsUser,
    errors: &mut Vec<String>,
) -> SccpLightClientKeeperEndpoints {
    use node_defaults::sccp::endpoints;
    let http = |entries: &[String], name: &str, compiled: &[&str], errors: &mut Vec<String>| {
        parse_list(
            entries,
            name,
            || compiled_http_endpoints(compiled),
            |raw| parse_sccp_http_endpoint(raw).map_err(|error| error.to_string()),
            |url| url.as_str().to_owned(),
            errors,
        )
    };
    SccpLightClientKeeperEndpoints {
        ethereum_execution: http(
            &user.ethereum_execution,
            "ethereum_execution",
            endpoints::ETHEREUM_EXECUTION,
            errors,
        ),
        ethereum_beacon: http(
            &user.ethereum_beacon,
            "ethereum_beacon",
            endpoints::ETHEREUM_BEACON,
            errors,
        ),
        bsc: http(&user.bsc, "bsc", endpoints::BSC, errors),
        ton_liteservers: parse_list(
            &user.ton_liteservers,
            "ton_liteservers",
            || compiled_ton_liteservers(endpoints::TON_LITESERVERS),
            |raw| SccpTonLiteserver::from_str(raw).map_err(|error| error.to_string()),
            |server: &SccpTonLiteserver| server.address.to_string(),
            errors,
        ),
    }
}

/// Parse one endpoint list: empty selects `compiled`; otherwise every entry must parse, be
/// unique by `key`, and the list holds at most the keeper's maximum.
fn parse_list<T>(
    entries: &[String],
    name: &str,
    compiled: impl FnOnce() -> Vec<T>,
    parse: impl Fn(&str) -> Result<T, String>,
    key: impl Fn(&T) -> String,
    errors: &mut Vec<String>,
) -> Vec<T> {
    if entries.is_empty() {
        return compiled();
    }
    let max = node_defaults::sccp::light_client_keeper::MAX_ENDPOINTS_PER_LIST;
    if entries.len() > max {
        errors.push(format!(
            "sccp.endpoints.{name} must have at most {max} entries"
        ));
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    let mut parsed = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        match parse(entry) {
            Ok(value) if seen.insert(key(&value)) => parsed.push(value),
            Ok(_) => errors.push(format!(
                "sccp.endpoints.{name}[{index}] duplicates an earlier entry"
            )),
            Err(error) => errors.push(format!("sccp.endpoints.{name}[{index}]: {error}")),
        }
    }
    parsed
}

fn parse_secret_headers(
    entries: WithOrigin<Vec<SccpClientSecretHeaderUser>>,
    errors: &mut Vec<String>,
) -> Vec<SccpSecretHeader> {
    let (entries, origin) = entries.into_tuple();
    let max = node_defaults::sccp::light_client_keeper::MAX_SECRET_HEADERS;
    if entries.len() > max {
        errors.push(format!(
            "sccp.secret_headers must have at most {max} entries"
        ));
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    let mut parsed = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let context = format!("sccp.secret_headers[{index}]");
        let endpoint = parse_sccp_http_endpoint(&entry.endpoint)
            .map_err(|error| errors.push(format!("{context}.endpoint: {error}")))
            .ok();
        let header = parse_sccp_secret_header_name(&entry.header)
            .map_err(|error| errors.push(format!("{context}.header: {error}")))
            .ok();
        let value_file = if entry.value_file.as_os_str().is_empty() {
            errors.push(format!("{context}.value_file must name a file"));
            None
        } else {
            Some(WithOrigin::new(entry.value_file, origin.clone()).resolve_relative_path())
        };
        let (Some(endpoint), Some(header), Some(value_file)) = (endpoint, header, value_file)
        else {
            continue;
        };
        if !seen.insert((endpoint.as_str().to_owned(), header.clone())) {
            errors.push(format!("{context} repeats a header for the same endpoint"));
            continue;
        }
        parsed.push(SccpSecretHeader {
            endpoint,
            header,
            value_file,
        });
    }
    parsed
}

/// Decode `0x`-prefixed hex of exactly `N` bytes (either letter case).
fn parse_hex_fixed<const N: usize>(field: &str, text: &str) -> Result<[u8; N], String> {
    let body = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must be 0x-prefixed hex"))?;
    let mut out = [0_u8; N];
    hex::decode_to_slice(body, &mut out)
        .map_err(|_| format!("{field} must be exactly {N} bytes of hex"))?;
    Ok(out)
}

fn ton_code(field: &str, entry: Option<&SccpTonCodeEntry>) -> Result<SccpTonCodeRefV1, String> {
    let entry = entry.ok_or_else(|| format!("{field} is required for ton-mainnet"))?;
    Ok(SccpTonCodeRefV1 {
        hash: parse_hex_fixed::<32>(&format!("{field}.hash"), &entry.hash)?,
        depth: entry.depth,
    })
}

/// Build the deployment of one entry, checking that exactly the fields of its family are set.
fn entry_deployment(
    entry: &SccpPinnedDeploymentEntry,
) -> Result<(SccpNetworkV1, SccpDeploymentV1), String> {
    let network = SccpNetworkV1::from_profile_key(&entry.network)
        .filter(|network| network.is_external())
        .ok_or_else(|| {
            format!(
                "network `{}` is not an external SCCP profile",
                entry.network
            )
        })?;
    if entry.revision == 0 {
        return Err("revision must be at least 1".to_owned());
    }
    let evm_fields = entry.address.is_some() || entry.runtime_code_hash.is_some();
    let ton_fields = entry.master_account.is_some()
        || entry.minter_code.is_some()
        || entry.wallet_code.is_some()
        || entry.bucket_code.is_some();
    let deployment = if network == SccpNetworkV1::TonMainnet {
        if evm_fields {
            return Err("address and runtime_code_hash are not ton-mainnet fields".to_owned());
        }
        let master = entry
            .master_account
            .as_deref()
            .ok_or("master_account is required for ton-mainnet")?;
        SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
            master_account: parse_hex_fixed::<32>("master_account", master)?,
            minter_code: ton_code("minter_code", entry.minter_code.as_ref())?,
            wallet_code: ton_code("wallet_code", entry.wallet_code.as_ref())?,
            bucket_code: ton_code("bucket_code", entry.bucket_code.as_ref())?,
        })
    } else {
        if ton_fields {
            return Err(format!(
                "master_account and code references are not {} fields",
                entry.network
            ));
        }
        let address = entry
            .address
            .as_deref()
            .ok_or("address is required for EVM deployments")?;
        let runtime_code_hash = parse_hex_fixed::<32>(
            "runtime_code_hash",
            entry
                .runtime_code_hash
                .as_deref()
                .ok_or("runtime_code_hash is required for EVM deployments")?,
        )?;
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: parse_hex_fixed::<20>("address", address)?,
            runtime_code_hash,
        })
    };
    if !deployment.fits_network(network) {
        return Err(format!(
            "the deployment address is not a valid {} address",
            entry.network
        ));
    }
    Ok((network, deployment))
}

fn parse_deployments(
    entries: &[SccpPinnedDeploymentEntry],
    errors: &mut Vec<String>,
) -> SccpPinnedDeploymentsV1 {
    let mut pinned = SccpPinnedDeploymentsV1::new();
    if entries.len() > defaults::MAX_DEPLOYMENTS {
        errors.push(format!(
            "sccp.deployments must have at most {} entries",
            defaults::MAX_DEPLOYMENTS
        ));
        return pinned;
    }
    let mut words = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let context = format!("sccp.deployments[{index}]");
        let (network, deployment) = match entry_deployment(entry) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{context}: {error}"));
                continue;
            }
        };
        // Destination words are unique per Taira network (§4.14.3): one contract cannot serve
        // two routes or revisions.
        let word = (entry.network_id, deployment.destination_word());
        if let Some(previous) = words.insert(word, index) {
            errors.push(format!(
                "{context} reuses the contract of sccp.deployments[{previous}]"
            ));
            continue;
        }
        let revisions = pinned
            .entry(entry.network_id)
            .or_default()
            .entry(network)
            .or_default();
        if revisions.insert(entry.revision, deployment).is_some() {
            errors.push(format!(
                "{context} pins revision {} of {} twice",
                entry.revision, entry.network
            ));
        }
    }
    pinned
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network_id() -> NetworkId {
        let hash =
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([0x11; 32]));
        NetworkId::from_genesis_hash(hash)
    }

    fn evm_entry(address: &str, revision: u32) -> SccpPinnedDeploymentEntry {
        SccpPinnedDeploymentEntry {
            network_id: network_id(),
            network: "ethereum-mainnet".to_owned(),
            revision,
            address: Some(address.to_owned()),
            runtime_code_hash: Some(format!("0x{}", "ab".repeat(32))),
            master_account: None,
            minter_code: None,
            wallet_code: None,
            bucket_code: None,
        }
    }

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("client.toml");
        std::fs::write(&path, body).expect("write config");
        path
    }

    fn load_fixture(path: &Path) -> Result<SccpClientConfig, ConfigError> {
        let mut reader = iroha_config_base::read::ConfigReader::new()
            .without_env()
            .read_toml_with_extends(path)
            .map_err(|error| ConfigError::Read(format!("{error:?}")))?;
        let user = reader.read_nested::<SccpClientConfigUser>("sccp");
        reader
            .into_result()
            .map_err(|error| ConfigError::Read(format!("{error:?}")))?;
        SccpClientConfig::from_user(
            user.unwrap(),
            &path.parent().unwrap().join(defaults::JOURNAL_DIR_NAME),
        )
    }

    #[test]
    fn isolated_codec_fixture_refuses_unread_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = write_config(
            dir.path(),
            "chain = \"00000000-0000-0000-0000-000000000000\"\n[account]\nchain_discriminant = 753\n[sccp]\npoll_interval_ms = 500\n",
        );
        let Err(ConfigError::Read(report)) = load_fixture(&client) else {
            panic!("the isolated codec fixture must reject unread keys");
        };
        assert!(report.contains("chain"), "{report}");
        let misspelled = write_config(
            dir.path(),
            "[scp.endpoints]\nbsc = [\"https://a.example\"]\n",
        );
        assert!(matches!(
            load_fixture(&misspelled),
            Err(ConfigError::Read(_))
        ));
    }

    #[test]
    fn extends_chains_are_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("base.toml"),
            "[sccp]\nrequest_timeout_ms = 1234\n",
        )
        .expect("base");
        let path = write_config(
            dir.path(),
            "extends = \"base.toml\"\n[sccp]\npoll_interval_ms = 700\n",
        );
        let config = load_fixture(&path).expect("loads");
        assert_eq!(config.request_timeout, Duration::from_millis(1_234));
        assert_eq!(config.poll_interval, Duration::from_millis(700));
    }

    #[test]
    fn an_absent_table_yields_every_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(dir.path(), "# no [sccp] table\n");
        let config = load_fixture(&path).expect("defaults load");
        assert_eq!(
            config.request_timeout,
            Duration::from_millis(defaults::REQUEST_TIMEOUT_MS)
        );
        assert_eq!(config.poll_interval, Duration::from_millis(2_000));
        assert_eq!(config.journal_dir, dir.path().join("sccp-journal"));
        assert_eq!(
            config.endpoints,
            SccpLightClientKeeperEndpoints::compiled_defaults()
        );
        assert!(config.secret_headers.is_empty());
        assert!(config.deployments.is_empty());
        assert_eq!(config.http_config().request_timeout, config.request_timeout);
        let set = config
            .endpoint_set(HttpEndpointKind::EthereumExecution)
            .expect("compiled list");
        assert_eq!(
            set.len(),
            node_defaults::sccp::endpoints::ETHEREUM_EXECUTION.len()
        );
    }

    /// A client config with every `[sccp]` key set, written into `dir`.
    fn full_table(dir: &Path) -> SccpClientConfig {
        let network_id = network_id().to_string();
        let body = format!(
            r#"
[sccp]
request_timeout_ms = 1500
poll_interval_ms = 500
journal_dir = "journal"

[sccp.endpoints]
ethereum_execution = ["https://rpc.example/key", "http://127.0.0.1:8545"]
ton_liteservers = ["5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk="]

[[sccp.secret_headers]]
endpoint = "https://rpc.example/key"
header = "X-Api-Key"
value_file = "secrets/rpc.key"

[[sccp.deployments]]
network_id = "{network_id}"
network = "ethereum-mainnet"
revision = 1
address = "0x{a}"
runtime_code_hash = "0x{h}"

[[sccp.deployments]]
network_id = "{network_id}"
network = "bsc-mainnet"
revision = 2
address = "0x{b}"
runtime_code_hash = "0x{h}"

[[sccp.deployments]]
network_id = "{network_id}"
network = "ton-mainnet"
revision = 1
master_account = "0x{m}"
minter_code = {{ hash = "0x{h}", depth = 7 }}
wallet_code = {{ hash = "0x{h}", depth = 5 }}
bucket_code = {{ hash = "0x{h}", depth = 3 }}
"#,
            a = "22".repeat(20),
            b = "33".repeat(20),
            m = "44".repeat(32),
            h = "AB".repeat(32),
        );
        load_fixture(&write_config(dir, &body)).expect("loads")
    }

    #[test]
    fn a_full_table_parses_timeouts_endpoints_and_headers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = full_table(dir.path());
        assert_eq!(config.request_timeout, Duration::from_millis(1_500));
        assert_eq!(config.journal_dir, dir.path().join("journal"));
        assert_eq!(config.endpoints.ethereum_execution.len(), 2);
        assert_eq!(
            config.endpoints.bsc,
            compiled_http_endpoints(node_defaults::sccp::endpoints::BSC)
        );
        assert_eq!(config.endpoints.ton_liteservers.len(), 1);
        assert_eq!(config.secret_headers.len(), 1);
        assert_eq!(config.secret_headers[0].header, "x-api-key");
        assert_eq!(
            config.secret_headers[0].value_file,
            dir.path().join("secrets/rpc.key")
        );
        let set = config
            .endpoint_set(HttpEndpointKind::EthereumExecution)
            .expect("configured list");
        assert_eq!(set.len(), 2);
        assert_eq!(set.endpoints()[0].secret_headers().len(), 1);
    }

    #[test]
    fn a_full_table_pins_deployments_per_network_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = full_table(dir.path());
        let id = network_id();
        let evm = config
            .pinned_deployment(&id, SccpNetworkV1::EthereumMainnet, 1)
            .expect("evm pin");
        assert_eq!(
            *evm,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: [0x22; 20],
                runtime_code_hash: [0xab; 32],
            })
        );
        assert_eq!(
            config.pinned_deployment(&id, SccpNetworkV1::BscMainnet, 2),
            Some(&SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: [0x33; 20],
                runtime_code_hash: [0xab; 32],
            }))
        );
        assert!(matches!(
            config.pinned_deployment(&id, SccpNetworkV1::TonMainnet, 1),
            Some(SccpDeploymentV1::Ton(_))
        ));
        assert!(config.knows_network(&id));
        assert_eq!(
            config.check_deployment(&id, SccpNetworkV1::EthereumMainnet, 1, evm),
            Ok(())
        );
        let other = SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [0x23; 20],
            runtime_code_hash: [0xab; 32],
        });
        assert_eq!(
            config.check_deployment(&id, SccpNetworkV1::EthereumMainnet, 1, &other),
            Err(PinError::Mismatch)
        );
        assert_eq!(
            config.check_deployment(&id, SccpNetworkV1::EthereumMainnet, 2, evm),
            Err(PinError::NotPinned)
        );
        let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x12; 32]),
        ));
        assert_eq!(
            config.check_deployment(&foreign, SccpNetworkV1::EthereumMainnet, 1, evm),
            Err(PinError::UnknownNetwork)
        );
    }

    #[test]
    fn retired_attestation_wait_setting_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(dir.path(), "[sccp]\nattestation_timeout_ms = 900000\n");
        assert!(
            matches!(load_fixture(&path), Err(ConfigError::Read(_))),
            "native SCCP proofs have no attestation wait or compatibility setting"
        );
    }

    #[test]
    fn unknown_keys_and_invalid_values_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unknown = write_config(dir.path(), "[sccp]\nrequest_timeout = 5\n");
        assert!(matches!(load_fixture(&unknown), Err(ConfigError::Read(_))));
        let retired = write_config(dir.path(), "[sccp.endpoints]\ntron = []\n");
        assert!(
            matches!(load_fixture(&retired), Err(ConfigError::Read(_))),
            "SCCP v1 has no TRON endpoint list"
        );
        let invalid = write_config(
            dir.path(),
            "[sccp]\npoll_interval_ms = 0\n[sccp.endpoints]\nbsc = [\"http://rpc.example\", \"https://a.example\", \"https://a.example\"]\n",
        );
        let Err(ConfigError::Invalid(messages)) = load_fixture(&invalid) else {
            panic!("invalid values must be rejected");
        };
        assert!(messages.iter().any(|m| m.contains("poll_interval_ms")));
        assert!(messages.iter().any(|m| m.contains("bsc[0]")));
        assert!(messages.iter().any(|m| m.contains("bsc[2] duplicates")));
        let error = ConfigError::Invalid(messages).to_string();
        assert!(error.starts_with("invalid [sccp] table"));
    }

    #[test]
    fn deployment_entries_are_checked_per_family() {
        let good = evm_entry(&format!("0x{}", "22".repeat(20)), 1);
        assert!(entry_deployment(&good).is_ok());
        let mut zero = evm_entry(&format!("0x{}", "00".repeat(20)), 1);
        assert!(entry_deployment(&zero).unwrap_err().contains("not a valid"));
        zero.revision = 0;
        assert!(entry_deployment(&zero).unwrap_err().contains("revision"));
        let mut taira = good.clone();
        taira.network = "sora-taira".to_owned();
        assert!(entry_deployment(&taira).is_err());
        let mut unprefixed = good.clone();
        unprefixed.address = Some("22".repeat(20));
        assert!(entry_deployment(&unprefixed).unwrap_err().contains("0x"));
        let mut short = good.clone();
        short.address = Some(format!("0x{}", "22".repeat(19)));
        assert!(entry_deployment(&short).unwrap_err().contains("20 bytes"));
        let mut mixed = good.clone();
        mixed.master_account = Some(format!("0x{}", "44".repeat(32)));
        assert!(entry_deployment(&mixed).is_err());
        let mut retired = good.clone();
        retired.network = "tron-mainnet".to_owned();
        retired.address = Some(format!("0x41{}", "33".repeat(20)));
        assert!(
            entry_deployment(&retired)
                .unwrap_err()
                .contains("not an external SCCP profile"),
            "SCCP v1 has no TRON profile"
        );
        let mut evm_fields_on_ton = good.clone();
        evm_fields_on_ton.network = "ton-mainnet".to_owned();
        assert!(
            entry_deployment(&evm_fields_on_ton).is_err(),
            "TON takes no EVM fields"
        );

        let mut errors = Vec::new();
        let duplicate = parse_deployments(&[good.clone(), good.clone()], &mut errors);
        assert_eq!(duplicate.len(), 1);
        assert!(errors[0].contains("reuses the contract"));
        let mut errors = Vec::new();
        let other = evm_entry(&format!("0x{}", "23".repeat(20)), 1);
        parse_deployments(&[good, other], &mut errors);
        assert!(errors[0].contains("twice"));
    }

    #[test]
    fn hex_and_errors_render() {
        assert_eq!(parse_hex_fixed::<2>("f", "0xABcd"), Ok([0xab, 0xcd]));
        assert!(parse_hex_fixed::<2>("f", "0xabc").is_err());
        assert!(parse_hex_fixed::<2>("f", "abcd").is_err());
        assert!(PinError::Mismatch.to_string().contains("differs"));
        assert!(
            ConfigError::Read("boom".to_owned())
                .to_string()
                .contains("boom")
        );
        assert!(ton_code("minter_code", None).is_err());
    }
}
