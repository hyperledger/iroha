//! SCCP client configuration: the file-only `[sccp]` table of spec §7 and §8.
//!
//! ```toml
//! [sccp]
//! request_timeout_ms = 10000          # one public-RPC request, then fail over
//! poll_interval_ms = 2000             # Torii and destination polling cadence
//! attestation_timeout_ms = 900000     # give up waiting for an attestation
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
//! The `[sccp]` table must **not** go into the file the `iroha` client loads yet. That loader
//! (`iroha::config::Config`, reading `iroha::config::user::Root` with `read_and_complete`)
//! rejects every top-level key its root does not declare, and the root has no `sccp` field, so
//! adding `[sccp]` to `client.toml` breaks the ordinary client and CLI. Until the root nests the
//! table, it lives in its own file, by default [`defaults::CONFIG_FILE_NAME`] next to the client
//! config ([`SccpClientConfig::path_beside`]). That file holds `[sccp]` and an optional
//! `extends` only: [`SccpClientConfig::load`] refuses any other top-level key, so a client
//! config passed by mistake, or a misspelled table that would silently fall back to the public
//! endpoints, is an error. The table's shape is final, so it moves into the client config
//! verbatim once the root accepts it.
//!
//! The file is read with the `iroha_config_base` reader the client config uses (same TOML
//! sources, `extends` handling and unknown-key rejection), never from environment variables.
//! Every field has a default, so a file with an empty or absent `[sccp]` works: the endpoint
//! lists fall back to `iroha_config::parameters::defaults::sccp::endpoints` and the request
//! timeout to the keeper's default. Pinned deployments are the wallet's trust anchor for
//! `GET /v1/sccp/registry` (§7.1 step 1): a flow refuses a Taira network or a deployment that is
//! not pinned here.
//!
//! TODO(ws35): nest `[sccp]` in the `iroha` client config (this needs `crates/iroha/src/config/
//! user.rs`, which no SCCP workstream owns yet). `iroha` cannot depend on this crate
//! (`iroha_sccp_wallet` → `iroha_wallet` → `iroha`), so first move the plain user types
//! ([`SccpClientConfigUser`], [`SccpClientEndpointsUser`], [`SccpPinnedDeploymentEntry`],
//! [`SccpTonCodeEntry`]) to a layer below `iroha` (for example `iroha_config::client::sccp`),
//! add them as `#[config(nested)] sccp` to `iroha::config::user::Root`, and reduce this module
//! to [`SccpClientConfigUser::parse`] on that value; [`SccpClientConfig::load`] and the separate
//! file then go away.

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use iroha_config::parameters::{
    actual::{
        SccpLightClientKeeperEndpoints, SccpSecretHeader, SccpTonLiteserver,
        compiled_http_endpoints, compiled_ton_liteservers, parse_sccp_http_endpoint,
        parse_sccp_secret_header_name,
    },
    defaults as node_defaults, user,
};
use iroha_config_base::{ReadConfig, WithOrigin, read::ConfigReader, util::DurationMs};
use iroha_data_model::{
    NetworkId,
    bridge::SccpNetworkV1,
    sccp::deployment::{
        SccpDeploymentV1, SccpEvmDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1,
    },
};
use iroha_sccp_rpc::{EndpointSet, HttpConfig, HttpEndpointKind, endpoints::EndpointError};

/// Defaults of the `[sccp]` client table.
pub mod defaults {
    /// One public-RPC request, before failing over to the next endpoint.
    pub const REQUEST_TIMEOUT_MS: u64 =
        iroha_config::parameters::defaults::sccp::light_client_keeper::REQUEST_TIMEOUT_MS;
    /// Polling cadence of Torii statuses and destination receipts.
    pub const POLL_INTERVAL_MS: u64 = 2_000;
    /// Longest wait for an attestation (§7.1 step 4 expects about 8–12 s).
    pub const ATTESTATION_TIMEOUT_MS: u64 = 900_000;
    /// Longest wait for a destination transaction receipt.
    pub const CONFIRMATION_TIMEOUT_MS: u64 = 900_000;
    /// Journal directory name next to the `[sccp]` file when `journal_dir` is empty.
    pub const JOURNAL_DIR_NAME: &str = "sccp-journal";
    /// Name of the `[sccp]` file next to the client config (see the module docs).
    pub const CONFIG_FILE_NAME: &str = "sccp.toml";
    /// Most `[[sccp.deployments]]` entries.
    pub const MAX_DEPLOYMENTS: usize = 256;
}

const fn ms(millis: u64) -> DurationMs {
    DurationMs(Duration::from_millis(millis))
}

/// User view of `[sccp]`, read with [`ReadConfig`].
#[derive(Debug, Clone, ReadConfig)]
pub struct SccpClientConfigUser {
    /// Timeout of one RPC request in milliseconds (nonzero).
    #[config(default = "ms(defaults::REQUEST_TIMEOUT_MS)")]
    pub request_timeout_ms: DurationMs,
    /// Polling cadence in milliseconds (nonzero).
    #[config(default = "ms(defaults::POLL_INTERVAL_MS)")]
    pub poll_interval_ms: DurationMs,
    /// Longest wait for an attestation in milliseconds (nonzero).
    #[config(default = "ms(defaults::ATTESTATION_TIMEOUT_MS)")]
    pub attestation_timeout_ms: DurationMs,
    /// Longest wait for a destination receipt in milliseconds (nonzero).
    #[config(default = "ms(defaults::CONFIRMATION_TIMEOUT_MS)")]
    pub confirmation_timeout_ms: DurationMs,
    /// Journal directory; empty means `sccp-journal` next to the `[sccp]` file. A relative path
    /// resolves against the file that sets it.
    #[config(default = "PathBuf::new()")]
    pub journal_dir: WithOrigin<PathBuf>,
    /// `[sccp.endpoints]`: RPC endpoint lists per chain.
    #[config(nested)]
    pub endpoints: SccpClientEndpointsUser,
    /// `[[sccp.secret_headers]]`: secret request headers read from owner-only files.
    #[config(default)]
    pub secret_headers: WithOrigin<Vec<user::SccpSecretHeader>>,
    /// `[[sccp.deployments]]`: pinned deployments per Taira `NetworkId`.
    #[config(default)]
    pub deployments: Vec<SccpPinnedDeploymentEntry>,
}

/// `[sccp.endpoints]`: endpoint lists per chain, tried in order with failover. An empty list
/// selects the compiled public list; a configured list replaces it.
#[derive(Debug, Clone, Default, ReadConfig)]
pub struct SccpClientEndpointsUser {
    /// Ethereum execution-layer JSON-RPC URLs.
    #[config(default)]
    pub ethereum_execution: Vec<String>,
    /// Ethereum beacon API URLs.
    #[config(default)]
    pub ethereum_beacon: Vec<String>,
    /// BNB Smart Chain JSON-RPC URLs.
    #[config(default)]
    pub bsc: Vec<String>,
    /// TON liteservers as `<ipv4>:<port>:<base64 ed25519 public key>`.
    #[config(default)]
    pub ton_liteservers: Vec<String>,
}

/// A TON code reference in a pinned deployment.
#[derive(Debug, Clone, PartialEq, Eq, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SccpTonCodeEntry {
    /// `0x`-prefixed representation hash of the code cell.
    pub hash: String,
    /// Depth of the code cell.
    pub depth: u16,
}

/// One `[[sccp.deployments]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SccpPinnedDeploymentEntry {
    /// Taira `NetworkId` the deployment belongs to.
    pub network_id: NetworkId,
    /// External profile key (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    pub network: String,
    /// Route revision (at least 1).
    pub revision: u32,
    /// EVM: contract address (20 bytes).
    #[norito(default)]
    pub address: Option<String>,
    /// EVM: `keccak256` of the deployed runtime code.
    #[norito(default)]
    pub runtime_code_hash: Option<String>,
    /// TON: account id of the Jetton master (workchain 0).
    #[norito(default)]
    pub master_account: Option<String>,
    /// TON: minter code.
    #[norito(default)]
    pub minter_code: Option<SccpTonCodeEntry>,
    /// TON: Jetton wallet code.
    #[norito(default)]
    pub wallet_code: Option<SccpTonCodeEntry>,
    /// TON: consumption bucket code.
    #[norito(default)]
    pub bucket_code: Option<SccpTonCodeEntry>,
}

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
    /// Longest wait for an attestation.
    pub attestation_timeout: Duration,
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
    /// The default location of the `[sccp]` file for the client config at `client_config`:
    /// [`defaults::CONFIG_FILE_NAME`] in the same directory.
    #[must_use]
    pub fn path_beside(client_config: &Path) -> PathBuf {
        client_config
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(defaults::CONFIG_FILE_NAME)
    }

    /// Read the `[sccp]` file at `path` (with its `extends` chain) and validate it. A file
    /// without `[sccp]` yields the defaults; any other top-level key is refused, because the
    /// table must not share the file the `iroha` client loads (see the module docs).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] for unreadable files and unknown or malformed keys, and
    /// [`ConfigError::Invalid`] for rule violations.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut reader = ConfigReader::new()
            .without_env()
            .read_toml_with_extends(path)
            .map_err(|report| ConfigError::Read(format!("{report:?}")))?;
        let user = reader.read_nested::<SccpClientConfigUser>("sccp");
        reader
            .into_result()
            .map_err(|report| ConfigError::Read(format!("{report:?}")))?;
        let default_journal_dir = path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(defaults::JOURNAL_DIR_NAME);
        user.unwrap().parse(&default_journal_dir)
    }

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

impl SccpClientConfigUser {
    /// Validate and resolve the table; `default_journal_dir` replaces an empty `journal_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] with every violation.
    pub fn parse(self, default_journal_dir: &Path) -> Result<SccpClientConfig, ConfigError> {
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
            self.request_timeout_ms,
            "request_timeout_ms",
            defaults::REQUEST_TIMEOUT_MS,
        );
        let poll_interval = nonzero(
            self.poll_interval_ms,
            "poll_interval_ms",
            defaults::POLL_INTERVAL_MS,
        );
        let attestation_timeout = nonzero(
            self.attestation_timeout_ms,
            "attestation_timeout_ms",
            defaults::ATTESTATION_TIMEOUT_MS,
        );
        let confirmation_timeout = nonzero(
            self.confirmation_timeout_ms,
            "confirmation_timeout_ms",
            defaults::CONFIRMATION_TIMEOUT_MS,
        );
        let journal_dir = if self.journal_dir.value().as_os_str().is_empty() {
            default_journal_dir.to_path_buf()
        } else {
            self.journal_dir.resolve_relative_path()
        };
        let endpoints = self.endpoints.parse(&mut errors);
        let secret_headers = parse_secret_headers(self.secret_headers, &mut errors);
        let deployments = parse_deployments(&self.deployments, &mut errors);
        if !errors.is_empty() {
            return Err(ConfigError::Invalid(errors));
        }
        Ok(SccpClientConfig {
            request_timeout,
            poll_interval,
            attestation_timeout,
            confirmation_timeout,
            journal_dir,
            endpoints,
            secret_headers,
            deployments,
        })
    }
}

impl SccpClientEndpointsUser {
    fn parse(&self, errors: &mut Vec<String>) -> SccpLightClientKeeperEndpoints {
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
                &self.ethereum_execution,
                "ethereum_execution",
                endpoints::ETHEREUM_EXECUTION,
                errors,
            ),
            ethereum_beacon: http(
                &self.ethereum_beacon,
                "ethereum_beacon",
                endpoints::ETHEREUM_BEACON,
                errors,
            ),
            bsc: http(&self.bsc, "bsc", endpoints::BSC, errors),
            ton_liteservers: parse_list(
                &self.ton_liteservers,
                "ton_liteservers",
                || compiled_ton_liteservers(endpoints::TON_LITESERVERS),
                |raw| SccpTonLiteserver::from_str(raw).map_err(|error| error.to_string()),
                |server: &SccpTonLiteserver| server.address.to_string(),
                errors,
            ),
        }
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
    entries: WithOrigin<Vec<user::SccpSecretHeader>>,
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
        let path = dir.join(defaults::CONFIG_FILE_NAME);
        std::fs::write(&path, body).expect("write config");
        path
    }

    #[test]
    fn the_file_sits_beside_the_client_config() {
        assert_eq!(
            SccpClientConfig::path_beside(Path::new("/home/u/.iroha/client.toml")),
            Path::new("/home/u/.iroha/sccp.toml")
        );
        assert_eq!(
            SccpClientConfig::path_beside(Path::new("client.toml")),
            Path::new("sccp.toml")
        );
    }

    #[test]
    fn client_config_keys_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = write_config(
            dir.path(),
            "chain = \"00000000-0000-0000-0000-000000000000\"\n[account]\nchain_discriminant = 753\n[sccp]\npoll_interval_ms = 500\n",
        );
        let Err(ConfigError::Read(report)) = SccpClientConfig::load(&client) else {
            panic!("the [sccp] file must not be the client config");
        };
        assert!(report.contains("chain"), "{report}");
        let misspelled = write_config(
            dir.path(),
            "[scp.endpoints]\nbsc = [\"https://a.example\"]\n",
        );
        assert!(matches!(
            SccpClientConfig::load(&misspelled),
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
        let config = SccpClientConfig::load(&path).expect("loads");
        assert_eq!(config.request_timeout, Duration::from_millis(1_234));
        assert_eq!(config.poll_interval, Duration::from_millis(700));
    }

    #[test]
    fn an_absent_table_yields_every_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(dir.path(), "# no [sccp] table\n");
        let config = SccpClientConfig::load(&path).expect("defaults load");
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
        SccpClientConfig::load(&write_config(dir, &body)).expect("loads")
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
    fn unknown_keys_and_invalid_values_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unknown = write_config(dir.path(), "[sccp]\nrequest_timeout = 5\n");
        assert!(matches!(
            SccpClientConfig::load(&unknown),
            Err(ConfigError::Read(_))
        ));
        let retired = write_config(dir.path(), "[sccp.endpoints]\ntron = []\n");
        assert!(
            matches!(SccpClientConfig::load(&retired), Err(ConfigError::Read(_))),
            "SCCP v1 has no TRON endpoint list"
        );
        let invalid = write_config(
            dir.path(),
            "[sccp]\npoll_interval_ms = 0\n[sccp.endpoints]\nbsc = [\"http://rpc.example\", \"https://a.example\", \"https://a.example\"]\n",
        );
        let Err(ConfigError::Invalid(messages)) = SccpClientConfig::load(&invalid) else {
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
