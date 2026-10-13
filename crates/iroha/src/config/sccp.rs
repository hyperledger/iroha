//! File-only SCCP client configuration shared by the SDK and local wallet.
//!
//! The ordinary client root owns `[sccp]`; no separate file or environment override exists.
//! These wire-independent user values do not link wallet or node runtime code into the SDK.

use iroha_config_base::{ReadConfig, WithOrigin, util::DurationMs};
use iroha_data_model::NetworkId;
use std::{path::PathBuf, time::Duration};

/// Defaults of the `[sccp]` client table.
pub mod defaults {
    /// One public-RPC request, before failing over to the next endpoint.
    pub const REQUEST_TIMEOUT_MS: u64 = 10_000;
    /// Polling cadence of Torii statuses and destination receipts.
    pub const POLL_INTERVAL_MS: u64 = 2_000;
    /// Longest wait for a destination transaction receipt.
    pub const CONFIRMATION_TIMEOUT_MS: u64 = 900_000;
    /// Journal directory name next to the `[sccp]` file when `journal_dir` is empty.
    pub const JOURNAL_DIR_NAME: &str = "sccp-journal";
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
    pub secret_headers: WithOrigin<Vec<SccpClientSecretHeaderUser>>,
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

/// One file-only secret-header binding; the secret value is read only by the transport.
#[derive(Debug, Clone, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SccpClientSecretHeaderUser {
    /// Exact RPC endpoint to which the header may be sent.
    pub endpoint: String,
    /// HTTP request header name.
    pub header: String,
    /// Owner-private value file, resolved against its original configuration source.
    pub value_file: PathBuf,
}

impl Default for SccpClientConfigUser {
    fn default() -> Self {
        Self {
            request_timeout_ms: ms(defaults::REQUEST_TIMEOUT_MS),
            poll_interval_ms: ms(defaults::POLL_INTERVAL_MS),
            confirmation_timeout_ms: ms(defaults::CONFIRMATION_TIMEOUT_MS),
            journal_dir: WithOrigin::inline(PathBuf::new()),
            endpoints: SccpClientEndpointsUser::default(),
            secret_headers: WithOrigin::inline(Vec::new()),
            deployments: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config_base::read::ConfigReader;

    #[test]
    fn sccp_defaults_match_file_reader_and_never_read_environment() {
        let mut reader =
            ConfigReader::new().with_env(|_: &str| -> Option<std::borrow::Cow<'static, str>> {
                panic!("SCCP client preferences are file-only")
            });
        let user = reader.read_nested::<SccpClientConfigUser>("sccp");
        reader.into_result().unwrap();
        let user = user.unwrap();
        let default = SccpClientConfigUser::default();
        assert_eq!(user.request_timeout_ms, default.request_timeout_ms);
        assert_eq!(user.poll_interval_ms, default.poll_interval_ms);
        assert_eq!(
            user.confirmation_timeout_ms,
            default.confirmation_timeout_ms
        );
        assert!(user.journal_dir.value().as_os_str().is_empty());
        assert!(user.endpoints.bsc.is_empty());
        assert!(user.secret_headers.value().is_empty());
        assert!(user.deployments.is_empty());
    }
}
