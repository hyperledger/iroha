//! Structures related to sharable through network configuration
#![cfg(feature = "std")]

use iroha_crypto::prelude::*;
use serde::{Deserialize, Serialize};

/// Configuration parameters container.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct Configuration {
    /// Public key of this peer.
    pub public_key: PublicKey,
    /// Disable coloring of the backtrace and error report on panic.
    pub disable_panic_terminal_colors: bool,
    /// `Kura` related configuration.
    pub kura: kura::Configuration,
    /// `Sumeragi` related configuration.
    pub sumeragi: sumeragi::Configuration,
    /// `Torii` related configuration.
    pub torii: torii::Configuration,
    /// `BlockSynchronizer` configuration.
    pub block_sync: block_sync::Configuration,
    /// `Queue` configuration.
    pub queue: queue::Configuration,
    /// `Logger` configuration.
    pub logger: logger::Configuration,
    /// Configuration for `GenesisBlock`.
    pub genesis: genesis::Configuration,
    /// Configuration for `WorldStateView`.
    pub wsv: wsv::Configuration,
    /// Network configuration
    pub network: network::Configuration,
    /// Configuration for telemetry
    #[cfg(feature = "telemetry")]
    pub telemetry: telemetry::Configuration,
}

/// Module for network-related configuration and structs.
pub mod network {
    use super::*;
    /// Network Configuration parameters container.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// Buffer capacity of actor's MPSC channel
        pub actor_channel_capacity: u32,
    }
}

/// Module for kura-related configuration and structs.
pub mod kura {
    use super::*;

    /// Configuration of kura
    #[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// Possible modes: `strict`, `fast`.
        pub init_mode: Mode,
        /// Path to the existing block store folder or path to create new folder.
        pub block_store_path: String,
        /// Maximum number of blocks to write into single storage file
        pub blocks_per_storage_file: core::num::NonZeroU64,
        /// Default buffer capacity of actor's MPSC channel
        pub actor_channel_capacity: u32,
    }

    /// Kura work mode.
    #[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum Mode {
        /// Strict validation of all blocks.
        Strict,
        /// Fast initialization with basic checks.
        Fast,
    }
}

/// Module for sumeragi-related configuration and structs.
pub mod sumeragi {
    use super::*;
    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// Current Peer Identification.
        pub peer_id: crate::peer::Id,
        /// Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
        pub block_time_ms: u64,
        /// Optional list of predefined trusted peers.
        pub trusted_peers: TrustedPeers,
        /// Amount of time Peer waits for CommitMessage from the proxy tail.
        pub commit_time_limit_ms: u64,
        /// Amount of time Peer waits for TxReceipt from the leader.
        pub tx_receipt_time_limit_ms: u64,
        /// Limits to which transactions must adhere
        pub transaction_limits: crate::transaction::TransactionLimits,
        /// Buffer capacity of actor's MPSC channel
        pub actor_channel_capacity: u32,
        /// Maximum number of transactions in tx gossip batch message. While configuring this, attention should be payed to `p2p` max message size.
        pub gossip_batch_size: u32,
        /// Period in milliseconds for pending transaction gossiping between peers.
        pub gossip_period_ms: u64,
    }

    /// `SumeragiConfiguration` provides an ability to define parameters
    /// such as `BLOCK_TIME_MS` and list of `TRUSTED_PEERS`.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(transparent)]
    pub struct TrustedPeers {
        /// Optional list of predefined trusted peers. Must contain unique
        /// entries. Custom deserializer raises error if duplicates found.
        pub peers: std::collections::HashSet<crate::peer::Id>,
    }
}

/// Module for torii-related configuration and structs.
pub mod torii {
    use super::*;
    /// Structure that defines the configuration parameters of `Torii` which is the routing module.
    /// For example the `p2p_addr`, which is used for consensus and block-synchronisation purposes,
    /// as well as `max_transaction_size`.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// Torii URL for p2p communication for consensus and block synchronization purposes.
        pub p2p_addr: String,
        /// Torii URL for client API.
        pub api_url: String,
        /// Torii URL for reporting internal status and metrics for administration.
        pub telemetry_url: String,
        /// Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.
        pub max_transaction_size: u32,
        /// Maximum number of bytes in raw message. Used to prevent from DOS attacks.
        pub max_content_len: u32,
    }
}

/// Module for block_sync-related configuration and structs.
pub mod block_sync {
    use super::*;

    /// Configuration for `BlockSynchronizer`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// The time between sending requests for latest block.
        pub gossip_period_ms: u64,
        /// The number of blocks that can be sent in one message.
        /// Underlying network (`iroha_network`) should support transferring messages this large.
        pub block_batch_size: u32,
        /// Buffer capacity of actor's MPSC channel
        pub actor_channel_capacity: u32,
    }
}

/// Module for queue-related configuration and structs.
pub mod queue {
    use super::*;

    /// Configuration for `Queue`.
    #[derive(Copy, Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// The upper limit of the number of transactions per block.
        pub maximum_transactions_in_block: u32,
        /// The upper limit of the number of transactions waiting in this queue.
        pub maximum_transactions_in_queue: u32,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub transaction_time_to_live_ms: u64,
        /// The threshold to determine if a transaction has been tampered to have a future timestamp.
        pub future_threshold_ms: u64,
    }
}

/// Module for logger-related configuration and structs.
pub mod logger {
    use super::*;

    /// Configuration for `Logger`.
    #[derive(Clone, Deserialize, Serialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// Maximum log level
        pub max_log_level: Level,
        /// Capacity (or batch size) for telemetry channel
        pub telemetry_capacity: u32,
        /// Compact mode (no spans from telemetry)
        pub compact_mode: bool,
        /// If provided, logs will be copied to said file in the
        /// format readable by [bunyan](https://lib.rs/crates/bunyan)
        pub log_file_path: Option<std::path::PathBuf>,
        /// Enable ANSI terminal colors for formatted output.
        pub terminal_colors: bool,
    }

    /// Log level for reading from environment and (de)serializing
    #[allow(clippy::upper_case_acronyms)]
    #[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Level {
        /// Error
        ERROR,
        /// Warn
        WARN,
        /// Info (Default)
        INFO,
        /// Debug
        DEBUG,
        /// Trace
        TRACE,
    }
}

/// Module for genesis-related configuration and structs.
pub mod genesis {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    /// Configuration of the genesis block and the process of its submission.
    pub struct Configuration {
        /// The genesis account public key, should be supplied to all peers.
        pub account_public_key: PublicKey,
        /// Number of attempts to connect to peers, while waiting for them to submit genesis.
        pub wait_for_peers_retry_count_limit: u64,
        /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
        pub wait_for_peers_retry_period_ms: u64,
        /// Delay before genesis block submission after minimum number of peers were discovered to be online.
        /// Used to ensure that other peers had time to connect to each other.
        pub genesis_submission_delay_ms: u64,
    }
}

/// Module for wsv-related configuration and structs.
pub mod wsv {
    use super::*;
    use crate::metadata::Limits as MetadataLimits;

    /// `WorldStateView` configuration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// [`MetadataLimits`] for every asset with store.
        pub asset_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any asset definition's metadata.
        pub asset_definition_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any account's metadata.
        pub account_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any domain's metadata.
        pub domain_metadata_limits: MetadataLimits,
        /// [`LengthLimits`] for the number of chars in identifiers that can be stored in the WSV.
        pub ident_length_limits: crate::LengthLimits,
        /// [`WASM Runtime`](wasm::Runtime) configuration
        pub wasm_runtime_config: wasm::Configuration,
    }
}

/// Module for wasm-related configuration and structs.
pub mod wasm {
    use super::*;
    /// `WebAssembly Runtime` configuration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// Every WASM instruction costs approximately 1 unit of fuel. See
        /// [`wasmtime` reference](https://docs.rs/wasmtime/0.29.0/wasmtime/struct.Store.html#method.add_fuel)
        pub fuel_limit: u64,

        /// Maximum amount of linear memory a given smartcontract can allocate
        pub max_memory: u32,
    }
}

/// Module for telemetry-related configuration and structs.
pub mod telemetry {
    use super::*;

    /// Configuration parameters container
    #[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// The node's name to be seen on the telemetry
        pub name: Option<String>,
        /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
        pub url: Option<url::Url>,
        /// The minimum period of time in seconds to wait before reconnecting
        pub min_retry_period: u64,
        /// The maximum exponent of 2 that is used for increasing delay between reconnections
        pub max_retry_delay_exponent: u8,
        /// The filepath that to write dev-telemetry to
        #[cfg(feature = "dev-telemetry")]
        pub file: Option<std::path::PathBuf>,
    }
}
