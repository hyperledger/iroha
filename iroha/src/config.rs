//! This module contains `Configuration` structure and related implementation.
use crate::{
    crypto::{PrivateKey, PublicKey},
    kura::Mode,
    peer::PeerId,
};
use iroha_derive::*;
use serde::Deserialize;
use std::{env, fmt::Debug, fs::File, io::BufReader, path::Path};

const TORII_URL: &str = "TORII_URL";
const BLOCK_TIME_MS: &str = "BLOCK_TIME_MS";
const KURA_INIT_MODE: &str = "KURA_INIT_MODE";
const KURA_BLOCK_STORE_PATH: &str = "KURA_BLOCK_STORE_PATH";
const TRUSTED_PEERS: &str = "IROHA_TRUSTED_PEERS";
const MAX_FAULTY_PEERS: &str = "MAX_FAULTY_PEERS";
const IROHA_PUBLIC_KEY: &str = "IROHA_PUBLIC_KEY";
const IROHA_PRIVATE_KEY: &str = "IROHA_PRIVATE_KEY";
const COMMIT_TIME_MS: &str = "COMMIT_TIME_MS";
const TX_RECEIPT_TIME_MS: &str = "TX_RECEIPT_TIME_MS";
const DEFAULT_TORII_URL: &str = "127.0.0.1:1337";
const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
const DEFAULT_COMMIT_TIME_MS: u64 = 1000;
const DEFAULT_TX_RECEIPT_TIME_MS: u64 = 200;
const DEFAULT_KURA_BLOCK_STORE_PATH: &str = "./blocks";
const DEFAULT_MAX_FAULTY_PEERS: usize = 0;

/// Configuration parameters container.
#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Configuration {
    /// Torii URL.
    #[serde(default = "default_torii_url")]
    pub torii_url: String,
    /// Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
    #[serde(default = "default_block_time_ms")]
    pub block_time_ms: u64,
    /// Possible modes: `strict`, `fast`.
    #[serde(default)]
    pub kura_init_mode: Mode,
    /// Path to the existing block store folder or path to create new folder.
    #[serde(default = "default_kura_block_store_path")]
    pub kura_block_store_path: String,
    /// Optional list of predefined trusted peers.
    #[serde(default)]
    pub trusted_peers: Vec<PeerId>,
    /// Maximum amount of peers to fail and do not compromise the consensus.
    #[serde(default = "default_max_faulty_peers")]
    pub max_faulty_peers: usize,
    // TODO: solve duplication problem with having public key in both `peer_id` and main `Configuration` struct
    /// Public key of this peer. Should be the same as in `peer_id`
    pub public_key: PublicKey,
    /// Private key of this peer.
    pub private_key: PrivateKey,
    /// Amount of time Peer waits for CommitMessage from the proxy tail.
    #[serde(default = "default_commit_time_ms")]
    pub commit_time_ms: u64,
    /// Amount of time Peer waits for TxReceipt from the leader.
    #[serde(default = "default_tx_receipt_time_ms")]
    pub tx_receipt_time_ms: u64,
}

impl Configuration {
    /// This method will build `Configuration` from a json *pretty* formatted file (without `:` in
    /// key names).
    /// # Panics
    /// This method will panic if configuration file presented, but has incorrect scheme or format.
    /// # Errors
    /// This method will return error if system will fail to find a file or read it's content.
    #[log]
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Configuration, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open a file: {}", e))?;
        let reader = BufReader::new(file);
        let mut configuration: Configuration = serde_json::from_reader(reader)
            .map_err(|e| format!("Failed to deserialize json from reader: {}", e))?;
        if let Ok(torii_url) = env::var(TORII_URL) {
            configuration.torii_url = torii_url;
        }
        if let Ok(block_time_ms) = env::var(BLOCK_TIME_MS) {
            configuration.block_time_ms = block_time_ms
                .parse()
                .map_err(|e| format!("Failed to parse Block Build Time: {}", e))?;
        }
        if let Ok(kura_init_mode) = env::var(KURA_INIT_MODE) {
            configuration.kura_init_mode = serde_json::from_str(&kura_init_mode)
                .map_err(|e| format!("Failed to parse Kura Init Mode: {}", e))?;
        }
        if let Ok(kura_block_store_path) = env::var(KURA_BLOCK_STORE_PATH) {
            configuration.kura_block_store_path = kura_block_store_path;
        }
        if let Ok(trusted_peers) = env::var(TRUSTED_PEERS) {
            configuration.trusted_peers = serde_json::from_str(&trusted_peers)
                .map_err(|e| format!("Failed to parse Trusted Peers: {}", e))?;
        }
        if let Ok(max_faulty_peers) = env::var(MAX_FAULTY_PEERS) {
            configuration.max_faulty_peers = max_faulty_peers
                .parse()
                .map_err(|e| format!("Failed to parse Max Faulty Peers: {}", e))?;
        }
        if let Ok(public_key) = env::var(IROHA_PUBLIC_KEY) {
            configuration.public_key = serde_json::from_str(&public_key)
                .map_err(|e| format!("Failed to parse Public Key: {}", e))?;
        }
        if let Ok(private_key) = env::var(IROHA_PRIVATE_KEY) {
            configuration.private_key = serde_json::from_str(&private_key)
                .map_err(|e| format!("Failed to parse Private Key: {}", e))?;
        }
        if let Ok(commit_time_ms) = env::var(COMMIT_TIME_MS) {
            configuration.commit_time_ms = commit_time_ms
                .parse()
                .map_err(|e| format!("Failed to parse Commit Time Ms: {}", e))?;
        }
        if let Ok(tx_receipt_time_ms) = env::var(TX_RECEIPT_TIME_MS) {
            configuration.tx_receipt_time_ms = tx_receipt_time_ms
                .parse()
                .map_err(|e| format!("Failed to parse Tx Receipt Time Ms: {}", e))?;
        }
        Ok(configuration)
    }

    /// Set `kura_block_store_path` configuration parameter - will overwrite the existing one.
    ///
    /// # Panic
    /// If path is not valid this method will panic.
    pub fn kura_block_store_path(&mut self, path: &Path) {
        self.kura_block_store_path = path
            .to_str()
            .expect("Failed to yield slice from path")
            .to_string();
    }

    /// Set `trusted_peers` configuration parameter - will overwrite the existing one.
    pub fn trusted_peers(&mut self, trusted_peers: Vec<PeerId>) {
        self.trusted_peers = trusted_peers;
    }

    /// Set `max_faulty_peers` configuration parameter - will overwrite the existing one.
    pub fn max_faulty_peers(&mut self, max_faulty_peers: usize) {
        self.max_faulty_peers = max_faulty_peers;
    }

    /// Gets `public_key` and `private_key` configuration parameters.
    pub fn key_pair(&self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key.clone())
    }

    /// Time estimation from receiving a transaction to storing it in a block on all peers.
    pub fn pipeline_time_ms(&self) -> u64 {
        self.tx_receipt_time_ms + self.block_time_ms + self.commit_time_ms
    }
}

fn default_torii_url() -> String {
    DEFAULT_TORII_URL.to_string()
}

fn default_block_time_ms() -> u64 {
    DEFAULT_BLOCK_TIME_MS
}

fn default_kura_block_store_path() -> String {
    DEFAULT_KURA_BLOCK_STORE_PATH.to_string()
}

fn default_max_faulty_peers() -> usize {
    DEFAULT_MAX_FAULTY_PEERS
}

fn default_commit_time_ms() -> u64 {
    DEFAULT_COMMIT_TIME_MS
}

fn default_tx_receipt_time_ms() -> u64 {
    DEFAULT_TX_RECEIPT_TIME_MS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;
    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[test]
    fn parse_example_json() -> Result<(), String> {
        let configuration = Configuration::from_path(CONFIGURATION_PATH)
            .map_err(|e| format!("Failed to read configuration from example config: {}", e))?;
        let expected_trusted_peers = vec![
            PeerId {
                address: "127.0.0.1:1337".to_string(),
                public_key: PublicKey::try_from(vec![
                    101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117,
                    15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
                ])?,
            },
            PeerId {
                address: "localhost:1338".to_string(),
                public_key: PublicKey::try_from(vec![
                    101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117,
                    15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
                ])?,
            },
            PeerId {
                address: "195.162.0.1:23".to_string(),
                public_key: PublicKey::try_from(vec![
                    101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117,
                    15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
                ])?,
            },
        ];
        assert_eq!("127.0.0.1:1338", configuration.torii_url);
        assert_eq!(100, configuration.block_time_ms);
        assert_eq!(expected_trusted_peers, configuration.trusted_peers);
        Ok(())
    }

    #[test]
    fn parse_public_key_success() {
        let public_key_string = "{\"inner\": [101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]}";
        let expected_public_key = PublicKey::try_from(vec![
            101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22,
            28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
        ])
        .expect("Failed to parse PublicKey from Vec.");
        let result = serde_json::from_str(public_key_string).expect("Failed to parse Public Key.");
        assert_eq!(expected_public_key, result);
    }

    #[test]
    fn parse_private_key_success() {
        let private_key_string = "{\"inner\": [113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20, 245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]}";
        let expected_private_key = PrivateKey::try_from(vec![
            113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20,
            245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38,
            73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40,
            26, 61, 248, 40, 159, 58, 53,
        ])
        .expect("Failed to convert PrivateKey from Vector.");
        let result = serde_json::from_str(private_key_string).expect("Failed to parse PrivateKey");
        assert_eq!(expected_private_key, result);
    }

    #[test]
    fn parse_trusted_peers_success() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key":{"inner": [101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]}}, {"address":"localhost:1338", "public_key":{"inner": [101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]}}, {"address": "195.162.0.1:23", "public_key":{"inner": [101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]}}]"#;
        let expected_trusted_peers = vec![
            PeerId {
                address: "127.0.0.1:1337".to_string(),
                public_key: PublicKey::try_from(vec![
                    101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117,
                    15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
                ])
                .expect("Failed to parse PublicKey from Vec."),
            },
            PeerId {
                address: "localhost:1338".to_string(),
                public_key: PublicKey::try_from(vec![
                    101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117,
                    15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
                ])
                .expect("Failed to parse PublicKey from Vec."),
            },
            PeerId {
                address: "195.162.0.1:23".to_string(),
                public_key: PublicKey::try_from(vec![
                    101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117,
                    15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
                ])
                .expect("Failed to parse PublicKey from Vec."),
            },
        ];
        let result: Vec<PeerId> =
            serde_json::from_str(trusted_peers_string).expect("Failed to parse Trusted Peers.");
        assert_eq!(expected_trusted_peers, result);
    }
}
