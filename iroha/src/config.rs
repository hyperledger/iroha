//! This module contains `Configuration` structure and related implementation.
use crate::{
    crypto::{PrivateKey, PublicKey},
    kura::Mode,
    peer::PeerId,
};
use iroha_derive::*;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    env,
    fmt::{self, Debug, Display, Formatter},
    fs,
    path::Path,
};

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
const DEFAULT_KURA_INIT_MODE: Mode = Mode::Strict;
const DEFAULT_KURA_BLOCK_STORE_PATH: &str = "./blocks";
const DEFAULT_MAX_FAULTY_PEERS: usize = 0;

/// Configuration parameters container.
#[derive(Clone)]
pub struct Configuration {
    /// Current instance `PeerId`.
    pub peer_id: PeerId,
    /// Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
    pub block_time_ms: u64,
    /// Possible modes: `strict`, `fast`.
    pub mode: Mode,
    /// Path to the existing block store folder or path to create new folder.
    pub kura_block_store_path: String,
    /// Optional list of predefined trusted peers.
    pub trusted_peers: Vec<PeerId>,
    /// Maximum amount of peers to fail and do not compromise the consensus.
    pub max_faulty_peers: usize,
    // TODO: solve duplication problem with having public key in both `peer_id` and main `Configuration` struct
    /// Public key of this peer. Should be the same as in `peer_id`
    pub public_key: PublicKey,
    /// Private key of this peer.
    pub private_key: PrivateKey,
    /// Amount of time Peer waits for CommitMessage from the proxy tail.
    pub commit_time_ms: u64,
    /// Amount of time Peer waits for TxReceipt from the leader.
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
        let mut config_map: HashMap<String, String> = fs::read_to_string(path)
            .map_err(|error| format!("Failed to read configuration from path: {}.", error))?
            .lines()
            .filter(|line| line.contains(':'))
            .map(|line| line.split_at(line.find(':').unwrap()))
            .map(|(key, value)| {
                (
                    String::from(key.trim().trim_start_matches('"').trim_end_matches('"')),
                    String::from(
                        value
                            .trim_start_matches(':')
                            .trim()
                            .trim_start_matches('"')
                            .trim_end_matches(',')
                            .trim_end_matches('"'),
                    ),
                )
            })
            .collect();
        Ok(ConfigurationBuilder {
            torii_url: env::var(TORII_URL)
                .ok()
                .or_else(|| config_map.remove(TORII_URL)),
            block_time_ms: env::var(BLOCK_TIME_MS)
                .ok()
                .or_else(|| config_map.remove(BLOCK_TIME_MS)),
            mode: env::var(KURA_INIT_MODE)
                .ok()
                .or_else(|| config_map.remove(KURA_INIT_MODE))
                .map(Mode::from),
            kura_block_store_path: env::var(KURA_BLOCK_STORE_PATH)
                .ok()
                .or_else(|| config_map.remove(KURA_BLOCK_STORE_PATH)),
            trusted_peers: parse_trusted_peers(
                env::var(TRUSTED_PEERS)
                    .ok()
                    .or_else(|| config_map.remove(TRUSTED_PEERS)),
            )?,
            max_faulty_peers: env::var(MAX_FAULTY_PEERS)
                .ok()
                .or_else(|| config_map.remove(MAX_FAULTY_PEERS)),
            public_key: parse_public_key(
                &env::var(IROHA_PUBLIC_KEY)
                    .ok()
                    .or_else(|| config_map.remove(IROHA_PUBLIC_KEY))
                    .ok_or("IROHA_PUBLIC_KEY should be set.")?,
            )?,
            private_key: parse_private_key(
                &env::var(IROHA_PRIVATE_KEY)
                    .ok()
                    .or_else(|| config_map.remove(IROHA_PRIVATE_KEY))
                    .ok_or("IROHA_PRIVATE_KEY should be set.")?,
            )?,
            commit_time_ms: env::var(COMMIT_TIME_MS)
                .ok()
                .or_else(|| config_map.remove(COMMIT_TIME_MS)),
            tx_receipt_time_ms: env::var(TX_RECEIPT_TIME_MS)
                .ok()
                .or_else(|| config_map.remove(TX_RECEIPT_TIME_MS)),
        }
        .build()?)
    }

    /// Set `peer_id` configuration parameter - will overwrite the existing one.
    pub fn peer_id(&mut self, peer_id: PeerId) {
        self.peer_id = peer_id;
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

    /// Set `public_key` and `private_key` configuration parameters - will overwrite the existing one.
    pub fn key_pair(&self) -> (PublicKey, PrivateKey) {
        (self.public_key.clone(), self.private_key)
    }

    /// Time estimation from receiving a transaction to storing it in a block on all peers.
    pub fn pipeline_time_ms(&self) -> u64 {
        self.tx_receipt_time_ms + self.block_time_ms + self.commit_time_ms
    }
}

impl Display for Configuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeerId: {:?}, Block Build Step Time in milliseconds: {}, Commit Time in milliseconds: {}, Mode: {:?}",
            self.peer_id, self.block_time_ms, self.commit_time_ms, self.mode,
        )
    }
}

impl Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let first_half_of_private_key: [u8; 32] = self.private_key[0..32]
            .try_into()
            .expect("Wrong format of private key.");
        let second_half_of_private_key: [u8; 32] = self.private_key[32..64]
            .try_into()
            .expect("Wrong format of private key.");
        f.debug_struct("Configuration")
            .field("peer_id", &self.peer_id)
            .field("block_time_ms", &self.block_time_ms)
            .field("mode", &self.mode)
            .field("kura_block_store_path", &self.kura_block_store_path)
            .field("trusted_peers", &self.trusted_peers)
            .field("max_faulty_peers", &self.max_faulty_peers)
            .field("public_key", &self.public_key)
            .field("private_key[0..32]", &first_half_of_private_key)
            .field("private_key[32..64]", &second_half_of_private_key)
            .field("commit_time_ms", &self.commit_time_ms)
            .finish()
    }
}

struct ConfigurationBuilder {
    torii_url: Option<String>,
    block_time_ms: Option<String>,
    mode: Option<Mode>,
    kura_block_store_path: Option<String>,
    trusted_peers: Vec<PeerId>,
    max_faulty_peers: Option<String>,
    public_key: PublicKey,
    private_key: PrivateKey,
    commit_time_ms: Option<String>,
    tx_receipt_time_ms: Option<String>,
}

impl ConfigurationBuilder {
    fn build(self) -> Result<Configuration, String> {
        let peer_id = PeerId {
            address: self
                .torii_url
                .unwrap_or_else(|| DEFAULT_TORII_URL.to_string()),
            public_key: self.public_key.clone(),
        };
        Ok(Configuration {
            peer_id,
            block_time_ms: self
                .block_time_ms
                .unwrap_or_else(|| DEFAULT_BLOCK_TIME_MS.to_string())
                .parse()
                .expect("Block build step should be a number."),
            mode: self.mode.unwrap_or_else(|| DEFAULT_KURA_INIT_MODE),
            kura_block_store_path: self
                .kura_block_store_path
                .unwrap_or_else(|| DEFAULT_KURA_BLOCK_STORE_PATH.to_string()),
            trusted_peers: self.trusted_peers,
            max_faulty_peers: self
                .max_faulty_peers
                .unwrap_or_else(|| DEFAULT_MAX_FAULTY_PEERS.to_string())
                .parse()
                .map_err(|e| format!("Max faulty peers parse failed: {}", e))?,
            public_key: self.public_key,
            private_key: self.private_key,
            commit_time_ms: self
                .commit_time_ms
                .unwrap_or_else(|| DEFAULT_COMMIT_TIME_MS.to_string())
                .parse()
                .expect("Commit time should be a number."),
            tx_receipt_time_ms: self
                .tx_receipt_time_ms
                .unwrap_or_else(|| DEFAULT_TX_RECEIPT_TIME_MS.to_string())
                .parse()
                .expect("Tx receipt time should be a number."),
        })
    }
}

/// Parses string formatted as "[address1, address2, ...]" into `Vec<PeerId>`.
fn parse_trusted_peers(trusted_peers_string: Option<String>) -> Result<Vec<PeerId>, String> {
    match trusted_peers_string {
        None => Ok(Vec::new()),
        Some(trusted_peers_string) => {
            let vector: Vec<PeerId> = trusted_peers_string
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split("}, {")
                .map(|peer_id| {
                    let key_start = peer_id
                        .find('[')
                        .expect("Failed to find start of the public key.");
                    let key_end = peer_id
                        .find(']')
                        .expect("Failed to find end of the public key.");
                    let address = peer_id
                        .trim()
                        .trim_start_matches('{')
                        .trim()
                        .trim_start_matches("\"address\":")
                        .trim()
                        .trim_start_matches('"')
                        .trim()
                        .split('"')
                        .next()
                        .expect("Failed to parse address.")
                        .trim()
                        .to_string();
                    let public_key = parse_public_key(
                        peer_id
                            .get(key_start..key_end)
                            .expect("Failed to get public key range."),
                    )
                    .expect("Failed to parse public key.");
                    PeerId {
                        address,
                        public_key,
                    }
                })
                .collect();
            Ok(vector)
        }
    }
}

/// Parses string formatted as "[ byte1, byte2, ... ]" into `crypto::PublicKey`.
fn parse_public_key(public_key_string: &str) -> Result<PublicKey, String> {
    let vector: Vec<u8> = public_key_string
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|byte| byte.trim().parse::<u8>().expect("Failed to parse byte."))
        .collect();
    Ok(PublicKey::try_from(vector)?)
}

/// Parses string formatted as "[ byte1, byte2, ... ]" into `crypto::PrivateKey`.
fn parse_private_key(private_key_string: &str) -> Result<PrivateKey, String> {
    let vector: Vec<u8> = private_key_string
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|byte| byte.trim().parse::<u8>().expect("Failed to parse byte."))
        .collect();
    let mut private_key = [0; 64];
    private_key.copy_from_slice(&vector[..]);
    Ok(private_key)
}

impl From<String> for Mode {
    fn from(string_mode: String) -> Self {
        Mode::from(string_mode.as_str())
    }
}

impl From<&str> for Mode {
    fn from(string_mode: &str) -> Self {
        match string_mode {
            "strict" => Mode::Strict,
            "fast" => Mode::Fast,
            other => {
                eprintln!("Defined unexpected Kura Mode: {}", other);
                Mode::Strict
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!("127.0.0.1:1338", configuration.peer_id.address);
        assert_eq!(100, configuration.block_time_ms);
        assert_eq!(expected_trusted_peers, configuration.trusted_peers);
        Ok(())
    }

    #[test]
    fn parse_public_key_success() {
        let public_key_string = "[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]";
        let expected_public_key = PublicKey::try_from(vec![
            101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22,
            28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
        ])
        .expect("Failed to parse PublicKey from Vec.");
        let result = parse_public_key(public_key_string);
        assert!(result.is_ok());
        assert_eq!(expected_public_key, result.unwrap());
    }

    #[test]
    fn parse_private_key_success() {
        let private_key_string = "[113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20, 245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]";
        let expected_private_key = vec![
            113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20,
            245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38,
            73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40,
            26, 61, 248, 40, 159, 58, 53,
        ];
        let result = parse_private_key(private_key_string);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(expected_private_key[..32], result[..32]);
        assert_eq!(expected_private_key[32..], result[32..]);
    }

    #[test]
    fn parse_trusted_peers_success() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key":"[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]"}, {"address":"localhost:1338", "public_key":"[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]"}, {"address": "195.162.0.1:23", "public_key":"[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]"}]"#;
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
        let result = parse_trusted_peers(Some(trusted_peers_string.to_string()));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(expected_trusted_peers, result);
    }
}
