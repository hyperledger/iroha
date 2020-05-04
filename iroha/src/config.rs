use crate::{
    crypto::{PrivateKey, PublicKey},
    peer::PeerId,
};
use std::{
    collections::HashMap,
    convert::TryInto,
    env,
    fmt::{self, Display, Formatter},
    fs,
    path::Path,
};

const TORII_URL: &str = "TORII_URL";
const BLOCK_TIME_MS: &str = "BLOCK_TIME_MS";
const KURA_INIT_MODE: &str = "KURA_INIT_MODE";
const KURA_BLOCK_STORE_PATH: &str = "KURA_BLOCK_STORE_PATH";
const MAX_FAULTY_PEERS: &str = "MAX_FAULTY_PEERS";
const IROHA_PUBLIC_KEY: &str = "IROHA_PUBLIC_KEY";
const IROHA_PRIVATE_KEY: &str = "IROHA_PRIVATE_KEY";
const DEFAULT_TORII_URL: &str = "127.0.0.1:1337";
const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
const DEFAULT_KURA_INIT_MODE: &str = "strict";
const DEFAULT_KURA_BLOCK_STORE_PATH: &str = "./blocks";
const DEFAULT_MAX_FAULTY_PEERS: usize = 0;

/// Configuration parameters container.
pub struct Configuration {
    pub torii_url: String,
    pub block_build_step_ms: u64,
    /// Possible modes: `strict`, `fast`.
    pub mode: String,
    pub kura_block_store_path: String,
    pub trusted_peers: Option<Vec<PeerId>>,
    pub max_faulty_peers: usize,
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl Configuration {
    /// This method will build `Configuration` from a json *pretty* formatted file (without `:` in
    /// key names).
    /// # Panics
    /// This method will panic if configuration file presented, but has incorrect scheme or format.
    /// # Errors
    /// This method will return error if system will fail to find a file or read it's content.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Configuration, String> {
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
            block_build_step_ms: env::var(BLOCK_TIME_MS)
                .ok()
                .or_else(|| config_map.remove(BLOCK_TIME_MS)),
            mode: env::var(KURA_INIT_MODE)
                .ok()
                .or_else(|| config_map.remove(KURA_INIT_MODE)),
            kura_block_store_path: env::var(KURA_BLOCK_STORE_PATH)
                .ok()
                .or_else(|| config_map.remove(KURA_BLOCK_STORE_PATH)),
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
            trusted_peers: Option::None,
        }
        .build()?)
    }

    pub fn torii_url(&mut self, torii_url: &str) {
        self.torii_url = torii_url.to_string();
    }

    pub fn kura_block_store_path(&mut self, path: &Path) {
        self.kura_block_store_path = path
            .to_str()
            .expect("Failed to yield slice from path")
            .to_string();
    }

    pub fn trusted_peers(&mut self, trusted_peers: Vec<PeerId>) {
        self.trusted_peers = Option::Some(trusted_peers);
    }

    pub fn max_faulty_peers(&mut self, max_faulty_peers: usize) {
        self.max_faulty_peers = max_faulty_peers;
    }

    pub fn key_pair(&self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }
}

impl Display for Configuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "URL: {}, Block Build Step Time in milliseconds: {}, Mode: {}",
            self.torii_url, self.block_build_step_ms, self.mode,
        )
    }
}

struct ConfigurationBuilder {
    torii_url: Option<String>,
    block_build_step_ms: Option<String>,
    mode: Option<String>,
    kura_block_store_path: Option<String>,
    trusted_peers: Option<Vec<PeerId>>,
    max_faulty_peers: Option<String>,
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl ConfigurationBuilder {
    fn build(self) -> Result<Configuration, String> {
        Ok(Configuration {
            torii_url: self
                .torii_url
                .unwrap_or_else(|| DEFAULT_TORII_URL.to_string()),
            block_build_step_ms: self
                .block_build_step_ms
                .unwrap_or_else(|| DEFAULT_BLOCK_TIME_MS.to_string())
                .parse()
                .expect("Block build step should be a number."),
            mode: self
                .mode
                .unwrap_or_else(|| DEFAULT_KURA_INIT_MODE.to_string()),
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
        })
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
    vector[..]
        .try_into()
        .map_err(|e| format!("Public key should be 32 bytes long: {}", e))
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

#[cfg(test)]
mod tests {
    use super::*;
    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[test]
    fn parse_example_json() -> Result<(), String> {
        let configuration = Configuration::from_path(CONFIGURATION_PATH)
            .map_err(|e| format!("Failed to read configuration from example config: {}", e))?;
        assert_eq!("127.0.0.1:1338", configuration.torii_url);
        assert_eq!(100, configuration.block_build_step_ms);
        Ok(())
    }

    #[test]
    fn parse_public_key_success() {
        let public_key_string = "[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]";
        let expected_public_key = vec![
            101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22,
            28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
        ];
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
}
