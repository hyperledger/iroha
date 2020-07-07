//! This module contains `Configuration` structure and related implementation.
use crate::{
    block_sync::config::BlockSyncConfiguration,
    crypto::{KeyPair, PrivateKey, PublicKey},
    kura::config::KuraConfiguration,
    peer::PeerId,
    queue::config::QueueConfiguration,
    sumeragi::config::SumeragiConfiguration,
    torii::config::ToriiConfiguration,
};
use iroha_derive::*;
use serde::Deserialize;
use std::{env, fmt::Debug, fs::File, io::BufReader, path::Path};

const IROHA_PUBLIC_KEY: &str = "IROHA_PUBLIC_KEY";
const IROHA_PRIVATE_KEY: &str = "IROHA_PRIVATE_KEY";

/// Configuration parameters container.
#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Configuration {
    /// Public key of this peer.
    pub public_key: PublicKey,
    /// Private key of this peer.
    pub private_key: PrivateKey,
    /// `Kura` related configuration.
    pub kura_configuration: KuraConfiguration,
    /// `Sumeragi` related configuration.
    pub sumeragi_configuration: SumeragiConfiguration,
    /// `Torii` related configuration.
    pub torii_configuration: ToriiConfiguration,
    /// `BlockSynchronizer` configuration.
    pub block_sync_configuration: BlockSyncConfiguration,
    /// `Queue` configuration.
    pub queue_configuration: QueueConfiguration,
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
        configuration.sumeragi_configuration.key_pair = KeyPair {
            public_key: configuration.public_key,
            private_key: configuration.private_key.clone(),
        };
        configuration.sumeragi_configuration.peer_id = PeerId::new(
            &configuration.torii_configuration.torii_url,
            &configuration.public_key,
        );
        Ok(configuration)
    }

    /// Load environment variables and replace existing parameters with these variables values.
    #[log]
    pub fn load_environment(&mut self) -> Result<(), String> {
        self.torii_configuration.load_environment()?;
        self.kura_configuration.load_environment()?;
        self.sumeragi_configuration.load_environment()?;
        self.block_sync_configuration.load_environment()?;
        self.queue_configuration.load_environment()?;
        if let Ok(public_key) = env::var(IROHA_PUBLIC_KEY) {
            self.public_key = serde_json::from_str(&public_key)
                .map_err(|e| format!("Failed to parse Public Key: {}", e))?;
        }
        if let Ok(private_key) = env::var(IROHA_PRIVATE_KEY) {
            self.private_key = serde_json::from_str(&private_key)
                .map_err(|e| format!("Failed to parse Private Key: {}", e))?;
        }
        self.sumeragi_configuration.key_pair = KeyPair {
            public_key: self.public_key,
            private_key: self.private_key.clone(),
        };
        self.sumeragi_configuration.peer_id =
            PeerId::new(&self.torii_configuration.torii_url, &self.public_key);
        Ok(())
    }
    /// Gets `public_key` and `private_key` configuration parameters.
    pub fn key_pair(&self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerId;
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
        assert_eq!(
            "127.0.0.1:1337",
            configuration.torii_configuration.torii_url
        );
        assert_eq!(1000, configuration.sumeragi_configuration.block_time_ms);
        assert_eq!(
            expected_trusted_peers,
            configuration.sumeragi_configuration.trusted_peers
        );
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
