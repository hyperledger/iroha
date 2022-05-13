//! `Sumeragi` configuration. Contains both block commit and Gossip-related configuration.
use std::{collections::HashSet, fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config::derive::Configurable;
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, transaction};
use serde::{Deserialize, Serialize};

/// Default Amount of time peer waits for the `CreatedBlock` message
/// after getting a `TransactionReceipt`.
pub const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
/// Default amount of time Peer waits for `CommitMessage` from the proxy tail.
pub const DEFAULT_COMMIT_TIME_MS: u64 = 2000;
/// Default amount of time Peer waits for `TxReceipt` from the leader.
pub const DEFAULT_TX_RECEIPT_TIME_MS: u64 = 500;
const DEFAULT_MAILBOX_SIZE: u32 = 100;
const DEFAULT_GOSSIP_PERIOD_MS: u64 = 1000;
const DEFAULT_GOSSIP_BATCH_SIZE: u32 = 500;

/// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
/// and list of `TRUSTED_PEERS`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configurable)]
#[serde(default)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "SUMERAGI_")]
pub struct SumeragiConfiguration {
    /// Key pair of private and public keys.
    #[serde(skip)]
    pub key_pair: KeyPair,
    /// Current Peer Identification.
    pub peer_id: PeerId,
    /// Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
    pub block_time_ms: u64,
    /// Optional list of predefined trusted peers.
    pub trusted_peers: TrustedPeers,
    /// Amount of time Peer waits for CommitMessage from the proxy tail.
    pub commit_time_ms: u64,
    /// Amount of time Peer waits for TxReceipt from the leader.
    pub tx_receipt_time_ms: u64,
    /// Limits to which transactions must adhere
    pub transaction_limits: TransactionLimits,
    /// Mailbox size
    pub mailbox: u32,
    /// Maximum number of transactions in tx gossip batch message. While configuring this, attention should be payed to `p2p` max message size.
    pub gossip_batch_size: u32,
    /// Period in milliseconds for pending transaction gossiping between peers.
    pub gossip_period_ms: u64,
}

impl Default for SumeragiConfiguration {
    fn default() -> Self {
        Self {
            key_pair: Self::placeholder_keypair(),
            peer_id: Self::placeholder_peer_id(),
            trusted_peers: Self::placeholder_trusted_peers(),
            block_time_ms: DEFAULT_BLOCK_TIME_MS,
            commit_time_ms: DEFAULT_COMMIT_TIME_MS,
            tx_receipt_time_ms: DEFAULT_TX_RECEIPT_TIME_MS,
            transaction_limits: TransactionLimits {
                max_instruction_number: transaction::DEFAULT_MAX_INSTRUCTION_NUMBER,
                max_wasm_size_bytes: transaction::DEFAULT_MAX_WASM_SIZE_BYTES,
            },
            mailbox: DEFAULT_MAILBOX_SIZE,
            gossip_batch_size: DEFAULT_GOSSIP_BATCH_SIZE,
            gossip_period_ms: DEFAULT_GOSSIP_PERIOD_MS,
        }
    }
}

impl SumeragiConfiguration {
    /// Key-pair used by default for demo purposes
    #[allow(clippy::expect_used)]
    fn placeholder_keypair() -> KeyPair {
        let public_key = "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
            .parse()
            .expect("Public key not in mulithash format");
        let private_key = PrivateKey::from_hex(
            Algorithm::Ed25519,
            "282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
        ).expect("Private key not hex encoded");

        KeyPair::new(public_key, private_key).expect("Key pair mismatch")
    }

    fn placeholder_peer_id() -> PeerId {
        let (public_key, _) = Self::placeholder_keypair().into();

        PeerId {
            address: "127.0.0.1:1337".to_owned(),
            public_key,
        }
    }

    fn placeholder_trusted_peers() -> TrustedPeers {
        let mut peers = HashSet::new();
        peers.insert(Self::placeholder_peer_id());
        TrustedPeers { peers }
    }

    /// Set `trusted_peers` configuration parameter. Will overwrite
    /// existing `trusted_peers` but does not check for duplication.
    #[inline]
    pub fn set_trusted_peers(&mut self, trusted_peers: Vec<PeerId>) {
        self.trusted_peers.peers = trusted_peers.into_iter().collect();
    }

    /// Time estimation from receiving a transaction to storing it in
    /// a block on all peers for the "sunny day" scenario.
    #[inline]
    #[must_use]
    pub const fn pipeline_time_ms(&self) -> u64 {
        self.tx_receipt_time_ms + self.block_time_ms + self.commit_time_ms
    }
}

/// `SumeragiConfiguration` provides an ability to define parameters
/// such as `BLOCK_TIME_MS` and list of `TRUSTED_PEERS`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(transparent)]
pub struct TrustedPeers {
    /// Optional list of predefined trusted peers. Must contain unique
    /// entries. Custom deserializer raises error if duplicates found.
    #[serde(deserialize_with = "deserialize_unique_trusted_peers")]
    pub peers: HashSet<PeerId>,
}

/// Custom deserializer that ensures that `trusted_peers` only
/// contains unique `PeerId`'s.
///
/// # Errors
/// - Peer Ids not unique,
/// - Not a sequence (array)
fn deserialize_unique_trusted_peers<'de, D>(deserializer: D) -> Result<HashSet<PeerId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    /// Helper, for constructing a unique visitor that errors whenever
    /// a duplicate entry is found.
    struct UniqueVisitor(core::marker::PhantomData<fn() -> HashSet<PeerId>>);

    impl<'de> serde::de::Visitor<'de> for UniqueVisitor {
        type Value = HashSet<PeerId>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a set of unique `Peer::Id`s.")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<HashSet<PeerId>, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let mut result = HashSet::new();
            while let Some(value) = seq.next_element()? {
                if result.contains(&value) {
                    return Err(serde::de::Error::custom(format!(
                        "The peer id: {}'s public key appears twice.",
                        &value
                    )));
                }
                result.insert(value);
            }

            Ok(result)
        }
    }

    let visitor = UniqueVisitor(core::marker::PhantomData);
    deserializer.deserialize_seq(visitor)
}

impl TrustedPeers {
    /// Load trusted peers variables from JSON.
    ///
    /// # Errors
    /// - File not found
    /// - File is not Valid JSON.
    /// - File is valid JSON, but configuration options don't match.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Self> {
        let file = File::open(&path)
            .wrap_err_with(|| format!("Failed to open trusted peers file {:?}", &path))?;
        let reader = BufReader::new(file);
        let trusted_peers: HashSet<PeerId> =
            serde_json::from_reader(reader).wrap_err("Failed to deserialize json from reader")?;
        Ok(TrustedPeers {
            peers: trusted_peers,
        })
    }
}
