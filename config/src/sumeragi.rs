//! `Sumeragi` configuration. Contains both block commit and Gossip-related configuration.
#![allow(clippy::std_instead_of_core, clippy::arithmetic)]
use std::{collections::HashSet, fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config_base::derive::{view, Documented, LoadFromEnv, Proxy};
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, transaction};
use serde::{Deserialize, Serialize};

/// Default Amount of time peer waits for the `CreatedBlock` message
/// after getting a `TransactionReceipt`.
pub const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
/// Default amount of time Peer waits for `CommitMessage` from the proxy tail.
pub const DEFAULT_COMMIT_TIME_LIMIT_MS: u64 = 2000;
/// Default amount of time Peer waits for `TxReceipt` from the leader.
pub const DEFAULT_TX_RECEIPT_TIME_LIMIT_MS: u64 = 500;
const DEFAULT_ACTOR_CHANNEL_CAPACITY: u32 = 100;
const DEFAULT_GOSSIP_PERIOD_MS: u64 = 1000;
const DEFAULT_GOSSIP_BATCH_SIZE: u32 = 500;

// Generate `ConfigurationView` without keys
view! {
    /// `Sumeragi` configuration.
    /// [`struct@Configuration`] provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and a list of `TRUSTED_PEERS`.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Proxy, Documented, LoadFromEnv)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "SUMERAGI_")]
    pub struct Configuration {
        /// The key pair consisting of a private and a public key.
        //TODO: consider putting a `#[serde(skip)]` on the proxy struct here
        #[view(ignore)]
        pub key_pair: KeyPair,
        /// Current Peer Identification.
        pub peer_id: PeerId,
        /// The period of time a peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
        pub block_time_ms: u64,
        /// Optional list of predefined trusted peers.
        pub trusted_peers: TrustedPeers,
        /// The period of time a peer waits for `CommitMessage` from the proxy tail.
        pub commit_time_limit_ms: u64,
        /// The period of time a peer waits for `TxReceipt` from the leader.
        pub tx_receipt_time_limit_ms: u64,
        /// The limits to which transactions must adhere
        pub transaction_limits: TransactionLimits,
        /// Buffer capacity of actor's MPSC channel
        pub actor_channel_capacity: u32,
        /// Maximum number of transactions in tx gossip batch message. While configuring this, pay attention to `p2p` max message size.
        pub gossip_batch_size: u32,
        /// Period in milliseconds for pending transaction gossiping between peers.
        pub gossip_period_ms: u64,
    }
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            key_pair: None,
            peer_id: None,
            trusted_peers: None,
            block_time_ms: Some(DEFAULT_BLOCK_TIME_MS),
            commit_time_limit_ms: Some(DEFAULT_COMMIT_TIME_LIMIT_MS),
            tx_receipt_time_limit_ms: Some(DEFAULT_TX_RECEIPT_TIME_LIMIT_MS),
            transaction_limits: Some(TransactionLimits {
                max_instruction_number: transaction::DEFAULT_MAX_INSTRUCTION_NUMBER,
                max_wasm_size_bytes: transaction::DEFAULT_MAX_WASM_SIZE_BYTES,
            }),
            actor_channel_capacity: Some(DEFAULT_ACTOR_CHANNEL_CAPACITY),
            gossip_batch_size: Some(DEFAULT_GOSSIP_BATCH_SIZE),
            gossip_period_ms: Some(DEFAULT_GOSSIP_PERIOD_MS),
        }
    }
}
impl ConfigurationProxy {
    /// To be used for proxy finalisation. Should only be
    /// used if no peers are present.
    ///
    /// # Panics
    /// The [`peer_id`] field of [`Self`]
    /// has not been initialized prior to calling this method.
    pub fn insert_self_as_trusted_peers(&mut self) {
        let mut peers = HashSet::new();
        #[allow(clippy::expect_used)]
        let peer_id = self
            .peer_id
            .clone()
            .expect("Insertion of `self` as `trusted_peers` implies that `peer_id` field should be initialized");
        peers.insert(peer_id);
        self.trusted_peers = Some(TrustedPeers { peers });
    }
}
impl Configuration {
    /// Time estimation from receiving a transaction to storing it in
    /// a block on all peers for the "sunny day" scenario.
    #[inline]
    #[must_use]
    pub const fn pipeline_time_ms(&self) -> u64 {
        self.tx_receipt_time_limit_ms + self.block_time_ms + self.commit_time_limit_ms
    }
}

/// `SumeragiConfiguration` provides an ability to define parameters
/// such as `BLOCK_TIME_MS` and a list of `TRUSTED_PEERS`.
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
