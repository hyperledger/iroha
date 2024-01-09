//! `Sumeragi` configuration. Contains both block commit and Gossip-related configuration.
use std::{fmt::Debug, fs::File, io::BufReader, num::NonZeroU32, path::Path, time::Duration};

use iroha_data_model::prelude::*;
use iroha_primitives::unique_vec::UniqueVec;
use serde::{Deserialize, Serialize};

use self::default::*;
use crate::{Complete, CompleteError, CompleteResult, FromEnvDefaultFallback, UserDuration};

/// Module with a set of default values.
pub mod default {
    use std::{
        num::{NonZeroU32, NonZeroU64},
        time::Duration,
    };

    use nonzero_ext::nonzero;

    pub const DEFAULT_TRANSACTION_GOSSIP_PERIOD: Duration = Duration::from_secs(1);
    pub const DEFAULT_MAX_TRANSACTIONS_IN_BLOCK: u32 = 2_u32.pow(9);

    pub const DEFAULT_BLOCK_GOSSIP_PERIOD: Duration = Duration::from_secs(10);

    pub const DEFAULT_MAX_TRANSACTIONS_PER_GOSSIP: NonZeroU32 = nonzero!(500u32);
    pub const DEFAULT_MAX_BLOCKS_PER_GOSSIP: NonZeroU32 = nonzero!(4u32);

    // /// Default estimation of consensus duration.
    // #[allow(clippy::integer_division)]
    // pub const DEFAULT_CONSENSUS_ESTIMATION_MS: u64 =
    //     DEFAULT_BLOCK_TIME_MS + (DEFAULT_COMMIT_TIME_LIMIT_MS / 2);
}

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    pub block_gossip_period: Option<UserDuration>,
    pub max_blocks_per_gossip: Option<NonZeroU32>,
    pub max_transactions_per_gossip: Option<NonZeroU32>,
    pub transaction_gossip_period: Option<UserDuration>,
    pub trusted_peers: Option<TrustedPeers>,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            block_gossip_period: self
                .block_gossip_period
                .map(UserDuration::get)
                .unwrap_or(DEFAULT_BLOCK_GOSSIP_PERIOD),
            max_blocks_per_gossip: self
                .max_blocks_per_gossip
                .unwrap_or_else(|| DEFAULT_MAX_BLOCKS_PER_GOSSIP.into()),
            max_transactions_per_gossip: self
                .max_transactions_per_gossip
                .unwrap_or_else(|| DEFAULT_MAX_TRANSACTIONS_PER_GOSSIP.into()),
            transaction_gossip_period: self
                .transaction_gossip_period
                .map(UserDuration::get)
                .unwrap_or(DEFAULT_TRANSACTION_GOSSIP_PERIOD),
            trusted_peers: self.trusted_peers.unwrap_or_default(),
        })
    }
}

#[derive(Debug)]
pub struct Config {
    pub block_gossip_period: Duration,
    pub max_blocks_per_gossip: NonZeroU32,
    pub max_transactions_per_gossip: NonZeroU32,
    pub transaction_gossip_period: Duration,
    pub trusted_peers: TrustedPeers,
}

/// Part of the [`Configuration`]. It is separated from the main structure in order to be able
/// to load it from a separate file (see [`TrustedPeers::from_path`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(transparent)]
#[repr(transparent)]
pub struct TrustedPeers {
    /// Optional list of predefined trusted peers. Must contain unique
    /// entries. Custom deserializer raises error if duplicates found.
    #[serde(deserialize_with = "UniqueVec::display_deserialize_failing_on_duplicates")]
    pub peers: UniqueVec<PeerId>,
}

impl FromEnvDefaultFallback for UserLayer {}
