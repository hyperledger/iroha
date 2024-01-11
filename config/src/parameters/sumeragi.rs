//! `Sumeragi` configuration. Contains both block commit and Gossip-related configuration.
use std::{fmt::Debug, fs::File, io::BufReader, num::NonZeroU32, path::Path, time::Duration};

use eyre::eyre;
use iroha_data_model::prelude::*;
use iroha_primitives::unique_vec::UniqueVec;
use merge::Merge;
use serde::{Deserialize, Serialize};

use self::default::*;
use crate::{
    Complete, CompleteError, CompleteResult, FromEnvDefaultFallback, UserDuration, UserField,
};

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

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct UserLayer {
    pub block_gossip_period: UserField<UserDuration>,
    pub max_blocks_per_gossip: UserField<NonZeroU32>,
    pub max_transactions_per_gossip: UserField<NonZeroU32>,
    pub transaction_gossip_period: UserField<UserDuration>,
    pub trusted_peers: UserTrustedPeers,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            block_gossip_period: self
                .block_gossip_period
                .map_or(DEFAULT_BLOCK_GOSSIP_PERIOD, UserDuration::get),
            max_blocks_per_gossip: self
                .max_blocks_per_gossip
                .unwrap_or(DEFAULT_MAX_BLOCKS_PER_GOSSIP),
            max_transactions_per_gossip: self
                .max_transactions_per_gossip
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_PER_GOSSIP),
            transaction_gossip_period: self
                .transaction_gossip_period
                .map_or(DEFAULT_TRANSACTION_GOSSIP_PERIOD, UserDuration::get),
            trusted_peers: TrustedPeers {
                peers: construct_unique_vec(self.trusted_peers.peers)
                    .map_err(CompleteError::Custom)?,
            },
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

#[derive(Debug)]
pub struct TrustedPeers {
    pub peers: UniqueVec<PeerId>,
}

#[derive(Deserialize, Serialize, Default, PartialEq, Eq, Debug, Clone)]
#[serde(transparent)]
pub struct UserTrustedPeers {
    // FIXME: doesn't raise an error on finding duplicates during deserialization
    pub peers: Vec<PeerId>,
}

impl Merge for UserTrustedPeers {
    fn merge(&mut self, mut other: Self) {
        self.peers.append(other.peers.as_mut())
    }
}

impl FromEnvDefaultFallback for UserLayer {}

// FIXME: handle duplicates properly, not here, and with details
fn construct_unique_vec<T: Debug + PartialEq>(
    unchecked: Vec<T>,
) -> Result<UniqueVec<T>, eyre::Report> {
    let mut unique = UniqueVec::new();
    for x in unchecked.into_iter() {
        let pushed = unique.push(x);
        if !pushed {
            Err(eyre!("found duplicate"))?
        }
    }
    Ok(unique)
}
