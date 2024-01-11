//! Module for `Queue`-related configuration and structs.
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

use merge::Merge;
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};

use crate::{
    Complete, CompleteError, CompleteResult, FromEnv, FromEnvDefaultFallback, FromEnvResult,
    ReadEnv, UserDuration, UserField,
};

const DEFAULT_MAX_TRANSACTIONS_IN_QUEUE: NonZeroU32 = nonzero!(2_u32.pow(16));
const DEFAULT_MAX_TRANSACTIONS_IN_QUEUE_PER_USER: NonZeroU32 = nonzero!(2_u32.pow(16));
const DEFAULT_TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
const DEFAULT_FUTURE_THRESHOLD: Duration = Duration::from_secs(1);

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct UserLayer {
    /// The upper limit of the number of transactions waiting in the queue.
    pub max_transactions_in_queue: UserField<NonZeroU32>,
    /// The upper limit of the number of transactions waiting in the queue for single user.
    /// Use this option to apply throttling.
    pub max_transactions_in_queue_per_user: UserField<NonZeroU32>,
    /// The transaction will be dropped after this time if it is still in the queue.
    pub transaction_time_to_live_ms: UserField<UserDuration>,
    /// The threshold to determine if a transaction has been tampered to have a future timestamp.
    pub future_threshold_ms: UserField<UserDuration>,
}

/// `Queue` configuration.
#[derive(Copy, Clone, Deserialize, Serialize, Debug)]
pub struct Config {
    pub max_transactions_in_queue: NonZeroU32,
    pub max_transactions_in_queue_per_user: NonZeroU32,
    pub transaction_time_to_live_ms: Duration,
    pub future_threshold_ms: Duration,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            max_transactions_in_queue: self
                .max_transactions_in_queue
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_IN_QUEUE),
            max_transactions_in_queue_per_user: self
                .max_transactions_in_queue_per_user
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_IN_QUEUE),
            transaction_time_to_live_ms: self
                .transaction_time_to_live_ms
                .map_or(DEFAULT_TRANSACTION_TIME_TO_LIVE, UserDuration::get),
            future_threshold_ms: self
                .future_threshold_ms
                .map_or(DEFAULT_FUTURE_THRESHOLD, UserDuration::get),
        })
    }
}

impl FromEnvDefaultFallback for UserLayer {}
