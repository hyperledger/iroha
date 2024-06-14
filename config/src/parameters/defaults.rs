//! Parameters default values

// TODO: document if needed
#![allow(missing_docs)]

use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

use iroha_data_model::{prelude::MetadataLimits, transaction::TransactionLimits, LengthLimits};
use nonzero_ext::nonzero;

pub mod queue {
    use super::*;

    pub const CAPACITY: NonZeroUsize = nonzero!(2_usize.pow(16));
    pub const CAPACITY_PER_USER: NonZeroUsize = nonzero!(2_usize.pow(16));
    // 24 hours
    pub const TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(24 * 60 * 60);
    pub const FUTURE_THRESHOLD: Duration = Duration::from_secs(1);
}

pub mod kura {
    pub const STORE_DIR: &str = "./storage";
}

pub mod network {
    use super::*;

    pub const TRANSACTION_GOSSIP_PERIOD: Duration = Duration::from_secs(1);
    pub const TRANSACTION_GOSSIP_MAX_SIZE: NonZeroU32 = nonzero!(500u32);

    pub const BLOCK_GOSSIP_PERIOD: Duration = Duration::from_secs(10);
    pub const BLOCK_GOSSIP_MAX_SIZE: NonZeroU32 = nonzero!(4u32);

    pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
}

pub mod snapshot {
    use super::*;

    pub const STORE_DIR: &str = "./storage/snapshot";
    // The default frequency of making snapshots is 1 minute, need to be adjusted for larger world state view size
    pub const CREATE_EVERY: Duration = Duration::from_secs(60);
}

pub mod chain_wide {
    use iroha_config_base::util::Bytes;

    use super::*;

    pub const MAX_TXS: NonZeroU32 = nonzero!(2_u32.pow(9));
    pub const BLOCK_TIME: Duration = Duration::from_secs(2);
    pub const COMMIT_TIME: Duration = Duration::from_secs(4);
    pub const WASM_FUEL_LIMIT: u64 = 55_000_000;
    pub const WASM_MAX_MEMORY: Bytes<u32> = Bytes(500 * 2_u32.pow(20));

    /// Default estimation of consensus duration.
    pub const CONSENSUS_ESTIMATION: Duration =
        match BLOCK_TIME.checked_add(match COMMIT_TIME.checked_div(2) {
            Some(x) => x,
            None => unreachable!(),
        }) {
            Some(x) => x,
            None => unreachable!(),
        };

    /// Default limits for metadata
    pub const METADATA_LIMITS: MetadataLimits = MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
    /// Default limits for ident length
    pub const IDENT_LENGTH_LIMITS: LengthLimits = LengthLimits::new(1, 2_u32.pow(7));
    /// Default maximum number of instructions and expressions per transaction
    pub const MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
    /// Default maximum number of instructions and expressions per transaction
    pub const MAX_WASM_SIZE_BYTES: u64 = 4 * 2_u64.pow(20);

    /// Default transaction limits
    pub const TRANSACTION_LIMITS: TransactionLimits =
        TransactionLimits::new(MAX_INSTRUCTION_NUMBER, MAX_WASM_SIZE_BYTES);
}

pub mod torii {
    use std::time::Duration;

    use iroha_config_base::util::Bytes;

    pub const MAX_CONTENT_LEN: Bytes<u64> = Bytes(2_u64.pow(20) * 16);
    pub const QUERY_IDLE_TIME: Duration = Duration::from_secs(30);
}

pub mod telemetry {
    use std::time::Duration;

    /// Default minimal retry period
    pub const MIN_RETRY_PERIOD: Duration = Duration::from_secs(1);
    /// Default maximum exponent for the retry delay
    pub const MAX_RETRY_DELAY_EXPONENT: u8 = 4;
}
