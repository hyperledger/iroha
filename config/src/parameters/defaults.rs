//! Module with a set of default values.

use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    ops::{Add, Div},
    time::Duration,
};

use iroha_data_model::{prelude::MetadataLimits, transaction::TransactionLimits, LengthLimits};
use iroha_primitives::addr::{socket_addr, SocketAddr};
use nonzero_ext::nonzero;

pub mod queue {
    use super::*;

    pub const DEFAULT_MAX_TRANSACTIONS_IN_QUEUE: NonZeroUsize = nonzero!(2_usize.pow(16));
    pub const DEFAULT_MAX_TRANSACTIONS_IN_QUEUE_PER_USER: NonZeroUsize = nonzero!(2_usize.pow(16));
    pub const DEFAULT_TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(24 * 60 * 60);
    // 24 hours
    pub const DEFAULT_FUTURE_THRESHOLD: Duration = Duration::from_secs(1);
}
pub mod kura {
    use super::*;

    pub const DEFAULT_BLOCK_STORE_PATH: &str = "./storage";
}
pub mod logger {
    use super::*;

    #[cfg(feature = "tokio-console")]
    pub const DEFAULT_TOKIO_CONSOLE_ADDR: SocketAddr = socket_addr!(127.0.0.1:5555);
}

pub mod network {
    use super::*;

    pub const DEFAULT_TRANSACTION_GOSSIP_PERIOD: Duration = Duration::from_secs(1);

    pub const DEFAULT_BLOCK_GOSSIP_PERIOD: Duration = Duration::from_secs(10);

    pub const DEFAULT_MAX_TRANSACTIONS_PER_GOSSIP: NonZeroU32 = nonzero!(500u32);
    pub const DEFAULT_MAX_BLOCKS_PER_GOSSIP: NonZeroU32 = nonzero!(4u32);
}

pub mod snapshot {
    use super::*;

    pub const DEFAULT_SNAPSHOT_PATH: &str = "./storage";
    // Default frequency of making snapshots is 1 minute, need to be adjusted for larger world state view size
    pub const DEFAULT_SNAPSHOT_CREATE_EVERY_MS: Duration = Duration::from_secs(60);
    pub const DEFAULT_ENABLED: bool = true;
}

pub mod chain_wide {
    use super::*;

    pub const DEFAULT_MAX_TXS: NonZeroU32 = nonzero!(2_u32.pow(9));
    pub const DEFAULT_BLOCK_TIME: Duration = Duration::from_secs(2);
    pub const DEFAULT_COMMIT_TIME_LIMIT: Duration = Duration::from_secs(4);
    pub const DEFAULT_WASM_FUEL_LIMIT: u64 = 30_000_000;
    pub const DEFAULT_WASM_MAX_MEMORY: u32 = 500 * 2_u32.pow(20);

    /// Default estimation of consensus duration.
    pub const DEFAULT_CONSENSUS_ESTIMATION: Duration =
        match DEFAULT_BLOCK_TIME.checked_add(match DEFAULT_COMMIT_TIME_LIMIT.checked_div(2) {
            Some(x) => x,
            None => unreachable!(),
        }) {
            Some(x) => x,
            None => unreachable!(),
        };

    /// Default limits for metadata
    pub const DEFAULT_METADATA_LIMITS: MetadataLimits =
        MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
    /// Default limits for ident length
    pub const DEFAULT_IDENT_LENGTH_LIMITS: LengthLimits = LengthLimits::new(1, 2_u32.pow(7));
    /// Default maximum number of instructions and expressions per transaction
    pub const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
    /// Default maximum number of instructions and expressions per transaction
    pub const DEFAULT_MAX_WASM_SIZE_BYTES: u64 = 4 * 2_u64.pow(20);

    /// Default transaction limits
    pub const DEFAULT_TRANSACTION_LIMITS: TransactionLimits =
        TransactionLimits::new(DEFAULT_MAX_INSTRUCTION_NUMBER, DEFAULT_MAX_WASM_SIZE_BYTES);
}

pub mod torii {
    use std::time::Duration;

    pub const DEFAULT_MAX_CONTENT_LENGTH: u32 = 2_u32.pow(20) * 16;
    pub const DEFAULT_QUERY_IDLE_TIME: Duration = Duration::from_secs(30);
}

pub mod telemetry {
    use std::time::Duration;

    /// Default minimal retry period
    pub const DEFAULT_MIN_RETRY_PERIOD: Duration = Duration::from_secs(1);
    /// Default maximum exponent for the retry delay
    pub const DEFAULT_MAX_RETRY_DELAY_EXPONENT: u8 = 4;
}
