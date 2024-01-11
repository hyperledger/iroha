//! `Torii` configuration as well as the default values for the URLs used for the main endpoints: `p2p`, `telemetry`, but not `api`.

use std::time::Duration;

use iroha_primitives::addr::{socket_addr, SocketAddr};
use merge::Merge;
use serde::{Deserialize, Serialize};

use crate::{
    ByteSize, Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvResult,
    ParseEnvResult, ReadEnv, UserDuration, UserField,
};

const DEFAULT_MAX_CONTENT_LENGTH: u64 = 2_u64.pow(20) * 16;
const DEFAULT_QUERY_IDLE_TIME: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct UserLayer {
    pub address: UserField<SocketAddr>,
    pub max_content_len: UserField<ByteSize>,
    pub query_idle_time: UserField<UserDuration>,
}

#[derive(Debug)]
pub struct Config {
    pub address: SocketAddr,
    pub max_content_len: ByteSize,
    pub query_idle_time: Duration,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            address: self
                .address
                .get()
                .ok_or_else(|| CompleteError::missing_field("torii.address"))?,
            max_content_len: self
                .max_content_len
                .get()
                .unwrap_or(ByteSize(DEFAULT_MAX_CONTENT_LENGTH)),
            query_idle_time: self
                .query_idle_time
                .map_or(DEFAULT_QUERY_IDLE_TIME, UserDuration::get),
        })
    }
}

impl FromEnv for UserLayer {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let address =
            ParseEnvResult::parse_simple(&mut emitter, env, "API_ADDRESS", "torii.address").into();

        emitter.finish()?;

        Ok(Self {
            address,
            ..Self::default()
        })
    }
}
