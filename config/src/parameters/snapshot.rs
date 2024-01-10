//! Module for `SnapshotMaker`-related configuration and structs.

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvResult, ParseEnvResult,
    ReadEnv, UserDuration,
};

const DEFAULT_SNAPSHOT_PATH: &str = "./storage";
// Default frequency of making snapshots is 1 minute, need to be adjusted for larger world state view size
const DEFAULT_SNAPSHOT_CREATE_EVERY_MS: Duration = Duration::from_secs(60);
const DEFAULT_ENABLED: bool = true;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    /// The period of time to wait between attempts to create new snapshot.
    pub create_every_ms: Option<UserDuration>,
    /// Path to the directory where snapshots should be stored
    pub store_path: Option<PathBuf>,
    /// Flag to enable or disable snapshot creation
    pub creation_enabled: Option<bool>,
}

#[derive(Debug)]
pub struct Config {
    pub create_every_ms: Duration,
    pub store_path: PathBuf,
    pub creation_enabled: bool,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            creation_enabled: self.creation_enabled.unwrap_or(DEFAULT_ENABLED),
            create_every_ms: self
                .create_every_ms
                .map_or(DEFAULT_SNAPSHOT_CREATE_EVERY_MS, UserDuration::get),
            store_path: self
                .store_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SNAPSHOT_PATH)),
        })
    }
}

impl FromEnv for UserLayer {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let store_path = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "SNAPSHOT_STORE",
            "snapshot.store_path",
        )
        .into();
        let creation_enabled = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "SNAPSHOT_CREATION_ENABLED",
            "snapshot.creation_enabled",
        )
        .into();

        emitter.finish()?;

        Ok(Self {
            store_path,
            creation_enabled,
            ..Self::default()
        })
    }
}
