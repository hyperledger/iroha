//! Module for kura-related configuration and structs

use std::{path::PathBuf, str::FromStr};

use derive_more::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvResult, ParseEnvResult,
    ReadEnv,
};

const DEFAULT_BLOCK_STORE_PATH: &str = "./storage";

/// `Kura` configuration.
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    pub init_mode: Option<Mode>,
    pub block_store_path: Option<PathBuf>,
    pub debug: DebugUserConfig,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct DebugUserConfig {
    output_new_blocks: Option<bool>,
}

#[derive(Debug)]
pub struct Config {
    pub init_mode: Mode,
    pub block_store_path: PathBuf,
    pub debug_output_new_blocks: bool,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            init_mode: self.init_mode.unwrap_or_default(),
            block_store_path: self
                .block_store_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_BLOCK_STORE_PATH)),
            debug_output_new_blocks: self.debug.output_new_blocks.unwrap_or(false),
        })
    }
}

impl FromEnv for UserLayer {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let init_mode =
            ParseEnvResult::parse_simple(&mut emitter, env, "KURA_INIT_MODE", "kura.init_mode")
                .into();
        let block_store_path = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "KURA_BLOCK_STORE",
            "kura.block_store_path",
        )
        .into();
        let debug_output_new_blocks = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "KURA_DEBUG_OUTPUT_NEW_BLOCKS",
            "kura.debug.output_new_blocks",
        )
        .into();

        emitter.finish()?;

        Ok(Self {
            init_mode,
            block_store_path,
            debug: DebugUserConfig {
                output_new_blocks: debug_output_new_blocks,
            },
        })
    }
}

/// Kura initialization mode.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, parse_display::Display, parse_display::FromStr,
)]
#[display(style = "snake_case")]
pub enum Mode {
    /// Strict validation of all blocks.
    #[default]
    Strict,
    /// Fast initialization with basic checks.
    Fast,
}

impl Serialize for Mode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self)
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{from_value, json};

    use super::*;

    #[test]
    fn init_mode_display_reprs() {
        assert_eq!(format!("{}", Mode::Strict), "strict");
        assert_eq!(format!("{}", Mode::Fast), "fast");
        assert_eq!("strict".parse::<Mode>().unwrap(), Mode::Strict);
        assert_eq!("fast".parse::<Mode>().unwrap(), Mode::Fast);
    }

    #[test]
    fn init_mode_serde_uses_display() {
        let sample = [Mode::Strict, Mode::Fast];
        let json = json!(["strict", "fast"]);

        assert_eq!(serde_json::to_string(&sample).unwrap(), json.to_string());

        let encoded: [Mode; 2] = from_value(json).expect("should parse");
        assert_eq!(encoded, sample);
    }
}
