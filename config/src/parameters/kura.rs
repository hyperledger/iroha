//! Module for kura-related configuration and structs

use std::{fmt::Display, path::PathBuf, str::FromStr};

use iroha_config_base::{
    impl_deserialize_from_str, impl_serialize_display, Complete, CompleteResult, Emitter, FromEnv,
    FromEnvResult, Merge, ParseEnvResult, ReadEnv,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const DEFAULT_BLOCK_STORE_PATH: &str = "./storage";

/// `Kura` configuration.
#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct UserLayer {
    pub init_mode: Option<Mode>,
    pub block_store_path: Option<PathBuf>,
    pub debug: DebugUserConfig,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
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

impl_serialize_display!(Mode);
impl_deserialize_from_str!(Mode);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_mode_display_reprs() {
        assert_eq!(format!("{}", Mode::Strict), "strict");
        assert_eq!(format!("{}", Mode::Fast), "fast");
        assert_eq!("strict".parse::<Mode>().unwrap(), Mode::Strict);
        assert_eq!("fast".parse::<Mode>().unwrap(), Mode::Fast);
    }
}
