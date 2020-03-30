use std::{collections::HashMap, env, fs, path::Path};

const TORII_URL: &str = "TORII_URL";
const BLOCK_TIME_MS: &str = "BLOCK_TIME_MS";
const KURA_INIT_MODE: &str = "KURA_INIT_MODE";
const DEFAULT_TORII_URL: &str = "127.0.0.1:1337";
const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
const DEFAULT_KURA_INIT_MODE: &str = "strict";

/// Configuration parameters container.
pub struct Configuration {
    pub torii_url: String,
    pub block_build_step_ms: u64,
    /// Possible modes: `strict`, `fast`.
    pub mode: String,
}

impl Configuration {
    /// This method will build `Configuration` from a json *pretty* formatted file (without `:` in
    /// key names).
    /// # Panics
    /// This method will panic if configuration file presented, but has incorrect scheme or format.
    /// # Errors
    /// This method will return error if system will fail to find a file or read it's content.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Configuration, String> {
        let mut config_map: HashMap<String, String> = fs::read_to_string(path)
            .map_err(|error| format!("Failed to read configuration from path: {}.", error))?
            .lines()
            .filter(|line| line.contains(':'))
            .map(|line| line.split_at(line.find(':').unwrap()))
            .map(|(key, value)| (String::from(key), String::from(value)))
            .collect();
        Ok(ConfigurationBuilder {
            torii_url: env::var(TORII_URL)
                .ok()
                .or_else(|| config_map.remove(TORII_URL)),
            block_build_step_ms: env::var(BLOCK_TIME_MS)
                .ok()
                .or_else(|| config_map.remove(BLOCK_TIME_MS)),
            mode: env::var(KURA_INIT_MODE)
                .ok()
                .or_else(|| config_map.remove(KURA_INIT_MODE)),
        }
        .build())
    }
}

struct ConfigurationBuilder {
    torii_url: Option<String>,
    block_build_step_ms: Option<String>,
    mode: Option<String>,
}

impl ConfigurationBuilder {
    fn build(self) -> Configuration {
        Configuration {
            torii_url: self
                .torii_url
                .unwrap_or_else(|| DEFAULT_TORII_URL.to_string()),
            block_build_step_ms: self
                .block_build_step_ms
                .unwrap_or_else(|| DEFAULT_BLOCK_TIME_MS.to_string())
                .parse()
                .expect("Block build step should be a number."),
            mode: self
                .mode
                .unwrap_or_else(|| DEFAULT_KURA_INIT_MODE.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_example_json() {
        let configuration = Configuration::from_path("tests/example_config.json")
            .expect("Failed to read configuration from example config.");
        assert_eq!(DEFAULT_TORII_URL, configuration.torii_url);
        assert_eq!(DEFAULT_BLOCK_TIME_MS, configuration.block_build_step_ms);
    }
}
