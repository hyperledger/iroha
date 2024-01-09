//! Module for telemetry-related configuration and structs.
use std::{
    num::{NonZeroU64, NonZeroU8},
    path::PathBuf,
    time::Duration,
};

use eyre::eyre;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    parameters::telemetry::retry_period::{
        DEFAULT_MAX_RETRY_DELAY_EXPONENT, DEFAULT_MIN_RETRY_PERIOD,
    },
    Complete, CompleteError, CompleteResult, FromEnv, FromEnvDefaultFallback, FromEnvResult,
    ReadEnv, UserDuration,
};

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    /// The node's name to be seen on the telemetry
    pub name: Option<String>,
    /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
    pub url: Option<Url>,
    /// The minimum period of time in seconds to wait before reconnecting
    pub min_retry_period: Option<UserDuration>,
    /// The maximum exponent of 2 that is used for increasing delay between reconnections
    pub max_retry_delay_exponent: Option<NonZeroU8>,
    /// Dev telemetry configuration
    #[serde(default)]
    pub dev: UserDevConfig,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct UserDevConfig {
    /// The filepath that to write dev-telemetry to
    pub file: Option<PathBuf>,
}

#[derive(Debug)]
pub struct Config {
    regular: Option<RegularTelemetryConfig>,
    dev: Option<DevTelemetryConfig>,
}

/// Complete configuration needed to start regular telemetry.
#[derive(Debug)]
pub struct RegularTelemetryConfig {
    #[allow(missing_docs)]
    pub name: String,
    #[allow(missing_docs)]
    pub url: Url,
    #[allow(missing_docs)]
    pub min_retry_period: Duration,
    #[allow(missing_docs)]
    pub max_retry_delay_exponent: NonZeroU8,
}

/// Complete configuration needed to start dev telemetry.
#[derive(Debug)]
pub struct DevTelemetryConfig {
    #[allow(missing_docs)]
    pub file: PathBuf,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        let Self {
            name,
            url,
            max_retry_delay_exponent,
            min_retry_period,
            dev: UserDevConfig { file },
        } = self;

        let regular = match (name, url) {
            (Some(name), Some(url)) => Some(RegularTelemetryConfig {
                name: name.clone(),
                url: url.clone(),
                max_retry_delay_exponent: max_retry_delay_exponent
                    .unwrap_or(DEFAULT_MAX_RETRY_DELAY_EXPONENT),
                min_retry_period: min_retry_period
                    .map(UserDuration::get)
                    .unwrap_or(DEFAULT_MIN_RETRY_PERIOD),
            }),
            (None, None) => None,
            // TODO improve error detail
            _ => Err(eyre!(
                "telemetry.name and telemetry.file should be set together"
            ))
            .map_err(CompleteError::Custom)?,
        };

        let dev = file
            .as_ref()
            .map(|file| DevTelemetryConfig { file: file.clone() });

        Ok(Config { regular, dev })
    }
}

impl FromEnvDefaultFallback for UserLayer {}

/// `RetryPeriod` configuration
pub mod retry_period {
    use std::{num::NonZeroU8, time::Duration};

    use nonzero_ext::nonzero;

    /// Default minimal retry period
    // FIXME: it was `1`. Was it secs of millisecs?
    pub const DEFAULT_MIN_RETRY_PERIOD: Duration = Duration::from_secs(1);
    /// Default maximum exponent for the retry delay
    pub const DEFAULT_MAX_RETRY_DELAY_EXPONENT: NonZeroU8 = nonzero!(4u8);
}
