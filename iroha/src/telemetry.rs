//! Module with telemetry actor

#[cfg(feature = "dev-telemetry")]
use std::path::PathBuf;

#[cfg(feature = "dev-telemetry")]
pub mod dev;

use async_std::{sync::Receiver, task::JoinHandle};
use iroha_config::derive::Configurable;
use iroha_error::Result;
use iroha_logger::telemetry::Telemetry;
use serde::{Deserialize, Serialize};

#[cfg(feature = "dev-telemetry")]
#[derive(Clone, Default, Deserialize, Serialize, Debug, Configurable)]
pub struct Configuration {
    #[config(serde_as_str)]
    pub telemetry_file: Option<PathBuf>,
}

#[cfg(not(feature = "dev-telemetry"))]
#[derive(Clone, Copy, Default, Deserialize, Serialize, Debug, Configurable)]
pub struct Configuration {}

#[cfg(feature = "dev-telemetry")]
/// Start telemetry actor
pub fn start(config: &Configuration, telemetry: Receiver<Telemetry>) -> Result<JoinHandle<()>> {
    dev::start(config.telemetry_file.as_ref(), telemetry)
}

#[cfg(not(feature = "dev-telemetry"))]
#[allow(clippy::needless_pass_by_value, clippy::trivially_copy_pass_by_ref)]
/// Start telemetry actor
pub fn start(_config: &Configuration, _telemetry: Receiver<Telemetry>) -> Result<JoinHandle<()>> {
    use async_std::task::spawn;

    // Just a mock for easy joining
    Ok(spawn(async {}))
}
