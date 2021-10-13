//! Module with telemetry actor

#[cfg(feature = "dev-telemetry")]
use std::path::PathBuf;

#[cfg(feature = "dev-telemetry")]
pub mod dev;
// TBD: Should it have dev-telemetry?
pub mod ws;

use eyre::Result;
use iroha_config::derive::Configurable;
use iroha_logger::telemetry::Telemetry;
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc::Receiver, task::JoinHandle};
use url::Url;

#[cfg(feature = "dev-telemetry")]
#[derive(Clone, Default, Deserialize, Serialize, Debug, Configurable)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "TELEMETRY_")]
pub struct Configuration {
    #[config(serde_as_str)]
    pub name: Option<String>,
    #[config(serde_as_str)]
    pub url: Option<Url>,
    #[config(serde_as_str)]
    pub file: Option<PathBuf>,
}

#[cfg(not(feature = "dev-telemetry"))]
#[derive(Clone, Copy, Default, Deserialize, Serialize, Debug, Configurable)]
pub struct Configuration {}

/// Start telemetry actor
#[cfg(feature = "dev-telemetry")]
pub async fn start(
    config: &Configuration,
    telemetry: Receiver<Telemetry>,
    telemetry_future: Receiver<Telemetry>,
) -> Result<JoinHandle<()>> {
    let handle = dev::start(config.file.as_ref(), telemetry_future).await?;
    if let (Some(name), Some(url)) = (&config.name, &config.url) {
        tokio::task::spawn(ws::start(name.clone(), url.clone(), telemetry));
    }
    // TBD: What is the point of returning the handle if it's ignored?
    Ok(handle)
}

#[cfg(not(feature = "dev-telemetry"))]
#[allow(clippy::needless_pass_by_value, clippy::trivially_copy_pass_by_ref)]
/// Start telemetry actor
pub fn start(
    _config: &Configuration,
    _telemetry: Receiver<Telemetry>,
    _telemetry_future: Receiver<Telemetry>,
) -> Result<JoinHandle<()>> {
    use tokio::task::spawn;

    // Just a mock for easy joining
    Ok(spawn(async {}))
}
