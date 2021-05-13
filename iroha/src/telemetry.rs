//! Module with telemetry actor

use std::{fs::OpenOptions, path::PathBuf};

use async_std::{
    stream::StreamExt,
    sync::Receiver,
    task::{self, JoinHandle},
};
use iroha_config::derive::Configurable;
use iroha_error::{Result, WrapErr};
use iroha_logger::telemetry::Telemetry;
use iroha_telemetry::futures;
use lz4::EncoderBuilder;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize, Debug, Configurable)]
pub struct Configuration {
    pub telemetry_file: Option<PathBuf>,
}

/// Start telemetry actor
pub fn start(
    config: &Configuration,
    telemetry: Receiver<Telemetry>,
) -> Result<Option<JoinHandle<()>>> {
    let telemetry_file = if let Some(telemetry_file) = &config.telemetry_file {
        telemetry_file
    } else {
        return Ok(None);
    };

    let file = OpenOptions::new()
        .write(true)
		// Fails to write full item at exit. that is why not append
		// TODO: think of workaround with dropcheck?
		//
        //.append(true)
        .create(true)
        .open(telemetry_file)
        .wrap_err("Failed to create and open file for telemetry")?;
    let mut file = EncoderBuilder::new()
        .build(file)
        .wrap_err("Failed to create lz4 encoder")?;
    let mut stream = futures::get_stream(telemetry);

    // Serde doesn't support async Read Write traits.
    // So let synchonous synchronous code be here.
    //
    // TODO: After migration to tokio move to https://docs.rs/tokio-serde
    let jh = task::spawn_blocking(move || {
        while let Some(telemetry) = task::block_on(stream.next()) {
            if let Err(error) = serde_json::to_writer(&mut file, &telemetry) {
                iroha_logger::error!(%error, "Error while writing telemetry to file");
            }
        }
    });

    Ok(Some(jh))
}
