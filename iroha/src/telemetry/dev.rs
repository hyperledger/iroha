//! Module with development telemetry

use std::{fs::OpenOptions, path::PathBuf};

use async_std::{
    stream::StreamExt,
    sync::Receiver,
    task::{self, JoinHandle},
};
use iroha_error::{Result, WrapErr};
use iroha_logger::telemetry::Telemetry;
use iroha_telemetry::futures;
use lz4::EncoderBuilder;

pub fn start(
    telemetry_file: Option<&PathBuf>,
    telemetry: Receiver<Telemetry>,
) -> Result<JoinHandle<()>> {
    let mut telemetry = futures::get_stream(telemetry);

    let telemetry_file = if let Some(telemetry_file) = &telemetry_file {
        telemetry_file
    } else {
        return Ok(task::spawn(telemetry.for_each(drop)));
    };

    let file = OpenOptions::new()
        .write(true)
        // Fails to write full item at exit. that is why not append
        // TODO: think of workaround with dropcheck?
        //
        //.append(true)
        .create(true)
        .truncate(true)
        .open(telemetry_file)
        .wrap_err("Failed to create and open file for telemetry")?;
    let mut writer = EncoderBuilder::new()
        .auto_flush(true)
        .build(file)
        .wrap_err("Failed to create lz4 encoder")?;

    // Serde doesn't support async Read Write traits.
    // So let synchonous synchronous code be here.
    //
    // TODO: After migration to tokio move to https://docs.rs/tokio-serde
    let join_handle = task::spawn_blocking(move || {
        while let Some(telemetry) = task::block_on(telemetry.next()) {
            if let Err(error) = serde_json::to_writer(&mut writer, &telemetry) {
                iroha_logger::error!(%error, "Failed to write telemetry to file");
            }
        }
    });

    Ok(join_handle)
}
