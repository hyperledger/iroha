//! Module with development telemetry

use eyre::{Result, WrapErr};
use iroha_logger::telemetry::Telemetry;
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    sync::mpsc::Receiver,
    task::{self, JoinHandle},
};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

use crate::Configuration;

/// Starts telemetry writing to a file
/// # Errors
/// Fails if unable to open the file
pub async fn start(
    config: &Configuration,
    telemetry: Receiver<Telemetry>,
) -> Result<JoinHandle<()>> {
    let mut telemetry = crate::futures::get_stream(ReceiverStream::new(telemetry));

    let telemetry_file = if let Some(telemetry_file) = &config.file {
        telemetry_file
    } else {
        return Ok(task::spawn(async move {
            while telemetry.next().await.is_some() {}
        }));
    };

    let mut file = OpenOptions::new()
            .write(true)
            // Fails to write full item at exit. that is why not append
            // TODO: think of workaround with dropcheck?
            //
            //.append(true)
            .create(true)
            .truncate(true)
            .open(telemetry_file)
            .await
            .wrap_err("Failed to create and open file for telemetry")?;

    // Serde doesn't support async Read Write traits.
    // So let synchonous synchronous code be here.
    //
    // TODO: After migration to tokio move to https://docs.rs/tokio-serde
    let join_handle = task::spawn(async move {
        while let Some(item) = telemetry.next().await {
            let telemetry_json = match serde_json::to_string(&item) {
                Ok(json) => json,
                Err(error) => {
                    iroha_logger::error!(%error, "Failed to serialize telemetry to json");
                    continue;
                }
            };
            if let Err(error) = file.write_all(telemetry_json.as_bytes()).await {
                iroha_logger::error!(%error, "Failed to write telemetry to file");
            }
        }
    });

    Ok(join_handle)
}
