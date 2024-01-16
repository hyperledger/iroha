//! Module with development telemetry

use eyre::{Result, WrapErr};
use iroha_config::parameters::actual::DevTelemetryConfig;
use iroha_logger::telemetry::Event as Telemetry;
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    sync::broadcast::Receiver,
    task::{self, JoinHandle},
};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

/// Starts telemetry writing to a file
/// # Errors
/// Fails if unable to open the file
pub async fn start(
    DevTelemetryConfig {
        file: telemetry_file,
    }: DevTelemetryConfig,
    telemetry: Receiver<Telemetry>,
) -> Result<JoinHandle<()>> {
    let mut stream = crate::futures::get_stream(BroadcastStream::new(telemetry).fuse());

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
    // So let synchronous code be here.
    //
    // TODO: After migration to tokio move to https://docs.rs/tokio-serde
    let join_handle = task::spawn(async move {
        while let Some(item) = stream.next().await {
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
