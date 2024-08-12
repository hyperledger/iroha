//! Telemetry for development rather than production purposes

use std::path::PathBuf;

use eyre::{eyre, Result, WrapErr};
use iroha_futures::FuturePollTelemetry;
use iroha_logger::telemetry::Event as Telemetry;
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::broadcast::Receiver,
    task::{self, JoinHandle},
};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

/// Starts telemetry writing to a file. Will create all parent directories.
///
/// # Errors
/// Fails if unable to open the file
pub async fn start_file_output(
    path: PathBuf,
    telemetry: Receiver<Telemetry>,
) -> Result<JoinHandle<()>> {
    let mut stream = crate::futures::get_stream(BroadcastStream::new(telemetry).fuse());

    std::fs::create_dir_all(
        path.parent()
            .ok_or_else(|| eyre!("the dev telemetry output file should have a parent directory"))?,
    )
    .wrap_err_with(|| {
        eyre!(
            "failed to recursively create directories for the dev telemetry output file: {}",
            path.display()
        )
    })?;

    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(&path)
        .await
        .wrap_err_with(|| {
            eyre!(
                "failed to open the dev telemetry output file: {}",
                path.display()
            )
        })?;

    let join_handle = task::spawn(async move {
        while let Some(item) = stream.next().await {
            if let Err(error) = write_telemetry(&mut file, &item).await {
                iroha_logger::error!(%error, "failed to write telemetry")
            }
        }
    });

    Ok(join_handle)
}

async fn write_telemetry(file: &mut File, item: &FuturePollTelemetry) -> Result<()> {
    // Serde doesn't support async Read Write traits.
    // So let synchronous code be here.
    let mut json =
        serde_json::to_string(&item).wrap_err("failed to serialize telemetry to JSON")?;

    json.push('\n');
    file.write_all(json.as_bytes())
        .await
        .wrap_err("failed to write data to the file")?;
    Ok(())
}
