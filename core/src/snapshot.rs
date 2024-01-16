//! This module contains [`WorldStateView`] snapshot actor service.
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use iroha_config::parameters::actual::Snapshot as Config;
use iroha_crypto::HashOf;
use iroha_data_model::block::SignedBlock;
use iroha_logger::prelude::*;
use serde::{de::DeserializeSeed, Serialize};
use tokio::sync::mpsc;

use crate::{
    kura::{BlockCount, Kura},
    query::store::LiveQueryStoreHandle,
    sumeragi::SumeragiHandle,
    wsv::{KuraSeed, WorldStateView},
};

/// Name of the [`WorldStateView`] snapshot file.
const SNAPSHOT_FILE_NAME: &str = "snapshot.data";
/// Name of the temporary [`WorldStateView`] snapshot file.
const SNAPSHOT_TMP_FILE_NAME: &str = "snapshot.tmp";

/// Errors produced by [`SnapshotMaker`] actor.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// [`SnapshotMaker`] actor handle.
#[derive(Clone)]
pub struct SnapshotMakerHandle {
    /// Not used to actually send messages but to signal that there is no more handles to [`SnapshotMaker`]
    _message_sender: mpsc::Sender<()>,
}

/// Actor responsible for [`WorldStateView`] snapshot reading and writing.
pub struct SnapshotMaker {
    sumeragi: SumeragiHandle,
    /// Frequency at which snapshot is made
    snapshot_create_every: Duration,
    /// Path to the directory where snapshots are stored
    snapshot_dir: PathBuf,
    /// Flag to enable/disable snapshot creation
    snapshot_creation_enabled: bool,
    /// Flag to signal that new wsv is available for taking snapshot
    new_wsv_available: bool,
}

impl SnapshotMaker {
    /// Start [`Self`] actor.
    pub fn start(self) -> SnapshotMakerHandle {
        let (message_sender, message_receiver) = mpsc::channel(1);
        if self.snapshot_creation_enabled {
            tokio::task::spawn(self.run(message_receiver));
        } else {
            iroha_logger::info!("Snapshot creation is disabled");
        }
        SnapshotMakerHandle {
            _message_sender: message_sender,
        }
    }

    /// [`Self`] task.
    async fn run(mut self, mut message_receiver: mpsc::Receiver<()>) {
        let mut snapshot_create_every = tokio::time::interval(self.snapshot_create_every);
        // Don't try to create snapshot more frequently if previous take longer time
        snapshot_create_every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = snapshot_create_every.tick(), if self.new_wsv_available => {
                    // Offload snapshot creation into blocking thread
                    self.create_snapshot().await;
                },
                () = self.sumeragi.finalized_wsv_updated() => {
                    self.sumeragi.apply_finalized_wsv(|finalized_wsv| self.new_wsv_available = finalized_wsv.height() > 0);
                }
                _ = message_receiver.recv() => {
                    info!("All handler to SnapshotMaker are dropped. Saving latest snapshot and shutting down...");
                    if self.new_wsv_available {
                        self.create_snapshot().await;
                    }
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    }

    /// Invoke snapshot creation task
    async fn create_snapshot(&mut self) {
        let sumeragi = self.sumeragi.clone();
        let path_to_snapshot = self.snapshot_dir.clone();
        let handle = tokio::task::spawn_blocking(move || -> Result<u64> {
            sumeragi.apply_finalized_wsv(|wsv| {
                Self::try_write_snapshot(wsv, &path_to_snapshot)?;
                Ok(wsv.height())
            })
        });

        match handle.await {
            Ok(Ok(at_height)) => {
                iroha_logger::info!(at_height, "Snapshot for wsv was created successfully.");
                self.new_wsv_available = false;
            }
            Ok(Err(error)) => {
                iroha_logger::error!(%error, "Failed to create snapshot for wsv.");
            }
            Err(panic) => {
                iroha_logger::error!(%panic, "Task panicked during creation of wsv snapshot.");
            }
        }
    }

    /// Serialize and write snapshot to file,
    /// overwriting any previously stored data.
    ///
    /// # Errors
    /// - IO errors
    /// - Serialization errors
    fn try_write_snapshot(wsv: &WorldStateView, snapshot_dir: impl AsRef<Path>) -> Result<()> {
        let path_to_file = snapshot_dir.as_ref().join(SNAPSHOT_FILE_NAME);
        let path_to_tmp_file = snapshot_dir.as_ref().join(SNAPSHOT_TMP_FILE_NAME);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path_to_tmp_file)
            .map_err(|err| Error::IO(err, path_to_tmp_file.clone()))?;
        let mut serializer = serde_json::Serializer::new(file);
        wsv.serialize(&mut serializer)?;
        std::fs::rename(path_to_tmp_file, &path_to_file)
            .map_err(|err| Error::IO(err, path_to_file.clone()))?;
        Ok(())
    }

    /// Create [`Self`] from [`Configuration`]
    pub fn from_configuration(config: &Config, sumeragi: SumeragiHandle) -> Self {
        Self {
            sumeragi,
            snapshot_create_every: config.create_every,
            snapshot_dir: config.store_path.clone(),
            snapshot_creation_enabled: config.creation_enabled,
            new_wsv_available: false,
        }
    }
}

/// Try deserialize [`WorldStateView`] from snapshot file
///
/// # Errors
/// - IO errors
/// - Deserialization errors
pub fn try_read_snapshot(
    snapshot_dir: impl AsRef<Path>,
    kura: &Arc<Kura>,
    query_handle: LiveQueryStoreHandle,
    BlockCount(block_count): BlockCount,
) -> Result<WorldStateView> {
    let mut bytes = Vec::new();
    let path = snapshot_dir.as_ref().join(SNAPSHOT_FILE_NAME);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|err| Error::IO(err, path.clone()))?;
    file.read_to_end(&mut bytes)
        .map_err(|err| Error::IO(err, path.clone()))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let seed = KuraSeed {
        kura: Arc::clone(kura),
        query_handle,
    };
    let wsv = seed.deserialize(&mut deserializer)?;
    let snapshot_height = wsv.block_hashes.len();
    if snapshot_height > block_count {
        return Err(Error::MismatchedHeight {
            snapshot_height,
            kura_height: block_count,
        });
    }
    for height in 1..snapshot_height {
        let kura_block_hash = kura
            .get_block_hash(height as u64)
            .expect("Kura has height at least as large as wsv_height");
        let snapshot_block_hash = wsv.block_hashes[height - 1];
        if kura_block_hash != snapshot_block_hash {
            return Err(Error::MismatchedHash {
                height,
                snapshot_block_hash,
                kura_block_hash,
            });
        }
    }
    Ok(wsv)
}

/// Error variants for snapshot reading/writing logic
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum Error {
    /// Failed reading/writing {1:?} from disk
    IO(#[source] std::io::Error, PathBuf),
    /// Error (de)serializing [`WorldStateView`] snapshot
    Serialization(#[from] serde_json::Error),
    /// Snapshot is in a non-consistent state. Snapshot has greater height ({snapshot_height}) than kura block store ({kura_height})
    MismatchedHeight {
        /// Amount of block hashes stored by snapshot
        snapshot_height: usize,
        /// Amount of blocks stored by [`Kura`]
        kura_height: usize,
    },
    /// Snapshot is in a non-consistent state. Hash of the block at height {height} is different between snapshot ({snapshot_block_hash}) and kura ({kura_block_hash})
    MismatchedHash {
        /// Height at which block hashes differs between snapshot and [`Kura`]
        height: usize,
        /// Hash of the block stored in snapshot
        snapshot_block_hash: HashOf<SignedBlock>,
        /// Hash of the block stored in kura
        kura_block_hash: HashOf<SignedBlock>,
    },
}
