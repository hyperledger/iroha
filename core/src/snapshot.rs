//! This module contains [`State`] snapshot actor service.
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use iroha_config::{parameters::actual::Snapshot as Config, snapshot::Mode};
use iroha_crypto::HashOf;
use iroha_data_model::block::SignedBlock;
use iroha_logger::prelude::*;
use serde::{de::DeserializeSeed, Serialize};
use tokio::sync::mpsc;

use crate::{
    kura::{BlockCount, Kura},
    query::store::LiveQueryStoreHandle,
    state::{deserialize::KuraSeed, State, StateReadOnly},
};

/// Name of the [`State`] snapshot file.
const SNAPSHOT_FILE_NAME: &str = "snapshot.data";
/// Name of the temporary [`State`] snapshot file.
const SNAPSHOT_TMP_FILE_NAME: &str = "snapshot.tmp";

// /// Errors produced by [`SnapshotMaker`] actor.
// pub type Result<T, E = Error> = core::result::Result<T, E>;

/// [`SnapshotMaker`] actor handle.
#[derive(Clone)]
pub struct SnapshotMakerHandle {
    /// Not used to actually send messages but to signal that there is no more handles to [`SnapshotMaker`]
    _message_sender: mpsc::Sender<()>,
}

/// Actor responsible for [`State`] snapshot reading and writing.
pub struct SnapshotMaker {
    state: Arc<State>,
    /// Frequency at which snapshot is made
    create_every: Duration,
    /// Path to the directory where snapshots are stored
    store_dir: PathBuf,
    /// Hash of the latest block stored in the state
    latest_block_hash: Option<HashOf<SignedBlock>>,
}

impl SnapshotMaker {
    /// Start [`Self`] actor.
    pub fn start(self) -> SnapshotMakerHandle {
        let (message_sender, message_receiver) = mpsc::channel(1);
        tokio::task::spawn(self.run(message_receiver));

        SnapshotMakerHandle {
            _message_sender: message_sender,
        }
    }

    /// [`Self`] task.
    async fn run(mut self, mut message_receiver: mpsc::Receiver<()>) {
        let mut snapshot_create_every = tokio::time::interval(self.create_every);
        // Don't try to create snapshot more frequently if previous take longer time
        snapshot_create_every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = snapshot_create_every.tick() => {
                    // Offload snapshot creation into blocking thread
                    self.create_snapshot().await;
                },
                _ = message_receiver.recv() => {
                    info!("All handler to SnapshotMaker are dropped. Saving latest snapshot and shutting down...");
                    self.create_snapshot().await;
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    }

    /// Invoke snapshot creation task
    async fn create_snapshot(&mut self) {
        let store_dir = self.store_dir.clone();
        let latest_block_hash;
        let at_height;
        {
            let state_view = self.state.view();
            latest_block_hash = state_view.latest_block_hash();
            at_height = state_view.height();
        }

        if latest_block_hash != self.latest_block_hash {
            let state = self.state.clone();
            let handle = tokio::task::spawn_blocking(move || -> Result<(), TryWriteError> {
                try_write_snapshot(&state, &store_dir)
            });

            match handle.await {
                Ok(Ok(())) => {
                    iroha_logger::info!(at_height, "Successfully created a snapshot of state");
                    self.latest_block_hash = latest_block_hash;
                }
                Ok(Err(error)) => {
                    iroha_logger::error!(%error, "Failed to create a snapshot of state");
                }
                Err(panic) => {
                    iroha_logger::error!(%panic, "Task panicked during creation of state snapshot");
                }
            }
        }
    }

    /// Create from [`Config`].
    ///
    /// Might return [`None`] if the configuration is not suitable for _making_ snapshots.
    pub fn from_config(config: &Config, state: Arc<State>) -> Option<Self> {
        if let Mode::ReadWrite = config.mode {
            let latest_block_hash = state.view().latest_block_hash();
            Some(Self {
                state,
                create_every: config.create_every,
                store_dir: config.store_dir.clone(),
                latest_block_hash,
            })
        } else {
            None
        }
    }
}

/// Try to deserialize [`State`] from a snapshot file.
///
/// # Errors
/// - IO errors
/// - Deserialization errors
pub fn try_read_snapshot(
    store_dir: impl AsRef<Path>,
    kura: &Arc<Kura>,
    query_handle: LiveQueryStoreHandle,
    BlockCount(block_count): BlockCount,
) -> Result<State, TryReadError> {
    let mut bytes = Vec::new();
    let path = store_dir.as_ref().join(SNAPSHOT_FILE_NAME);
    let mut file = match std::fs::OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(err) => {
            return if err.kind() == std::io::ErrorKind::NotFound {
                Err(TryReadError::NotFound)
            } else {
                Err(TryReadError::IO(err, path.clone()))
            }
        }
    };
    file.read_to_end(&mut bytes)
        .map_err(|err| TryReadError::IO(err, path.clone()))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let seed = KuraSeed {
        kura: Arc::clone(kura),
        query_handle,
    };
    let state = seed.deserialize(&mut deserializer)?;
    let state_view = state.view();
    let snapshot_height = state_view.block_hashes.len();
    if snapshot_height > block_count {
        return Err(TryReadError::MismatchedHeight {
            snapshot_height,
            kura_height: block_count,
        });
    }
    for height in 1..snapshot_height {
        let kura_block_hash = kura
            .get_block_hash(height as u64)
            .expect("Kura has height at least as large as state height");
        let snapshot_block_hash = state_view.block_hashes[height - 1];
        if kura_block_hash != snapshot_block_hash {
            return Err(TryReadError::MismatchedHash {
                height,
                snapshot_block_hash,
                kura_block_hash,
            });
        }
    }
    Ok(state)
}

/// Serialize and write snapshot to file,
/// overwriting any previously stored data.
///
/// # Errors
/// - IO errors
/// - Serialization errors
fn try_write_snapshot(state: &State, store_dir: impl AsRef<Path>) -> Result<(), TryWriteError> {
    std::fs::create_dir_all(store_dir.as_ref())
        .map_err(|err| TryWriteError::IO(err, store_dir.as_ref().to_path_buf()))?;
    let path_to_file = store_dir.as_ref().join(SNAPSHOT_FILE_NAME);
    let path_to_tmp_file = store_dir.as_ref().join(SNAPSHOT_TMP_FILE_NAME);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path_to_tmp_file)
        .map_err(|err| TryWriteError::IO(err, path_to_tmp_file.clone()))?;
    let mut serializer = serde_json::Serializer::new(file);
    state.serialize(&mut serializer)?;
    std::fs::rename(path_to_tmp_file, &path_to_file)
        .map_err(|err| TryWriteError::IO(err, path_to_file.clone()))?;
    Ok(())
}

/// Error variants for snapshot reading
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum TryReadError {
    /// The snapshot was not found
    NotFound,
    /// Failed reading/writing {1:?} from disk
    IO(#[source] std::io::Error, PathBuf),
    /// Error (de)serializing state snapshot
    Serialization(#[from] serde_json::Error),
    /// Snapshot is in a non-consistent state. Snapshot has greater height (`snapshot_height`) than kura block store (`kura_height`)
    MismatchedHeight {
        /// The amount of block hashes stored by snapshot
        snapshot_height: usize,
        /// The amount of blocks stored by [`Kura`]
        kura_height: usize,
    },
    /// Snapshot is in a non-consistent state. Hash of the block at height `height` is different between snapshot (`snapshot_block_hash`) and kura (`kura_block_hash`)
    MismatchedHash {
        /// Height at which block hashes differs between snapshot and [`Kura`]
        height: usize,
        /// Hash of the block stored in snapshot
        snapshot_block_hash: HashOf<SignedBlock>,
        /// Hash of the block stored in kura
        kura_block_hash: HashOf<SignedBlock>,
    },
}

/// Error variants for snapshot writing
#[derive(thiserror::Error, Debug, displaydoc::Display)]
enum TryWriteError {
    /// Failed reading/writing {1:?} from disk
    IO(#[source] std::io::Error, PathBuf),
    /// Error (de)serializing World State View snapshot
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use tempfile::tempdir;
    use tokio::test;

    use super::*;
    use crate::query::store::LiveQueryStore;

    fn state_factory() -> State {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        State::new(
            crate::queue::tests::world_with_test_domains(),
            kura,
            query_handle,
        )
    }

    #[test]
    async fn creates_all_dirs_while_writing_snapshots() {
        let tmp_root = tempdir().unwrap();
        let snapshot_store_dir = tmp_root.path().join("path/to/snapshot/dir");
        let state = state_factory();

        try_write_snapshot(&state, &snapshot_store_dir).unwrap();

        assert!(Path::exists(snapshot_store_dir.as_path()))
    }

    #[test]
    async fn can_read_snapshot_after_writing() {
        let tmp_root = tempdir().unwrap();
        let store_dir = tmp_root.path().join("snapshot");
        let state = state_factory();

        try_write_snapshot(&state, &store_dir).unwrap();
        let _wsv = try_read_snapshot(
            &store_dir,
            &Kura::blank_kura_for_testing(),
            LiveQueryStore::test().start(),
            BlockCount(usize::try_from(state.view().height()).unwrap()),
        )
        .unwrap();
    }

    #[test]
    async fn cannot_find_snapshot_on_read_is_not_found() {
        let tmp_root = tempdir().unwrap();
        let store_dir = tmp_root.path().join("snapshot");

        let Err(error) = try_read_snapshot(
            store_dir,
            &Kura::blank_kura_for_testing(),
            LiveQueryStore::test().start(),
            BlockCount(15),
        ) else {
            panic!("should not be ok")
        };

        assert!(matches!(error, TryReadError::NotFound));
    }

    #[test]
    async fn cannot_parse_snapshot_on_read_is_error() {
        let tmp_root = tempdir().unwrap();
        let store_dir = tmp_root.path().join("snapshot");
        std::fs::create_dir(&store_dir).unwrap();
        {
            let mut file = File::create(store_dir.join(SNAPSHOT_FILE_NAME)).unwrap();
            file.write_all(&[1, 4, 1, 2, 3, 4, 1, 4]).unwrap();
        }

        let Err(error) = try_read_snapshot(
            &store_dir,
            &Kura::blank_kura_for_testing(),
            LiveQueryStore::test().start(),
            BlockCount(15),
        ) else {
            panic!("should not be ok")
        };

        assert_eq!(format!("{error}"), "Error (de)serializing state snapshot");
    }

    // TODO: test block count comparison
}
