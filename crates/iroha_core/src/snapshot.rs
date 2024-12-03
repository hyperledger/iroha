//! This module contains [`State`] snapshot actor service.
use std::{
    io::Read,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use iroha_config::{parameters::actual::Snapshot as Config, snapshot::Mode};
use iroha_crypto::HashOf;
use iroha_data_model::block::BlockHeader;
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_logger::prelude::*;
use serde::{de::DeserializeSeed, Serialize};

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

/// Actor responsible for [`State`] snapshot reading and writing.
pub struct SnapshotMaker {
    state: Arc<State>,
    /// Frequency at which snapshot is made
    create_every: Duration,
    /// Path to the directory where snapshots are stored
    store_dir: PathBuf,
    /// Hash of the latest block stored in the state
    latest_block_hash: Option<HashOf<BlockHeader>>,
}

impl SnapshotMaker {
    /// Start the actor.
    pub fn start(self, shutdown_signal: ShutdownSignal) -> Child {
        Child::new(
            tokio::spawn(self.run(shutdown_signal)),
            OnShutdown::Wait(Duration::from_secs(2)),
        )
    }

    async fn run(mut self, shutdown_signal: ShutdownSignal) {
        let mut snapshot_create_every = tokio::time::interval(self.create_every);
        // Don't try to create snapshot more frequently if previous take longer time
        snapshot_create_every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = snapshot_create_every.tick() => {
                    // Offload snapshot creation into blocking thread
                    self.create_snapshot().await;
                },
                () = shutdown_signal.receive() => {
                    info!("Saving latest snapshot and shutting down");
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
                // TODO: enhance error by attaching `store_dir` parameter origin
                try_write_snapshot(&state, store_dir)
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
        if let Mode::ReadWrite = config.mode() {
            let latest_block_hash = state.view().latest_block_hash();
            Some(Self {
                state,
                create_every: *config.create_every(),
                store_dir: config.store_dir().resolve_relative_path(),
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
    live_query_store_lazy: impl FnOnce() -> LiveQueryStoreHandle,
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
        query_handle: live_query_store_lazy(),
    };
    let state = seed.deserialize(&mut deserializer)?;
    let state_view = state.view();
    let snapshot_height = state_view.height();
    if snapshot_height > block_count {
        return Err(TryReadError::MismatchedHeight {
            snapshot_height,
            kura_height: block_count,
        });
    }
    for height in 1..=snapshot_height {
        let kura_block = NonZeroUsize::new(height)
            .and_then(|height| kura.get_block(height))
            .expect("Kura has height at least as large as state height");
        let snapshot_block_hash = state_view.block_hashes[height - 1];
        if kura_block.hash() != snapshot_block_hash {
            // If last block hash is different it might mean that snapshot was crated for soft-fork block so just drop changes made by this block
            if height == snapshot_height {
                iroha_logger::warn!(
                    "Snapshot has incorrect latest block hash, discarding changes made by this block"
                );
                state.block_and_revert(kura_block.header()).commit();
            } else {
                return Err(TryReadError::MismatchedHash {
                    height,
                    snapshot_block_hash,
                    kura_block_hash: kura_block.hash(),
                });
            }
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
        snapshot_block_hash: HashOf<BlockHeader>,
        /// Hash of the block stored in kura
        kura_block_hash: HashOf<BlockHeader>,
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

    use iroha_crypto::KeyPair;
    use iroha_data_model::peer::PeerId;
    use tempfile::tempdir;
    use tokio::test;

    use super::*;
    use crate::{
        block::ValidBlock, query::store::LiveQueryStore, sumeragi::network_topology::Topology,
    };

    fn state_factory() -> State {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
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
            LiveQueryStore::start_test,
            BlockCount(state.view().height()),
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
            LiveQueryStore::start_test,
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
            LiveQueryStore::start_test,
            BlockCount(15),
        ) else {
            panic!("should not be ok")
        };

        assert_eq!(format!("{error}"), "Error (de)serializing state snapshot");
    }

    #[test]
    async fn can_read_multiple_blocks() {
        let tmp_root = tempdir().unwrap();
        let store_dir = tmp_root.path().join("snapshot");
        let kura = Kura::blank_kura_for_testing();
        let state = state_factory();

        let peer_key_pair = KeyPair::random();
        let peer_id = PeerId::new(peer_key_pair.public_key().clone());
        let topology = Topology::new(vec![peer_id]);
        let valid_block = ValidBlock::new_dummy(peer_key_pair.private_key());
        let committed_block = valid_block
            .clone()
            .commit(&topology)
            .unpack(|_| {})
            .unwrap();

        {
            let mut state_block = state.block(committed_block.as_ref().header());
            let _events =
                state_block.apply_without_execution(&committed_block, topology.as_ref().to_owned());
            state_block.commit();
        }
        kura.store_block(committed_block);

        let valid_block =
            ValidBlock::new_dummy_and_modify_header(peer_key_pair.private_key(), |header| {
                header.height = header.height.checked_add(1).unwrap();
            });
        let committed_block = valid_block
            .clone()
            .commit(&topology)
            .unpack(|_| {})
            .unwrap();

        {
            let mut state_block = state.block(committed_block.as_ref().header());
            let _events =
                state_block.apply_without_execution(&committed_block, topology.as_ref().to_owned());
            state_block.commit();
        }
        kura.store_block(committed_block);

        try_write_snapshot(&state, &store_dir).unwrap();

        let state = try_read_snapshot(
            &store_dir,
            &kura,
            LiveQueryStore::start_test,
            BlockCount(state.view().height()),
        )
        .unwrap();

        assert_eq!(state.view().height(), 2);
    }

    #[test]
    async fn can_read_last_block_incorrect() {
        let tmp_root = tempdir().unwrap();
        let store_dir = tmp_root.path().join("snapshot");
        let kura = Kura::blank_kura_for_testing();
        let state = state_factory();

        let peer_key_pair = KeyPair::random();
        let peer_id = PeerId::new(peer_key_pair.public_key().clone());
        let topology = Topology::new(vec![peer_id]);
        let valid_block = ValidBlock::new_dummy(peer_key_pair.private_key());
        let committed_block = valid_block
            .clone()
            .commit(&topology)
            .unpack(|_| {})
            .unwrap();

        {
            let mut state_block = state.block(committed_block.as_ref().header());
            let _events =
                state_block.apply_without_execution(&committed_block, topology.as_ref().to_owned());
            state_block.commit();
        }
        kura.store_block(committed_block);

        let valid_block =
            ValidBlock::new_dummy_and_modify_header(peer_key_pair.private_key(), |header| {
                header.height = header.height.checked_add(1).unwrap();
            });
        let committed_block = valid_block
            .clone()
            .commit(&topology)
            .unpack(|_| {})
            .unwrap();

        {
            let mut state_block = state.block(committed_block.as_ref().header());
            let _events =
                state_block.apply_without_execution(&committed_block, topology.as_ref().to_owned());
            state_block.commit();
        }

        // Store inside kura different block at the same height with different view change index so that block
        // This case imitate situation when snapshot was created for block which later is discarded as soft-fork
        let valid_block =
            ValidBlock::new_dummy_and_modify_header(peer_key_pair.private_key(), |header| {
                header.height = header.height.checked_add(1).unwrap();
                header.view_change_index += 1;
            });
        let committed_block = valid_block
            .clone()
            .commit(&topology)
            .unpack(|_| {})
            .unwrap();
        kura.store_block(committed_block);

        try_write_snapshot(&state, &store_dir).unwrap();

        let state = try_read_snapshot(
            &store_dir,
            &kura,
            LiveQueryStore::start_test,
            BlockCount(state.view().height()),
        )
        .unwrap();

        // Invalid block was discarded
        assert_eq!(state.view().height(), 1);
    }
}
