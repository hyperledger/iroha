//! This module contains persistence related Iroha logic.
//! `Kura` is the main entity which should be used to store new `Block`s on the blockchain.

use std::{
    fs,
    path::{Path, PathBuf},
};

use async_std::{
    fs::{metadata, File},
    prelude::*,
};
use iroha_error::{Result, WrapErr};
use iroha_version::scale::{DecodeVersioned, EncodeVersioned};
use serde::{Deserialize, Serialize};

use crate::{block::VersionedCommittedBlock, merkle::MerkleTree, prelude::*};

/// High level data storage representation.
/// Provides all necessary methods to read and write data, hides implementation details.
#[derive(Debug)]
pub struct Kura {
    mode: Mode,
    block_store: BlockStore,
    block_sender: CommittedBlockSender,
    merkle_tree: MerkleTree,
}

#[allow(dead_code)]
impl Kura {
    /// Default `Kura` constructor.
    /// Kura will not be ready to work with before `init` method invocation.
    pub fn new(
        mode: Mode,
        block_store_path: &Path,
        block_sender: CommittedBlockSender,
    ) -> Result<Self> {
        Ok(Kura {
            mode,
            block_store: BlockStore::new(block_store_path)?,
            block_sender,
            merkle_tree: MerkleTree::new(),
        })
    }

    pub fn from_configuration(
        configuration: &config::KuraConfiguration,
        block_sender: CommittedBlockSender,
    ) -> Result<Self> {
        Kura::new(
            configuration.kura_init_mode,
            Path::new(&configuration.kura_block_store_path),
            block_sender,
        )
    }

    /// After constructing `Kura` it should be initialized to be ready to work with it.
    pub async fn init(&mut self) -> Result<Vec<VersionedCommittedBlock>> {
        let blocks = self.block_store.read_all().await;
        self.merkle_tree = MerkleTree::build(blocks.iter().map(VersionedCommittedBlock::hash));
        Ok(blocks)
    }

    /// Methods consumes new validated block and atomically stores and caches it.
    #[iroha_logger::log]
    pub async fn store(&mut self, block: VersionedCommittedBlock) -> Result<Hash> {
        match self.block_store.write(&block).await {
            Ok(hash) => {
                //TODO: shouldn't we add block hash to merkle tree here?
                self.block_sender.send(block).await;
                Ok(hash)
            }
            Err(error) => {
                let blocks = self.block_store.read_all().await;
                self.merkle_tree =
                    MerkleTree::build(blocks.iter().map(VersionedCommittedBlock::hash));
                Err(error)
            }
        }
    }
}

/// Kura work mode.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Strict validation of all blocks.
    Strict,
    /// Fast initialization with basic checks.
    Fast,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Strict
    }
}

/// Representation of a consistent storage.
#[derive(Debug)]
struct BlockStore {
    path: PathBuf,
}

impl BlockStore {
    fn new(path: &Path) -> Result<BlockStore> {
        if fs::read_dir(path).is_err() {
            fs::create_dir_all(path).wrap_err("Failed to create Block Store directory.")?;
        }
        Ok(BlockStore {
            path: path.to_path_buf(),
        })
    }

    fn get_block_filename(block_height: u64) -> String {
        format!("{}", block_height)
    }

    fn get_block_path(&self, block_height: u64) -> PathBuf {
        self.path.join(BlockStore::get_block_filename(block_height))
    }

    async fn write(&self, block: &VersionedCommittedBlock) -> Result<Hash> {
        //filename is its height
        let path = self.get_block_path(block.header().height);
        let mut file = File::create(path)
            .await
            .wrap_err("Failed to open storage file.")?;
        let hash = block.hash();
        let serialized_block: Vec<u8> = block.encode_versioned()?;
        file.write_all(&serialized_block)
            .await
            .wrap_err("Failed to write to storage file.")?;
        Ok(hash)
    }

    async fn read(&self, height: u64) -> Result<VersionedCommittedBlock> {
        let path = self.get_block_path(height);
        let mut file = File::open(&path).await.wrap_err("No file found.")?;
        let metadata = metadata(&path).await.wrap_err("Unable to read metadata.")?;
        #[allow(clippy::cast_possible_truncation)]
        let mut buffer = vec![0; metadata.len() as usize];
        let _ = file.read(&mut buffer).await.wrap_err("Buffer overflow.")?;
        VersionedCommittedBlock::decode_versioned(&buffer)
            .wrap_err("Failed to read block from store.")
    }

    /// Returns a sorted vector of blocks starting from 0 height to the top block.
    async fn read_all(&self) -> Vec<VersionedCommittedBlock> {
        let mut height = 1;
        let mut blocks = Vec::new();
        while let Ok(block) = self.read(height).await {
            blocks.push(block);
            height += 1;
        }
        blocks
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use std::path::Path;

    use iroha_config::derive::Configurable;
    use iroha_error::{error, Result};
    use serde::{Deserialize, Serialize};

    use super::Mode;

    const DEFAULT_KURA_BLOCK_STORE_PATH: &str = "./blocks";

    #[derive(Clone, Deserialize, Serialize, Debug, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct KuraConfiguration {
        /// Possible modes: `strict`, `fast`.
        #[serde(default)]
        pub kura_init_mode: Mode,
        /// Path to the existing block store folder or path to create new folder.
        #[serde(default = "default_kura_block_store_path")]
        pub kura_block_store_path: String,
    }

    impl Default for KuraConfiguration {
        fn default() -> Self {
            Self {
                kura_init_mode: Mode::default(),
                kura_block_store_path: default_kura_block_store_path(),
            }
        }
    }

    impl KuraConfiguration {
        /// Set `kura_block_store_path` configuration parameter - will overwrite the existing one.
        ///
        /// # Errors
        /// If path is not valid this method will fail.
        pub fn kura_block_store_path(&mut self, path: &Path) -> Result<()> {
            self.kura_block_store_path = path
                .to_str()
                .ok_or_else(|| error!("Failed to yield slice from path"))?
                .to_owned();
            Ok(())
        }
    }

    fn default_kura_block_store_path() -> String {
        DEFAULT_KURA_BLOCK_STORE_PATH.to_owned()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation, clippy::restriction)]

    use async_std::sync;
    use iroha_crypto::KeyPair;
    use iroha_data_model::prelude::*;
    use tempfile::TempDir;

    use super::*;

    #[async_std::test]
    async fn strict_init_kura() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir.");
        let (tx, _rx) = sync::channel(100);
        assert!(Kura::new(Mode::Strict, temp_dir.path(), tx)
            .unwrap()
            .init()
            .await
            .is_ok());
    }

    #[async_std::test]
    async fn write_block_to_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(&WorldStateView::new(World::new()), &AllowAll.into())
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        assert!(BlockStore::new(dir.path())
            .unwrap()
            .write(&block)
            .await
            .is_ok());
    }

    #[async_std::test]
    async fn read_block_from_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(&WorldStateView::new(World::new()), &AllowAll.into())
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        let block_store = BlockStore::new(dir.path()).unwrap();
        let _ = block_store
            .write(&block)
            .await
            .expect("Failed to write block to file.");
        assert!(block_store.read(1).await.is_ok())
    }

    #[async_std::test]
    async fn read_all_blocks_from_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(dir.path()).unwrap();
        let n = 10;
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let mut block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(&WorldStateView::new(World::new()), &AllowAll.into())
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        for height in 1..=n {
            let hash = block_store
                .write(&block)
                .await
                .expect("Failed to write block to file.");
            block = PendingBlock::new(Vec::new())
                .chain(height, hash, 0, Vec::new())
                .validate(&WorldStateView::new(World::new()), &AllowAll.into())
                .sign(&keypair)
                .expect("Failed to sign blocks.")
                .commit();
        }
        let blocks = block_store.read_all().await;
        assert_eq!(blocks.len(), n as usize)
    }

    ///Kura takes as input blocks, which comprise multiple transactions. Kura is meant to take only
    ///blocks as input that have passed stateless and stateful validation, and have been finalized
    ///by consensus. For finalized blocks, Kura simply commits the block to the block storage on
    ///the block_store and updates atomically the in-memory hashmaps that make up the key-value store that
    ///is the world-state-view. To optimize networking syncing, which works on 100 block chunks,
    ///chunks of 100 blocks each are stored in files in the block store.
    #[async_std::test]
    async fn store_block() {
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(&WorldStateView::new(World::new()), &AllowAll.into())
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = sync::channel(100);
        let mut kura = Kura::new(Mode::Strict, dir.path(), tx).unwrap();
        drop(kura.init().await.expect("Failed to init Kura."));
        let _ = kura
            .store(block)
            .await
            .expect("Failed to store block into Kura.");
    }
}
