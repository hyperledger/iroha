use crate::{merkle::MerkleTree, prelude::*};
use async_std::{
    fs::{metadata, File},
    prelude::*,
};
use iroha_derive::log;
use std::{
    convert::TryFrom,
    fs,
    path::{Path, PathBuf},
};

/// High level data storage representation.
/// Provides all necessary methods to read and write data, hides implementation details.
#[derive(Debug)]
pub struct Kura {
    _mode: String,
    blocks: Vec<Block>,
    block_store: BlockStore,
    world_state_view_tx: BlockSender,
    merkle_tree: MerkleTree,
}

impl Kura {
    pub fn new(_mode: String, block_store_path: &Path, world_state_view_tx: BlockSender) -> Self {
        Kura {
            _mode,
            block_store: BlockStore::new(block_store_path),
            world_state_view_tx,
            merkle_tree: MerkleTree::new(),
            blocks: Vec::new(),
        }
    }

    pub async fn init(&mut self) -> Result<(), String> {
        let blocks = self.block_store.read_all().await;
        let blocks_refs = blocks.iter().collect::<Vec<&Block>>();
        self.merkle_tree.build(&blocks_refs);
        self.blocks = blocks;
        Ok(())
    }

    /// Methods consumes new validated block and atomically stores and caches it.
    #[log]
    pub async fn store(&mut self, mut block: Block) -> Result<Hash, String> {
        if !self.blocks.is_empty() {
            let last_block_index = self.blocks.len() - 1;
            block.height = last_block_index as u64 + 1;
            block.previous_block_hash = Some(self.blocks.as_mut_slice()[last_block_index].hash());
        }
        let block_store_result = self.block_store.write(&block).await;
        match block_store_result {
            Ok(hash) => {
                self.world_state_view_tx.send(block.clone()).await;
                self.blocks.push(block);
                Ok(hash)
            }
            Err(error) => {
                let blocks = self.block_store.read_all().await;
                let blocks_refs = blocks.iter().collect::<Vec<&Block>>();
                self.merkle_tree.build(&blocks_refs);
                Err(error)
            }
        }
    }
}

/// Representation of a consistent storage.
#[derive(Debug)]
struct BlockStore {
    path: PathBuf,
}

impl BlockStore {
    fn new(path: &Path) -> BlockStore {
        if fs::read_dir(path).is_err() {
            fs::create_dir_all(path).expect("Failed to create Block Store directory.");
        }
        BlockStore {
            path: path.to_path_buf(),
        }
    }

    fn get_block_filename(block_height: u64) -> String {
        format!("{}", block_height)
    }

    fn get_block_path(&self, block_height: u64) -> PathBuf {
        self.path.join(BlockStore::get_block_filename(block_height))
    }

    async fn write(&self, block: &Block) -> Result<Hash, String> {
        //filename is its height
        let path = self.get_block_path(block.height);
        match File::create(path).await {
            Ok(mut file) => {
                let hash = block.hash();
                let serialized_block: Vec<u8> = block.into();
                if let Err(error) = file.write_all(&serialized_block).await {
                    return Err(format!("Failed to write to storage file {}.", error));
                }
                Ok(hash)
            }
            Err(error) => Result::Err(format!("Failed to open storage file {}.", error)),
        }
    }

    async fn read(&self, height: u64) -> Result<Block, String> {
        let path = self.get_block_path(height);
        let mut file = File::open(&path).await.map_err(|_| "No file found.")?;
        let metadata = metadata(&path)
            .await
            .map_err(|_| "Unable to read metadata.")?;
        let mut buffer = vec![0; metadata.len() as usize];
        file.read(&mut buffer)
            .await
            .map_err(|_| "Buffer overflow.")?;
        Ok(Block::try_from(buffer).expect("Failed to read block from store."))
    }

    /// Returns a sorted vector of blocks starting from 0 height to the top block.
    async fn read_all(&self) -> Vec<Block> {
        let mut height = 0;
        let mut blocks = Vec::new();
        while let Ok(block) = self.read(height).await {
            blocks.push(block);
            height += 1;
        }
        blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::sync;
    use tempfile::TempDir;

    #[async_std::test]
    async fn strict_init_kura() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir.");
        let (tx, _rx) = sync::channel(100);
        assert!(Kura::new("strict".to_string(), temp_dir.path(), tx)
            .init()
            .await
            .is_ok());
    }

    #[async_std::test]
    async fn write_block_to_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let block = Block::builder(Vec::new()).build();
        assert!(BlockStore::new(dir.path()).write(&block).await.is_ok());
    }

    #[async_std::test]
    async fn read_block_from_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let block = Block::builder(Vec::new()).build();
        let block_store = BlockStore::new(dir.path());
        block_store
            .write(&block)
            .await
            .expect("Failed to write block to file.");
        assert!(block_store.read(0).await.is_ok())
    }

    #[async_std::test]
    async fn read_all_blocks_from_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(dir.path());
        let n = 10;
        for i in 0..n {
            block_store
                .write(&Block::builder(Vec::new()).height(i).build())
                .await
                .expect("Failed to write block to file.");
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
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = sync::channel(100);
        let mut kura = Kura::new("strict".to_string(), dir.path(), tx);
        kura.init().await.expect("Failed to init Kura.");
        kura.store(Block::builder(Vec::new()).build())
            .await
            .expect("Failed to store block into Kura.");
    }
}
