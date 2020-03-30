use crate::{
    prelude::*,
    validation::{self, MerkleTree},
    wsv::WorldStateView,
};
use std::path::{Path, PathBuf};

/// High level data storage representation.
/// Provides all necessary methods to read and write data, hides implementation details.
pub struct Kura {
    block_store: BlockStore,
    world_state_view: WorldStateView,
    merkle_tree: MerkleTree,
}

impl Kura {
    /// Kura reads all transactions in all block keeping its order without any validation.
    /// Better to use only for operations with no expectations about correctnes.
    pub async fn fast_init() -> Self {
        let block_store = BlockStore::default();
        let blocks = block_store.read_all().await;
        let blocks_refs = blocks.iter().collect::<Vec<&Block>>();
        let world_state_view = WorldStateView::init(&blocks_refs).await;
        let merkle_tree = MerkleTree::build(&blocks_refs);
        Kura {
            block_store,
            world_state_view,
            merkle_tree,
        }
    }

    /// `Kura::fast_init` with transactions and blocks validation (signatures correctness and business rules).
    pub async fn strict_init() -> Result<Self, &'static str> {
        let kura = Kura::fast_init().await;
        validation::validate(kura.block_store.read_all().await)?;
        Ok(kura)
    }

    /// Methods consumes new validated block and atomically stores and caches it.
    pub async fn store(&mut self, block: &Block) -> Result<Hash, String> {
        use futures::join;
        let (block_store_result, _) = join!(
            self.block_store.write(&block),
            self.world_state_view.put(&block)
        );
        //TODO: replace with rebuild of a tree? self.merkle_tree.put(block.clone());
        match block_store_result {
            Ok(hash) => Ok(hash),
            Err(error) => {
                let blocks = self.block_store.read_all().await;
                let blocks_refs = blocks.iter().collect::<Vec<&Block>>();
                self.world_state_view = WorldStateView::init(&blocks_refs).await;
                self.merkle_tree = MerkleTree::build(&blocks_refs);
                Err(error)
            }
        }
    }

    pub fn get_world_state_view(&self) -> &WorldStateView {
        &self.world_state_view
    }
}

#[async_std::test]
async fn strict_init_kura() {
    assert!(Kura::strict_init().await.is_ok());
}

static DEFAULT_BLOCK_STORE_LOCATION: &str = "./blocks/";

/// Representation of a consistent storage.
struct BlockStore {
    block_store_location: PathBuf,
}

impl Default for BlockStore {
    fn default() -> Self {
        BlockStore::new(DEFAULT_BLOCK_STORE_LOCATION)
    }
}

impl BlockStore {
    fn new(block_store_location: &str) -> BlockStore {
        use std::fs;

        let path = Path::new(block_store_location);
        fs::create_dir_all(path).expect("Failed to create storage directory.");
        BlockStore {
            block_store_location: path.to_path_buf(),
        }
    }

    fn get_block_filename(block_height: u64) -> String {
        format!("{}", block_height)
    }

    fn get_block_path(&self, block_height: u64) -> PathBuf {
        self.block_store_location
            .join(BlockStore::get_block_filename(block_height))
    }

    async fn write(&self, block: &Block) -> Result<Hash, String> {
        use async_std::fs::File;
        use async_std::prelude::*;

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
        use async_std::fs::{metadata, File};
        use async_std::prelude::*;

        let path = self.get_block_path(height);
        let mut file = File::open(&path).await.map_err(|_| "No file found.")?;
        let metadata = metadata(&path)
            .await
            .map_err(|_| "Unable to read metadata.")?;
        let mut buffer = vec![0; metadata.len() as usize];
        file.read(&mut buffer)
            .await
            .map_err(|_| "Buffer overflow.")?;
        Ok(Block::from(buffer))
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

    #[async_std::test]
    async fn write_block_to_block_store() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let block = Block::builder(Vec::new()).build();
        assert!(BlockStore::new(dir.path().to_str().unwrap())
            .write(&block)
            .await
            .is_ok());
    }

    #[async_std::test]
    async fn read_block_from_block_store() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let block = Block::builder(Vec::new()).build();
        let block_store = BlockStore::new(dir.path().to_str().unwrap());
        block_store
            .write(&block)
            .await
            .expect("Failed to write block to file.");
        assert!(block_store.read(0).await.is_ok())
    }

    #[async_std::test]
    async fn read_all_blocks_from_block_store() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let block_store = BlockStore::new(dir.path().to_str().unwrap());
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

    /// Cleans up default directory of block_store storage.
    /// Should be used in tests that may potentially read from block_store
    /// to prevent failures due to changes in block structure.
    pub async fn cleanup_default_block_dir() -> Result<(), String> {
        use async_std::fs;

        fs::remove_dir_all(DEFAULT_BLOCK_STORE_LOCATION)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    ///Kura takes as input blocks, which comprise multiple transactions. Kura is meant to take only
    ///blocks as input that have passed stateless and stateful validation, and have been finalized
    ///by consensus. For finalized blocks, Kura simply commits the block to the block storage on
    ///the block_store and updates atomically the in-memory hashmaps that make up the key-value store that
    ///is the world-state-view. To optimize networking syncing, which works on 100 block chunks,
    ///chunks of 100 blocks each are stored in files in the block store.
    #[async_std::test]
    async fn store_block() {
        cleanup_default_block_dir()
            .await
            .expect("Failed to cleanup blocks dir.");
        let mut kura = Kura::fast_init().await;
        kura.store(&Block::builder(Vec::new()).build())
            .await
            .expect("Failed to store block into Kura.");
    }
}
