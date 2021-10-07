//! This module contains persistence related Iroha logic.
//! [`Kura`] is the main entity which should be used to store new [`Block`](`crate::block::VersionedCommittedBlock`)s on the blockchain.

use std::{
    collections::BTreeSet,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use futures::{Stream, StreamExt, TryStreamExt};
use iroha_actor::{broker::*, prelude::*};
use iroha_version::scale::{DecodeVersioned, EncodeVersioned};
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
};
use tokio_stream::wrappers::ReadDirStream;

use crate::{
    block::VersionedCommittedBlock,
    block_sync::ContinueSync,
    merkle::MerkleTree,
    prelude::*,
    sumeragi::{self, UpdateNetworkTopology},
    wsv::WorldTrait,
};

/// Message for storing committed block
#[derive(Clone, Debug, Message)]
pub struct StoreBlock(pub VersionedCommittedBlock);

/// High level data storage representation.
/// Provides all necessary methods to read and write data, hides implementation details.
#[derive(Debug)]
pub struct Kura<W: WorldTrait> {
    mode: Mode,
    block_store: BlockStore,
    merkle_tree: MerkleTree,
    wsv: Arc<WorldStateView<W>>,
    broker: Broker,
}

/// Generic kura trait for mocks
#[async_trait]
pub trait KuraTrait: Actor + Handler<StoreBlock> {
    /// World for applying blocks which have been stored on disk
    type World: WorldTrait;

    /// Default [`Kura`] constructor.
    /// Kura will not be ready to work with before `init()` method invocation.
    /// # Errors
    /// Fails if reading from disk while initing fails
    async fn new(
        mode: Mode,
        block_store_path: &Path,
        blocks_per_file: NonZeroU64,
        wsv: Arc<WorldStateView<Self::World>>,
        broker: Broker,
    ) -> Result<Self>;

    /// Loads kura from configuration
    /// # Errors
    /// Fails if call to new fails
    async fn from_configuration(
        configuration: &config::KuraConfiguration,
        wsv: Arc<WorldStateView<Self::World>>,
        broker: Broker,
    ) -> Result<Self> {
        Self::new(
            configuration.init_mode,
            Path::new(&configuration.block_store_path),
            configuration.blocks_per_storage_file,
            wsv,
            broker,
        )
        .await
    }
}

#[async_trait]
impl<W: WorldTrait> KuraTrait for Kura<W> {
    type World = W;

    async fn new(
        mode: Mode,
        block_store_path: &Path,
        blocks_per_file: NonZeroU64,
        wsv: Arc<WorldStateView<W>>,
        broker: Broker,
    ) -> Result<Self> {
        Ok(Self {
            mode,
            block_store: BlockStore::new(block_store_path, blocks_per_file).await?,
            merkle_tree: MerkleTree::new(),
            wsv,
            broker,
        })
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait> Actor for Kura<W> {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<StoreBlock, _>(ctx);

        #[allow(clippy::panic)]
        match self.init().await {
            Ok(blocks) => {
                self.wsv.init(blocks).await;
                let latest_block_hash = self.wsv.latest_block_hash();
                let height = self.wsv.height();
                self.broker
                    .issue_send(sumeragi::Init {
                        latest_block_hash,
                        height,
                    })
                    .await;
            }
            Err(error) => {
                iroha_logger::error!(%error, "Initialization of kura failed");
                panic!("Init failed");
            }
        }
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait> Handler<StoreBlock> for Kura<W> {
    type Result = ();

    async fn handle(&mut self, StoreBlock(block): StoreBlock) -> Self::Result {
        if let Err(error) = self.store(block).await {
            iroha_logger::error!(%error, "Failed to write block")
        }
    }
}

impl<W: WorldTrait> Kura<W> {
    /// After constructing [`Kura`] it should be initialized to be ready to work with it.
    ///
    /// # Errors
    /// * May fail if file storage is either unavailable or data is invalid/corrupted
    ///
    #[iroha_futures::telemetry_future]
    pub async fn init(&mut self) -> Result<Vec<VersionedCommittedBlock>> {
        let blocks = self
            .block_store
            .read_all()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        self.merkle_tree = MerkleTree::build(blocks.iter().map(VersionedCommittedBlock::hash));
        Ok(blocks)
    }

    /// Methods consumes new validated block and atomically stores and caches it.
    #[iroha_futures::telemetry_future]
    #[iroha_logger::log("INFO", skip(self, block))]
    pub async fn store(&mut self, block: VersionedCommittedBlock) -> Result<Hash> {
        match self.block_store.write(&block).await {
            Ok(hash) => {
                //TODO: shouldn't we add block hash to merkle tree here?
                self.wsv.apply(block).await;
                self.broker.issue_send(UpdateNetworkTopology).await;
                self.broker.issue_send(ContinueSync).await;
                Ok(hash)
            }
            Err(error) => {
                let blocks = self
                    .block_store
                    .read_all()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?;
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
pub struct BlockStore {
    path: PathBuf,
    blocks_per_file: NonZeroU64,
}

type Result<T, E = Error> = std::result::Result<T, E>;
/// Error variants for persistent storage logic
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Generic IO error
    #[error("Failed reading/writing from disk")]
    IO(
        #[from]
        #[source]
        std::io::Error,
    ),
    /// Error (de)serializing block
    #[error("Failed to serialize/deserialize block")]
    Codec(
        #[from]
        #[source]
        iroha_version::error::Error,
    ),
    /// Zero-height block was provided
    #[error("An attempt to write zero-height block.")]
    ZeroBlock,
    /// Inconsequential blocks read
    #[error("Inconsequential block read. Unexpected height {0}")]
    InconsequentialBlockRead(u64),
    /// Inconsequential write
    #[error("Inconsequential block write.")]
    InconsequentialBlockWrite,
}

/// Maximum buffer for block deserialization (hardcoded 500Kb for now)
/// TODO: make it configurable
static BUFFER_SIZE_LIMIT: u64 = 512_000;

impl BlockStore {
    /// Initialize block storage at `path`.
    ///
    /// # Errors
    /// - Failed to create directory.
    pub async fn new(path: &Path, blocks_per_file: NonZeroU64) -> Result<BlockStore> {
        if fs::read_dir(path).await.is_err() {
            fs::create_dir_all(path).await?;
        }
        Ok(BlockStore {
            path: path.to_path_buf(),
            blocks_per_file,
        })
    }

    /// Returns expected filename of datafile containing block, provided its height
    async fn get_block_filename(
        dir: &Path,
        block_height: NonZeroU64,
        blocks_per_file: NonZeroU64,
    ) -> Result<String> {
        const INITIAL_DATA_FILE: &str = "1";
        let storage_indices = storage_files_base_indices(dir).await?;
        let max_base = match storage_indices.iter().last() {
            Some(max_base) => *max_base,
            None => return Ok(INITIAL_DATA_FILE.to_owned()),
        };
        if block_height <= max_base {
            return Err(Error::InconsequentialBlockWrite);
        }
        if (block_height.get() - max_base.get()) < blocks_per_file.get() {
            return Ok(max_base.to_string());
        }
        Ok(block_height.to_string())
    }

    /// Get filysystem path for the block at height.
    ///
    /// # Errors
    /// - Filesystem access failure (HW or permissions)
    ///
    pub async fn get_block_path(&self, block_height: NonZeroU64) -> Result<PathBuf> {
        let filename =
            BlockStore::get_block_filename(&self.path, block_height, self.blocks_per_file).await?;
        Ok(self.path.join(filename))
    }

    /// Append block to latest (or new) file on the disk.
    ///
    /// # Errors
    /// * Block with height 0 is considered invalid and will return error
    /// * Any FS errors or write errors (HW/insufficient permissions)
    ///
    #[iroha_futures::telemetry_future]
    pub async fn write(&self, block: &VersionedCommittedBlock) -> Result<Hash> {
        let height = NonZeroU64::new(block.header().height).ok_or(Error::ZeroBlock)?;
        let path = self.get_block_path(height).await?;
        let mut file = BufWriter::new(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?,
        );
        let hash = block.hash();
        let serialized_block: Vec<u8> = block.encode_versioned()?;
        let block_size = serialized_block.len() as u64;
        file.write_u64_le(block_size).await?;
        file.write_all(&serialized_block).await?;
        file.flush().await?;
        Ok(hash)
    }

    /// Fetch single block from a stream
    ///
    /// # Errors
    /// * Will fail if storage file contents is malformed (incorrect framing or encoding)
    ///
    async fn read_block(
        file_stream: &mut BufReader<fs::File>,
    ) -> Result<Option<VersionedCommittedBlock>> {
        if file_stream.fill_buf().await?.is_empty() {
            return Ok(None);
        }
        let len = file_stream.read_u64_le().await?;
        if len > BUFFER_SIZE_LIMIT {
            return Err(Error::IO(std::io::ErrorKind::OutOfMemory.into()));
        }
        #[allow(clippy::cast_possible_truncation)]
        let mut buffer: Vec<u8> = vec![0; len as usize];
        let _len = file_stream.read_exact(&mut buffer).await?;
        Ok(Some(VersionedCommittedBlock::decode_versioned(&buffer)?))
    }

    /// Converts raw file stream into stream of decoded blocks
    ///
    /// # Errors
    /// * Will propagate read errors if any
    ///
    fn read_file(
        mut file_stream: BufReader<fs::File>,
    ) -> impl Stream<Item = Result<VersionedCommittedBlock>> {
        async_stream::stream! {
            while let Some(block) = Self::read_block(&mut file_stream).await.transpose() {
                yield block;
            }
        }
    }

    /// Returns a stream of deserialized blocks that in order of reading from sorted storage files
    ///
    /// # Errors
    /// * Will propagate errors from any FS operations
    /// * Will provide error on non-sequential block (swapped, gap, not 1-based sequence)
    ///
    #[iroha_futures::telemetry_future]
    pub async fn read_all(
        &self,
    ) -> Result<impl Stream<Item = Result<VersionedCommittedBlock>> + 'static> {
        let base_indices = storage_files_base_indices(&self.path).await?;
        let dir_path = Arc::new(self.path.clone());
        let result = tokio_stream::iter(base_indices)
            .map(move |e| dir_path.join(e.to_string()))
            .then(fs::File::open)
            .map_ok(BufReader::new)
            .map_ok(Self::read_file)
            .try_flatten()
            .enumerate()
            .map(|(i, b)| b.map(|b| (i, b)))
            .and_then(|(i, b)| async move {
                if b.header().height == (i as u64) + 1 {
                    Ok(b)
                } else {
                    Err(Error::InconsequentialBlockRead(b.header().height))
                }
            });
        Ok(result)
    }
}

/// Returns sorted Vec of datafiles base heights as u64
///
/// # Errors
/// Will fail on filesystem access error
///
async fn storage_files_base_indices(path: &Path) -> Result<BTreeSet<NonZeroU64>> {
    let bases = ReadDirStream::new(fs::read_dir(path).await?)
        .filter_map(|e| async {
            e.ok()
                .and_then(|e| e.file_name().to_string_lossy().parse::<NonZeroU64>().ok())
        })
        .collect::<BTreeSet<_>>()
        .await;
    Ok(bases)
}

/// This module contains all configuration related logic.
pub mod config {
    use std::{num::NonZeroU64, path::Path};

    use eyre::{eyre, Result};
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    use super::Mode;

    const DEFAULT_BLOCKS_PER_STORAGE_FILE: u64 = 1000_u64;
    const DEFAULT_BLOCK_STORE_PATH: &str = "./blocks";

    /// Configuration of kura
    #[derive(Clone, Deserialize, Serialize, Debug, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "KURA_")]
    pub struct KuraConfiguration {
        /// Possible modes: `strict`, `fast`.
        #[serde(default)]
        pub init_mode: Mode,
        /// Path to the existing block store folder or path to create new folder.
        #[serde(default = "default_block_store_path")]
        pub block_store_path: String,
        /// Maximum number of blocks to write into single storage file
        #[serde(default = "default_blocks_per_storage_file")]
        pub blocks_per_storage_file: NonZeroU64,
    }

    impl Default for KuraConfiguration {
        fn default() -> Self {
            Self {
                init_mode: Mode::default(),
                block_store_path: default_block_store_path(),
                blocks_per_storage_file: default_blocks_per_storage_file(),
            }
        }
    }

    impl KuraConfiguration {
        /// Set `block_store_path` configuration parameter - will overwrite the existing one.
        ///
        /// # Errors
        /// If path is not valid this method will fail.
        pub fn block_store_path(&mut self, path: &Path) -> Result<()> {
            self.block_store_path = path
                .to_str()
                .ok_or_else(|| eyre!("Failed to yield slice from path"))?
                .to_owned();
            Ok(())
        }
    }

    fn default_block_store_path() -> String {
        DEFAULT_BLOCK_STORE_PATH.to_owned()
    }

    fn default_blocks_per_storage_file() -> NonZeroU64 {
        #![allow(clippy::expect_used)]
        NonZeroU64::new(DEFAULT_BLOCKS_PER_STORAGE_FILE).expect(
            "Default BLOCKS_PER_STORAGE value is set to non-positive value. This must not happen",
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation, clippy::restriction)]

    use iroha_actor::broker::Broker;
    use iroha_crypto::KeyPair;
    use tempfile::TempDir;

    use super::*;
    use crate::{sumeragi::view_change, wsv::World};

    const TEST_STORAGE_FILE_SIZE: u64 = 3_u64;

    #[tokio::test]
    async fn strict_init_kura() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir.");
        assert!(Kura::<World>::new(
            Mode::Strict,
            temp_dir.path(),
            NonZeroU64::new(TEST_STORAGE_FILE_SIZE).unwrap(),
            Arc::default(),
            Broker::new()
        )
        .await
        .unwrap()
        .init()
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn write_block_to_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(
                &WorldStateView::new(World::new()),
                &AllowAll.into(),
                &AllowAll.into(),
            )
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        assert!(BlockStore::new(
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap()
        )
        .await
        .unwrap()
        .write(&block)
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn read_all_blocks_from_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
        )
        .await
        .unwrap();
        let n = 10;
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let mut block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(
                &WorldStateView::new(World::new()),
                &AllowAll.into(),
                &AllowAll.into(),
            )
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        for height in 1_u64..=n {
            let hash = block_store
                .write(&block)
                .await
                .expect("Failed to write block to file.");
            block = PendingBlock::new(Vec::new())
                .chain(height, hash, view_change::ProofChain::empty(), Vec::new())
                .validate(
                    &WorldStateView::new(World::new()),
                    &AllowAll.into(),
                    &AllowAll.into(),
                )
                .sign(&keypair)
                .expect("Failed to sign blocks.")
                .commit();
        }
        let blocks = block_store
            .read_all()
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert_eq!(blocks.len(), n as usize)
    }

    ///Kura takes as input blocks, which comprise multiple transactions. Kura is meant to take only
    ///blocks as input that have passed stateless and stateful validation, and have been finalized
    ///by consensus. For finalized blocks, Kura simply commits the block to the block storage on
    ///the block_store and updates atomically the in-memory hashmaps that make up the key-value store that
    ///is the world-state-view. To optimize networking syncing, which works on 100 block chunks,
    ///chunks of 100 blocks each are stored in files in the block store.
    #[tokio::test]
    async fn store_block() {
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(
                &WorldStateView::new(World::new()),
                &AllowAll.into(),
                &AllowAll.into(),
            )
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        let dir = tempfile::tempdir().unwrap();
        let mut kura = Kura::<World>::new(
            Mode::Strict,
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
            Arc::default(),
            Broker::new(),
        )
        .await
        .unwrap();
        kura.init().await.expect("Failed to init Kura.");
        let _ = kura
            .store(block)
            .await
            .expect("Failed to store block into Kura.");
    }

    /// There is a risk that Kura will be requested to write blocks inconsequently
    /// There's currently no foolproof measures against it, but we have a case where it's obvious
    /// Namely, if a new block height is too far in the future, we can deduce it as an error.
    #[tokio::test]
    async fn write_inconseq_failure() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
        )
        .await
        .unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(
                &WorldStateView::new(World::new()),
                &AllowAll.into(),
                &AllowAll.into(),
            )
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        let hash = block_store
            .write(&block)
            .await
            .expect("Failed to write block to file.");
        let _gap_block = PendingBlock::new(Vec::new())
            .chain(
                tests::TEST_STORAGE_FILE_SIZE * 2,
                hash,
                view_change::ProofChain::empty(),
                Vec::new(),
            )
            .validate(
                &WorldStateView::new(World::new()),
                &AllowAll.into(),
                &AllowAll.into(),
            )
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();

        let write_failure = block_store.write(&block).await;
        matches!(write_failure, Err(Error::InconsequentialBlockWrite));
    }

    /// In contrast to write, we can detect inconsistency in blocks on read right away
    /// If blocks heights is something other than orderly line of 1-based progression,
    /// we'll get an InconsequentialBlockRead(n) error where n is misplaced block height
    /// It's an error that's most likely to get if some storage files were deleted.
    #[tokio::test]
    async fn read_inconseq_failure() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
        )
        .await
        .unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .validate(
                &WorldStateView::new(World::new()),
                &AllowAll.into(),
                &AllowAll.into(),
            )
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();
        let hash = block_store
            .write(&block)
            .await
            .expect("Failed to write block to file.");
        let _gap_block = PendingBlock::new(Vec::new())
            .chain(3_u64, hash, view_change::ProofChain::empty(), Vec::new())
            .validate(
                &WorldStateView::new(World::new()),
                &AllowAll.into(),
                &AllowAll.into(),
            )
            .sign(&keypair)
            .expect("Failed to sign blocks.")
            .commit();

        let expected_read_fail = block_store
            .read_all()
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await;
        matches!(
            expected_read_fail,
            Err(Error::InconsequentialBlockRead(3_u64))
        );
    }

    /// In case we've got gibberish instead of proper data in storage files,
    /// we'll get one of the two possible errors:
    /// * FraimingError, if file structure is invalid (basically, unexpected EOF)
    /// * CodecError, if data is impossible to parse back into VersionedComittedBlock
    /// Both indicating that file is malformed.
    #[tokio::test]
    async fn read_gibberish_failure() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
        )
        .await
        .unwrap();
        let written = fs::write(dir.path().join("1"), vec![1; 40]).await;
        assert!(matches!(written, Ok(_)));
        let expected_read_fail = block_store
            .read_all()
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await;
        let framing_err = matches!(expected_read_fail, Err(Error::IO(_)));
        let decode_err = matches!(expected_read_fail, Err(Error::Codec(_)));
        assert!(framing_err || decode_err);
    }
}
