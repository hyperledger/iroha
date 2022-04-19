//! This module contains persistence related Iroha logic.
//! [`Kura`] is the main entity which should be used to store new [`Block`](`crate::block::VersionedCommittedBlock`)s on the blockchain.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt::Debug,
    io,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use futures::{Stream, StreamExt, TryStreamExt};
use iroha_actor::{broker::*, prelude::*};
use iroha_crypto::{HashOf, MerkleTree};
use iroha_logger::prelude::*;
use iroha_version::scale::{DecodeVersioned, EncodeVersioned};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
};
use tokio_stream::wrappers::ReadDirStream;

use crate::{
    block::VersionedCommittedBlock, block_sync::ContinueSync, prelude::*, sumeragi, wsv::WorldTrait,
};

/// Message for storing committed block
#[derive(Clone, Debug, Message)]
pub struct StoreBlock(pub VersionedCommittedBlock);

/// Gets hash of some specific block by height
#[derive(Clone, Copy, Debug, Message)]
#[message(result = "Option<HashOf<VersionedCommittedBlock>>")]
pub struct GetBlockHash {
    /// The block's height
    pub height: usize,
}

/// High level data storage representation.
/// Provides all necessary methods to read and write data, hides implementation details.
#[derive(Debug)]
pub struct KuraWithIO<W: WorldTrait, IO> {
    // TODO: Kura doesn't have different initialisation modes!!!
    #[allow(dead_code)]
    mode: Mode,
    block_store: BlockStore<IO>,
    merkle_tree: MerkleTree<VersionedCommittedBlock>,
    wsv: Arc<WorldStateView<W>>,
    broker: Broker,
    mailbox: u32,
}

/// Production qualification of `KuraWithIO`
pub type Kura<W> = KuraWithIO<W, DefaultIO>;

/// Generic implementation for tests - accepting IO mocks
impl<W: WorldTrait, IO: DiskIO> KuraWithIO<W, IO> {
    /// ctor
    /// # Errors
    /// Will forward error from `BlockStore` construction
    pub async fn new_meta(
        mode: Mode,
        block_store_path: &Path,
        blocks_per_file: NonZeroU64,
        wsv: Arc<WorldStateView<W>>,
        broker: Broker,
        mailbox: u32,
        io: IO,
    ) -> Result<Self> {
        Ok(Self {
            mode,
            block_store: BlockStore::new(block_store_path, blocks_per_file, io.clone()).await?,
            merkle_tree: MerkleTree::new(),
            wsv,
            broker,
            mailbox,
        })
    }
}

/// Generic kura trait for mocks
#[async_trait]
pub trait KuraTrait:
    Actor
    + ContextHandler<StoreBlock, Result = ()>
    + ContextHandler<GetBlockHash, Result = Option<HashOf<VersionedCommittedBlock>>>
    + Debug
{
    /// World for applying blocks which have been stored on disk
    type World: WorldTrait;

    /// Construct [`Kura`].
    /// Kura will not be ready to work with before `init()` method invocation.
    /// # Errors
    /// Fails if reading from disk while initing fails
    async fn new(
        mode: Mode,
        block_store_path: &Path,
        blocks_per_file: NonZeroU64,
        wsv: Arc<WorldStateView<Self::World>>,
        broker: Broker,
        mailbox: u32,
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
            configuration.mailbox,
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
        mailbox: u32,
    ) -> Result<Self> {
        Self::new_meta(
            mode,
            block_store_path,
            blocks_per_file,
            wsv,
            broker,
            mailbox,
            DefaultIO,
        )
        .await
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait, IO: DiskIO> Actor for KuraWithIO<W, IO> {
    fn mailbox_capacity(&self) -> u32 {
        self.mailbox
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<StoreBlock, _>(ctx);

        #[allow(clippy::panic)]
        match self.init().await {
            Ok(blocks) => {
                #[cfg(feature = "telemetry")]
                if let Some(block) = blocks.first() {
                    iroha_logger::telemetry!(msg = iroha_telemetry::msg::SYSTEM_CONNECTED, genesis_hash = %block.hash());
                }
                self.wsv.init(blocks).await;
                let last_block = self.wsv.latest_block_hash();
                let height = self.wsv.height();
                self.broker
                    .issue_send(sumeragi::message::Init { last_block, height })
                    .await;
            }
            Err(error) => {
                error!(%error, "Initialization of kura failed");
                panic!("Kura initialization failed");
            }
        }
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait, IO: DiskIO> Handler<GetBlockHash> for KuraWithIO<W, IO> {
    type Result = Option<HashOf<VersionedCommittedBlock>>;
    async fn handle(&mut self, GetBlockHash { height }: GetBlockHash) -> Self::Result {
        if height == 0 {
            return None;
        }
        // Block height starts with 1
        self.merkle_tree.get_leaf(height - 1)
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait, IO: DiskIO> Handler<StoreBlock> for KuraWithIO<W, IO> {
    type Result = ();

    async fn handle(&mut self, StoreBlock(block): StoreBlock) {
        #[cfg(feature = "telemetry")]
        if block.header().height == 1 {
            iroha_logger::telemetry!(msg = iroha_telemetry::msg::SYSTEM_CONNECTED, genesis_hash = %block.hash());
        }
        if let Err(error) = self.store(block).await {
            error!(%error, "Failed to write block")
        }
    }
}

impl<W: WorldTrait, IO: DiskIO> KuraWithIO<W, IO> {
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
        self.merkle_tree = blocks
            .iter()
            .map(VersionedCommittedBlock::hash)
            .collect::<MerkleTree<_>>();
        Ok(blocks)
    }

    /// Methods consumes new validated block and atomically stores and caches it.
    #[iroha_futures::telemetry_future]
    #[log("INFO", skip(self, block))]
    pub async fn store(
        &mut self,
        block: VersionedCommittedBlock,
    ) -> Result<HashOf<VersionedCommittedBlock>> {
        match self.block_store.write(&block).await {
            Ok(block_hash) => {
                self.merkle_tree = self.merkle_tree.add(block_hash);
                self.broker.issue_send(ContinueSync).await;
                Ok(block_hash)
            }
            Err(error) => {
                let blocks = self
                    .block_store
                    .read_all()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?;
                self.merkle_tree = blocks
                    .iter()
                    .map(VersionedCommittedBlock::hash)
                    .collect::<MerkleTree<_>>();
                Err(error)
            }
        }
    }
}

/// Kura work mode.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
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
pub struct BlockStore<IO> {
    path: PathBuf,
    blocks_per_file: NonZeroU64,
    io: IO,
}

type Result<T, E = Error> = std::result::Result<T, E>;
/// Error variants for persistent storage logic
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Generic IO error
    #[error("Failed reading/writing from disk")]
    IO(#[from] std::io::Error),
    /// Error (de)serializing block
    #[error("Failed to serialize/deserialize block")]
    Codec(#[from] iroha_version::error::Error),
    /// Allocation error
    #[error("Failed to allocate buffer")]
    Alloc(#[from] std::collections::TryReserveError),
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

impl<IO: DiskIO> BlockStore<IO> {
    /// Initialize block storage at `path`.
    ///
    /// # Errors
    /// - Failed to create directory.
    pub async fn new(path: &Path, blocks_per_file: NonZeroU64, io: IO) -> Result<Self> {
        if fs::read_dir(path).await.is_err() {
            fs::create_dir_all(path).await?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            blocks_per_file,
            io,
        })
    }

    /// Returns expected filename of datafile containing block, provided its height
    async fn get_block_filename(&self, block_height: NonZeroU64) -> Result<String> {
        const INITIAL_DATA_FILE: &str = "1";
        let storage_indices = storage_files_base_indices(&self.path, &self.io).await?;
        let max_base = match storage_indices.iter().last() {
            Some(max_base) => *max_base,
            None => return Ok(INITIAL_DATA_FILE.to_owned()),
        };
        if block_height <= max_base {
            return Err(Error::InconsequentialBlockWrite);
        }
        if (block_height.get() - max_base.get()) < self.blocks_per_file.get() {
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
        let filename = self.get_block_filename(block_height).await?;
        Ok(self.path.join(filename))
    }

    /// Append block to latest (or new) file on the disk.
    ///
    /// # Errors
    /// * Block with height 0 is considered invalid and will return error
    /// * Any FS errors or write errors (HW/insufficient permissions)
    ///
    #[iroha_futures::telemetry_future]
    pub async fn write(
        &self,
        block: &VersionedCommittedBlock,
    ) -> Result<HashOf<VersionedCommittedBlock>> {
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
        let serialized_block: Vec<u8> = block.encode_versioned();
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
    /// * Most likely, buffer size will be wrong and lead to `TryReserveError`
    ///
    #[allow(clippy::future_not_send)]
    async fn read_block<R: AsyncBufReadExt + Unpin>(
        file_stream: &mut R,
    ) -> Result<Option<VersionedCommittedBlock>> {
        if file_stream.fill_buf().await?.is_empty() {
            return Ok(None);
        }
        let len = file_stream.read_u64_le().await?;
        let mut buffer = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        buffer.try_reserve(len as usize)?;
        #[allow(clippy::cast_possible_truncation)]
        buffer.resize(len as usize, 0);
        let _len = file_stream.read_exact(&mut buffer).await?;
        Ok(Some(VersionedCommittedBlock::decode_versioned(&buffer)?))
    }

    /// Converts raw file stream into stream of decoded blocks
    ///
    /// # Errors
    /// * Will propagate read errors if any
    ///
    fn read_file<R: AsyncBufReadExt + Unpin>(
        mut file_stream: R,
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
    pub async fn read_all(
        &self,
    ) -> Result<impl Stream<Item = Result<VersionedCommittedBlock>> + 'static> {
        let io = self.io.clone();
        let base_indices = storage_files_base_indices(&self.path, &self.io).await?;
        let dir_path = self.path.clone();
        let result = tokio_stream::iter(base_indices)
            .map(move |e| dir_path.join(e.to_string()))
            .then(move |e| {
                let io = io.clone();
                async move { io.open(e.into_os_string()).await }
            })
            .map_ok(BufReader::new)
            .map_ok(Self::read_file)
            .try_flatten()
            .enumerate()
            .map(|(i, b)| b.map(|bb| (i, bb)))
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
async fn storage_files_base_indices<IO: DiskIO>(
    path: &Path,
    io: &IO,
) -> Result<BTreeSet<NonZeroU64>> {
    let bases = io
        .read_dir(path.to_path_buf())
        .await?
        .filter_map(|item| async {
            item.ok()
                .and_then(|e| e.to_string_lossy().parse::<NonZeroU64>().ok())
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
    const DEFAULT_MAILBOX_SIZE: u32 = 100;

    /// Configuration of kura
    #[derive(Clone, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
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
        /// Default mailbox size
        #[serde(default = "default_mailbox_size")]
        pub mailbox: u32,
    }

    impl Default for KuraConfiguration {
        fn default() -> Self {
            Self {
                init_mode: Mode::default(),
                block_store_path: default_block_store_path(),
                blocks_per_storage_file: default_blocks_per_storage_file(),
                mailbox: default_mailbox_size(),
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

    const fn default_mailbox_size() -> u32 {
        DEFAULT_MAILBOX_SIZE
    }
}

/// A trait, describing filesystem IO for Kura
#[async_trait::async_trait]
pub trait DiskIO: Clone + Send + Sync + 'static {
    /// Stream of storage filenames
    type Dir: Stream<Item = io::Result<OsString>> + Send + 'static;
    /// File for IO operations
    type File: tokio::io::AsyncRead + Send + Unpin + 'static;
    /// Fetch data files names (basically, ls operation)
    async fn read_dir(&self, path: PathBuf) -> io::Result<Self::Dir>;
    /// Open file for IO
    async fn open(&self, path: OsString) -> io::Result<Self::File>;
}

/// Initial, default disk IO implementation
#[derive(Clone, Copy, Debug)]
pub struct DefaultIO;

/// Stream of storage filenames
#[pin_project]
pub struct ReadDirFileNames(#[pin] ReadDirStream);
impl Stream for ReadDirFileNames {
    type Item = io::Result<OsString>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.project();
        this.0.poll_next(cx).map_ok(|e| e.file_name())
    }
}

#[async_trait::async_trait]
impl DiskIO for DefaultIO {
    type Dir = ReadDirFileNames;
    type File = tokio::fs::File;

    async fn read_dir(&self, path: PathBuf) -> io::Result<Self::Dir> {
        Ok(ReadDirFileNames(ReadDirStream::new(
            fs::read_dir(path).await?,
        )))
    }
    async fn open(&self, path: OsString) -> io::Result<Self::File> {
        fs::File::open(path).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation, clippy::restriction)]

    use std::collections::BTreeMap;

    use iroha_actor::broker::Broker;
    use iroha_crypto::KeyPair;
    use iroha_data_model::transaction::TransactionLimits;
    use tempfile::TempDir;
    use tokio::io;

    use super::*;
    use crate::{sumeragi::view_change, tx::TransactionValidator, wsv::World};

    const TEST_STORAGE_FILE_SIZE: u64 = 3_u64;

    #[tokio::test]
    async fn strict_init_kura() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir.");
        assert!(Kura::<World>::new(
            Mode::Strict,
            temp_dir.path(),
            NonZeroU64::new(TEST_STORAGE_FILE_SIZE).unwrap(),
            Arc::default(),
            Broker::new(),
            100,
        )
        .await
        .unwrap()
        .init()
        .await
        .is_ok());
    }

    fn get_transaction_validator() -> TransactionValidator<World> {
        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };

        TransactionValidator::new(
            tx_limits,
            AllowAll::new(),
            AllowAll::new(),
            Arc::new(WorldStateView::new(World::new())),
        )
    }

    #[tokio::test]
    async fn write_block_to_block_store() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new(), Vec::new())
            .chain_first()
            .validate(&get_transaction_validator())
            .sign(keypair)
            .expect("Failed to sign blocks.")
            .commit();
        assert!(BlockStore::<DefaultIO>::new(
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
            DefaultIO
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
            DefaultIO,
        )
        .await
        .unwrap();
        let n = 10;
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let mut block = PendingBlock::new(Vec::new(), Vec::new())
            .chain_first()
            .validate(&get_transaction_validator())
            .sign(keypair.clone())
            .expect("Failed to sign blocks.")
            .commit();
        for height in 1_u64..=n {
            let hash = block_store
                .write(&block)
                .await
                .expect("Failed to write block to file.");
            block = PendingBlock::new(Vec::new(), Vec::new())
                .chain(height, hash, view_change::ProofChain::empty(), Vec::new())
                .validate(&get_transaction_validator())
                .sign(keypair.clone())
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
        let block = PendingBlock::new(Vec::new(), Vec::new())
            .chain_first()
            .validate(&get_transaction_validator())
            .sign(keypair)
            .expect("Failed to sign blocks.")
            .commit();
        let dir = tempfile::tempdir().unwrap();
        let mut kura = Kura::<World>::new(
            Mode::Strict,
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
            Arc::default(),
            Broker::new(),
            100,
        )
        .await
        .unwrap();
        kura.init().await.expect("Failed to init Kura.");
        kura.store(block)
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
            DefaultIO,
        )
        .await
        .unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new(), Vec::new())
            .chain_first()
            .validate(&get_transaction_validator())
            .sign(keypair.clone())
            .expect("Failed to sign blocks.")
            .commit();
        let hash = block_store
            .write(&block)
            .await
            .expect("Failed to write block to file.");
        let _gap_block = PendingBlock::new(Vec::new(), Vec::new())
            .chain(
                tests::TEST_STORAGE_FILE_SIZE * 2,
                hash,
                view_change::ProofChain::empty(),
                Vec::new(),
            )
            .validate(&get_transaction_validator())
            .sign(keypair)
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
            DefaultIO,
        )
        .await
        .unwrap();
        let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let block = PendingBlock::new(Vec::new(), Vec::new())
            .chain_first()
            .validate(&get_transaction_validator())
            .sign(keypair.clone())
            .expect("Failed to sign blocks.")
            .commit();
        let hash = block_store
            .write(&block)
            .await
            .expect("Failed to write block to file.");
        let _gap_block = PendingBlock::new(Vec::new(), Vec::new())
            .chain(3_u64, hash, view_change::ProofChain::empty(), Vec::new())
            .validate(&get_transaction_validator())
            .sign(keypair)
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
    /// * IO error, if file structure is invalid (basically, unexpected EOF)
    /// * Alloc error - allocation failure in try_reserve (buffer size is too large)
    /// * Codec error, if data is impossible to parse back into VersionedComittedBlock
    /// Both indicating that file is malformed.
    #[tokio::test]
    async fn read_gibberish_failure() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(
            dir.path(),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
            DefaultIO,
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
        let io_err = matches!(expected_read_fail, Err(Error::IO(_)));
        let decode_err = matches!(expected_read_fail, Err(Error::Codec(_)));
        let alloc_err = matches!(expected_read_fail, Err(Error::Alloc(_)));
        assert!(io_err || decode_err || alloc_err);
    }

    /// A test, injecting errors into disk IO operations
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn read_all_blocks_faulty_device() {
        #[pin_project]
        #[derive(Clone)]
        struct UnreliableFile {
            results: Arc<Vec<Result<Vec<u8>, io::ErrorKind>>>,
            cursor: usize,
        }

        impl UnreliableFile {
            pub async fn open(
                results: Arc<Vec<Result<Vec<u8>, io::ErrorKind>>>,
            ) -> io::Result<UnreliableFile> {
                Ok(UnreliableFile { results, cursor: 0 })
            }
        }

        impl io::AsyncRead for UnreliableFile {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                let cursor = self.cursor;
                let this = self.project();

                if cursor == this.results.len() {
                    return std::task::Poll::Ready(Ok(()));
                }

                match &this.results[cursor] {
                    Err(err) => {
                        *this.cursor += 1;
                        let err = Err(io::Error::new(*err, ""));
                        std::task::Poll::Ready(err)
                    }
                    Ok(data) => {
                        *this.cursor += 1;
                        let unfilled: &mut [u8] = buf.initialize_unfilled();
                        for (index, value) in data.iter().enumerate() {
                            unfilled[index] = *value;
                        }
                        buf.advance(data.len());
                        std::task::Poll::Ready(Ok(()))
                    }
                }
            }
        }

        type UnreliableFilesystem = BTreeMap<OsString, Arc<Vec<Result<Vec<u8>, io::ErrorKind>>>>;
        #[derive(Clone)]
        struct UnreliableIO {
            files: UnreliableFilesystem,
        }

        #[async_trait::async_trait]
        impl DiskIO for UnreliableIO {
            type Dir = futures::stream::Iter<std::vec::IntoIter<io::Result<OsString>>>;
            type File = UnreliableFile;

            async fn read_dir(&self, _path: PathBuf) -> io::Result<Self::Dir> {
                Ok(futures::stream::iter(
                    self.files
                        .keys()
                        .cloned()
                        .map(Ok)
                        .collect::<Vec<_>>()
                        .into_iter(),
                ))
            }

            async fn open(&self, path: OsString) -> io::Result<Self::File> {
                PathBuf::from(path)
                    .file_name()
                    .and_then(|e| self.files.get(e))
                    .map(Arc::clone)
                    .map(Self::File::open)
                    .unwrap()
                    .await
            }
        }

        let block_store = BlockStore::new(
            &PathBuf::from("dir/"),
            NonZeroU64::new(tests::TEST_STORAGE_FILE_SIZE).unwrap(),
            UnreliableIO {
                files: vec![(
                    "1".into(),
                    Arc::new(vec![
                        Ok(vec![122, 0, 0, 0, 0, 0, 0, 0]),
                        Err(io::ErrorKind::TimedOut),
                    ]),
                )]
                .into_iter()
                .collect(),
            },
        )
        .await
        .unwrap();

        let expected_read_fail = block_store
            .read_all()
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .expect_err("Should always fail");
        let err = if let Error::IO(io) = expected_read_fail {
            io
        } else {
            panic!("Discovered some other error: {:?}", expected_read_fail)
        };

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // TimedOut
        // NotSeekable
        // FileTooLarge
        // ResourceBusy
        // FilenameTooLong
        // Unsupported
        // UnexpectedEof
        // OutOfMemory
        // Other
        // Uncategorized
    }
}
