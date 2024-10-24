//! Translates to warehouse. File-system and persistence-related
//! logic.  [`Kura`] is the main entity which should be used to store
//! new [`Block`](`crate::block::SignedBlock`)s on the
//! blockchain.
use std::{
    fmt::Debug,
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use iroha_config::{
    kura::InitMode,
    parameters::{actual::Kura as Config, defaults::kura::BLOCKS_IN_MEMORY},
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::block::{BlockHeader, SignedBlock};
use iroha_futures::supervisor::{spawn_os_thread_as_future, Child, OnShutdown, ShutdownSignal};
use iroha_logger::prelude::*;
use iroha_version::scale::{DecodeVersioned, EncodeVersioned};
use parity_scale_codec::DecodeAll;
use parking_lot::Mutex;

use crate::block::CommittedBlock;

const INDEX_FILE_NAME: &str = "blocks.index";
const DATA_FILE_NAME: &str = "blocks.data";
const HASHES_FILE_NAME: &str = "blocks.hashes";

const SIZE_OF_BLOCK_HASH: u64 = Hash::LENGTH as u64;

/// The interface of Kura subsystem
#[derive(Debug)]
pub struct Kura {
    /// The block storage
    block_store: Mutex<BlockStore>,
    /// The array of block hashes and a slot for an arc of the block. This is normally recovered from the index file.
    block_data: Mutex<BlockData>,
    /// Path to file for plain text blocks.
    block_plain_text_path: Option<PathBuf>,
    /// At most N last blocks will be stored in memory.
    /// Older blocks will be dropped from memory and loaded from the disk if they are needed.
    blocks_in_memory: NonZeroUsize,
    /// Amount of blocks loaded during initialization
    init_block_count: usize,
}

type BlockData = Vec<(HashOf<BlockHeader>, Option<Arc<SignedBlock>>)>;

impl Kura {
    /// Initialize Kura and start a thread that receives
    /// and stores new blocks.
    ///
    /// # Errors
    /// Fails if there are filesystem errors when trying
    /// to access the block store indicated by the provided
    /// path.
    pub fn new(config: &Config) -> Result<(Arc<Self>, BlockCount)> {
        let store_dir = config.store_dir.resolve_relative_path();
        let mut block_store = BlockStore::new(&store_dir);
        block_store.create_files_if_they_do_not_exist()?;

        let block_plain_text_path = config
            .debug_output_new_blocks
            .then(|| store_dir.join("blocks.json"));

        let block_data = Kura::init(&mut block_store, config.init_mode)?;
        let block_count = block_data.len();
        info!(mode=?config.init_mode, block_count, "Kura init complete");

        let kura = Arc::new(Self {
            block_store: Mutex::new(block_store),
            block_data: Mutex::new(block_data),
            block_plain_text_path,
            blocks_in_memory: config.blocks_in_memory,
            init_block_count: block_count,
        });

        Ok((kura, BlockCount(block_count)))
    }

    /// Create a kura instance that doesn't write to disk. Instead it serves as a handler
    /// for in-memory blocks only.
    pub fn blank_kura_for_testing() -> Arc<Kura> {
        Arc::new(Self {
            block_store: Mutex::new(BlockStore::new(PathBuf::new())),
            block_data: Mutex::new(Vec::new()),
            block_plain_text_path: None,
            blocks_in_memory: BLOCKS_IN_MEMORY,
            init_block_count: 0,
        })
    }

    /// Start the Kura thread
    pub fn start(kura: Arc<Self>, shutdown_signal: ShutdownSignal) -> Child {
        Child::new(
            tokio::task::spawn(spawn_os_thread_as_future(
                std::thread::Builder::new().name("kura".to_owned()),
                move || {
                    Self::kura_receive_blocks_loop(&kura, &shutdown_signal);
                },
            )),
            OnShutdown::Wait(Duration::from_secs(5)),
        )
    }

    /// Initialize [`Kura`] after its construction to be able to work with it.
    ///
    /// # Errors
    /// Fails if:
    /// - file storage is unavailable
    /// - data in file storage is invalid or corrupted
    #[iroha_logger::log(skip_all, name = "kura_init")]
    fn init(block_store: &mut BlockStore, mode: InitMode) -> Result<BlockData> {
        let block_index_count: usize = block_store
            .read_index_count()?
            .try_into()
            .expect("INTERNAL BUG: block index count exceeds usize::MAX");

        let block_hashes = match mode {
            InitMode::Fast => {
                Kura::init_fast_mode(block_store, block_index_count).or_else(|error| {
                    warn!(%error, "Hashes file is broken. Falling back to strict init mode.");
                    Kura::init_strict_mode(block_store, block_index_count)
                })
            }
            InitMode::Strict => Kura::init_strict_mode(block_store, block_index_count),
        }?;

        // The none value is set in order to indicate that the blocks exist on disk but are not yet loaded.
        let block_data = block_hashes.into_iter().map(|hash| (hash, None)).collect();
        Ok(block_data)
    }

    fn init_fast_mode(
        block_store: &BlockStore,
        block_index_count: usize,
    ) -> Result<Vec<HashOf<BlockHeader>>, Error> {
        let block_hashes_count = block_store
            .read_hashes_count()?
            .try_into()
            .expect("INTERNAL BUG: block hashes count exceeds usize::MAX");
        if block_hashes_count == block_index_count {
            block_store.read_block_hashes(0, block_hashes_count)
        } else {
            Err(Error::HashesFileHeightMismatch)
        }
    }

    fn init_strict_mode(
        block_store: &mut BlockStore,
        block_index_count: usize,
    ) -> Result<Vec<HashOf<BlockHeader>>, Error> {
        let mut block_hashes = Vec::with_capacity(block_index_count);

        let mut block_indices = vec![BlockIndex::default(); block_index_count];
        block_store.read_block_indices(0, &mut block_indices)?;

        let mut prev_block_hash = None;
        for block in block_indices {
            // This is re-allocated every iteration. This could cause a problem.
            let mut block_data_buffer = vec![0_u8; block.length.try_into()?];

            match block_store.read_block_data(block.start, &mut block_data_buffer) {
                Ok(()) => match SignedBlock::decode_all_versioned(&block_data_buffer) {
                    Ok(decoded_block) => {
                        if prev_block_hash != decoded_block.header().prev_block_hash {
                            error!(expected=?prev_block_hash, actual=?decoded_block.header().prev_block_hash,
                                "Block has wrong previous block hash. Not reading any blocks beyond this height."
                            );
                            break;
                        }
                        let decoded_block_hash = decoded_block.hash();
                        block_hashes.push(decoded_block_hash);
                        prev_block_hash = Some(decoded_block_hash);
                    }
                    Err(error) => {
                        error!(?error, "Encountered malformed block. Not reading any blocks beyond this height.");
                        break;
                    }
                },
                Err(error) => {
                    error!(?error, "Malformed block index or corrupted block data file. Not reading any blocks beyond this height.");
                    break;
                }
            }
        }

        block_store.overwrite_block_hashes(&block_hashes)?;

        Ok(block_hashes)
    }

    #[iroha_logger::log(skip_all)]
    fn kura_receive_blocks_loop(kura: &Kura, shutdown_signal: &ShutdownSignal) {
        let mut written_block_count = kura.init_block_count;
        let mut latest_written_block_hash = {
            let block_data = kura.block_data.lock();
            written_block_count
                .checked_sub(1)
                .map(|idx| block_data[idx].0)
        };

        let mut should_exit = false;
        loop {
            // If kura receive shutdown then close block channel and write remaining blocks to the storage
            if shutdown_signal.is_sent() {
                info!("Kura block thread is being shut down. Writing remaining blocks to store.");
                should_exit = true;
            }

            let mut block_data = kura.block_data.lock();

            let new_latest_written_block_hash = written_block_count
                .checked_sub(1)
                .map(|idx| block_data[idx].0);
            if new_latest_written_block_hash != latest_written_block_hash {
                written_block_count -= 1; // There has been a soft-fork and we need to rewrite the top block.
            }
            latest_written_block_hash = new_latest_written_block_hash;

            if written_block_count >= block_data.len() {
                if should_exit {
                    info!("Kura has written remaining blocks to disk and is shutting down.");
                    return;
                }

                written_block_count = block_data.len();
                drop(block_data);
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }

            // If we get here there are blocks to be written.
            let start_height = written_block_count;
            let mut blocks_to_be_written = Vec::new();
            while written_block_count < block_data.len() {
                let block_ref = block_data[written_block_count].1.as_ref().expect(
                    "INTERNAL BUG: The block to be written is None. Check store_block function.",
                );
                blocks_to_be_written.push(Arc::clone(block_ref));
                Self::drop_old_block(
                    &mut block_data,
                    written_block_count,
                    kura.blocks_in_memory.get(),
                );
                written_block_count += 1;
            }

            // We don't want to hold up other threads so we drop the lock on the block data.
            drop(block_data);

            if let Some(path) = kura.block_plain_text_path.as_ref() {
                let mut plain_text_file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .expect("INTERNAL BUG: Couldn't create file for plain text blocks.");

                for new_block in &blocks_to_be_written {
                    serde_json::to_writer_pretty(&mut plain_text_file, new_block.as_ref())
                        .expect("INTERNAL BUG: Failed to write to plain text file for blocks.");
                }
            }

            let mut block_store_guard = kura.block_store.lock();
            if let Err(error) = block_store_guard.write_index_count(start_height as u64) {
                error!(?error, "Failed to write index count");
                panic!("Kura has encountered a fatal IO error.");
            }

            for block in blocks_to_be_written {
                if let Err(error) = block_store_guard.append_block_to_chain(&block) {
                    error!(?error, "Failed to store block");
                    panic!("Kura has encountered a fatal IO error.");
                }
            }
        }
    }

    /// Get the hash of the block at the provided height.
    pub fn get_block_hash(&self, block_height: NonZeroUsize) -> Option<HashOf<BlockHeader>> {
        let hash_data_guard = self.block_data.lock();

        let block_height = block_height.get();
        if hash_data_guard.len() < block_height {
            return None;
        }

        let block_index = block_height - 1;
        Some(hash_data_guard[block_index].0)
    }

    /// Search through blocks for the height of the block with the given hash.
    pub fn get_block_height_by_hash(&self, hash: HashOf<BlockHeader>) -> Option<NonZeroUsize> {
        self.block_data
            .lock()
            .iter()
            .position(|(block_hash, _block_arc)| *block_hash == hash)
            .and_then(|idx| idx.checked_add(1))
            .and_then(NonZeroUsize::new)
    }

    /// Get a reference to block by height, loading it from disk if needed.
    pub fn get_block(&self, block_height: NonZeroUsize) -> Option<Arc<SignedBlock>> {
        let mut data_array_guard = self.block_data.lock();

        if data_array_guard.len() < block_height.get() {
            return None;
        }

        let block_index = block_height.get() - 1;
        if let Some(block_arc) = data_array_guard[block_index].1.as_ref() {
            return Some(Arc::clone(block_arc));
        };

        let block_store = self.block_store.lock();
        let BlockIndex { start, length } = block_store
            .read_block_index(block_index as u64)
            .expect("INTERNAL BUG: Failed to read block index from disk.");

        let mut block_buf = vec![
            0_u8;
            usize::try_from(length)
                .expect("INTERNAL BUG: index_len didn't fit in 32-bits")
        ];
        block_store
            .read_block_data(start, &mut block_buf)
            .expect("INTERNAL BUG: Failed to read block data.");
        let block = SignedBlock::decode_all_versioned(&block_buf)
            .expect("INTERNAL BUG: Failed to decode block");

        let block_arc = Arc::new(block);
        // Only last N blocks should be kept in memory
        if block_index + self.blocks_in_memory.get() >= data_array_guard.len() {
            data_array_guard[block_index].1 = Some(Arc::clone(&block_arc));
        }
        Some(block_arc)
    }

    /// Put a block in kura's in memory block store.
    pub fn store_block(&self, block: CommittedBlock) {
        let block = Arc::new(SignedBlock::from(block));
        self.block_data.lock().push((block.hash(), Some(block)));
    }

    /// Replace the block in `Kura`'s in memory block store.
    pub fn replace_top_block(&self, block: CommittedBlock) {
        let block = Arc::new(SignedBlock::from(block));
        let mut data = self.block_data.lock();
        data.pop();
        data.push((block.hash(), Some(block)));
    }

    // Drop old block to prevent unbounded memory usage.
    // It will be loaded from the disk if needed later.
    fn drop_old_block(
        block_data: &mut BlockData,
        written_block_count: usize,
        blocks_in_memory: usize,
    ) {
        // Keep last N blocks and genesis block.
        // (genesis block is used in metrics to get genesis timestamp)
        if written_block_count > blocks_in_memory {
            block_data[written_block_count - blocks_in_memory].1 = None;
        }
    }
}

/// Loaded block count
#[derive(Clone, Copy, Debug)]
pub struct BlockCount(pub usize);

/// An implementation of a block store for `Kura`
/// that uses `std::fs`, the default IO file in Rust.
#[derive(Debug)]
pub struct BlockStore {
    path_to_blockchain: PathBuf,
}

#[derive(Default, Debug, Clone, Copy)]
/// Lightweight wrapper for block indices in the block index file
pub struct BlockIndex {
    /// Start of block in bytes
    pub start: u64,
    /// Length of block section in bytes
    pub length: u64,
}

impl BlockStore {
    /// Create a new block store in `path`.
    pub fn new(store_path: impl AsRef<Path>) -> Self {
        Self {
            path_to_blockchain: store_path.as_ref().to_path_buf(),
        }
    }

    /// Read a series of block indices from the block index file and
    /// attempt to fill all of `dest_buffer`.
    ///
    /// # Errors
    /// IO Error.
    pub fn read_block_indices(
        &self,
        start_block_height: u64,
        dest_buffer: &mut [BlockIndex],
    ) -> Result<()> {
        let path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        let mut index_file = std::fs::OpenOptions::new()
            .read(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let start_location = start_block_height * (2 * std::mem::size_of::<u64>() as u64);
        let block_count = dest_buffer.len();

        if start_location + (2 * std::mem::size_of::<u64>() as u64) * block_count as u64
            > index_file.metadata().add_err_context(&path)?.len()
        {
            return Err(Error::OutOfBoundsBlockRead {
                start_block_height,
                block_count,
            });
        }
        index_file
            .seek(SeekFrom::Start(start_location))
            .add_err_context(&path)?;
        // (start, length), (start,length) ...
        for current_buffer in dest_buffer.iter_mut() {
            let mut buffer = [0; core::mem::size_of::<u64>()];

            *current_buffer = BlockIndex {
                start: {
                    index_file.read_exact(&mut buffer).add_err_context(&path)?;
                    u64::from_le_bytes(buffer)
                },
                length: {
                    index_file.read_exact(&mut buffer).add_err_context(&path)?;
                    u64::from_le_bytes(buffer)
                },
            };
        }

        Ok(())
    }

    /// Call `read_block_indices` with a buffer of one.
    ///
    /// # Errors
    /// IO Error.
    pub fn read_block_index(&self, block_height: u64) -> Result<BlockIndex> {
        let mut index = BlockIndex {
            start: 0,
            length: 0,
        };
        self.read_block_indices(block_height, std::slice::from_mut(&mut index))?;
        Ok(index)
    }

    /// Get the number of indices in the index file, which is
    /// calculated as the size of the index file in bytes divided by
    /// `2*size_of(u64)`.
    ///
    /// # Errors
    /// IO Error.
    ///
    /// The most common reason this function fails is
    /// that you did not call `create_files_if_they_do_not_exist`.
    ///
    /// Note that if there is an error, you can be quite sure all
    /// other read and write operations will also fail.
    #[allow(clippy::integer_division)]
    pub fn read_index_count(&self) -> Result<u64> {
        let path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        let index_file = std::fs::OpenOptions::new()
            .read(true)
            .open(path.clone())
            .add_err_context(&path)?;
        Ok(index_file.metadata().add_err_context(&path)?.len()
            / (2 * std::mem::size_of::<u64>() as u64))
        // Each entry is 16 bytes.
    }

    /// Read a series of block hashes from the block hashes file
    ///
    /// # Errors
    /// IO Error.
    pub fn read_block_hashes(
        &self,
        start_block_height: u64,
        block_count: usize,
    ) -> Result<Vec<HashOf<BlockHeader>>> {
        let path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        let mut hashes_file = std::fs::OpenOptions::new()
            .read(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let start_location = start_block_height * SIZE_OF_BLOCK_HASH;

        if start_location + (SIZE_OF_BLOCK_HASH) * block_count as u64
            > hashes_file.metadata().add_err_context(&path)?.len()
        {
            return Err(Error::OutOfBoundsBlockRead {
                start_block_height,
                block_count,
            });
        }
        hashes_file
            .seek(SeekFrom::Start(start_location))
            .add_err_context(&path)?;

        (0..block_count)
            .map(|_| {
                let mut buffer = [0; Hash::LENGTH];

                hashes_file
                    .read_exact(&mut buffer)
                    .add_err_context(&path)
                    .and_then(|()| HashOf::decode_all(&mut buffer.as_slice()).map_err(Error::Codec))
            })
            .collect()
    }

    /// Get the number of hashes in the hashes file, which is
    /// calculated as the size of the hashes file in bytes divided by
    /// `size_of(HashOf<BlockHeader>)`.
    ///
    /// # Errors
    /// IO Error.
    ///
    /// The most common reason this function fails is
    /// that you did not call `create_files_if_they_do_not_exist`.
    #[allow(clippy::integer_division)]
    pub fn read_hashes_count(&self) -> Result<u64> {
        let path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        let hashes_file = std::fs::OpenOptions::new()
            .read(true)
            .open(path.clone())
            .add_err_context(&path)?;
        Ok(hashes_file.metadata().add_err_context(&path)?.len() / SIZE_OF_BLOCK_HASH)
    }

    /// Read block data starting from the
    /// `start_location_in_data_file` in data file in order to fill
    /// `dest_buffer`.
    ///
    /// # Errors
    /// IO Error.
    pub fn read_block_data(
        &self,
        start_location_in_data_file: u64,
        dest_buffer: &mut [u8],
    ) -> Result<()> {
        let path = self.path_to_blockchain.join(DATA_FILE_NAME);
        let mut data_file = std::fs::OpenOptions::new()
            .read(true)
            .open(path.clone())
            .add_err_context(&path)?;
        data_file
            .seek(SeekFrom::Start(start_location_in_data_file))
            .add_err_context(&path)?;
        data_file.read_exact(dest_buffer).add_err_context(&path)?;

        Ok(())
    }

    /// Write the index of a single block at the specified `block_height`.
    /// If `block_height` is beyond the end of the index file, attempt to
    /// extend the index file.
    ///
    /// # Errors
    /// IO Error.
    pub fn write_block_index(&mut self, block_height: u64, start: u64, length: u64) -> Result<()> {
        let path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        let mut index_file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let start_location = block_height * (2 * std::mem::size_of::<u64>() as u64);
        if start_location + (2 * std::mem::size_of::<u64>() as u64)
            > index_file.metadata().add_err_context(&path)?.len()
        {
            index_file
                .set_len(start_location + (2 * std::mem::size_of::<u64>() as u64))
                .add_err_context(&path)?;
        }
        index_file
            .seek(SeekFrom::Start(start_location))
            .add_err_context(&path)?;
        // block0       | block1
        // start, length| start, length  ... et cetera.
        index_file
            .write_all(&start.to_le_bytes())
            .add_err_context(&path)?;
        index_file
            .write_all(&length.to_le_bytes())
            .add_err_context(&path)?;
        Ok(())
    }

    /// Change the size of the index file (the value returned by
    /// `read_index_count`).
    ///
    /// # Errors
    /// IO Error.
    ///
    /// The most common reason this function fails is
    /// that you did not call `create_files_if_they_do_not_exist`.
    ///
    /// Note that if there is an error, you can be quite sure all other
    /// read and write operations will also fail.
    pub fn write_index_count(&mut self, new_count: u64) -> Result<()> {
        let path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        let index_file = std::fs::OpenOptions::new()
            .write(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let new_byte_size = new_count * (2 * std::mem::size_of::<u64>() as u64);
        index_file.set_len(new_byte_size).add_err_context(&path)?;
        Ok(())
    }

    /// Write `block_data` into the data file starting at
    /// `start_location_in_data_file`. Extend the file if
    /// necessary.
    ///
    /// # Errors
    /// IO Error.
    pub fn write_block_data(
        &mut self,
        start_location_in_data_file: u64,
        block_data: &[u8],
    ) -> Result<()> {
        let path = self.path_to_blockchain.join(DATA_FILE_NAME);
        let mut data_file = std::fs::OpenOptions::new()
            .write(true)
            .open(path.clone())
            .add_err_context(&path)?;
        if start_location_in_data_file + block_data.len() as u64
            > data_file.metadata().add_err_context(&path)?.len()
        {
            data_file
                .set_len(start_location_in_data_file + block_data.len() as u64)
                .add_err_context(&path)?;
        }
        data_file
            .seek(SeekFrom::Start(start_location_in_data_file))
            .add_err_context(&path)?;
        data_file.write_all(block_data).add_err_context(&path)?;
        Ok(())
    }

    /// Write the hash of a single block at the specified `block_height`.
    /// If `block_height` is beyond the end of the index file, attempt to
    /// extend the index file.
    ///
    /// # Errors
    /// IO Error.
    pub fn write_block_hash(&mut self, block_height: u64, hash: HashOf<BlockHeader>) -> Result<()> {
        let path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        let mut hashes_file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let start_location = block_height * SIZE_OF_BLOCK_HASH;
        if start_location + SIZE_OF_BLOCK_HASH
            > hashes_file.metadata().add_err_context(&path)?.len()
        {
            hashes_file
                .set_len(start_location + SIZE_OF_BLOCK_HASH)
                .add_err_context(&path)?;
        }
        hashes_file
            .seek(SeekFrom::Start(start_location))
            .add_err_context(&path)?;
        hashes_file
            .write_all(hash.as_ref())
            .add_err_context(&path)?;
        Ok(())
    }

    /// Write the hashes to the hashes file overwriting any previous hashes.
    ///
    /// # Errors
    /// IO Error.
    pub fn overwrite_block_hashes(&mut self, hashes: &[HashOf<BlockHeader>]) -> Result<()> {
        let path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        let hashes_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let mut hashes_file = BufWriter::new(hashes_file);
        for hash in hashes {
            hashes_file
                .write_all(hash.as_ref())
                .add_err_context(&path)?;
        }
        Ok(())
    }

    /// Create the index and data files if they do not
    /// already exist.
    ///
    /// # Errors
    /// Fails if any of the files don't exist and couldn't be
    /// created.
    pub fn create_files_if_they_do_not_exist(&mut self) -> Result<()> {
        std::fs::create_dir_all(&*self.path_to_blockchain)
            .map_err(|e| Error::MkDir(e, self.path_to_blockchain.clone()))?;
        let path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let path = self.path_to_blockchain.join(DATA_FILE_NAME);
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open(path.clone())
            .add_err_context(&path)?;
        let path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open(path.clone())
            .add_err_context(&path)?;
        Ok(())
    }

    /// Append `block_data` to this block store. First write
    /// the data to the data file and then create a new index
    /// for it in the index file.
    ///
    /// # Errors
    /// Fails if any of the required platform-specific functions
    /// fail.
    pub fn append_block_to_chain(&mut self, block: &SignedBlock) -> Result<()> {
        let bytes = block.encode_versioned();
        let new_block_height = self.read_index_count()?;
        let start_location_in_data_file = if new_block_height == 0 {
            0
        } else {
            let ultimate_block = self.read_block_index(new_block_height - 1)?;
            ultimate_block.start + ultimate_block.length
        };

        self.write_block_data(start_location_in_data_file, &bytes)?;
        self.write_block_index(
            new_block_height,
            start_location_in_data_file,
            bytes.len() as u64,
        )?;
        self.write_block_hash(new_block_height, block.hash())?;

        Ok(())
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;
/// Error variants for persistent storage logic
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum Error {
    /// Failed reading/writing {1:?} from disk
    IO(#[source] std::io::Error, PathBuf),
    /// Failed to create the directory {1:?}
    MkDir(#[source] std::io::Error, PathBuf),
    /// Failed to serialize/deserialize block
    Codec(#[from] parity_scale_codec::Error),
    /// Failed to allocate buffer
    Alloc(#[from] std::collections::TryReserveError),
    /// Tried reading block data out of bounds: `start_block_height`, `block_count`
    OutOfBoundsBlockRead {
        /// The block height from which the read was supposed to start
        start_block_height: u64,
        /// The actual block count
        block_count: usize,
    },
    /// Tried to lock block store by creating a lockfile at {0}, but it already exists
    Locked(PathBuf),
    /// Conversion of wide integer into narrow integer failed. This error cannot be caught at compile time at present
    IntConversion(#[from] std::num::TryFromIntError),
    /// Blocks count differs hashes file and index file
    HashesFileHeightMismatch,
}

trait AddErrContextExt<T> {
    type Context;

    fn add_err_context(self, context: &Self::Context) -> Result<T, Error>;
}

impl<T> AddErrContextExt<T> for Result<T, std::io::Error> {
    type Context = PathBuf;

    fn add_err_context(self, path: &Self::Context) -> Result<T, Error> {
        self.map_err(|e| Error::IO(e, path.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, thread, time::Duration};

    use iroha_config::parameters::defaults::kura::BLOCKS_IN_MEMORY;
    use iroha_crypto::KeyPair;
    use iroha_data_model::{
        account::Account,
        domain::{Domain, DomainId},
        isi::Log,
        peer::PeerId,
        transaction::TransactionBuilder,
        ChainId, Level,
    };
    use iroha_genesis::GenesisBuilder;
    use iroha_test_samples::gen_account_in;
    use nonzero_ext::nonzero;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        block::{BlockBuilder, ValidBlock},
        query::store::LiveQueryStore,
        smartcontracts::Registrable,
        state::State,
        sumeragi::network_topology::Topology,
        StateReadOnly, World,
    };

    fn indices<const N: usize>(value: [(u64, u64); N]) -> [BlockIndex; N] {
        let mut ret = [BlockIndex {
            start: 0,
            length: 0,
        }; N];
        for idx in 0..value.len() {
            ret[idx] = value[idx].into();
        }
        ret
    }

    impl PartialEq for BlockIndex {
        fn eq(&self, other: &Self) -> bool {
            self.start == other.start && self.length == other.length
        }
    }

    impl PartialEq<(u64, u64)> for BlockIndex {
        fn eq(&self, other: &(u64, u64)) -> bool {
            self.start == other.0 && self.length == other.1
        }
    }

    impl From<(u64, u64)> for BlockIndex {
        fn from(value: (u64, u64)) -> Self {
            Self {
                start: value.0,
                length: value.1,
            }
        }
    }

    #[test]
    fn read_and_write_to_blockchain_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path());
        block_store.create_files_if_they_do_not_exist().unwrap();

        block_store.write_block_index(0, 5, 7).unwrap();
        assert_eq!(block_store.read_block_index(0).unwrap(), (5, 7));

        block_store.write_block_index(0, 2, 9).unwrap();
        assert_ne!(block_store.read_block_index(0).unwrap(), (5, 7));

        block_store.write_block_index(3, 1, 2).unwrap();
        block_store.write_block_index(2, 6, 3).unwrap();

        assert_eq!(block_store.read_block_index(0).unwrap(), (2, 9));
        assert_eq!(block_store.read_block_index(2).unwrap(), (6, 3));
        assert_eq!(block_store.read_block_index(3).unwrap(), (1, 2));

        // or equivilant
        {
            let should_be = indices([(2, 9), (0, 0), (6, 3), (1, 2)]);
            let mut is = indices([(0, 0), (0, 0), (0, 0), (0, 0)]);

            block_store.read_block_indices(0, &mut is).unwrap();
            assert_eq!(should_be, is);
        }

        assert_eq!(block_store.read_index_count().unwrap(), 4);
        block_store.write_index_count(0).unwrap();
        assert_eq!(block_store.read_index_count().unwrap(), 0);
        block_store.write_index_count(12).unwrap();
        assert_eq!(block_store.read_index_count().unwrap(), 12);
    }

    #[test]
    fn read_and_write_to_blockchain_data_store() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path());
        block_store.create_files_if_they_do_not_exist().unwrap();

        block_store
            .write_block_data(43, b"This is some data!")
            .unwrap();

        let mut read_buffer = [0_u8; b"This is some data!".len()];
        block_store.read_block_data(43, &mut read_buffer).unwrap();

        assert_eq!(b"This is some data!", &read_buffer);
    }

    #[test]
    fn fresh_block_store_has_zero_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path());
        block_store.create_files_if_they_do_not_exist().unwrap();

        assert_eq!(0, block_store.read_index_count().unwrap());
    }

    #[test]
    fn append_block_to_chain_increases_block_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path());
        block_store.create_files_if_they_do_not_exist().unwrap();

        let dummy_block = ValidBlock::new_dummy(KeyPair::random().private_key()).into();

        let append_count = 35;
        for _ in 0..append_count {
            block_store.append_block_to_chain(&dummy_block).unwrap();
        }

        assert_eq!(append_count, block_store.read_index_count().unwrap());
    }

    #[test]
    fn append_block_to_chain_increases_hashes_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path());
        block_store.create_files_if_they_do_not_exist().unwrap();

        let dummy_block = ValidBlock::new_dummy(KeyPair::random().private_key()).into();

        let append_count = 35;
        for _ in 0..append_count {
            block_store.append_block_to_chain(&dummy_block).unwrap();
        }

        assert_eq!(append_count, block_store.read_hashes_count().unwrap());
    }

    #[test]
    fn append_block_to_chain_write_correct_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path());
        block_store.create_files_if_they_do_not_exist().unwrap();

        let dummy_block = ValidBlock::new_dummy(KeyPair::random().private_key()).into();

        let append_count = 35;
        for _ in 0..append_count {
            block_store.append_block_to_chain(&dummy_block).unwrap();
        }

        let block_hashes = block_store.read_block_hashes(0, append_count).unwrap();

        for hash in block_hashes {
            assert_eq!(hash, dummy_block.hash())
        }
    }

    #[test]
    fn append_block_to_chain_places_blocks_correctly_in_data_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path());
        block_store.create_files_if_they_do_not_exist().unwrap();

        let dummy_block = ValidBlock::new_dummy(KeyPair::random().private_key()).into();

        let append_count = 35;
        for _ in 0..append_count {
            block_store.append_block_to_chain(&dummy_block).unwrap();
        }

        let block_data = dummy_block.encode_versioned();
        for i in 0..append_count {
            let BlockIndex { start, length } = block_store.read_block_index(i).unwrap();
            assert_eq!(i * block_data.len() as u64, start);
            assert_eq!(block_data.len() as u64, length);
        }
    }

    #[test]
    fn strict_init_kura() {
        let temp_dir = TempDir::new().unwrap();
        Kura::new(&Config {
            init_mode: InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(
                temp_dir.path().to_str().unwrap().into(),
            ),
            blocks_in_memory: BLOCKS_IN_MEMORY,
            debug_output_new_blocks: false,
        })
        .unwrap();
    }

    #[test]
    fn kura_not_miss_replace_block() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_time()
            .build()
            .unwrap();

        {
            let _rt_guard = rt.enter();
            let _logger = iroha_logger::test_logger();
        }

        // Create kura and write some blocks
        let temp_dir = TempDir::new().unwrap();
        let [block_genesis, _block, block_soft_fork, block_next] =
            create_blocks(&rt, &temp_dir).try_into().unwrap();

        // Reinitialize kura and check that correct blocks are loaded
        {
            let (kura, block_count) = Kura::new(&Config {
                init_mode: InitMode::Strict,
                store_dir: iroha_config::base::WithOrigin::inline(
                    temp_dir.path().to_str().unwrap().into(),
                ),
                blocks_in_memory: BLOCKS_IN_MEMORY,
                debug_output_new_blocks: false,
            })
            .unwrap();

            assert_eq!(block_count.0, 3);

            assert_eq!(
                kura.get_block(nonzero!(1_usize)),
                Some(Arc::new(block_genesis.into()))
            );
            assert_eq!(
                kura.get_block(nonzero!(2_usize)),
                Some(Arc::new(block_soft_fork.into()))
            );
            assert_eq!(
                kura.get_block(nonzero!(3_usize)),
                Some(Arc::new(block_next.into()))
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn create_blocks(rt: &tokio::runtime::Runtime, temp_dir: &TempDir) -> Vec<CommittedBlock> {
        const BLOCK_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);
        let mut blocks = Vec::new();

        let (leader_public_key, leader_private_key) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), leader_public_key);
        let topology = Topology::new(vec![peer_id]);

        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let (genesis_id, genesis_key_pair) = gen_account_in("genesis");
        let genesis_domain_id = DomainId::from_str("genesis").expect("Valid");
        let genesis_domain = Domain::new(genesis_domain_id).build(&genesis_id);
        let genesis_account = Account::new(genesis_id.clone()).build(&genesis_id);
        let (account_id, account_keypair) = gen_account_in("wonderland");
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let domain = Domain::new(domain_id).build(&genesis_id);
        let account = Account::new(account_id.clone()).build(&genesis_id);

        let live_query_store = {
            let _rt_guard = rt.enter();
            LiveQueryStore::start_test()
        };

        let (kura, block_count) = Kura::new(&Config {
            init_mode: InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(
                temp_dir.path().to_str().unwrap().into(),
            ),
            blocks_in_memory: BLOCKS_IN_MEMORY,
            debug_output_new_blocks: false,
        })
        .unwrap();
        // Starting with empty block store
        assert_eq!(block_count.0, 0);

        let _handle = {
            let _rt_guard = rt.enter();
            Kura::start(kura.clone(), ShutdownSignal::new())
        };

        let state = State::new(
            World::with([domain, genesis_domain], [account, genesis_account], []),
            Arc::clone(&kura),
            live_query_store,
        );

        let executor_path = PathBuf::from("../../defaults/executor.wasm").into();
        let genesis = GenesisBuilder::new(chain_id.clone(), executor_path)
            .set_topology(topology.as_ref().to_owned())
            .build_and_sign(&genesis_key_pair)
            .expect("genesis block should be built");

        {
            let mut state_block = state.block(genesis.0.header());
            let block_genesis = ValidBlock::validate(
                genesis.0.clone(),
                &topology,
                &chain_id,
                &genesis_id,
                &mut state_block,
            )
            .unpack(|_| {})
            .unwrap()
            .commit(&topology)
            .unpack(|_| {})
            .unwrap();
            let _events =
                state_block.apply_without_execution(&block_genesis, topology.as_ref().to_owned());
            state_block.commit();
            blocks.push(block_genesis.clone());
            kura.store_block(block_genesis.clone());
        }

        let (max_clock_drift, tx_limits) = {
            let params = state.view().world.parameters;
            (params.sumeragi().max_clock_drift(), params.transaction)
        };
        let tx1 = TransactionBuilder::new(chain_id.clone(), account_id.clone())
            .with_instructions([Log::new(Level::INFO, "msg1".to_string())])
            .sign(account_keypair.private_key());

        let tx2 = TransactionBuilder::new(chain_id.clone(), account_id)
            .with_instructions([Log::new(Level::INFO, "msg2".to_string())])
            .sign(account_keypair.private_key());
        let tx1 =
            crate::AcceptedTransaction::accept(tx1, &chain_id, max_clock_drift, tx_limits).unwrap();
        let tx2 =
            crate::AcceptedTransaction::accept(tx2, &chain_id, max_clock_drift, tx_limits).unwrap();

        {
            let unverified_block = BlockBuilder::new(vec![tx1.clone()])
                .chain(0, state.view().latest_block().as_deref())
                .sign(&leader_private_key)
                .unpack(|_| {});

            let mut state_block = state.block(unverified_block.header());
            let block = unverified_block
                .categorize(&mut state_block)
                .unpack(|_| {})
                .commit(&topology)
                .unpack(|_| {})
                .unwrap();
            let _events = state_block.apply_without_execution(&block, topology.as_ref().to_owned());
            state_block.commit();
            blocks.push(block.clone());
            kura.store_block(block);
        }
        thread::sleep(BLOCK_FLUSH_TIMEOUT);

        {
            let unverified_block_soft_fork = BlockBuilder::new(vec![tx1])
                .chain(1, Some(&genesis.0))
                .sign(&leader_private_key)
                .unpack(|_| {});

            let mut state_block = state.block_and_revert(unverified_block_soft_fork.header());
            let block_soft_fork = unverified_block_soft_fork
                .categorize(&mut state_block)
                .unpack(|_| {})
                .commit(&topology)
                .unpack(|_| {})
                .unwrap();
            let _events =
                state_block.apply_without_execution(&block_soft_fork, topology.as_ref().to_owned());
            state_block.commit();
            blocks.push(block_soft_fork.clone());
            kura.replace_top_block(block_soft_fork);
        }
        thread::sleep(BLOCK_FLUSH_TIMEOUT);

        {
            let unverified_block_next = BlockBuilder::new(vec![tx2])
                .chain(0, state.view().latest_block().as_deref())
                .sign(&leader_private_key)
                .unpack(|_| {});

            let mut state_block = state.block(unverified_block_next.header());
            let block_next = unverified_block_next
                .categorize(&mut state_block)
                .unpack(|_| {})
                .commit(&topology)
                .unpack(|_| {})
                .unwrap();
            let _events =
                state_block.apply_without_execution(&block_next, topology.as_ref().to_owned());
            state_block.commit();
            blocks.push(block_next.clone());
            kura.store_block(block_next);
        }
        thread::sleep(BLOCK_FLUSH_TIMEOUT);

        blocks
    }
}
