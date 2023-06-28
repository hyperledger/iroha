//! Translates to warehouse. File-system and persistence-related
//! logic.  [`Kura`] is the main entity which should be used to store
//! new [`Block`](`crate::block::VersionedCommittedBlock`)s on the
//! blockchain.
#![allow(clippy::std_instead_of_alloc, clippy::arithmetic_side_effects)]
use std::{
    fmt::Debug,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use derive_more::Deref;
use iroha_config::kura::Mode;
use iroha_crypto::HashOf;
use iroha_data_model::block::VersionedCommittedBlock;
use iroha_logger::prelude::*;
use iroha_version::scale::{DecodeVersioned, EncodeVersioned};
use parking_lot::Mutex;

use crate::handler::ThreadHandler;

const INDEX_FILE_NAME: &str = "blocks.index";
const DATA_FILE_NAME: &str = "blocks.data";
const LOCK_FILE_NAME: &str = "kura.lock";

/// The interface of Kura subsystem
#[derive(Debug)]
pub struct Kura {
    // TODO: Kura doesn't have different initialisation modes!!!
    #[allow(dead_code)]
    /// The mode of initialisation of [`Kura`].
    mode: Mode,
    /// The block storage
    block_store: Mutex<BlockStore<Locked>>,
    /// The array of block hashes and a slot for an arc of the block. This is normally recovered from the index file.
    #[allow(clippy::type_complexity)]
    block_data: Mutex<
        Vec<(
            HashOf<VersionedCommittedBlock>,
            Option<Arc<VersionedCommittedBlock>>,
        )>,
    >,
    /// Path to file for plain text blocks.
    block_plain_text_path: Option<PathBuf>,
}

impl Kura {
    /// Initialize Kura and start a thread that receives
    /// and stores new blocks.
    ///
    /// # Errors
    /// Fails if there are filesystem errors when trying
    /// to access the block store indicated by the provided
    /// path.
    pub fn new(
        mode: Mode,
        block_store_path: &Path,
        debug_output_new_blocks: bool,
    ) -> Result<Arc<Self>> {
        let mut block_store = BlockStore::new(block_store_path).lock()?;
        block_store.create_files_if_they_do_not_exist()?;

        let block_plain_text_path = debug_output_new_blocks.then(|| {
            let mut path_buf = block_store_path.to_path_buf();
            path_buf.push("blocks.json");
            path_buf
        });

        let kura = Arc::new(Self {
            mode,
            block_store: Mutex::new(block_store),
            block_data: Mutex::new(Vec::new()),
            block_plain_text_path,
        });

        Ok(kura)
    }

    /// Create a kura instance that doesn't write to disk. Instead it serves as a handler
    /// for in-memory blocks only.
    pub fn blank_kura_for_testing() -> Arc<Kura> {
        let block_store = BlockStore::fake_locked_for_tests(PathBuf::new());
        Arc::new(Self {
            mode: Mode::Strict,
            block_store: Mutex::new(block_store),
            block_data: Mutex::new(Vec::new()),
            block_plain_text_path: None,
        })
    }

    /// Start the Kura thread
    pub fn start(kura: Arc<Self>) -> ThreadHandler {
        // Oneshot channel to allow forcefully stopping the thread.
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

        let thread_handle = std::thread::spawn(move || {
            Self::kura_receive_blocks_loop(&kura, shutdown_receiver);
        });

        let shutdown = move || {
            if let Err(error) = shutdown_sender.send(()) {
                iroha_logger::error!(?error);
            }
        };

        ThreadHandler::new(Box::new(shutdown), thread_handle)
    }

    /// Initialize [`Kura`] after its construction to be able to work with it.
    ///
    /// # Errors
    /// Fails if:
    /// - file storage is unavailable
    /// - data in file storage is invalid or corrupted
    #[iroha_logger::log(skip_all, name = "kura_init")]
    pub fn init(&self) -> Result<BlockCount> {
        let block_store = self.block_store.lock();

        let block_index_count: usize = block_store
            .read_index_count()?
            .try_into()
            .expect("We don't have 4 billion blocks.");
        let mut block_indices = vec![BlockIndex::default(); block_index_count];
        block_store.read_block_indices(0, &mut block_indices)?;

        let mut block_hashes: Vec<HashOf<VersionedCommittedBlock>> = Vec::new();
        for block in block_indices {
            // This is re-allocated every iteration. This could cause a problem.
            let mut block_data_buffer = vec![0_u8; block.length.try_into()?];

            match block_store.read_block_data(block.start, &mut block_data_buffer) {
                Ok(_) => match VersionedCommittedBlock::decode_all_versioned(&block_data_buffer) {
                    Ok(decoded_block) => {
                        block_hashes.push(decoded_block.hash());
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
        let block_count = block_hashes.len();
        info!(block_count, "Kura init complete");

        // The none value is set in order to indicate that the blocks exist on disk but
        // are not yet loaded.
        *self.block_data.lock() = block_hashes.into_iter().map(|hash| (hash, None)).collect();
        Ok(BlockCount(block_count))
    }

    #[allow(clippy::expect_used, clippy::cognitive_complexity, clippy::panic)]
    #[iroha_logger::log(skip_all)]
    fn kura_receive_blocks_loop(
        kura: &Kura,
        mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
    ) {
        let (mut written_block_count, mut latest_block_hash) = {
            let block_data_guard = kura.block_data.lock();
            (block_data_guard.len(), block_data_guard.last().map(|d| d.0))
        };
        let mut should_exit = false;
        loop {
            // If kura receive shutdown then close block channel and write remaining blocks to the storage
            if shutdown_receiver.try_recv().is_ok() {
                info!("Kura block thread is being shut down. Writing remaining blocks to store.");
                should_exit = true;
            }

            let block_data_guard = kura.block_data.lock();

            let new_latest_block_hash = block_data_guard.last().map(|d| d.0);
            if block_data_guard.len() == written_block_count
                && new_latest_block_hash != latest_block_hash
            {
                written_block_count -= 1; // There has been a soft-fork and we need to rewrite the top block.
            }
            latest_block_hash = new_latest_block_hash;

            if written_block_count >= block_data_guard.len() {
                if should_exit {
                    info!("Kura has written remaining blocks to disk and is shutting down.");
                    return;
                }

                written_block_count = block_data_guard.len();
                drop(block_data_guard);
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }

            // If we get here there are blocks to be written.
            let start_height = written_block_count;
            let mut blocks_to_be_written = Vec::new();
            while written_block_count < block_data_guard.len() {
                let block_ref = block_data_guard[written_block_count]
                    .1
                    .as_ref()
                    .expect("The block to be written cannot be None, see store_block function.");
                blocks_to_be_written.push(Arc::clone(block_ref));
                written_block_count += 1;
            }

            // We don't want to hold up other threads so we drop the lock on the block data.
            drop(block_data_guard);

            if let Some(path) = kura.block_plain_text_path.as_ref() {
                let mut plain_text_file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .expect("Couldn't create file for plain text blocks.");

                for new_block in &blocks_to_be_written {
                    serde_json::to_writer_pretty(&mut plain_text_file, new_block.as_ref())
                        .expect("Failed to write to plain text file for blocks.");
                }
            }

            let mut block_store_guard = kura.block_store.lock();
            if let Err(error) = block_store_guard.write_index_count(start_height as u64) {
                error!(?error, "Failed to write index count");
                panic!("Kura has encountered a fatal IO error.");
            }

            for block in blocks_to_be_written {
                let serialized_block: Vec<u8> = block.encode_versioned();

                if let Err(error) = block_store_guard.append_block_to_chain(&serialized_block) {
                    error!(?error, "Failed to store block");
                    panic!("Kura has encountered a fatal IO error.");
                }
            }
        }
    }

    /// Get the hash of the block at the provided height.
    #[allow(clippy::expect_used)]
    pub fn get_block_hash(&self, block_height: u64) -> Option<HashOf<VersionedCommittedBlock>> {
        let hash_data_guard = self.block_data.lock();
        if block_height == 0 || block_height > hash_data_guard.len() as u64 {
            return None;
        }
        let index: usize = (block_height - 1)
            .try_into()
            .expect("block_height fits in 32 bits or we are running on a 64 bit machine");
        Some(hash_data_guard[index].0)
    }

    /// Search through blocks for the height of the block with the given hash.
    pub fn get_block_height_by_hash(&self, hash: &HashOf<VersionedCommittedBlock>) -> Option<u64> {
        self.block_data
            .lock()
            .iter()
            .position(|(block_hash, _block_arc)| block_hash == hash)
            .map(|index| index as u64 + 1)
    }

    /// Get a reference to block by height, loading it from disk if needed.
    #[allow(clippy::expect_used)]
    // The below lint suggests changing the code into something that does not compile due
    // to the borrow checker.
    pub fn get_block_by_height(&self, block_height: u64) -> Option<Arc<VersionedCommittedBlock>> {
        let mut data_array_guard = self.block_data.lock();
        if block_height == 0 || block_height > data_array_guard.len() as u64 {
            return None;
        }
        let block_number: usize = (block_height - 1)
            .try_into()
            .expect("Failed to cast to u32.");

        if let Some(block_arc) = data_array_guard[block_number].1.as_ref() {
            return Some(Arc::clone(block_arc));
        };

        let block_store = self.block_store.lock();
        let BlockIndex { start, length } = block_store
            .read_block_index(block_number as u64)
            .expect("Failed to read block index from disk.");

        let mut block_buf =
            vec![0_u8; usize::try_from(length).expect("index_len didn't fit in 32-bits")];
        block_store
            .read_block_data(start, &mut block_buf)
            .expect("Failed to read block data.");
        let block = VersionedCommittedBlock::decode_all_versioned(&block_buf)
            .expect("Failed to decode block");

        let block_arc = Arc::new(block);
        data_array_guard[block_number].1 = Some(Arc::clone(&block_arc));
        Some(block_arc)
    }

    /// Get a reference to block by hash, loading it from disk if needed.
    ///
    /// Internally this function searches linearly for the block's height and
    /// then calls `get_block_by_height`. If you know the height of the block,
    /// call `get_block_by_height` directly.
    pub fn get_block_by_hash(
        &self,
        block_hash: &HashOf<VersionedCommittedBlock>,
    ) -> Option<Arc<VersionedCommittedBlock>> {
        let index = self
            .block_data
            .lock()
            .iter()
            .position(|(hash, _arc)| hash == block_hash);

        index.and_then(|index| self.get_block_by_height(index as u64 + 1))
    }

    /// Put a block in kura's in memory block store.
    pub fn store_block(&self, block: impl Into<Arc<VersionedCommittedBlock>>) {
        let block = block.into();
        self.block_data.lock().push((block.hash(), Some(block)));
    }

    /// Replace the block in `Kura`'s in memory block store.
    pub fn replace_top_block(&self, block: impl Into<Arc<VersionedCommittedBlock>>) {
        let block = block.into();
        let mut data = self.block_data.lock();
        data.pop();
        data.push((block.hash(), Some(block)));
    }
}

// Marker trait for typestate. Not sealed, since while it
// doesn't need to be implemented by a user, implementing it
// shouldn't lead to problematic behaviour.
#[doc(hidden)]
pub trait Lock: core::ops::Deref<Target = PathBuf> {}

/// Marker struct for typestate. The marker signifies that the store is not protected
/// by a lockfile the [`BlockStore`] instance owns and thus can be used read-only.
///
/// Owns the path to store because [`Unlocked`] needs
/// to unlock it when dropped, and `Drop` impls
/// cannot be specialized, so `Drop` has to be implemented
/// on typestate `struct`.
#[derive(Debug, Deref)]
pub struct Unlocked(PathBuf);
impl Lock for Unlocked {}

impl Unlocked {
    /// Create new [`Unlocked`] at `path`
    fn new(path: PathBuf) -> Self {
        Self(path)
    }

    /// Try to acquire lockfile and convert self to [`Locked`]
    fn lock(self) -> Result<Locked> {
        let path = self.join(LOCK_FILE_NAME);
        if let Err(e) = fs::File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path.clone())
        {
            match e.kind() {
                std::io::ErrorKind::AlreadyExists => Err(Error::Locked(self.0)),
                std::io::ErrorKind::NotFound => {
                    std::fs::create_dir_all(self.0.clone())
                        .map_err(|e| Error::MkDir(e, path.clone()))?;
                    if let Err(e) = fs::File::options()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(path.clone())
                    {
                        Err(Error::IO(e, path))
                    } else {
                        Ok(Locked(self.0))
                    }
                }
                _ => Err(Error::IO(e, path)),
            }
        } else {
            Ok(Locked(self.0))
        }
    }
}

/// Newtype wrapper for block count
#[derive(Clone, Copy, Debug)]
pub struct BlockCount(pub usize);

/// Marker struct for typestate, signifies that store is protected by
/// a lockfile owned by this instance of [`BlockStore`] and thus can be written into.
///
/// Owns the path to store because [`Unlocked`] needs
/// to unlock it when dropped, and `Drop` impls
/// cannot be specialized, so `Drop` has to be implemented
/// on typestate struct.
#[derive(Debug, Deref)]
pub struct Locked(PathBuf);
impl Lock for Locked {}

impl Locked {
    // Try to lift lockfile. Only for internal use in `unlock`
    // and `Drop` implementation.
    fn try_lift_lock(&mut self) -> Result<()> {
        let path = self.join(LOCK_FILE_NAME);
        if let Err(e) = fs::remove_file(path.clone()) {
            match e.kind() {
                std::io::ErrorKind::NotFound => Err(Error::Unlocked(self.0.clone())),
                _ => Err(Error::IO(e, path)),
            }
        } else {
            Ok(())
        }
    }

    // Lift lockfile and convert self to [`Unlocked`]
    fn unlock(mut self) -> Result<Unlocked> {
        // Lift the lockfile manually
        self.try_lift_lock()?;

        // Prevent destructor from running (lockfile is already deleted)
        let mut me = core::mem::ManuallyDrop::new(self);

        let path = core::mem::take(&mut me.0);

        Ok(Unlocked(path))
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        if let Err(err) = self.try_lift_lock() {
            warn!(%err, "Couldn't remove lockfile at {:?}. Either the lockfile was deleted externally while Iroha instance was running, or there was an IO error. Check the block store with kura_inspector and then delete the lockfile manually.", self);
        }
    }
}

/// An implementation of a block store for `Kura`
/// that uses `std::fs`, the default IO file in Rust.
#[derive(Debug)]
pub struct BlockStore<L: Lock> {
    path_to_blockchain: L,
}

/// Operations available only on unlocked store,
/// i.e. creation and locking.
impl BlockStore<Unlocked> {
    /// Create a new read-only block store in `path`.
    pub fn new(path: &Path) -> Self {
        BlockStore {
            path_to_blockchain: Unlocked::new(path.to_path_buf()),
        }
    }

    /// Try to acquire a lockfile and convert self to
    /// read-write [`BlockStore<Locked>`]
    ///
    /// # Errors
    /// - IO errors
    /// - lockfile already exists
    pub fn lock(self) -> Result<BlockStore<Locked>> {
        Ok(BlockStore {
            path_to_blockchain: self.path_to_blockchain.lock()?,
        })
    }
}

#[derive(Default, Debug, Clone, Copy)]
/// Lightweight wrapper for block indices in the block index file
pub struct BlockIndex {
    /// Start of block in bytes
    pub start: u64,
    /// Length of block section in bytes
    pub length: u64,
}

/// Operations available both on locked and unlocked store,
/// i.e. only read operations.
impl<L: Lock> BlockStore<L> {
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
            .map_err(|e| Error::IO(e, path.clone()))?;
        let start_location = start_block_height * (2 * std::mem::size_of::<u64>() as u64);
        let block_count = dest_buffer.len();

        if start_location + (2 * std::mem::size_of::<u64>() as u64) * block_count as u64
            > index_file
                .metadata()
                .map_err(|e| Error::IO(e, path.clone()))?
                .len()
        {
            return Err(Error::OutOfBoundsBlockRead {
                start_block_height,
                block_count,
            });
        }
        index_file
            .seek(SeekFrom::Start(start_location))
            .map_err(|e| Error::IO(e, path.clone()))?;
        let mut buffer = [0; core::mem::size_of::<u64>()];
        // (start, length), (start,length) ...
        for current_buffer in dest_buffer.iter_mut() {
            *current_buffer = BlockIndex {
                start: {
                    index_file
                        .read_exact(&mut buffer)
                        .map_err(|e| Error::IO(e, path.clone()))?;
                    u64::from_le_bytes(buffer)
                },
                length: {
                    index_file
                        .read_exact(&mut buffer)
                        .map_err(|e| Error::IO(e, path.clone()))?;
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
            .map_err(|e| Error::IO(e, path.clone()))?;
        Ok(index_file.metadata().map_err(|e| Error::IO(e, path))?.len()
            / (2 * std::mem::size_of::<u64>() as u64))
        // Each entry is 16 bytes.
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
            .map_err(|e| Error::IO(e, path.clone()))?;
        data_file
            .seek(SeekFrom::Start(start_location_in_data_file))
            .map_err(|e| Error::IO(e, path.clone()))?;
        data_file
            .read_exact(dest_buffer)
            .map_err(|e| Error::IO(e, path))?;
        Ok(())
    }
}

/// Functions available only for lock-protected block store,
/// i.e. write operations.
impl BlockStore<Locked> {
    // Doesn't actually lock anything, do not use outside of tests.
    #[cfg_attr(
        not(debug_assertions),
        deprecated(note = "Use of fake store in release is probably not what you want")
    )]
    fn fake_locked_for_tests(path: PathBuf) -> Self {
        Self {
            path_to_blockchain: Locked(path),
        }
    }
    /// Try to release the lockfile and convert self to
    /// read-only [`BlockStore<Unlocked>`]
    ///
    /// # Errors
    /// - IO errors
    /// - lockfile doesn't exist
    pub fn unlock(self) -> Result<BlockStore<Unlocked>> {
        Ok(BlockStore {
            path_to_blockchain: self.path_to_blockchain.unlock()?,
        })
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
            .create(true)
            .open(path.clone())
            .map_err(|e| Error::IO(e, path.clone()))?;
        let start_location = block_height * (2 * std::mem::size_of::<u64>() as u64);
        if start_location + (2 * std::mem::size_of::<u64>() as u64)
            > index_file
                .metadata()
                .map_err(|e| Error::IO(e, path.clone()))?
                .len()
        {
            index_file
                .set_len(start_location + (2 * std::mem::size_of::<u64>() as u64))
                .map_err(|e| Error::IO(e, path.clone()))?;
        }
        index_file
            .seek(SeekFrom::Start(start_location))
            .map_err(|e| Error::IO(e, path.clone()))?;
        // block0       | block1
        // start, length| start, length  ... et cetera.
        index_file
            .write_all(&start.to_le_bytes())
            .map_err(|e| Error::IO(e, path.clone()))?;
        index_file
            .write_all(&length.to_le_bytes())
            .map_err(|e| Error::IO(e, path))?;
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
            .map_err(|e| Error::IO(e, path.clone()))?;
        let new_byte_size = new_count * (2 * std::mem::size_of::<u64>() as u64);
        index_file
            .set_len(new_byte_size)
            .map_err(|e| Error::IO(e, path))?;
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
            .map_err(|e| Error::IO(e, path.clone()))?;
        if start_location_in_data_file + block_data.len() as u64
            > data_file
                .metadata()
                .map_err(|e| Error::IO(e, path.clone()))?
                .len()
        {
            data_file
                .set_len(start_location_in_data_file + block_data.len() as u64)
                .map_err(|e| Error::IO(e, path.clone()))?;
        }
        data_file
            .seek(SeekFrom::Start(start_location_in_data_file))
            .map_err(|e| Error::IO(e, path.clone()))?;
        data_file
            .write_all(block_data)
            .map_err(|e| Error::IO(e, path.clone()))?;
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
            .create(true)
            .open(path.clone())
            .map_err(|e| Error::IO(e, path))?;
        let path = self.path_to_blockchain.join(DATA_FILE_NAME);
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(path.clone())
            .map_err(|e| Error::IO(e, path))?;
        Ok(())
    }

    /// Append `block_data` to this block store. First write
    /// the data to the data file and then create a new index
    /// for it in the index file.
    ///
    /// # Errors
    /// Fails if any of the required platform-specific functions
    /// fail.
    pub fn append_block_to_chain(&mut self, block_data: &[u8]) -> Result<()> {
        let new_block_height = self.read_index_count()?;
        let start_location_in_data_file = if new_block_height == 0 {
            0
        } else {
            let ultimate_block = self.read_block_index(new_block_height - 1)?;
            ultimate_block.start + ultimate_block.length
        };

        self.write_block_data(start_location_in_data_file, block_data)?;
        self.write_block_index(
            new_block_height,
            start_location_in_data_file,
            block_data.len() as u64,
        )?;

        Ok(())
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;
/// Error variants for persistent storage logic
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Generic IO error
    #[error("Failed reading/writing {_1:?} from disk")]
    IO(#[source] std::io::Error, PathBuf),
    /// Failed to create the directory
    #[error("Failed to create the directory {_1:?}")]
    MkDir(std::io::Error, PathBuf),
    /// Error (de)serializing block
    #[error("Failed to serialize/deserialize block")]
    Codec(#[from] iroha_version::error::Error),
    /// Allocation error
    #[error("Failed to allocate buffer")]
    Alloc(#[from] std::collections::TryReserveError),
    /// Zero-height block was provided
    /// The block store tried reading data beyond the end of the block data file.
    #[error("Tried reading block data out of bounds: {start_block_height}, {block_count}.")]
    OutOfBoundsBlockRead {
        /// The block height from which the read was supposed to start
        start_block_height: u64,
        /// The actual block count
        block_count: usize,
    },
    /// Tried to lock an already locked store
    #[error("Tried to lock block store by creating a lockfile at {0}, but it already exists")]
    Locked(PathBuf),
    /// Tried to unlock an already unlocked store
    #[error("Tried to unlock block store by deleting lockfile at {0}, but it couldn't be found")]
    Unlocked(PathBuf),
    /// Integer conversion error
    #[error("Conversion of wide integer into narrow integer. This error cannot be caught at compile time at present")]
    IntConversion(#[from] std::num::TryFromIntError),
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {

    use tempfile::TempDir;

    use super::*;

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
        let mut block_store = BlockStore::new(dir.path()).lock().unwrap();
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
        let mut block_store = BlockStore::new(dir.path()).lock().unwrap();
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
        let mut block_store = BlockStore::new(dir.path()).lock().unwrap();
        block_store.create_files_if_they_do_not_exist().unwrap();

        assert_eq!(0, block_store.read_index_count().unwrap());
    }

    #[test]
    fn append_block_to_chain_increases_block_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path()).lock().unwrap();
        block_store.create_files_if_they_do_not_exist().unwrap();

        let append_count = 35;
        for _ in 0..append_count {
            block_store
                .append_block_to_chain(b"A hypothetical block")
                .unwrap();
        }

        assert_eq!(append_count, block_store.read_index_count().unwrap());
    }

    #[test]
    fn append_block_to_chain_places_blocks_correctly_in_data_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = BlockStore::new(dir.path()).lock().unwrap();
        block_store.create_files_if_they_do_not_exist().unwrap();

        let block_data = b"some block data";

        let append_count = 35;
        for _ in 0..append_count {
            block_store.append_block_to_chain(block_data).unwrap();
        }

        for i in 0..append_count {
            let BlockIndex { start, length } = block_store.read_block_index(i).unwrap();
            assert_eq!(i * block_data.len() as u64, start);
            assert_eq!(block_data.len() as u64, length);
        }
    }

    #[test]
    fn lock_and_unlock() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _store = BlockStore::new(dir.path())
                .lock()
                .expect("Lock acquisition failed");
            assert!(
                dir.path().join(LOCK_FILE_NAME).try_exists().expect("IO"),
                "Lockfile should have been created"
            );
        }
        assert!(
            !dir.path().join(LOCK_FILE_NAME).try_exists().expect("IO"),
            "Lockfile should have been deleted"
        );
    }

    #[test]
    fn concurrent_lock() {
        let dir = tempfile::tempdir().unwrap();
        let _store = BlockStore::new(dir.path())
            .lock()
            .expect("Lock acquisition failed");
        let _store_2 = BlockStore::new(dir.path())
            .lock()
            .expect_err("Should fail to acquire lock");
    }

    #[test]
    fn unexpected_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let block_store = BlockStore::new(dir.path())
            .lock()
            .expect("Lock acquisition failed");
        fs::remove_file(dir.path().join(LOCK_FILE_NAME))
            .expect("Lockfile should have been created");
        block_store
            .unlock()
            .expect_err("Shoud fail to release lock");
    }

    #[tokio::test]
    async fn strict_init_kura() {
        let temp_dir = TempDir::new().unwrap();
        Kura::new(Mode::Strict, temp_dir.path(), false)
            .unwrap()
            .init()
            .unwrap();
    }
}
