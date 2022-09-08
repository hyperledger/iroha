//! Translates to warehouse. File-system and persistence-related
//! logic.  [`Kura`] is the main entity which should be used to store
//! new [`Block`](`crate::block::VersionedCommittedBlock`)s on the
//! blockchain.
#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic,
    clippy::significant_drop_in_scrutinee
)]
use std::{
    fmt::Debug,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use iroha_config::kura::{Configuration, Mode};
use iroha_crypto::HashOf;
use iroha_logger::prelude::*;
use iroha_version::scale::{DecodeVersioned, EncodeVersioned};
use tokio::sync::mpsc::{channel, error::SendError, Receiver, Sender};

use crate::{block::VersionedCommittedBlock, handler::ThreadHandler};

/// The interface of Kura subsystem
pub struct Kura {
    // TODO: Kura doesn't have different initialisation modes!!!
    #[allow(dead_code)]
    mode: Mode,
    block_store: Mutex<Box<dyn BlockStoreTrait + Send>>,
    block_hash_array: Mutex<Vec<HashOf<VersionedCommittedBlock>>>,
    // broker: Broker,
    block_reciever: Mutex<Receiver<VersionedCommittedBlock>>,
    block_sender: Sender<VersionedCommittedBlock>,
}

impl Kura {
    /// Initialize Kura and start a thread that recieves
    /// and stores new blocks.
    ///
    /// # Errors
    /// Fails if there are filesystem errors when trying
    /// to access the block store indicated by the provided
    /// path.
    #[allow(clippy::unwrap_in_result, clippy::expect_used)]
    pub fn new(
        mode: Mode,
        block_store_path: &Path,
        // broker: Broker,
        block_channel_size: u32,
    ) -> Result<Arc<Self>> {
        let (block_sender, block_reciever) = channel(
            block_channel_size
                .try_into()
                .expect("block_channel_size is 32 bit"),
        );

        let mut block_store = StdFileBlockStore::new(block_store_path);
        block_store.create_files_if_they_do_not_exist()?;

        let kura = Arc::new(Self {
            mode,
            block_store: Mutex::new(Box::new(block_store)),
            block_hash_array: Mutex::new(Vec::new()),
            // broker,
            block_reciever: Mutex::new(block_reciever),
            block_sender,
        });

        Ok(kura)
    }

    /// Start the Kura thread
    pub fn start(kura: Arc<Self>) -> ThreadHandler {
        // Oneshot channel to allow forcefully stopping the thread.
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

        let thread_handle = std::thread::spawn(move || {
            Self::kura_recieve_blocks_loop(&kura, shutdown_receiver);
        });

        let shutdown = move || {
            let _result = shutdown_sender.send(());
        };

        ThreadHandler::new(Box::new(shutdown), thread_handle)
    }

    /// Loads kura from configuration
    ///
    /// # Errors
    /// Fails if there are filesystem errors when trying
    /// to access the block store indicated by the
    /// path in the configuration.
    pub fn from_configuration(configuration: &Configuration) -> Result<Arc<Self>> {
        Self::new(
            configuration.init_mode,
            Path::new(&configuration.block_store_path),
            // broker,
            configuration.actor_channel_capacity,
        )
    }

    /// Initialize [`Kura`] after its construction to be able to work with it.
    ///
    /// # Errors
    /// Fails if:
    /// - file storage is unavailable
    /// - data in file storage is invalid or corrupted
    #[allow(clippy::unwrap_in_result, clippy::expect_used)]
    pub fn init(&self) -> Result<Vec<VersionedCommittedBlock>> {
        let mut blocks = Vec::new();

        let block_store = self.block_store.lock().expect("lock block store");

        let block_index_count: usize = block_store
            .read_index_count()?
            .try_into()
            .expect("We don't have 4 billion blocks.");
        let mut block_indices = Vec::new();
        block_indices.try_reserve(block_index_count)?;
        block_indices.resize(block_index_count, (0_u64, 0_u64));
        block_store.read_block_indices(0, &mut block_indices)?;

        for (block_start, block_len) in block_indices {
            let mut block_data_buffer = Vec::new();
            let block_data_buffer_len: usize = block_len
                .try_into()
                .expect("TODO: handle allocation too large because block_len is corrupted.");
            block_data_buffer.try_reserve(block_data_buffer_len)?;
            block_data_buffer.resize(block_data_buffer_len, 0_u8);

            match block_store.read_block_data(block_start, &mut block_data_buffer) {
                Ok(_) => match VersionedCommittedBlock::decode_versioned(&block_data_buffer) {
                    Ok(decoded_block) => {
                        blocks.push(decoded_block);
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

        info!("Loaded {} blocks at init.", blocks.len());

        let hash_array = blocks.iter().map(VersionedCommittedBlock::hash).collect();

        let mut guard = self
            .block_hash_array
            .lock()
            .expect("lock on block hash array");
        *guard = hash_array;

        Ok(blocks)
    }

    #[allow(clippy::expect_used, clippy::cognitive_complexity, clippy::panic)]
    fn kura_recieve_blocks_loop(
        kura: &Kura,
        mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
    ) {
        let mut block_reciever_guard = kura
            .block_reciever
            .lock()
            .expect("able to lock kura recieve block mutex");
        let mut is_closed = false;
        loop {
            // If kura receive shutdown then close block channel and write remaining blocks to the storage
            if shutdown_receiver.try_recv().is_ok() {
                info!("Kura block thread is being shut down");
                block_reciever_guard.close();
                is_closed = true;
            }

            match block_reciever_guard.try_recv() {
                // No new blocks would be received
                Err(_) if is_closed => break,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                Ok(new_block) => {
                    #[cfg(feature = "telemetry")]
                    if new_block.header().height == 1 {
                        iroha_logger::telemetry!(msg = iroha_telemetry::msg::SYSTEM_CONNECTED, genesis_hash = %new_block.hash());
                    }

                    let block_hash = new_block.hash();
                    let serialized_block: Vec<u8> = new_block.encode_versioned();

                    match kura
                        .block_store
                        .lock()
                        .expect("lock on block store")
                        .append_block_to_chain(&serialized_block)
                    {
                        Ok(()) => {
                            kura.block_hash_array
                                .lock()
                                .expect("lock on block hash array")
                                .push(block_hash);
                        }
                        Err(error) => {
                            error!("Failed to store block, ERROR = {}", error);
                            panic!("Kura has encountered a fatal I/O error.");
                        }
                    }
                }
            }
        }
        info!("Kura block thread is shutting down");
    }

    /// Get the hash of the block at the provided height.
    #[allow(clippy::unwrap_in_result, clippy::expect_used)]
    pub fn get_block_hash(&self, block_height: u64) -> Option<HashOf<VersionedCommittedBlock>> {
        let hash_array_guard = self.block_hash_array.lock().expect("access hash array");
        if block_height == 0 || block_height > hash_array_guard.len() as u64 {
            return None;
        }
        let index: usize = (block_height - 1)
            .try_into()
            .expect("block_height fits in 32 bits or we are running on a 64 bit machine");
        Some(hash_array_guard[index])
    }

    /// Put a block in the queue to be stored by Kura. If the queue is
    /// full, wait until there is space.
    pub async fn store_block_async(&self, block: VersionedCommittedBlock) {
        if let Err(SendError(block)) = self.block_sender.send(block).await {
            error!(?block, "unable to write block, kura thread was closed");
        }
    }

    /// Put a block in the queue to be stored by Kura. If the queue is
    /// full, block the current thread until there is space.
    pub fn store_block_blocking(&self, block: VersionedCommittedBlock) {
        if let Err(SendError(block)) = self.block_sender.blocking_send(block) {
            error!(?block, "unable to write block, kura thread was closed");
        }
    }
}

/// The interface for the **block store**, which is where [Kura],
/// the block storage subsystem, stores its blocks.
///
/// The [`BlockStoreTrait`] defines and implements functionality used by Kura
/// for every platform. The default implementation is `StdFileBlockStore`,
/// which uses `std::fs`.
pub trait BlockStoreTrait {
    /// Read a series of block indices from the block index file and
    /// attempt to fill all of `dest_buffer`.
    ///
    /// # Errors
    /// IO Error.
    fn read_block_indices(
        &self,
        start_block_height: u64,
        dest_buffer: &mut [(u64, u64)],
    ) -> Result<()>;

    /// Write the index of a single block at the specified `block_height`.
    /// If `block_height` is beyond the end of the index file, attempt to
    /// extend the index file.
    ///
    /// # Errors
    /// IO Error.
    fn write_block_index(&mut self, block_height: u64, start: u64, length: u64) -> Result<()>;

    /// Get the number of indices in the index file, which is calculated as the size of
    /// the index file in bytes divided by 16.
    ///
    /// # Errors
    /// IO Error.
    ///
    /// The most common reason this function fails is
    /// that you did not call `create_files_if_they_do_not_exist`.
    ///
    /// Note that if there is an error, you can be quite sure all other
    /// read and write operations will also fail.
    fn read_index_count(&self) -> Result<u64>;

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
    fn write_index_count(&mut self, new_count: u64) -> Result<()>;

    /// Read block data starting from the `start_location_in_data_file` in data file
    /// in order to fill `dest_buffer`.
    ///
    /// # Errors
    /// IO Error.
    fn read_block_data(
        &self,
        start_location_in_data_file: u64,
        dest_buffer: &mut [u8],
    ) -> Result<()>;

    /// Write `block_data` into the data file starting at
    /// `start_location_in_data_file`. Extend the file if
    /// necessary.
    ///
    /// # Errors
    /// IO Error.
    fn write_block_data(
        &mut self,
        start_location_in_data_file: u64,
        block_data: &[u8],
    ) -> Result<()>;

    /// Create the index and data files if they do not
    /// already exist.
    ///
    /// # Errors
    /// Fails if the any of the files don't exist
    /// and couldn't be created.
    fn create_files_if_they_do_not_exist(&mut self) -> Result<()>;

    // Above are the platform dependent functions.
    // Below are the platform independent functions that use the above functions.

    /// Call `read_block_indices` with a buffer of one.
    ///
    /// # Errors
    /// IO Error.
    fn read_block_index(&self, block_height: u64) -> Result<(u64, u64)> {
        let mut index = (0, 0);
        self.read_block_indices(block_height, std::slice::from_mut(&mut index))?;
        Ok(index)
    }

    /// Append `block_data` to this block store. First writing
    /// the data to the data file and then creating a new index
    /// for it in the index file.
    ///
    /// # Errors
    /// Fails if any of the required platform specific functions
    /// fail.
    fn append_block_to_chain(&mut self, block_data: &[u8]) -> Result<()> {
        let new_block_height = self.read_index_count()?;
        let start_location_in_data_file = if new_block_height == 0 {
            0
        } else {
            let (ultimate_block_start, ultimate_block_len) =
                self.read_block_index(new_block_height - 1)?;
            ultimate_block_start + ultimate_block_len
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

/// An implementation of a block store for Kura
/// that uses `std::fs`, the default IO file in Rust.
pub struct StdFileBlockStore {
    path_to_blockchain: PathBuf,
}

impl StdFileBlockStore {
    const INDEX_FILE_NAME: &'static str = "blocks.index";
    const DATA_FILE_NAME: &'static str = "blocks.data";

    /// Create a new block store in `path`.
    pub fn new(path: &Path) -> Self {
        StdFileBlockStore {
            path_to_blockchain: path.to_path_buf(),
        }
    }
}

impl BlockStoreTrait for StdFileBlockStore {
    #[allow(
        clippy::needless_range_loop,
        clippy::unwrap_used,
        clippy::unwrap_in_result
    )]
    fn read_block_indices(
        &self,
        start_block_height: u64,
        dest_buffer: &mut [(u64, u64)],
    ) -> Result<()> {
        let mut index_file = std::fs::OpenOptions::new()
            .read(true)
            .open(self.path_to_blockchain.join(Self::INDEX_FILE_NAME))?;
        let start_location = start_block_height * (2 * std::mem::size_of::<u64>() as u64);
        let block_count = dest_buffer.len() as u64;

        if start_location + (2 * std::mem::size_of::<u64>() as u64) * block_count
            > index_file.metadata()?.len()
        {
            return Err(Error::OutOfBoundsBlockRead(start_block_height, block_count));
        }
        index_file.seek(SeekFrom::Start(start_location))?;
        let mut buffer = [0; core::mem::size_of::<u64>()];
        // (start, length), (start,length) ...
        for i in 0..block_count {
            let index: usize = i.try_into().unwrap();
            dest_buffer[index] = (
                {
                    index_file.read_exact(&mut buffer)?;
                    u64::from_le_bytes(buffer)
                },
                {
                    index_file.read_exact(&mut buffer)?;
                    u64::from_le_bytes(buffer)
                },
            );
        }
        Ok(())
    }

    fn write_block_index(&mut self, block_height: u64, start: u64, length: u64) -> Result<()> {
        let mut index_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(self.path_to_blockchain.join(Self::INDEX_FILE_NAME))?;
        let start_location = block_height * (2 * std::mem::size_of::<u64>() as u64);
        if start_location + (2 * std::mem::size_of::<u64>() as u64) > index_file.metadata()?.len() {
            index_file.set_len(start_location + (2 * std::mem::size_of::<u64>() as u64))?;
        }
        index_file.seek(SeekFrom::Start(start_location))?;
        // block0       | block1
        // start, length| start, length  ... et cetera.
        index_file.write_all(&start.to_le_bytes())?;
        index_file.write_all(&length.to_le_bytes())?;
        Ok(())
    }

    #[allow(clippy::integer_division)]
    fn read_index_count(&self) -> Result<u64> {
        let index_file = std::fs::OpenOptions::new()
            .read(true)
            .open(self.path_to_blockchain.join(Self::INDEX_FILE_NAME))?;
        Ok(index_file.metadata()?.len() / (2 * std::mem::size_of::<u64>() as u64))
        // Each entry is 16 bytes.
    }

    fn write_index_count(&mut self, new_count: u64) -> Result<()> {
        let index_file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.path_to_blockchain.join(Self::INDEX_FILE_NAME))?;
        let new_byte_size = new_count * (2 * std::mem::size_of::<u64>() as u64);
        index_file.set_len(new_byte_size)?;
        Ok(())
    }

    fn read_block_data(
        &self,
        start_location_in_data_file: u64,
        dest_buffer: &mut [u8],
    ) -> Result<()> {
        let mut data_file = std::fs::OpenOptions::new()
            .read(true)
            .open(self.path_to_blockchain.join(Self::DATA_FILE_NAME))?;
        data_file.seek(SeekFrom::Start(start_location_in_data_file))?;
        data_file.read_exact(dest_buffer)?;
        Ok(())
    }

    fn write_block_data(
        &mut self,
        start_location_in_data_file: u64,
        block_data: &[u8],
    ) -> Result<()> {
        let mut data_file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.path_to_blockchain.join(Self::DATA_FILE_NAME))?;
        if start_location_in_data_file + block_data.len() as u64 > data_file.metadata()?.len() {
            data_file.set_len(start_location_in_data_file + block_data.len() as u64)?;
        }
        data_file.seek(SeekFrom::Start(start_location_in_data_file))?;
        data_file.write_all(block_data)?;
        Ok(())
    }

    fn create_files_if_they_do_not_exist(&mut self) -> Result<()> {
        std::fs::create_dir_all(&self.path_to_blockchain)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(self.path_to_blockchain.join(Self::INDEX_FILE_NAME))?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(self.path_to_blockchain.join(Self::DATA_FILE_NAME))?;
        Ok(())
    }
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
    /// The block store tried reading data beyond the end of the block data file.
    #[error("Tried reading block data read out of bounds: {0}, {1}.")]
    OutOfBoundsBlockRead(u64, u64),
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn read_and_write_to_blockchain_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = StdFileBlockStore {
            path_to_blockchain: dir.path().to_path_buf(),
        };
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
            let should_be = [(2, 9), (0, 0), (6, 3), (1, 2)];
            let mut is = [(0, 0), (0, 0), (0, 0), (0, 0)];

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
        let mut block_store = StdFileBlockStore {
            path_to_blockchain: dir.path().to_path_buf(),
        };
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
        let mut block_store = StdFileBlockStore {
            path_to_blockchain: dir.path().to_path_buf(),
        };
        block_store.create_files_if_they_do_not_exist().unwrap();

        assert_eq!(0, block_store.read_index_count().unwrap());
    }

    #[test]
    fn append_block_to_chain_increases_block_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut block_store = StdFileBlockStore {
            path_to_blockchain: dir.path().to_path_buf(),
        };
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
        let mut block_store = StdFileBlockStore {
            path_to_blockchain: dir.path().to_path_buf(),
        };
        block_store.create_files_if_they_do_not_exist().unwrap();

        let block_data = b"some block data";

        let append_count = 35;
        for _ in 0..append_count {
            block_store.append_block_to_chain(block_data).unwrap();
        }

        for i in 0..append_count {
            let (start, len) = block_store.read_block_index(i).unwrap();
            assert_eq!(i * block_data.len() as u64, start);
            assert_eq!(block_data.len() as u64, len);
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn strict_init_kura() {
        let temp_dir = TempDir::new().unwrap();
        assert!(Kura::new(Mode::Strict, temp_dir.path(), 100,)
            .unwrap()
            .init()
            .is_ok());
    }
}
