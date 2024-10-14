use std::{num::NonZeroU64, sync::Arc};

use iroha_core::kura::Kura;
use iroha_data_model::block::{
    stream::{BlockMessage, BlockSubscriptionRequest},
    SignedBlock,
};

use crate::stream::{self, WebSocketScale};

/// Type of error for `Consumer`
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error from provided stream/websocket
    #[error("Stream error: {0}")]
    Stream(Box<stream::Error>),
}

impl From<stream::Error> for Error {
    fn from(error: stream::Error) -> Self {
        Self::Stream(Box::new(error))
    }
}

/// Result type for `Consumer`
pub type Result<T> = core::result::Result<T, Error>;

/// Consumer for Iroha `Block`(s).
/// Passes the blocks over the corresponding connection `stream`.
#[derive(Debug)]
pub struct Consumer<'ws> {
    pub stream: &'ws mut WebSocketScale,
    height: NonZeroU64,
    kura: Arc<Kura>,
}

impl<'ws> Consumer<'ws> {
    /// Constructs [`Consumer`], which forwards blocks through the `stream`.
    ///
    /// # Errors
    /// Can fail due to timeout or without message at websocket or during decoding request
    #[iroha_futures::telemetry_future]
    pub async fn new(stream: &'ws mut WebSocketScale, kura: Arc<Kura>) -> Result<Self> {
        let BlockSubscriptionRequest(height) = stream.recv().await?;
        Ok(Consumer {
            stream,
            height,
            kura,
        })
    }

    /// Forwards block if block for given height already exists
    ///
    /// # Errors
    /// Can fail due to timeout. Also receiving might fail
    #[iroha_futures::telemetry_future]
    pub async fn consume(&mut self) -> Result<()> {
        if let Some(block) = self.kura.get_block_by_height(
            self.height
                .try_into()
                .expect("INTERNAL BUG: Number of blocks exceeds usize::MAX"),
        ) {
            // TODO: to avoid clone `BlockMessage` could be split into sending and receiving parts
            self.stream
                .send(BlockMessage(SignedBlock::clone(&block)))
                .await?;
            self.height = self
                .height
                .checked_add(1)
                .expect("Maximum block height is achieved.");
        }
        Ok(())
    }
}
