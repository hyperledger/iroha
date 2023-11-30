//! Actor responsible for configuration state and its dynamic updates.
//!
//! Currently the API exposed by [`KisoHandle`] works only with [`ConfigurationDTO`], because
//! no any part of Iroha is interested in the whole state. However, the API could be extended
//! in future.
//!
//! ## Example
//!
//! ```
//! #[tokio::main]
//! async fn main() {
//!   todo!()
//! }
//! ```

use eyre::Result;
use iroha_config::{
    client_api::{ConfigurationDTO, Logger as LoggerDTO},
    iroha::Configuration,
};
use iroha_logger::actor::{Error as LoggerError, LoggerHandle};
use tokio::sync::{mpsc, oneshot};

const DEFAULT_CHANNEL_SIZE: usize = 32;

/// The handle to work with the actor.
///
/// The actor will shutdown when all its handles are dropped.
#[derive(Clone)]
pub struct KisoHandle {
    sender: mpsc::Sender<Message>,
}

impl KisoHandle {
    /// Spawn a new actor
    pub fn new(state: Configuration, logger: LoggerHandle) -> Self {
        let (sender, receiver) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let mut actor = Actor {
            receiver,
            state,
            logger,
        };
        tokio::spawn(async move { actor.run().await });

        Self { sender }
    }

    /// Fetch the [`ConfigurationDTO`] from the actor's state.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn get_dto(&self) -> Result<ConfigurationDTO, Error> {
        let (send, recv) = oneshot::channel();
        let msg = Message::GetDTO { respond_to: send };
        let _ = self.sender.send(msg).await;
        let dto = recv.await?;
        Ok(dto)
    }

    /// Update the configuration state, applying side effects.
    ///
    /// Awaits until the update is applied.
    ///
    /// # Errors
    /// - If updating failure occurs
    /// - If communication with actor is failed
    pub async fn update_with_dto(&self, dto: ConfigurationDTO) -> Result<(), Error> {
        let (send, recv) = oneshot::channel();
        let msg = Message::UpdateWithDTO {
            dto,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await?
    }
}

enum Message {
    GetDTO {
        respond_to: oneshot::Sender<ConfigurationDTO>,
    },
    UpdateWithDTO {
        dto: ConfigurationDTO,
        respond_to: oneshot::Sender<Result<(), Error>>,
    },
}

/// TODO
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// TODO
    #[error("cannot dynamically update the configuration")]
    Update(#[from] iroha_logger::ReloadError),
    /// TODO
    #[error("cannot get actor's response")]
    Communication(#[from] oneshot::error::RecvError),
}

impl From<LoggerError> for Error {
    fn from(value: LoggerError) -> Self {
        match value {
            LoggerError::LevelReload(err) => Self::from(err),
            LoggerError::Communication(err) => Self::from(err),
        }
    }
}

struct Actor {
    receiver: mpsc::Receiver<Message>,
    state: Configuration,
    logger: LoggerHandle,
}

impl Actor {
    async fn run(&mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await
        }
    }

    async fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::GetDTO { respond_to } => {
                let dto = ConfigurationDTO::from(&self.state);
                let _ = respond_to.send(dto);
            }
            Message::UpdateWithDTO {
                dto:
                    ConfigurationDTO {
                        logger: LoggerDTO { level: new_level },
                    },
                respond_to,
            } => {
                if let Err(err) = self.logger.reload_level(new_level).await {
                    let _ = respond_to.send(Err(err.into()));
                    return;
                }
                self.state.logger.level = new_level;
                let _ = respond_to.send(Ok(()));
            }
        }
    }
}
