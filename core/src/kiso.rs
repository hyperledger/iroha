//! Actor responsible for configuration state and its dynamic updates.
//!
//! Currently the API exposed by [`KisoHandle`] works only with [`ConfigurationDTO`], because
//! no any part of Iroha is interested in the whole state. However, the API could be extended
//! in future.
//!
//! Updates mechanism is implemented via subscriptions to [`tokio::sync::watch`] channels. For now,
//! only `logger.level` field is dynamic, which might be tracked with [`KisoHandle::subscribe_on_log_level()`].

use eyre::Result;
use iroha_config::{
    client_api::{ConfigurationDTO, Logger as LoggerDTO},
    parameters::actual::Root,
};
use iroha_logger::Level;
use tokio::sync::{mpsc, oneshot, watch};

const DEFAULT_CHANNEL_SIZE: usize = 32;

/// Handle to work with the actor.
///
/// The actor will shutdown when all its handles are dropped.
#[derive(Clone)]
pub struct KisoHandle {
    actor: mpsc::Sender<Message>,
}

impl KisoHandle {
    /// Spawn a new actor
    pub fn new(state: Root) -> Self {
        let (actor_sender, actor_receiver) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (log_level_update, _) = watch::channel(state.logger.level);
        let mut actor = Actor {
            handle: actor_receiver,
            state,
            log_level_update,
        };
        tokio::spawn(async move { actor.run().await });

        Self {
            actor: actor_sender,
        }
    }

    /// Fetch the [`ConfigurationDTO`] from the actor's state.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn get_dto(&self) -> Result<ConfigurationDTO, Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::GetDTO { respond_to: tx };
        let _ = self.actor.send(msg).await;
        let dto = rx.await?;
        Ok(dto)
    }

    /// Update the configuration state and notify subscribers.
    ///
    /// Works in a fire-and-forget way, i.e. completion of this task doesn't mean that updates are applied. However,
    /// subsequent call of [`Self::get_dto()`] will return an updated state.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn update_with_dto(&self, dto: ConfigurationDTO) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::UpdateWithDTO {
            dto,
            respond_to: tx,
        };
        let _ = self.actor.send(msg).await;
        rx.await?
    }

    /// Subscribe on updates of `logger.level` parameter.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn subscribe_on_log_level(&self) -> Result<watch::Receiver<Level>, Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeOnLogLevel { respond_to: tx };
        let _ = self.actor.send(msg).await;
        let receiver = rx.await?;
        Ok(receiver)
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
    SubscribeOnLogLevel {
        respond_to: oneshot::Sender<watch::Receiver<Level>>,
    },
}

/// Possible errors might occur while working with [`KisoHandle`]
#[derive(thiserror::Error, displaydoc::Display, Debug)]
pub enum Error {
    /// Failed to get actor's response
    Communication(#[from] oneshot::error::RecvError),
}

struct Actor {
    handle: mpsc::Receiver<Message>,
    state: Root,
    // Current implementation is somewhat not scalable in terms of code writing: for any
    // future dynamic parameter, it will require its own `subscribe_on_<field>` function in [`KisoHandle`],
    // new channel here, and new [`Message`] variant. If boilerplate expands, a more general solution will be
    // required. However, as of now a single manually written implementation seems optimal.
    log_level_update: watch::Sender<Level>,
}

impl Actor {
    async fn run(&mut self) {
        while let Some(msg) = self.handle.recv().await {
            self.handle_message(msg)
        }
    }

    fn handle_message(&mut self, msg: Message) {
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
                let _ = self.log_level_update.send(new_level);
                self.state.logger.level = new_level;

                let _ = respond_to.send(Ok(()));
            }
            Message::SubscribeOnLogLevel { respond_to } => {
                let _ = respond_to.send(self.log_level_update.subscribe());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroha_config::{
        client_api::{ConfigurationDTO, Logger as LoggerDTO},
        parameters::actual::Root,
    };

    use super::*;

    fn test_config() -> Root {
        use iroha_config::{
            base::UnwrapPartial,
            parameters::user_layer::{CliContext, RootPartial},
        };

        // FIXME Specifying path here might break!
        RootPartial::from_toml("../config/iroha_test_config.toml")
            .expect("test config should be valid (or it is a bug)")
            .unwrap_partial()
            .expect("test config should be exhaustive")
            .parse(CliContext {
                submit_genesis: true,
            })
            .expect("test config should be valid")
    }

    #[tokio::test]
    async fn subscription_on_log_level_works() {
        const INIT_LOG_LEVEL: Level = Level::WARN;
        const NEW_LOG_LEVEL: Level = Level::DEBUG;
        const WATCH_LAG_MILLIS: u64 = 30;

        let mut config = test_config();
        config.logger.level = INIT_LOG_LEVEL;
        let kiso = KisoHandle::new(config);

        let mut recv = kiso
            .subscribe_on_log_level()
            .await
            .expect("Subscription should be fine");

        let _err = tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect_err("Watcher should not be active initially");

        kiso.update_with_dto(ConfigurationDTO {
            logger: LoggerDTO {
                level: NEW_LOG_LEVEL,
            },
        })
        .await
        .expect("Update should work fine");

        let () = tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect("Watcher should resolve within timeout")
            .expect("Watcher should not be closed");

        let value = *recv.borrow_and_update();
        assert_eq!(value, NEW_LOG_LEVEL);
    }
}
