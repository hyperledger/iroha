//! Actor responsible for configuration state and its dynamic updates.
//!
//! Currently the API exposed by [`KisoHandle`] works only with [`ConfigDTO`], because
//! no any part of Iroha is interested in the whole state. However, the API could be extended
//! in future.
//!
//! Updates mechanism is implemented via subscriptions to [`tokio::sync::watch`] channels. For now,
//! only `logger.level` field is dynamic, which might be tracked with [`KisoHandle::subscribe_on_log_level()`].

use eyre::Result;
use iroha_config::{
    client_api::{ConfigDTO, Logger as LoggerDTO},
    logger::Directives,
    parameters::actual::{Logger, Root as Config},
};
use iroha_futures::supervisor::{Child, OnShutdown};
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
    pub fn start(state: Config) -> (Self, Child) {
        let (actor_sender, actor_receiver) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (log_level_update, _) = watch::channel(state.logger().level().clone());
        let mut actor = Actor {
            handle: actor_receiver,
            // state,
            logger: state.logger().clone(),
            log_level_update,
        };
        (
            Self {
                actor: actor_sender,
            },
            Child::new(
                tokio::spawn(async move { actor.run().await }),
                OnShutdown::Abort,
            ),
        )
    }

    /// Fetch the [`ConfigDTO`] from the actor's state.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn get_dto(&self) -> Result<ConfigDTO, Error> {
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
    pub async fn update_with_dto(&self, dto: ConfigDTO) -> Result<(), Error> {
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
    pub async fn subscribe_on_log_level(&self) -> Result<watch::Receiver<Directives>, Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeOnLogLevel { respond_to: tx };
        let _ = self.actor.send(msg).await;
        let receiver = rx.await?;
        Ok(receiver)
    }
}

enum Message {
    GetDTO {
        respond_to: oneshot::Sender<ConfigDTO>,
    },
    UpdateWithDTO {
        dto: ConfigDTO,
        respond_to: oneshot::Sender<Result<(), Error>>,
    },
    SubscribeOnLogLevel {
        respond_to: oneshot::Sender<watch::Receiver<Directives>>,
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
    logger: Logger,
    // Current implementation is somewhat not scalable in terms of code writing: for any
    // future dynamic parameter, it will require its own `subscribe_on_<field>` function in [`KisoHandle`],
    // new channel here, and new [`Message`] variant. If boilerplate expands, a more general solution will be
    // required. However, as of now a single manually written implementation seems optimal.
    log_level_update: watch::Sender<Directives>,
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
                let dto = ConfigDTO::from(&self.logger);
                let _ = respond_to.send(dto);
            }
            Message::UpdateWithDTO {
                dto:
                    ConfigDTO {
                        logger: LoggerDTO { level: new_level },
                    },
                respond_to,
            } => {
                let _ = self.log_level_update.send(new_level.clone());
                self.logger.set_level(new_level);

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
        base::{read::ConfigReader, toml::TomlSource},
        client_api::{ConfigDTO, Logger as LoggerDTO},
        parameters::{actual::RootBuilder, user::Root as UserConfig},
    };
    use iroha_logger::Level;

    use super::*;

    fn test_config() -> RootBuilder {
        // if it fails, it is probably a bug
        ConfigReader::new()
            .with_toml_source(
                TomlSource::from_file("../iroha_config/iroha_test_config.toml").unwrap(),
            )
            .read_and_complete::<UserConfig>()
            .unwrap()
            .parse_builder()
            .unwrap()
    }

    #[tokio::test]
    async fn subscription_on_log_level_works() {
        const INIT_LOG_LEVEL: Level = Level::WARN;
        const NEW_LOG_LEVEL: Level = Level::DEBUG;
        const WATCH_LAG_MILLIS: u64 = 30;

        let mut config = test_config().build().expect("Should build original config");

        config.logger_mut().set_level(INIT_LOG_LEVEL.into());

        let (kiso, _) = KisoHandle::start(config);

        let mut recv = kiso
            .subscribe_on_log_level()
            .await
            .expect("Subscription should be fine");

        let _err = tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect_err("Watcher should not be active initially");

        kiso.update_with_dto(ConfigDTO {
            logger: LoggerDTO {
                level: NEW_LOG_LEVEL.into(),
            },
        })
        .await
        .expect("Update should work fine");

        let () = tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect("Watcher should resolve within timeout")
            .expect("Watcher should not be closed");

        let value = recv.borrow_and_update().clone();
        assert_eq!(value, NEW_LOG_LEVEL.into());
    }
}
