//! Actor encapsulating interaction with logger & telemetry subsystems.

use iroha_config::logger::into_tracing_level;
use iroha_data_model::Level;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing_core::Subscriber;
use tracing_subscriber::{reload, reload::Error as ReloadError};

use crate::telemetry;

/// TODO
#[derive(Clone)]
pub struct LoggerHandle {
    sender: mpsc::Sender<Message>,
}

impl LoggerHandle {
    pub(crate) fn new<S: Subscriber>(
        handle: reload::Handle<tracing_subscriber::filter::LevelFilter, S>,
        telemetry_receiver: mpsc::Receiver<telemetry::ChannelEvent>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(32);
        let (regular, _) = broadcast::channel(32);
        let (future_forward, _) = broadcast::channel(32);
        let mut actor = LoggerActor {
            message_receiver: rx,
            level_handle: handle,
            telemetry_receiver,
            telemetry_forwarder_regular: regular,
            telemetry_forwarder_future: future_forward,
        };
        tokio::spawn(async move { actor.run().await });

        Self { sender: tx }
    }

    /// Reload the log level filter.
    ///
    /// # Errors
    /// - If reloading on the side of [`reload::Handle`] fails
    /// - If actor communication fails
    pub async fn reload_level(&self, new_value: Level) -> color_eyre::Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::ReloadLevel {
                value: new_value,
                respond_to: tx,
            })
            .await;
        Ok(rx.await??)
    }

    /// Subscribe to the telemetry events broadcasting.
    ///
    /// # Errors
    /// If actor communication fails
    pub async fn subscribe_on_telemetry(
        &self,
        channel: telemetry::Channel,
    ) -> color_eyre::Result<broadcast::Receiver<telemetry::Event>, Error> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::SubscribeOnTelemetry {
                channel,
                respond_to: tx,
            })
            .await;
        Ok(rx.await?)
    }
}

enum Message {
    ReloadLevel {
        value: Level,
        respond_to: oneshot::Sender<color_eyre::Result<(), ReloadError>>,
    },
    SubscribeOnTelemetry {
        channel: telemetry::Channel,
        respond_to: oneshot::Sender<broadcast::Receiver<telemetry::Event>>,
    },
}

/// Possible errors that might occur while interacting with the actor.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// If dynamic log level reloading failed
    #[error("cannot dynamically reload the log level")]
    LevelReload(#[from] ReloadError),
    /// If actor communication is broken
    #[error("failed to communicate with the actor")]
    Communication(#[from] oneshot::error::RecvError),
}

struct LoggerActor<S: Subscriber> {
    message_receiver: mpsc::Receiver<Message>,
    telemetry_receiver: mpsc::Receiver<telemetry::ChannelEvent>,
    telemetry_forwarder_regular: broadcast::Sender<telemetry::Event>,
    telemetry_forwarder_future: broadcast::Sender<telemetry::Event>,
    level_handle: reload::Handle<tracing_subscriber::filter::LevelFilter, S>,
}

impl<S: Subscriber> LoggerActor<S> {
    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.message_receiver.recv() => {
                    self.handle_message(msg);
                },
                Some(telemetry::ChannelEvent(channel, event)) = self.telemetry_receiver.recv() => {
                    let forward_to = match channel {
                        telemetry::Channel::Regular => &self.telemetry_forwarder_regular,
                        telemetry::Channel::Future => &self.telemetry_forwarder_future,
                    };

                    let _ = forward_to.send(event);
                },
                else => break
            }
            tokio::task::yield_now().await;
        }
    }

    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::ReloadLevel { value, respond_to } => {
                let level = into_tracing_level(value);
                let filter = tracing_subscriber::filter::LevelFilter::from_level(level);
                let result = self.level_handle.reload(filter);
                let _ = respond_to.send(result);
            }
            Message::SubscribeOnTelemetry {
                channel: kind,
                respond_to,
            } => {
                let receiver = match kind {
                    telemetry::Channel::Regular => self.telemetry_forwarder_regular.subscribe(),
                    telemetry::Channel::Future => self.telemetry_forwarder_future.subscribe(),
                };
                let _ = respond_to.send(receiver);
            }
        }
    }
}
