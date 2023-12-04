//! Module with telemetry layer for tracing

use std::{error::Error, fmt::Debug};

use derive_more::{Deref, DerefMut};
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{
    field::{Field, Visit},
    Event as TracingEvent, Subscriber,
};

use crate::layer::{EventInspectorTrait, EventSubscriber};

/// Target for telemetry in `tracing`
pub const TARGET_PREFIX: &str = "telemetry::";
/// Target for telemetry future in `tracing`
pub const FUTURE_TARGET_PREFIX: &str = "telemetry_future::";

/// Fields for telemetry (type for efficient saving)
#[derive(Clone, Debug, PartialEq, Eq, Default, Deref, DerefMut)]
pub struct Fields(pub Vec<(&'static str, Value)>);

impl From<Fields> for Value {
    fn from(Fields(fields): Fields) -> Self {
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect()
    }
}

/// Telemetry which can be received from telemetry layer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Subsystem from which telemetry was received
    pub target: &'static str,
    /// Fields which was recorded
    pub fields: Fields,
}

impl Visit for Event {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.fields
            .push((field.name(), format!("{:?}", &value).into()))
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.push((field.name(), value.into()))
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.push((field.name(), value.into()))
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.push((field.name(), value.into()))
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.push((field.name(), value.into()))
    }

    fn record_error(&mut self, field: &Field, mut error: &(dyn Error + 'static)) {
        let mut vec = vec![error.to_string()];
        while let Some(inner) = error.source() {
            error = inner;
            vec.push(inner.to_string())
        }
        self.fields.push((field.name(), vec.into()))
    }
}

impl Event {
    fn from_event(target: &'static str, event: &TracingEvent<'_>) -> Self {
        let fields = Fields::default();
        let mut telemetry = Self { target, fields };
        event.record(&mut telemetry);
        telemetry
    }
}

/// Telemetry layer
#[derive(Debug, Clone)]
pub struct Layer<S: Subscriber> {
    sender: mpsc::Sender<ChannelEvent>,
    subscriber: S,
}

impl<S: Subscriber> Layer<S> {
    /// Create telemetry from channel sender
    pub fn from_senders(subscriber: S, sender: mpsc::Sender<ChannelEvent>) -> impl Subscriber {
        EventSubscriber(Self { sender, subscriber })
    }

    /// Create new telemetry layer with specific channel size (via const generic)
    #[allow(clippy::new_ret_no_self)]
    pub fn new<const CHANNEL_SIZE: usize>(
        subscriber: S,
    ) -> (impl Subscriber, mpsc::Receiver<ChannelEvent>) {
        let (sender, receiver) = mpsc::channel(CHANNEL_SIZE);
        let telemetry = Self::from_senders(subscriber, sender);
        (telemetry, receiver)
    }

    /// Create new telemetry layer with specific channel size
    #[allow(clippy::new_ret_no_self)]
    pub fn from_capacity(
        subscriber: S,
        channel_size: usize,
    ) -> (impl Subscriber, mpsc::Receiver<ChannelEvent>) {
        let (sender, receiver) = mpsc::channel(channel_size);
        let telemetry = Self::from_senders(subscriber, sender);
        (telemetry, receiver)
    }

    fn send_event(&self, channel: Channel, target: &'static str, event: &TracingEvent<'_>) {
        let _ = self
            .sender
            .try_send(ChannelEvent(channel, Event::from_event(target, event)));
    }
}

impl<S: Subscriber> EventInspectorTrait for Layer<S> {
    type Subscriber = S;

    fn inner_subscriber(&self) -> &Self::Subscriber {
        &self.subscriber
    }

    fn event(&self, event: &TracingEvent<'_>) {
        let target = event.metadata().target();
        #[allow(clippy::option_if_let_else)] // This is actually more readable.
        if let Some(target) = target.strip_prefix(TARGET_PREFIX) {
            self.send_event(Channel::Regular, target, event);
        } else if let Some(target) = target.strip_prefix(FUTURE_TARGET_PREFIX) {
            self.send_event(Channel::Future, target, event);
        } else {
            self.subscriber.event(event)
        }
    }
}

/// A pair of [`Channel`] associated with [`Event`]
pub struct ChannelEvent(pub Channel, pub Event);

/// Supported telemetry channels
#[derive(Copy, Clone)]
pub enum Channel {
    /// Regular telemetry
    Regular,
    /// Telemetry collected from futures instrumented with `iroha_futures::TelemetryFuture`.
    Future,
}
