//! Module for adding layers for events for subscribers

use std::{
    any::TypeId,
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU8, Ordering},
};

use tracing::{
    level_filters::LevelFilter as TracingLevelFilter,
    span::{Attributes, Record},
    subscriber::Interest,
    Event, Id, Level, Metadata, Subscriber,
};
use tracing_core::span::Current;

/// Trait for filtering or inspecting events
pub trait EventInspectorTrait: 'static {
    /// Inner subscriber of current layer
    type Subscriber: Subscriber;
    /// Function which filters or inspects events
    fn event(&self, event: &Event<'_>);
    /// Basically deref for inner subscriber
    fn inner_subscriber(&self) -> &Self::Subscriber;
}

/// Wrapper which implements `Subscriber` trait for any implementator of `EventfilterTrait`
#[derive(Debug, Clone)]
pub struct EventSubscriber<E>(pub E);

impl<E> Deref for EventSubscriber<E> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E> DerefMut for EventSubscriber<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<E: EventInspectorTrait> Subscriber for EventSubscriber<E> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.inner_subscriber().enabled(metadata)
    }

    fn new_span(&self, span: &Attributes<'_>) -> Id {
        self.inner_subscriber().new_span(span)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        self.inner_subscriber().record(span, values)
    }

    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.inner_subscriber().record_follows_from(span, follows)
    }

    fn enter(&self, span: &Id) {
        self.inner_subscriber().enter(span)
    }

    fn exit(&self, span: &Id) {
        self.inner_subscriber().exit(span)
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        self.inner_subscriber().register_callsite(metadata)
    }

    fn max_level_hint(&self) -> Option<TracingLevelFilter> {
        self.inner_subscriber().max_level_hint()
    }

    fn clone_span(&self, id: &Id) -> Id {
        self.inner_subscriber().clone_span(id)
    }

    #[allow(deprecated)]
    fn drop_span(&self, id: Id) {
        self.inner_subscriber().drop_span(id)
    }

    fn try_close(&self, id: Id) -> bool {
        self.inner_subscriber().try_close(id)
    }

    fn current_span(&self) -> Current {
        self.inner_subscriber().current_span()
    }

    #[allow(unsafe_code)]
    unsafe fn downcast_raw(&self, id: TypeId) -> Option<*const ()> {
        self.inner_subscriber().downcast_raw(id)
    }

    fn event(&self, event: &Event<'_>) {
        E::event(self, event)
    }
}

/// Filter of logs by level
#[derive(Debug, Clone)]
pub struct LevelFilter<S> {
    subscriber: S,
}

static CURRENT_LEVEL: AtomicU8 = AtomicU8::new(0);

impl<S: Subscriber> LevelFilter<S> {
    fn level_as_u8(level: Level) -> u8 {
        match level {
            Level::TRACE => 0,
            Level::DEBUG => 1,
            Level::INFO => 2,
            Level::WARN => 3,
            Level::ERROR => 4,
        }
    }

    /// Constructor of level filter
    #[allow(clippy::new_ret_no_self)]
    pub fn new(level: Level, subscriber: S) -> impl Subscriber {
        Self::update_max_level(level);
        EventSubscriber(Self { subscriber })
    }

    /// Updater of max level
    pub fn update_max_level(level: Level) {
        CURRENT_LEVEL.store(Self::level_as_u8(level), Ordering::SeqCst)
    }
}

impl<S: Subscriber> EventInspectorTrait for LevelFilter<S> {
    type Subscriber = S;

    fn inner_subscriber(&self) -> &Self::Subscriber {
        &self.subscriber
    }

    fn event(&self, event: &Event<'_>) {
        let level = Self::level_as_u8(*event.metadata().level());
        if level >= CURRENT_LEVEL.load(Ordering::Relaxed) {
            self.subscriber.event(event)
        }
    }
}
