#![allow(clippy::module_name_repetitions)]

//! Module with message broker for `iroha_actor`
///
/// ```rust
/// use iroha_actor::{prelude::*, broker::*};
///
/// #[derive(Clone)]
/// struct Message1(String);
/// impl Message for Message1 { type Result = (); }
///
/// #[derive(Clone)]
/// struct Message2(String);
/// impl Message for Message2 { type Result = (); }
///
/// struct Actor1(Broker);
/// struct Actor2(Broker);
///
/// #[async_trait::async_trait]
/// impl Actor for Actor1 {
///     async fn on_start(&mut self, ctx: &mut Context<Self>) {
///         self.0.subscribe::<Message1, _>(ctx);
///         self.0.issue_send(Message2("Hello".to_string())).await;
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl Handler<Message1> for Actor1 {
///     type Result = ();
///     async fn handle(&mut self, msg: Message1) {
///         println!("Actor1: {}", msg.0);
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl Actor for Actor2 {
///     async fn on_start(&mut self, ctx: &mut Context<Self>) {
///         self.0.subscribe::<Message2, _>(ctx);
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl Handler<Message2> for Actor2 {
///     type Result = ();
///     async fn handle(&mut self, msg: Message2) {
///         println!("Actor2: {}", msg.0);
///         self.0.issue_send(Message1(msg.0.clone() + " world")).await;
///     }
/// }
/// tokio::runtime::Runtime::new().unwrap().block_on(async {
///     let broker = Broker::new();
///     Actor2(broker.clone()).start().await;
///     Actor1(broker).start().await;
/// })
/// ```
use std::any::{Any, TypeId};
use std::sync::Arc;

use dashmap::{mapref::entry::Entry, DashMap};
use futures::future;

use super::*;

type TypeMap<V> = DashMap<TypeId, V>;
type BrokerRecipient = Box<dyn Any + Sync + Send + 'static>;

/// Broker type. Can be cloned and shared between many actors.
///
/// TODO: There might be several actors of one type. We should handle this case!
#[derive(Debug)]
pub struct Broker(Arc<TypeMap<Vec<(TypeId, BrokerRecipient)>>>);

impl Clone for Broker {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Default for Broker {
    fn default() -> Self {
        Self::new()
    }
}

impl Broker {
    /// Default constructor for broker
    pub fn new() -> Self {
        Self(Arc::new(DashMap::new()))
    }

    fn message_entry(&'_ self, id: TypeId) -> Entry<'_, TypeId, Vec<(TypeId, BrokerRecipient)>> {
        self.0.entry(id)
    }

    /// Send message via broker
    pub async fn issue_send<M: BrokerMessage + Send + Sync>(&self, m: M) {
        let entry = if let Entry::Occupied(entry) = self.message_entry(TypeId::of::<M>()) {
            entry
        } else {
            return;
        };
        let send = entry.get().iter().filter_map(|(_, recipient)| {
            recipient
                .downcast_ref::<Recipient<M>>()
                .map(|recipient| recipient.send(m.clone()))
        });
        drop(future::join_all(send).await);
    }

    fn subscribe_recipient<M: BrokerMessage>(&self, recipient: Recipient<M>) {
        let mut entry = self
            .message_entry(TypeId::of::<M>())
            .or_insert_with(|| Vec::with_capacity(1));
        if entry
            .iter()
            .any(|(actor_id, _)| *actor_id == TypeId::of::<Self>())
        {
            return;
        }
        entry.push((TypeId::of::<Self>(), Box::new(recipient)));
    }

    /// Subscribe actor to specific message type
    pub fn subscribe<M: BrokerMessage, A: Actor + ContextHandler<M>>(&self, ctx: &mut Context<A>) {
        self.subscribe_recipient(ctx.recipient::<M>())
    }

    /// Subscribe with channel to specific message type
    pub fn subscribe_with_channel<M: BrokerMessage + Debug>(&self) -> mpsc::Receiver<M> {
        let (sender, receiver) = mpsc::channel(100);
        self.subscribe_recipient(sender.into());
        receiver
    }

    /// Unsubscribe actor to this specific message type
    pub fn unsubscribe<M: BrokerMessage, A: Actor + ContextHandler<M>>(
        &self,
        _ctx: &mut Context<A>,
    ) {
        let mut entry = if let Entry::Occupied(entry) = self.message_entry(TypeId::of::<M>()) {
            entry
        } else {
            return;
        };

        if let Some(pos) = entry
            .get()
            .iter()
            .position(|(actor_id, _)| actor_id == &TypeId::of::<Self>())
        {
            drop(entry.get_mut().remove(pos));
        }
    }
}

/// Trait alias for messages which can be broked
pub trait BrokerMessage: Message<Result = ()> + Clone + 'static + Send {}

impl<M: Message<Result = ()> + Clone + 'static + Send> BrokerMessage for M {}
