//! Module with message broker for `iroha_actor`
//!
//! ```rust
//! use iroha_actor::{prelude::*, broker::*};
//!
//! #[derive(Clone)]
//! struct Message1(String);
//! impl Message for Message1 { type Result = (); }
//!
//! #[derive(Clone)] struct Message2(String);
//! impl Message for Message2 { type Result = (); }
//!
//! struct Actor1(Broker);
//! struct Actor2(Broker);
//!
//! #[async_trait::async_trait]
//! impl Actor for Actor1 {
//!     async fn on_start(&mut self, ctx: &mut Context<Self>) {
//!         self.0.subscribe::<Message1, _>(ctx);
//!         self.0.issue_send(Message2("Hello".to_string())).await;
//!     }
//! }
//!
//! #[async_trait::async_trait]
//! impl Handler<Message1> for Actor1 {
//!     type Result = ();
//!     async fn handle(&mut self, msg: Message1) {
//!         println!("Actor1: {}", msg.0);
//!     }
//! }
//!
//! #[async_trait::async_trait]
//! impl Actor for Actor2 {
//!     async fn on_start(&mut self, ctx: &mut Context<Self>) {
//!         self.0.subscribe::<Message2, _>(ctx);
//!     }
//! }
//!
//! #[async_trait::async_trait]
//! impl Handler<Message2> for Actor2 {
//!     type Result = ();
//!     async fn handle(&mut self, msg: Message2) {
//!         println!("Actor2: {}", msg.0);
//!         self.0.issue_send(Message1(msg.0.clone() + " world")).await;
//!     }
//! }
//! tokio::runtime::Runtime::new().unwrap().block_on(async {
//!     let broker = Broker::new();
//!     Actor2(broker.clone()).start().await;
//!     Actor1(broker).start().await;
//!     // Actor2: Hello
//!     // Actor1: Hello world
//! })
//! ```

#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic
)]

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::Arc,
};

use dashmap::{mapref::entry::Entry, DashMap};
use futures::{prelude::*, stream::FuturesUnordered};
use iroha_primitives::small::{self, SmallVec};

use super::*;

type MessageId = TypeId;
type MessageMap<V> = DashMap<MessageId, V>;
type ActorMap<V> = HashMap<ActorId, V>;
type BrokerRecipient = Box<dyn Any + Sync + Send + 'static>;

/// Broker type. Can be cloned and shared between many actors.
#[derive(Debug)]
pub struct Broker(Arc<MessageMap<ActorMap<BrokerRecipient>>>);

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
    /// Construct [`Broker`].
    pub fn new() -> Self {
        Self(Arc::new(MessageMap::new()))
    }

    fn entry(&'_ self, id: TypeId) -> Entry<'_, TypeId, ActorMap<BrokerRecipient>> {
        self.0.entry(id)
    }

    /// Number of subscribers for specific message
    pub fn subscribers<M: BrokerMessage + Send + Sync>(&self) -> usize {
        let entry = if let Entry::Occupied(entry) = self.entry(TypeId::of::<M>()) {
            entry
        } else {
            return 0;
        };

        entry
            .get()
            .iter()
            .filter_map(|(id, recipient)| Some((id, recipient.downcast_ref::<Recipient<M>>()?)))
            .fold(0, |p, (_, n)| p + if n.0.is_closed() { 0 } else { 1 })
    }

    /// Synchronously send message via broker.
    pub fn issue_send_sync<M: BrokerMessage + Send + Sync>(&self, m: &M) {
        let mut entry = if let Entry::Occupied(entry) = self.entry(TypeId::of::<M>()) {
            entry
        } else {
            return;
        };

        let closed = entry
                .get()
                .iter()
                .filter_map(|(id, recipient)| Some((id, recipient.downcast_ref::<Recipient<M>>()?)))
                .map(|(id, recipient)| {
                    let m = m.clone();
                    {
                        if recipient.0.is_closed() {
                            return Some(*id);
                        }

                        recipient.send_sync(m);
                        None
                    }
                })
                .collect::<SmallVec<[_; small::SMALL_SIZE]>>() // TODO: Revise using real-world benchmarks.
                .into_iter()
            .flatten();

        let entry = entry.get_mut();

        for c in closed {
            entry.remove(&c);
        }
    }

    /// Send message via broker
    pub async fn issue_send<M: BrokerMessage + Send + Sync>(&self, m: M) {
        let mut entry = if let Entry::Occupied(entry) = self.entry(TypeId::of::<M>()) {
            entry
        } else {
            return;
        };

        let closed = entry
                .get()
                .iter()
                .filter_map(|(id, recipient)| Some((id, recipient.downcast_ref::<Recipient<M>>()?)))
                .map(|(id, recipient)| {
                    let m = m.clone();
                    async move {
                        if recipient.0.is_closed() {
                            return Some(*id);
                        }

                        recipient.send(m).await;
                        None
                    }
                })
                .collect::<FuturesUnordered<_>>()
                .collect::<SmallVec<[_; small::SMALL_SIZE]>>() // TODO: Revise using real-world benchmarks.
                .await
                .into_iter()
            .flatten();

        let entry = entry.get_mut();

        for c in closed {
            entry.remove(&c);
        }
    }

    fn subscribe_recipient<M: BrokerMessage>(&self, recipient: Recipient<M>, a: ActorId) {
        self.entry(TypeId::of::<M>())
            .or_insert_with(|| ActorMap::with_capacity(1))
            .insert(a, Box::new(recipient));
    }

    /// Subscribe actor to specific message type
    pub fn subscribe<M: BrokerMessage, A: Actor + ContextHandler<M>>(&self, ctx: &mut Context<A>) {
        self.subscribe_recipient(ctx.recipient::<M>(), ctx.actor_id)
    }

    /// Subscribe with channel to specific message type
    pub fn subscribe_with_channel<M: BrokerMessage + Debug>(&self) -> mpsc::Receiver<M> {
        let (sender, receiver) = mpsc::channel(100);
        self.subscribe_recipient(sender.into(), ActorId::new(None));
        receiver
    }

    /// Unsubscribe actor to this specific message type
    pub fn unsubscribe<M: BrokerMessage, A: Actor + ContextHandler<M>>(
        &self,
        ctx: &mut Context<A>,
    ) {
        self.0
            .get_mut(&TypeId::of::<M>())
            .map(|mut entry| entry.remove(&ctx.actor_id));
    }
}

/// Trait alias for messages which can be broked
pub trait BrokerMessage: Message<Result = ()> + Clone + 'static + Send {}

impl<M: Message<Result = ()> + Clone + 'static + Send> BrokerMessage for M {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsubscribe_on_stop() {
        #[derive(Clone, Debug)]
        struct Actor1(Broker);

        #[derive(Clone, Copy, Debug)]
        struct Message1;
        impl Message for Message1 {
            type Result = ();
        }

        #[derive(Clone, Copy, Debug)]
        struct Stop;
        impl Message for Stop {
            type Result = ();
        }

        #[async_trait::async_trait]
        impl Actor for Actor1 {
            async fn on_start(&mut self, ctx: &mut Context<Self>) {
                self.0.subscribe::<Message1, _>(ctx);
                self.0.subscribe::<Stop, _>(ctx);
            }
        }

        #[async_trait::async_trait]
        impl Handler<Message1> for Actor1 {
            type Result = ();
            async fn handle(&mut self, _: Message1) {}
        }

        #[async_trait::async_trait]
        impl ContextHandler<Stop> for Actor1 {
            type Result = ();
            async fn handle(&mut self, ctx: &mut Context<Self>, _: Stop) {
                ctx.stop_now();
            }
        }

        let broker = Broker::new();
        Actor1(broker.clone()).start().await;
        Actor1(broker.clone()).start().await;

        {
            let mut rec = broker.subscribe_with_channel::<Message1>();

            time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                (
                    broker.subscribers::<Message1>(),
                    broker.subscribers::<Stop>()
                ),
                (3, 2)
            );

            broker.issue_send(Message1).await;
            time::sleep(Duration::from_millis(100)).await;

            broker.issue_send(Stop).await;
            time::sleep(Duration::from_millis(100)).await;

            assert_eq!(
                (
                    broker.subscribers::<Message1>(),
                    broker.subscribers::<Stop>()
                ),
                (1, 0)
            );

            tokio::time::timeout(Duration::from_millis(10), rec.recv())
                .await
                .unwrap()
                .unwrap();
        }

        assert_eq!(
            (
                broker.subscribers::<Message1>(),
                broker.subscribers::<Stop>()
            ),
            (0, 0)
        );
    }

    #[tokio::test]
    async fn two_channels_subscribe_to_same_message() {
        #[derive(Clone, Debug)]
        struct Message1;

        impl Message for Message1 {
            type Result = ();
        }

        let broker = Broker::new();
        let mut receiver1 = broker.subscribe_with_channel::<Message1>();
        let mut receiver2 = broker.subscribe_with_channel::<Message1>();

        broker.issue_send(Message1).await;
        let Message1: Message1 = tokio::time::timeout(Duration::from_millis(100), receiver1.recv())
            .await
            .unwrap()
            .unwrap();
        let Message1: Message1 = tokio::time::timeout(Duration::from_millis(100), receiver2.recv())
            .await
            .unwrap()
            .unwrap();
    }
}
