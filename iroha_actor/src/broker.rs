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
///
///     fn broker(&self) -> Option<&Broker> {
///         Some(&self.0)
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
///
///     fn broker(&self) -> Option<&Broker> {
///         Some(&self.0)
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
use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};

use super::*;

const CHANNEL_SUBSCRIBER_SIZE: usize = 100;

/// Type alias for Message Type.
pub type MessageType = TypeId;

/// Type alias for Actor Type.
pub type ActorType = TypeId;

/// Type alias for Subscription Id.
pub type SubscriptionId = u128;

/// Channel to the Actor.
type BrokerRecipient = Box<dyn Any + Sync + Send + 'static>;

#[derive(Debug, Default)]
/// Subscribers for a particular `MessageType`.
pub struct Subscribers {
    subscribers: HashMap<SubscriptionId, BrokerRecipient>,
    next_subscripton_id: SubscriptionId,
}

impl Subscribers {
    /// Constructor.
    pub fn new() -> Subscribers {
        Subscribers::default()
    }

    #[allow(clippy::expect_used)]
    fn subscribe_recipient(&mut self, recipient: BrokerRecipient) -> SubscriptionId {
        let id = self.next_subscripton_id;
        self.subscribers.insert(id, recipient);
        self.next_subscripton_id = self.next_subscripton_id.checked_add(1).expect(
            "Subscription Id counter overflow. Too many subscription for this message were created.",
        );
        id
    }

    /// Subscribe actor to this [`MessageType`].
    pub fn subscribe_actor(&mut self, recipient: BrokerRecipient) -> SubscriptionId {
        self.subscribe_recipient(recipient)
    }

    /// Create and subscribe channel to this [`MessageType`].
    pub fn subscribe_channel<M: BrokerMessage + Debug>(
        &mut self,
    ) -> (mpsc::Receiver<M>, SubscriptionId) {
        let (sender, receiver) = mpsc::channel(CHANNEL_SUBSCRIBER_SIZE);
        let sender: Recipient<M> = sender.into();
        (receiver, self.subscribe_recipient(Box::new(sender)))
    }

    /// Unsubscribe channel from this [`MessageType`] by channel id.
    pub fn unsubscribe(&mut self, id: SubscriptionId) {
        self.subscribers.remove(&id);
    }

    /// Send message to subscribers of this [`MessageType`].
    pub async fn publish_message<M: BrokerMessage + Send + Sync>(&self, message: M) {
        let mut send_futures: FuturesUnordered<_> = self
            .subscribers
            .iter()
            .filter_map(|(_, recipient)| {
                recipient
                    .downcast_ref::<Recipient<M>>()
                    .map(|recipient| recipient.send(message.clone()))
            })
            .collect();
        while let Some(()) = send_futures.next().await {}
    }

    /// Number of subscribers.
    pub fn len(&self) -> usize {
        self.subscribers.len()
    }

    /// If there are no subscribers.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Broker type. Can be cloned and shared between many actors.
#[derive(Debug)]
pub struct Broker(Arc<DashMap<MessageType, Subscribers>>);

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

    /// Send message via broker
    pub async fn issue_send<M: BrokerMessage + Send + Sync>(&self, message: M) {
        let warn_empty = || {
            iroha_logger::warn!(
                "The message {:?} was send but no entity is subscribed to it.",
                TypeId::of::<M>()
            )
        };
        if let Some(subscribers) = self.0.get(&TypeId::of::<M>()) {
            if subscribers.is_empty() {
                warn_empty();
            } else {
                subscribers.value().publish_message(message).await;
            }
        } else {
            warn_empty();
        }
    }

    /// Subscribe actor to specific message type
    pub fn subscribe<M: BrokerMessage, A: Actor + ContextHandler<M>>(&self, ctx: &mut Context<A>) {
        let id = self
            .0
            .entry(TypeId::of::<M>())
            .or_insert(Subscribers::new())
            .subscribe_actor(Box::new(ctx.recipient::<M>()));
        ctx.unsubscribe_from_on_stop.push((id, TypeId::of::<M>()));
    }

    /// Subscribe with channel to specific message type.
    pub fn subscribe_with_channel<M: BrokerMessage + Debug>(
        &self,
    ) -> (mpsc::Receiver<M>, SubscriptionId) {
        self.0
            .entry(TypeId::of::<M>())
            .or_insert(Subscribers::new())
            .subscribe_channel()
    }

    /// Unsubscribe actor to this specific message type.
    pub fn unsubscribe<M: BrokerMessage>(&self, subscription_id: SubscriptionId) {
        self.unsubscribe_by_type_id(TypeId::of::<M>(), subscription_id);
    }

    /// Unsubscribe actor to this specific message type id.
    pub fn unsubscribe_by_type_id(
        &self,
        message_type: MessageType,
        subscription_id: SubscriptionId,
    ) {
        if let Some(mut subscribers) = self.0.get_mut(&message_type) {
            subscribers.value_mut().unsubscribe(subscription_id);
        }
    }
}

/// Trait alias for messages which can be broked
pub trait BrokerMessage: Message<Result = ()> + Clone + 'static + Send {}

impl<M: Message<Result = ()> + Clone + 'static + Send> BrokerMessage for M {}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::sync::RwLock;

    use super::*;

    pub struct Actor1(Broker, Arc<RwLock<u32>>);

    #[async_trait]
    impl Actor for Actor1 {
        async fn on_start(&mut self, ctx: &mut Context<Self>) {
            self.0.subscribe::<StopMessage, _>(ctx);
            self.0.subscribe::<Message1, _>(ctx);
        }

        fn broker(&self) -> Option<&broker::Broker> {
            Some(&self.0)
        }
    }

    #[derive(Clone, Copy)]
    pub struct StopMessage;

    impl Message for StopMessage {
        type Result = ();
    }

    #[async_trait::async_trait]
    impl ContextHandler<StopMessage> for Actor1 {
        type Result = ();

        async fn handle(
            &mut self,
            ctx: &mut Context<Self>,
            StopMessage: StopMessage,
        ) -> Self::Result {
            ctx.stop_now()
        }
    }

    #[derive(Clone, Copy)]
    pub struct Message1;

    impl Message for Message1 {
        type Result = ();
    }

    #[async_trait::async_trait]
    impl Handler<Message1> for Actor1 {
        type Result = ();

        async fn handle(&mut self, Message1: Message1) -> Self::Result {
            *self.1.write().await += 1;
        }
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn actor_unsubscribes_on_stop() {
        let broker = Broker::new();
        Actor1(broker.clone(), Arc::default()).start().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            broker
                .0
                .get(&TypeId::of::<StopMessage>())
                .unwrap()
                .subscribers
                .len(),
            1
        );
        assert_eq!(
            broker
                .0
                .get(&TypeId::of::<Message1>())
                .unwrap()
                .subscribers
                .len(),
            1
        );
        broker.issue_send(StopMessage).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(broker
            .0
            .get(&TypeId::of::<StopMessage>())
            .unwrap()
            .subscribers
            .is_empty());
        assert!(broker
            .0
            .get(&TypeId::of::<Message1>())
            .unwrap()
            .subscribers
            .is_empty());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn actors_of_the_same_type() {
        let broker = Broker::new();
        let actor1_counter = Arc::new(RwLock::new(0));
        Actor1(broker.clone(), Arc::clone(&actor1_counter))
            .start()
            .await;
        let actor2_counter = Arc::new(RwLock::new(0));
        Actor1(broker.clone(), Arc::clone(&actor2_counter))
            .start()
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            broker
                .0
                .get(&TypeId::of::<StopMessage>())
                .unwrap()
                .subscribers
                .len(),
            2
        );
        assert_eq!(
            broker
                .0
                .get(&TypeId::of::<Message1>())
                .unwrap()
                .subscribers
                .len(),
            2
        );
        broker.issue_send(Message1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*actor1_counter.read().await, 1);
        assert_eq!(*actor2_counter.read().await, 1);
        broker.issue_send(StopMessage).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(broker
            .0
            .get(&TypeId::of::<StopMessage>())
            .unwrap()
            .subscribers
            .is_empty());
        assert!(broker
            .0
            .get(&TypeId::of::<Message1>())
            .unwrap()
            .subscribers
            .is_empty());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn two_channels_subscribe_to_same_message() {
        #[derive(Clone, Debug)]
        struct Message1;

        impl Message for Message1 {
            type Result = ();
        }

        let broker = Broker::new();
        let mut receiver1 = broker.subscribe_with_channel::<Message1>().0;
        let mut receiver2 = broker.subscribe_with_channel::<Message1>().0;

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
