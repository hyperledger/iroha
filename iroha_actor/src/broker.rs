//! Module with message broker for `iroha_actor`

#![allow(clippy::module_name_repetitions)]

use std::any::{Any, TypeId};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use futures::future;
use once_cell::sync::Lazy;

use super::*;

type TypeMap<V> = DashMap<TypeId, V>;
type BrokerRecipient = Box<dyn Any + Sync + Send + 'static>;

static BROKER: Lazy<TypeMap<Vec<(TypeId, BrokerRecipient)>>> = Lazy::new(DashMap::new);

/// Trait alias for messages which can be broked
pub trait BrokerMessage: Message<Result = ()> + Clone + 'static + Send {}

impl<M: Message<Result = ()> + Clone + 'static + Send> BrokerMessage for M {}

fn message_entry<'a>(id: TypeId) -> Entry<'a, TypeId, Vec<(TypeId, BrokerRecipient)>> {
    BROKER.entry(id)
}

/// Send message via broker
pub async fn issue_send<M: BrokerMessage + Send + Sync>(m: M) {
    let entry = if let Entry::Occupied(entry) = message_entry(TypeId::of::<M>()) {
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

/// Trait for using broker
/// ```rust
/// use iroha_actor::{prelude::*, broker::{self, *}};
///
/// #[derive(Clone)]
/// struct Message1(String);
/// impl Message for Message1 { type Result = (); }
///
/// #[derive(Clone)]
/// struct Message2(String);
/// impl Message for Message2 { type Result = (); }
///
/// struct Actor1;
/// struct Actor2;
///
/// #[async_trait::async_trait]
/// impl Actor for Actor1 {
///     async fn on_start(&mut self, ctx: &mut Context<Self>) {
///         self.subscribe::<Message1>(ctx);
///         broker::issue_send(Message2("Hello".to_string())).await;
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl Handler<Message1> for Actor1 {
///     type Result = ();
///     async fn handle(&mut self, ctx: &mut Context<Self>, msg: Message1) {
///         println!("Actor1: {}", msg.0);
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl Actor for Actor2 {
///     async fn on_start(&mut self, ctx: &mut Context<Self>) {
///         self.subscribe::<Message2>(ctx);
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl Handler<Message2> for Actor2 {
///     type Result = ();
///     async fn handle(&mut self, ctx: &mut Context<Self>, msg: Message2) {
///         println!("Actor2: {}", msg.0);
///         broker::issue_send(Message1(msg.0.clone() + " world")).await;
///     }
/// }
/// async_std::task::block_on(async {
///     Actor2.start();
///     Actor1.start();
/// })
/// ```
#[async_trait::async_trait]
pub trait BrokerActor: Actor {
    /// Subscribe actor to specific message type
    fn subscribe<M: BrokerMessage>(&self, ctx: &mut Context<Self>)
    where
        Self: Handler<M>,
    {
        let mut entry = message_entry(TypeId::of::<M>()).or_insert_with(|| Vec::with_capacity(1));
        if entry
            .iter()
            .any(|(actor_id, _)| actor_id == &TypeId::of::<Self>())
        {
            return;
        }
        entry.push((TypeId::of::<Self>(), Box::new(ctx.recipient::<M>())));
    }

    /// Unsubscribe actor to this specific message type
    fn unsubscribe<M: BrokerMessage>(&self, _ctx: &mut Context<Self>) {
        let mut entry = if let Entry::Occupied(entry) = message_entry(TypeId::of::<M>()) {
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

impl<A: Actor> BrokerActor for A {}
