//!
//! Iroha simple actor framework.
//!

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    time::Duration,
};

/// Derive macro for message:
/// ```rust
/// use iroha_actor::Message;
///
/// #[derive(Message)]
/// struct MessageNoResponse;
///
/// #[derive(Message)]
/// #[message(result = "i32")]
/// struct MessageResponse(i32);
/// ```
pub use actor_derive::Message;
use envelope::{Envelope, EnvelopeProxy, SyncEnvelopeProxy, ToEnvelope};
use futures::{Stream, StreamExt};
use iroha_logger::InstrumentFutures;
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        oneshot::{self, error::RecvError},
    },
    task::{self, JoinHandle},
    time,
};
#[cfg(feature = "deadlock_detection")]
use {deadlock::ActorId, std::any::type_name};

pub mod broker;
#[cfg(feature = "deadlock_detection")]
mod deadlock;
mod envelope;

pub mod prelude {
    //! Module with most used items
    pub use super::{
        broker, Actor, Addr, AlwaysAddr, Context, ContextHandler, Handler, Message, Recipient,
    };
}

/// Address of actor. Can be used to send messages to it.
#[derive(Debug)]
pub struct Addr<A: Actor> {
    sender: mpsc::Sender<Envelope<A>>,
    #[cfg(feature = "deadlock_detection")]
    actor_id: ActorId,
}

impl<A: Actor> Clone for Addr<A> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            #[cfg(feature = "deadlock_detection")]
            actor_id: self.actor_id,
        }
    }
}

impl<A: Actor> Addr<A> {
    fn new(sender: mpsc::Sender<Envelope<A>>) -> Self {
        Self {
            sender,
            #[cfg(feature = "deadlock_detection")]
            actor_id: ActorId::new(Some(type_name::<A>())),
        }
    }

    /// Send a message and wait for an answer.
    /// # Errors
    /// Fails if noone will send message
    /// # Panics
    /// If queue is full
    #[allow(unused_variables, clippy::expect_used)]
    pub async fn send<M>(&self, message: M) -> Result<M::Result, RecvError>
    where
        M: Message + Send + 'static,
        M::Result: Send,
        A: ContextHandler<M>,
    {
        let (sender, reciever) = oneshot::channel();
        let envelope = SyncEnvelopeProxy::pack(message, Some(sender));
        #[cfg(feature = "deadlock_detection")]
        let from_actor_id_option = deadlock::task_local_actor_id();
        #[cfg(feature = "deadlock_detection")]
        if let Some(from_actor_id) = from_actor_id_option {
            deadlock::r#in(self.actor_id, from_actor_id).await;
        }
        #[allow(clippy::todo)]
        if self.sender.send(envelope).await.is_err() {
            todo!("Queue is full. Handle this case");
        }
        let result = reciever.await;
        #[cfg(feature = "deadlock_detection")]
        if let Some(from_actor_id) = from_actor_id_option {
            deadlock::out(self.actor_id, from_actor_id).await;
        }
        result
    }

    /// Send a message and wait for an answer.
    /// # Errors
    /// Fails if queue is full or actor is disconnected
    #[allow(clippy::result_unit_err)]
    pub async fn do_send<M>(&self, message: M)
    where
        M: Message + Send + 'static,
        M::Result: Send,
        A: ContextHandler<M>,
    {
        let envelope = SyncEnvelopeProxy::pack(message, None);
        // TODO: propagate the error.
        let _error = self.sender.send(envelope).await;
    }

    /// Constructs recipient for sending only specific messages (without answers)
    pub fn recipient<M>(&self) -> Recipient<M>
    where
        M: Message<Result = ()> + Send + 'static,
        A: ContextHandler<M>,
    {
        Recipient(Box::new(self.clone()))
    }

    /// Constructs address which will never panic on sending.
    ///
    /// Beware: You need to make sure that this actor will be always alive
    pub fn expect_running(self) -> AlwaysAddr<A> {
        AlwaysAddr(self)
    }
}

/// Address of an actor which is always alive.
#[derive(Debug)]
pub struct AlwaysAddr<A: Actor>(Addr<A>);

impl<A: Actor> Clone for AlwaysAddr<A> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<A: Actor> Deref for AlwaysAddr<A> {
    type Target = Addr<A>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A: Actor> DerefMut for AlwaysAddr<A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<A: Actor> AlwaysAddr<A> {
    /// Send a message and wait for an answer.
    pub async fn send<M>(&self, message: M) -> M::Result
    where
        M: Message + Send + 'static,
        M::Result: Send,
        A: ContextHandler<M>,
    {
        #[allow(clippy::expect_used)]
        self.deref()
            .send(message)
            .await
            .expect("Failed to get response from actor. It should have never failed!")
    }
}

impl<M> From<mpsc::Sender<M>> for Recipient<M>
where
    M: Message<Result = ()> + Send + 'static + Debug,
    M::Result: Send,
{
    fn from(sender: mpsc::Sender<M>) -> Self {
        Self(Box::new(sender))
    }
}

/// Address of actor. Can be used to send messages to it.
pub struct Recipient<M: Message<Result = ()>>(Box<dyn Sender<M> + Sync + Send + 'static>);

impl<M: Message<Result = ()> + Send> Recipient<M> {
    /// Send message to actor
    pub async fn send(&self, m: M) {
        self.0.send(m).await
    }
}

#[async_trait::async_trait]
trait Sender<M: Message<Result = ()>> {
    async fn send(&self, m: M);
}

#[async_trait::async_trait]
impl<A, M> Sender<M> for Addr<A>
where
    M: Message<Result = ()> + Send + 'static,
    A: ContextHandler<M>,
{
    async fn send(&self, m: M) {
        self.do_send(m).await
    }
}

#[async_trait::async_trait]
impl<M> Sender<M> for mpsc::Sender<M>
where
    M: Message<Result = ()> + Send + 'static + Debug,
{
    async fn send(&self, m: M) {
        let _result = self.send(m).await;
    }
}

/// Actor trait
#[async_trait::async_trait]
pub trait Actor: Send + Sized + 'static {
    /// Capacity of actor queue
    fn mailbox_capacity(&self) -> usize {
        100
    }

    /// At start hook of actor
    async fn on_start(&mut self, _ctx: &mut Context<Self>) {}

    /// At stop hook of actor
    async fn on_stop(&mut self, _ctx: &mut Context<Self>) {}

    /// Initialize actor with its address.
    fn preinit(self) -> InitializedActor<Self> {
        let mailbox_capacity = self.mailbox_capacity();
        InitializedActor::new(self, mailbox_capacity)
    }

    /// Initialize actor with default values
    fn preinit_default() -> InitializedActor<Self>
    where
        Self: Default,
    {
        Self::default().preinit()
    }

    /// Starts an actor and returns its address
    async fn start(self) -> Addr<Self> {
        self.preinit().start().await
    }

    /// Starts an actor with default values and returns its address
    async fn start_default() -> Addr<Self>
    where
        Self: Default,
    {
        Self::default().start().await
    }
}

/// Initialized actor. Mainly used to take address before starting it.
#[derive(Debug)]
pub struct InitializedActor<A: Actor> {
    /// Address of actor
    pub address: Addr<A>,
    /// Actor itself
    pub actor: A,
    receiver: Receiver<Envelope<A>>,
}

impl<A: Actor> InitializedActor<A> {
    /// Constructor.
    pub fn new(actor: A, mailbox_capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(mailbox_capacity);
        InitializedActor {
            actor,
            address: Addr::new(sender),
            receiver,
        }
    }

    /// Start actor
    pub async fn start(self) -> Addr<A> {
        let address = self.address;
        let mut receiver = self.receiver;
        let mut actor = self.actor;
        let (handle_sender, handle_receiver) = oneshot::channel();
        let move_addr = address.clone();
        let actor_future = async move {
            #[allow(clippy::expect_used)]
            let join_handle = handle_receiver
                .await
                .expect("Unreachable as the message is always sent.");
            let mut ctx = Context::new(move_addr.clone(), join_handle);
            actor.on_start(&mut ctx).await;
            while let Some(Envelope(mut message)) = receiver.recv().await {
                EnvelopeProxy::handle(&mut *message, &mut actor, &mut ctx).await;
            }
            iroha_logger::error!(actor = std::any::type_name::<A>(), "Actor stopped");
            actor.on_stop(&mut ctx).await;
        }
        .in_current_span();
        #[cfg(not(feature = "deadlock_detection"))]
        let join_handle = task::spawn(actor_future);
        #[cfg(feature = "deadlock_detection")]
        let join_handle = deadlock::spawn_task_with_actor_id(address.actor_id, actor_future);
        // TODO: propagate the error.
        let _error = handle_sender.send(join_handle);
        address
    }
}

/// Message trait for setting result of message
pub trait Message {
    /// Result type of message
    type Result: 'static;
}

/// Trait for actor for handling specific message type
#[async_trait::async_trait]
pub trait ContextHandler<M: Message>: Actor {
    /// Result of handler
    type Result: MessageResponse<M>;

    /// Message handler
    async fn handle(&mut self, ctx: &mut Context<Self>, msg: M) -> Self::Result;
}

/// Trait for actor for handling specific message type without context
#[async_trait::async_trait]
pub trait Handler<M: Message>: Actor {
    /// Result of handler
    type Result: MessageResponse<M>;

    /// Message handler
    async fn handle(&mut self, msg: M) -> Self::Result;
}

#[async_trait::async_trait]
impl<M: Message + Send + 'static, S: Handler<M>> ContextHandler<M> for S {
    type Result = S::Result;

    async fn handle(&mut self, _: &mut Context<Self>, msg: M) -> Self::Result {
        Handler::handle(self, msg).await
    }
}

/// Dev trait for Message responding
#[async_trait::async_trait]
pub trait MessageResponse<M: Message>: Send {
    /// Handles message
    async fn handle(self, sender: oneshot::Sender<M::Result>);
}

#[async_trait::async_trait]
impl<M> MessageResponse<M> for M::Result
where
    M: Message,
    M::Result: Send,
{
    async fn handle(self, sender: oneshot::Sender<M::Result>) {
        drop(sender.send(self));
    }
}

/// Context for execution of actor
#[derive(Debug)]
pub struct Context<A: Actor> {
    addr: Addr<A>,
    handle: JoinHandle<()>,
}

impl<A: Actor> Context<A> {
    /// Default constructor
    pub fn new(addr: Addr<A>, handle: JoinHandle<()>) -> Self {
        Self { addr, handle }
    }

    /// Gets an address of current actor
    pub fn addr(&self) -> Addr<A> {
        self.addr.clone()
    }

    /// Gets an recipient for current actor with specified message type
    pub fn recipient<M>(&self) -> Recipient<M>
    where
        M: Message<Result = ()> + Send + 'static,
        A: ContextHandler<M>,
    {
        self.addr().recipient()
    }

    /// Sends actor specified message
    pub fn notify<M>(&self, message: M)
    where
        M: Message<Result = ()> + Send + 'static,
        A: ContextHandler<M>,
    {
        let addr = self.addr();
        drop(task::spawn(
            async move { addr.do_send(message).await }.in_current_span(),
        ));
    }

    /// Sends actor specified message in some time
    pub fn notify_later<M>(&self, message: M, later: Duration)
    where
        M: Message<Result = ()> + Send + 'static,
        A: Handler<M>,
    {
        let addr = self.addr();
        drop(task::spawn(
            async move {
                time::sleep(later).await;
                addr.do_send(message).await
            }
            .in_current_span(),
        ));
    }

    /// Sends actor specified message in a loop with specified duration
    pub fn notify_every<M>(&self, every: Duration)
    where
        M: Message<Result = ()> + Default + Send + 'static,
        A: Handler<M>,
    {
        let addr = self.addr();
        drop(task::spawn(
            async move {
                loop {
                    time::sleep(every).await;
                    addr.do_send(M::default()).await
                }
            }
            .in_current_span(),
        ));
    }

    /// Notifies actor with items from stream
    pub fn notify_with<M, S>(&self, stream: S)
    where
        M: Message<Result = ()> + Send + 'static,
        S: Stream<Item = M> + Send + 'static,
        A: Handler<M>,
    {
        let addr = self.addr();
        drop(task::spawn(
            async move {
                futures::pin_mut!(stream);
                while let Some(item) = stream.next().await {
                    addr.do_send(item).await;
                }
            }
            .in_current_span(),
        ));
    }

    /// Notifies actor with items from stream
    pub fn notify_with_context<M, S>(&self, stream: S)
    where
        M: Message<Result = ()> + Send + 'static,
        S: Stream<Item = M> + Send + 'static,
        A: ContextHandler<M>,
    {
        let addr = self.addr();
        drop(task::spawn(
            async move {
                futures::pin_mut!(stream);
                while let Some(item) = stream.next().await {
                    addr.do_send(item).await;
                }
            }
            .in_current_span(),
        ));
    }
}
