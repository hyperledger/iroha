//!
//! Iroha simple actor framework.
//!

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
use envelope::{Envelope, SyncEnvelopeProxy, ToEnvelope};
#[cfg(not(feature = "deadlock_detection"))]
use tokio::task;
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        oneshot::{self, error::RecvError},
    },
    task::JoinHandle,
};
#[cfg(feature = "deadlock_detection")]
use {deadlock::ActorId, std::any::type_name};

pub mod broker;
#[cfg(feature = "deadlock_detection")]
mod deadlock;
mod envelope;

pub mod prelude {
    //! Module with most used items
    pub use super::{broker, Actor, Addr, Context, Handler, Message, Recipient};
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
            actor_id: ActorId::new(Some(type_name::<Self>())),
        }
    }

    /// Send a message and wait for an answer.
    /// # Errors
    /// Fails if noone will send message
    #[allow(unused_variables, clippy::expect_used)]
    pub async fn send<M>(&self, message: M) -> Result<M::Result, RecvError>
    where
        M: Message + Send + 'static,
        M::Result: Send,
        A: Handler<M>,
    {
        let (sender, reciever) = oneshot::channel();
        let envelope = SyncEnvelopeProxy::pack(message, Some(sender));
        #[cfg(feature = "deadlock_detection")]
        let from_actor_id_option = deadlock::task_local_actor_id();
        #[cfg(feature = "deadlock_detection")]
        if let Some(from_actor_id) = from_actor_id_option {
            deadlock::r#in(self.actor_id, from_actor_id).await;
        }
        // TODO: propagate the error.
        let _error = self.sender.send(envelope).await;
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
        A: Handler<M>,
    {
        let envelope = SyncEnvelopeProxy::pack(message, None);
        // TODO: propagate the error.
        let _error = self.sender.send(envelope).await;
    }

    /// Constructs recipient for sending only specific messages (without answers)
    pub fn recipient<M>(&self) -> Recipient<M>
    where
        M: Message<Result = ()> + Send + 'static,
        A: Handler<M>,
    {
        Recipient(Box::new(self.clone()))
    }
}

#[allow(missing_debug_implementations)]
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
    M::Result: Send,
    A: Handler<M>,
{
    async fn send(&self, m: M) {
        self.do_send(m).await
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

    /// Initilize actor with its address.
    fn init(self) -> InitializedActor<Self> {
        let mailbox_capacity = self.mailbox_capacity();
        InitializedActor::new(self, mailbox_capacity)
    }

    /// Initialize actor with default values
    fn init_default() -> InitializedActor<Self>
    where
        Self: Default,
    {
        Self::default().init()
    }
}

/// Initialized actor. Mainly used to take address before starting it.
#[derive(Debug)]
pub struct InitializedActor<A: Actor> {
    actor: A,
    address: Addr<A>,
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
    pub async fn start(self) {
        let address = self.address.clone();
        let mut receiver = self.receiver;
        let mut actor = self.actor;
        let (handle_sender, handle_receiver) = oneshot::channel();
        let actor_future = async move {
            #[allow(clippy::expect_used)]
            let join_handle = handle_receiver
                .await
                .expect("Unreachable as the message is always sent.");
            let mut ctx = Context::new(address.clone(), join_handle);
            actor.on_start(&mut ctx).await;
            while let Some(Envelope(mut message)) = receiver.recv().await {
                message.handle(&mut actor, &mut ctx).await;
            }
            actor.on_stop(&mut ctx).await;
        };
        #[cfg(not(feature = "deadlock_detection"))]
        let join_handle = task::spawn(actor_future);
        #[cfg(feature = "deadlock_detection")]
        let join_handle = deadlock::spawn_task_with_actor_id(self.address.actor_id, actor_future);
        // TODO: propagate the error.
        let _error = handle_sender.send(join_handle);
    }

    /// Address.
    pub fn address(&self) -> &Addr<A> {
        &self.address
    }
}

/// Message trait for setting result of message
pub trait Message {
    /// Result type of message
    type Result: 'static;
}

/// Trait for actor for handling specific message type
#[async_trait::async_trait]
pub trait Handler<M: Message>: Actor {
    /// Result of handler
    type Result: MessageResponse<M>;

    /// Message handler
    async fn handle(&mut self, ctx: &mut Context<Self>, msg: M) -> Self::Result;
}

/// Dev trait for Message responding
#[async_trait::async_trait]
pub trait MessageResponse<M: Message>: Send {
    /// Handles message
    async fn handle(self, sender: oneshot::Sender<M::Result>);
}

#[async_trait::async_trait]
impl<M: Message<Result = ()>> MessageResponse<M> for () {
    async fn handle(self, sender: oneshot::Sender<M::Result>) {
        let _ = sender.send(());
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
        A: Handler<M>,
    {
        self.addr().recipient()
    }
}
