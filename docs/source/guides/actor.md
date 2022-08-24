# Actor model

The **Actor model** is a mathematical theory that treats “Actors” as the universal primitives of concurrent digital computation. The model has been used both as a framework for a theoretical understanding of concurrency, and as the theoretical basis for several practical implementations of concurrent systems.[\[1\]][link1]

If you want to get a feel of the actor model a good way to start will be to read some code on [Erlang][Erlang] or on modern [Elixir][Elixir].

## Properties

- Everything is an actor (no main function in erlang or elixir - just start an actor)
- An actor receives and reacts in certain ways to messages:
  + Send messages to other actors
  + Create new actors
  + Changes its state

There are no guarantees in terms of ordering. The only guarantee is that every actor response messages one by one.

## The simplest example

Lorem ipsum of OOP is the example of animal inheritance. As for actor system it is ping actor:

```rust
use iroha_actor::prelude::*;

struct PingActor { count: usize }

impl Actor for PingActor {}

struct Ping(usize);

impl Message for Ping {
    type Result = usize;
}

#[async_trait::async_trait]
impl Handler<Ping> for PingActor {
    type Result = usize;

    async fn handle(&mut self, Ping(cnt): Ping) -> usize {
        self.count += cnt;
        self.count
    }
}

let addr = PingActor(0).start().await;
assert_eq!(addr.send(10).unwrap(), 10);
```

## Unique rust properties

### Type safety

#### Address

Actors can receive messages iff they implement their handler (same for sending).

```rust
impl<A: Actor> Addr<A> {
    pub async fn send<M>(&self, message: M) -> Result<M::Result, Error>
    where
        M: Message,
        A: ContextHandler<M>;

    pub async fn do_send<M>(&self, message: M)
    where
        M: Message,
        A: ContextHandler<M>,
}
```

```rust
struct UnknownMessage;

let addr: Addr<PingActor> = PingActor(0).start().await;
addr.send(UnknownMessage).await // ERROR: Trait context handler is not implemented...
```

#### Recipient

There are also capability based feature. You can get a recipient (an address not for an actor, but for a message):

```rust
#[derive(Message)]
#[message(result = "()")]
struct Pong;

#[async_trait::async_trait]
impl Handler<Pong> for PingActor {
    type Result = ();
    async fn handle(&mut self, Pong: Pong) {
        println!("Pong!");
    }
}

let addr: Addr<PingActor> = PingActor(0).start().await;
let recipient: Recipient<Pong> = addr.recipient();
recipient.send(Ping(10)).await; // ERROR: Expected type Pong but got Ping
```

### Deadlock detection

There is deadlock detection for rust

Take a look at [this test](../../../actor/tests/deadlock.rs) for more.

### Broker

Broker is a way to signal some message to several actors which are interested in specific message.

- Or it can be interpreted to send not message, but a signal in which
might be interested several actors.
- Or it can be interpreted as pushing contract to actor side (if actor is interested in message, it can subscribe to it)

**BEWARE**: no typesafety here. You should make sure that at least one alive actor is subscribed to message, otherwise message will be dropped.

#### Examples

```rust
use iroha_actor::{prelude::*, broker::*};

#[derive(Clone)]
struct Message1(String);
impl Message for Message1 { type Result = (); }

#[derive(Clone)] struct Message2(String);
impl Message for Message2 { type Result = (); }

struct Actor1(Broker);
struct Actor2(Broker);

#[async_trait::async_trait]
impl Actor for Actor1 {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.0.subscribe::<Message1, _>(ctx);
        self.0.issue_send(Message2("Hello".to_string())).await;
    }
}

#[async_trait::async_trait]
impl Handler<Message1> for Actor1 {
    type Result = ();
    async fn handle(&mut self, Message1(msg): Message1) {
        println!("Actor1: {}", msg);
    }
}

#[async_trait::async_trait]
impl Actor for Actor2 {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.0.subscribe::<Message2, _>(ctx);
    }
}

#[async_trait::async_trait]
impl Handler<Message2> for Actor2 {
    type Result = ();
    async fn handle(&mut self, Message2(msg): Message2) {
        println!("Actor2: {}", msg);
        self.0.issue_send(Message1(msg.clone() + " world")).await;
    }
}

let broker = Broker::new();
Actor2(broker.clone()).start().await;
Actor1(broker).start().await;
// Actor2: Hello
// Actor1: Hello world
```

## Usefull features

### Delays and timers

Via `notify_*` family functions for actors:

- `notify` - send message once in some time
- `notify_every` - sends message every duration time. Basically timer, from which you can't unsubscribe :)
- `notify_with` - sinks stream into an actor

## Read more

- Paper with background for actor systems: [link][link1]
- Actix actor system book: [link](https://actix.rs/book/actix/)
- Akka actors in Java and Scala: [link](https://doc.akka.io/docs/akka/current/typed/actors.html)

## TODO

- [Supervisors](Supervisors) are great abstraction to do, as it lets to recover from unrecoverable scenarios.
- [Arbiters](Arbiters)

[Supervisors]: https://docs.rs/actix/latest/actix/struct.Supervisor.html
[link1]: https://arxiv.org/vc/arxiv/papers/1008/1008.1459v8.pdf
[Erlang]: https://en.wikipedia.org/wiki/Erlang_(programming_language)
[Elixir]: https://en.wikipedia.org/wiki/Elixir_(programming_language)
[Arbiters]: https://actix.rs/book/actix/sec-6-sync-arbiter.html
