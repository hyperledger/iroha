//! Module which is used for deadlock detection of actors

#![allow(clippy::expect_used, clippy::panic)]

use std::fmt::{self, Debug, Display};
use std::ops::{Deref, DerefMut};
use std::{
    cmp::{Eq, PartialEq},
    time::Duration,
};

use async_std::task::{self, current, Task, TaskId};
use once_cell::sync::Lazy;
use petgraph::graph::Graph;
use petgraph::{algo, graph::NodeIndex};

use super::*;

#[derive(Clone, Copy)]
pub struct ActorId {
    pub name: Option<&'static str>,
    pub id: TaskId,
}

impl ActorId {
    pub const fn new(id: TaskId) -> Self {
        Self { name: None, id }
    }
}

impl Display for ActorId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(name) = &self.name {
            write!(f, "{}:{}", name, self.id)
        } else {
            write!(f, "<unknown>:{}", self.id)
        }
    }
}

impl Debug for ActorId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self, f)
    }
}

impl PartialEq for ActorId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for ActorId {}

impl From<&Task> for ActorId {
    fn from(task: &Task) -> Self {
        Self::new(task.id())
    }
}

#[derive(Default)]
struct DeadlockActor(Graph<ActorId, ()>);

impl Deref for DeadlockActor {
    type Target = Graph<ActorId, ()>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DeadlockActor {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

struct Reminder;
struct AddEdge {
    from: ActorId,
    to: ActorId,
}
struct RemoveEdge {
    from: ActorId,
    to: ActorId,
}
impl Message for Reminder {
    type Result = ();
}
impl Message for AddEdge {
    type Result = ();
}
impl Message for RemoveEdge {
    type Result = ();
}

impl DeadlockActor {
    fn find_or_create_from_to(
        &mut self,
        from: ActorId,
        to: ActorId,
    ) -> (NodeIndex<u32>, NodeIndex<u32>) {
        let (mut from_idx, mut to_idx) = (None, None);
        for i in self.node_indices() {
            if self[i] == from {
                from_idx = Some(i);
            } else if self[i] == to {
                to_idx = Some(i);
            }
        }
        (
            from_idx.unwrap_or_else(|| self.add_node(from)),
            to_idx.unwrap_or_else(|| self.add_node(to)),
        )
    }

    fn has_cycle(&self) -> bool {
        algo::is_cyclic_directed(&self.0)
    }
}

#[async_trait::async_trait]
impl Actor for DeadlockActor {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        let recipient = ctx.recipient::<Reminder>();
        drop(task::spawn(async move {
            loop {
                recipient.send(Reminder).await;
                task::sleep(Duration::from_millis(100)).await
            }
        }));
    }
}

// Reminder for DeadlockActor
#[async_trait::async_trait]
impl Handler<Reminder> for DeadlockActor {
    type Result = ();
    async fn handle(&mut self, _: &mut Context<Self>, _: Reminder) {
        if self.has_cycle() {
            panic!("Detected deadlock. Aborting. Cycle:\n{:#?}", self.0);
        }
    }
}

#[async_trait::async_trait]
impl Handler<AddEdge> for DeadlockActor {
    type Result = ();
    async fn handle(&mut self, _: &mut Context<Self>, AddEdge { from, to }: AddEdge) {
        let (from, to) = self.find_or_create_from_to(from, to);
        let _ = self.add_edge(from, to, ());
    }
}

#[async_trait::async_trait]
impl Handler<RemoveEdge> for DeadlockActor {
    type Result = ();
    async fn handle(&mut self, _: &mut Context<Self>, RemoveEdge { from, to }: RemoveEdge) {
        let (from, to) = self.find_or_create_from_to(from, to);
        let edge = self.find_edge(from, to).expect("Should be always present");
        let _ = self.remove_edge(edge);
    }
}

/// TODO: After switching to tokio move to using once cell and
/// force initing of actor beforehand in async api.
static DEADLOCK_ACTOR: Lazy<Addr<DeadlockActor>> =
    Lazy::new(|| task::block_on(DeadlockActor::start_default()));

pub async fn r#in(to: ActorId) {
    let from = ActorId::from(&current());
    DEADLOCK_ACTOR.do_send(AddEdge { from, to }).await;
}

pub async fn out(to: ActorId) {
    let from = ActorId::from(&current());
    DEADLOCK_ACTOR.do_send(RemoveEdge { from, to }).await;
}
