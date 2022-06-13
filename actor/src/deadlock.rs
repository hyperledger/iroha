//! Module which is used for deadlock detection of actors

#![allow(clippy::expect_used, clippy::panic)]

use std::{future::Future, time::Duration};

use derive_more::{Deref, DerefMut};
use once_cell::sync::Lazy;
use petgraph::{
    algo,
    graph::{Graph, NodeIndex},
};
use tokio::{
    task::{self, JoinHandle},
    time,
};

use super::*;

tokio::task_local! {
    static ACTOR_ID: ActorId;
}

/// Spawns a task with task local [`ActorId`].
pub fn spawn_task_with_actor_id<F>(actor_id: ActorId, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    task::spawn(ACTOR_ID.scope(actor_id, future))
}

/// Gets task local [`ActorId`] if this task has it or None.
pub fn task_local_actor_id() -> Option<ActorId> {
    ACTOR_ID.try_with(|id| *id).ok()
}

#[derive(Default, Deref, DerefMut)]
struct DeadlockActor(Graph<ActorId, ()>);

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
        task::spawn(async move {
            loop {
                recipient.send(Reminder).await;
                time::sleep(Duration::from_millis(100)).await
            }
        });
    }
}

// Reminder for DeadlockActor
#[async_trait::async_trait]
impl Handler<Reminder> for DeadlockActor {
    type Result = ();
    async fn handle(&mut self, _: Reminder) {
        assert!(
            !self.has_cycle(),
            "Detected deadlock. Aborting. Cycle:\n{:#?}",
            self.0
        );
    }
}

#[async_trait::async_trait]
impl Handler<AddEdge> for DeadlockActor {
    type Result = ();
    async fn handle(&mut self, AddEdge { from, to }: AddEdge) {
        let (from, to) = self.find_or_create_from_to(from, to);
        let _ = self.add_edge(from, to, ());
    }
}

#[async_trait::async_trait]
impl Handler<RemoveEdge> for DeadlockActor {
    type Result = ();
    async fn handle(&mut self, RemoveEdge { from, to }: RemoveEdge) {
        let (from, to) = self.find_or_create_from_to(from, to);
        let edge = self.find_edge(from, to).expect("Should be always present");
        let _ = self.remove_edge(edge);
    }
}

/// TODO: After switching to tokio move to using once cell and
/// force initing of actor beforehand in async api.
static DEADLOCK_ACTOR: Lazy<Addr<DeadlockActor>> = Lazy::new(|| {
    let actor = DeadlockActor::preinit_default();
    let address = actor.address.clone();
    let _result = task::spawn(actor.start());
    address
});

pub async fn r#in(to: ActorId, from: ActorId) {
    DEADLOCK_ACTOR.do_send(AddEdge { from, to }).await;
}

pub async fn out(to: ActorId, from: ActorId) {
    DEADLOCK_ACTOR.do_send(RemoveEdge { from, to }).await;
}
