//! Actor identification.
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]
use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    sync::atomic::{AtomicUsize, Ordering},
};

static ACTOR_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
pub struct ActorId {
    pub name: Option<&'static str>,
    pub id: usize,
}

impl ActorId {
    pub fn new(name: Option<&'static str>) -> Self {
        Self {
            name,
            id: ACTOR_ID_COUNTER.fetch_add(1, Ordering::SeqCst),
        }
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

impl Hash for ActorId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl PartialEq for ActorId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ActorId {}
