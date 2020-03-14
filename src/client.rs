pub mod command;
pub mod query;

use crate::client::{command::*, query::*};

#[derive(Default)]
pub struct Client {}

/// Representation of `Iroha` client.
impl Client {
    pub fn new() -> Self {
        Client {}
    }

    /// Command API entry point. Submits commands to `Iroha` peers.
    pub fn submit(&self, _command: Command) -> Result<(), ()> {
        Ok(())
    }

    /// Query API entry point for `Asset` domain.
    //TODO: generate DSL based on configuration?
    pub fn assets(&self) -> AssetsQueries {
        AssetsQueries {}
    }
}
