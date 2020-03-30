pub mod command;
pub mod query;

use crate::client::command::*;

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
}

pub mod assets {
    use crate::client::query::*;
    use crate::prelude::*;
    /// Query API entry point for `Asset` domain.
    pub fn by_id(account_id: Id) -> Query {
        GetAccountAssets::build_query(account_id)
    }
}
