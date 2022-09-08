//! Iroha smart contract functionality. Most of the traits mentioned
//! [`isi`] or Iroha Special Instructions are the main way of
//! interacting with the [`WorldStateView`], even [`wasm`] based
//! smart-contracts can only interact with the `world`, via
//! instructions.

pub mod isi;
pub mod wasm;

use iroha_data_model::prelude::*;
pub use isi::*;

use crate::wsv::WorldStateView;

/// Trait implementations should provide actions to apply changes on [`WorldStateView`].
pub trait Execute {
    /// Error type returned by execute function
    type Error: std::error::Error;

    /// Apply actions to `wsv` on behalf of `authority`.
    ///
    /// # Errors
    /// Concrete to each implementer.
    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error>;
}

/// Calculate the result of the expression without mutating the state.
pub trait Evaluate {
    /// The resulting type of the expression.
    type Value;
    /// Error type returned if the evaluation fails. Typically just [`isi::error::Error`].
    type Error: std::error::Error;

    /// Calculate result.
    ///
    /// # Errors
    /// Concrete to each implementer.
    fn evaluate(&self, wsv: &WorldStateView, context: &Context)
        -> Result<Self::Value, Self::Error>;
}

/// This trait should be implemented for all Iroha Queries.
pub trait ValidQuery: Query {
    /// Execute query on the [`WorldStateView`].
    /// Should not mutate [`WorldStateView`]!
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    ///
    /// # Errors
    /// Concrete to each implementer
    fn execute(&self, wsv: &WorldStateView) -> eyre::Result<Self::Output, query::Error>;

    /// Executes query and maps it into value
    ///
    /// # Errors
    /// Concrete to each implementer
    fn execute_into_value(&self, wsv: &WorldStateView) -> eyre::Result<Value, query::Error> {
        self.execute(wsv).map(Into::into)
    }
}
