//! Module that opts different smartcontract runtime
//!
//! Currently supported only Iroha instructions

pub mod isi;

use std::error::Error;

use iroha_data_model::prelude::*;
pub use isi::*;

use super::wsv::WorldStateView;

/// Trait implementations should provide actions to apply changes on `WorldStateView`.
#[allow(clippy::missing_errors_doc)]
pub trait Execute {
    /// Error type returned by execute function
    type Error: Error;

    /// Apply actions to `wsv` on behalf of `authority`.
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error>;
}

/// Calculate the result of the expression without mutating the state.
#[allow(clippy::missing_errors_doc)]
pub trait Evaluate {
    /// The resulting type of the expression.
    type Value;

    /// Calculates result.
    fn evaluate(&self, wsv: &WorldStateView, context: &Context)
        -> iroha_error::Result<Self::Value>;
}

/// This trait should be implemented for all Iroha Queries.
#[allow(clippy::missing_errors_doc)]
pub trait Query: QueryOutput {
    /// Execute query on the `WorldStateView`.
    /// Should not mutate `WorldStateView`!
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    fn execute(&self, wsv: &WorldStateView) -> iroha_error::Result<Self::Output>;

    /// Executes query and maps it into value
    fn execute_into_value(&self, wsv: &WorldStateView) -> iroha_error::Result<Value> {
        self.execute(wsv).map(Into::into)
    }
}
