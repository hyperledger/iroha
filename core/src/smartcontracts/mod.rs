//! Iroha smart contract functionality. Most of the traits mentioned
//! [`isi`] or Iroha Special Instructions are the main way of
//! interacting with the [`State`], even [`wasm`] based
//! smart-contracts can only interact with the `world`, via
//! instructions.

pub mod isi;
pub mod wasm;

use iroha_data_model::{
    isi::error::InstructionExecutionError as Error,
    prelude::*,
    query::{
        error::QueryExecutionFail,
        predicate::{CompoundPredicate, HasPredicateBox},
    },
};
pub use isi::*;

use crate::state::{StateReadOnly, StateTransaction};

/// Trait implementations should provide actions to apply changes on [`StateTransaction`].
pub trait Execute {
    /// Apply actions to `state_transaction` on behalf of `authority`.
    ///
    /// # Errors
    /// Concrete to each implementer.
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error>;
}

/// This trait should be implemented for all iterable Iroha Queries.
pub trait ValidIterableQuery: iroha_data_model::query::IterableQuery
where
    Self::Item: HasPredicateBox,
{
    /// Execute a query on a read-only state.
    ///
    /// The filter is deliberately passed to the query implementation,
    ///  so it can be smart about it and use indexes if possible.
    ///
    /// # Errors
    /// Concrete to each implementer
    fn execute<'state>(
        self,
        filter: CompoundPredicate<<Self::Item as HasPredicateBox>::PredicateBoxType>,
        state_ro: &'state impl StateReadOnly,
    ) -> Result<impl Iterator<Item = Self::Item> + 'state, QueryExecutionFail>;
}

/// This trait should be implemented for all Iroha Queries.
pub trait ValidSingularQuery: iroha_data_model::query::SingularQuery {
    /// Execute query on the [`WorldSnapshot`].
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    ///
    /// # Errors
    /// Concrete to each implementer
    fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Self::Output, QueryExecutionFail>;
}
