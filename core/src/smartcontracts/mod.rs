//! Iroha smart contract functionality. Most of the traits mentioned
//! [`isi`] or Iroha Special Instructions are the main way of
//! interacting with the [`State`], even [`wasm`] based
//! smart-contracts can only interact with the `world`, via
//! instructions.

pub mod isi;
pub mod wasm;

use iroha_data_model::{
    isi::error::InstructionExecutionError as Error, prelude::*, query::error::QueryExecutionFail,
};
pub use isi::*;

use self::query::Lazy;
use crate::state::{StateSnapshot, StateTransaction};

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

/// This trait should be implemented for all Iroha Queries.
pub trait ValidQuery: iroha_data_model::query::Query
where
    Self::Output: Lazy,
{
    /// Execute query on the [`WorldSnapshot`].
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    ///
    /// # Errors
    /// Concrete to each implementer
    fn execute<'state>(
        &self,
        state_snapshot: &'state StateSnapshot<'state>,
    ) -> Result<<Self::Output as Lazy>::Lazy<'state>, QueryExecutionFail>;
}
