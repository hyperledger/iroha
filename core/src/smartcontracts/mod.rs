//! Iroha smart contract functionality. Most of the traits mentioned
//! [`isi`] or Iroha Special Instructions are the main way of
//! interacting with the [`WorldStateView`], even [`wasm`] based
//! smart-contracts can only interact with the `world`, via
//! instructions.

pub mod isi;
pub mod wasm;

use iroha_data_model::{
    isi::error::InstructionExecutionError as Error, prelude::*, query::error::QueryExecutionFail,
};
pub use isi::*;

use self::query::Lazy;
use crate::wsv::WorldStateView;

/// Trait implementations should provide actions to apply changes on [`WorldStateView`].
pub trait Execute {
    /// Apply actions to `wsv` on behalf of `authority`.
    ///
    /// # Errors
    /// Concrete to each implementer.
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error>;
}

/// This trait should be implemented for all Iroha Queries.
pub trait ValidQuery: iroha_data_model::query::Query
where
    Self::Output: Lazy,
{
    /// Execute query on the [`WorldStateView`].
    /// Should not mutate [`WorldStateView`]!
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    ///
    /// # Errors
    /// Concrete to each implementer
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<<Self::Output as Lazy>::Lazy<'wsv>, QueryExecutionFail>;
}
