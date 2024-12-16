//! Contains common types and traits to facilitate building and sending queries, either from the client or from smart contracts.

mod batch_downcast;
mod iter;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::marker::PhantomData;

use derive_where::derive_where;
pub use iter::QueryIterator;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::query::{
    builder::batch_downcast::HasTypedBatchIter,
    dsl::{
        BaseProjector, CompoundPredicate, HasPrototype, IntoSelectorTuple, PredicateMarker,
        SelectorMarker, SelectorTuple,
    },
    parameters::{FetchSize, Pagination, QueryParams, Sorting},
    Query, QueryBox, QueryOutputBatchBoxTuple, QueryWithFilter, QueryWithParams, SingularQueryBox,
    SingularQueryOutputBox,
};

/// A trait abstracting away concrete backend for executing queries against iroha.
pub trait QueryExecutor {
    /// A type of cursor used in iterable queries.
    ///
    /// The cursor type is an opaque type that allows to continue execution of an iterable query with [`Self::continue_query`]
    type Cursor;
    /// An error that can occur during query execution.
    type Error;

    /// Executes a singular query and returns its result.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    fn execute_singular_query(
        &self,
        query: SingularQueryBox,
    ) -> Result<SingularQueryOutputBox, Self::Error>;

    /// Starts an iterable query and returns the first batch of results, the remaining number of results and a cursor to continue the query.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    #[expect(clippy::type_complexity)]
    fn start_query(
        &self,
        query: QueryWithParams,
    ) -> Result<(QueryOutputBatchBoxTuple, u64, Option<Self::Cursor>), Self::Error>;

    /// Continues an iterable query from the given cursor and returns the next batch of results, the remaining number of results and a cursor to continue the query.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    #[expect(clippy::type_complexity)]
    fn continue_query(
        cursor: Self::Cursor,
    ) -> Result<(QueryOutputBatchBoxTuple, u64, Option<Self::Cursor>), Self::Error>;
}

/// An error that can occur when constraining the number of results of an iterable query to one.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    displaydoc::Display,
    Deserialize,
    Serialize,
    Decode,
    Encode,
)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SingleQueryError<E> {
    /// An error occurred during query execution
    QueryError(E),
    /// Expected exactly one query result, got none
    ExpectedOneGotNone,
    /// Expected exactly one query result, got more than one
    ExpectedOneGotMany,
    /// Expected one or zero query results, got more than one
    ExpectedOneOrZeroGotMany,
}

impl<E> From<E> for SingleQueryError<E> {
    fn from(e: E) -> Self {
        SingleQueryError::QueryError(e)
    }
}

/// Struct that simplifies construction of an iterable query.
#[derive_where(Clone; Q, CompoundPredicate<Q::Item>, SelectorTuple<Q::Item>)]
pub struct QueryBuilder<'e, E, Q, T>
where
    Q: Query,
{
    query_executor: &'e E,
    query: Q,
    filter: CompoundPredicate<Q::Item>,
    selector: SelectorTuple<Q::Item>,
    pagination: Pagination,
    sorting: Sorting,
    fetch_size: FetchSize,
    // NOTE: T is a phantom type used to denote the selected tuple in `selector`
    phantom: PhantomData<T>,
}

impl<'a, E, Q> QueryBuilder<'a, E, Q, Q::Item>
where
    Q: Query,
{
    /// Create a new iterable query builder for a given backend and query.
    pub fn new(query_executor: &'a E, query: Q) -> Self {
        Self {
            query_executor,
            query,
            filter: CompoundPredicate::PASS,
            selector: SelectorTuple::default(),
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
            phantom: PhantomData,
        }
    }
}

impl<'a, E, Q, T> QueryBuilder<'a, E, Q, T>
where
    Q: Query,
{
    /// Only return results that match the given predicate.
    ///
    /// If multiple filters are added, they are combined with a logical AND.
    #[must_use]
    pub fn filter(self, filter: CompoundPredicate<Q::Item>) -> Self {
        Self {
            filter: self.filter.and(filter),
            ..self
        }
    }

    /// Only return results that match the predicate constructed with the given closure.
    ///
    /// If multiple filters are added, they are combined with a logical AND.
    #[must_use]
    pub fn filter_with<B>(self, predicate_builder: B) -> Self
    where
        Q::Item: HasPrototype,
        B: FnOnce(
            <Q::Item as HasPrototype>::Prototype<
                PredicateMarker,
                BaseProjector<PredicateMarker, Q::Item>,
            >,
        ) -> CompoundPredicate<Q::Item>,
        <Q::Item as HasPrototype>::Prototype<
            PredicateMarker,
            BaseProjector<PredicateMarker, Q::Item>,
        >: Default,
    {
        self.filter(predicate_builder(Default::default()))
    }

    /// Return only the fields of the results specified by the given closure.
    ///
    /// You can select multiple fields by returning a tuple from the closure.
    #[must_use]
    pub fn select_with<B, O>(self, f: B) -> QueryBuilder<'a, E, Q, O::SelectedTuple>
    where
        Q::Item: HasPrototype,
        B: FnOnce(
            <Q::Item as HasPrototype>::Prototype<
                SelectorMarker,
                BaseProjector<SelectorMarker, Q::Item>,
            >,
        ) -> O,
        <Q::Item as HasPrototype>::Prototype<
            SelectorMarker,
            BaseProjector<SelectorMarker, Q::Item>,
        >: Default,
        O: IntoSelectorTuple<SelectingType = Q::Item>,
    {
        let new_selector = f(Default::default()).into_selector_tuple();

        QueryBuilder {
            query_executor: self.query_executor,
            query: self.query,
            filter: self.filter,
            selector: new_selector,
            pagination: self.pagination,
            sorting: self.sorting,
            fetch_size: self.fetch_size,
            phantom: PhantomData,
        }
    }

    /// Sort the results according to the specified sorting.
    #[must_use]
    pub fn with_sorting(self, sorting: Sorting) -> Self {
        Self { sorting, ..self }
    }

    /// Only return part of the results specified by the pagination.
    #[must_use]
    pub fn with_pagination(self, pagination: Pagination) -> Self {
        Self { pagination, ..self }
    }

    /// Change the batch size of the iterable query.
    ///
    /// Larger batch sizes reduce the number of round-trips to iroha peer, but require more memory.
    #[must_use]
    pub fn with_fetch_size(self, fetch_size: FetchSize) -> Self {
        Self { fetch_size, ..self }
    }
}

impl<E, Q, T> QueryBuilder<'_, E, Q, T>
where
    Q: Query,
    E: QueryExecutor,
    QueryBox: From<QueryWithFilter<Q>>,
    T: HasTypedBatchIter,
{
    /// Execute the query, returning an iterator over its results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn execute(self) -> Result<QueryIterator<E, T>, E::Error> {
        let with_filter = QueryWithFilter::new(self.query, self.filter, self.selector);
        let boxed: QueryBox = with_filter.into();

        let query = QueryWithParams {
            query: boxed,
            params: QueryParams {
                pagination: self.pagination,
                sorting: self.sorting,
                fetch_size: self.fetch_size,
            },
        };

        let (first_batch, remaining_items, continue_cursor) =
            self.query_executor.start_query(query)?;

        let iterator = QueryIterator::<E, T>::new(first_batch, remaining_items, continue_cursor)
            .expect(
                "INTERNAL BUG: iroha returned unexpected type in iterable query. Is there a schema mismatch?",
            );

        Ok(iterator)
    }
}

/// An extension trait for query builders that provides convenience methods to execute queries.
pub trait QueryBuilderExt<E, Q, T>
where
    E: QueryExecutor,
    Q: Query,
    T: HasTypedBatchIter,
{
    /// Execute the query, returning all the results collected into a vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    fn execute_all(self) -> Result<Vec<T>, E::Error>;

    /// Execute the query, constraining the number of results to zero or one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails or if more than one result is returned.
    fn execute_single_opt(self) -> Result<Option<T>, SingleQueryError<E::Error>>;

    /// Execute the query, constraining the number of results to exactly one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails or if zero or more than one result is returned.
    fn execute_single(self) -> Result<T, SingleQueryError<E::Error>>;
}

impl<E, Q, T> QueryBuilderExt<E, Q, T> for QueryBuilder<'_, E, Q, T>
where
    E: QueryExecutor,
    Q: Query,
    QueryBox: From<QueryWithFilter<Q>>,
    T: HasTypedBatchIter,
{
    fn execute_all(self) -> Result<Vec<T>, E::Error> {
        self.execute()?.collect::<Result<Vec<_>, _>>()
    }

    fn execute_single_opt(self) -> Result<Option<T>, SingleQueryError<E::Error>> {
        let mut iter = self.execute()?;
        let first = iter.next().transpose()?;
        let second = iter.next().transpose()?;

        match (first, second) {
            (None, None) => Ok(None),
            (Some(result), None) => Ok(Some(result)),
            (Some(_), Some(_)) => Err(SingleQueryError::ExpectedOneOrZeroGotMany),
            (None, Some(_)) => {
                unreachable!()
            }
        }
    }

    fn execute_single(self) -> Result<T, SingleQueryError<E::Error>> {
        let mut iter = self.execute()?;
        let first = iter.next().transpose()?;
        let second = iter.next().transpose()?;

        match (first, second) {
            (None, None) => Err(SingleQueryError::ExpectedOneGotNone),
            (Some(result), None) => Ok(result),
            (Some(_), Some(_)) => Err(SingleQueryError::ExpectedOneGotMany),
            (None, Some(_)) => {
                unreachable!()
            }
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::QueryBuilderExt;
}
