//! Contains common types and traits to facilitate building and sending queries, either from the client or from smart contracts.

#[cfg(not(feature = "std"))]
use alloc::vec::{self, Vec};
#[cfg(feature = "std")]
use std::vec;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::query::{
    parameters::{FetchSize, Pagination, QueryParams, Sorting},
    predicate::{projectors, AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype},
    Query, QueryBox, QueryOutputBatchBox, QueryWithFilter, QueryWithFilterFor, QueryWithParams,
    SingularQueryBox, SingularQueryOutputBox,
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

    /// Starts an iterable query and returns the first batch of results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    fn start_query(
        &self,
        query: QueryWithParams,
    ) -> Result<(QueryOutputBatchBox, Option<Self::Cursor>), Self::Error>;

    /// Continues an iterable query from the given cursor and returns the next batch of results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    fn continue_query(
        cursor: Self::Cursor,
    ) -> Result<(QueryOutputBatchBox, Option<Self::Cursor>), Self::Error>;
}

/// An iterator over results of an iterable query.
#[derive(Debug)]
pub struct QueryIterator<E: QueryExecutor, T> {
    current_batch_iter: vec::IntoIter<T>,
    continue_cursor: Option<E::Cursor>,
}

impl<E, T> QueryIterator<E, T>
where
    E: QueryExecutor,
    Vec<T>: TryFrom<QueryOutputBatchBox>,
{
    /// Create a new iterator over iterable query results.
    ///
    /// # Errors
    ///
    /// Returns an error if the type of the batch does not match the expected type `T`.
    pub fn new(
        first_batch: QueryOutputBatchBox,
        continue_cursor: Option<E::Cursor>,
    ) -> Result<Self, <Vec<T> as TryFrom<QueryOutputBatchBox>>::Error> {
        let batch: Vec<T> = first_batch.try_into()?;

        Ok(Self {
            current_batch_iter: batch.into_iter(),
            continue_cursor,
        })
    }
}

impl<E, T> Iterator for QueryIterator<E, T>
where
    E: QueryExecutor,
    Vec<T>: TryFrom<QueryOutputBatchBox>,
    <Vec<T> as TryFrom<QueryOutputBatchBox>>::Error: core::fmt::Debug,
{
    type Item = Result<T, E::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // if we haven't exhausted the current batch yet - return it
        if let Some(item) = self.current_batch_iter.next() {
            return Some(Ok(item));
        }

        // no cursor means the query result is exhausted or an error occurred on one of the previous iterations
        let cursor = self.continue_cursor.take()?;

        // get a next batch from iroha
        let (batch, cursor) = match E::continue_query(cursor) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        self.continue_cursor = cursor;

        // downcast the batch to the expected type
        // we've already downcast the first batch to the expected type, so if iroha returns a different type here, it surely is a bug
        let batch: Vec<T> = batch
            .try_into()
            .expect("BUG: iroha returned unexpected type in iterable query");

        self.current_batch_iter = batch.into_iter();

        self.next()
    }
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
pub struct QueryBuilder<'e, E, Q, P> {
    query_executor: &'e E,
    query: Q,
    filter: CompoundPredicate<P>,
    pagination: Pagination,
    sorting: Sorting,
    fetch_size: FetchSize,
}

impl<'a, E, Q, P> QueryBuilder<'a, E, Q, P>
where
    Q: Query,
    Q::Item: HasPredicateBox<PredicateBoxType = P>,
{
    /// Create a new iterable query builder for a given backend and query.
    pub fn new(query_executor: &'a E, query: Q) -> Self {
        Self {
            query_executor,
            query,
            filter: CompoundPredicate::PASS,
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        }
    }
}

impl<E, Q, P> QueryBuilder<'_, E, Q, P> {
    /// Only return results that match the given predicate.
    ///
    /// If multiple filters are added, they are combined with a logical AND.
    #[must_use]
    pub fn filter(self, filter: CompoundPredicate<P>) -> Self {
        Self {
            filter: self.filter.and(filter),
            ..self
        }
    }

    /// Only return results that match the predicate constructed with the given closure.
    ///
    /// If multiple filters are added, they are combined with a logical AND.
    #[must_use]
    pub fn filter_with<B, O>(self, predicate_builder: B) -> Self
    where
        P: HasPrototype,
        B: FnOnce(P::Prototype<projectors::BaseProjector<P>>) -> O,
        O: AstPredicate<P>,
    {
        use crate::query::predicate::predicate_ast_extensions::AstPredicateExt as _;

        self.filter(predicate_builder(Default::default()).normalize())
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

impl<E, Q, P> QueryBuilder<'_, E, Q, P>
where
    E: QueryExecutor,
    Q: Query,
    Q::Item: HasPredicateBox<PredicateBoxType = P>,
    QueryBox: From<QueryWithFilterFor<Q>>,
    Vec<Q::Item>: TryFrom<QueryOutputBatchBox>,
    <Vec<Q::Item> as TryFrom<QueryOutputBatchBox>>::Error: core::fmt::Debug,
{
    /// Execute the query, returning an iterator over its results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn execute(self) -> Result<QueryIterator<E, Q::Item>, E::Error> {
        let with_filter = QueryWithFilter::new(self.query, self.filter);
        let boxed: QueryBox = with_filter.into();

        let query = QueryWithParams {
            query: boxed,
            params: QueryParams {
                pagination: self.pagination,
                sorting: self.sorting,
                fetch_size: self.fetch_size,
            },
        };

        let (first_batch, continue_cursor) = self.query_executor.start_query(query)?;

        let iterator = QueryIterator::<E, Q::Item>::new(first_batch, continue_cursor)
            .expect(
                "INTERNAL BUG: iroha returned unexpected type in iterable query. Is there a schema mismatch?",
            );

        Ok(iterator)
    }
}

impl<E, Q, P> Clone for QueryBuilder<'_, E, Q, P>
where
    Q: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            query_executor: self.query_executor,
            query: self.query.clone(),
            filter: self.filter.clone(),
            pagination: self.pagination,
            sorting: self.sorting.clone(),
            fetch_size: self.fetch_size,
        }
    }
}

/// An extension trait for query builders that provides convenience methods to execute queries.
pub trait QueryBuilderExt<E, Q>
where
    E: QueryExecutor,
    Q: Query,
{
    /// Execute the query, returning all the results collected into a vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    fn execute_all(self) -> Result<Vec<Q::Item>, E::Error>;

    /// Execute the query, constraining the number of results to zero or one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails or if more than one result is returned.
    fn execute_single_opt(self) -> Result<Option<Q::Item>, SingleQueryError<E::Error>>;

    /// Execute the query, constraining the number of results to exactly one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails or if zero or more than one result is returned.
    fn execute_single(self) -> Result<Q::Item, SingleQueryError<E::Error>>;
}

impl<E, Q, P> QueryBuilderExt<E, Q> for QueryBuilder<'_, E, Q, P>
where
    E: QueryExecutor,
    Q: Query,
    Q::Item: HasPredicateBox<PredicateBoxType = P>,
    QueryBox: From<QueryWithFilterFor<Q>>,
    Vec<Q::Item>: TryFrom<QueryOutputBatchBox>,
    <Vec<Q::Item> as TryFrom<QueryOutputBatchBox>>::Error: core::fmt::Debug,
{
    fn execute_all(self) -> Result<Vec<Q::Item>, E::Error> {
        self.execute()?.collect::<Result<Vec<_>, _>>()
    }

    fn execute_single_opt(self) -> Result<Option<Q::Item>, SingleQueryError<E::Error>> {
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

    fn execute_single(self) -> Result<Q::Item, SingleQueryError<E::Error>> {
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
