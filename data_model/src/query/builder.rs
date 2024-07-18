//! Contains common types and traits to facilitate building and sending queries, either from the client or from smart contracts.

#[cfg(not(feature = "std"))]
use alloc::vec::{self, Vec};
#[cfg(feature = "std")]
use std::vec;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::query::{
    parameters::{FetchSize, IterableQueryParams, Pagination, Sorting},
    predicate::{projectors, AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype},
    IterableQuery, IterableQueryBox, IterableQueryOutputBatchBox, IterableQueryWithFilter,
    IterableQueryWithFilterFor, IterableQueryWithParams, SingularQueryBox, SingularQueryOutputBox,
};

/// A trait abstracting away concrete backend for executing queries against iroha.
pub trait QueryExecutor {
    /// A type of cursor used in iterable queries.
    ///
    /// The cursor type is an opaque type that allows to continue execution of an iterable query with [`Self::continue_iterable_query`]
    type Cursor;
    /// An error that can occur during query execution.
    type Error;
    // bound introduced to inject `SingularQueryError` in builder's `execute_single` and `execute_single_opt` methods
    /// An error type that combines `SingleQueryError` and `Self::Error`. Used by helper methods in query builder that constrain the number of results of an iterable query to one.
    type SingleError: From<SingleQueryError> + From<Self::Error>;

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
    fn start_iterable_query(
        &self,
        query: IterableQueryWithParams,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error>;

    /// Continues an iterable query from the given cursor and returns the next batch of results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    fn continue_iterable_query(
        cursor: Self::Cursor,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error>;
}

/// An iterator over results of an iterable query.
#[derive(Debug)]
pub struct IterableQueryIterator<E: QueryExecutor, T> {
    current_batch_iter: vec::IntoIter<T>,
    continue_cursor: Option<E::Cursor>,
}

impl<E, T> IterableQueryIterator<E, T>
where
    E: QueryExecutor,
    Vec<T>: TryFrom<IterableQueryOutputBatchBox>,
{
    /// Create a new iterator over iterable query results.
    ///
    /// # Errors
    ///
    /// Returns an error if the type of the batch does not match the expected type `T`.
    pub fn new(
        first_batch: IterableQueryOutputBatchBox,
        continue_cursor: Option<E::Cursor>,
    ) -> Result<Self, <Vec<T> as TryFrom<IterableQueryOutputBatchBox>>::Error> {
        let batch: Vec<T> = first_batch.try_into()?;

        Ok(Self {
            current_batch_iter: batch.into_iter(),
            continue_cursor,
        })
    }
}

impl<E, T> IterableQueryIterator<E, T>
where
    E: QueryExecutor,
{
    /// Returns the number of results remaining in the current batch.
    ///
    /// Note that it is NOT the number of results remaining in the query, which is not exposed by iroha API.
    pub fn remaining_in_current_batch(&self) -> usize {
        self.current_batch_iter.as_slice().len()
    }
}

impl<E, T> Iterator for IterableQueryIterator<E, T>
where
    E: QueryExecutor,
    Vec<T>: TryFrom<IterableQueryOutputBatchBox>,
    <Vec<T> as TryFrom<IterableQueryOutputBatchBox>>::Error: core::fmt::Debug,
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
        let (batch, cursor) = match E::continue_iterable_query(cursor) {
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
pub enum SingleQueryError {
    /// Expected exactly one query result, got none
    ExpectedOneGotNone,
    /// Expected exactly one query result, got more than one
    ExpectedOneGotMany,
    /// Expected one or zero query results, got more than one
    ExpectedOneOrZeroGotMany,
}

/// Struct that simplifies construction of an iterable query.
pub struct IterableQueryBuilder<'e, E, Q, P> {
    query_executor: &'e E,
    query: Q,
    filter: CompoundPredicate<P>,
    pagination: Pagination,
    sorting: Sorting,
    fetch_size: FetchSize,
}

impl<'a, E, Q, P> IterableQueryBuilder<'a, E, Q, P>
where
    Q: IterableQuery,
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

impl<E, Q, P> IterableQueryBuilder<'_, E, Q, P> {
    /// Only return results that match the specified predicate.
    ///
    /// If multiple filters are added, they are combined with a logical AND.
    #[must_use]
    pub fn with_filter<B, O>(self, predicate_builder: B) -> Self
    where
        P: HasPrototype,
        B: FnOnce(P::Prototype<projectors::BaseProjector<P>>) -> O,
        O: AstPredicate<P>,
    {
        use crate::query::predicate::predicate_ast_extensions::AstPredicateExt as _;

        self.with_raw_filter(predicate_builder(Default::default()).normalize())
    }

    /// Same as [`Self::with_filter`], but accepts a pre-constructed predicate in normalized form, instead of building a new one in place.
    #[must_use]
    pub fn with_raw_filter(self, filter: CompoundPredicate<P>) -> Self {
        Self {
            filter: self.filter.and(filter),
            ..self
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

impl<E, Q, P> IterableQueryBuilder<'_, E, Q, P>
where
    E: QueryExecutor,
    Q: IterableQuery,
    Q::Item: HasPredicateBox<PredicateBoxType = P>,
    IterableQueryBox: From<IterableQueryWithFilterFor<Q>>,
    Vec<Q::Item>: TryFrom<IterableQueryOutputBatchBox>,
    <Vec<Q::Item> as TryFrom<IterableQueryOutputBatchBox>>::Error: core::fmt::Debug,
{
    /// Execute the query, returning an iterator over its results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn execute(self) -> Result<IterableQueryIterator<E, Q::Item>, E::Error> {
        let with_filter = IterableQueryWithFilter::new(self.query, self.filter);
        let boxed: IterableQueryBox = with_filter.into();

        let query = IterableQueryWithParams {
            query: boxed,
            params: IterableQueryParams {
                pagination: self.pagination,
                sorting: self.sorting,
                fetch_size: self.fetch_size,
            },
        };

        let (first_batch, continue_cursor) = self.query_executor.start_iterable_query(query)?;

        let iterator = IterableQueryIterator::<E, Q::Item>::new(first_batch, continue_cursor)
            .expect(
                "iroha returned unexpected type in iterable query. Is there a schema mismatch?",
            );

        Ok(iterator)
    }

    /// Execute the query, returning all the results collected into a vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn execute_all(self) -> Result<Vec<Q::Item>, E::Error> {
        self.execute()?.collect::<Result<Vec<_>, _>>()
    }

    /// Execute the query, constraining the number of results to zero or one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails or if more than one result is returned.
    pub fn execute_single_opt(self) -> Result<Option<Q::Item>, E::SingleError> {
        let mut iter = self.execute()?;
        let first = iter.next().transpose()?;
        let second = iter.next().transpose()?;

        match (first, second) {
            (None, None) => Ok(None),
            (Some(result), None) => Ok(Some(result)),
            (Some(_), Some(_)) => Err(SingleQueryError::ExpectedOneOrZeroGotMany.into()),
            (None, Some(_)) => {
                unreachable!()
            }
        }
    }

    /// Execute the query, constraining the number of results to exactly one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails or if zero or more than one result is returned.
    pub fn execute_single(self) -> Result<Q::Item, E::SingleError> {
        let mut iter = self.execute()?;
        let first = iter.next().transpose()?;
        let second = iter.next().transpose()?;

        match (first, second) {
            (None, None) => Err(SingleQueryError::ExpectedOneGotNone.into()),
            (Some(result), None) => Ok(result),
            (Some(_), Some(_)) => Err(SingleQueryError::ExpectedOneGotMany.into()),
            (None, Some(_)) => {
                unreachable!()
            }
        }
    }
}

impl<E, Q, P> Clone for IterableQueryBuilder<'_, E, Q, P>
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
