#[cfg(not(feature = "std"))]
use alloc::vec::{self, Vec};
#[cfg(feature = "std")]
use std::vec;

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    prelude::FetchSize,
    query::{
        error::QueryExecutionFail,
        predicate::{projectors, AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype},
        IterableQuery, IterableQueryBox, IterableQueryOutputBatchBox, IterableQueryParams,
        IterableQueryWithFilter, IterableQueryWithFilterFor, IterableQueryWithParams, Pagination,
        SingularQueryBox, SingularQueryOutputBox, Sorting,
    },
};

pub trait QueryExecutor {
    type Cursor;
    type Error;
    // bound introduced to inject `SingularQueryError` in builder's `execute_single` and `execute_single_opt` methods
    type SingularError: From<SingleQueryError> + From<Self::Error>;

    fn execute_singular_query(
        &self,
        query: SingularQueryBox,
    ) -> Result<SingularQueryOutputBox, Self::Error>;

    fn start_iterable_query(
        &self,
        query: IterableQueryWithParams,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error>;

    fn continue_iterable_query(
        cursor: Self::Cursor,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error>;
}

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

        // no cursor means the query result is exhausted
        let Some(cursor) = self.continue_cursor.take() else {
            return None;
        };

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

        return self.next();
    }
}

#[derive(
    Debug,
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
    pub fn with_filter<B, O>(self, predicate_builder: B) -> Self
    where
        P: HasPrototype,
        B: FnOnce(P::Prototype<projectors::BaseProjector<P>>) -> O,
        O: AstPredicate<P>,
    {
        use crate::query::predicate::predicate_ast_extensions::AstPredicateExt as _;

        self.with_raw_filter(predicate_builder(Default::default()).normalize())
    }

    pub fn with_raw_filter(self, filter: CompoundPredicate<P>) -> Self {
        Self {
            filter: self.filter.and(filter),
            ..self
        }
    }

    pub fn with_sorting(self, sorting: Sorting) -> Self {
        Self { sorting, ..self }
    }

    pub fn with_pagination(self, pagination: Pagination) -> Self {
        Self { pagination, ..self }
    }

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

    pub fn execute_all(self) -> Result<Vec<Q::Item>, E::Error> {
        self.execute()?.collect::<Result<Vec<_>, _>>()
    }

    pub fn execute_single_opt(self) -> Result<Option<Q::Item>, E::SingularError> {
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

    pub fn execute_single(self) -> Result<Q::Item, E::SingularError> {
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
