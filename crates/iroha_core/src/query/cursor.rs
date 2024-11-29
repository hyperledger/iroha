//! Module with cursor-based pagination functional like [`Batched`].

use std::{fmt::Debug, num::NonZeroU64};

use iroha_data_model::{
    prelude::SelectorTuple,
    query::{
        dsl::{EvaluateSelector, HasProjection, SelectorMarker},
        QueryOutputBatchBox, QueryOutputBatchBoxTuple,
    },
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// An error with cursor processing.
#[derive(
    Debug,
    displaydoc::Display,
    thiserror::Error,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
)]
pub enum Error {
    /// The server's cursor does not match the provided cursor.
    Mismatch,
    /// There aren't enough items to proceed.
    Done,
}

fn evaluate_selector_tuple<T>(
    batch: Vec<T>,
    selector: &SelectorTuple<T>,
) -> QueryOutputBatchBoxTuple
where
    T: HasProjection<SelectorMarker, AtomType = ()> + 'static,
    T::Projection: EvaluateSelector<T>,
{
    let mut batch_tuple = Vec::new();

    let mut iter = selector.iter().peekable();

    while let Some(item) = iter.next() {
        if iter.peek().is_none() {
            // do not clone the last item
            batch_tuple.push(item.project(batch.into_iter()));
            return QueryOutputBatchBoxTuple { tuple: batch_tuple };
        }

        batch_tuple.push(item.project_clone(batch.iter()));
    }

    // this should only happen for empty selectors
    QueryOutputBatchBoxTuple { tuple: batch_tuple }
}

trait BatchedTrait {
    fn next_batch(
        &mut self,
        cursor: u64,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<NonZeroU64>), Error>;
    fn remaining(&self) -> u64;
}

struct BatchedInner<I>
where
    I: ExactSizeIterator,
    I::Item: HasProjection<SelectorMarker, AtomType = ()>,
{
    iter: I,
    selector: SelectorTuple<I::Item>,
    batch_size: NonZeroU64,
    cursor: Option<u64>,
}

impl<I> BatchedTrait for BatchedInner<I>
where
    I: ExactSizeIterator,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + 'static,
    <I::Item as HasProjection<SelectorMarker>>::Projection: EvaluateSelector<I::Item>,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    fn next_batch(
        &mut self,
        cursor: u64,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<NonZeroU64>), Error> {
        let Some(server_cursor) = self.cursor else {
            // the server is done with the iterator
            return Err(Error::Done);
        };

        if cursor != server_cursor {
            // the cursor doesn't match
            return Err(Error::Mismatch);
        }

        let expected_batch_size: usize = self
            .batch_size
            .get()
            .try_into()
            .expect("`u32` should always fit into `usize`");

        let mut current_batch_size = 0;
        let batch: Vec<I::Item> = self
            .iter
            .by_ref()
            .inspect(|_| current_batch_size += 1)
            .take(
                self.batch_size
                    .get()
                    .try_into()
                    .expect("`u32` should always fit into `usize`"),
            )
            .collect();

        // evaluate the requested projections
        let batch = evaluate_selector_tuple(batch, &self.selector);

        // did we get enough elements to continue?
        if current_batch_size >= expected_batch_size {
            self.cursor = Some(
                cursor
                    .checked_add(current_batch_size as u64)
                    .expect("Cursor size should never reach the platform limit"),
            );
        } else {
            self.cursor = None;
        }

        Ok((
            batch,
            self.cursor
                .map(|cursor| NonZeroU64::new(cursor).expect("Cursor is never 0")),
        ))
    }

    fn remaining(&self) -> u64 {
        self.iter.len() as u64
    }
}

/// A query output iterator that combines evaluating selectors, batching and type erasure.
pub struct ErasedQueryIterator {
    inner: Box<dyn BatchedTrait + Send + Sync>,
}

impl Debug for ErasedQueryIterator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryBatchedErasedIterator").finish()
    }
}

impl ErasedQueryIterator {
    /// Creates a new erased query iterator. Boxes the inner iterator to erase its type.
    pub fn new<I>(iter: I, selector: SelectorTuple<I::Item>, batch_size: NonZeroU64) -> Self
    where
        I: ExactSizeIterator + Send + Sync + 'static,
        I::Item: HasProjection<SelectorMarker, AtomType = ()> + 'static,
        <I::Item as HasProjection<SelectorMarker>>::Projection:
            EvaluateSelector<I::Item> + Send + Sync,
        QueryOutputBatchBox: From<Vec<I::Item>>,
    {
        Self {
            inner: Box::new(BatchedInner {
                iter,
                selector,
                batch_size,
                cursor: Some(0),
            }),
        }
    }

    /// Gets the next batch of results.
    ///
    /// Checks if the cursor matches the server's cursor.
    ///
    /// Returns the batch and the next cursor if the query iterator is not drained.
    ///
    /// # Errors
    ///
    /// - The cursor doesn't match the server's cursor.
    /// - There aren't enough items for the cursor.
    pub fn next_batch(
        &mut self,
        cursor: u64,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<NonZeroU64>), Error> {
        self.inner.next_batch(cursor)
    }

    /// Returns the number of remaining elements in the iterator.
    ///
    /// You should not rely on the reported amount being correct for safety, same as [`ExactSizeIterator::len`].
    pub fn remaining(&self) -> u64 {
        self.inner.remaining()
    }
}
