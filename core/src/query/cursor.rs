//! Module with cursor-based pagination functional like [`Batched`].

use std::{fmt::Debug, num::NonZeroU64};

use derive_more::Display;
use iroha_data_model::query::QueryOutputBatchBox;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

trait BatchedTrait {
    fn next_batch(
        &mut self,
        cursor: u64,
    ) -> Result<(QueryOutputBatchBox, Option<NonZeroU64>), UnknownCursor>;
}

struct BatchedInner<I> {
    iter: I,
    batch_size: NonZeroU64,
    cursor: Option<u64>,
}

impl<I> BatchedTrait for BatchedInner<I>
where
    I: Iterator,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    fn next_batch(
        &mut self,
        cursor: u64,
    ) -> Result<(QueryOutputBatchBox, Option<NonZeroU64>), UnknownCursor> {
        let Some(server_cursor) = self.cursor else {
            // the server is done with the iterator
            return Err(UnknownCursor);
        };

        if cursor != server_cursor {
            // the cursor doesn't match
            return Err(UnknownCursor);
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
        let batch = batch.into();

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
}

/// Unknown cursor error.
///
/// Happens when client sends a cursor that doesn't match any server's cursor.
#[derive(Debug, Display, thiserror::Error, Copy, Clone, Serialize, Deserialize, Encode, Decode)]
#[display(fmt = "Unknown cursor")]
pub struct UnknownCursor;

/// A query output iterator that combines batching and type erasure.
pub struct QueryBatchedErasedIterator {
    inner: Box<dyn BatchedTrait + Send + Sync>,
}

impl Debug for QueryBatchedErasedIterator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryBatchedErasedIterator").finish()
    }
}

impl QueryBatchedErasedIterator {
    /// Creates a new batched iterator. Boxes the inner iterator to erase its type.
    pub fn new<I>(iter: I, batch_size: NonZeroU64) -> Self
    where
        I: Iterator + Send + Sync + 'static,
        QueryOutputBatchBox: From<Vec<I::Item>>,
    {
        Self {
            inner: Box::new(BatchedInner {
                iter,
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
    /// - The iterator is drained.
    pub fn next_batch(
        &mut self,
        cursor: u64,
    ) -> Result<(QueryOutputBatchBox, Option<NonZeroU64>), UnknownCursor> {
        self.inner.next_batch(cursor)
    }
}
