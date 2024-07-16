//! Module with cursor-based pagination functional like [`Batched`].

use std::num::{NonZeroU32, NonZeroU64};

use derive_more::Display;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Trait for iterators that can be batched.
pub trait Batch: IntoIterator + Sized {
    /// Pack iterator into batches of the given size.
    fn batched(self, fetch_size: NonZeroU32) -> Batched<Self>;
}

impl<I: IntoIterator> Batch for I {
    fn batched(self, batch_size: NonZeroU32) -> Batched<Self> {
        Batched {
            iter: self.into_iter(),
            batch_size,
            cursor: Some(0),
        }
    }
}

/// Paginated [`Iterator`].
/// Not recommended to use directly, only use in iterator chains.
#[derive(Debug)]
pub struct Batched<I: IntoIterator> {
    iter: I::IntoIter,
    batch_size: NonZeroU32,
    cursor: Option<u64>,
}

/// Unknown cursor error.
///
/// Happens when client sends a cursor that doesn't match any server's cursor.
#[derive(Debug, Display, thiserror::Error, Copy, Clone, Serialize, Deserialize, Encode, Decode)]
#[display(fmt = "Unknown cursor")]
pub struct UnknownCursor;

impl<I: IntoIterator + FromIterator<I::Item>> Batched<I> {
    pub(crate) fn next_batch(
        &mut self,
        cursor: Option<u64>,
    ) -> Result<(I, Option<NonZeroU64>), UnknownCursor> {
        if cursor != self.cursor {
            return Err(UnknownCursor);
        }

        let mut batch_size = 0;
        let batch: I = self
            .iter
            .by_ref()
            .inspect(|_| batch_size += 1)
            .take(
                self.batch_size
                    .get()
                    .try_into()
                    .expect("`u32` should always fit into `usize`"),
            )
            .collect();

        self.cursor = if let Some(cursor) = self.cursor {
            if batch_size >= self.batch_size.get() {
                let batch_size = self.batch_size.get().into();
                Some(
                    cursor
                        .checked_add(batch_size)
                        .expect("Cursor size should never reach the platform limit"),
                )
            } else {
                None
            }
        } else if batch_size >= self.batch_size.get() {
            Some(self.batch_size.get().into())
        } else {
            None
        };

        Ok((
            batch,
            self.cursor
                .map(|cursor| NonZeroU64::new(cursor).expect("Cursor is never 0")),
        ))
    }

    /// Check if all values where drained from the iterator.
    pub fn is_depleted(&self) -> bool {
        self.cursor.is_none()
    }
}
