use std::num::{NonZeroU64, NonZeroUsize};

use crate::torii::{Error, Result};

pub trait Batch: IntoIterator + Sized {
    fn batched(self, fetch_size: NonZeroUsize) -> Batched<Self>;
}

impl<I: IntoIterator> Batch for I {
    fn batched(self, batch_size: NonZeroUsize) -> Batched<Self> {
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
    batch_size: NonZeroUsize,
    cursor: Option<u64>,
}

impl<I: IntoIterator + FromIterator<I::Item>> Batched<I> {
    pub(crate) fn next_batch(&mut self, cursor: Option<u64>) -> Result<(I, Option<NonZeroU64>)> {
        if cursor != self.cursor {
            return Err(Error::UnknownCursor);
        }

        let mut batch_size = 0;
        let batch: I = self
            .iter
            .by_ref()
            .inspect(|_| batch_size += 1)
            .take(self.batch_size.get())
            .collect();

        self.cursor = if let Some(cursor) = self.cursor {
            if batch_size >= self.batch_size.get() {
                let batch_size = self
                    .batch_size
                    .get()
                    .try_into()
                    .expect("usize should fit in u64");
                Some(
                    cursor
                        .checked_add(batch_size)
                        .expect("Cursor size should never reach the platform limit"),
                )
            } else {
                None
            }
        } else if batch_size >= self.batch_size.get() {
            Some(
                self.batch_size
                    .get()
                    .try_into()
                    .expect("usize should fit in u64"),
            )
        } else {
            None
        };

        Ok((
            batch,
            self.cursor
                .map(|cursor| NonZeroU64::new(cursor).expect("Cursor is never 0")),
        ))
    }

    pub fn is_depleted(&self) -> bool {
        self.cursor.is_none()
    }
}
