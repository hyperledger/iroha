use crate::query::{
    builder::{
        batch_downcast::{HasTypedBatchIter, TypedBatchDowncastError},
        QueryExecutor,
    },
    QueryOutputBatchBoxTuple,
};

/// An iterator over results of an iterable query.
#[derive(Debug)]
pub struct QueryIterator<E: QueryExecutor, T: HasTypedBatchIter> {
    current_batch_iter: T::TypedBatchIter,
    remaining_items: u64,
    continue_cursor: Option<E::Cursor>,
}

impl<E, T> QueryIterator<E, T>
where
    E: QueryExecutor,
    T: HasTypedBatchIter,
{
    /// Create a new iterator over iterable query results.
    ///
    /// # Errors
    ///
    /// Returns an error if the type of the batch does not match the expected type `T`.
    pub fn new(
        first_batch: QueryOutputBatchBoxTuple,
        remaining_items: u64,
        continue_cursor: Option<E::Cursor>,
    ) -> Result<Self, TypedBatchDowncastError> {
        let batch_iter = T::downcast(first_batch)?;

        Ok(Self {
            current_batch_iter: batch_iter,
            remaining_items,
            continue_cursor,
        })
    }
}

impl<E, T> Iterator for QueryIterator<E, T>
where
    E: QueryExecutor,
    T: HasTypedBatchIter,
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
        let (batch, remaining_items, cursor) = match E::continue_query(cursor) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        self.continue_cursor = cursor;

        // downcast the batch to the expected type
        // we've already downcast the first batch to the expected type, so if iroha returns a different type here, it surely is a bug
        let batch_iter =
            T::downcast(batch).expect("BUG: iroha returned unexpected type in iterable query");

        self.current_batch_iter = batch_iter;
        self.remaining_items = remaining_items;

        self.next()
    }
}

impl<E, T> ExactSizeIterator for QueryIterator<E, T>
where
    E: QueryExecutor,
    T: HasTypedBatchIter,
{
    fn len(&self) -> usize {
        self.remaining_items
            .try_into()
            .ok()
            .and_then(|r: usize| r.checked_add(self.current_batch_iter.len()))
            .expect("should be within the range of usize")
    }
}
