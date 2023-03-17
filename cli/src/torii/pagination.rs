use iroha_data_model::prelude::*;

/// Describes a collection to which pagination can be applied.
/// Implemented for the [`Iterator`] implementors.
pub trait Paginate: Iterator + Sized {
    /// Return a paginated [`Iterator`].
    fn paginate(self, pagination: Pagination) -> Paginated<Self>;
}

impl<I: Iterator + Sized> Paginate for I {
    fn paginate(self, pagination: Pagination) -> Paginated<Self> {
        Paginated {
            pagination,
            iter: self,
        }
    }
}

/// Paginated [`Iterator`].
/// Not recommended to use directly, only use in iterator chains.
#[derive(Debug)]
pub struct Paginated<I: Iterator> {
    pagination: Pagination,
    iter: I,
}

impl<I: Iterator> Iterator for Paginated<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(limit) = self.pagination.limit.as_mut() {
            if *limit == 0 {
                return None;
            }

            *limit -= 1
        }

        #[allow(clippy::option_if_let_else)]
        // Required because of E0524. 2 closures with unique refs to self
        if let Some(start) = self.pagination.start.take() {
            self.iter
                .nth(start.try_into().expect("u32 should always fit in usize"))
        } else {
            self.iter.next()
        }
    }
}

/// Filter for warp which extracts pagination
pub fn paginate() -> impl warp::Filter<Extract = (Pagination,), Error = warp::Rejection> + Copy {
    warp::query()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(None, None))
                .collect::<Vec<_>>(),
            vec![1_i32, 2_i32, 3_i32]
        )
    }

    #[test]
    fn start() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(Some(0), None))
                .collect::<Vec<_>>(),
            vec![1_i32, 2_i32, 3_i32]
        );
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(Some(1), None))
                .collect::<Vec<_>>(),
            vec![2_i32, 3_i32]
        );
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(Some(3), None))
                .collect::<Vec<_>>(),
            Vec::<i32>::new()
        );
    }

    #[test]
    fn limit() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(None, Some(0)))
                .collect::<Vec<_>>(),
            Vec::<i32>::new()
        );
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(None, Some(2)))
                .collect::<Vec<_>>(),
            vec![1_i32, 2_i32]
        );
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(None, Some(4)))
                .collect::<Vec<_>>(),
            vec![1_i32, 2_i32, 3_i32]
        );
    }

    #[test]
    fn start_and_limit() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination::new(Some(1), Some(1)))
                .collect::<Vec<_>>(),
            vec![2_i32]
        )
    }
}
