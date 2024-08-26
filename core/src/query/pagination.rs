//! Module with [`Paginate`] iterator adaptor which provides [`paginate`] function.

use iroha_data_model::query::parameters::Pagination;

/// Describes a collection to which pagination can be applied.
/// Implemented for the [`Iterator`] implementors.
pub trait Paginate: Iterator + Sized {
    /// Return a paginated [`Iterator`].
    fn paginate(self, pagination: Pagination) -> Paginated<Self>;
}

impl<I: Iterator> Paginate for I {
    fn paginate(self, pagination: Pagination) -> Paginated<Self> {
        Paginated::new(pagination, self)
    }
}

/// Paginated [`Iterator`].
/// Not recommended to use directly, only use in iterator chains.
#[derive(Debug)]
pub struct Paginated<I: Iterator>(core::iter::Take<core::iter::Skip<I>>);

impl<I: Iterator> Paginated<I> {
    fn new(pagination: Pagination, iter: I) -> Self {
        Self(
            iter.skip(
                pagination
                    .offset
                    .try_into()
                    .expect("u64 should fit into usize"),
            )
            .take(pagination.limit.map_or_else(
                || usize::MAX,
                |limit| limit.get().try_into().expect("u64 should fit into usize"),
            )),
        )
    }
}

impl<I: Iterator> Iterator for Paginated<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::query::parameters::Pagination;
    use nonzero_ext::nonzero;

    use super::*;

    #[test]
    fn empty() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination {
                    limit: None,
                    offset: 0
                })
                .collect::<Vec<_>>(),
            vec![1_i32, 2_i32, 3_i32]
        )
    }

    #[test]
    fn start() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination {
                    limit: None,
                    offset: 1
                })
                .collect::<Vec<_>>(),
            vec![2_i32, 3_i32]
        );
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination {
                    limit: None,
                    offset: 3
                })
                .collect::<Vec<_>>(),
            Vec::<i32>::new()
        );
    }

    #[test]
    fn limit() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination {
                    limit: Some(nonzero!(2_u64)),
                    offset: 0
                })
                .collect::<Vec<_>>(),
            vec![1_i32, 2_i32]
        );
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination {
                    limit: Some(nonzero!(4_u64)),
                    offset: 0
                })
                .collect::<Vec<_>>(),
            vec![1_i32, 2_i32, 3_i32]
        );
    }

    #[test]
    fn start_and_limit() {
        assert_eq!(
            vec![1_i32, 2_i32, 3_i32]
                .into_iter()
                .paginate(Pagination {
                    limit: Some(nonzero!(1_u64)),
                    offset: 1,
                })
                .collect::<Vec<_>>(),
            vec![2_i32]
        )
    }
}
