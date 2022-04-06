//! Structures and traits related to pagination.
#![allow(clippy::expect_used)]

#[cfg(not(feature = "std"))]
use alloc::{
    collections::btree_map,
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::fmt;
#[cfg(feature = "std")]
use std::collections::btree_map;

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "warp")]
use warp::{
    http::StatusCode,
    reply::{self, Response},
    Filter, Rejection, Reply,
};

const PAGINATION_START: &str = "start";
const PAGINATION_LIMIT: &str = "limit";

/// Describes a collection to which pagination can be applied.
/// Implemented for the [`Iterator`] implementors.
pub trait Paginate: Iterator + Sized {
    /// Returns a paginated [`Iterator`].
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

/// Structure for pagination requests
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, Decode, Encode, IntoSchema,
)]
pub struct Pagination {
    /// start of indexing
    pub start: Option<u32>,
    /// limit of indexing
    pub limit: Option<u32>,
}

impl Pagination {
    /// Constructs [`Pagination`].
    pub const fn new(start: Option<u32>, limit: Option<u32>) -> Self {
        Self { start, limit }
    }
}

/// Error for pagination
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PaginateError(pub core::num::ParseIntError);

impl fmt::Display for PaginateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to decode pagination. Error occurred in one of numbers: {}",
            self.0
        )
    }
}
#[cfg(feature = "std")]
impl std::error::Error for PaginateError {}

#[cfg(feature = "warp")]
impl Reply for PaginateError {
    fn into_response(self) -> Response {
        reply::with_status(self.to_string(), StatusCode::BAD_REQUEST).into_response()
    }
}

#[cfg(feature = "warp")]
/// Filter for warp which extracts pagination
pub fn paginate() -> impl Filter<Extract = (Pagination,), Error = Rejection> + Copy {
    warp::query()
}

impl From<Pagination> for btree_map::BTreeMap<String, String> {
    fn from(pagination: Pagination) -> Self {
        let mut query_params = Self::new();
        if let Some(start) = pagination.start {
            query_params.insert(String::from(PAGINATION_START), start.to_string());
        }
        if let Some(limit) = pagination.limit {
            query_params.insert(String::from(PAGINATION_LIMIT), limit.to_string());
        }
        query_params
    }
}

impl From<Pagination> for Vec<(&'static str, usize)> {
    fn from(pagination: Pagination) -> Self {
        match (pagination.start, pagination.limit) {
            (Some(start), Some(limit)) => {
                vec![
                    (
                        PAGINATION_START,
                        start.try_into().expect("u32 should always fit in usize"),
                    ),
                    (
                        PAGINATION_LIMIT,
                        limit.try_into().expect("u32 should always fit in usize"),
                    ),
                ]
            }
            (Some(start), None) => vec![(
                PAGINATION_START,
                start.try_into().expect("u32 should always fit in usize"),
            )],
            (None, Some(limit)) => vec![(
                PAGINATION_LIMIT,
                limit.try_into().expect("u32 should always fit in usize"),
            )],
            (None, None) => Vec::new(),
        }
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
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
