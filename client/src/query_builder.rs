use std::fmt::Debug;

use iroha_data_model::{
    predicate::PredicateBox,
    query::{sorting::Sorting, Pagination, Query},
    Value,
};

use crate::client::{Client, QueryOutput, QueryResult};

pub struct QueryRequestBuilder<'a, R> {
    client: &'a Client,
    request: R,
    pagination: Pagination,
    filter: PredicateBox,
    sorting: Sorting,
}

impl<'a, R> QueryRequestBuilder<'a, R>
where
    R: Query + Debug,
    R::Output: QueryOutput,
    <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
{
    pub(crate) fn new(client: &'a Client, request: R) -> Self {
        Self {
            client,
            request,
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            filter: PredicateBox::default(),
        }
    }

    pub fn with_filter(mut self, filter: PredicateBox) -> Self {
        self.filter = filter;
        self
    }

    pub fn with_sorting(mut self, sorting: Sorting) -> Self {
        self.sorting = sorting;
        self
    }

    pub fn with_pagination(mut self, pagination: Pagination) -> Self {
        self.pagination = pagination;
        self
    }

    pub fn execute(self) -> QueryResult<<R::Output as QueryOutput>::Target> {
        self.client.request_with_filter_and_pagination_and_sorting(
            self.request,
            self.pagination,
            self.sorting,
            self.filter,
        )
    }
}
