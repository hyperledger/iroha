//! Functions and types to make queries to the Iroha peer.

use std::{collections::HashMap, fmt::Debug};

use eyre::{eyre, Context, Result};
use http::StatusCode;
use iroha_crypto::KeyPair;
use iroha_data_model::{
    account::AccountId,
    query::{
        builder::{QueryBuilder, QueryExecutor},
        parameters::ForwardCursor,
        predicate::HasPredicateBox,
        QueryOutput, QueryOutputBatchBox, QueryRequest, QueryResponse, QueryWithParams,
        SingularQuery, SingularQueryBox, SingularQueryOutputBox,
    },
    ValidationFail,
};
use iroha_torii_const::uri as torii_uri;
use parity_scale_codec::{DecodeAll, Encode};
use url::Url;

use crate::{
    client::{join_torii_url, Client, QueryResult, ResponseReport},
    data_model::query::Query,
    http::{Method as HttpMethod, RequestBuilder},
    http_default::DefaultRequestBuilder,
};

#[derive(Debug)]
struct ClientQueryRequestHead {
    torii_url: Url,
    headers: HashMap<String, String>,
    account_id: AccountId,
    key_pair: KeyPair,
}

impl ClientQueryRequestHead {
    fn assemble(&self, query: QueryRequest) -> DefaultRequestBuilder {
        // authorize and sign the query
        let query = query
            .with_authority(self.account_id.clone())
            .sign(&self.key_pair);

        DefaultRequestBuilder::new(
            HttpMethod::POST,
            join_torii_url(&self.torii_url, torii_uri::QUERY),
        )
        .headers(self.headers.clone())
        .body(query.encode())
    }
}

/// Decode a raw response from the node's query endpoint
fn decode_query_response(resp: &http::Response<Vec<u8>>) -> QueryResult<QueryResponse> {
    match resp.status() {
        StatusCode::OK => {
            let res = QueryResponse::decode_all(&mut resp.body().as_slice());
            res.wrap_err(
                "Failed to decode response from Iroha. \
                         You are likely using a version of the client library \
                         that is incompatible with the version of the peer software",
            )
                .map_err(Into::into)
        }
        StatusCode::BAD_REQUEST
        | StatusCode::UNAUTHORIZED
        | StatusCode::FORBIDDEN
        | StatusCode::NOT_FOUND
        | StatusCode::UNPROCESSABLE_ENTITY => Err(ValidationFail::decode_all(
            &mut resp.body().as_ref(),
        )
            .map_or_else(
                |_| {
                    QueryError::Other(
                        ResponseReport::with_msg("Query failed", resp)
                            .map_or_else(
                                |_| eyre!(
                                        "Failed to decode response from Iroha. \
                                        Response is neither a `ValidationFail` encoded value nor a valid utf-8 string error response. \
                                        You are likely using a version of the client library that is incompatible with the version of the peer software",
                                    ),
                                Into::into
                            ),
                    )
                },
                QueryError::Validation,
            )),
        _ => Err(ResponseReport::with_msg("Unexpected query response", resp).unwrap_or_else(core::convert::identity).into()),
    }
}

fn decode_singular_query_response(
    resp: &http::Response<Vec<u8>>,
) -> QueryResult<SingularQueryOutputBox> {
    let QueryResponse::Singular(resp) = decode_query_response(resp)? else {
        return Err(eyre!(
            "Got unexpected type of query response from the node (expected singular)"
        )
        .into());
    };
    Ok(resp)
}

fn decode_iterable_query_response(resp: &http::Response<Vec<u8>>) -> QueryResult<QueryOutput> {
    let QueryResponse::Iterable(resp) = decode_query_response(resp)? else {
        return Err(eyre!(
            "Got unexpected type of query response from the node (expected iterable)"
        )
        .into());
    };
    Ok(resp)
}

/// An iterable query cursor for use in the client
#[derive(Debug)]
pub struct QueryCursor {
    // instead of storing iroha client itself, we store the base URL and headers required to make a request
    //   along with the account id and key pair to sign the request.
    // this removes the need to either keep a reference or use an Arc, but breaks abstraction a little
    request_head: ClientQueryRequestHead,
    cursor: ForwardCursor,
}

/// Different errors as a result of query response handling
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum QueryError {
    /// Query validation error
    Validation(#[from] ValidationFail),
    /// Other error
    Other(#[from] eyre::Error),
}

impl From<ResponseReport> for QueryError {
    #[inline]
    fn from(ResponseReport(err): ResponseReport) -> Self {
        Self::Other(err)
    }
}

impl QueryExecutor for Client {
    type Cursor = QueryCursor;
    type Error = QueryError;

    fn execute_singular_query(
        &self,
        query: SingularQueryBox,
    ) -> Result<SingularQueryOutputBox, Self::Error> {
        let request_head = self.get_query_request_head();

        let request = QueryRequest::Singular(query);

        let response = request_head.assemble(request).build()?.send()?;
        let response = decode_singular_query_response(&response)?;

        Ok(response)
    }

    fn start_query(
        &self,
        query: QueryWithParams,
    ) -> Result<(QueryOutputBatchBox, Option<Self::Cursor>), Self::Error> {
        let request_head = self.get_query_request_head();

        let request = QueryRequest::Start(query);

        let response = request_head.assemble(request).build()?.send()?;
        let response = decode_iterable_query_response(&response)?;

        let (batch, cursor) = response.into_parts();

        let cursor = cursor.map(|cursor| QueryCursor {
            request_head,
            cursor,
        });

        Ok((batch, cursor))
    }

    fn continue_query(
        cursor: Self::Cursor,
    ) -> Result<(QueryOutputBatchBox, Option<Self::Cursor>), Self::Error> {
        let QueryCursor {
            request_head,
            cursor,
        } = cursor;

        let request = QueryRequest::Continue(cursor);

        let response = request_head.assemble(request).build()?.send()?;
        let response = decode_iterable_query_response(&response)?;

        let (batch, cursor) = response.into_parts();

        let cursor = cursor.map(|cursor| QueryCursor {
            request_head,
            cursor,
        });

        Ok((batch, cursor))
    }
}

impl Client {
    /// Get a [`ClientQueryRequestHead`] - an object that can be used to make queries independently of the client.
    ///
    /// You probably do not want to use it directly, but rather use [`Client::query_single`] or [`Client::query`].
    fn get_query_request_head(&self) -> ClientQueryRequestHead {
        ClientQueryRequestHead {
            torii_url: self.torii_url.clone(),
            headers: self.headers.clone(),
            account_id: self.account.clone(),
            key_pair: self.key_pair.clone(),
        }
    }

    /// Execute a singular query and return the result
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn query_single<Q>(&self, query: Q) -> Result<Q::Output, QueryError>
    where
        Q: SingularQuery,
        SingularQueryBox: From<Q>,
        Q::Output: TryFrom<SingularQueryOutputBox>,
        <Q::Output as TryFrom<SingularQueryOutputBox>>::Error: Debug,
    {
        let query = SingularQueryBox::from(query);

        let result = self.execute_singular_query(query)?;

        Ok(result
            .try_into()
            .expect("BUG: iroha returned unexpected type in singular query"))
    }

    /// Build an iterable query and return a builder object
    pub fn query<Q>(
        &self,
        query: Q,
    ) -> QueryBuilder<Self, Q, <<Q as Query>::Item as HasPredicateBox>::PredicateBoxType>
    where
        Q: Query,
    {
        QueryBuilder::new(self, query)
    }

    /// Make a request to continue an iterable query with the provided raw [`ForwardCursor`]
    ///
    /// You probably do not want to use this function, but rather use the [`Self::query`] method to make a query and iterate over its results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn raw_continue_iterable_query(
        &self,
        cursor: ForwardCursor,
    ) -> Result<QueryResponse, QueryError> {
        let request_head = self.get_query_request_head();

        let request = QueryRequest::Continue(cursor);

        let response = request_head.assemble(request).build()?.send()?;
        let response = decode_query_response(&response)?;

        Ok(response)
    }
}

#[cfg(test)]
mod query_errors_handling {
    use http::Response;

    use super::*;
    use crate::data_model::ValidationFail;

    #[test]
    fn certain_errors() -> Result<()> {
        let responses = vec![(StatusCode::UNPROCESSABLE_ENTITY, ValidationFail::TooComplex)];
        for (status_code, err) in responses {
            let resp = Response::builder().status(status_code).body(err.encode())?;

            match decode_query_response(&resp) {
                Err(QueryError::Validation(actual)) => {
                    // PartialEq isn't implemented, so asserting by encoded repr
                    assert_eq!(actual.encode(), err.encode());
                }
                x => return Err(eyre!("Wrong output for {:?}: {:?}", (status_code, err), x)),
            }
        }

        Ok(())
    }

    #[test]
    fn indeterminate() -> Result<()> {
        let response = Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Vec::<u8>::new())?;

        match decode_query_response(&response) {
            Err(QueryError::Other(_)) => Ok(()),
            x => Err(eyre!("Expected indeterminate, found: {:?}", x)),
        }
    }
}
