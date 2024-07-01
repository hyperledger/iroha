#![warn(unused, missing_docs)]

use std::{collections::HashMap, fmt::Debug};

use eyre::{eyre, Context, Result};
use http::StatusCode;
use iroha_crypto::KeyPair;
use iroha_data_model::{
    account::AccountId,
    query::{
        builder::{IterableQueryBuilder, QueryExecutor},
        predicate::HasPredicateBox,
        ForwardCursor, IterableQueryOutput, IterableQueryOutputBatchBox, IterableQueryWithParams,
        QueryRequest2, QueryResponse2, SingularQuery, SingularQueryBox, SingularQueryOutputBox,
    },
    ValidationFail,
};
use iroha_torii_const::uri as torii_uri;
use parity_scale_codec::{DecodeAll, Encode};
use url::Url;

use crate::{
    client::{join_torii_url, Client, QueryResult, ResponseReport},
    data_model::query::IterableQuery,
    http::{Method as HttpMethod, RequestBuilder},
    http_default::DefaultRequestBuilder,
};

#[derive(Debug)]
struct ClientQueryRequestHead {
    pub torii_url: Url,
    pub headers: HashMap<String, String>,
    pub account_id: AccountId,
    pub key_pair: KeyPair,
}

impl ClientQueryRequestHead {
    pub fn assemble(&self, query: QueryRequest2) -> DefaultRequestBuilder {
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
fn decode_query_response(resp: &http::Response<Vec<u8>>) -> QueryResult<QueryResponse2> {
    match resp.status() {
        StatusCode::OK => {
            let res = QueryResponse2::decode_all(&mut resp.body().as_slice());
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
                    ClientQueryError::Other(
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
                ClientQueryError::Validation,
            )),
        _ => Err(ResponseReport::with_msg("Unexpected query response", resp).unwrap_or_else(core::convert::identity).into()),
    }
}

fn decode_singular_query_response(
    resp: &http::Response<Vec<u8>>,
) -> QueryResult<SingularQueryOutputBox> {
    let QueryResponse2::Singular(resp) = decode_query_response(resp)? else {
        return Err(eyre!(
            "Got unexpected type of query response from the node (expected singular)"
        )
        .into());
    };
    Ok(resp)
}

fn decode_iterable_query_response(
    resp: &http::Response<Vec<u8>>,
) -> QueryResult<IterableQueryOutput> {
    let QueryResponse2::Iterable(resp) = decode_query_response(resp)? else {
        return Err(eyre!(
            "Got unexpected type of query response from the node (expected iterable)"
        )
        .into());
    };
    Ok(resp)
}

#[derive(Debug)]
pub struct ClientQueryCursor {
    // instead of storing iroha client itself, we store the base URL and headers required to make a request
    //   along with the account id and key pair to sign the request.
    // this removes the need to either keep a reference or use an Arc, but breaks abstraction a little
    request_head: ClientQueryRequestHead,
    cursor: ForwardCursor,
}

/// Different errors as a result of query response handling
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ClientQueryError {
    /// Query validation error
    Validation(#[from] ValidationFail),
    /// Other error
    Other(#[from] eyre::Error),
}

impl From<ResponseReport> for ClientQueryError {
    #[inline]
    fn from(ResponseReport(err): ResponseReport) -> Self {
        Self::Other(err)
    }
}

impl QueryExecutor for Client {
    type Cursor = ClientQueryCursor;
    type Error = ClientQueryError;

    fn execute_singular_query(
        &self,
        query: SingularQueryBox,
    ) -> Result<SingularQueryOutputBox, Self::Error> {
        let request_head = self.get_query_request_head();

        let request = QueryRequest2::Singular(query);

        let response = request_head.assemble(request).build()?.send()?;
        let response = decode_singular_query_response(&response)?;

        Ok(response)
    }

    fn start_iterable_query(
        &self,
        query: IterableQueryWithParams,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error> {
        let request_head = self.get_query_request_head();

        let request = QueryRequest2::StartIterable(query);

        let response = request_head.assemble(request).build()?.send()?;
        let response = decode_iterable_query_response(&response)?;

        let (batch, cursor) = response.into_parts();

        let cursor = cursor.map(|cursor| ClientQueryCursor {
            request_head,
            cursor,
        });

        Ok((batch, cursor))
    }

    fn continue_iterable_query(
        cursor: Self::Cursor,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error> {
        let ClientQueryCursor {
            request_head,
            cursor,
        } = cursor;

        let request = QueryRequest2::ContinueIterable(cursor);

        let response = request_head.assemble(request).build()?.send()?;
        let response = decode_iterable_query_response(&response)?;

        let (batch, cursor) = response.into_parts();

        let cursor = cursor.map(|cursor| ClientQueryCursor {
            request_head,
            cursor,
        });

        Ok((batch, cursor))
    }
}

impl Client {
    /// Get a [`ClientQueryRequestHead`] - an object that can be used to make queries independently of the client.
    ///
    /// You probably do not want to use it directly, but rather use [`Client::query`] or [`Client::iter_query`].
    fn get_query_request_head(&self) -> ClientQueryRequestHead {
        ClientQueryRequestHead {
            torii_url: self.torii_url.clone(),
            headers: self.headers.clone(),
            account_id: self.account.clone(),
            key_pair: self.key_pair.clone(),
        }
    }

    #[warn(missing_docs)] // TODO
    pub fn query<Q>(&self, query: Q) -> Result<Q::Output, ClientQueryError>
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

    #[warn(missing_docs)] // TODO
    pub fn iter_query<Q, P>(&self, query: Q) -> IterableQueryBuilder<Self, Q, P>
    where
        Q: IterableQuery,
        Q::Item: HasPredicateBox<PredicateBoxType = P>,
    {
        IterableQueryBuilder::new(self, query)
    }

    #[warn(missing_docs)] // TODO
    pub fn raw_continue_iterable_query(
        &self,
        cursor: ForwardCursor,
    ) -> Result<QueryResponse2, ClientQueryError> {
        let request_head = self.get_query_request_head();

        let request = QueryRequest2::ContinueIterable(cursor);

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
                Err(ClientQueryError::Validation(actual)) => {
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
            Err(ClientQueryError::Other(_)) => Ok(()),
            x => Err(eyre!("Expected indeterminate, found: {:?}", x)),
        }
    }
}
