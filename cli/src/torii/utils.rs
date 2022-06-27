use std::convert::Infallible;

use iroha_cli_derive::generate_endpoints;
use iroha_version::prelude::*;
use parity_scale_codec::Encode;
use warp::{hyper::body::Bytes, reply::Response, Filter, Rejection, Reply};

use super::routing::VerifiedQueryRequest;

/// Structure for empty response body
#[derive(Clone, Copy)]
pub struct Empty;

impl Reply for Empty {
    fn into_response(self) -> Response {
        Response::new(vec![].into())
    }
}

/// Structure for response in scale codec in body
pub struct Scale<T>(pub T);

impl<T: Encode + Send> Reply for Scale<T> {
    fn into_response(self) -> Response {
        Response::new(self.0.encode().into())
    }
}

/// Adds state to filter
macro_rules! add_state {
    ( $( $state : expr ),* $(,)? ) => {
        warp::any().map({
            let state = ($( $state.clone(), )*);
            move || state.clone()
        }).untuple_one()
    }
}

pub mod body {
    use iroha_core::smartcontracts::query::Error as QueryError;
    use iroha_data_model::query::VersionedSignedQueryRequest;
    use iroha_logger::warn;

    use super::*;

    #[derive(Debug)]
    pub struct WarpQueryError(QueryError);

    impl From<QueryError> for WarpQueryError {
        fn from(source: QueryError) -> Self {
            Self(source)
        }
    }

    impl warp::reject::Reject for WarpQueryError {}

    impl TryFrom<&Bytes> for super::VerifiedQueryRequest {
        type Error = WarpQueryError;

        fn try_from(body: &Bytes) -> Result<Self, Self::Error> {
            let res = try_decode_all_or_just_decode!(VersionedSignedQueryRequest, body.as_ref());
            let query = res.map_err(|e| WarpQueryError(Box::new(e).into()))?;
            let VersionedSignedQueryRequest::V1(query) = query;
            Ok(Self::try_from(query)?)
        }
    }

    /// Decode query request
    pub fn query() -> impl Filter<Extract = (VerifiedQueryRequest,), Error = Rejection> + Copy {
        warp::body::bytes()
            .and_then(|body: Bytes| async move { (&body).try_into().map_err(warp::reject::custom) })
    }

    /// Decode body as versioned scale codec
    pub fn versioned<T: DecodeVersioned>() -> impl Filter<Extract = (T,), Error = Rejection> + Copy
    {
        warp::body::bytes().and_then(|body: Bytes| async move {
            try_decode_all_or_just_decode!(T as "Body", body.as_ref()).map_err(warp::reject::custom)
        })
    }
}

/// Warp result response type
pub struct WarpResult<O, E>(Result<O, E>);

impl<O: Reply, E: Reply> Reply for WarpResult<O, E> {
    fn into_response(self) -> warp::reply::Response {
        match self {
            Self(Ok(ok)) => ok.into_response(),
            Self(Err(err)) => err.into_response(),
        }
    }
}

generate_endpoints!(2, 3, 4);
