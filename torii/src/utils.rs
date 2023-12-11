use std::convert::Infallible;

use iroha_version::prelude::*;
use warp::{
    http::{header::CONTENT_TYPE, HeaderValue},
    hyper::body::Bytes,
    reply::Response,
    Filter, Rejection, Reply,
};

/// Structure for empty response body
#[derive(Clone, Copy)]
pub struct Empty;

impl Reply for Empty {
    fn into_response(self) -> Response {
        Response::new(vec![].into())
    }
}

/// MIME used in Torii for SCALE encoding
// note: no elegant way to associate it with generic `Scale<T>`
pub const PARITY_SCALE_MIME_TYPE: &'_ str = "application/x-parity-scale";

/// Structure to reply using SCALE encoding
#[derive(Debug)]
pub struct Scale<T>(pub T);

impl<T: Encode + Send> Reply for Scale<T> {
    fn into_response(self) -> Response {
        let mut res = Response::new(self.0.encode().into());
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static(PARITY_SCALE_MIME_TYPE),
        );
        res
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
    use iroha_version::error::Error as VersionError;

    use super::*;

    /// Decode body as versioned scale codec
    pub fn versioned<T: DecodeVersioned>() -> impl Filter<Extract = (T,), Error = Rejection> + Copy
    {
        warp::body::bytes().and_then(|body: Bytes| async move {
            T::decode_all_versioned(body.as_ref()).map_err(warp::reject::custom)
        })
    }

    /// Recover from failure in `versioned`
    pub fn recover_versioned(rejection: Rejection) -> Result<impl Reply, Rejection> {
        rejection
            .find::<VersionError>()
            .map(warp::Reply::into_response)
            .ok_or(rejection)
    }
}

/// Warp result response type
pub struct WarpResult<O, E>(pub Result<O, E>);

impl<O: Reply, E: Reply> Reply for WarpResult<O, E> {
    fn into_response(self) -> warp::reply::Response {
        match self {
            Self(Ok(ok)) => ok.into_response(),
            Self(Err(err)) => err.into_response(),
        }
    }
}

iroha_torii_derive::generate_endpoints!(2, 3, 4, 5, 6, 7);
