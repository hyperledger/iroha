use std::convert::Infallible;

use iroha_version::scale::DecodeVersioned;
use parity_scale_codec::Encode;
use warp::{hyper::body::Bytes, reply::Response, Filter, Rejection, Reply};

use super::VerifiedQueryRequest;

/// Structure for empty response body
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
pub fn add_state<State: Send + Clone>(
    state: State,
) -> impl Filter<Extract = (State,), Error = Rejection> + Clone + Send {
    warp::any().and_then(move || {
        let state = state.clone();
        async move { Ok::<_, Rejection>(state) }
    })
}

pub mod body {
    use super::*;

    /// Decode query request
    pub fn query() -> impl Filter<Extract = (VerifiedQueryRequest,), Error = Rejection> + Copy {
        warp::body::bytes()
            .and_then(|body: Bytes| async move { (&body).try_into().map_err(warp::reject::custom) })
    }

    /// Decode body as versioned scale codec
    pub fn versioned<T: DecodeVersioned>() -> impl Filter<Extract = (T,), Error = Rejection> + Copy
    {
        warp::body::bytes().and_then(|body: Bytes| async move {
            DecodeVersioned::decode_versioned(body.as_ref()).map_err(warp::reject::custom)
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

macro_rules! impl_custom_and_then {
    ( $name:ident ( $($arg_name:ident : $arg_gen:ident),* $(,)? ) ) => {
        /// Maps filter to handler with `n` arguments (`n` is suffix of function)
        pub fn $name<O, E, F, Fut, Fil, $($arg_gen,)*>(f: F, router: Fil)
            -> impl Filter<Extract = (WarpResult<O, E>,), Error = Rejection> + Clone
        where
            Fil: Filter<Extract = ($($arg_gen,)*), Error = Rejection> + Clone,
            F: Fn($($arg_gen,)*) -> Fut + Copy + Send + Sync + 'static,
            Fut: std::future::Future<Output = Result<O, E>> + Send,
            $($arg_gen: Send,)*
        {
            router.and_then(move |$($arg_name,)*|
                async move {
                    Ok::<_, Infallible>(WarpResult(f($($arg_name,)*).await))
                }
            )
        }
    }
}

impl_custom_and_then!(endpoint1(a: A));
impl_custom_and_then!(endpoint2(a: A, b: B));
impl_custom_and_then!(endpoint3(a: A, b: B, c: C));
//impl_custom_and_then!(endpoint4 (a: A, b: B, c: C, d: D));
