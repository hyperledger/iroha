use axum::{
    http::{header::CONTENT_TYPE, HeaderValue},
    response::{IntoResponse, Response},
};
use iroha_version::prelude::*;

/// MIME used in Torii for SCALE encoding
// note: no elegant way to associate it with generic `Scale<T>`
pub const PARITY_SCALE_MIME_TYPE: &'_ str = "application/x-parity-scale";

/// Structure to reply using SCALE encoding
#[derive(Debug)]
pub struct Scale<T>(pub T);

impl<T: Encode + Send> IntoResponse for Scale<T> {
    fn into_response(self) -> Response {
        let mut res = Response::new(self.0.encode().into());
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static(PARITY_SCALE_MIME_TYPE),
        );
        res
    }
}

pub mod extractors {
    use axum::{
        async_trait,
        body::Bytes,
        extract::{FromRequest, FromRequestParts, Request},
        http::StatusCode,
    };

    use super::*;

    /// Extractor of scale encoded versioned data from body
    #[derive(Clone, Copy, Debug)]
    pub struct ScaleVersioned<T>(pub T);

    #[async_trait]
    impl<S, T> FromRequest<S> for ScaleVersioned<T>
    where
        Bytes: FromRequest<S>,
        S: Send + Sync,
        T: DecodeVersioned,
    {
        type Rejection = Response;

        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let body = Bytes::from_request(req, state)
                .await
                .map_err(IntoResponse::into_response)?;

            T::decode_all_versioned(&body)
                .map(ScaleVersioned)
                .map_err(|err| {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        format!("Could not decode request: {err}"),
                    )
                        .into_response()
                })
        }
    }

    /// Extractor of Accept header
    #[allow(unused)] // unused without `telemetry` feature
    pub struct ExtractAccept(pub HeaderValue);

    #[async_trait]
    impl<S> FromRequestParts<S> for ExtractAccept
    where
        S: Send + Sync,
    {
        type Rejection = (StatusCode, &'static str);

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            parts
                .headers
                .get(axum::http::header::ACCEPT)
                .cloned()
                .map(ExtractAccept)
                .ok_or((StatusCode::BAD_REQUEST, "`Accept` header is missing"))
        }
    }
}
