use axum::{
    http::{header::CONTENT_TYPE, HeaderValue},
    response::{IntoResponse, Response},
};
use iroha_data_model::query::http::{ClientQueryRequest, SignedQuery};
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

pub mod body {
    use axum::{
        async_trait,
        body::Bytes,
        extract::{FromRequest, FromRequestParts, Query, Request},
    };
    use iroha_data_model::query::cursor::ForwardCursor;

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
                        format!("Transaction Rejected (Malformed), Reason : '{err}'"),
                    )
                        .into_response()
                })
        }
    }

    /// Extractor for [`ClientQueryRequest`]
    ///
    /// First try to deserialize body as [`SignedQuery`] if fail try to parse query parameters for [`ForwardCursor`] values
    #[derive(Clone, Debug)]
    pub struct ClientQueryRequestExtractor(pub ClientQueryRequest);

    #[async_trait]
    impl<S> FromRequest<S> for ClientQueryRequestExtractor
    where
        Bytes: FromRequest<S>,
        S: Send + Sync,
    {
        type Rejection = Response;

        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let (mut parts, body) = req.into_parts();
            let cursor = Query::<ForwardCursor>::from_request_parts(&mut parts, &state)
                .await
                .map(|Query(cursor)| ClientQueryRequest::cursor(cursor));
            let req = Request::from_parts(parts, body);
            ScaleVersioned::<SignedQuery>::from_request(req, state)
                .await
                .map(|ScaleVersioned(query)| ClientQueryRequest::query(query))
                .or(cursor)
                // TODO: custom error to show that neither SignedQuery nor ForwardCursor
                .map_err(IntoResponse::into_response)
                .map(ClientQueryRequestExtractor)
        }
    }
}
