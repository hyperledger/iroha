//! Physical response frames retain the admitted complete query owner through their last byte.
//!
//! Capturing a permit in a `map_frame` closure protects only the HTTP body, not an extracted
//! `Bytes` value. Every data frame instead retains the original permit and its exact
//! zero-copy backing. Clones and slices share that owner. Wrapper layouts come from the actual
//! admission's finite encoder corridor; they cannot manufacture producer authority.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{body::Body, response::Response};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use iroha_allocation::AllocationCharge;

use crate::{QueryFanoutMemoryReservation, history_producer::HistoryProducerOwner};

#[derive(Debug)]
struct ResponseCapacity;
impl fmt::Display for ResponseCapacity {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("query response memory capacity exhausted")
    }
}
impl std::error::Error for ResponseCapacity {}

/// Native owners move this token onto the stack only after their control storage is freed.
struct QueryDataReclaim {
    _layout: AllocationCharge,
    _owner: HistoryProducerOwner,
}

pub fn owned<T: AsRef<[u8]> + Send + 'static>(
    bytes: T,
    owner: &HistoryProducerOwner,
) -> Result<axum::body::Bytes, axum::Error> {
    let layout = axum::body::Bytes::owner_with_reclaim_layout::<T, QueryDataReclaim>();
    let mut reserved = owner
        .response_metadata()
        .try_reserve(layout)
        .map_err(|_| axum::Error::new(ResponseCapacity))?;
    let charge = reserved
        .try_split(layout)
        .expect("the exact wrapper layout was admitted above");
    axum::body::Bytes::try_from_owner_with_reclaim(
        bytes,
        QueryDataReclaim {
            _layout: charge,
            _owner: owner.clone(),
        },
    )
    .map_err(|(bytes, reclaim)| {
        // Allocation never occurred. Destroy source backing before returning its credit.
        drop(bytes);
        drop(reclaim);
        axum::Error::new(ResponseCapacity)
    })
}

fn retain_data(
    bytes: axum::body::Bytes,
    owner: &HistoryProducerOwner,
) -> Result<axum::body::Bytes, axum::Error> {
    // Length alone cannot prove absent backing: an owned truncated value can keep a large
    // original allocation alive. Every data frame therefore retains the native owner.
    owned(bytes, owner)
}

struct QueryResponseBody<B> {
    source: B,
    owner: HistoryProducerOwner,
    refused: bool,
}
impl<B> HttpBody for QueryResponseBody<B>
where
    B: HttpBody<Data = axum::body::Bytes, Error = axum::Error>,
{
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    #[allow(unsafe_code)]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // SAFETY: source is structurally pinned with this private wrapper. No method
        // moves it after pinning, there is no custom Drop, and the other fields are
        // never projected as pinned. The native body allocation pins the whole wrapper.
        let this = unsafe { self.get_unchecked_mut() };
        if this.refused {
            return Poll::Ready(None);
        }
        // SAFETY: source remains at its original pinned address until wrapper destruction.
        match unsafe { Pin::new_unchecked(&mut this.source) }.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let Some(data) = frame.data_ref() else {
                    // HeaderMap/HeaderValue can own backing too. The closed JSON/SSE
                    // producer has no admitted metadata-frame codec; fail before export.
                    this.refused = true;
                    return Poll::Ready(Some(Err(axum::Error::new(ResponseCapacity))));
                };
                match retain_data(data.clone(), &this.owner) {
                    Ok(data) => Poll::Ready(Some(Ok(frame.map_data(|_| data)))),
                    Err(error) => {
                        this.refused = true;
                        Poll::Ready(Some(Err(error)))
                    }
                }
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.refused || self.source.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.source.size_hint()
    }
}

struct QueryBodyReclaim {
    _body_layout: AllocationCharge,
    _token_layout: AllocationCharge,
    _owner: HistoryProducerOwner,
}

fn refusal() -> Response {
    Response::builder()
        .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::empty())
        .expect("fixed refusal response")
}

/// Admit the original typed source and its token before allocating the native body.
/// This accepts a source value, not a previously boxed body or a response cap.
pub fn body<B>(source: B, owner: &HistoryProducerOwner) -> Result<Body, axum::Error>
where
    B: HttpBody<Data = axum::body::Bytes, Error = axum::Error> + Send + 'static,
{
    let body_layout = Body::body_layout::<QueryResponseBody<B>>();
    let token_layout = Body::reclaim_layout::<QueryBodyReclaim>();
    let mut body_reserved = owner
        .response_metadata()
        .try_reserve(body_layout)
        .map_err(|_| axum::Error::new(ResponseCapacity))?;
    let mut token_reserved = owner
        .response_metadata()
        .try_reserve(token_layout)
        .map_err(|_| axum::Error::new(ResponseCapacity))?;
    let reclaim = QueryBodyReclaim {
        _body_layout: body_reserved
            .try_split(body_layout)
            .expect("the exact body wrapper layout was admitted"),
        _token_layout: token_reserved
            .try_split(token_layout)
            .expect("the exact token storage layout was admitted"),
        _owner: owner.clone(),
    };
    let source = QueryResponseBody {
        source,
        owner: owner.clone(),
        refused: false,
    };
    Body::try_new_with_reclaim(source, reclaim).map_err(|(source, reclaim)| {
        drop(source);
        drop(reclaim);
        axum::Error::new(ResponseCapacity)
    })
}

fn impossible(error: std::convert::Infallible) -> axum::Error {
    match error {}
}

/// A canonical JSON buffer's first body allocation is the prepaid typed source.
pub fn json(
    bytes: axum::body::Bytes,
    owner: &HistoryProducerOwner,
) -> Result<Response, axum::Error> {
    let mapper: fn(std::convert::Infallible) -> axum::Error = impossible;
    let source = Full::new(bytes).map_err(mapper);
    let mut response = Response::new(body(source, owner)?);
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

pub fn hold(mut response: Response, memory: QueryFanoutMemoryReservation) -> Response {
    let Ok(owner) = HistoryProducerOwner::from_reservation(&memory) else {
        // Response-only native proof tokens already travel in EncodedBody-owned Bytes. They
        // cannot be promoted into this query-pool framing capability.
        drop(response);
        drop(memory);
        return refusal();
    };
    response.extensions_mut().insert(memory.clone());
    let (parts, body) = response.into_parts();
    match self::body(body, &owner) {
        Ok(body) => Response::from_parts(parts, body),
        Err(_) => {
            drop(parts);
            drop(owner);
            drop(memory);
            refusal()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use http_body_util::StreamBody;
    use std::convert::Infallible;

    const WORKING: usize = 48 * 1024 * 1024;

    fn acquire(pool: &crate::ByteWeightedMemoryPool) -> QueryFanoutMemoryReservation {
        QueryFanoutMemoryReservation::from_admitted_fanout(
            pool.try_acquire_parts([WORKING as u64]).unwrap(),
            crate::QueryFanoutMemoryEnvelope::for_body_admission(WORKING).unwrap(),
            pool.generation(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn extracted_cloned_and_sliced_data_outlives_the_body_with_its_real_owner() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let response = hold(
            Response::new(Body::from(Bytes::from_static(b"native response"))),
            acquire(&pool),
        );
        let (parts, mut body) = response.into_parts();
        drop(parts);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let clone = bytes.clone();
        let slice = bytes.slice(7..);
        drop(body);
        drop(bytes);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        drop(clone);
        assert_eq!(slice.as_ref(), b"response");
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        drop(slice);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_some());
    }

    #[tokio::test]
    async fn eight_full_owners_refuse_ninth_until_the_last_retained_frame_drops() {
        let pool = crate::ByteWeightedMemoryPool::new(8 * WORKING).unwrap();
        let mut retained = Vec::new();
        for _ in 0..8 {
            let response = hold(
                Response::new(Body::from(Bytes::from_static(b"owned"))),
                acquire(&pool),
            );
            let (parts, mut body) = response.into_parts();
            drop(parts);
            retained.push(body.frame().await.unwrap().unwrap().into_data().unwrap());
            drop(body);
        }
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        let last = retained.pop().unwrap();
        let slice = last.slice(1..);
        drop(last);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        drop(slice);
        let ninth = pool.try_acquire_parts([WORKING as u64]).unwrap();
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        drop(ninth);
        drop(retained);
        assert!(pool.try_acquire_parts([(8 * WORKING) as u64]).is_some());
    }

    #[tokio::test]
    async fn many_small_frames_cannot_outgrow_native_wrapper_backing() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let memory = acquire(&pool);
        let owner = HistoryProducerOwner::from_reservation(&memory).unwrap();
        let layout = Bytes::owner_with_reclaim_layout::<Bytes, QueryDataReclaim>();
        let baseline = owner.response_metadata().reserved_bytes();
        owner
            .response_metadata()
            .set_limit_bytes(baseline + 2 * layout.size());
        let first = retain_data(Bytes::from_static(b"a"), &owner).unwrap();
        let second = retain_data(Bytes::from_static(b"b"), &owner).unwrap();
        assert!(retain_data(Bytes::from_static(b"c"), &owner).is_err());
        assert_eq!(
            owner.response_metadata().reserved_bytes(),
            baseline + 2 * layout.size()
        );
        assert!(retain_data(Bytes::new(), &owner).is_err());
        assert_eq!(
            owner.response_metadata().reserved_bytes(),
            baseline + 2 * layout.size()
        );
        drop(first);
        assert!(retain_data(Bytes::from_static(b"c"), &owner).is_ok());
        drop(second);
        assert_eq!(owner.response_metadata().reserved_bytes(), baseline);
    }

    #[tokio::test]
    async fn extracted_empty_slice_retains_its_physical_backing_and_complete_owner() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let mut empty = Bytes::from_owner(vec![0x5a; 1024 * 1024]);
        empty.truncate(0);
        let source = futures_util::stream::iter([Ok::<_, Infallible>(empty)]);
        let response = hold(Response::new(Body::from_stream(source)), acquire(&pool));
        let (parts, mut body) = response.into_parts();
        drop(parts);
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let clone = data.clone();
        let slice = data.slice(..);
        drop(body);
        drop(data);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        // bytes 1.11.1 intentionally replaces an empty slice with static empty backing.
        // That slice need not retain a permit after the final genuinely owned clone drops.
        assert!(slice.is_empty());
        drop(clone);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_some());
        drop(slice);
    }

    #[tokio::test]
    async fn cancellation_drops_the_native_body_before_returning_query_capacity() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let source = futures_util::stream::pending::<Result<Bytes, Infallible>>();
        let response = hold(Response::new(Body::from_stream(source)), acquire(&pool));
        let (parts, body) = response.into_parts();
        drop(parts);
        {
            let read = async move {
                let mut body = body;
                body.frame().await
            };
            tokio::pin!(read);
            assert!(futures_util::poll!(&mut read).is_pending());
            assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
            // End the original physical future's scope, including its pending source body.
        }
        assert!(pool.try_acquire_parts([WORKING as u64]).is_some());
    }

    #[tokio::test]
    async fn original_non_unpin_source_is_admitted_before_its_first_body_allocation() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let memory = acquire(&pool);
        let owner = HistoryProducerOwner::from_reservation(&memory).unwrap();
        let source = futures_util::stream::unfold(false, |emitted| async move {
            if emitted {
                futures_util::future::pending::<()>().await;
                None
            } else {
                Some((
                    Ok::<_, axum::Error>(Frame::data(Bytes::from_static(b"typed"))),
                    true,
                ))
            }
        });
        let mut body = super::body(StreamBody::new(source), &owner).unwrap();
        drop(owner);
        drop(memory);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let clone = bytes.clone();
        assert!(futures_util::poll!(body.frame()).is_pending());
        drop(body);
        drop(bytes);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        drop(clone);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_some());
    }

    #[tokio::test]
    async fn unowned_trailers_are_refused_before_the_metadata_frame_escapes() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let mut trailers = axum::http::HeaderMap::new();
        trailers.insert(
            "x-unowned",
            axum::http::HeaderValue::from_static("metadata"),
        );
        let source = futures_util::stream::iter([Ok::<_, Infallible>(
            hyper::body::Frame::<Bytes>::trailers(trailers),
        )]);
        let response = hold(
            Response::new(Body::new(StreamBody::new(source))),
            acquire(&pool),
        );
        let (parts, mut body) = response.into_parts();
        drop(parts);
        assert!(body.frame().await.unwrap().is_err());
        assert!(body.frame().await.is_none());
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        drop(body);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_some());
    }

    #[test]
    fn failed_body_layout_admission_reclaims_original_source_and_owner() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let memory = acquire(&pool);
        let owner = HistoryProducerOwner::from_reservation(&memory).unwrap();
        owner
            .response_metadata()
            .set_limit_bytes(owner.response_metadata().reserved_bytes());
        drop(owner);
        let response = hold(Response::new(Body::from("original source")), memory);
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(pool.try_acquire_parts([WORKING as u64]).is_some());
    }
}
