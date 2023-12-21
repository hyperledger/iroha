//! Routing functions for Torii. If you want to add an endpoint to
//! Iroha you should add it here by creating a `handle_*` function,
//! and add it to impl Torii.

// FIXME: This can't be fixed, because one trait in `warp` is private.
#![allow(opaque_hidden_inferred_bound)]

#[cfg(feature = "telemetry")]
use eyre::{eyre, WrapErr};
use futures::TryStreamExt;
use iroha_config::client_api::ConfigurationDTO;
use iroha_core::{
    query::{pagination::Paginate, store::LiveQueryStoreHandle},
    smartcontracts::query::ValidQueryRequest,
    sumeragi::SumeragiHandle,
};
use iroha_data_model::{
    block::{
        stream::{BlockMessage, BlockSubscriptionRequest},
        SignedBlock,
    },
    prelude::*,
    query::{
        cursor::ForwardCursor, http, sorting::Sorting, Pagination, QueryRequest,
        QueryWithParameters,
    },
    BatchedResponse, BatchedResponseV1,
};
#[cfg(feature = "telemetry")]
use iroha_telemetry::metrics::Status;
use tokio::task;

use super::*;
use crate::stream::{Sink, Stream};

/// Filter for warp which extracts [`http::ClientQueryRequest`]
pub fn client_query_request(
) -> impl warp::Filter<Extract = (http::ClientQueryRequest,), Error = warp::Rejection> + Copy {
    body::versioned::<SignedQuery>()
        .and(sorting())
        .and(paginate())
        .and(fetch_size())
        .and_then(|signed_query, sorting, pagination, fetch_size| async move {
            Result::<_, std::convert::Infallible>::Ok(http::ClientQueryRequest::query(
                signed_query,
                sorting,
                pagination,
                fetch_size,
            ))
        })
        .or(cursor().and_then(|cursor| async move {
            Result::<_, std::convert::Infallible>::Ok(http::ClientQueryRequest::cursor(cursor))
        }))
        .unify()
}

/// Filter for warp which extracts sorting
fn sorting() -> impl warp::Filter<Extract = (Sorting,), Error = warp::Rejection> + Copy {
    warp::query()
}

/// Filter for warp which extracts cursor
fn cursor() -> impl warp::Filter<Extract = (ForwardCursor,), Error = warp::Rejection> + Copy {
    warp::query()
}

/// Filter for warp which extracts pagination
pub fn paginate() -> impl warp::Filter<Extract = (Pagination,), Error = warp::Rejection> + Copy {
    warp::query()
}

/// Filter for warp which extracts fetch size
pub fn fetch_size() -> impl warp::Filter<Extract = (FetchSize,), Error = warp::Rejection> + Copy {
    warp::query()
}

#[iroha_futures::telemetry_future]
pub async fn handle_transaction(
    queue: Arc<Queue>,
    sumeragi: SumeragiHandle,
    transaction: SignedTransaction,
) -> Result<Empty> {
    let wsv = sumeragi.wsv_clone();
    let transaction_limits = wsv.config.transaction_limits;
    let transaction = AcceptedTransaction::accept(transaction, &transaction_limits)
        .map_err(Error::AcceptTransaction)?;
    queue
        .push(transaction, &wsv)
        .map_err(|queue::Failure { tx, err }| {
            iroha_logger::warn!(
                tx_hash=%tx.payload().hash(), ?err,
                "Failed to push into queue"
            );

            Box::new(err)
        })
        .map_err(Error::PushIntoQueue)
        .map(|()| Empty)
}

#[iroha_futures::telemetry_future]
pub async fn handle_queries(
    live_query_store: LiveQueryStoreHandle,
    sumeragi: SumeragiHandle,

    query_request: http::ClientQueryRequest,
) -> Result<Scale<BatchedResponse<Value>>> {
    let handle = task::spawn_blocking(move || match query_request.0 {
        QueryRequest::Query(QueryWithParameters {
            query: signed_query,
            sorting,
            pagination,
            fetch_size,
        }) => sumeragi.apply_wsv(|wsv| {
            let valid_query = ValidQueryRequest::validate(signed_query, wsv)?;
            let query_output = valid_query.execute(wsv)?;
            live_query_store
                .handle_query_output(query_output, &sorting, pagination, fetch_size)
                .map_err(ValidationFail::from)
        }),
        QueryRequest::Cursor(cursor) => live_query_store
            .handle_query_cursor(cursor)
            .map_err(ValidationFail::from),
    });
    handle
        .await
        .expect("Failed to join query handling task")
        .map(Scale)
        .map_err(Into::into)
}

#[derive(serde::Serialize)]
#[non_exhaustive]
enum Health {
    Healthy,
}

pub fn handle_health() -> Json {
    reply::json(&Health::Healthy)
}

#[iroha_futures::telemetry_future]
#[cfg(feature = "schema")]
pub async fn handle_schema() -> Json {
    reply::json(&iroha_schema_gen::build_schemas())
}

#[iroha_futures::telemetry_future]
pub async fn handle_pending_transactions(
    queue: Arc<Queue>,
    sumeragi: SumeragiHandle,
    pagination: Pagination,
    // ignore it for now
    _fetch_size: FetchSize,
) -> Result<Scale<BatchedResponse<Vec<SignedTransaction>>>> {
    let query_response = sumeragi.apply_wsv(|wsv| {
        queue
            .all_transactions(wsv)
            .map(Into::into)
            .paginate(pagination)
            .collect::<Vec<_>>()
    });

    let batched_response = BatchedResponseV1 {
        batch: query_response,
        cursor: ForwardCursor::default(),
    };

    Ok(Scale(batched_response.into()))
}

#[iroha_futures::telemetry_future]
pub async fn handle_get_configuration(kiso: KisoHandle) -> Result<Json> {
    let dto = kiso.get_dto().await?;
    Ok(reply::json(&dto))
}

#[iroha_futures::telemetry_future]
pub async fn handle_post_configuration(
    kiso: KisoHandle,
    value: ConfigurationDTO,
) -> Result<impl Reply> {
    kiso.update_with_dto(value).await?;
    Ok(reply::with_status(reply::reply(), StatusCode::ACCEPTED))
}

#[iroha_futures::telemetry_future]
pub async fn handle_blocks_stream(kura: Arc<Kura>, mut stream: WebSocket) -> eyre::Result<()> {
    let BlockSubscriptionRequest(mut from_height) = stream.recv().await?;

    let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
    loop {
        // FIXME: cleanup.

        tokio::select! {
            // This branch catches `Close` and unexpected messages
            closed = async {
                while let Some(message) = stream.try_next().await? {
                    if message.is_close() {
                        return Ok(());
                    }
                    iroha_logger::warn!(?message, "Unexpected message received");
                }
                eyre::bail!("Can't receive close message")
            } => {
                match closed {
                    Ok(()) =>  {
                        return stream.close().await.map_err(Into::into);
                    }
                    Err(err) => return Err(err)
                }
            }
            // This branch sends blocks
            _ = interval.tick() => {
                if let Some(block) = kura.get_block_by_height(from_height.get()) {
                    stream
                        // TODO: to avoid clone `BlockMessage` could be split into sending and receiving parts
                        .send(BlockMessage(SignedBlock::clone(&block)))
                        .await?;
                    from_height = from_height.checked_add(1).expect("Maximum block height is achieved.");
                }
            }
            // Else branch to prevent panic i.e. I don't know what
            // this does.
            else => ()
        }
    }
}

pub mod subscription {
    //! Contains the `handle_subscription` functions and used for general routing.

    use super::*;
    use crate::event;

    /// Type for any error during subscription handling
    #[derive(Debug, displaydoc::Display, thiserror::Error)]
    enum Error {
        /// Event consumption resulted in an error
        Consumer(#[from] Box<event::Error>),
        /// Event reception error
        Event(#[from] tokio::sync::broadcast::error::RecvError),
        /// WebSocket error
        WebSocket(#[from] warp::Error),
        /// A `Close` message is received. Not strictly an Error
        CloseMessage,
    }

    impl From<event::Error> for Error {
        fn from(error: event::Error) -> Self {
            match error {
                event::Error::Stream(box_err)
                    if matches!(*box_err, event::StreamError::CloseMessage) =>
                {
                    Self::CloseMessage
                }
                error => Self::Consumer(Box::new(error)),
            }
        }
    }

    type Result<T> = core::result::Result<T, Error>;

    /// Handle subscription request
    ///
    /// Subscribes `stream` for `events` filtered by filter that is
    /// received through the `stream`
    ///
    /// There should be a [`warp::filters::ws::Message::close()`]
    /// message to end subscription
    #[iroha_futures::telemetry_future]
    pub async fn handle_subscription(events: EventsSender, stream: WebSocket) -> eyre::Result<()> {
        let mut consumer = event::Consumer::new(stream).await?;

        match subscribe_forever(events, &mut consumer).await {
            Ok(()) | Err(Error::CloseMessage) => consumer.close_stream().await.map_err(Into::into),
            Err(err) => Err(err.into()),
        }
    }

    /// Make endless `consumer` subscription for `events`
    ///
    /// Ideally should return `Result<!>` cause it either runs forever
    /// either returns `Err` variant
    async fn subscribe_forever(events: EventsSender, consumer: &mut event::Consumer) -> Result<()> {
        let mut events = events.subscribe();

        loop {
            tokio::select! {
                // This branch catches `Close` and unexpected messages
                closed = consumer.stream_closed() => {
                    match closed {
                        Ok(()) => return Err(Error::CloseMessage),
                        Err(err) => return Err(err.into())
                    }
                }
                // This branch catches and sends events
                event = events.recv() => {
                    let event = event?;
                    iroha_logger::trace!(?event);
                    consumer.consume(event).await?;
                }
                // Else branch to prevent panic
                else => ()
            }
        }
    }
}

#[iroha_futures::telemetry_future]
#[cfg(feature = "telemetry")]
pub async fn handle_version(sumeragi: SumeragiHandle) -> Json {
    use iroha_version::Version;

    let string = sumeragi
        .apply_wsv(WorldStateView::latest_block_ref)
        .expect("Genesis not applied. Nothing we can do. Solve the issue and rerun.")
        .version()
        .to_string();
    reply::json(&string)
}

#[cfg(feature = "telemetry")]
pub fn handle_metrics(sumeragi: &SumeragiHandle) -> Result<String> {
    if let Err(error) = sumeragi.update_metrics() {
        iroha_logger::error!(%error, "Error while calling sumeragi::update_metrics.");
    }
    sumeragi
        .metrics()
        .try_to_string()
        .map_err(Error::Prometheus)
}

fn update_metrics_gracefully(sumeragi: &SumeragiHandle) {
    if let Err(error) = sumeragi.update_metrics() {
        iroha_logger::error!(%error, "Error while calling `sumeragi::update_metrics`.");
    }
}

#[cfg(feature = "telemetry")]
#[allow(clippy::unnecessary_wraps)]
pub fn handle_status(
    sumeragi: &SumeragiHandle,
    accept: Option<impl AsRef<str>>,
    tail: &warp::path::Tail,
) -> Result<Response> {
    use eyre::ContextCompat;

    update_metrics_gracefully(sumeragi);
    let status = Status::from(&sumeragi.metrics());

    let tail = tail.as_str();
    if tail.is_empty() {
        if accept.is_some_and(|x| x.as_ref() == PARITY_SCALE_MIME_TYPE) {
            Ok(Scale(status).into_response())
        } else {
            Ok(reply::json(&status).into_response())
        }
    } else {
        // TODO: This probably can be optimised to elide the full
        // structure. Ideally there should remain a list of fields and
        // field aliases somewhere in `serde` macro output, which can
        // elide the creation of the value, and directly read the value
        // behind the mutex.
        let value = serde_json::to_value(status)
            .wrap_err("Failed to serialize JSON")
            .map_err(Error::StatusFailure)?;

        let reply = tail
            .split('/')
            .try_fold(&value, serde_json::Value::get)
            .wrap_err_with(|| eyre!("Path not found: \"{}\"", tail))
            .map_err(Error::StatusSegmentNotFound)
            .map(|segment| reply::json(segment).into_response())?;

        Ok(reply)
    }
}
