//! Routing functions for Torii. If you want to add an endpoint to
//! Iroha you should add it here by creating a `handle_*` function,
//! and add it to impl Torii.

use axum::extract::ws::WebSocket;
#[cfg(feature = "telemetry")]
use eyre::{eyre, WrapErr};
use futures::TryStreamExt;
use iroha_config::client_api::ConfigDTO;
use iroha_core::{query::store::LiveQueryStoreHandle, smartcontracts::query::ValidQueryRequest};
use iroha_data_model::{
    block::{
        stream::{BlockMessage, BlockSubscriptionRequest},
        SignedBlock,
    },
    prelude::*,
    query::{QueryRequestWithAuthority, QueryResponse, SignedQuery},
};
#[cfg(feature = "telemetry")]
use iroha_telemetry::metrics::Status;
use stream::StreamMessage as _;
use tokio::task;

use super::*;
use crate::stream::{Sink, Stream};

#[iroha_futures::telemetry_future]
pub async fn handle_transaction(
    chain_id: Arc<ChainId>,
    queue: Arc<Queue>,
    state: Arc<State>,
    transaction: SignedTransaction,
) -> Result<()> {
    let state_view = state.view();
    let transaction_limits = state_view.world().parameters().transaction;
    let transaction = AcceptedTransaction::accept(transaction, &chain_id, transaction_limits)
        .map_err(Error::AcceptTransaction)?;
    queue
        .push(transaction, &state_view)
        .map_err(|queue::Failure { tx, err }| {
            iroha_logger::warn!(
                tx_hash=%tx.as_ref().hash(), ?err,
                "Failed to push into queue"
            );

            Box::new(err)
        })
        .map_err(Error::PushIntoQueue)
}

#[iroha_futures::telemetry_future]
pub async fn handle_queries(
    live_query_store: LiveQueryStoreHandle,
    state: Arc<State>,
    query: SignedQuery,
) -> Result<Scale<QueryResponse>> {
    let handle = task::spawn_blocking(move || {
        let state_view = state.view();

        let SignedQuery::V1(query) = query;
        let query: QueryRequestWithAuthority = query.payload;
        let authority = query.authority.clone();

        let valid_query = ValidQueryRequest::validate_for_client(query, &state_view)?;
        let response = valid_query.execute(&live_query_store, &state_view, &authority)?;

        Ok::<_, ValidationFail>(response)
    });
    handle
        .await
        .expect("Failed to join query handling task")
        .map(Scale)
        .map_err(Into::into)
}

pub async fn handle_health() -> &'static str {
    "Healthy"
}

#[iroha_futures::telemetry_future]
#[cfg(feature = "schema")]
pub async fn handle_schema() -> Json<iroha_schema::MetaMap> {
    Json(iroha_schema_gen::build_schemas())
}

#[iroha_futures::telemetry_future]
pub async fn handle_get_configuration(kiso: KisoHandle) -> Result<Json<ConfigDTO>> {
    let dto = kiso.get_dto().await?;
    Ok(Json(dto))
}

#[iroha_futures::telemetry_future]
pub async fn handle_post_configuration(
    kiso: KisoHandle,
    value: ConfigDTO,
) -> Result<impl IntoResponse> {
    kiso.update_with_dto(value).await?;
    Ok((StatusCode::ACCEPTED, ()))
}

#[iroha_futures::telemetry_future]
pub async fn handle_blocks_stream(kura: Arc<Kura>, mut stream: WebSocket) -> eyre::Result<()> {
    let BlockSubscriptionRequest(mut from_height) =
        Stream::<BlockSubscriptionRequest>::recv(&mut stream).await?;

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
                if let Some(block) = kura.get_block_by_height(from_height.try_into().expect("INTERNAL BUG: Number of blocks exceeds usize::MAX")) {
                    // TODO: to avoid clone `BlockMessage` could be split into sending and receiving parts
                    Sink::<BlockMessage>::send(&mut stream, BlockMessage(SignedBlock::clone(&block))).await?;
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
        /// `WebSocket` error
        WebSocket(#[from] axum::Error),
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
pub async fn handle_version(state: Arc<State>) -> String {
    use iroha_version::Version;

    let state_view = state.view();
    state_view
        .latest_block()
        .expect("Genesis not applied. Nothing we can do. Solve the issue and rerun.")
        .version()
        .to_string()
}

#[cfg(feature = "telemetry")]
fn update_metrics_gracefully(metrics_reporter: &MetricsReporter) {
    if let Err(error) = metrics_reporter.update_metrics() {
        iroha_logger::error!(%error, "Error while calling `metrics_reporter::update_metrics`.");
    }
}

#[cfg(feature = "telemetry")]
pub fn handle_metrics(metrics_reporter: &MetricsReporter) -> Result<String> {
    update_metrics_gracefully(metrics_reporter);
    metrics_reporter
        .metrics()
        .try_to_string()
        .map_err(Error::Prometheus)
}

#[cfg(feature = "telemetry")]
#[allow(clippy::unnecessary_wraps)]
pub fn handle_status(
    metrics_reporter: &MetricsReporter,
    accept: Option<impl AsRef<[u8]>>,
    tail: Option<&str>,
) -> Result<Response> {
    use eyre::ContextCompat;

    update_metrics_gracefully(metrics_reporter);
    let status = Status::from(&metrics_reporter.metrics());

    if let Some(tail) = tail {
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
            .map(|segment| Json(segment).into_response())?;

        Ok(reply)
    } else if accept.is_some_and(|x| x.as_ref() == utils::PARITY_SCALE_MIME_TYPE.as_bytes()) {
        Ok(Scale(status).into_response())
    } else {
        Ok(Json(status).into_response())
    }
}

#[cfg(feature = "profiling")]
pub mod profiling {
    use std::num::{NonZeroU16, NonZeroU64};

    use nonzero_ext::nonzero;
    use pprof::protos::Message;
    use serde::{Deserialize, Serialize};

    use super::*;

    /// Query params used to configure profile gathering
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Serialize, Deserialize, Clone, Copy)]
    pub struct ProfileParams {
        /// How often to sample Iroha
        #[serde(default = "ProfileParams::default_frequency")]
        frequency: NonZeroU16,
        /// How long to sample Iroha
        #[serde(default = "ProfileParams::default_seconds")]
        seconds: NonZeroU64,
    }

    impl ProfileParams {
        fn default_frequency() -> NonZeroU16 {
            nonzero!(99_u16)
        }

        fn default_seconds() -> NonZeroU64 {
            nonzero!(10_u64)
        }
    }

    /// Serve pprof protobuf profiles
    pub async fn handle_profile(
        ProfileParams { frequency, seconds }: ProfileParams,
        profiling_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    ) -> Result<Vec<u8>> {
        match profiling_lock.try_lock() {
            Ok(_guard) => {
                let mut body = Vec::new();
                {
                    // Create profiler guard
                    let guard = pprof::ProfilerGuardBuilder::default()
                        .frequency(i32::from(frequency.get()))
                        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                        .build()
                        .map_err(|e| {
                            Error::Pprof(eyre::eyre!(
                                "pprof::ProfilerGuardBuilder::build fail: {}",
                                e
                            ))
                        })?;

                    // Collect profiles for seconds
                    tokio::time::sleep(tokio::time::Duration::from_secs(seconds.get())).await;

                    let report = guard
                        .report()
                        .build()
                        .map_err(|e| Error::Pprof(eyre::eyre!("generate report fail: {}", e)))?;

                    let profile = report.pprof().map_err(|e| {
                        Error::Pprof(eyre::eyre!("generate pprof from report fail: {}", e))
                    })?;

                    profile.write_to_vec(&mut body).map_err(|e| {
                        Error::Pprof(eyre::eyre!("encode pprof into bytes fail: {}", e))
                    })?;
                }

                Ok(body)
            }
            Err(_) => {
                // profile already running return error
                Err(Error::Pprof(eyre::eyre!("profiling already running")))
            }
        }
    }
}
