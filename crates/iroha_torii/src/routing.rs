//! Routing functions for Torii. If you want to add an endpoint to
//! Iroha you should add it here by creating a `handle_*` function,
//! and add it to impl Torii.

use axum::extract::ws::WebSocket;
#[cfg(feature = "telemetry")]
use eyre::{eyre, WrapErr};
use iroha_config::client_api::ConfigDTO;
use iroha_core::{query::store::LiveQueryStoreHandle, smartcontracts::query::ValidQueryRequest};
use iroha_data_model::{
    self,
    prelude::*,
    query::{QueryRequestWithAuthority, QueryResponse, SignedQuery},
};
#[cfg(feature = "telemetry")]
use iroha_telemetry::metrics::Status;
use tokio::task;

use super::*;

#[iroha_futures::telemetry_future]
pub async fn handle_transaction(
    chain_id: Arc<ChainId>,
    queue: Arc<Queue>,
    state: Arc<State>,
    tx: SignedTransaction,
) -> Result<()> {
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi.max_clock_drift(), params.transaction)
    };

    let accepted_tx = AcceptedTransaction::accept(tx, &chain_id, max_clock_drift, tx_limits)
        .map_err(Error::AcceptTransaction)?;

    queue
        .push(accepted_tx, state.view())
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

pub mod block {
    //! Blocks stream handler

    use stream::WebSocketScale;

    use super::*;
    use crate::block;

    /// Type for any error during blocks streaming
    #[derive(Debug, displaydoc::Display, thiserror::Error)]
    enum Error {
        /// Block consumption resulted in an error: {_0}
        Consumer(#[from] Box<block::Error>),
        /// Connection is closed
        Close,
    }

    impl From<block::Error> for Error {
        fn from(error: block::Error) -> Self {
            match error {
                block::Error::Stream(err) if matches!(*err, stream::Error::Closed) => Self::Close,
                error => Self::Consumer(Box::new(error)),
            }
        }
    }

    type Result<T> = core::result::Result<T, Error>;

    #[iroha_futures::telemetry_future]
    pub async fn handle_blocks_stream(kura: Arc<Kura>, stream: WebSocket) -> eyre::Result<()> {
        let mut stream = WebSocketScale(stream);
        let init_and_subscribe = async {
            let mut consumer = block::Consumer::new(&mut stream, kura).await?;
            subscribe_forever(&mut consumer).await
        };

        match init_and_subscribe.await {
            Ok(()) => stream.close().await.map_err(Into::into),
            Err(Error::Close) => Ok(()),
            Err(err) => {
                // NOTE: try close websocket and return initial error
                let _ = stream.close().await;
                Err(err.into())
            }
        }
    }

    /// Make endless `consumer` subscription for `blocks`
    ///
    /// Ideally should return `Result<!>` cause it either runs forever or returns error
    async fn subscribe_forever(consumer: &mut block::Consumer<'_>) -> Result<()> {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
        loop {
            tokio::select! {
                // Wait for stream to be closed by client
                closed = consumer.stream.closed() => {
                    match closed {
                        Ok(()) => return Err(Error::Close),
                        Err(err) => return Err(block::Error::from(err).into())
                    }
                }
                // This branch sends blocks
                _ = interval.tick() => consumer.consume().await?,
            }
        }
    }
}

pub mod event {
    //! Events stream handler

    use stream::WebSocketScale;

    use super::*;
    use crate::event;

    /// Type for any error during events streaming
    #[derive(Debug, displaydoc::Display, thiserror::Error)]
    enum Error {
        /// Event consumption resulted in an error: {_0}
        Consumer(#[from] Box<event::Error>),
        /// Event reception error
        Event(#[from] tokio::sync::broadcast::error::RecvError),
        /// Connection is closed
        Close,
    }

    impl From<event::Error> for Error {
        fn from(error: event::Error) -> Self {
            match error {
                event::Error::Stream(err) if matches!(*err, stream::Error::Closed) => Self::Close,
                error => Self::Consumer(Box::new(error)),
            }
        }
    }

    type Result<T> = core::result::Result<T, Error>;

    /// Subscribes `stream` for `events` filtered by filter that is
    /// received through the `stream`
    #[iroha_futures::telemetry_future]
    pub async fn handle_events_stream(events: EventsSender, stream: WebSocket) -> eyre::Result<()> {
        let mut stream = WebSocketScale(stream);
        let init_and_subscribe = async {
            let mut consumer = event::Consumer::new(&mut stream).await?;
            subscribe_forever(events, &mut consumer).await
        };

        match init_and_subscribe.await {
            Ok(()) => stream.close().await.map_err(Into::into),
            Err(Error::Close) => Ok(()),
            Err(err) => {
                // NOTE: try close websocket and return initial error
                let _ = stream.close().await;
                Err(err.into())
            }
        }
    }

    /// Make endless `consumer` subscription for `events`
    ///
    /// Ideally should return `Result<!>` cause it either runs forever or returns error
    async fn subscribe_forever(
        events: EventsSender,
        consumer: &mut event::Consumer<'_>,
    ) -> Result<()> {
        let mut events = events.subscribe();

        loop {
            tokio::select! {
                // Wait for stream to be closed by client
                closed = consumer.stream.closed() => {
                    match closed {
                        Ok(()) => return Err(Error::Close),
                        Err(err) => return Err(event::Error::from(err).into())
                    }
                }
                // This branch catches and sends events
                event = events.recv() => {
                    let event = event?;
                    iroha_logger::trace!(?event);
                    consumer.consume(event).await?;
                }
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
