//! The web server of Iroha. `Torii` translates to gateway.
//!
//! Crate provides the following features that are not enabled by default:
//!
//! - `telemetry`: enables Status, Metrics, and API Version endpoints
//! - `schema`: enables Data Model Schema endpoint

use std::{
    convert::Infallible,
    fmt::{Debug, Write as _},
    net::ToSocketAddrs,
    sync::Arc,
};

use futures::{stream::FuturesUnordered, StreamExt};
use iroha_config::parameters::actual::Torii as Config;
#[cfg(feature = "telemetry")]
use iroha_core::metrics::MetricsReporter;
use iroha_core::{
    kiso::{Error as KisoError, KisoHandle},
    kura::Kura,
    prelude::*,
    query::store::LiveQueryStoreHandle,
    queue::{self, Queue},
    state::State,
    EventsSender,
};
use iroha_data_model::ChainId;
use iroha_primitives::addr::SocketAddr;
use iroha_torii_const::uri;
use tokio::{sync::Notify, task};
use utils::*;
use warp::{
    http::StatusCode,
    reply::{self, Json, Response},
    ws::{WebSocket, Ws},
    Filter as _, Reply,
};

#[macro_use]
pub(crate) mod utils;
mod event;
mod routing;
mod stream;

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii {
    chain_id: Arc<ChainId>,
    kiso: KisoHandle,
    queue: Arc<Queue>,
    events: EventsSender,
    notify_shutdown: Arc<Notify>,
    query_service: LiveQueryStoreHandle,
    kura: Arc<Kura>,
    transaction_max_content_length: u64,
    address: SocketAddr,
    state: Arc<State>,
    #[cfg(feature = "telemetry")]
    metrics_reporter: MetricsReporter,
}

impl Torii {
    /// Construct `Torii`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        kiso: KisoHandle,
        config: Config,
        queue: Arc<Queue>,
        events: EventsSender,
        notify_shutdown: Arc<Notify>,
        query_service: LiveQueryStoreHandle,
        kura: Arc<Kura>,
        state: Arc<State>,
        #[cfg(feature = "telemetry")] metrics_reporter: MetricsReporter,
    ) -> Self {
        Self {
            chain_id: Arc::new(chain_id),
            kiso,
            queue,
            events,
            notify_shutdown,
            query_service,
            kura,
            state,
            #[cfg(feature = "telemetry")]
            metrics_reporter,
            address: config.address.into_value(),
            transaction_max_content_length: config.max_content_len_bytes,
        }
    }

    /// Helper function to create router. This router can be tested without starting up an HTTP server
    #[allow(clippy::too_many_lines)]
    fn create_api_router(&self) -> impl warp::Filter<Extract = impl warp::Reply> + Clone + Send {
        let health_route = warp::get()
            .and(warp::path(uri::HEALTH))
            .and_then(|| async { Ok::<_, Infallible>(routing::handle_health()) });

        let get_router = warp::get().and(
            warp::path(uri::CONFIGURATION)
                .and(add_state!(self.kiso))
                .and_then(|kiso| async move {
                    Ok::<_, Infallible>(WarpResult(routing::handle_get_configuration(kiso).await))
                }),
        );

        #[cfg(feature = "telemetry")]
        let get_router = get_router
            .or(warp::path(uri::STATUS)
                .and(add_state!(self.metrics_reporter.clone()))
                .and(warp::header::optional(warp::http::header::ACCEPT.as_str()))
                .and(warp::path::tail())
                .and_then(
                    |metrics_reporter, accept: Option<String>, tail| async move {
                        Ok::<_, Infallible>(crate::utils::WarpResult(routing::handle_status(
                            &metrics_reporter,
                            accept.as_ref(),
                            &tail,
                        )))
                    },
                ))
            .or(warp::path(uri::METRICS)
                .and(add_state!(self.metrics_reporter))
                .and_then(|metrics_reporter| async move {
                    Ok::<_, Infallible>(crate::utils::WarpResult(routing::handle_metrics(
                        &metrics_reporter,
                    )))
                }))
            .or(warp::path(uri::API_VERSION)
                .and(add_state!(self.state.clone()))
                .and_then(|state| async {
                    Ok::<_, Infallible>(routing::handle_version(state).await)
                }));

        #[cfg(feature = "schema")]
        let get_router = get_router.or(warp::path(uri::SCHEMA)
            .and_then(|| async { Ok::<_, Infallible>(routing::handle_schema().await) }));

        #[cfg(feature = "profiling")]
        let get_router = {
            // `warp` panics if there is `/` in the string given to the `warp::path` filter
            // Path filter has to be boxed to have a single uniform type during iteration
            let profile_router_path = uri::PROFILE
                .split('/')
                .skip_while(|p| p.is_empty())
                .fold(warp::any().boxed(), |path_filter, path| {
                    path_filter.and(warp::path(path)).boxed()
                });

            let profiling_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
            get_router.or(profile_router_path
                .and(warp::query::<routing::profiling::ProfileParams>())
                .and_then(move |params| {
                    let profiling_lock = Arc::clone(&profiling_lock);
                    async move {
                        Ok::<_, Infallible>(
                            routing::profiling::handle_profile(params, profiling_lock).await,
                        )
                    }
                }))
        };

        let post_router = warp::post()
            .and(
                endpoint4(
                    routing::handle_transaction,
                    warp::path(uri::TRANSACTION)
                        .and(add_state!(self.chain_id, self.queue, self.state.clone()))
                        .and(warp::body::content_length_limit(
                            self.transaction_max_content_length,
                        ))
                        .and(body::versioned()),
                )
                .or(endpoint3(
                    routing::handle_queries,
                    warp::path(uri::QUERY)
                        .and(add_state!(self.query_service, self.state.clone(),))
                        .and(routing::client_query_request()),
                ))
                .or(endpoint2(
                    routing::handle_post_configuration,
                    warp::path(uri::CONFIGURATION)
                        .and(add_state!(self.kiso))
                        .and(warp::body::json()),
                )),
            )
            .recover(|rejection| async move { body::recover_versioned(rejection) });

        let events_ws_router = warp::path(uri::SUBSCRIPTION)
            .and(add_state!(self.events))
            .and(warp::ws())
            .map(|events, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) =
                        routing::subscription::handle_subscription(events, this_ws).await
                    {
                        iroha_logger::error!(%error, "Failure during subscription");
                    }
                })
            });

        // `warp` panics if there is `/` in the string given to the `warp::path` filter
        // Path filter has to be boxed to have a single uniform type during iteration
        let block_ws_router_path = uri::BLOCKS_STREAM
            .split('/')
            .skip_while(|p| p.is_empty())
            .fold(warp::any().boxed(), |path_filter, path| {
                path_filter.and(warp::path(path)).boxed()
            });

        let blocks_ws_router = block_ws_router_path
            .and(add_state!(self.kura))
            .and(warp::ws())
            .map(|sumeragi: Arc<_>, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) = routing::handle_blocks_stream(sumeragi, this_ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe to blocks stream");
                    }
                })
            });

        let ws_router = events_ws_router.or(blocks_ws_router);

        warp::any()
            .and(
                // we want to avoid logging for the "health" endpoint.
                // we have to place it **first** so that warp's trace will
                // not log 404 if it doesn't find "/health" which might be placed
                // **after** `.with(trace)`
                health_route,
            )
            .or(ws_router
                .or(get_router)
                .or(post_router)
                .with(warp::trace::request()))
    }

    /// Start main API endpoints.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    fn start_api(self: Arc<Self>) -> eyre::Result<Vec<task::JoinHandle<()>>> {
        let torii_address = &self.address;

        let handles = torii_address
            .to_socket_addrs()?
            .map(|addr| {
                let torii = Arc::clone(&self);

                let api_router = torii.create_api_router();
                let signal_fut = async move { torii.notify_shutdown.notified().await };
                // FIXME: warp panics if fails to bind!
                //        handle this properly, report address origin after Axum
                //        migration: https://github.com/hyperledger/iroha/issues/3776
                let (_, serve_fut) =
                    warp::serve(api_router).bind_with_graceful_shutdown(addr, signal_fut);

                task::spawn(serve_fut)
            })
            .collect();

        Ok(handles)
    }

    /// To handle incoming requests `Torii` should be started first.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    #[iroha_futures::telemetry_future]
    pub async fn start(self) -> eyre::Result<()> {
        let torii = Arc::new(self);
        let mut handles = vec![];

        handles.extend(Arc::clone(&torii).start_api()?);

        handles
            .into_iter()
            .collect::<FuturesUnordered<_>>()
            .for_each(|handle| {
                if let Err(error) = handle {
                    iroha_logger::error!(%error, "Join handle error");
                }

                futures::future::ready(())
            })
            .await;

        Ok(())
    }
}

/// Torii errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Failed to process query
    Query(#[from] iroha_data_model::ValidationFail),
    /// Failed to accept transaction
    AcceptTransaction(#[from] iroha_core::tx::AcceptTransactionFail),
    /// Failed to get or set configuration
    Config(#[source] eyre::Report),
    /// Failed to push into queue
    PushIntoQueue(#[from] Box<queue::Error>),
    #[cfg(feature = "telemetry")]
    /// Failed to get Prometheus metrics
    Prometheus(#[source] eyre::Report),
    #[cfg(feature = "profiling")]
    /// Failed to get pprof profile
    Pprof(#[source] eyre::Report),
    #[cfg(feature = "telemetry")]
    /// Failed to get status
    StatusFailure(#[source] eyre::Report),
    /// Failure caused by configuration subsystem
    ConfigurationFailure(#[from] KisoError),
    /// Failed to find status segment by provided path
    StatusSegmentNotFound(#[source] eyre::Report),
}

impl Reply for Error {
    fn into_response(self) -> Response {
        match self {
            Self::Query(err) => {
                reply::with_status(utils::Scale(&err), Self::query_status_code(&err))
                    .into_response()
            }
            _ => reply::with_status(Self::to_string(&self), self.status_code()).into_response(),
        }
    }
}

impl Error {
    fn status_code(&self) -> StatusCode {
        use Error::*;

        match self {
            Query(e) => Self::query_status_code(e),
            AcceptTransaction(_) => StatusCode::BAD_REQUEST,
            Config(_) | StatusSegmentNotFound(_) => StatusCode::NOT_FOUND,
            PushIntoQueue(err) => match **err {
                queue::Error::Full => StatusCode::INTERNAL_SERVER_ERROR,
                queue::Error::SignatoryInconsistent => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            },
            #[cfg(feature = "telemetry")]
            Prometheus(_) | StatusFailure(_) => StatusCode::INTERNAL_SERVER_ERROR,
            #[cfg(feature = "profiling")]
            Pprof(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ConfigurationFailure(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn query_status_code(validation_error: &iroha_data_model::ValidationFail) -> StatusCode {
        use iroha_data_model::{
            isi::error::InstructionExecutionError, query::error::QueryExecutionFail::*,
            ValidationFail::*,
        };

        match validation_error {
            NotPermitted(_) => StatusCode::FORBIDDEN,
            QueryFailed(query_error)
            | InstructionFailed(InstructionExecutionError::Query(query_error)) => match query_error
            {
                Conversion(_) | UnknownCursor | FetchSizeTooBig | InvalidSingularParameters => {
                    StatusCode::BAD_REQUEST
                }
                Signature(_) => StatusCode::UNAUTHORIZED,
                Find(_) => StatusCode::NOT_FOUND,
            },
            TooComplex => StatusCode::UNPROCESSABLE_ENTITY,
            InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            InstructionFailed(error) => {
                iroha_logger::error!(
                ?error,
                "Query validation failed with unexpected error. This means a bug inside Runtime Executor",
            );
                StatusCode::INTERNAL_SERVER_ERROR
            }
            UnrecognizedAuthority | InactiveAuthority => StatusCode::UNAUTHORIZED,
        }
    }

    fn to_string(err: &dyn std::error::Error) -> String {
        let mut s = "Error:\n".to_owned();
        let mut idx = 0_i32;
        let mut err_opt = Some(err);
        while let Some(e) = err_opt {
            write!(s, "    {idx}: {}", &e.to_string()).expect("Valid");
            idx += 1_i32;
            err_opt = e.source()
        }
        s
    }
}

/// Result type
pub type Result<T, E = Error> = std::result::Result<T, E>;
