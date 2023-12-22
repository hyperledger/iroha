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
use iroha_config::torii::{uri, Configuration as ToriiConfiguration};
use iroha_core::{
    kiso::{Error as KisoError, KisoHandle},
    kura::Kura,
    prelude::*,
    query::store::LiveQueryStoreHandle,
    queue::{self, Queue},
    sumeragi::SumeragiHandle,
    EventsSender,
};
use iroha_primitives::addr::SocketAddr;
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
    kiso: KisoHandle,
    queue: Arc<Queue>,
    events: EventsSender,
    notify_shutdown: Arc<Notify>,
    sumeragi: SumeragiHandle,
    query_service: LiveQueryStoreHandle,
    kura: Arc<Kura>,
    transaction_max_content_length: u64,
    address: SocketAddr,
}

impl Torii {
    /// Construct `Torii`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kiso: KisoHandle,
        config: &ToriiConfiguration,
        queue: Arc<Queue>,
        events: EventsSender,
        notify_shutdown: Arc<Notify>,
        sumeragi: SumeragiHandle,
        query_service: LiveQueryStoreHandle,
        kura: Arc<Kura>,
    ) -> Self {
        Self {
            kiso,
            queue,
            events,
            notify_shutdown,
            sumeragi,
            query_service,
            kura,
            address: config.api_url.clone(),
            transaction_max_content_length: config.max_content_len.into(),
        }
    }

    /// Helper function to create router. This router can be tested without starting up an HTTP server
    #[allow(clippy::too_many_lines)]
    fn create_api_router(&self) -> impl warp::Filter<Extract = impl warp::Reply> + Clone + Send {
        let health_route = warp::get()
            .and(warp::path(uri::HEALTH))
            .and_then(|| async { Ok::<_, Infallible>(routing::handle_health()) });

        let get_router = warp::get().and(
            endpoint3(
                routing::handle_pending_transactions,
                warp::path(uri::PENDING_TRANSACTIONS)
                    .and(add_state!(self.queue, self.sumeragi,))
                    .and(routing::paginate()),
            )
            .or(warp::path(uri::CONFIGURATION)
                .and(add_state!(self.kiso))
                .and_then(|kiso| async move {
                    Ok::<_, Infallible>(WarpResult(routing::handle_get_configuration(kiso).await))
                })),
        );

        #[cfg(feature = "telemetry")]
        let get_router = get_router
            .or(warp::path(uri::STATUS)
                .and(add_state!(self.sumeragi.clone()))
                .and(warp::header::optional(warp::http::header::ACCEPT.as_str()))
                .and(warp::path::tail())
                .and_then(|sumeragi, accept: Option<String>, tail| async move {
                    Ok::<_, Infallible>(crate::utils::WarpResult(routing::handle_status(
                        &sumeragi,
                        accept.as_ref(),
                        &tail,
                    )))
                }))
            .or(warp::path(uri::METRICS)
                .and(add_state!(self.sumeragi))
                .and_then(|sumeragi| async move {
                    Ok::<_, Infallible>(crate::utils::WarpResult(routing::handle_metrics(
                        &sumeragi,
                    )))
                }))
            .or(warp::path(uri::API_VERSION)
                .and(add_state!(self.sumeragi.clone()))
                .and_then(|sumeragi| async {
                    Ok::<_, Infallible>(routing::handle_version(sumeragi).await)
                }));

        #[cfg(feature = "schema")]
        let get_router = get_router.or(warp::path(uri::SCHEMA)
            .and_then(|| async { Ok::<_, Infallible>(routing::handle_schema().await) }));

        let post_router = warp::post()
            .and(
                endpoint3(
                    routing::handle_transaction,
                    warp::path(uri::TRANSACTION)
                        .and(add_state!(self.queue, self.sumeragi))
                        .and(warp::body::content_length_limit(
                            self.transaction_max_content_length,
                        ))
                        .and(body::versioned()),
                )
                .or(endpoint3(
                    routing::handle_queries,
                    warp::path(uri::QUERY)
                        .and(add_state!(self.query_service, self.sumeragi,))
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

    /// Start main api endpoints.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    fn start_api(self: Arc<Self>) -> eyre::Result<Vec<task::JoinHandle<()>>> {
        let torii_address = &self.address;

        let mut handles = vec![];
        match torii_address.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    let torii = Arc::clone(&self);

                    let api_router = torii.create_api_router();
                    let signal_fut = async move { torii.notify_shutdown.notified().await };
                    let (_, serve_fut) =
                        warp::serve(api_router).bind_with_graceful_shutdown(addr, signal_fut);

                    handles.push(task::spawn(serve_fut));
                }

                Ok(handles)
            }
            Err(error) => {
                iroha_logger::error!(%torii_address, %error, "API address configuration parse error");
                Err(eyre::Error::new(error))
            }
        }
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
    /// Error while getting or setting configuration
    Config(#[source] eyre::Report),
    /// Failed to push into queue
    PushIntoQueue(#[from] Box<queue::Error>),
    #[cfg(feature = "telemetry")]
    /// Error while getting Prometheus metrics
    Prometheus(#[source] eyre::Report),
    #[cfg(feature = "telemetry")]
    /// Internal error while getting status
    StatusFailure(#[source] eyre::Report),
    /// Failure caused by configuration subsystem
    ConfigurationFailure(#[from] KisoError),
    /// Cannot find status segment by provided path
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
                queue::Error::SignatureCondition { .. } => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            },
            #[cfg(feature = "telemetry")]
            Prometheus(_) | StatusFailure(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
                Conversion(_) | UnknownCursor | FetchSizeTooBig => StatusCode::BAD_REQUEST,
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
