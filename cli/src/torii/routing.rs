//! Routing functions for Torii. If you want to add an endpoint to
//! Iroha you should add it here by creating a `handle_*` function,
//! and add it to impl Torii.

// FIXME: This can't be fixed, because one trait in `warp` is private.
#![allow(opaque_hidden_inferred_bound)]

use std::{
    cmp::Ordering,
    num::{NonZeroU64, NonZeroUsize},
};

use cursor::Batch;
use eyre::WrapErr;
use futures::TryStreamExt;
use iroha_config::{
    base::proxy::Documented,
    iroha::{Configuration, ConfigurationView},
    torii::uri,
    GetConfiguration, PostConfiguration,
};
use iroha_core::{
    smartcontracts::{isi::query::ValidQueryRequest, query::LazyValue},
    sumeragi::SumeragiHandle,
};
use iroha_data_model::{
    block::{
        stream::{BlockMessage, BlockSubscriptionRequest},
        VersionedSignedBlock,
    },
    http::{BatchedResponse, VersionedBatchedResponse},
    prelude::*,
    query::{ForwardCursor, Pagination, Sorting},
};
#[cfg(feature = "telemetry")]
use iroha_telemetry::metrics::Status;
use pagination::Paginate;
use tokio::task;

use super::*;
use crate::stream::{Sink, Stream};

/// Filter for warp which extracts sorting
fn sorting() -> impl warp::Filter<Extract = (Sorting,), Error = warp::Rejection> + Copy {
    warp::query()
}

/// Filter for warp which extracts cursor
fn cursor() -> impl warp::Filter<Extract = (ForwardCursor,), Error = warp::Rejection> + Copy {
    warp::query()
}

/// Filter for warp which extracts pagination
fn paginate() -> impl warp::Filter<Extract = (Pagination,), Error = warp::Rejection> + Copy {
    warp::query()
}

#[iroha_futures::telemetry_future]
async fn handle_instructions(
    queue: Arc<Queue>,
    sumeragi: SumeragiHandle,
    transaction: VersionedSignedTransaction,
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
async fn handle_queries(
    sumeragi: SumeragiHandle,
    query_store: Arc<LiveQueryStore>,
    fetch_size: NonZeroUsize,

    request: VersionedSignedQuery,
    sorting: Sorting,
    pagination: Pagination,

    cursor: ForwardCursor,
) -> Result<Scale<VersionedBatchedResponse<Value>>> {
    let valid_request = sumeragi.apply_wsv(|wsv| ValidQueryRequest::validate(request, wsv))?;
    let request_id = (&valid_request, &sorting, &pagination);

    if let Some(query_id) = cursor.query_id {
        let live_query = query_store
            .remove(&query_id, &request_id)
            .ok_or(Error::UnknownCursor)?;

        return construct_query_response(
            request_id,
            &query_store,
            query_id,
            cursor.cursor.map(NonZeroU64::get),
            live_query,
        );
    }

    sumeragi.apply_wsv(|wsv| {
        let res = valid_request.execute(wsv).map_err(ValidationFail::from)?;

        match res {
            LazyValue::Value(batch) => {
                let cursor = ForwardCursor::default();
                let result = BatchedResponse { batch, cursor };
                Ok(Scale(result.into()))
            }
            LazyValue::Iter(iter) => {
                let live_query = apply_sorting_and_pagination(iter, &sorting, pagination);
                let query_id = uuid::Uuid::new_v4().to_string();

                let curr_cursor = Some(0);
                let live_query = live_query.batched(fetch_size);
                construct_query_response(
                    request_id,
                    &query_store,
                    query_id,
                    curr_cursor,
                    live_query,
                )
            }
        }
    })
}

fn construct_query_response(
    request_id: (&ValidQueryRequest, &Sorting, &Pagination),
    query_store: &LiveQueryStore,
    query_id: String,
    curr_cursor: Option<u64>,
    mut live_query: Batched<Vec<Value>>,
) -> Result<Scale<VersionedBatchedResponse<Value>>> {
    let (batch, next_cursor) = live_query.next_batch(curr_cursor)?;

    if !live_query.is_depleted() {
        query_store.insert(query_id.clone(), request_id, live_query);
    }

    let query_response = BatchedResponse {
        batch: Value::Vec(batch),
        cursor: ForwardCursor {
            query_id: Some(query_id),
            cursor: next_cursor,
        },
    };

    Ok(Scale(query_response.into()))
}

fn apply_sorting_and_pagination(
    iter: impl Iterator<Item = Value>,
    sorting: &Sorting,
    pagination: Pagination,
) -> Vec<Value> {
    if let Some(key) = &sorting.sort_by_metadata_key {
        let mut pairs: Vec<(Option<Value>, Value)> = iter
            .map(|value| {
                let key = match &value {
                    Value::Identifiable(IdentifiableBox::Asset(asset)) => match asset.value() {
                        AssetValue::Store(store) => store.get(key).cloned(),
                        _ => None,
                    },
                    Value::Identifiable(v) => TryInto::<&dyn HasMetadata>::try_into(v)
                        .ok()
                        .and_then(|has_metadata| has_metadata.metadata().get(key))
                        .cloned(),
                    _ => None,
                };
                (key, value)
            })
            .collect();
        pairs.sort_by(
            |(left_key, _), (right_key, _)| match (left_key, right_key) {
                (Some(l), Some(r)) => l.cmp(r),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
        );
        pairs
            .into_iter()
            .map(|(_, val)| val)
            .paginate(pagination)
            .collect()
    } else {
        iter.paginate(pagination).collect()
    }
}

#[derive(serde::Serialize)]
#[non_exhaustive]
enum Health {
    Healthy,
}

fn handle_health() -> Json {
    reply::json(&Health::Healthy)
}

#[iroha_futures::telemetry_future]
#[cfg(feature = "schema-endpoint")]
async fn handle_schema() -> Json {
    reply::json(&iroha_schema_gen::build_schemas())
}

#[iroha_futures::telemetry_future]
async fn handle_pending_transactions(
    queue: Arc<Queue>,
    sumeragi: SumeragiHandle,
    pagination: Pagination,
) -> Result<Scale<Vec<VersionedSignedTransaction>>> {
    let query_response = sumeragi.apply_wsv(|wsv| {
        queue
            .all_transactions(wsv)
            .map(Into::into)
            .paginate(pagination)
            .collect::<Vec<_>>()
        // TODO:
        //.batched(fetch_size)
    });

    Ok(Scale(query_response))
}

#[iroha_futures::telemetry_future]
async fn handle_get_configuration(
    iroha_cfg: Configuration,
    get_cfg: GetConfiguration,
) -> Result<Json> {
    use GetConfiguration::*;

    match get_cfg {
        Docs(field) => <Configuration as Documented>::get_doc_recursive(
            field.iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
        )
        .wrap_err("Failed to get docs {:?field}")
        .and_then(|doc| serde_json::to_value(doc).wrap_err("Failed to serialize docs")),
        // Cast to configuration view to hide private keys.
        Value => serde_json::to_value(ConfigurationView::from(iroha_cfg))
            .wrap_err("Failed to serialize value"),
    }
    .map(|v| reply::json(&v))
    .map_err(Error::Config)
}

#[iroha_futures::telemetry_future]
async fn handle_post_configuration(
    iroha_cfg: Configuration,
    cfg: PostConfiguration,
) -> Result<Json> {
    use iroha_config::base::runtime_upgrades::Reload;
    use PostConfiguration::*;

    iroha_logger::debug!(?cfg);
    match cfg {
        LogLevel(level) => {
            iroha_cfg.logger.max_log_level.reload(level)?;
        }
    };

    Ok(reply::json(&true))
}

#[iroha_futures::telemetry_future]
async fn handle_blocks_stream(kura: Arc<Kura>, mut stream: WebSocket) -> eyre::Result<()> {
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
                        .send(BlockMessage(VersionedSignedBlock::clone(&block)))
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

mod subscription {
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
async fn handle_version(sumeragi: SumeragiHandle) -> Json {
    use iroha_version::Version;

    let string = sumeragi
        .apply_wsv(WorldStateView::latest_block_ref)
        .expect("Genesis not applied. Nothing we can do. Solve the issue and rerun.")
        .version()
        .to_string();
    reply::json(&string)
}

#[cfg(feature = "telemetry")]
fn handle_metrics(sumeragi: &SumeragiHandle) -> Result<String> {
    if let Err(error) = sumeragi.update_metrics() {
        iroha_logger::error!(%error, "Error while calling sumeragi::update_metrics.");
    }
    sumeragi
        .metrics()
        .try_to_string()
        .map_err(Error::Prometheus)
}

#[cfg(feature = "telemetry")]
#[allow(clippy::unnecessary_wraps)]
fn handle_status(sumeragi: &SumeragiHandle) -> Result<warp::reply::Json, Infallible> {
    if let Err(error) = sumeragi.update_metrics() {
        iroha_logger::error!(%error, "Error while calling `sumeragi::update_metrics`.");
    }
    let status = Status::from(&sumeragi.metrics());
    Ok(reply::json(&status))
}

#[cfg(feature = "telemetry")]
#[allow(clippy::unused_async)]
async fn handle_status_precise(sumeragi: SumeragiHandle, segment: String) -> Result<Json> {
    if let Err(error) = sumeragi.update_metrics() {
        iroha_logger::error!(%error, "Error while calling `sumeragi::update_metrics`.");
    }
    // TODO: This probably can be optimised to elide the full
    // structure. Ideally there should remain a list of fields and
    // field aliases somewhere in `serde` macro output, which can
    // elide the creation of the value, and directly read the value
    // behind the mutex.
    let status = Status::from(&sumeragi.metrics());
    match serde_json::to_value(status) {
        Ok(value) => Ok(value
            .get(segment)
            .map_or_else(|| reply::json(&value), reply::json)),
        Err(err) => {
            iroha_logger::error!(%err, "Error while converting to JSON value");
            Ok(reply::json(&None::<String>))
        }
    }
}

impl Torii {
    /// Construct `Torii` from `ToriiConfiguration`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_configuration(
        iroha_cfg: Configuration,
        queue: Arc<Queue>,
        events: EventsSender,
        notify_shutdown: Arc<Notify>,
        sumeragi: SumeragiHandle,
        kura: Arc<Kura>,
    ) -> Self {
        Self {
            iroha_cfg,
            events,
            queue,
            notify_shutdown,
            sumeragi,
            query_store: Arc::default(),
            kura,
        }
    }

    #[cfg(feature = "telemetry")]
    /// Helper function to create router. This router can tested without starting up an HTTP server
    fn create_telemetry_router(
        &self,
    ) -> impl warp::Filter<Extract = impl warp::Reply> + Clone + Send {
        let status_path = warp::path(uri::STATUS);
        let get_router_status_precise = endpoint2(
            handle_status_precise,
            status_path
                .and(add_state!(self.sumeragi.clone()))
                .and(warp::path::param()),
        );
        let get_router_status_bare =
            status_path
                .and(add_state!(self.sumeragi.clone()))
                .and_then(|sumeragi| async move {
                    Ok::<_, Infallible>(WarpResult(handle_status(&sumeragi)))
                });
        let get_router_metrics = warp::path(uri::METRICS)
            .and(add_state!(self.sumeragi))
            .and_then(|sumeragi| async move {
                Ok::<_, Infallible>(WarpResult(handle_metrics(&sumeragi)))
            });
        let get_api_version = warp::path(uri::API_VERSION)
            .and(add_state!(self.sumeragi.clone()))
            .and_then(|sumeragi| async { Ok::<_, Infallible>(handle_version(sumeragi).await) });

        warp::get()
            .and(get_router_status_precise.or(get_router_status_bare))
            .or(get_router_metrics)
            .or(get_api_version)
            .with(warp::trace::request())
    }

    /// Helper function to create router. This router can tested without starting up an HTTP server
    fn create_api_router(&self) -> impl warp::Filter<Extract = impl warp::Reply> + Clone + Send {
        let health_route = warp::get()
            .and(warp::path(uri::HEALTH))
            .and_then(|| async { Ok::<_, Infallible>(handle_health()) });

        let get_router = warp::get().and(
            endpoint3(
                handle_pending_transactions,
                warp::path(uri::PENDING_TRANSACTIONS)
                    .and(add_state!(self.queue, self.sumeragi,))
                    .and(paginate()),
            )
            .or(endpoint2(
                handle_get_configuration,
                warp::path(uri::CONFIGURATION)
                    .and(add_state!(self.iroha_cfg))
                    .and(warp::body::json()),
            )),
        );

        #[cfg(feature = "schema-endpoint")]
        let get_router = get_router.or(warp::path(uri::SCHEMA)
            .and_then(|| async { Ok::<_, Infallible>(handle_schema().await) }));

        let post_router = warp::post()
            .and(
                endpoint3(
                    handle_instructions,
                    warp::path(uri::TRANSACTION)
                        .and(add_state!(self.queue, self.sumeragi))
                        .and(warp::body::content_length_limit(
                            self.iroha_cfg.torii.max_content_len.into(),
                        ))
                        .and(body::versioned()),
                )
                .or(endpoint7(
                    handle_queries,
                    warp::path(uri::QUERY)
                        .and(add_state!(
                            self.sumeragi,
                            self.query_store,
                            NonZeroUsize::try_from(self.iroha_cfg.torii.fetch_size)
                                .expect("u64 should always fit into usize"),
                        ))
                        .and(body::versioned())
                        .and(sorting())
                        .and(paginate())
                        .and(cursor()),
                ))
                .or(endpoint2(
                    handle_post_configuration,
                    warp::path(uri::CONFIGURATION)
                        .and(add_state!(self.iroha_cfg))
                        .and(warp::body::json()),
                )),
            )
            .recover(|rejection| async move { body::recover_versioned(rejection) });

        let events_ws_router = warp::path(uri::SUBSCRIPTION)
            .and(add_state!(self.events))
            .and(warp::ws())
            .map(|events, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) = subscription::handle_subscription(events, this_ws).await {
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
                    if let Err(error) = handle_blocks_stream(sumeragi, this_ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe to blocks stream");
                    }
                })
            });

        let ws_router = events_ws_router
            .or(blocks_ws_router)
            .with(warp::trace::request());

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

    /// Start status and metrics endpoints.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    #[cfg(feature = "telemetry")]
    fn start_telemetry(self: Arc<Self>) -> eyre::Result<Vec<tokio::task::JoinHandle<()>>> {
        let telemetry_url = &self.iroha_cfg.torii.telemetry_url;

        let mut handles = vec![];
        match telemetry_url.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    let torii = Arc::clone(&self);

                    let telemetry_router = torii.create_telemetry_router();
                    let signal_fut = async move { torii.notify_shutdown.notified().await };
                    let (_, serve_fut) =
                        warp::serve(telemetry_router).bind_with_graceful_shutdown(addr, signal_fut);

                    handles.push(task::spawn(serve_fut));
                }

                Ok(handles)
            }
            Err(error) => {
                iroha_logger::error!(%telemetry_url, ?error, "Telemetry address configuration parse error");
                Err(eyre::Error::new(error))
            }
        }
    }

    /// Start main api endpoints.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    fn start_api(self: Arc<Self>) -> eyre::Result<Vec<tokio::task::JoinHandle<()>>> {
        let api_url = &self.iroha_cfg.torii.api_url;

        let mut handles = vec![];
        match api_url.to_socket_addrs() {
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
                iroha_logger::error!(%api_url, %error, "API address configuration parse error");
                Err(eyre::Error::new(error))
            }
        }
    }

    /// To handle incoming requests `Torii` should be started first.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    #[iroha_futures::telemetry_future]
    pub(crate) async fn start(self) -> eyre::Result<()> {
        let query_idle_time = Duration::from_millis(self.iroha_cfg.torii.query_idle_time_ms.get());

        let torii = Arc::new(self);
        let mut handles = vec![];

        #[cfg(feature = "telemetry")]
        handles.extend(Arc::clone(&torii).start_telemetry()?);
        handles.extend(Arc::clone(&torii).start_api()?);
        handles.push(
            Arc::clone(&torii.query_store)
                .expired_query_cleanup(query_idle_time, Arc::clone(&torii.notify_shutdown)),
        );

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
