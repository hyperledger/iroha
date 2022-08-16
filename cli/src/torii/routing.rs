//! Routing functions for Torii. If you want to add an endpoint to
//! Iroha you should add it here by creating a `handle_*` function,
//! and add it to impl Torii. This module also defines the `VerifiedQueryRequest`,
//! which is the only kind of query that is permitted to execute.
use std::num::TryFromIntError;

use eyre::WrapErr;
use iroha_actor::Addr;
use iroha_config::{
    base::proxy::Documented,
    iroha::{Configuration, ConfigurationView},
    torii::uri,
    GetConfiguration, PostConfiguration,
};
use iroha_core::{
    block::stream::{
        BlockPublisherMessage, BlockSubscriberMessage, VersionedBlockPublisherMessage,
        VersionedBlockSubscriberMessage,
    },
    smartcontracts::{
        isi::query::{Error as QueryError, ValidQueryRequest},
        permissions::prelude::*,
    },
};
use iroha_crypto::SignatureOf;
use iroha_data_model::{
    predicate::PredicateBox,
    prelude::*,
    query::{self, SignedQueryRequest},
};
#[cfg(feature = "telemetry")]
use iroha_telemetry::metrics::Status;
use parity_scale_codec::{Decode, Encode};
use tokio::task;

use super::*;
use crate::stream::{Sink, Stream};

/// Query Request verified on the Iroha node side.
#[derive(Debug, Decode, Encode)]
pub struct VerifiedQueryRequest {
    /// Payload.
    payload: query::Payload,
    /// Signature of the client who sends this query.
    signature: SignatureOf<query::Payload>,
}

impl VerifiedQueryRequest {
    /// Validate query.
    ///
    /// # Errors
    /// if:
    /// - Account doesn't exist.
    /// - Account doesn't have the correct public key.
    /// - Account has incorrect permissions.
    pub fn validate(
        self,
        wsv: &WorldStateView,
        query_judge: &dyn Judge<Operation = QueryBox>,
    ) -> Result<(ValidQueryRequest, PredicateBox), QueryError> {
        let account_has_public_key = wsv.map_account(&self.payload.account_id, |account| {
            account.contains_signatory(self.signature.public_key())
        })?;
        if !account_has_public_key {
            return Err(QueryError::Signature(String::from(
                "Signature public key doesn't correspond to the account.",
            )));
        }
        query_judge
            .judge(&self.payload.account_id, &self.payload.query, wsv)
            .map_err(QueryError::Permission)?;
        Ok((
            ValidQueryRequest::new(self.payload.query),
            self.payload.filter,
        ))
    }
}

impl TryFrom<SignedQueryRequest> for VerifiedQueryRequest {
    type Error = QueryError;

    fn try_from(query: SignedQueryRequest) -> Result<Self, Self::Error> {
        query
            .signature
            .verify(&query.payload)
            .map(|_| Self {
                payload: query.payload,
                signature: query.signature,
            })
            .map_err(|e| Self::Error::Signature(e.to_string()))
    }
}

#[iroha_futures::telemetry_future]
pub(crate) async fn handle_instructions(
    iroha_cfg: Configuration,
    queue: Arc<Queue>,
    transaction: VersionedTransaction,
) -> Result<Empty> {
    let transaction: Transaction = transaction.into_v1();
    let transaction = VersionedAcceptedTransaction::from_transaction(
        transaction,
        &iroha_cfg.sumeragi.transaction_limits,
    )
    .map_err(Error::AcceptTransaction)?;
    #[allow(clippy::map_err_ignore)]
    let push_result = queue.push(transaction).map_err(|(_, err)| err);
    if let Err(ref error) = push_result {
        iroha_logger::warn!(%error, "Failed to push into queue")
    }
    push_result
        .map_err(Box::new)
        .map_err(Error::PushIntoQueue)
        .map(|()| Empty)
}

#[iroha_futures::telemetry_future]
pub(crate) async fn handle_queries(
    wsv: Arc<WorldStateView>,
    query_judge: QueryJudgeArc,
    pagination: Pagination,
    sorting: Sorting,
    request: VerifiedQueryRequest,
) -> Result<Scale<VersionedPaginatedQueryResult>> {
    let (valid_request, filter) = request.validate(&wsv, query_judge.as_ref())?;
    let original_result = valid_request.execute(&wsv)?;
    let result = filter.filter(original_result);

    let (total, result) = if let Value::Vec(vec_of_val) = result {
        let len = vec_of_val.len();
        let vec_of_val = apply_sorting_and_pagination(vec_of_val, &sorting, pagination);

        (len, Value::Vec(vec_of_val))
    } else {
        (1, result)
    };

    let total = total
        .try_into()
        .map_err(|e: TryFromIntError| QueryError::Conversion(e.to_string()))?;
    let result = QueryResult(result);
    let paginated_result = PaginatedQueryResult {
        result,
        pagination,
        filter,
        total,
    };
    Ok(Scale(paginated_result.into()))
}

fn apply_sorting_and_pagination(
    mut vec_of_val: Vec<Value>,
    sorting: &Sorting,
    pagination: Pagination,
) -> Vec<Value> {
    if let Some(ref key) = sorting.sort_by_metadata_key {
        let f = |value1: &Value| {
            if let Value::U128(num) = value1 {
                *num
            } else {
                0
            }
        };

        vec_of_val.sort_by_key(|value0| match value0 {
            Value::Identifiable(IdentifiableBox::Asset(asset)) => match asset.value() {
                AssetValue::Store(store) => store.get(key).map_or(0, f),
                _ => 0,
            },
            Value::Identifiable(v) => TryInto::<&dyn HasMetadata>::try_into(v)
                .map(|has_metadata| has_metadata.metadata().get(key).map_or(0, f))
                .unwrap_or(0),
            _ => 0,
        });
    }

    vec_of_val.into_iter().paginate(pagination).collect()
}

#[derive(serde::Serialize)]
#[non_exhaustive]
enum Health {
    Healthy,
}

#[iroha_futures::telemetry_future]
async fn handle_health() -> Json {
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
    pagination: Pagination,
) -> Result<Scale<VersionedPendingTransactions>> {
    Ok(Scale(
        queue
            .all_transactions()
            .into_iter()
            .map(VersionedAcceptedTransaction::into_v1)
            .map(Transaction::from)
            .paginate(pagination)
            .collect(),
    ))
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
async fn handle_blocks_stream(wsv: &WorldStateView, mut stream: WebSocket) -> eyre::Result<()> {
    let subscription_request: VersionedBlockSubscriberMessage = stream.recv().await?;
    let mut from_height = subscription_request.into_v1().try_into()?;

    stream
        .send(VersionedBlockPublisherMessage::from(
            BlockPublisherMessage::SubscriptionAccepted,
        ))
        .await?;

    let mut rx = wsv.subscribe_to_new_block_notifications();
    stream_blocks(&mut from_height, wsv, &mut stream).await?;

    loop {
        rx.changed().await?;
        stream_blocks(&mut from_height, wsv, &mut stream).await?;
    }
}

async fn stream_blocks(
    from_height: &mut u64,
    wsv: &WorldStateView,
    stream: &mut WebSocket,
) -> eyre::Result<()> {
    #[allow(clippy::expect_used)]
    for block in wsv.blocks_from_height(
        (*from_height)
            .try_into()
            .expect("Blockchain size limit reached"),
    ) {
        stream
            .send(VersionedBlockPublisherMessage::from(
                BlockPublisherMessage::from(block),
            ))
            .await?;

        let message: VersionedBlockSubscriberMessage = stream.recv().await?;
        if let BlockSubscriberMessage::BlockReceived = message.into_v1() {
            *from_height += 1;
        } else {
            return Err(eyre!("Expected `BlockReceived` message"));
        }
    }

    Ok(())
}

mod subscription {
    //! Contains the `handle_subscription` functions and used for general routing.

    use super::*;
    use crate::event;

    /// Type for any error during subscription handling
    #[derive(thiserror::Error, Debug)]
    enum Error {
        /// Event consuming error
        #[error("Event consuming error: {0}")]
        Consumer(Box<event::Error>),
        /// Event receiving error
        #[error("Event receiving error: {0}")]
        Event(#[from] tokio::sync::broadcast::error::RecvError),
        /// Error from provided websocket
        #[error("WebSocket error: {0}")]
        WebSocket(#[from] warp::Error),
        /// Error, indicating that `Close` message was received
        #[error("`Close` message received")]
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
    /// Subscribes `stream` for `events` filtered by filter that is received through the `stream`
    ///
    /// There should be a [`warp::filters::ws::Message::close()`] message to end subscription
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
    /// Ideally should return `Result<!>` cause it either runs forever either returns `Err` variant
    async fn subscribe_forever(events: EventsSender, consumer: &mut event::Consumer) -> Result<()> {
        let mut events = events.subscribe();

        loop {
            tokio::select! {
                // This branch catches `Close` ans unexpected messages
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
async fn handle_version(wsv: Arc<WorldStateView>) -> Json {
    use iroha_version::Version;

    #[allow(clippy::expect_used)]
    reply::json(
        &wsv.blocks()
            .last()
            .expect("At least genesis should always exist")
            .value()
            .version()
            .to_string(),
    )
}

#[cfg(feature = "telemetry")]
async fn handle_metrics(wsv: Arc<WorldStateView>, network: Addr<IrohaNetwork>) -> Result<String> {
    update_metrics(&wsv, network).await?;
    wsv.metrics.try_to_string().map_err(Error::Prometheus)
}

#[cfg(feature = "telemetry")]
async fn handle_status(wsv: Arc<WorldStateView>, network: Addr<IrohaNetwork>) -> Result<Json> {
    update_metrics(&wsv, network).await?;
    let status = Status::from(&wsv.metrics);
    Ok(reply::json(&status))
}

#[cfg(feature = "telemetry")]
async fn update_metrics(wsv: &WorldStateView, network: Addr<IrohaNetwork>) -> Result<()> {
    let peers = network
        .send(iroha_p2p::network::GetConnectedPeers)
        .await
        .map_err(Error::Status)?
        .peers
        .len() as u64;
    #[allow(clippy::cast_possible_truncation)]
    if let Some(timestamp) = wsv.genesis_timestamp() {
        // this will overflow in 584942417years.
        wsv.metrics
            .uptime_since_genesis_ms
            .set((current_time().as_millis() - timestamp) as u64)
    };
    let domains = wsv.domains();
    wsv.metrics.domains.set(domains.len() as u64);
    wsv.metrics.connected_peers.set(peers);
    for domain in domains {
        wsv.metrics
            .accounts
            .get_metric_with_label_values(&[domain.id().name.as_ref()])
            .wrap_err("Failed to compose domains")
            .map_err(Error::Prometheus)?
            .set(domain.accounts().len() as u64);
    }
    Ok(())
}

impl Torii {
    /// Construct `Torii` from `ToriiConfiguration`.
    pub fn from_configuration(
        iroha_cfg: Configuration,
        wsv: Arc<WorldStateView>,
        queue: Arc<Queue>,
        query_judge: QueryJudgeArc,
        events: EventsSender,
        network: Addr<IrohaNetwork>,
        notify_shutdown: Arc<Notify>,
    ) -> Self {
        Self {
            iroha_cfg,
            wsv,
            events,
            query_judge,
            queue,
            network,
            notify_shutdown,
        }
    }

    #[cfg(feature = "telemetry")]
    /// Helper function to create router. This router can tested without starting up an HTTP server
    fn create_telemetry_router(
        &self,
    ) -> impl warp::Filter<Extract = impl warp::Reply> + Clone + Send {
        let get_router_status = endpoint2(
            handle_status,
            warp::path(uri::STATUS).and(add_state!(self.wsv, self.network)),
        );
        let get_router_metrics = endpoint2(
            handle_metrics,
            warp::path(uri::METRICS).and(add_state!(self.wsv, self.network)),
        );
        let get_api_version = warp::path(uri::API_VERSION)
            .and(add_state!(self.wsv))
            .and_then(|wsv: Arc<_>| async { Ok::<_, Infallible>(handle_version(wsv).await) });

        warp::get()
            .and(get_router_status)
            .or(get_router_metrics)
            .or(get_api_version)
            .with(warp::trace::request())
    }

    /// Helper function to create router. This router can tested without starting up an HTTP server
    pub(crate) fn create_api_router(
        &self,
    ) -> impl warp::Filter<Extract = impl warp::Reply> + Clone + Send {
        let get_router = warp::path(uri::HEALTH)
            .and_then(|| async { Ok::<_, Infallible>(handle_health().await) })
            .or(endpoint2(
                handle_pending_transactions,
                warp::path(uri::PENDING_TRANSACTIONS)
                    .and(add_state!(self.queue))
                    .and(paginate()),
            ))
            .or(endpoint2(
                handle_get_configuration,
                warp::path(uri::CONFIGURATION)
                    .and(add_state!(self.iroha_cfg))
                    .and(warp::body::json()),
            ));

        #[cfg(feature = "schema-endpoint")]
        let get_router = get_router.or(warp::path(uri::SCHEMA)
            .and_then(|| async { Ok::<_, Infallible>(handle_schema().await) }));

        let post_router = endpoint3(
            handle_instructions,
            warp::path(uri::TRANSACTION)
                .and(add_state!(self.iroha_cfg, self.queue))
                .and(warp::body::content_length_limit(
                    self.iroha_cfg.torii.max_content_len.into(),
                ))
                .and(body::versioned()),
        )
        .or(endpoint5(
            handle_queries,
            warp::path(uri::QUERY)
                .and(add_state!(self.wsv, self.query_judge))
                .and(paginate())
                .and(sorting())
                .and(body::query()),
        ))
        .or(endpoint2(
            handle_post_configuration,
            warp::path(uri::CONFIGURATION)
                .and(add_state!(self.iroha_cfg))
                .and(warp::body::json()),
        ));

        let events_ws_router = warp::path(uri::SUBSCRIPTION)
            .and(add_state!(self.events))
            .and(warp::ws())
            .map(|events, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) = subscription::handle_subscription(events, this_ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe someone");
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
            .and(add_state!(self.wsv))
            .and(warp::ws())
            .map(|wsv: Arc<_>, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) = handle_blocks_stream(&wsv, this_ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe to blocks stream");
                    }
                })
            });

        let ws_router = events_ws_router.or(blocks_ws_router);

        ws_router
            .or(warp::post().and(post_router))
            .or(warp::get().and(get_router))
            .with(warp::trace::request())
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
                iroha_logger::error!(%telemetry_url, %error, "Telemetry address configuration parse error");
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
    pub async fn start(self) -> eyre::Result<()> {
        let mut handles = vec![];

        let torii = Arc::new(self);
        #[cfg(feature = "telemetry")]
        handles.extend(Arc::clone(&torii).start_telemetry()?);
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
