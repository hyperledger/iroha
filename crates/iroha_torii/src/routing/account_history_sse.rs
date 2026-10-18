//! `GET /v1/accounts/{account_id}/history/sse`: live account-history movements.
//!
//! Every height published after the stream is admitted is projected by the same
//! row producer that serves `/v1/accounts/{account_id}/history`, under the
//! caller's current dataspace visibility, so a streamed row is exactly the row
//! a later history page returns for that position. Rows are emitted oldest
//! first as `event: movement` frames. The stream is live-only: a client opens
//! it and, once it is open, reads the first history page and deduplicates by
//! row `id`; together the two leave no gap. On a global root every route reads
//! the same World under the caller's visibility, so the admitting node answers
//! the stream itself.
use super::{
    collection_sources::{CollectionTarget, account_history_rows_between, collection_limits},
    *,
};
use iroha_torii_shared::list_query::{FilterExpr, ListQuery};

/// `stream_error` payload codes this stream may end with, besides the shared
/// authorization and lag codes.
const STREAM_HISTORY_UNAVAILABLE: &str = "stream_history_unavailable";

/// A validated account-history stream subscription.
#[derive(Debug, Clone)]
pub struct AccountHistorySseRequest {
    account: AccountId,
    filter: Option<FilterExpr>,
    allowed_definition: Option<AssetDefinitionId>,
}

impl AccountHistorySseRequest {
    /// Validate one subscription: the path account, and a query string that may
    /// carry only `filter` (the account-history collection grammar). Account
    /// literals inside the filter are canonicalised exactly as for history
    /// pages, and the filter is admitted by the same collection plan.
    ///
    /// # Errors
    /// Rejects an unknown account literal, any page, order, projection,
    /// aggregate or total control, and a filter the history collection rejects.
    pub fn new(
        state: &CoreState,
        account_literal: &str,
        mut query: ListQuery,
        allowed_definition: Option<AssetDefinitionId>,
        telemetry: &MaybeTelemetry,
    ) -> Result<Self> {
        let (account, canonical) = parse_account_path_segment_with_state(
            state,
            account_literal,
            telemetry,
            ENDPOINT_ACCOUNTS_HISTORY_SSE,
        )?;
        reject_non_filter_controls(&query)?;
        let target = CollectionTarget::AccountHistory(canonical);
        super::collection_sources::canonicalize_collection_query(
            state, &target, &mut query, telemetry,
        )?;
        crate::collections::prepare(target.spec(), target.scope(), &query, &collection_limits())?;
        Ok(Self {
            account,
            filter: query.filter,
            allowed_definition,
        })
    }
}

/// Streams accept only the row filter: positions come from applied blocks and
/// every row is delivered once, so page, order and projection controls have no
/// meaning here.
fn reject_non_filter_controls(query: &ListQuery) -> Result<()> {
    let rejected = if query.limit.is_some() {
        Some("limit")
    } else if query.cursor.is_some() {
        Some("cursor")
    } else if !query.sort.is_empty() {
        Some("sort")
    } else if query.select.is_some() {
        Some("select")
    } else if query.aggregate.is_some() {
        Some("aggregate")
    } else if query.include_total {
        Some("include_total")
    } else {
        None
    };
    match rejected {
        Some(parameter) => Err(crate::collections::CollectionError::new(
            "invalid_query",
            parameter,
            format!("account-history streams accept only `filter`; remove `{parameter}`"),
        )
        .into()),
        None => Ok(()),
    }
}

struct AccountHistorySseState<F> {
    source: Arc<CoreState>,
    authorization: crate::stream_read_authorization::ToriiStreamReadAuthorization,
    request: Arc<AccountHistorySseRequest>,
    acquire: Arc<F>,
    pending: VecDeque<norito::json::Map>,
    next_height: Option<u64>,
    maximum_backlog: u64,
    authorization_interval: tokio::time::Interval,
    terminal: bool,
}

/// GET /v1/accounts/{account_id}/history/sse – live account-history movements.
///
/// The stream follows the canonical successors of the committed State visible at
/// admission, waking on State publication like the Explorer streams. Every
/// published height is projected once with the history row producer, under the
/// reader's current visibility and a fresh query-memory owner, and matching rows
/// are sent oldest first as `event: movement` frames. Authorization is rechecked
/// before every frame, from a decision refreshed whenever a block commits and
/// at least once per authorization interval; a backlog beyond the history
/// serving limit, a revoked authorization or an unreadable height ends the
/// stream with a terminal `stream_error`.
pub fn handle_v1_account_history_sse(
    source: Arc<CoreState>,
    visibility: ToriiDataspaceReadContext,
    request: AccountHistorySseRequest,
    app: crate::SharedAppState,
) -> Sse<impl futures::Stream<Item = Result<SseEvent, Infallible>>> {
    account_history_stream(
        source,
        visibility,
        request,
        app_query_limits().max_fetch_size,
        move || {
            let reservation = crate::try_acquire_new_query_fanout_memory(&app)
                .map_err(|_| crate::native_projection_response::capacity())?;
            crate::history_producer::HistoryProducerOwner::from_reservation(&reservation)
        },
    )
}

fn account_history_stream<F>(
    source: Arc<CoreState>,
    visibility: ToriiDataspaceReadContext,
    request: AccountHistorySseRequest,
    maximum_backlog: u64,
    acquire: F,
) -> Sse<impl futures::Stream<Item = Result<SseEvent, Infallible>>>
where
    F: Fn() -> Result<crate::history_producer::HistoryProducerOwner> + Send + Sync + 'static,
{
    // Rows at or below the height published at admission belong to history
    // pages; the stream owns every later height.
    let next_height = u64::try_from(source.committed_height())
        .ok()
        .and_then(|admitted| admitted.checked_add(1));
    let mut authorization_interval = tokio::time::interval(STREAM_AUTHORIZATION_CHECK_INTERVAL);
    authorization_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let stream = stream::unfold(
        AccountHistorySseState {
            source,
            authorization: crate::stream_read_authorization::ToriiStreamReadAuthorization::new(
                visibility,
            ),
            request: Arc::new(request),
            acquire: Arc::new(acquire),
            pending: VecDeque::new(),
            next_height,
            maximum_backlog: maximum_backlog.max(1),
            authorization_interval,
            terminal: false,
        },
        |mut state| async move {
            use crate::stream_read_authorization::StreamAuthorization as _;
            if state.terminal {
                return None;
            }
            loop {
                if !state.authorization.authorization_is_current() {
                    state.pending.clear();
                    state.terminal = true;
                    return Some((Ok(stream_authorization_revoked_event()), state));
                }
                if let Some(row) = state.pending.pop_front() {
                    let event = match norito::json::to_json(&norito::json::Value::Object(row)) {
                        Ok(json) => SseEvent::default().event("movement").data(json),
                        Err(error) => {
                            iroha_logger::error!(%error, "failed to encode account-history SSE row");
                            state.pending.clear();
                            state.terminal = true;
                            stream_error_event(
                                "stream_encode_error",
                                "The server could not encode an account-history movement.",
                                None,
                            )
                        }
                    };
                    return Some((Ok(event), state));
                }
                let Some(first) = state.next_height else {
                    state.terminal = true;
                    return Some((Ok(history_unavailable_event()), state));
                };
                let source = Arc::clone(&state.source);
                let committed = source.wait_for_committed_height(first);
                tokio::pin!(committed);
                tokio::select! {
                    () = &mut committed => {
                        let last = u64::try_from(source.committed_height()).unwrap_or(u64::MAX);
                        if last.saturating_sub(first) >= state.maximum_backlog {
                            state.terminal = true;
                            return Some((
                                Ok(stream_error_event(
                                    "stream_lagged",
                                    "The account-history stream exceeded its bounded canonical backlog and cannot replay it.",
                                    None,
                                )),
                                state,
                            ));
                        }
                        let owner = match (state.acquire)() {
                            Ok(owner) => owner,
                            Err(_) => {
                                state.terminal = true;
                                return Some((
                                    Ok(stream_error_event(
                                        "stream_history_capacity",
                                        "Account history is temporarily beyond local capacity; reconnect to retry.",
                                        None,
                                    )),
                                    state,
                                ));
                            }
                        };
                        let current = state.authorization.visibility().clone();
                        let request = Arc::clone(&state.request);
                        let worker_source = Arc::clone(&source);
                        let worker = crate::panic_recovery::spawn_blocking_recoverable(move || {
                            owner.scope(|| project_heights(&worker_source, &current, &request, first, last))
                        });
                        match crate::panic_recovery::join_recoverable(worker).await {
                            Ok(Ok(rows)) => {
                                state.pending.extend(rows);
                                state.next_height = last.checked_add(1);
                            }
                            Ok(Err(error)) => {
                                iroha_logger::warn!(%error, first, last, "account-history stream read failed");
                                state.terminal = true;
                                return Some((Ok(history_unavailable_event()), state));
                            }
                            Err(_) => {
                                state.terminal = true;
                                return Some((Ok(history_unavailable_event()), state));
                            }
                        }
                    }
                    _ = state.authorization_interval.tick() => {
                        if !state.authorization.revalidate() {
                            state.pending.clear();
                            state.terminal = true;
                            return Some((Ok(stream_authorization_revoked_event()), state));
                        }
                    }
                }
            }
        },
    );
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(SSE_HEARTBEAT_INTERVAL)
            .text("heartbeat"),
    )
}

fn history_unavailable_event() -> SseEvent {
    stream_error_event(
        STREAM_HISTORY_UNAVAILABLE,
        "Canonical account history is unavailable or exceeds its serving limits.",
        None,
    )
}

/// Rows of the subscribed account committed at `first..=last`, oldest first,
/// under the reader's visibility at projection time.
fn project_heights(
    state: &Arc<CoreState>,
    visibility: &DataspaceReadVisibility,
    request: &AccountHistorySseRequest,
    first: u64,
    last: u64,
) -> Result<Vec<norito::json::Map>> {
    if !visibility.allows_account(&state.world_view(), &request.account) {
        return Ok(Vec::new());
    }
    account_history_rows_between(
        state,
        &request.account,
        request.filter.as_ref(),
        request.allowed_definition.as_ref(),
        visibility,
        first..=last,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use iroha_core::{
        smartcontracts::Execute as _,
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        tx::AcceptedTransaction,
    };
    use iroha_crypto::Algorithm;
    use iroha_data_model::prelude as dm;
    use iroha_torii_shared::list_query::field;

    struct Fixture {
        chain: CertifiedTestChain,
        state: Arc<CoreState>,
        keys: iroha_crypto::KeyPair,
        alice: dm::AccountId,
    }

    fn fixture(seed: u8) -> Fixture {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 1))
            .expect("fixture genesis");
        let state = Arc::clone(chain.state());
        let keys = checked_routing_fixture_keypair(seed, Algorithm::Ed25519, "history stream key");
        let alice = dm::AccountId::new(keys.public_key().clone());
        {
            let latest = state.view().latest_block_hash();
            let mut block = state.block(iroha_data_model::block::BlockHeader::new(
                core::num::NonZeroU64::new(chain.height() + 1).unwrap(),
                latest,
                None,
                1_000,
                0,
            ));
            let mut tx = block.transaction();
            dm::Register::account(dm::Account::new(alice.account().clone()))
                .execute(alice.account(), &mut tx)
                .ok();
            tx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("seed fixture account");
        }
        Fixture {
            chain,
            state,
            keys,
            alice,
        }
    }

    impl Fixture {
        /// Commit one block with two account movements and return its height.
        fn commit_movements(&mut self, millis: u64) -> u64 {
            let mut builder = dm::TransactionBuilder::new(
                *self.state.network_id_ref(),
                self.alice.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            );
            builder.set_creation_time(core::time::Duration::from_millis(millis));
            let signed = builder
                .with_instructions::<dm::InstructionBox>([
                    dm::SetKeyValue::account(
                        self.alice.clone(),
                        format!("first{millis}").parse().unwrap(),
                        "one",
                    )
                    .into(),
                    dm::SetKeyValue::account(
                        self.alice.clone(),
                        format!("second{millis}").parse().unwrap(),
                        "two",
                    )
                    .into(),
                ])
                .sign(self.keys.private_key());
            crate::test_utils::commit_native_accepted_inputs(
                &mut self.chain,
                vec![AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(
                    signed,
                ))],
            );
            self.chain.height()
        }

        fn request(&self, query: ListQuery) -> Result<AccountHistorySseRequest> {
            AccountHistorySseRequest::new(
                self.state.as_ref(),
                &self.alice.to_string(),
                query,
                None,
                &MaybeTelemetry::for_tests(),
            )
        }

        fn stream(
            &self,
            query: ListQuery,
            visibility: ToriiDataspaceReadContext,
            maximum_backlog: u64,
        ) -> axum::body::Body {
            account_history_stream(
                Arc::clone(&self.state),
                visibility,
                self.request(query).expect("valid subscription"),
                maximum_backlog,
                || Ok(crate::history_producer::HistoryProducerOwner::for_test()),
            )
            .into_response()
            .into_body()
        }
    }

    /// Read SSE frames until `count` named events arrive; heartbeats are skipped.
    async fn read_events(body: &mut axum::body::Body, count: usize) -> Vec<(String, String)> {
        let mut buffered = String::new();
        let mut out = Vec::new();
        while out.len() < count {
            let frame = tokio::time::timeout(Duration::from_secs(10), body.frame())
                .await
                .expect("stream frame before timeout")
                .expect("stream still open")
                .expect("frame");
            let Ok(data) = frame.into_data() else {
                continue;
            };
            buffered.push_str(std::str::from_utf8(&data).expect("utf-8 SSE"));
            while let Some(end) = buffered.find("\n\n") {
                let block: String = buffered.drain(..end + 2).collect();
                let mut name = None;
                let mut payload = None;
                for line in block.lines() {
                    if let Some(value) = line.strip_prefix("event: ") {
                        name = Some(value.to_owned());
                    } else if let Some(value) = line.strip_prefix("data: ") {
                        payload = Some(value.to_owned());
                    }
                }
                if let (Some(name), Some(payload)) = (name, payload) {
                    out.push((name, payload));
                }
            }
        }
        out
    }

    /// Collect event names for `window`; used to prove that nothing is emitted.
    async fn read_for(body: &mut axum::body::Body, window: Duration) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + window;
        let mut names = Vec::new();
        while let Ok(Some(Ok(frame))) = tokio::time::timeout_at(deadline, body.frame()).await {
            let Ok(data) = frame.into_data() else {
                continue;
            };
            for line in std::str::from_utf8(&data).expect("utf-8 SSE").lines() {
                if let Some(name) = line.strip_prefix("event: ") {
                    names.push(name.to_owned());
                }
            }
        }
        names
    }

    fn rows(events: &[(String, String)]) -> Vec<norito::json::Value> {
        assert!(
            events.iter().all(|(name, _)| name == "movement"),
            "{events:?}"
        );
        events
            .iter()
            .map(|(_, data)| norito::json::from_str(data).expect("JSON row"))
            .collect()
    }

    fn coordinate(row: &norito::json::Value) -> (u64, u64, u64) {
        (
            row["block_height"].as_u64().unwrap(),
            row["block_index"].as_u64().unwrap(),
            row["movement_index"].as_u64().unwrap(),
        )
    }

    #[tokio::test]
    async fn heights_published_after_admission_stream_history_rows_oldest_first() {
        let mut fixture = fixture(0xD1);
        let before = fixture.commit_movements(1_500);
        let mut body = fixture.stream(
            ListQuery::new(),
            ToriiDataspaceReadContext::all_for_tests(),
            64,
        );
        let first = fixture.commit_movements(2_000);
        let second = fixture.commit_movements(3_000);
        let streamed = rows(&read_events(&mut body, 4).await);
        let coordinates: Vec<_> = streamed.iter().map(coordinate).collect();
        assert!(
            coordinates.windows(2).all(|pair| pair[0] < pair[1]),
            "{coordinates:?}"
        );
        assert_eq!(
            coordinates.iter().map(|c| c.0).collect::<Vec<_>>(),
            vec![first, first, second, second],
            "rows of height {before}, published before admission, belong to history pages"
        );
        // Every streamed row is exactly the row a history page returns.
        let page = super::super::collection_sources::execute_collection_local(
            None,
            &fixture.state,
            &CollectionTarget::AccountHistory(fixture.alice.to_string()),
            ListQuery::new().filter(field("block_height").gte(first)),
            &MaybeTelemetry::for_tests(),
            &DataspaceReadVisibility::all_for_tests(),
        )
        .await
        .expect("history page");
        let mut expected: Vec<norito::json::Value> = page
            .items
            .into_iter()
            .map(norito::json::Value::Object)
            .collect();
        expected.reverse();
        assert_eq!(streamed, expected);
    }

    #[tokio::test]
    async fn filters_narrow_the_stream_like_history_pages() {
        let mut fixture = fixture(0xD2);
        let mut body = fixture.stream(
            ListQuery::new().filter(field("movement_index").eq(1_u64)),
            ToriiDataspaceReadContext::all_for_tests(),
            64,
        );
        let first = fixture.commit_movements(2_000);
        let second = fixture.commit_movements(3_000);
        let streamed = rows(&read_events(&mut body, 2).await);
        assert_eq!(
            streamed.iter().map(coordinate).collect::<Vec<_>>(),
            vec![(first, 0, 1), (second, 0, 1)]
        );
    }

    #[tokio::test]
    async fn rows_the_reader_cannot_see_are_never_streamed() {
        let mut fixture = fixture(0xD5);
        // The same scope that hides these rows from history pages.
        let hidden = ToriiDataspaceReadContext {
            app: crate::mk_app_state_for_tests(),
            caller: None,
            admitted_visibility: DataspaceReadVisibility::default(),
            fixed_visibility: Some(DataspaceReadVisibility::default()),
        };
        let mut body = fixture.stream(ListQuery::new(), hidden, 64);
        let height = fixture.commit_movements(2_000);
        let page = super::super::collection_sources::execute_collection_local(
            None,
            &fixture.state,
            &CollectionTarget::AccountHistory(fixture.alice.to_string()),
            ListQuery::new().filter(field("block_height").eq(height)),
            &MaybeTelemetry::for_tests(),
            &DataspaceReadVisibility::default(),
        )
        .await
        .expect("hidden history page");
        assert!(page.items.is_empty(), "history hides these rows too");
        let names = read_for(&mut body, Duration::from_millis(400)).await;
        assert!(!names.iter().any(|name| name == "movement"), "{names:?}");
    }

    #[tokio::test]
    async fn a_backlog_beyond_the_bound_ends_with_a_terminal_error() {
        let mut fixture = fixture(0xD3);
        let mut body = fixture.stream(
            ListQuery::new(),
            ToriiDataspaceReadContext::all_for_tests(),
            1,
        );
        fixture.commit_movements(2_000);
        fixture.commit_movements(3_000);
        let streamed = read_events(&mut body, 1).await;
        assert_eq!(streamed[0].0, "stream_error");
        assert!(
            streamed[0].1.contains("\"stream_lagged\""),
            "{}",
            streamed[0].1
        );
        let terminal = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("a terminal stream ends");
        assert!(terminal.is_none());
    }

    #[test]
    fn subscriptions_accept_only_a_valid_history_filter() {
        let fixture = fixture(0xD4);
        fixture
            .request(ListQuery::new().filter(field("direction").eq("incoming")))
            .expect("history filter");
        for (query, parameter) in [
            (ListQuery::new().limit(5), "limit"),
            (ListQuery::new().cursor("opaque".to_owned()), "cursor"),
        ] {
            let err = fixture
                .request(query)
                .expect_err("page controls are rejected");
            assert!(
                matches!(&err, Error::CollectionQuery(err) if err.code == "invalid_query" && err.control == parameter),
                "{err:?}"
            );
        }
        let err = fixture
            .request(ListQuery::new().filter(field("no_such_field").eq(1_u64)))
            .expect_err("unknown fields are rejected");
        assert!(
            matches!(&err, Error::CollectionQuery(err) if err.code != "invalid_query"),
            "{err:?}"
        );
        assert!(
            AccountHistorySseRequest::new(
                fixture.state.as_ref(),
                "not-an-account",
                ListQuery::new(),
                None,
                &MaybeTelemetry::for_tests(),
            )
            .is_err(),
            "unknown account literals are rejected"
        );
    }
}
