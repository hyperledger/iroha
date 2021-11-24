//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use std::{convert::Infallible, fmt::Debug, net::ToSocketAddrs, sync::Arc};

use eyre::Context;
use iroha_config::Configurable;
use iroha_data_model::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utils::*;
use warp::{
    http::StatusCode,
    reject::Rejection,
    reply::{self, Json, Response},
    ws::{WebSocket, Ws},
    Filter, Reply,
};

#[macro_use]
mod utils;

use crate::{
    event::{Consumer, EventsSender},
    prelude::*,
    queue::{self, Queue},
    smartcontracts::{
        isi::query::{self, VerifiedQueryRequest},
        permissions::IsQueryAllowedBoxed,
    },
    wsv::WorldTrait,
    Configuration,
};

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii<W: WorldTrait> {
    iroha_cfg: Configuration,
    wsv: Arc<WorldStateView<W>>,
    events: EventsSender,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
    queue: Arc<Queue>,
}

/// Torii errors.
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to execute or validate query
    #[error("Failed to execute or validate query")]
    Query(#[source] query::Error),
    /// Failed to decode transaction
    #[error("Failed to decode transaction")]
    VersionedTransaction(#[source] iroha_version::error::Error),
    /// Failed to accept transaction
    #[error("Failed to accept transaction: {0}")]
    AcceptTransaction(eyre::Error),
    /// Failed to get pending transaction
    #[error("Failed to get pending transactions: {0}")]
    RequestPendingTransactions(eyre::Error),
    /// Failed to decode pending transactions from leader
    #[error("Failed to decode pending transactions from leader")]
    DecodeRequestPendingTransactions(#[source] iroha_version::error::Error),
    /// Failed to encode pending transactions
    #[error("Failed to encode pending transactions")]
    EncodePendingTransactions(#[source] iroha_version::error::Error),
    /// The block sync message channel is full. Dropping the incoming message.
    #[error("Transaction is too big")]
    TxTooBig,
    /// Error while getting or setting configuration
    #[error("Configuration error: {0}")]
    Config(eyre::Error),
    /// Failed to push into queue.
    #[error("Failed to push into queue")]
    PushIntoQueue(#[source] Box<queue::Error>),
}

impl Reply for Error {
    fn into_response(self) -> Response {
        const fn status_code(err: &Error) -> StatusCode {
            use Error::*;

            match err {
                Query(e) => e.status_code(),
                VersionedTransaction(_)
                | AcceptTransaction(_)
                | RequestPendingTransactions(_)
                | DecodeRequestPendingTransactions(_)
                | EncodePendingTransactions(_)
                | TxTooBig => StatusCode::BAD_REQUEST,
                Config(_) => StatusCode::NOT_FOUND,
                PushIntoQueue(err) => match **err {
                    queue::Error::Full => StatusCode::INTERNAL_SERVER_ERROR,
                    queue::Error::SignatureCondition(_) => StatusCode::UNAUTHORIZED,
                    _ => StatusCode::BAD_REQUEST,
                },
            }
        }

        fn to_string(mut err: &dyn std::error::Error) -> String {
            let mut s = "Error:\n".to_owned();
            let mut idx = 0;

            loop {
                s += &format!("    {}: {}\n", idx, &err.to_string());
                idx += 1;
                match err.source() {
                    Some(e) => err = e,
                    None => return s,
                }
            }
        }

        reply::with_status(to_string(&self), status_code(&self)).into_response()
    }
}

/// Result type
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl<W: WorldTrait> Torii<W> {
    /// Construct `Torii` from `ToriiConfiguration`.
    pub fn from_configuration(
        iroha_cfg: Configuration,
        wsv: Arc<WorldStateView<W>>,
        queue: Arc<Queue>,
        query_validator: Arc<IsQueryAllowedBoxed<W>>,
        events: EventsSender,
    ) -> Self {
        Self {
            iroha_cfg,
            wsv,
            events,
            query_validator,
            queue,
        }
    }

    #[allow(clippy::expect_used)]
    fn create_state(&self) -> ToriiState<W> {
        let wsv = Arc::clone(&self.wsv);
        let queue = Arc::clone(&self.queue);
        let iroha_cfg = self.iroha_cfg.clone();
        let query_validator = Arc::clone(&self.query_validator);

        Arc::new(InnerToriiState {
            iroha_cfg,
            wsv,
            queue,
            query_validator,
        })
    }

    /// Fixing status code for custom rejection, because of argument parsing
    #[allow(clippy::unused_async)]
    async fn recover_arg_parse(err: Rejection) -> Result<impl Reply, Rejection> {
        if let Some(err) = err.find::<query::Error>() {
            return Ok(reply::with_status(err.to_string(), err.status_code()));
        }
        if let Some(err) = err.find::<iroha_version::error::Error>() {
            return Ok(reply::with_status(err.to_string(), err.status_code()));
        }
        Err(err)
    }

    /// To handle incoming requests `Torii` should be started first.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    #[iroha_futures::telemetry_future]
    pub async fn start(self) -> eyre::Result<()> {
        let state = self.create_state();

        let get_router = warp::path(uri::HEALTH)
            .and_then(|| async { Ok::<_, Infallible>(handle_health().await) })
            .or(endpoint2(
                handle_pending_transactions,
                warp::path(uri::PENDING_TRANSACTIONS)
                    .and(add_state(Arc::clone(&state)))
                    .and(paginate()),
            ))
            .or(endpoint2(
                handle_get_configuration,
                warp::path(uri::CONFIGURATION)
                    .and(add_state(Arc::clone(&state)))
                    .and(warp::body::json()),
            ));

        let post_router = endpoint2(
            handle_instructions,
            warp::path(uri::TRANSACTION)
                .and(add_state(Arc::clone(&state)))
                .and(warp::body::content_length_limit(
                    state.iroha_cfg.torii.max_sumeragi_message_size as u64,
                ))
                .and(body::versioned()),
        )
        .or(endpoint3(
            handle_queries,
            warp::path(uri::QUERY)
                .and(add_state(Arc::clone(&state)))
                .and(paginate())
                .and(body::query()),
        ));

        let ws_router = warp::path(uri::SUBSCRIPTION)
            .and(add_state(self.events))
            .and(warp::ws())
            .map(|events, ws: Ws| {
                ws.on_upgrade(|ws| async move {
                    if let Err(error) = handle_subscription(events, ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe someone");
                    }
                })
            });

        let router = warp::post()
            .and(post_router)
            .or(warp::get().and(get_router))
            .or(ws_router)
            .with(warp::trace::request())
            .recover(Torii::<W>::recover_arg_parse);

        match self.iroha_cfg.torii.api_url.to_socket_addrs() {
            Ok(mut i) => {
                #[allow(clippy::expect_used)]
                let addr = i.next().expect("Failed to get socket addr");
                warp::serve(router).run(addr).await;
                Ok(())
            }
            Err(error) => {
                iroha_logger::error!(%error, "Failed to get socket addr");
                Err(eyre::Error::new(error))
            }
        }
    }
}

struct InnerToriiState<W: WorldTrait> {
    iroha_cfg: Configuration,
    wsv: Arc<WorldStateView<W>>,
    queue: Arc<Queue>,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
}

type ToriiState<W> = Arc<InnerToriiState<W>>;

#[iroha_futures::telemetry_future]
async fn handle_instructions<W: WorldTrait>(
    state: ToriiState<W>,
    transaction: VersionedTransaction,
) -> Result<Empty> {
    let transaction: Transaction = transaction.into_inner_v1();
    let transaction = VersionedAcceptedTransaction::from_transaction(
        transaction,
        state.iroha_cfg.torii.max_instruction_number,
    )
    .map_err(Error::AcceptTransaction)?;
    #[allow(clippy::map_err_ignore)]
    let push_result = state
        .queue
        .push(transaction, &*state.wsv)
        .map_err(|(_, err)| err);
    if let Err(ref error) = push_result {
        iroha_logger::warn!(%error, "Failed to push to queue")
    }
    push_result
        .map_err(Box::new)
        .map_err(Error::PushIntoQueue)
        .map(|()| Empty)
}

#[iroha_futures::telemetry_future]
async fn handle_queries<W: WorldTrait>(
    state: ToriiState<W>,
    pagination: Pagination,
    request: VerifiedQueryRequest,
) -> Result<Scale<VersionedQueryResult>, query::Error> {
    let valid_request = request.validate(&*state.wsv, &state.query_validator)?;
    let result = valid_request
        .execute(&*state.wsv)
        .map_err(query::Error::Find)?;
    let result = QueryResult(if let Value::Vec(value) = result {
        Value::Vec(value.into_iter().paginate(pagination).collect())
    } else {
        result
    });
    Ok(Scale(result.into()))
}

#[derive(Serialize)]
#[non_exhaustive]
enum Health {
    Healthy,
}

#[iroha_futures::telemetry_future]
async fn handle_health() -> Json {
    reply::json(&Health::Healthy)
}

#[iroha_futures::telemetry_future]
async fn handle_pending_transactions<W: WorldTrait>(
    state: ToriiState<W>,
    pagination: Pagination,
) -> Result<Scale<VersionedPendingTransactions>> {
    Ok(Scale(
        state
            .queue
            .all_transactions(&*state.wsv)
            .into_iter()
            .map(VersionedAcceptedTransaction::into_inner_v1)
            .map(Transaction::from)
            .paginate(pagination)
            .collect(),
    ))
}

/// Json config for getting configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum GetConfiguration {
    /// Getting docs of specific field
    Docs {
        /// Path to field, like `a.b.c` would be `["a", "b", "c"]`
        field: Vec<String>,
    },
    /// Getting value of configuration
    Value,
}

#[iroha_futures::telemetry_future]
async fn handle_get_configuration<W: WorldTrait>(
    state: ToriiState<W>,
    get_cfg: GetConfiguration,
) -> Result<Json> {
    use GetConfiguration::*;

    match get_cfg {
        Docs { field } => {
            Configuration::get_doc_recursive(field.iter().map(AsRef::as_ref).collect::<Vec<&str>>())
                .wrap_err("Failed to get docs")
                .and_then(|doc| serde_json::to_value(doc).wrap_err("Failed to serialize docs"))
        }
        Value => {
            serde_json::to_value(state.iroha_cfg.clone()).wrap_err("Failed to serialize value")
        }
    }
    .map(|v| reply::json(&v))
    .map_err(Error::Config)
}

#[iroha_futures::telemetry_future]
async fn handle_subscription(events: EventsSender, stream: WebSocket) -> eyre::Result<()> {
    let mut events = events.subscribe();
    let mut consumer = Consumer::new(stream).await?;

    while let Ok(change) = events.recv().await {
        iroha_logger::trace!(event = ?change);

        if let Err(error) = consumer.consume(&change).await {
            iroha_logger::error!(%error, "Failed to notify client. Closed connection.");
            break;
        }
    }

    Ok(())
}

/// URI that `Torii` uses to route incoming requests.
pub mod uri {
    /// Query URI is used to handle incoming Query requests.
    pub const QUERY: &str = "query";
    /// Transaction URI is used to handle incoming ISI requests.
    pub const TRANSACTION: &str = "transaction";
    /// Block URI is used to handle incoming Block requests.
    pub const CONSENSUS: &str = "consensus";
    /// Health URI is used to handle incoming Healthcheck requests.
    pub const HEALTH: &str = "health";
    /// The URI used for block synchronization.
    pub const BLOCK_SYNC: &str = "block";
    /// The web socket uri used to subscribe to block and transactions statuses.
    pub const SUBSCRIPTION: &str = "events";
    /// Get pending transactions.
    pub const PENDING_TRANSACTIONS: &str = "pending_transactions";
    /// The URI for local config changing inspecting
    pub const CONFIGURATION: &str = "configuration";
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    /// Default socket for p2p communication
    pub const DEFAULT_TORII_P2P_ADDR: &str = "127.0.0.1:1337";
    /// Default socket for listening on external requests.
    pub const DEFAULT_TORII_API_URL: &str = "127.0.0.1:8080";
    /// Default maximum size of single transaction.
    pub const DEFAULT_TORII_MAX_TRANSACTION_SIZE: usize = 2_usize.pow(15);
    /// Default maximum instruction number
    pub const DEFAULT_TORII_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
    /// Default maxiumum size of [`Sumeragi`] message size.
    pub const DEFAULT_TORII_MAX_SUMERAGI_MESSAGE_SIZE: usize = 2_usize.pow(12) * 4000;

    /// `ToriiConfiguration` provides an ability to define parameters such as `TORII_URL`.
    #[derive(Clone, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    #[config(env_prefix = "TORII_")]
    pub struct ToriiConfiguration {
        /// Torii URL for p2p communication for consensus and block synchronization purposes.
        pub p2p_addr: String,
        /// Torii URL for client API.
        pub api_url: String,
        /// Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.
        pub max_transaction_size: usize,
        /// Maximum number of bytes in raw message. Used to prevent from DOS attacks.
        pub max_sumeragi_message_size: usize,
        /// Maximum number of instruction per transaction. Used to prevent from DOS attacks.
        pub max_instruction_number: u64,
    }

    impl Default for ToriiConfiguration {
        fn default() -> Self {
            Self {
                api_url: DEFAULT_TORII_API_URL.to_owned(),
                p2p_addr: DEFAULT_TORII_P2P_ADDR.to_owned(),
                max_transaction_size: DEFAULT_TORII_MAX_TRANSACTION_SIZE,
                max_sumeragi_message_size: DEFAULT_TORII_MAX_SUMERAGI_MESSAGE_SIZE,
                max_instruction_number: DEFAULT_TORII_MAX_INSTRUCTION_NUMBER,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::restriction)]

    use std::{convert::TryInto, time::Duration};

    use futures::future::FutureExt;
    use tokio::time;

    use super::*;
    use crate::{
        queue::Queue,
        samples::{get_config, get_trusted_peers},
        smartcontracts::permissions::DenyAll,
        wsv::World,
    };

    fn create_torii() -> (Torii<World>, KeyPair) {
        let config = get_config(get_trusted_peers(None), None);
        let (events, _) = tokio::sync::broadcast::channel(100);
        let wsv = Arc::new(WorldStateView::new(World::with(
            ('a'..'z')
                .map(|name| name.to_string())
                .map(|name| (name.clone(), Domain::new(&name))),
            vec![],
        )));
        let keys = KeyPair::generate().expect("Failed to generate keys");
        wsv.world.domains.insert(
            "wonderland".to_owned(),
            Domain::with_accounts(
                "wonderland",
                std::iter::once(Account::with_signatory(
                    AccountId::new("alice", "wonderland"),
                    keys.public_key.clone(),
                )),
            ),
        );
        let queue = Arc::new(Queue::from_configuration(&config.queue));

        (
            Torii::from_configuration(config, wsv, queue, Arc::new(AllowAll.into()), events),
            keys,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_start_torii() {
        let (torii, _) = create_torii();

        let result = time::timeout(Duration::from_millis(50), torii.start()).await;

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn torii_pagination() {
        let (torii, keys) = create_torii();
        let state = torii.create_state();

        let get_domains = |start, limit| {
            let query: VerifiedQueryRequest = QueryRequest::new(
                QueryBox::FindAllDomains(Default::default()),
                AccountId::new("alice", "wonderland"),
            )
            .sign(keys.clone())
            .expect("Failed to sign query with keys")
            .try_into()
            .expect("Failed to verify");

            let pagination = Pagination { start, limit };
            handle_queries(state.clone(), pagination, query).map(|result| {
                let Scale(query_result) = result.unwrap();
                if let QueryResult(Value::Vec(domain)) = query_result.into_v1().unwrap().into() {
                    domain
                } else {
                    unreachable!()
                }
            })
        };

        assert_eq!(get_domains(None, None).await.len(), 26);
        assert_eq!(get_domains(Some(0), None).await.len(), 26);
        assert_eq!(get_domains(Some(15), Some(5)).await.len(), 5);
        assert_eq!(get_domains(None, Some(10)).await.len(), 10);
        assert_eq!(get_domains(Some(1), Some(15)).await.len(), 15);
    }

    #[derive(Default)]
    struct AssertSet {
        instructions: Vec<Instruction>,
        account: Option<AccountId>,
        keys: Option<KeyPair>,
        deny_all: bool,
    }

    impl AssertSet {
        fn new() -> Self {
            Self::default()
        }
        fn given(mut self, instruction: Instruction) -> Self {
            self.instructions.push(instruction);
            self
        }
        fn account(mut self, account: AccountId) -> Self {
            self.account = Some(account);
            self
        }
        fn keys(mut self, keys: KeyPair) -> Self {
            self.keys = Some(keys);
            self
        }
        fn deny_all(mut self) -> Self {
            self.deny_all = true;
            self
        }
        fn query(self, query: QueryBox) -> AssertReady {
            let Self {
                instructions,
                account,
                keys,
                deny_all,
            } = self;
            AssertReady {
                instructions,
                account,
                keys,
                deny_all,
                query,
                status: None,
                hints: Vec::new(),
            }
        }
    }

    struct AssertReady {
        instructions: Vec<Instruction>,
        account: Option<AccountId>,
        keys: Option<KeyPair>,
        deny_all: bool,
        query: QueryBox,
        status: Option<StatusCode>,
        hints: Vec<&'static str>,
    }

    impl AssertReady {
        fn status(mut self, status: StatusCode) -> Self {
            self.status = Some(status);
            self
        }
        fn hint(mut self, hint: &'static str) -> Self {
            self.hints.push(hint);
            self
        }
        async fn assert(self) {
            use iroha_version::scale::EncodeVersioned;

            use crate::smartcontracts::Execute;

            let (mut torii, keys) = create_torii();
            if self.deny_all {
                torii.query_validator = Arc::new(DenyAll.into());
            }
            let state = torii.create_state();

            let authority = AccountId::new("alice", "wonderland");
            for instruction in self.instructions {
                instruction
                    .execute(authority.clone(), &state.wsv)
                    .expect("Given instructions disorder");
            }

            let post_router = endpoint3(
                handle_queries,
                warp::path(uri::QUERY)
                    .and(add_state(Arc::clone(&state)))
                    .and(paginate())
                    .and(body::query()),
            );
            let router = warp::post()
                .and(post_router)
                .with(warp::trace::request())
                .recover(Torii::<World>::recover_arg_parse);

            let request: VersionedSignedQueryRequest =
                QueryRequest::new(self.query, self.account.unwrap_or(authority))
                    .sign(self.keys.unwrap_or(keys))
                    .expect("Failed to sign query with keys")
                    .into();

            let response = warp::test::request()
                .method("POST")
                .path("/query")
                .body(request.encode_versioned().unwrap())
                .reply(&router)
                .await;

            let response_body = match response.status() {
                StatusCode::OK => {
                    let response: VersionedQueryResult =
                        response.body().to_vec().try_into().unwrap();
                    let QueryResult(value) = response.into_v1().unwrap().into();
                    format!("{:?}", value)
                }
                _ => String::from_utf8(response.body().to_vec()).unwrap_or_default(),
            };
            dbg!(&response_body);

            if let Some(status) = self.status {
                assert_eq!(response.status(), status)
            }
            for hint in self.hints {
                dbg!(hint);
                assert!(response_body.contains(hint))
            }
        }
    }

    const DOMAIN: &str = "desert";

    fn register_domain() -> Instruction {
        Instruction::Register(RegisterBox::new(Domain::new(DOMAIN)))
    }
    fn register_account(name: &str) -> Instruction {
        Instruction::Register(RegisterBox::new(NewAccount::with_signatory(
            AccountId::new(name, DOMAIN),
            KeyPair::generate().unwrap().public_key,
        )))
    }
    fn register_asset_definition(name: &str) -> Instruction {
        Instruction::Register(RegisterBox::new(AssetDefinition::new_quantity(
            AssetDefinitionId::new(name, DOMAIN),
        )))
    }
    fn mint_asset(quantity: u32, asset: &str, account: &str) -> Instruction {
        Instruction::Mint(MintBox::new(
            Value::U32(quantity),
            AssetId::from_names(asset, DOMAIN, account, DOMAIN),
        ))
    }
    #[tokio::test]
    async fn find_asset() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            .given(register_asset_definition("rose"))
            .given(mint_asset(99, "rose", "alice"))
            .query(QueryBox::FindAssetById(FindAssetById::new(
                AssetId::from_names("rose", DOMAIN, "alice", DOMAIN),
            )))
            .status(StatusCode::OK)
            .hint("Quantity")
            .hint("99")
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_asset_with_no_mint() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            .given(register_asset_definition("rose"))
            // .given(mint_asset(99, "rose", "alice"))
            .query(QueryBox::FindAssetById(FindAssetById::new(
                AssetId::from_names("rose", DOMAIN, "alice", DOMAIN),
            )))
            .status(StatusCode::NOT_FOUND)
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_asset_with_no_asset_definition() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            // .given(register_asset_definition("rose"))
            // .given(mint_asset(99, "rose", "alice"))
            .query(QueryBox::FindAssetById(FindAssetById::new(
                AssetId::from_names("rose", DOMAIN, "alice", DOMAIN),
            )))
            .status(StatusCode::NOT_FOUND)
            .hint("definition")
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_asset_with_no_account() {
        AssertSet::new()
            .given(register_domain())
            // .given(register_account("alice"))
            .given(register_asset_definition("rose"))
            // .given(mint_asset(99, "rose", "alice"))
            .query(QueryBox::FindAssetById(FindAssetById::new(
                AssetId::from_names("rose", DOMAIN, "alice", DOMAIN),
            )))
            .status(StatusCode::NOT_FOUND)
            .hint("account")
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_asset_with_no_domain() {
        AssertSet::new()
            // .given(register_domain())
            // .given(register_account("alice"))
            // .given(register_asset_definition("rose"))
            // .given(mint_asset(99, "rose", "alice"))
            .query(QueryBox::FindAssetById(FindAssetById::new(
                AssetId::from_names("rose", DOMAIN, "alice", DOMAIN),
            )))
            .status(StatusCode::NOT_FOUND)
            .hint("domain")
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_asset_definition() {
        AssertSet::new()
            .given(register_domain())
            .given(register_asset_definition("rose"))
            .query(QueryBox::FindAllAssetsDefinitions(Default::default()))
            .status(StatusCode::OK)
            .hint("rose")
            .hint(DOMAIN)
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_account() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            .query(QueryBox::FindAccountById(FindAccountById::new(
                AccountId::new("alice", DOMAIN),
            )))
            .status(StatusCode::OK)
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_account_with_no_account() {
        AssertSet::new()
            .given(register_domain())
            // .given(register_account("alice"))
            .query(QueryBox::FindAccountById(FindAccountById::new(
                AccountId::new("alice", DOMAIN),
            )))
            .status(StatusCode::NOT_FOUND)
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_account_with_no_domain() {
        AssertSet::new()
            // .given(register_domain())
            // .given(register_account("alice"))
            .query(QueryBox::FindAccountById(FindAccountById::new(
                AccountId::new("alice", DOMAIN),
            )))
            .status(StatusCode::NOT_FOUND)
            .hint("domain")
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_domain() {
        AssertSet::new()
            .given(register_domain())
            .query(QueryBox::FindDomainByName(FindDomainByName::new(
                DOMAIN.to_string(),
            )))
            .status(StatusCode::OK)
            .assert()
            .await
    }
    #[tokio::test]
    async fn find_domain_with_no_domain() {
        AssertSet::new()
            // .given(register_domain())
            .query(QueryBox::FindDomainByName(FindDomainByName::new(
                DOMAIN.to_string(),
            )))
            .status(StatusCode::NOT_FOUND)
            .assert()
            .await
    }
    fn query() -> QueryBox {
        QueryBox::FindAccountById(FindAccountById::new(AccountId::new("alice", DOMAIN)))
    }
    #[tokio::test]
    async fn query_with_wrong_signatory() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            .account(AccountId::new("alice", DOMAIN))
            // .deny_all()
            .query(query())
            .status(StatusCode::UNAUTHORIZED)
            .assert()
            .await
    }
    #[tokio::test]
    async fn query_with_wrong_signature() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            .keys(KeyPair::generate().unwrap())
            // .deny_all()
            .query(query())
            .status(StatusCode::UNAUTHORIZED)
            .assert()
            .await
    }
    #[tokio::test]
    async fn query_with_wrong_signature_and_no_permission() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            .keys(KeyPair::generate().unwrap())
            .deny_all()
            .query(query())
            .status(StatusCode::UNAUTHORIZED)
            .assert()
            .await
    }
    #[tokio::test]
    async fn query_with_no_permission() {
        AssertSet::new()
            .given(register_domain())
            .given(register_account("alice"))
            // .keys(KeyPair::generate().unwrap())
            .deny_all()
            .query(query())
            .status(StatusCode::NOT_FOUND)
            .assert()
            .await
    }
    #[tokio::test]
    async fn query_with_no_permission_and_no_find() {
        AssertSet::new()
            .given(register_domain())
            // .given(register_account("alice"))
            // .keys(KeyPair::generate().unwrap())
            .deny_all()
            .query(query())
            .status(StatusCode::NOT_FOUND)
            .assert()
            .await
    }
    #[tokio::test]
    async fn query_with_no_find() {
        AssertSet::new()
            .given(register_domain())
            // .given(register_account("alice"))
            // .keys(KeyPair::generate().unwrap())
            // .deny_all()
            .query(query())
            .status(StatusCode::NOT_FOUND)
            .assert()
            .await
    }
}
