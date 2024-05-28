//! Contains the end-point querying logic.  This is where you need to
//! add any custom end-point related logic.
use std::{
    collections::HashMap,
    fmt::Debug,
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64},
    thread,
    time::Duration,
};

use derive_more::{DebugCustom, Display};
use eyre::{eyre, Result, WrapErr};
use futures_util::StreamExt;
use http_default::{AsyncWebSocketStream, WebSocketStream};
pub use iroha_config::client_api::ConfigDTO;
use iroha_data_model::{
    events::pipeline::{
        BlockEventFilter, BlockStatus, PipelineEventBox, PipelineEventFilterBox,
        TransactionEventFilter, TransactionStatus,
    },
    query::QueryOutputBox,
};
use iroha_logger::prelude::*;
use iroha_telemetry::metrics::Status;
use iroha_torii_const::uri as torii_uri;
use iroha_version::prelude::*;
use parity_scale_codec::DecodeAll;
use rand::Rng;
use url::Url;

use self::{blocks_api::AsyncBlockStream, events_api::AsyncEventStream};
use crate::{
    config::Config,
    crypto::{HashOf, KeyPair},
    data_model::{
        block::SignedBlock,
        isi::Instruction,
        prelude::*,
        query::{predicate::PredicateBox, Pagination, Query, Sorting},
        BatchedResponse, ChainId, ValidationFail,
    },
    http::{Method as HttpMethod, RequestBuilder, Response, StatusCode},
    http_default::{self, DefaultRequestBuilder, WebSocketError, WebSocketMessage},
    query_builder::QueryRequestBuilder,
};

const APPLICATION_JSON: &str = "application/json";

/// Phantom struct that handles responses of Query API.
/// Depending on input query struct, transforms a response into appropriate output.
#[derive(Debug, Clone)]
pub struct QueryResponseHandler<R> {
    query_request: QueryRequest,
    _output_type: PhantomData<R>,
}

impl<R> QueryResponseHandler<R> {
    fn new(query_request: QueryRequest) -> Self {
        Self {
            query_request,
            _output_type: PhantomData,
        }
    }
}

/// `Result` with [`ClientQueryError`] as an error
pub type QueryResult<T> = core::result::Result<T, ClientQueryError>;

/// Trait for signing transactions
pub trait Sign {
    /// Sign transaction with provided key pair.
    fn sign(self, key_pair: &crate::crypto::KeyPair) -> SignedTransaction;
}

impl Sign for TransactionBuilder {
    fn sign(self, key_pair: &crate::crypto::KeyPair) -> SignedTransaction {
        self.sign(key_pair)
    }
}

impl Sign for SignedTransaction {
    fn sign(self, key_pair: &crate::crypto::KeyPair) -> SignedTransaction {
        self.sign(key_pair)
    }
}

impl<R: QueryOutput> QueryResponseHandler<R>
where
    <R as TryFrom<QueryOutputBox>>::Error: Into<eyre::Error>,
{
    fn handle(&mut self, resp: &Response<Vec<u8>>) -> QueryResult<R> {
        // Separate-compilation friendly response handling
        fn _handle_query_response_base(
            resp: &Response<Vec<u8>>,
        ) -> QueryResult<BatchedResponse<QueryOutputBox>> {
            match resp.status() {
                StatusCode::OK => {
                    let res = BatchedResponse::decode_all_versioned(resp.body());
                    res.wrap_err(
                        "Failed to decode response from Iroha. \
                         You are likely using a version of the client library \
                         that is incompatible with the version of the peer software",
                    )
                        .map_err(Into::into)
                }
                StatusCode::BAD_REQUEST
                | StatusCode::UNAUTHORIZED
                | StatusCode::FORBIDDEN
                | StatusCode::NOT_FOUND
                | StatusCode::UNPROCESSABLE_ENTITY => Err(ValidationFail::decode_all(
                    &mut resp.body().as_ref(),
                )
                    .map_or_else(
                        |_| {
                            ClientQueryError::Other(
                                ResponseReport::with_msg("Query failed", resp)
                                    .map_or_else(
                                        |_| eyre!(
                                        "Failed to decode response from Iroha. \
                                        Response is neither a `ValidationFail` encoded value nor a valid utf-8 string error response. \
                                        You are likely using a version of the client library that is incompatible with the version of the peer software",
                                    ),
                                        Into::into
                                    ),
                            )
                        },
                        ClientQueryError::Validation,
                    )),
                _ => Err(ResponseReport::with_msg("Unexpected query response", resp).unwrap_or_else(core::convert::identity).into()),
            }
        }

        let (batch, cursor) = _handle_query_response_base(resp)?.into();

        let output = R::try_from(batch)
            .map_err(Into::into)
            .wrap_err("Unexpected type")?;

        self.query_request.request = crate::data_model::query::QueryRequest::Cursor(cursor);
        Ok(output)
    }
}

/// Different errors as a result of query response handling
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ClientQueryError {
    /// Query validation error
    Validation(#[from] ValidationFail),
    /// Other error
    Other(#[from] eyre::Error),
}

impl From<ResponseReport> for ClientQueryError {
    #[inline]
    fn from(ResponseReport(err): ResponseReport) -> Self {
        Self::Other(err)
    }
}

/// Phantom struct that handles Transaction API HTTP response
#[derive(Clone, Copy)]
struct TransactionResponseHandler;

impl TransactionResponseHandler {
    fn handle(resp: &Response<Vec<u8>>) -> Result<()> {
        if resp.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(
                ResponseReport::with_msg("Unexpected transaction response", resp)
                    .unwrap_or_else(core::convert::identity)
                    .into(),
            )
        }
    }
}

/// Phantom struct that handles status check HTTP response
#[derive(Clone, Copy)]
pub struct StatusResponseHandler;

impl StatusResponseHandler {
    pub(crate) fn handle(resp: &Response<Vec<u8>>) -> Result<Status> {
        let slice = Self::handle_raw(resp)?;
        serde_json::from_slice(slice).wrap_err("Failed to decode body")
    }

    fn handle_raw(resp: &Response<Vec<u8>>) -> Result<&Vec<u8>> {
        if resp.status() != StatusCode::OK {
            return Err(ResponseReport::with_msg("Unexpected status response", resp)
                .unwrap_or_else(core::convert::identity)
                .into());
        }
        Ok(resp.body())
    }
}

/// Private structure to incapsulate error reporting for HTTP response.
struct ResponseReport(eyre::Report);

impl ResponseReport {
    /// Constructs report with provided message
    ///
    /// # Errors
    /// If response body isn't a valid utf-8 string
    fn with_msg<S: AsRef<str>>(msg: S, response: &Response<Vec<u8>>) -> Result<Self, Self> {
        let status = response.status();
        let body = std::str::from_utf8(response.body());
        let msg = msg.as_ref();

        body.map_err(|_| {
            Self(eyre!(
                "{msg}; status: {status}; body isn't a valid utf-8 string"
            ))
        })
        .map(|body| Self(eyre!("{msg}; status: {status}; response body: {body}")))
    }
}

impl From<ResponseReport> for eyre::Report {
    #[inline]
    fn from(report: ResponseReport) -> Self {
        report.0
    }
}

/// Output of a query
pub trait QueryOutput: Into<QueryOutputBox> + TryFrom<QueryOutputBox> {
    /// Type of the query output
    type Target: Clone;

    /// Construct query output from query response
    fn new(output: Self, query_request: QueryResponseHandler<Self>) -> Self::Target;
}

/// Iterable query output
#[derive(Debug, Clone)]
pub struct ResultSet<T> {
    query_handler: QueryResponseHandler<Vec<T>>,

    iter: Vec<T>,
    client_cursor: usize,
}

impl<T> ResultSet<T> {
    /// Get the length of the batch returned by Iroha.
    ///
    /// This is controlled by `fetch_size` parameter of the query.
    pub fn batch_len(&self) -> usize {
        self.iter.len()
    }
}

impl<T: Clone> Iterator for ResultSet<T>
where
    Vec<T>: QueryOutput,
    <Vec<T> as TryFrom<QueryOutputBox>>::Error: Into<eyre::Error>,
{
    type Item = QueryResult<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.client_cursor >= self.iter.len() {
            let crate::data_model::query::QueryRequest::Cursor(cursor) =
                &self.query_handler.query_request.request
            else {
                return None;
            };
            if cursor.cursor().is_none() {
                return None;
            }

            let request = match self.query_handler.query_request.clone().assemble().build() {
                Err(err) => return Some(Err(ClientQueryError::Other(err))),
                Ok(ok) => ok,
            };

            let response = match request.send() {
                Err(err) => return Some(Err(ClientQueryError::Other(err))),
                Ok(ok) => ok,
            };
            let output = match self.query_handler.handle(&response) {
                Err(err) => return Some(Err(err)),
                Ok(ok) => ok,
            };
            self.iter = output;
            self.client_cursor = 0;
        }

        let item = Ok(self.iter.get(self.client_cursor).cloned());
        self.client_cursor += 1;
        item.transpose()
    }
}

impl<T: Debug + Clone> QueryOutput for Vec<T>
where
    Self: Into<QueryOutputBox> + TryFrom<QueryOutputBox>,
{
    type Target = ResultSet<T>;

    fn new(output: Self, query_handler: QueryResponseHandler<Self>) -> Self::Target {
        ResultSet {
            query_handler,
            iter: output,
            client_cursor: 0,
        }
    }
}

macro_rules! impl_query_output {
    ( $($ident:ty),+ $(,)? ) => { $(
        impl QueryOutput for $ident {
            type Target = Self;

            fn new(output: Self, _query_handler: QueryResponseHandler<Self>) -> Self::Target {
                output
            }
        } )+
    };
}
impl_query_output! {
    crate::data_model::role::Role,
    crate::data_model::asset::Asset,
    crate::data_model::asset::AssetDefinition,
    crate::data_model::account::Account,
    crate::data_model::domain::Domain,
    crate::data_model::block::BlockHeader,
    crate::data_model::metadata::MetadataValueBox,
    crate::data_model::query::TransactionQueryOutput,
    crate::data_model::executor::ExecutorDataModel,
    crate::data_model::trigger::Trigger,
    crate::data_model::prelude::Numeric,
}

/// Iroha client
#[derive(Clone, DebugCustom, Display)]
#[debug(
    fmt = "Client {{ torii: {torii_url}, public_key: {} }}",
    "key_pair.public_key()"
)]
#[display(fmt = "{}@{torii_url}", "key_pair.public_key()")]
pub struct Client {
    /// Unique id of the blockchain. Used for simple replay attack protection.
    pub chain_id: ChainId,
    /// Url for accessing iroha node
    pub torii_url: Url,
    /// Accounts keypair
    pub key_pair: KeyPair,
    /// Transaction time to live in milliseconds
    pub transaction_ttl: Option<Duration>,
    /// Transaction status timeout
    pub transaction_status_timeout: Duration,
    /// Current account
    pub account_id: AccountId,
    /// Http headers which will be appended to each request
    pub headers: HashMap<String, String>,
    /// If `true` add nonce, which makes different hashes for
    /// transactions which occur repeatedly and/or simultaneously
    pub add_transaction_nonce: bool,
}

/// Query request
#[derive(Debug, Clone)]
pub struct QueryRequest {
    torii_url: Url,
    headers: HashMap<String, String>,
    request: crate::data_model::query::QueryRequest<SignedQuery>,
}

impl QueryRequest {
    #[cfg(test)]
    fn dummy() -> Self {
        let torii_url = torii_uri::DEFAULT_API_ADDR;

        Self {
            torii_url: format!("http://{torii_url}").parse().unwrap(),
            headers: HashMap::new(),
            request: crate::data_model::query::QueryRequest::Query(
                ClientQueryBuilder::new(FindAllAccounts, test_samples::ALICE_ID.clone())
                    .sign(&test_samples::ALICE_KEYPAIR),
            ),
        }
    }

    fn assemble(self) -> DefaultRequestBuilder {
        let builder = DefaultRequestBuilder::new(
            HttpMethod::POST,
            self.torii_url.join(torii_uri::QUERY).expect("Valid URI"),
        )
        .headers(self.headers);

        match self.request {
            crate::data_model::query::QueryRequest::Query(signed_query) => {
                builder.body(signed_query.encode())
            }
            crate::data_model::query::QueryRequest::Cursor(cursor) => {
                builder.params(Vec::from(cursor))
            }
        }
    }
}

/// Representation of `Iroha` client.
impl Client {
    /// Constructor for client from configuration
    #[inline]
    pub fn new(configuration: Config) -> Self {
        Self::with_headers(configuration, HashMap::new())
    }

    /// Constructor for client from configuration and headers
    ///
    /// *Authorization* header will be added if `basic_auth` is presented
    #[inline]
    pub fn with_headers(
        Config {
            chain_id,
            account_id,
            torii_api_url,
            key_pair,
            basic_auth,
            transaction_add_nonce,
            transaction_ttl,
            transaction_status_timeout,
        }: Config,
        mut headers: HashMap<String, String>,
    ) -> Self {
        if let Some(basic_auth) = basic_auth {
            let credentials = format!("{}:{}", basic_auth.web_login, basic_auth.password);
            let engine = base64::engine::general_purpose::STANDARD;
            let encoded = base64::engine::Engine::encode(&engine, credentials);
            headers.insert(String::from("Authorization"), format!("Basic {encoded}"));
        }

        Self {
            chain_id,
            torii_url: torii_api_url,
            key_pair,
            transaction_ttl: Some(transaction_ttl),
            transaction_status_timeout,
            account_id,
            headers,
            add_transaction_nonce: transaction_add_nonce,
        }
    }

    /// Builds transaction out of supplied instructions or wasm.
    ///
    /// # Errors
    /// Fails if signing transaction fails
    pub fn build_transaction(
        &self,
        instructions: impl Into<Executable>,
        metadata: UnlimitedMetadata,
    ) -> SignedTransaction {
        let tx_builder = TransactionBuilder::new(self.chain_id.clone(), self.account_id.clone());

        let mut tx_builder = match instructions.into() {
            Executable::Instructions(instructions) => tx_builder.with_instructions(instructions),
            Executable::Wasm(wasm) => tx_builder.with_wasm(wasm),
        };

        if let Some(transaction_ttl) = self.transaction_ttl {
            tx_builder.set_ttl(transaction_ttl);
        }
        if self.add_transaction_nonce {
            let nonce = rand::thread_rng().gen::<NonZeroU32>();
            tx_builder.set_nonce(nonce);
        };

        tx_builder.with_metadata(metadata).sign(&self.key_pair)
    }

    /// Signs transaction
    ///
    /// # Errors
    /// Fails if signature generation fails
    pub fn sign_transaction<Tx: Sign>(&self, transaction: Tx) -> SignedTransaction {
        transaction.sign(&self.key_pair)
    }

    /// Signs query
    ///
    /// # Errors
    /// Fails if signature generation fails
    pub fn sign_query(&self, query: ClientQueryBuilder) -> SignedQuery {
        query.sign(&self.key_pair)
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit(&self, instruction: impl Instruction) -> Result<HashOf<SignedTransaction>> {
        let isi = instruction.into();
        self.submit_all([isi])
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all(
        &self,
        instructions: impl IntoIterator<Item = impl Instruction>,
    ) -> Result<HashOf<SignedTransaction>> {
        self.submit_all_with_metadata(instructions, UnlimitedMetadata::new())
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    /// Allows to specify [`Metadata`] of [`TransactionBuilder`].
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_with_metadata(
        &self,
        instruction: impl Instruction,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<SignedTransaction>> {
        self.submit_all_with_metadata([instruction], metadata)
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    /// Allows to specify [`Metadata`] of [`TransactionBuilder`].
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_with_metadata(
        &self,
        instructions: impl IntoIterator<Item = impl Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<SignedTransaction>> {
        self.submit_transaction(&self.build_transaction(instructions, metadata))
    }

    /// Submit a prebuilt transaction.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_transaction(
        &self,
        transaction: &SignedTransaction,
    ) -> Result<HashOf<SignedTransaction>> {
        iroha_logger::trace!(tx=?transaction, "Submitting");
        let (req, hash) = self.prepare_transaction_request::<DefaultRequestBuilder>(transaction);
        let response = req
            .build()?
            .send()
            .wrap_err_with(|| format!("Failed to send transaction with hash {hash:?}"))?;
        TransactionResponseHandler::handle(&response)?;
        Ok(hash)
    }

    /// Submit the prebuilt transaction and wait until it is either rejected or committed.
    /// If rejected, return the rejection reason.
    ///
    /// # Errors
    /// Fails if sending a transaction to a peer fails or there is an error in the response
    pub fn submit_transaction_blocking(
        &self,
        transaction: &SignedTransaction,
    ) -> Result<HashOf<SignedTransaction>> {
        let (init_sender, init_receiver) = tokio::sync::oneshot::channel();
        let hash = transaction.hash();

        thread::scope(|spawner| {
            let submitter_handle = spawner.spawn(move || -> Result<()> {
                // Do not submit transaction if event listener is failed to initialize
                if init_receiver
                    .blocking_recv()
                    .wrap_err("Failed to receive init message.")?
                {
                    self.submit_transaction(transaction)?;
                }
                Ok(())
            });

            let confirmation_res = self.listen_for_tx_confirmation(init_sender, hash);

            match submitter_handle.join() {
                Ok(Ok(())) => confirmation_res,
                Ok(Err(e)) => Err(e).wrap_err("Transaction submitter thread exited with error"),
                Err(_) => Err(eyre!("Transaction submitter thread panicked")),
            }
        })
    }

    fn listen_for_tx_confirmation(
        &self,
        init_sender: tokio::sync::oneshot::Sender<bool>,
        hash: HashOf<SignedTransaction>,
    ) -> Result<HashOf<SignedTransaction>> {
        let deadline = tokio::time::Instant::now() + self.transaction_status_timeout;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let mut event_iterator = {
                let filters = vec![
                    TransactionEventFilter::default().for_hash(hash).into(),
                    PipelineEventFilterBox::from(
                        BlockEventFilter::default().for_status(BlockStatus::Applied),
                    ),
                ];

                let event_iterator_result =
                    tokio::time::timeout_at(deadline, self.listen_for_events_async(filters))
                        .await
                        .map_err(Into::into)
                        .and_then(std::convert::identity)
                        .wrap_err("Failed to establish event listener connection");
                let _send_result = init_sender.send(event_iterator_result.is_ok());
                event_iterator_result?
            };

            let result = tokio::time::timeout_at(
                deadline,
                Self::listen_for_tx_confirmation_loop(&mut event_iterator, hash),
            )
            .await
            .map_err(Into::into)
            .and_then(std::convert::identity);
            event_iterator.close().await;
            result
        })
    }

    async fn listen_for_tx_confirmation_loop(
        event_iterator: &mut AsyncEventStream,
        hash: HashOf<SignedTransaction>,
    ) -> Result<HashOf<SignedTransaction>> {
        let mut block_height = None;

        while let Some(event) = event_iterator.next().await {
            if let EventBox::Pipeline(this_event) = event? {
                match this_event {
                    PipelineEventBox::Transaction(transaction_event) => {
                        match transaction_event.status() {
                            TransactionStatus::Queued => {}
                            TransactionStatus::Approved => {
                                block_height = transaction_event.block_height();
                            }
                            TransactionStatus::Rejected(reason) => {
                                return Err((Clone::clone(&**reason)).into());
                            }
                            TransactionStatus::Expired => return Err(eyre!("Transaction expired")),
                        }
                    }
                    PipelineEventBox::Block(block_event) => {
                        if Some(block_event.header().height()) == block_height {
                            if let BlockStatus::Applied = block_event.status() {
                                return Ok(hash);
                            }
                        }
                    }
                }
            }
        }

        Err(eyre!(
            "Connection dropped without `Committed` or `Rejected` event"
        ))
    }

    /// Lower-level Instructions API entry point.
    ///
    /// Returns a tuple with a provided request builder, a hash of the transaction, and a response handler.
    /// Despite the fact that response handling can be implemented just by asserting that status code is 200,
    /// it is better to use a response handler anyway. It allows to abstract from implementation details.
    ///
    /// For general usage example see [`Client::prepare_query_request`].
    fn prepare_transaction_request<B: RequestBuilder>(
        &self,
        transaction: &SignedTransaction,
    ) -> (B, HashOf<SignedTransaction>) {
        let transaction_bytes: Vec<u8> = transaction.encode_versioned();

        (
            B::new(
                HttpMethod::POST,
                self.torii_url
                    .join(torii_uri::TRANSACTION)
                    .expect("Valid URI"),
            )
            .headers(self.headers.clone())
            .body(transaction_bytes),
            transaction.hash(),
        )
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_blocking(
        &self,
        instruction: impl Instruction,
    ) -> Result<HashOf<SignedTransaction>> {
        self.submit_all_blocking(vec![instruction.into()])
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_blocking(
        &self,
        instructions: impl IntoIterator<Item = impl Instruction>,
    ) -> Result<HashOf<SignedTransaction>> {
        self.submit_all_blocking_with_metadata(instructions, UnlimitedMetadata::new())
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Allows to specify [`Metadata`] of [`TransactionBuilder`].
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_blocking_with_metadata(
        &self,
        instruction: impl Instruction,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<SignedTransaction>> {
        self.submit_all_blocking_with_metadata(vec![instruction.into()], metadata)
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Allows to specify [`Metadata`] of [`TransactionBuilder`].
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_blocking_with_metadata(
        &self,
        instructions: impl IntoIterator<Item = impl Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<SignedTransaction>> {
        let transaction = self.build_transaction(instructions, metadata);
        self.submit_transaction_blocking(&transaction)
    }

    /// Lower-level Query API entry point. Prepares an http-request and returns it with an http-response handler.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use eyre::Result;
    /// use crate::{
    ///     data_model::{predicate::PredicateBox, prelude::{Account, FindAllAccounts, Pagination}},
    ///     client::Client,
    ///     http::{RequestBuilder, Response, Method},
    /// };
    ///
    /// struct YourAsyncRequest;
    ///
    /// impl YourAsyncRequest {
    ///     async fn send(self) -> Response<Vec<u8>> {
    ///         todo!()
    ///     }
    /// }
    ///
    /// // Implement builder for this request
    /// impl RequestBuilder for YourAsyncRequest {
    ///     fn new(_: Method, url: impl AsRef<str>) -> Self {
    ///          todo!()
    ///     }
    ///
    ///     fn param<K: AsRef<str>, V: ToString>(self, _: K, _: V) -> Self  {
    ///          todo!()
    ///     }
    ///
    ///     fn header<N: AsRef<str>, V: ToString>(self, _: N, _: V) -> Self {
    ///          todo!()
    ///     }
    ///
    ///     fn body(self, data: Vec<u8>) -> Self {
    ///          todo!()
    ///     }
    /// }
    ///
    /// async fn fetch_accounts(client: &Client) -> Result<Vec<Account>> {
    ///     // Put `YourAsyncRequest` as a type here
    ///     // It returns the request and the handler (zero-cost abstraction) for the response
    ///     let (req, resp_handler) = client.prepare_query_request::<_, YourAsyncRequest>(
    ///         FindAllAccounts::new(),
    ///         Pagination::default(),
    ///         PredicateBox::default(),
    ///     )?;
    ///
    ///     // Do what you need to send the request and to get the response
    ///     let resp = req.send().await;
    ///
    ///     // Handle response with the handler and get typed result
    ///     let accounts = resp_handler.handle(resp)?;
    ///
    ///     Ok(accounts.output())
    /// }
    /// ```
    fn prepare_query_request<R: Query>(
        &self,
        request: R,
        filter: PredicateBox,
        pagination: Pagination,
        sorting: Sorting,
        fetch_size: FetchSize,
    ) -> (DefaultRequestBuilder, QueryResponseHandler<R::Output>)
    where
        <R::Output as TryFrom<QueryOutputBox>>::Error: Into<eyre::Error>,
    {
        let query_builder = ClientQueryBuilder::new(request, self.account_id.clone())
            .with_filter(filter)
            .with_pagination(pagination)
            .with_sorting(sorting)
            .with_fetch_size(fetch_size);
        let request = self.sign_query(query_builder);

        let query_request = QueryRequest {
            torii_url: self.torii_url.clone(),
            headers: self.headers.clone(),
            request: crate::data_model::query::QueryRequest::Query(request),
        };

        (
            query_request.clone().assemble(),
            QueryResponseHandler::new(query_request),
        )
    }

    /// Create a request with pagination, sorting and add the filter.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub(crate) fn request_with_filter_and_pagination_and_sorting<R: Query + Debug>(
        &self,
        request: R,
        pagination: Pagination,
        fetch_size: FetchSize,
        sorting: Sorting,
        filter: PredicateBox,
    ) -> QueryResult<<R::Output as QueryOutput>::Target>
    where
        R::Output: QueryOutput,
        <R::Output as TryFrom<QueryOutputBox>>::Error: Into<eyre::Error>,
    {
        iroha_logger::trace!(?request, %pagination, ?sorting, ?filter);
        let (req, mut resp_handler) =
            self.prepare_query_request::<R>(request, filter, pagination, sorting, fetch_size);

        let response = req.build()?.send()?;
        let output = resp_handler.handle(&response)?;
        let output = QueryOutput::new(output, resp_handler);

        Ok(output)
    }

    /// Query API entry point. Shorthand for `self.build_query(r).execute()`.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn request<R>(&self, request: R) -> QueryResult<<R::Output as QueryOutput>::Target>
    where
        R: Query + Debug,
        R::Output: QueryOutput,
        <R::Output as TryFrom<QueryOutputBox>>::Error: Into<eyre::Error>,
    {
        self.build_query(request).execute()
    }

    /// Query API entry point using cursor.
    ///
    /// You should probably not use this function directly.
    ///
    /// # Errors
    /// Fails if sending request fails
    #[cfg(debug_assertions)]
    pub fn request_with_cursor<O>(
        &self,
        cursor: crate::data_model::query::cursor::ForwardCursor,
    ) -> QueryResult<O::Target>
    where
        O: QueryOutput,
        <O as TryFrom<QueryOutputBox>>::Error: Into<eyre::Error>,
    {
        let request = QueryRequest {
            torii_url: self.torii_url.clone(),
            headers: self.headers.clone(),
            request: crate::data_model::query::QueryRequest::Cursor(cursor),
        };
        let response = request.clone().assemble().build()?.send()?;

        let mut resp_handler = QueryResponseHandler::<O>::new(request);
        let output = resp_handler.handle(&response)?;
        let output = O::new(output, resp_handler);

        Ok(output)
    }

    /// Query API entry point.
    /// Creates a [`QueryRequestBuilder`] which can be used to configure requests queries from `Iroha` peers.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn build_query<R>(&self, request: R) -> QueryRequestBuilder<'_, R>
    where
        R: Query + Debug,
        R::Output: QueryOutput,
        <R::Output as TryFrom<QueryOutputBox>>::Error: Into<eyre::Error>,
    {
        QueryRequestBuilder::new(self, request)
    }

    /// Connect (through `WebSocket`) to listen for `Iroha` `pipeline` and `data` events.
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`events_api::EventIterator::new`]
    pub fn listen_for_events(
        &self,
        event_filters: impl IntoIterator<Item = impl Into<EventFilterBox>>,
    ) -> Result<impl Iterator<Item = Result<EventBox>>> {
        events_api::EventIterator::new(self.events_handler(event_filters)?)
    }

    /// Connect asynchronously (through `WebSocket`) to listen for `Iroha` `pipeline` and `data` events.
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`events_api::AsyncEventStream::new`]
    pub async fn listen_for_events_async(
        &self,
        event_filters: impl IntoIterator<Item = impl Into<EventFilterBox>> + Send,
    ) -> Result<AsyncEventStream> {
        events_api::AsyncEventStream::new(self.events_handler(event_filters)?).await
    }

    /// Constructs an Events API handler. With it, you can use any WS client you want.
    ///
    /// # Errors
    /// Fails if handler construction fails
    #[inline]
    pub fn events_handler(
        &self,
        event_filters: impl IntoIterator<Item = impl Into<EventFilterBox>>,
    ) -> Result<events_api::flow::Init> {
        events_api::flow::Init::new(
            event_filters.into_iter().map(Into::into).collect(),
            self.headers.clone(),
            self.torii_url
                .join(torii_uri::SUBSCRIPTION)
                .expect("Valid URI"),
        )
    }

    /// Connect (through `WebSocket`) to listen for `Iroha` blocks
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`blocks_api::BlockIterator::new`]
    pub fn listen_for_blocks(
        &self,
        height: NonZeroU64,
    ) -> Result<impl Iterator<Item = Result<SignedBlock>>> {
        blocks_api::BlockIterator::new(self.blocks_handler(height)?)
    }

    /// Connect asynchronously (through `WebSocket`) to listen for `Iroha` blocks
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`blocks_api::BlockIterator::new`]
    pub async fn listen_for_blocks_async(&self, height: NonZeroU64) -> Result<AsyncBlockStream> {
        blocks_api::AsyncBlockStream::new(self.blocks_handler(height)?).await
    }

    /// Construct a handler for Blocks API. With this handler you can use any WS client you want.
    ///
    /// # Errors
    /// - if handler construction fails
    #[inline]
    pub fn blocks_handler(&self, height: NonZeroU64) -> Result<blocks_api::flow::Init> {
        blocks_api::flow::Init::new(
            height,
            self.headers.clone(),
            self.torii_url
                .join(torii_uri::BLOCKS_STREAM)
                .expect("Valid URI"),
        )
    }

    /// Get value of config on peer
    ///
    /// # Errors
    /// Fails if sending request or decoding fails
    pub fn get_config(&self) -> Result<ConfigDTO> {
        let resp = DefaultRequestBuilder::new(
            HttpMethod::GET,
            self.torii_url
                .join(torii_uri::CONFIGURATION)
                .expect("Valid URI"),
        )
        .headers(&self.headers)
        .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
        .build()?
        .send()?;

        if resp.status() != StatusCode::OK {
            return Err(eyre!(
                "Failed to get configuration with HTTP status: {}. {}",
                resp.status(),
                std::str::from_utf8(resp.body()).unwrap_or(""),
            ));
        }
        serde_json::from_slice(resp.body()).wrap_err("Failed to decode body")
    }

    /// Send a request to change the configuration of a specified field.
    ///
    /// # Errors
    /// If sending request or decoding fails
    pub fn set_config(&self, dto: ConfigDTO) -> Result<()> {
        let body = serde_json::to_vec(&dto).wrap_err(format!("Failed to serialize {dto:?}"))?;
        let url = self
            .torii_url
            .join(torii_uri::CONFIGURATION)
            .expect("Valid URI");
        let resp = DefaultRequestBuilder::new(HttpMethod::POST, url)
            .headers(&self.headers)
            .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
            .body(body)
            .build()?
            .send()?;

        if resp.status() != StatusCode::ACCEPTED {
            return Err(eyre!(
                "Failed to post configuration with HTTP status: {}. {}",
                resp.status(),
                std::str::from_utf8(resp.body()).unwrap_or(""),
            ));
        };

        Ok(())
    }

    /// Gets network status seen from the peer
    ///
    /// # Errors
    /// Fails if sending request or decoding fails
    pub fn get_status(&self) -> Result<Status> {
        let req = self
            .prepare_status_request::<DefaultRequestBuilder>()
            .header(http::header::ACCEPT, "application/x-parity-scale");
        let resp = req.build()?.send()?;
        let scaled_resp = StatusResponseHandler::handle_raw(&resp).cloned()?;
        DecodeAll::decode_all(&mut scaled_resp.as_slice()).map_err(|err| eyre!("{err}"))
    }

    /// Prepares http-request to implement [`Self::get_status`] on your own.
    ///
    /// For general usage example see [`Client::prepare_query_request`].
    ///
    /// # Errors
    /// Fails if request build fails
    pub fn prepare_status_request<B: RequestBuilder>(&self) -> B {
        B::new(
            HttpMethod::GET,
            self.torii_url.join(torii_uri::STATUS).expect("Valid URI"),
        )
        .headers(self.headers.clone())
    }
}

/// Logic for `sync` and `async` Iroha websocket streams
pub mod stream_api {
    use futures_util::{SinkExt, Stream, StreamExt};

    use super::*;
    use crate::{
        http::ws::conn_flow::{Events, Init, InitData},
        http_default::DefaultWebSocketRequestBuilder,
    };

    /// Iterator for getting messages from the `WebSocket` stream.
    pub(super) struct SyncIterator<E> {
        stream: WebSocketStream,
        handler: E,
    }

    impl<E> SyncIterator<E> {
        /// Construct `SyncIterator` and send the subscription request.
        ///
        /// # Errors
        /// - Request failed to build
        /// - `connect` failed
        /// - Sending failed
        /// - Message not received in stream during connection or subscription
        /// - Message is an error
        pub fn new<I: Init<DefaultWebSocketRequestBuilder>>(
            handler: I,
        ) -> Result<SyncIterator<I::Next>> {
            trace!("Creating `SyncIterator`");
            let InitData {
                first_message,
                req,
                next: next_handler,
            } = Init::<http_default::DefaultWebSocketRequestBuilder>::init(handler);

            let mut stream = req.build()?.connect()?;
            stream.send(WebSocketMessage::Binary(first_message))?;

            trace!("`SyncIterator` created successfully");
            Ok(SyncIterator {
                stream,
                handler: next_handler,
            })
        }
    }

    impl<E: Events> Iterator for SyncIterator<E> {
        type Item = Result<E::Event>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.stream.read() {
                    Ok(WebSocketMessage::Binary(message)) => {
                        return Some(self.handler.message(message))
                    }
                    Ok(_) => continue,
                    Err(WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed) => {
                        return None
                    }
                    Err(err) => return Some(Err(err.into())),
                }
            }
        }
    }

    impl<E> Drop for SyncIterator<E> {
        fn drop(&mut self) {
            let mut close = || -> eyre::Result<()> {
                self.stream.close(None)?;
                let msg = self.stream.read()?;
                if !msg.is_close() {
                    return Err(eyre!(
                        "Server hasn't sent `Close` message for websocket handshake"
                    ));
                }
                Ok(())
            };

            trace!("Closing WebSocket connection");
            let _ = close().map_err(|e| error!(%e));
            trace!("WebSocket connection closed");
        }
    }

    /// Async stream for getting messages from the `WebSocket` stream.
    pub struct AsyncStream<E> {
        stream: AsyncWebSocketStream,
        handler: E,
    }

    impl<E> AsyncStream<E> {
        /// Construct [`AsyncStream`] and send the subscription request.
        ///
        /// # Errors
        /// - Request failed to build
        /// - `connect_async` failed
        /// - Sending failed
        /// - Message not received in stream during connection or subscription
        /// - Message is an error
        #[allow(clippy::future_not_send)]
        pub async fn new<I: Init<DefaultWebSocketRequestBuilder>>(
            handler: I,
        ) -> Result<AsyncStream<I::Next>> {
            trace!("Creating `AsyncStream`");
            let InitData {
                first_message,
                req,
                next: next_handler,
            } = Init::<http_default::DefaultWebSocketRequestBuilder>::init(handler);

            let mut stream = req.build()?.connect_async().await?;
            stream.send(WebSocketMessage::Binary(first_message)).await?;

            trace!("`AsyncStream` created successfully");
            Ok(AsyncStream {
                stream,
                handler: next_handler,
            })
        }
    }

    impl<E: Send> AsyncStream<E> {
        /// Close websocket
        /// # Errors
        /// - Server fails to send `Close` message
        /// - Closing the websocket connection itself fails.
        pub async fn close(mut self) {
            let close = async {
                self.stream.close(None).await?;
                if let Some(msg) = self.stream.next().await {
                    if !msg?.is_close() {
                        eyre::bail!("Server hasn't sent `Close` message for websocket handshake");
                    }
                }
                Ok(())
            };

            trace!("Closing WebSocket connection");
            let _ = close.await.map_err(|e| error!(%e));
            trace!("WebSocket connection closed");
        }
    }

    impl<E: Events + Unpin> Stream for AsyncStream<E> {
        type Item = Result<E::Event>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match futures_util::ready!(self.stream.poll_next_unpin(cx)) {
                Some(Ok(WebSocketMessage::Binary(message))) => {
                    std::task::Poll::Ready(Some(self.handler.message(message)))
                }
                Some(Ok(_)) => std::task::Poll::Pending,
                Some(Err(err)) => std::task::Poll::Ready(Some(Err(err.into()))),
                None => std::task::Poll::Ready(None),
            }
        }
    }
}

/// Logic related to Events API client implementation.
pub mod events_api {

    use super::*;
    use crate::http::ws::{
        conn_flow::{Events as FlowEvents, Init as FlowInit, InitData},
        transform_ws_url,
    };

    /// Events API flow. For documentation and usage examples, refer to [`crate::http::ws::conn_flow`].
    pub mod flow {
        use super::*;

        /// Initialization struct for Events API flow.
        pub struct Init {
            /// TORII URL
            url: Url,
            /// HTTP request headers
            headers: HashMap<String, String>,
            /// Event filter
            filters: Vec<EventFilterBox>,
        }

        impl Init {
            /// Construct new item with provided filter, headers and url.
            ///
            /// # Errors
            /// Fails if [`transform_ws_url`] fails.
            #[inline]
            pub(in super::super) fn new(
                filters: Vec<EventFilterBox>,
                headers: HashMap<String, String>,
                url: Url,
            ) -> Result<Self> {
                Ok(Self {
                    url: transform_ws_url(url)?,
                    headers,
                    filters,
                })
            }
        }

        impl<R: RequestBuilder> FlowInit<R> for Init {
            type Next = Events;

            fn init(self) -> InitData<R, Self::Next> {
                let Self {
                    url,
                    headers,
                    filters,
                } = self;

                let msg = EventSubscriptionRequest::new(filters).encode();
                InitData::new(R::new(HttpMethod::GET, url).headers(headers), msg, Events)
            }
        }

        /// Events handler for Events API flow
        #[derive(Debug, Copy, Clone)]
        pub struct Events;

        impl FlowEvents for Events {
            type Event = crate::data_model::prelude::EventBox;

            fn message(&self, message: Vec<u8>) -> Result<Self::Event> {
                let event_socket_message = EventMessage::decode_all(&mut message.as_slice())?;
                Ok(event_socket_message.into())
            }
        }
    }

    /// Iterator for getting events from the `WebSocket` stream.
    pub(super) type EventIterator = stream_api::SyncIterator<flow::Events>;

    /// Async stream for getting events from the `WebSocket` stream.
    pub type AsyncEventStream = stream_api::AsyncStream<flow::Events>;
}

mod blocks_api {
    use super::*;
    use crate::http::ws::{
        conn_flow::{Events as FlowEvents, Init as FlowInit, InitData},
        transform_ws_url,
    };

    /// Blocks API flow. For documentation and usage examples, refer to [`crate::http::ws::conn_flow`].
    pub mod flow {
        use std::num::NonZeroU64;

        use super::*;
        use crate::data_model::block::stream::*;

        /// Initialization struct for Blocks API flow.
        pub struct Init {
            /// Block height from which to start streaming blocks
            height: NonZeroU64,
            /// HTTP request headers
            headers: HashMap<String, String>,
            /// TORII URL
            url: Url,
        }

        impl Init {
            /// Construct new item with provided headers and url.
            ///
            /// # Errors
            /// If [`transform_ws_url`] fails.
            #[inline]
            pub(in super::super) fn new(
                height: NonZeroU64,
                headers: HashMap<String, String>,
                url: Url,
            ) -> Result<Self> {
                Ok(Self {
                    height,
                    headers,
                    url: transform_ws_url(url)?,
                })
            }
        }

        impl<R: RequestBuilder> FlowInit<R> for Init {
            type Next = Events;

            fn init(self) -> InitData<R, Self::Next> {
                let Self {
                    height,
                    headers,
                    url,
                } = self;

                let msg = BlockSubscriptionRequest::new(height).encode();
                InitData::new(R::new(HttpMethod::GET, url).headers(headers), msg, Events)
            }
        }

        /// Events handler for Blocks API flow
        #[derive(Debug, Copy, Clone)]
        pub struct Events;

        impl FlowEvents for Events {
            type Event = crate::data_model::block::SignedBlock;

            fn message(&self, message: Vec<u8>) -> Result<Self::Event> {
                Ok(BlockMessage::decode_all(&mut message.as_slice()).map(Into::into)?)
            }
        }
    }

    /// Iterator for getting blocks from the `WebSocket` stream.
    pub(super) type BlockIterator = stream_api::SyncIterator<flow::Events>;

    /// Async stream for getting blocks from the `WebSocket` stream.
    pub type AsyncBlockStream = stream_api::AsyncStream<flow::Events>;
}

pub mod account {
    //! Module with queries for account
    use super::*;

    /// Construct a query to get all accounts
    pub const fn all() -> FindAllAccounts {
        FindAllAccounts
    }

    /// Construct a query to get account by id
    pub fn by_id(account_id: AccountId) -> FindAccountById {
        FindAccountById::new(account_id)
    }

    /// Construct a query to get all accounts containing specified asset
    pub fn all_with_asset(asset_definition_id: AssetDefinitionId) -> FindAccountsWithAsset {
        FindAccountsWithAsset::new(asset_definition_id)
    }
}

pub mod asset {
    //! Module with queries for assets
    use super::*;

    /// Construct a query to get all assets
    pub const fn all() -> FindAllAssets {
        FindAllAssets
    }

    /// Construct a query to get all asset definitions
    pub const fn all_definitions() -> FindAllAssetsDefinitions {
        FindAllAssetsDefinitions
    }

    /// Construct a query to get asset definition by its id
    pub fn definition_by_id(asset_definition_id: AssetDefinitionId) -> FindAssetDefinitionById {
        FindAssetDefinitionById::new(asset_definition_id)
    }

    /// Construct a query to get all assets by account id
    pub fn by_account_id(account_id: AccountId) -> FindAssetsByAccountId {
        FindAssetsByAccountId::new(account_id)
    }

    /// Construct a query to get an asset by its id
    pub fn by_id(asset_id: AssetId) -> FindAssetById {
        FindAssetById::new(asset_id)
    }
}

pub mod block {
    //! Module with queries related to blocks

    use super::*;

    /// Construct a query to find all blocks
    pub const fn all() -> FindAllBlocks {
        FindAllBlocks
    }

    /// Construct a query to find all block headers
    pub const fn all_headers() -> FindAllBlockHeaders {
        FindAllBlockHeaders
    }

    /// Construct a query to find block header by hash
    pub fn header_by_hash(hash: HashOf<SignedBlock>) -> FindBlockHeaderByHash {
        FindBlockHeaderByHash::new(hash)
    }
}

pub mod domain {
    //! Module with queries for domains
    use super::*;

    /// Construct a query to get all domains
    pub const fn all() -> FindAllDomains {
        FindAllDomains
    }

    /// Construct a query to get all domain by id
    pub fn by_id(domain_id: DomainId) -> FindDomainById {
        FindDomainById::new(domain_id)
    }
}

pub mod transaction {
    //! Module with queries for transactions

    use super::*;

    /// Construct a query to find all transactions
    pub fn all() -> FindAllTransactions {
        FindAllTransactions
    }

    /// Construct a query to retrieve transactions for account
    pub fn by_account_id(account_id: AccountId) -> FindTransactionsByAccountId {
        FindTransactionsByAccountId::new(account_id)
    }

    /// Construct a query to retrieve transaction by hash
    pub fn by_hash(hash: HashOf<SignedTransaction>) -> FindTransactionByHash {
        FindTransactionByHash::new(hash)
    }
}

pub mod trigger {
    //! Module with queries for triggers
    use super::*;

    /// Construct a query to get triggers by domain id
    pub fn by_domain_id(domain_id: DomainId) -> FindTriggersByDomainId {
        FindTriggersByDomainId::new(domain_id)
    }
}

pub mod permission {
    //! Module with queries for permission tokens
    use super::*;

    /// Construct a query to get all [`Permission`] granted
    /// to account with given [`Id`][AccountId]
    pub fn by_account_id(account_id: AccountId) -> FindPermissionsByAccountId {
        FindPermissionsByAccountId::new(account_id)
    }
}

pub mod role {
    //! Module with queries for roles
    use super::*;

    /// Construct a query to retrieve all roles
    pub const fn all() -> FindAllRoles {
        FindAllRoles
    }

    /// Construct a query to retrieve all role ids
    pub const fn all_ids() -> FindAllRoleIds {
        FindAllRoleIds
    }

    /// Construct a query to retrieve a role by its id
    pub fn by_id(role_id: RoleId) -> FindRoleByRoleId {
        FindRoleByRoleId::new(role_id)
    }

    /// Construct a query to retrieve all roles for an account
    pub fn by_account_id(account_id: AccountId) -> FindRolesByAccountId {
        FindRolesByAccountId::new(account_id)
    }
}

pub mod parameter {
    //! Module with queries for config parameters
    use super::*;

    /// Construct a query to retrieve all config parameters
    pub const fn all() -> FindAllParameters {
        FindAllParameters
    }
}

pub mod executor {
    //! Queries for executor entities
    use super::*;

    /// Retrieve executor data model
    pub const fn data_model() -> FindExecutorDataModel {
        FindExecutorDataModel
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use iroha_primitives::small::SmallStr;
    use test_samples::gen_account_in;

    use super::*;
    use crate::config::{BasicAuth, Config, WebLogin};

    const LOGIN: &str = "mad_hatter";
    const PASSWORD: &str = "ilovetea";
    // `mad_hatter:ilovetea` encoded with base64
    const ENCRYPTED_CREDENTIALS: &str = "bWFkX2hhdHRlcjppbG92ZXRlYQ==";

    fn config_factory() -> Config {
        let (account_id, key_pair) = gen_account_in("wonderland");
        Config {
            chain_id: ChainId::from("0"),
            key_pair,
            account_id,
            torii_api_url: "http://127.0.0.1:8080".parse().unwrap(),
            basic_auth: None,
            transaction_add_nonce: false,
            transaction_ttl: Duration::from_secs(5),
            transaction_status_timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn txs_same_except_for_nonce_have_different_hashes() {
        let client = Client::new(Config {
            transaction_add_nonce: true,
            ..config_factory()
        });

        let build_transaction =
            || client.build_transaction(Vec::<InstructionBox>::new(), UnlimitedMetadata::new());
        let tx1 = build_transaction();
        let tx2 = build_transaction();
        assert_ne!(tx1.hash(), tx2.hash());

        let tx2 = {
            let mut tx =
                TransactionBuilder::new(client.chain_id.clone(), client.account_id.clone())
                    .with_executable(tx1.instructions().clone())
                    .with_metadata(tx1.metadata().clone());

            tx.set_creation_time(tx1.creation_time());
            if let Some(nonce) = tx1.nonce() {
                tx.set_nonce(nonce);
            }
            if let Some(transaction_ttl) = client.transaction_ttl {
                tx.set_ttl(transaction_ttl);
            }

            client.sign_transaction(tx)
        };
        assert_eq!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn authorization_header() {
        let client = Client::new(Config {
            basic_auth: Some(BasicAuth {
                web_login: WebLogin::from_str(LOGIN).expect("Failed to create valid `WebLogin`"),
                password: SmallStr::from_str(PASSWORD),
            }),
            ..config_factory()
        });

        let value = client
            .headers
            .get("Authorization")
            .expect("Expected `Authorization` header");
        let expected_value = format!("Basic {ENCRYPTED_CREDENTIALS}");
        assert_eq!(value, &expected_value);
    }

    #[cfg(test)]
    mod query_errors_handling {
        use http::Response;

        use super::*;
        use crate::data_model::{asset::Asset, query::error::QueryExecutionFail, ValidationFail};

        #[test]
        fn certain_errors() -> Result<()> {
            let mut sut = QueryResponseHandler::<Vec<Asset>>::new(QueryRequest::dummy());
            let responses = vec![
                (
                    StatusCode::UNAUTHORIZED,
                    ValidationFail::QueryFailed(QueryExecutionFail::Signature(
                        "whatever".to_owned(),
                    )),
                ),
                (StatusCode::UNPROCESSABLE_ENTITY, ValidationFail::TooComplex),
            ];
            for (status_code, err) in responses {
                let resp = Response::builder().status(status_code).body(err.encode())?;

                match sut.handle(&resp) {
                    Err(ClientQueryError::Validation(actual)) => {
                        // PartialEq isn't implemented, so asserting by encoded repr
                        assert_eq!(actual.encode(), err.encode());
                    }
                    x => return Err(eyre!("Wrong output for {:?}: {:?}", (status_code, err), x)),
                }
            }

            Ok(())
        }

        #[test]
        fn indeterminate() -> Result<()> {
            let mut sut = QueryResponseHandler::<Vec<Asset>>::new(QueryRequest::dummy());
            let response = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Vec::<u8>::new())?;

            match sut.handle(&response) {
                Err(ClientQueryError::Other(_)) => Ok(()),
                x => Err(eyre!("Expected indeterminate, found: {:?}", x)),
            }
        }
    }
}
