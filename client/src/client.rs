//! Contains the end-point querying logic.  This is where you need to
//! add any custom end-point related logic.
use std::{
    collections::HashMap,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    sync::mpsc,
    thread,
    time::Duration,
};

use eyre::{eyre, Result, WrapErr};
use http_default::WebSocketStream;
use iroha_config::{GetConfiguration, PostConfiguration};
use iroha_core::smartcontracts::isi::query::Error as QueryError;
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::{prelude::*, query::SignedQueryRequest};
use iroha_logger::prelude::*;
use iroha_telemetry::metrics::Status;
use iroha_version::prelude::*;
use rand::Rng;
use serde::de::DeserializeOwned;
use small::SmallStr;

use crate::{
    config::Configuration,
    http::{Headers as HttpHeaders, Method as HttpMethod, RequestBuilder, Response, StatusCode},
    http_default::{self, DefaultRequestBuilder, WebSocketError, WebSocketMessage},
};

/// General trait for all response handlers
pub trait ResponseHandler<T = Vec<u8>> {
    /// What is the output of the handler
    type Output;

    /// Handles HTTP response
    fn handle(self, response: Response<T>) -> Self::Output;
}

/// Phantom struct that handles responses of Query API.
/// Depending on input query struct, transforms a response into appropriate output.
#[derive(Clone, Copy)]
pub struct QueryResponseHandler<R>(PhantomData<R>);

impl<R> Default for QueryResponseHandler<R> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// `Result` with [`ClientQueryError`] as an error
pub type QueryHandlerResult<T> = core::result::Result<T, ClientQueryError>;

impl<R> ResponseHandler for QueryResponseHandler<R>
where
    R: Query + Into<QueryBox> + Debug,
    <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
{
    type Output = QueryHandlerResult<ClientQueryOutput<R>>;

    fn handle(self, resp: Response<Vec<u8>>) -> Self::Output {
        // Separate-compilation friendly response handling
        fn _handle_query_response_base(
            resp: &Response<Vec<u8>>,
        ) -> QueryHandlerResult<VersionedPaginatedQueryResult> {
            match resp.status() {
                StatusCode::OK => VersionedPaginatedQueryResult::decode_versioned(resp.body())
                    .wrap_err("Failed to decode response body as VersionedPaginatedQueryResult")
                    .map_err(Into::into),
                StatusCode::BAD_REQUEST
                | StatusCode::UNAUTHORIZED
                | StatusCode::FORBIDDEN
                | StatusCode::NOT_FOUND => {
                    let err = QueryError::decode(&mut resp.body().as_ref())
                        .wrap_err("Failed to decode response body as QueryError")?;
                    Err(ClientQueryError::QueryError(err))
                }
                _ => Err(ResponseReport::with_msg("Unexpected query response", resp).into()),
            }
        }

        _handle_query_response_base(&resp).and_then(|VersionedPaginatedQueryResult::V1(result)| {
            ClientQueryOutput::try_from(result).map_err(Into::into)
        })
    }
}

/// Different errors as a result of query response handling
#[derive(Debug, thiserror::Error)]
// `QueryError` variant is too large (32 bytes), but I think that this enum is not
// very frequently constructed, so boxing here is unnecessary.
#[allow(variant_size_differences)]
pub enum ClientQueryError {
    /// Certain Iroha query error
    #[error("Query error: {0}")]
    QueryError(QueryError),
    /// Some other error
    #[error("Other error: {0}")]
    Other(eyre::Error),
}

impl From<eyre::Error> for ClientQueryError {
    #[inline]
    fn from(err: eyre::Error) -> Self {
        Self::Other(err)
    }
}

impl From<ResponseReport> for ClientQueryError {
    #[inline]
    fn from(ResponseReport(err): ResponseReport) -> Self {
        Self::Other(err)
    }
}

/// Phantom struct that handles Transaction API HTTP response
#[derive(Clone, Copy)]
pub struct TransactionResponseHandler;

impl ResponseHandler for TransactionResponseHandler {
    type Output = Result<()>;

    fn handle(self, resp: Response<Vec<u8>>) -> Self::Output {
        if resp.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(ResponseReport::with_msg("Unexpected transaction response", &resp).into())
        }
    }
}

/// Phantom struct that handles status check HTTP response
#[derive(Clone, Copy)]
pub struct StatusResponseHandler;

impl ResponseHandler for StatusResponseHandler {
    type Output = Result<Status>;

    fn handle(self, resp: Response<Vec<u8>>) -> Self::Output {
        if resp.status() != StatusCode::OK {
            return Err(ResponseReport::with_msg("Unexpected status response", &resp).into());
        }
        serde_json::from_slice(resp.body()).wrap_err("Failed to decode body")
    }
}

/// Private structure to incapsulate error reporting for HTTP response.
struct ResponseReport(eyre::Report);

impl ResponseReport {
    /// Constructs report with provided message
    fn with_msg<S>(msg: S, response: &Response<Vec<u8>>) -> Self
    where
        S: AsRef<str>,
    {
        let status = response.status();
        let body = String::from_utf8_lossy(response.body());
        let msg = msg.as_ref();

        Self(eyre!("{msg}; status: {status}; response body: {body}"))
    }
}

impl From<ResponseReport> for eyre::Report {
    #[inline]
    fn from(report: ResponseReport) -> Self {
        report.0
    }
}

/// More convenient version of [`iroha_data_model::prelude::PaginatedQueryResult`].
/// The only difference is that this struct has `output` field extracted from the result
/// accordingly to the source query.
#[derive(Clone, Debug)]
pub struct ClientQueryOutput<R>
where
    R: Query + Into<QueryBox> + Debug,
    <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
{
    /// Query output
    pub output: R::Output,
    /// See [`iroha_data_model::prelude::PaginatedQueryResult`]
    pub pagination: Pagination,
    /// See [`iroha_data_model::prelude::PaginatedQueryResult`]
    pub total: u64,
}

impl<R> ClientQueryOutput<R>
where
    R: Query + Into<QueryBox> + Debug,
    <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
{
    /// Extracts output as is
    pub fn only_output(self) -> R::Output {
        self.output
    }
}

impl<R> TryFrom<PaginatedQueryResult> for ClientQueryOutput<R>
where
    R: Query + Into<QueryBox> + Debug,
    <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
{
    type Error = eyre::Report;

    fn try_from(
        PaginatedQueryResult {
            result,
            pagination,
            total,
        }: PaginatedQueryResult,
    ) -> Result<Self> {
        let QueryResult(result) = result;
        let output = R::Output::try_from(result)
            .map_err(Into::into)
            .wrap_err("Unexpected type")?;

        Ok(Self {
            output,
            pagination,
            total,
        })
    }
}

/// Iroha client
#[derive(Clone)]
pub struct Client {
    /// Url for accessing iroha node
    torii_url: SmallStr,
    /// Url to report status for administration
    telemetry_url: SmallStr,
    /// Limits to which transactions must adhere to
    transaction_limits: TransactionLimits,
    /// Accounts keypair
    key_pair: KeyPair,
    /// Transaction time to live in milliseconds
    proposed_transaction_ttl_ms: u64,
    /// Transaction status timeout
    transaction_status_timeout: Duration,
    /// Current account
    account_id: AccountId,
    /// Http headers which will be appended to each request
    headers: HttpHeaders,
    /// If `true` add nonce, which makes different hashes for
    /// transactions which occur repeatedly and/or simultaneously
    add_transaction_nonce: bool,
}

/// Representation of `Iroha` client.
impl Client {
    /// Constructor for client from configuration
    ///
    /// # Errors
    /// If configuration isn't valid (e.g public/private keys don't match)
    pub fn new(configuration: &Configuration) -> Result<Self> {
        Self::with_headers(configuration, HttpHeaders::default())
    }

    /// Constructor for client from configuration and headers
    ///
    /// *Authentication* header will be added, if `login` and `password` fields are presented
    ///
    /// # Errors
    /// If configuration isn't valid (e.g public/private keys don't match)
    pub fn with_headers(
        configuration: &Configuration,
        mut headers: HashMap<String, String>,
    ) -> Result<Self> {
        if let Some(basic_auth) = &configuration.basic_auth {
            let credentials = format!("{}:{}", basic_auth.web_login, basic_auth.password);
            let encoded = base64::encode(credentials);
            headers.insert(String::from("Authorization"), format!("Basic {}", encoded));
        }

        Ok(Self {
            torii_url: configuration.torii_api_url.clone(),
            telemetry_url: configuration.torii_telemetry_url.clone(),
            transaction_limits: configuration.transaction_limits,
            key_pair: KeyPair::new(
                configuration.public_key.clone(),
                configuration.private_key.clone(),
            )?,
            proposed_transaction_ttl_ms: configuration.transaction_time_to_live_ms,
            transaction_status_timeout: Duration::from_millis(
                configuration.transaction_status_timeout_ms,
            ),
            account_id: configuration.account_id.clone(),
            headers,
            add_transaction_nonce: configuration.add_transaction_nonce,
        })
    }

    /// Builds transaction out of supplied instructions or wasm.
    ///
    /// # Errors
    /// Fails if signing transaction fails
    pub fn build_transaction(
        &self,
        instructions: Executable,
        metadata: UnlimitedMetadata,
    ) -> Result<Transaction> {
        let transaction = Transaction::new(
            self.account_id.clone(),
            instructions,
            self.proposed_transaction_ttl_ms,
        );

        let transaction_with_metadata = if self.add_transaction_nonce {
            let nonce = rand::thread_rng().gen::<u32>();
            transaction.with_nonce(nonce)
        } else {
            transaction
        }
        .with_metadata(metadata);

        self.sign_transaction(transaction_with_metadata)
    }

    /// Signs transaction
    ///
    /// # Errors
    /// Fails if generating signature fails
    pub fn sign_transaction(&self, transaction: Transaction) -> Result<Transaction> {
        transaction
            .sign(self.key_pair.clone())
            .wrap_err("Failed to sign transaction")
    }

    /// Signs query
    ///
    /// # Errors
    /// Fails if generating signature fails
    pub fn sign_query(&self, query: QueryRequest) -> Result<SignedQueryRequest> {
        query
            .sign(self.key_pair.clone())
            .wrap_err("Failed to sign query")
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    #[log]
    pub fn submit(
        &mut self,
        instruction: impl Into<Instruction> + Debug,
    ) -> Result<HashOf<VersionedTransaction>> {
        self.submit_all(vec![instruction.into()])
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all(
        &mut self,
        instructions: impl IntoIterator<Item = Instruction>,
    ) -> Result<HashOf<VersionedTransaction>> {
        self.submit_all_with_metadata(instructions, UnlimitedMetadata::new())
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    #[log]
    pub fn submit_with_metadata(
        &mut self,
        instruction: Instruction,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedTransaction>> {
        self.submit_all_with_metadata(vec![instruction], metadata)
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_with_metadata(
        &mut self,
        instructions: impl IntoIterator<Item = Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedTransaction>> {
        self.submit_transaction(self.build_transaction(instructions.into(), metadata)?)
    }

    /// Submit a prebuilt transaction.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<HashOf<VersionedTransaction>> {
        let (req, hash, resp_handler) =
            self.prepare_transaction_request::<DefaultRequestBuilder>(transaction)?;
        let response = req
            .send()
            .wrap_err_with(|| format!("Failed to send transaction with hash {:?}", hash))?;
        resp_handler.handle(response)?;
        Ok(hash)
    }

    /// Lower-level Instructions API entry point.
    ///
    /// Returns a tuple with a provided request builder, a hash of the transaction, and a response handler.
    /// Despite the fact that response handling can be implemented just by asserting that status code is 200,
    /// it is better to use a response handler anyway. It allows to abstract from implementation details.
    ///
    /// For general usage example see [`Client::prepare_query_request`].
    ///
    /// # Errors
    /// Fails if transaction check fails
    pub fn prepare_transaction_request<B>(
        &self,
        transaction: Transaction,
    ) -> Result<(B, HashOf<VersionedTransaction>, TransactionResponseHandler)>
    where
        B: RequestBuilder,
    {
        transaction.check_limits(&self.transaction_limits)?;
        let transaction: VersionedTransaction = transaction.into();
        let hash = transaction.hash();
        let transaction_bytes: Vec<u8> = transaction.encode_versioned();

        Ok((
            B::new(
                HttpMethod::POST,
                format!("{}/{}", &self.torii_url, uri::TRANSACTION),
            )
            .bytes(transaction_bytes)
            .headers(self.headers.clone()),
            hash,
            TransactionResponseHandler,
        ))
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_blocking(
        &mut self,
        instruction: impl Into<Instruction>,
    ) -> Result<HashOf<VersionedTransaction>> {
        self.submit_all_blocking(vec![instruction.into()])
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_blocking(
        &mut self,
        instructions: impl IntoIterator<Item = Instruction>,
    ) -> Result<HashOf<VersionedTransaction>> {
        self.submit_all_blocking_with_metadata(instructions, UnlimitedMetadata::new())
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_blocking_with_metadata(
        &mut self,
        instruction: impl Into<Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedTransaction>> {
        self.submit_all_blocking_with_metadata(vec![instruction.into()], metadata)
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_blocking_with_metadata(
        &mut self,
        instructions: impl IntoIterator<Item = Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedTransaction>> {
        struct EventListenerInitialized;

        let mut client = self.clone();
        let (event_sender, event_receiver) = mpsc::channel();
        let (init_sender, init_receiver) = mpsc::channel();
        let transaction = self.build_transaction(instructions.into(), metadata)?;
        let hash = transaction.hash();
        let _handle = thread::spawn(move || -> eyre::Result<()> {
            let event_iterator = client
                .listen_for_events(PipelineEventFilter::new().hash(hash.into()).into())
                .wrap_err("Failed to establish event listener connection.")?;
            init_sender
                .send(EventListenerInitialized)
                .wrap_err("Failed to send through init channel.")?;
            for event in event_iterator.flatten() {
                if let Event::Pipeline(this_event) = event {
                    match this_event.status {
                        PipelineStatus::Validating => {}
                        PipelineStatus::Rejected(reason) => event_sender
                            .send(Err(reason))
                            .wrap_err("Failed to send through event channel.")?,
                        PipelineStatus::Committed => event_sender
                            .send(Ok(hash.transmute()))
                            .wrap_err("Failed to send through event channel.")?,
                    }
                }
            }
            Ok(())
        });
        init_receiver
            .recv()
            .wrap_err("Failed to receive init message.")?;
        self.submit_transaction(transaction)?;
        event_receiver
            .recv_timeout(self.transaction_status_timeout)
            .map_or_else(
                |err| Err(err).wrap_err("Timeout waiting for transaction status"),
                |result| Ok(result?),
            )
    }

    /// Lower-level Query API entry point. Prepares an http-request and returns it with an http-response handler.
    ///
    /// # Errors
    /// Fails if query signing fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use eyre::Result;
    /// use iroha_client::{
    ///     client::{Client, ResponseHandler},
    ///     http::{RequestBuilder, Response},
    /// };
    /// use iroha_data_model::prelude::{Account, FindAllAccounts, Pagination};
    ///
    /// struct YourAsyncRequest;
    ///
    /// impl YourAsyncRequest {
    ///     async fn send(self) -> Response<Vec<u8>> {
    ///         // do the stuff
    ///     }
    /// }
    ///
    /// // Implement builder for this request
    /// impl RequestBuilder for YourAsyncRequest {
    ///     // ...
    /// }
    ///
    /// async fn fetch_accounts(client: &Client) -> Result<Vec<Account>> {
    ///     // Put `YourAsyncRequest` as a type here
    ///     // It returns the request and the handler (zero-cost abstraction) for the response
    ///     let (req, resp_handler) = client.prepare_query_request::<_, YourAsyncRequest>(
    ///         FindAllAccounts::new(),
    ///         Pagination::default(),
    ///     )?;
    ///
    ///     // Do what you need to send the request and to get the response
    ///     let resp = req.send().await;
    ///
    ///     // Handle response with the handler and get typed result
    ///     let accounts = resp_handler.handle(resp)?;
    ///
    ///     Ok(accounts.only_output())
    /// }
    /// ```
    pub fn prepare_query_request<R, B>(
        &self,
        request: R,
        pagination: Pagination,
    ) -> Result<(B, QueryResponseHandler<R>)>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
        B: RequestBuilder,
    {
        let pagination: Vec<_> = pagination.into();
        let request = QueryRequest::new(request.into(), self.account_id.clone());
        let request: VersionedSignedQueryRequest = self.sign_query(request)?.into();

        Ok((
            B::new(
                HttpMethod::POST,
                format!("{}/{}", &self.torii_url, uri::QUERY),
            )
            .bytes(request.encode_versioned())
            .params(pagination)
            .headers(self.headers.clone()),
            QueryResponseHandler::default(),
        ))
    }

    /// Query API entry point. Requests queries from `Iroha` peers with pagination.
    ///
    /// Uses default blocking http-client. If you need some custom integration, look at
    /// [`Self::prepare_query_request()`].
    ///
    /// # Errors
    /// Fails if sending request fails
    #[log]
    pub fn request_with_pagination<R>(
        &self,
        request: R,
        pagination: Pagination,
    ) -> QueryHandlerResult<ClientQueryOutput<R>>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        let (req, resp_handler) =
            self.prepare_query_request::<R, DefaultRequestBuilder>(request, pagination)?;
        let response = req.send()?;
        resp_handler.handle(response)
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    ///
    /// # Errors
    /// Fails if sending request fails
    #[log]
    pub fn request<R>(&self, request: R) -> QueryHandlerResult<R::Output>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.request_with_pagination(request, Pagination::default())
            .map(ClientQueryOutput::only_output)
    }

    /// Connects through `WebSocket` to listen for `Iroha` pipeline and data events.
    ///
    /// # Errors
    /// Fails if subscribing to websocket fails
    pub fn listen_for_events(
        &mut self,
        event_filter: FilterBox,
    ) -> Result<impl Iterator<Item = Result<Event>>> {
        EventIterator::new(
            &format!("{}/{}", &self.torii_url, uri::SUBSCRIPTION),
            event_filter,
            self.headers.clone(),
        )
    }

    /// Tries to find the original transaction in the pending local tx queue.
    /// Should be used for an MST case.
    /// Takes pagination as parameter.
    ///
    /// # Errors
    /// Fails if subscribing to websocket fails
    pub fn get_original_transaction_with_pagination(
        &self,
        transaction: &Transaction,
        retry_count: u32,
        retry_in: Duration,
        pagination: Pagination,
    ) -> Result<Option<Transaction>> {
        let pagination: Vec<_> = pagination.into();
        for _ in 0..retry_count {
            let response = DefaultRequestBuilder::new(
                HttpMethod::GET,
                format!("{}/{}", &self.torii_url, uri::PENDING_TRANSACTIONS),
            )
            .params(pagination.clone())
            .headers(self.headers.clone())
            .send()?;

            if response.status() == StatusCode::OK {
                let pending_transactions =
                    VersionedPendingTransactions::decode_versioned(response.body())?;
                let VersionedPendingTransactions::V1(pending_transactions) = pending_transactions;
                let transaction = pending_transactions
                    .into_iter()
                    .find(|pending_transaction| {
                        pending_transaction
                            .payload
                            .equals_excluding_creation_time(&transaction.payload)
                    });
                if transaction.is_some() {
                    return Ok(transaction);
                }
                thread::sleep(retry_in);
            } else {
                return Err(eyre!(
                    "Failed to make query request with HTTP status: {}, {}",
                    response.status(),
                    std::str::from_utf8(response.body()).unwrap_or(""),
                ));
            }
        }
        Ok(None)
    }

    /// Tries to find the original transaction in the local pending tx queue.
    /// Should be used for an MST case.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn get_original_transaction(
        &self,
        transaction: &Transaction,
        retry_count: u32,
        retry_in: Duration,
    ) -> Result<Option<Transaction>> {
        self.get_original_transaction_with_pagination(
            transaction,
            retry_count,
            retry_in,
            Pagination::default(),
        )
    }

    fn get_config<T: DeserializeOwned>(&self, get_config: &GetConfiguration) -> Result<T> {
        let headers = [("Content-Type".to_owned(), "application/json".to_owned())]
            .into_iter()
            .collect();
        let resp = DefaultRequestBuilder::new(
            HttpMethod::GET,
            format!("{}/{}", &self.torii_url, uri::CONFIGURATION),
        )
        .bytes(serde_json::to_vec(get_config).wrap_err("Failed to serialize")?)
        .headers(headers)
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
    pub fn set_config(&self, post_config: PostConfiguration) -> Result<bool> {
        let headers = [("Content-type".to_owned(), "application/json".to_owned())]
            .into_iter()
            .collect();
        let body = serde_json::to_vec(&post_config)
            .wrap_err(format!("Failed to serialize {:?}", post_config))?;
        let url = &format!("{}/{}", self.torii_url, uri::CONFIGURATION);
        let resp = DefaultRequestBuilder::new(HttpMethod::POST, url)
            .bytes(body)
            .headers(headers)
            .send()?;

        if resp.status() != StatusCode::OK {
            return Err(eyre!(
                "Failed to post configuration with HTTP status: {}. {}",
                resp.status(),
                std::str::from_utf8(resp.body()).unwrap_or(""),
            ));
        }
        serde_json::from_slice(resp.body())
            .wrap_err(format!("Failed to decode body {:?}", resp.body()))
    }

    /// Get documentation of some field on config
    ///
    /// # Errors
    /// Fails if sending request or decoding fails
    pub fn get_config_docs(&self, field: &[&str]) -> Result<Option<String>> {
        let field = field.iter().copied().map(ToOwned::to_owned).collect();
        self.get_config(&GetConfiguration::Docs(field))
            .wrap_err("Failed to get docs for field")
    }

    /// Get value of config on peer
    ///
    /// # Errors
    /// Fails if sending request or decoding fails
    pub fn get_config_value(&self) -> Result<serde_json::Value> {
        self.get_config(&GetConfiguration::Value)
            .wrap_err("Failed to get configuration value")
    }

    /// Gets network status seen from the peer
    /// # Errors
    /// Fails if sending request or decoding fails
    pub fn get_status(&self) -> Result<Status> {
        let (req, resp_handler) = self.prepare_status_request::<DefaultRequestBuilder>();
        let resp = req.send()?;
        resp_handler.handle(resp)
    }

    /// Prepares http-request to implement [`Self::get_status()`] on your own.
    ///
    /// For general usage example see [`Client::prepare_query_request`].
    ///
    /// # Errors
    /// Fails if request build fails
    pub fn prepare_status_request<B>(&self) -> (B, StatusResponseHandler)
    where
        B: RequestBuilder,
    {
        (
            B::new(
                HttpMethod::GET,
                format!("{}/{}", &self.telemetry_url, uri::STATUS),
            )
            .headers(self.headers.clone()),
            StatusResponseHandler,
        )
    }
}

/// Iterator for getting events from the `WebSocket` stream.
#[derive(Debug)]
pub struct EventIterator {
    stream: WebSocketStream,
}

impl EventIterator {
    /// Constructs `EventIterator` and sends the subscription request.
    ///
    /// # Errors
    /// Fails if connecting and sending subscription to web socket fails
    pub fn new(url: &str, event_filter: FilterBox, headers: HttpHeaders) -> Result<Self> {
        let mut stream = http_default::web_socket_connect(url, headers)?;
        stream.write_message(WebSocketMessage::Binary(
            VersionedEventSubscriberMessage::from(EventSubscriberMessage::from(event_filter))
                .encode_versioned(),
        ))?;
        loop {
            match stream.read_message() {
                Ok(WebSocketMessage::Binary(message)) => {
                    if let EventPublisherMessage::SubscriptionAccepted =
                        VersionedEventPublisherMessage::decode_versioned(&message)?.into_v1()
                    {
                        break;
                    }
                    return Err(eyre!("Expected `SubscriptionAccepted`."));
                }
                Ok(_) => continue,
                Err(WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed) => {
                    return Err(eyre!("WebSocket connection closed."))
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(Self { stream })
    }
}

impl Iterator for EventIterator {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.stream.read_message() {
                Ok(WebSocketMessage::Binary(message)) => {
                    let event_socket_message =
                        match VersionedEventPublisherMessage::decode_versioned(&message) {
                            Ok(event_socket_message) => event_socket_message.into_v1(),
                            Err(err) => return Some(Err(err.into())),
                        };
                    let event = match event_socket_message {
                        EventPublisherMessage::Event(event) => event,
                        msg => return Some(Err(eyre!("Expected Event but got {:?}", msg))),
                    };
                    let versioned_message = VersionedEventSubscriberMessage::from(
                        EventSubscriberMessage::EventReceived,
                    )
                    .encode_versioned();
                    return match self
                        .stream
                        .write_message(WebSocketMessage::Binary(versioned_message))
                    {
                        Ok(_) => Some(Ok(event)),
                        Err(err) => Some(Err(eyre!("Failed to send receipt: {}", err))),
                    };
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

impl Drop for EventIterator {
    fn drop(&mut self) {
        let mut close = || -> eyre::Result<()> {
            self.stream.close(None)?;
            let mes = self.stream.read_message()?;
            if !mes.is_close() {
                return Err(eyre!(
                    "Server hasn't sent `Close` message for websocket handshake"
                ));
            }
            Ok(())
        };

        let _ = close().map_err(|e| warn!(%e));
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("public_key", self.key_pair.public_key())
            .field("torii_url", &self.torii_url)
            .field("telemetry_url", &self.telemetry_url)
            .finish()
    }
}

pub mod account {
    //! Module with queries for account
    use super::*;

    /// Get query to get all accounts
    pub const fn all() -> FindAllAccounts {
        FindAllAccounts::new()
    }

    /// Get query to get account by id
    pub fn by_id(account_id: impl Into<EvaluatesTo<AccountId>>) -> FindAccountById {
        FindAccountById::new(account_id)
    }
}

pub mod asset {
    //! Module with queries for assets
    use super::*;

    /// Get query to get all assets
    pub const fn all() -> FindAllAssets {
        FindAllAssets::new()
    }

    /// Get query to get all asset definitions
    pub const fn all_definitions() -> FindAllAssetsDefinitions {
        FindAllAssetsDefinitions::new()
    }

    /// Get query to get all assets by account id
    pub fn by_account_id(account_id: impl Into<EvaluatesTo<AccountId>>) -> FindAssetsByAccountId {
        FindAssetsByAccountId::new(account_id)
    }

    /// Get query to get all assets by account id
    pub fn by_id(asset_id: impl Into<EvaluatesTo<<Asset as Identifiable>::Id>>) -> FindAssetById {
        FindAssetById::new(asset_id)
    }
}

pub mod domain {
    //! Module with queries for domains
    use super::*;

    /// Get query to get all domains
    pub const fn all() -> FindAllDomains {
        FindAllDomains::new()
    }

    /// Get query to get all domain by id
    pub fn by_id(domain_id: impl Into<EvaluatesTo<DomainId>>) -> FindDomainById {
        FindDomainById::new(domain_id)
    }
}

pub mod transaction {
    //! Module with queries for transactions
    use iroha_crypto::Hash;

    use super::*;

    /// Get query to retrieve transactions for account
    pub fn by_account_id(
        account_id: impl Into<EvaluatesTo<AccountId>>,
    ) -> FindTransactionsByAccountId {
        FindTransactionsByAccountId::new(account_id)
    }

    /// Get query to retrieve transaction by hash
    pub fn by_hash(hash: impl Into<EvaluatesTo<Hash>>) -> FindTransactionByHash {
        FindTransactionByHash::new(hash)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    use std::str::FromStr;

    use super::*;
    use crate::config::{BasicAuth, WebLogin};

    const LOGIN: &str = "mad_hatter";
    const PASSWORD: &str = "ilovetea";
    // `mad_hatter:ilovetea` encoded with base64
    const ENCRYPTED_CREDENTIALS: &str = "bWFkX2hhdHRlcjppbG92ZXRlYQ==";

    #[test]
    fn txs_same_except_for_nonce_have_different_hashes() {
        let (public_key, private_key) = KeyPair::generate().unwrap().into();

        let cfg = Configuration {
            public_key,
            private_key,
            add_transaction_nonce: true,
            ..Configuration::default()
        };
        let client = Client::new(&cfg).expect("Invalid client configuration");

        let build_transaction = || {
            client
                .build_transaction(Vec::<Instruction>::new().into(), UnlimitedMetadata::new())
                .unwrap()
        };
        let tx1 = build_transaction();
        let mut tx2 = build_transaction();

        tx2.payload.creation_time = tx1.payload.creation_time;
        assert_ne!(tx1.hash(), tx2.hash());
        tx2.payload.nonce = tx1.payload.nonce;
        assert_eq!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn authorization_header() {
        let basic_auth = BasicAuth {
            web_login: WebLogin::from_str(LOGIN).expect("Failed to create valid `WebLogin`"),
            password: SmallStr::from_str(PASSWORD),
        };

        let cfg = Configuration {
            basic_auth: Some(basic_auth),
            ..Configuration::default()
        };
        let client = Client::new(&cfg).expect("Invalid client configuration");

        let value = client
            .headers
            .get("Authorization")
            .expect("Expected `Authorization` header");
        let expected_value = format!("Basic {}", ENCRYPTED_CREDENTIALS);
        assert_eq!(value, &expected_value);
    }

    #[cfg(test)]
    mod query_errors_handling {
        use http::Response;
        use iroha_core::smartcontracts::isi::query::UnsupportedVersionError;

        use super::*;

        #[test]
        fn certain_errors() -> Result<()> {
            let sut = QueryResponseHandler::<FindAllAssets>::default();
            let responses = vec![
                (
                    StatusCode::BAD_REQUEST,
                    QueryError::Version(UnsupportedVersionError { version: 19 }),
                ),
                (
                    StatusCode::UNAUTHORIZED,
                    QueryError::Signature("whatever".to_owned()),
                ),
                (
                    StatusCode::FORBIDDEN,
                    QueryError::Permission("whatever".to_owned()),
                ),
                (
                    StatusCode::NOT_FOUND,
                    // Here should be `Find`, but actually handler doesn't care
                    QueryError::Evaluate("whatever".to_owned()),
                ),
            ];

            for (status_code, err) in responses {
                let resp = Response::builder()
                    .status(status_code)
                    .body(err.clone().encode())?;

                match sut.handle(resp) {
                    Err(ClientQueryError::QueryError(actual)) => {
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
            let sut = QueryResponseHandler::<FindAllAssets>::default();
            let response = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Vec::<u8>::new())?;

            match sut.handle(response) {
                Err(ClientQueryError::Other(_)) => Ok(()),
                x => Err(eyre!("Expected indeterminate, found: {:?}", x)),
            }
        }
    }
}
