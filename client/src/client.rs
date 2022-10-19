//! Contains the end-point querying logic.  This is where you need to
//! add any custom end-point related logic.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, thread, time::Duration};

use derive_more::{DebugCustom, Display};
use eyre::{eyre, Result, WrapErr};
use futures_util::StreamExt;
use http_default::{AsyncWebSocketStream, WebSocketStream};
use iroha_config::{client::Configuration, torii::uri, GetConfiguration, PostConfiguration};
use iroha_core::{
    prelude::VersionedCommittedBlock, smartcontracts::isi::query::Error as QueryError,
};
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::{predicate::PredicateBox, prelude::*, query::SignedQueryRequest};
use iroha_logger::prelude::*;
use iroha_primitives::small::SmallStr;
use iroha_telemetry::metrics::Status;
use iroha_version::prelude::*;
use parity_scale_codec::DecodeAll;
use rand::Rng;
use serde::de::DeserializeOwned;

use self::{blocks_api::AsyncBlockStream, events_api::AsyncEventStream};
use crate::{
    http::{Method as HttpMethod, RequestBuilder, Response, StatusCode},
    http_default::{self, DefaultRequestBuilder, WebSocketError, WebSocketMessage},
};

const APPLICATION_JSON: &str = "application/json";

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
                StatusCode::OK => {
                    let res =
                        try_decode_all_or_just_decode!(VersionedPaginatedQueryResult, resp.body());
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
                | StatusCode::NOT_FOUND => {
                    let mut res = QueryError::decode_all(&mut resp.body().as_ref());
                    if res.is_err() {
                        warn!("Can't decode query error, not all bytes were consumed");
                        res = QueryError::decode(&mut resp.body().as_ref());
                    }
                    let err = res.wrap_err(
                        "Failed to decode error-response from Iroha. \
                         You are likely using a version of the client library \
                         that is incompatible with the version of the peer software",
                    )?;
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
    /// The filter that was applied to the output.
    pub filter: PredicateBox,
    /// See [`iroha_data_model::prelude::PaginatedQueryResult`]
    pub pagination: Pagination,
    /// See [`iroha_data_model::prelude::PaginatedQueryResult`]
    pub sorting: Sorting,
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
            sorting,
            total,
            filter,
        }: PaginatedQueryResult,
    ) -> Result<Self> {
        let QueryResult(result) = result;
        let output = R::Output::try_from(result)
            .map_err(Into::into)
            .wrap_err("Unexpected type")?;

        Ok(Self {
            output,
            pagination,
            sorting,
            total,
            filter,
        })
    }
}

/// Iroha client
#[derive(Clone, DebugCustom, Display)]
#[debug(
    fmt = "Client {{ torii: {torii_url}, telemetry_url: {telemetry_url}, public_key: {} }}",
    "key_pair.public_key()"
)]
#[display(fmt = "{}@{torii_url}", "key_pair.public_key()")]
pub struct Client {
    /// Url for accessing iroha node
    torii_url: SmallStr,
    /// Url to report status for administration
    telemetry_url: SmallStr,
    /// The limits to which transactions must adhere to
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
    headers: HashMap<String, String>,
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
    #[inline]
    pub fn new(configuration: &Configuration) -> Result<Self> {
        Self::with_headers(configuration, HashMap::new())
    }

    /// Constructor for client from configuration and headers
    ///
    /// *Authentication* header will be added, if `login` and `password` fields are presented
    ///
    /// # Errors
    /// If configuration isn't valid (e.g public/private keys don't match)
    #[inline]
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
    ) -> Result<SignedTransaction> {
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
    pub fn sign_transaction<Tx: Sign>(&self, transaction: Tx) -> Result<SignedTransaction> {
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
    pub fn submit(
        &self,
        instruction: impl Into<Instruction> + Debug,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
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
        instructions: impl IntoIterator<Item = Instruction>,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        self.submit_all_with_metadata(instructions, UnlimitedMetadata::new())
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_with_metadata(
        &self,
        instruction: Instruction,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        self.submit_all_with_metadata([instruction], metadata)
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_with_metadata(
        &self,
        instructions: impl IntoIterator<Item = Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        self.submit_transaction(self.build_transaction(instructions.into(), metadata)?)
    }

    /// Submit a prebuilt transaction.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        iroha_logger::trace!(tx=?transaction);
        let (req, hash, resp_handler) =
            self.prepare_transaction_request::<DefaultRequestBuilder>(transaction)?;
        let response = req
            .build()?
            .send()
            .wrap_err_with(|| format!("Failed to send transaction with hash {:?}", hash))?;
        resp_handler.handle(response)?;
        Ok(hash)
    }

    /// Submit the prebuilt transaction and wait until it is either rejected or committed.
    /// If rejected, return the rejection reason.
    ///
    /// # Errors
    /// Fails if sending a transaction to a peer fails or there is an error in the response
    pub fn submit_transaction_blocking(
        &self,
        transaction: SignedTransaction,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
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
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        let deadline = tokio::time::Instant::now() + self.transaction_status_timeout;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let mut event_iterator = {
                let event_iterator_result = tokio::time::timeout_at(
                    deadline,
                    self.listen_for_events_async(
                        PipelineEventFilter::new().hash(hash.into()).into(),
                    ),
                )
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
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        while let Some(event) = event_iterator.next().await {
            if let Event::Pipeline(this_event) = event? {
                match this_event.status {
                    PipelineStatus::Validating => {}
                    PipelineStatus::Rejected(reason) => {
                        return Err(reason).wrap_err("Transaction rejected")
                    }
                    PipelineStatus::Committed => return Ok(hash.transmute()),
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
    ///
    /// # Errors
    /// Fails if transaction check fails
    pub fn prepare_transaction_request<B: RequestBuilder>(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(
        B,
        HashOf<VersionedSignedTransaction>,
        TransactionResponseHandler,
    )> {
        transaction.check_limits(&self.transaction_limits)?;
        let transaction: VersionedSignedTransaction = transaction.into();
        let hash = transaction.hash();
        let transaction_bytes: Vec<u8> = transaction.encode_versioned();

        Ok((
            B::new(
                HttpMethod::POST,
                format!("{}/{}", &self.torii_url, uri::TRANSACTION),
            )
            .headers(self.headers.clone())
            .body(transaction_bytes),
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
        &self,
        instruction: impl Into<Instruction>,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        self.submit_all_blocking(vec![instruction.into()])
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_blocking(
        &self,
        instructions: impl IntoIterator<Item = Instruction>,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        self.submit_all_blocking_with_metadata(instructions, UnlimitedMetadata::new())
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_blocking_with_metadata(
        &self,
        instruction: impl Into<Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        self.submit_all_blocking_with_metadata(vec![instruction.into()], metadata)
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Allows to specify [`Metadata`] of [`Transaction`].
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_blocking_with_metadata(
        &self,
        instructions: impl IntoIterator<Item = Instruction>,
        metadata: UnlimitedMetadata,
    ) -> Result<HashOf<VersionedSignedTransaction>> {
        let transaction = self.build_transaction(instructions.into(), metadata)?;
        self.submit_transaction_blocking(transaction)
    }

    /// Lower-level Query API entry point. Prepares an http-request and returns it with an http-response handler.
    ///
    /// # Errors
    /// Fails if query signing fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use eyre::Result;
    /// use iroha_client::{
    ///     client::{Client, ResponseHandler},
    ///     http::{RequestBuilder, Response, Method},
    /// };
    /// use iroha_data_model::{predicate::PredicateBox, prelude::{Account, FindAllAccounts, Pagination}};
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
    ///     Ok(accounts.only_output())
    /// }
    /// ```
    pub fn prepare_query_request<R, B>(
        &self,
        request: R,
        pagination: Pagination,
        sorting: Sorting,
        filter: PredicateBox,
    ) -> Result<(B, QueryResponseHandler<R>)>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
        B: RequestBuilder,
    {
        let pagination: Vec<_> = pagination.into();
        let sorting: Vec<_> = sorting.into();
        let request = QueryRequest::new(request.into(), self.account_id.clone(), filter);
        let request: VersionedSignedQueryRequest = self.sign_query(request)?.into();

        Ok((
            B::new(
                HttpMethod::POST,
                format!("{}/{}", &self.torii_url, uri::QUERY),
            )
            .params(pagination)
            .params(sorting)
            .headers(self.headers.clone())
            .body(request.encode_versioned()),
            QueryResponseHandler::default(),
        ))
    }

    /// Create a request with pagination, sorting and add the filter.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn request_with_pagination_and_filter_and_sorting<R>(
        &self,
        request: R,
        pagination: Pagination,
        sorting: Sorting,
        filter: PredicateBox,
    ) -> QueryHandlerResult<ClientQueryOutput<R>>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>, // Seems redundant
    {
        iroha_logger::trace!(?request, %pagination, ?sorting, ?filter);
        let (req, resp_handler) = self.prepare_query_request::<R, DefaultRequestBuilder>(
            request, pagination, sorting, filter,
        )?;
        let response = req.build()?.send()?;
        resp_handler.handle(response)
    }

    /// Create a request with pagination and sorting.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn request_with_pagination_and_sorting<R>(
        &self,
        request: R,
        pagination: Pagination,
        sorting: Sorting,
    ) -> QueryHandlerResult<ClientQueryOutput<R>>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.request_with_pagination_and_filter_and_sorting(
            request,
            pagination,
            sorting,
            PredicateBox::default(),
        )
    }

    /// Create a request with pagination, sorting, and the given filter.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn request_with_pagination_and_filter<R>(
        &self,
        request: R,
        pagination: Pagination,
        filter: PredicateBox,
    ) -> QueryHandlerResult<ClientQueryOutput<R>>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>, // Seems redundant
    {
        self.request_with_pagination_and_filter_and_sorting(
            request,
            pagination,
            Sorting::default(),
            filter,
        )
    }

    /// Query API entry point. Requests queries from `Iroha` peers with pagination.
    ///
    /// Uses default blocking http-client. If you need some custom integration, look at
    /// [`Self::prepare_query_request`].
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn request_with_pagination<R>(
        &self,
        request: R,
        pagination: Pagination,
    ) -> QueryHandlerResult<ClientQueryOutput<R>>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.request_with_pagination_and_filter(request, pagination, PredicateBox::default())
    }

    /// Query API entry point. Requests queries from `Iroha` peers with sorting.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn request_with_sorting<R>(
        &self,
        request: R,
        sorting: Sorting,
    ) -> QueryHandlerResult<ClientQueryOutput<R>>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.request_with_pagination_and_sorting(request, Pagination::default(), sorting)
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn request<R>(&self, request: R) -> QueryHandlerResult<R::Output>
    where
        R: Query + Into<QueryBox> + Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.request_with_pagination(request, Pagination::default())
            .map(ClientQueryOutput::only_output)
    }

    /// Connect (through `WebSocket`) to listen for `Iroha` `pipeline` and `data` events.
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`events_api::EventIterator::new`]
    pub fn listen_for_events(
        &self,
        event_filter: FilterBox,
    ) -> Result<impl Iterator<Item = Result<Event>>> {
        iroha_logger::trace!(?event_filter);
        events_api::EventIterator::new(self.events_handler(event_filter)?)
    }

    /// Connect asynchronously (through `WebSocket`) to listen for `Iroha` `pipeline` and `data` events.
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`events_api::AsyncEventStream::new`]
    pub async fn listen_for_events_async(
        &self,
        event_filter: FilterBox,
    ) -> Result<AsyncEventStream> {
        iroha_logger::trace!(?event_filter, "Async listening with");
        events_api::AsyncEventStream::new(self.events_handler(event_filter)?).await
    }

    /// Constructs an Events API handler. With it, you can use any WS client you want.
    ///
    /// # Errors
    /// Fails if handler construction fails
    #[inline]
    pub fn events_handler(&self, event_filter: FilterBox) -> Result<events_api::flow::Init> {
        events_api::flow::Init::new(
            event_filter,
            self.headers.clone(),
            &format!("{}/{}", &self.torii_url, uri::SUBSCRIPTION),
        )
    }

    /// Connect (through `WebSocket`) to listen for `Iroha` blocks
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`blocks_api::BlockIterator::new`]
    pub fn listen_for_blocks(
        &self,
        height: u64,
    ) -> Result<impl Iterator<Item = Result<VersionedCommittedBlock>>> {
        blocks_api::BlockIterator::new(self.blocks_handler(height)?)
    }

    /// Connect asynchronously (through `WebSocket`) to listen for `Iroha` blocks
    ///
    /// # Errors
    /// - Forwards from [`Self::events_handler`]
    /// - Forwards from [`blocks_api::BlockIterator::new`]
    pub async fn listen_for_blocks_async(&self, height: u64) -> Result<AsyncBlockStream> {
        blocks_api::AsyncBlockStream::new(self.blocks_handler(height)?).await
    }

    /// Construct a handler for Blocks API. With this handler you can use any WS client you want.
    ///
    /// # Errors
    /// Fails if handler construction fails
    #[inline]
    pub fn blocks_handler(&self, height: u64) -> Result<blocks_api::flow::Init> {
        blocks_api::flow::Init::new(
            height,
            self.headers.clone(),
            &format!("{}/{}", &self.torii_url, uri::BLOCKS_STREAM),
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
        transaction: &SignedTransaction,
        retry_count: u32,
        retry_in: Duration,
        pagination: Pagination,
    ) -> Result<Option<SignedTransaction>> {
        let pagination: Vec<_> = pagination.into();
        for _ in 0..retry_count {
            let response = DefaultRequestBuilder::new(
                HttpMethod::GET,
                format!("{}/{}", &self.torii_url, uri::PENDING_TRANSACTIONS),
            )
            .params(pagination.clone())
            .headers(self.headers.clone())
            .build()?
            .send()?;

            if response.status() == StatusCode::OK {
                let pending_transactions =
                    try_decode_all_or_just_decode!(VersionedPendingTransactions, response.body())?;
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
        transaction: &SignedTransaction,
        retry_count: u32,
        retry_in: Duration,
    ) -> Result<Option<SignedTransaction>> {
        self.get_original_transaction_with_pagination(
            transaction,
            retry_count,
            retry_in,
            Pagination::default(),
        )
    }

    fn get_config<T: DeserializeOwned>(&self, get_config: &GetConfiguration) -> Result<T> {
        let resp = DefaultRequestBuilder::new(
            HttpMethod::GET,
            format!("{}/{}", &self.torii_url, uri::CONFIGURATION),
        )
        .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
        .body(serde_json::to_vec(get_config).wrap_err("Failed to serialize")?)
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
    pub fn set_config(&self, post_config: PostConfiguration) -> Result<bool> {
        let body = serde_json::to_vec(&post_config)
            .wrap_err(format!("Failed to serialize {:?}", post_config))?;
        let url = &format!("{}/{}", self.torii_url, uri::CONFIGURATION);
        let resp = DefaultRequestBuilder::new(HttpMethod::POST, url)
            .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
            .body(body)
            .build()?
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
    ///
    /// # Errors
    /// Fails if sending request or decoding fails
    pub fn get_status(&self) -> Result<Status> {
        let (req, resp_handler) = self.prepare_status_request::<DefaultRequestBuilder>();
        let resp = req.build()?.send()?;
        resp_handler.handle(resp)
    }

    /// Prepares http-request to implement [`Self::get_status`] on your own.
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

/// Logic for `sync` and `async` Iroha websocket streams
pub mod stream_api {
    use futures_util::{FutureExt, SinkExt, Stream, StreamExt};

    use super::*;
    use crate::{
        http::ws::conn_flow::{EventData, Events, Handshake, Init, InitData},
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
        ) -> Result<SyncIterator<<I::Next as Handshake>::Next>> {
            trace!("Creating `SyncIterator`");
            let InitData {
                first_message,
                req,
                next: handler,
            } = Init::<http_default::DefaultWebSocketRequestBuilder>::init(handler);

            let mut stream = req.build()?.connect()?;
            stream.write_message(WebSocketMessage::Binary(first_message))?;

            let handler = loop {
                let mes = stream.read_message();
                trace!(?mes, "Received message");
                match mes {
                    Ok(WebSocketMessage::Binary(message)) => break handler.message(message)?,
                    Ok(_) => continue,
                    Err(WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed) => {
                        return Err(eyre!("WebSocket connection closed."))
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            trace!("`SyncIterator` created successfully");
            Ok(SyncIterator { stream, handler })
        }
    }

    impl<E: Events> Iterator for SyncIterator<E> {
        type Item = Result<E::Event>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.stream.read_message() {
                    Ok(WebSocketMessage::Binary(message)) => {
                        return Some(self.handler.message(message).and_then(
                            |EventData { reply, event }| {
                                self.stream
                                    .write_message(WebSocketMessage::Binary(reply))
                                    .map(|_| event)
                                    .wrap_err("Failed to reply")
                            },
                        ));
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
                let mes = self.stream.read_message()?;
                if !mes.is_close() {
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
        pub async fn new<I>(handler: I) -> Result<AsyncStream<<I::Next as Handshake>::Next>>
        where
            I: Init<DefaultWebSocketRequestBuilder> + Send,
            I::Next: Send,
            <I::Next as Handshake>::Next: Send,
        {
            trace!("Creating `AsyncStream`");
            let InitData {
                first_message,
                req,
                next: handler,
            } = Init::<http_default::DefaultWebSocketRequestBuilder>::init(handler);

            let mut stream = req.build()?.connect_async().await?;
            stream.send(WebSocketMessage::Binary(first_message)).await?;

            let handler = loop {
                let mes = stream
                    .next()
                    .await
                    .ok_or(eyre!("Expect to receive message"))?;
                trace!(?mes, "Received message");
                match mes {
                    Ok(WebSocketMessage::Binary(message)) => break handler.message(message)?,
                    Ok(_) => continue,
                    Err(err) => return Err(err.into()),
                }
            };
            trace!("`AsyncStream` created successfully");
            Ok(AsyncStream { stream, handler })
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
                if let Some(mes) = self.stream.next().await {
                    if !mes?.is_close() {
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
                    match self.handler.message(message) {
                        Ok(EventData { event, reply }) => {
                            let mut send = self.stream.send(WebSocketMessage::Binary(reply));
                            let result = futures_util::ready!(send.poll_unpin(cx))
                                .map(|_| event)
                                .wrap_err("Failed to reply");
                            std::task::Poll::Ready(Some(result))
                        }
                        Err(err) => std::task::Poll::Ready(Some(Err(err))),
                    }
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
        conn_flow::{
            EventData, Events as FlowEvents, Handshake as FlowHandshake, Init as FlowInit, InitData,
        },
        transform_ws_url,
    };

    /// Events API flow. For documentation and usage examples, refer to [`crate::http::ws::conn_flow`].
    pub mod flow {
        use super::*;

        /// Initialization struct for Events API flow.
        pub struct Init {
            /// Event filter
            filter: FilterBox,
            /// HTTP request headers
            headers: HashMap<String, String>,
            /// TORII URL
            url: String,
        }

        impl Init {
            /// Construct new item with provided filter, headers and url.
            ///
            /// # Errors
            /// Fails if [`transform_ws_url`] fails.
            #[inline]
            pub(in super::super) fn new(
                filter: FilterBox,
                headers: HashMap<String, String>,
                url: impl AsRef<str>,
            ) -> Result<Self> {
                Ok(Self {
                    filter,
                    headers,
                    url: transform_ws_url(url.as_ref())?,
                })
            }
        }

        impl<R: RequestBuilder> FlowInit<R> for Init {
            type Next = Handshake;

            fn init(self) -> InitData<R, Self::Next> {
                let Self {
                    filter,
                    headers,
                    url,
                } = self;

                let msg =
                    VersionedEventSubscriberMessage::from(EventSubscriberMessage::from(filter))
                        .encode_versioned();

                InitData::new(
                    R::new(HttpMethod::GET, url).headers(headers),
                    msg,
                    Handshake,
                )
            }
        }

        /// Handshake handler for Events API flow
        #[derive(Copy, Clone)]
        pub struct Handshake;

        impl FlowHandshake for Handshake {
            type Next = Events;

            fn message(self, message: Vec<u8>) -> Result<Self::Next>
            where
                Self::Next: FlowEvents,
            {
                if let EventPublisherMessage::SubscriptionAccepted =
                    try_decode_all_or_just_decode!(VersionedEventPublisherMessage, &message)?
                        .into_v1()
                {
                    Ok(Events)
                } else {
                    Err(eyre!("Expected `SubscriptionAccepted`."))
                }
            }
        }

        /// Events handler for Events API flow
        #[derive(Debug, Copy, Clone)]
        pub struct Events;

        impl FlowEvents for Events {
            type Event = iroha_data_model::prelude::Event;

            fn message(&self, message: Vec<u8>) -> Result<EventData<Self::Event>> {
                let event_socket_message =
                    try_decode_all_or_just_decode!(VersionedEventPublisherMessage, &message)?
                        .into_v1();
                let event = match event_socket_message {
                    EventPublisherMessage::Event(event) => event,
                    msg => return Err(eyre!("Expected Event but got {:?}", msg)),
                };
                let versioned_message =
                    VersionedEventSubscriberMessage::from(EventSubscriberMessage::EventReceived)
                        .encode_versioned();

                Ok(EventData::new(event, versioned_message))
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
        conn_flow::{
            EventData, Events as FlowEvents, Handshake as FlowHandshake, Init as FlowInit, InitData,
        },
        transform_ws_url,
    };

    /// Blocks API flow. For documentation and usage examples, refer to [`crate::http::ws::conn_flow`].
    pub mod flow {
        use iroha_core::block::stream::{
            BlockPublisherMessage, BlockSubscriberMessage, VersionedBlockPublisherMessage,
            VersionedBlockSubscriberMessage,
        };

        use super::*;

        /// Initialization struct for Blocks API flow.
        pub struct Init {
            /// Block height from which to start streaming blocks
            height: u64,
            /// HTTP request headers
            headers: HashMap<String, String>,
            /// TORII URL
            url: String,
        }

        impl Init {
            /// Construct new item with provided headers and url.
            ///
            /// # Errors
            /// If [`transform_ws_url`] fails.
            #[inline]
            pub(in super::super) fn new(
                height: u64,
                headers: HashMap<String, String>,
                url: impl AsRef<str>,
            ) -> Result<Self> {
                Ok(Self {
                    height,
                    headers,
                    url: transform_ws_url(url.as_ref())?,
                })
            }
        }

        impl<R: RequestBuilder> FlowInit<R> for Init {
            type Next = Handshake;

            fn init(self) -> InitData<R, Self::Next> {
                let Self {
                    height,
                    headers,
                    url,
                } = self;

                let msg =
                    VersionedBlockSubscriberMessage::from(BlockSubscriberMessage::from(height))
                        .encode_versioned();

                InitData::new(
                    R::new(HttpMethod::GET, url).headers(headers),
                    msg,
                    Handshake,
                )
            }
        }

        //// Handshake handler for Blocks API flow
        #[derive(Copy, Clone)]
        pub struct Handshake;

        impl FlowHandshake for Handshake {
            type Next = Events;

            fn message(self, message: Vec<u8>) -> Result<Self::Next>
            where
                Self::Next: FlowEvents,
            {
                if let BlockPublisherMessage::SubscriptionAccepted =
                    try_decode_all_or_just_decode!(VersionedBlockPublisherMessage, &message)?
                        .into_v1()
                {
                    Ok(Events)
                } else {
                    Err(eyre!("Expected `SubscriptionAccepted`."))
                }
            }
        }

        /// Events handler for Blocks API flow
        #[derive(Debug, Copy, Clone)]
        pub struct Events;

        impl FlowEvents for Events {
            type Event = iroha_core::prelude::VersionedCommittedBlock;

            fn message(&self, message: Vec<u8>) -> Result<EventData<Self::Event>> {
                let block_socket_message =
                    try_decode_all_or_just_decode!(VersionedBlockPublisherMessage, &message)?
                        .into_v1();
                let block = match block_socket_message {
                    BlockPublisherMessage::Block(block) => block,
                    msg => return Err(eyre!("Expected Event but got {:?}", msg)),
                };
                let versioned_message =
                    VersionedBlockSubscriberMessage::from(BlockSubscriberMessage::BlockReceived)
                        .encode_versioned();

                Ok(EventData::new(block, versioned_message))
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
        FindAllAccounts::new()
    }

    /// Construct a query to get account by id
    pub fn by_id(account_id: impl Into<EvaluatesTo<AccountId>>) -> FindAccountById {
        FindAccountById::new(account_id)
    }

    /// Construct a query to get all accounts containing specified asset
    pub fn all_with_asset(
        asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>,
    ) -> FindAccountsWithAsset {
        FindAccountsWithAsset::new(asset_definition_id)
    }
}

pub mod asset {
    //! Module with queries for assets
    use super::*;

    /// Construct a query to get all assets
    pub const fn all() -> FindAllAssets {
        FindAllAssets::new()
    }

    /// Construct a query to get all asset definitions
    pub const fn all_definitions() -> FindAllAssetsDefinitions {
        FindAllAssetsDefinitions::new()
    }

    /// Construct a query to get asset definition by its id
    pub fn definition_by_id(
        asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>,
    ) -> FindAssetDefinitionById {
        FindAssetDefinitionById::new(asset_definition_id)
    }

    /// Construct a query to get all assets by account id
    pub fn by_account_id(account_id: impl Into<EvaluatesTo<AccountId>>) -> FindAssetsByAccountId {
        FindAssetsByAccountId::new(account_id)
    }

    /// Construct a query to get an asset by its id
    pub fn by_id(asset_id: impl Into<EvaluatesTo<<Asset as Identifiable>::Id>>) -> FindAssetById {
        FindAssetById::new(asset_id)
    }
}

pub mod block {
    //! Module with queries related to blocks
    use iroha_crypto::Hash;

    use super::*;

    /// Construct a query to find all blocks
    pub const fn all() -> FindAllBlocks {
        FindAllBlocks::new()
    }

    /// Construct a query to find all block headers
    pub const fn all_headers() -> FindAllBlockHeaders {
        FindAllBlockHeaders::new()
    }

    /// Construct a query to find block header by hash
    pub fn header_by_hash(hash: impl Into<EvaluatesTo<Hash>>) -> FindBlockHeaderByHash {
        FindBlockHeaderByHash::new(hash)
    }
}

pub mod domain {
    //! Module with queries for domains
    use super::*;

    /// Construct a query to get all domains
    pub const fn all() -> FindAllDomains {
        FindAllDomains::new()
    }

    /// Construct a query to get all domain by id
    pub fn by_id(domain_id: impl Into<EvaluatesTo<DomainId>>) -> FindDomainById {
        FindDomainById::new(domain_id)
    }
}

pub mod transaction {
    //! Module with queries for transactions
    use iroha_crypto::Hash;

    use super::*;

    /// Construct a query to find all transactions
    pub fn all() -> FindAllTransactions {
        FindAllTransactions::new()
    }

    /// Construct a query to retrieve transactions for account
    pub fn by_account_id(
        account_id: impl Into<EvaluatesTo<AccountId>>,
    ) -> FindTransactionsByAccountId {
        FindTransactionsByAccountId::new(account_id)
    }

    /// Construct a query to retrieve transaction by hash
    pub fn by_hash(hash: impl Into<EvaluatesTo<Hash>>) -> FindTransactionByHash {
        FindTransactionByHash::new(hash)
    }
}

pub mod trigger {
    //! Module with queries for triggers
    use super::*;

    /// Construct a query to get triggers by domain id
    pub fn by_domain_id(domain_id: impl Into<EvaluatesTo<DomainId>>) -> FindTriggersByDomainId {
        FindTriggersByDomainId::new(domain_id)
    }
}

pub mod permissions {
    //! Module with queries for permission tokens
    use super::*;

    /// Construct a query to get all registered [`PermissionTokenDefinition`]s
    pub const fn all_definitions() -> FindAllPermissionTokenDefinitions {
        FindAllPermissionTokenDefinitions {}
    }

    /// Construct a query to get all [`PermissionToken`] granted
    /// to account with given [`Id`][AccountId]
    pub fn by_account_id(
        account_id: impl Into<EvaluatesTo<AccountId>>,
    ) -> FindPermissionTokensByAccountId {
        FindPermissionTokensByAccountId {
            id: account_id.into(),
        }
    }
}

pub mod role {
    //! Module with queries for roles
    use super::*;

    /// Construct a query to retrieve all roles
    pub const fn all() -> FindAllRoles {
        FindAllRoles::new()
    }

    /// Construct a query to retrieve all role ids
    pub const fn all_ids() -> FindAllRoleIds {
        FindAllRoleIds::new()
    }

    /// Construct a query to retrieve a role by its id
    pub fn by_id(role_id: impl Into<EvaluatesTo<RoleId>>) -> FindRoleByRoleId {
        FindRoleByRoleId::new(role_id)
    }

    /// Construct a query to retrieve all roles for an account
    pub fn by_account_id(account_id: impl Into<EvaluatesTo<AccountId>>) -> FindRolesByAccountId {
        FindRolesByAccountId::new(account_id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    use std::str::FromStr;

    use iroha_config::{
        client::{BasicAuth, ConfigurationProxy, WebLogin},
        torii::{uri::DEFAULT_API_URL, DEFAULT_TORII_TELEMETRY_URL},
    };

    use super::*;

    const LOGIN: &str = "mad_hatter";
    const PASSWORD: &str = "ilovetea";
    // `mad_hatter:ilovetea` encoded with base64
    const ENCRYPTED_CREDENTIALS: &str = "bWFkX2hhdHRlcjppbG92ZXRlYQ==";

    #[test]
    fn txs_same_except_for_nonce_have_different_hashes() {
        let (public_key, private_key) = KeyPair::generate().unwrap().into();

        let cfg = ConfigurationProxy {
            public_key: Some(public_key),
            private_key: Some(private_key),
            account_id: Some(
                "alice@wonderland"
                    .parse()
                    .expect("This account ID should be valid"),
            ),
            torii_api_url: Some(SmallStr::from_str(DEFAULT_API_URL)),
            torii_telemetry_url: Some(SmallStr::from_str(DEFAULT_TORII_TELEMETRY_URL)),
            add_transaction_nonce: Some(true),
            ..ConfigurationProxy::default()
        }
        .build()
        .expect("Client config should build as all required fields were provided");
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

        let cfg = ConfigurationProxy {
            public_key: Some(
                "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"
                    .parse()
                    .expect("Public key not in mulithash format"),
            ),
            private_key: Some(iroha_crypto::PrivateKey::from_hex(
            iroha_crypto::Algorithm::Ed25519,
            "9ac47abf59b356e0bd7dcbbbb4dec080e302156a48ca907e47cb6aea1d32719e7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"
            ).expect("Private key not hex encoded")),
            account_id: Some(
                "alice@wonderland"
                    .parse()
                    .expect("This account ID should be valid"),
            ),
            torii_api_url: Some(SmallStr::from_str(DEFAULT_API_URL)),
            torii_telemetry_url: Some(SmallStr::from_str(DEFAULT_TORII_TELEMETRY_URL)),
            basic_auth: Some(Some(basic_auth)),
            ..ConfigurationProxy::default()
        }
        .build()
        .expect("Client config should build as all required fields were provided");
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

        use super::*;

        #[test]
        fn certain_errors() -> Result<()> {
            let sut = QueryResponseHandler::<FindAllAssets>::default();
            let responses = vec![
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
                let resp = Response::builder().status(status_code).body(err.encode())?;

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
