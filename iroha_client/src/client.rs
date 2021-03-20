use crate::{
    config::Configuration,
    http_client::{self, StatusCode, WebSocketError, WebSocketMessage},
};
use http_client::WebSocketStream;
use iroha_crypto::{Hash, KeyPair};
use iroha_derive::log;
use iroha_dsl::prelude::*;
use iroha_error::{error, Error, Result, WrapErr};
use iroha_version::prelude::*;
use std::{
    convert::TryInto,
    fmt::{self, Debug, Formatter},
    sync::mpsc,
    thread,
    time::Duration,
};

/// Iroha client
#[derive(Clone)]
pub struct Client {
    torii_url: String,
    max_instruction_number: usize,
    key_pair: KeyPair,
    proposed_transaction_ttl_ms: u64,
    transaction_status_timout: Duration,
    account_id: AccountId,
}

/// Representation of `Iroha` client.
impl Client {
    /// Constructor for client
    pub fn new(configuration: &Configuration) -> Self {
        Client {
            torii_url: configuration.torii_api_url.clone(),
            max_instruction_number: configuration.max_instruction_number,
            key_pair: KeyPair {
                public_key: configuration.public_key.clone(),
                private_key: configuration.private_key.clone(),
            },
            proposed_transaction_ttl_ms: configuration.transaction_time_to_live_ms,
            transaction_status_timout: Duration::from_millis(
                configuration.transaction_status_timeout_ms,
            ),
            account_id: configuration.account_id.clone(),
        }
    }

    /// Builds transaction out of supplied instructions.
    ///
    /// # Errors
    /// Fails if signing transaction fails
    pub fn build_transaction(&self, instructions: Vec<Instruction>) -> Result<Transaction> {
        Transaction::new(
            instructions,
            self.account_id.clone(),
            self.proposed_transaction_ttl_ms,
        )
        .sign(&self.key_pair)
    }

    /// Signs transaction
    ///
    /// # Errors
    /// Fails if generating signature fails
    pub fn sign_transaction(&self, transaction: Transaction) -> Result<Transaction> {
        transaction.sign(&self.key_pair)
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    #[log]
    pub fn submit(&mut self, instruction: Instruction) -> Result<Hash> {
        self.submit_all(vec![instruction])
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all(&mut self, instructions: Vec<Instruction>) -> Result<Hash> {
        self.submit_transaction(self.build_transaction(instructions)?)
    }

    /// Submit a prebuilt transaction.
    /// Returns submitted transaction's hash or error string.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_transaction(&mut self, transaction: Transaction) -> Result<Hash> {
        transaction.check_instruction_len(self.max_instruction_number)?;
        let hash = transaction.hash();
        let transaction: VersionedTransaction = transaction.into();
        let transaction: Vec<u8> = transaction.encode_versioned()?;
        let response = http_client::post(
            &format!("http://{}{}", self.torii_url, uri::INSTRUCTIONS_URI),
            transaction.clone(),
        )
        .wrap_err_with(|| format!("Failed to send transaction: {:?}", &transaction))?;
        if response.status() == StatusCode::OK {
            Ok(hash)
        } else {
            Err(error!(
                "Failed to submit instructions with HTTP status: {}",
                response.status()
            ))
        }
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_blocking(&mut self, instruction: Instruction) -> Result<Hash> {
        self.submit_all_blocking(vec![instruction])
    }

    /// Submits and waits until the transaction is either rejected or committed.
    /// Returns rejection reason if transaction was rejected.
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit_all_blocking(&mut self, instructions: Vec<Instruction>) -> Result<Hash> {
        let mut client = self.clone();
        let (sender, receiver) = mpsc::channel();
        let transaction = self.build_transaction(instructions)?;
        let hash = transaction.hash();
        let _ = thread::spawn(move || {
            for event in client
                .listen_for_events(PipelineEventFilter::by_hash(hash).into())
                .expect("Failed to initialize iterator.")
            {
                if let Ok(Event::Pipeline(event)) = event {
                    match event.status {
                        PipelineStatus::Validating => {}
                        PipelineStatus::Rejected(reason) => sender
                            .send(Err(reason))
                            .expect("Failed to send through channel."),
                        PipelineStatus::Committed => sender
                            .send(Ok(hash))
                            .expect("Failed to send through channel."),
                    }
                }
            }
        });
        let _ = self.submit_transaction(transaction)?;
        receiver
            .recv_timeout(self.transaction_status_timout)
            .map_or_else(
                |err| Err(err).wrap_err("Timeout waiting for transaction status"),
                |result| Ok(result?),
            )
    }

    /// Query API entry point. Requests queries from `Iroha` peers with pagination.
    ///
    /// # Errors
    /// Fails if sending request fails
    #[log]
    pub fn request_with_pagination(
        &mut self,
        request: &QueryRequest,
        pagination: Pagination,
    ) -> Result<QueryResult> {
        let pagination: Vec<_> = pagination.into();
        let request: VersionedSignedQueryRequest = request.clone().sign(&self.key_pair)?.into();
        let response = http_client::get(
            &format!("http://{}{}", self.torii_url, uri::QUERY_URI),
            request.encode_versioned()?,
            pagination,
        )?;
        if response.status() == StatusCode::OK {
            response.body().clone().try_into().map_err(Error::msg)
        } else {
            Err(error!(
                "Failed to make query request with HTTP status: {}",
                response.status()
            ))
        }
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    ///
    /// # Errors
    /// Fails if sending request fails
    #[log]
    pub fn request(&mut self, request: &QueryRequest) -> Result<QueryResult> {
        self.request_with_pagination(request, Pagination::default())
    }

    /// Connects through `WebSocket` to listen for `Iroha` pipeline and data events.
    ///
    /// # Errors
    /// Fails if subscribing to websocket fails
    pub fn listen_for_events(&mut self, event_filter: EventFilter) -> Result<EventIterator> {
        EventIterator::new(
            &format!("ws://{}{}", self.torii_url, uri::SUBSCRIPTION_URI),
            event_filter,
        )
    }

    /// Tries to find the original transaction in the pending tx queue on the leader peer.
    /// Should be used for an MST case.
    /// Takes pagination as parameter.
    ///
    /// # Errors
    /// Fails if subscribing to websocket fails
    pub fn get_original_transaction_with_pagination(
        &mut self,
        transaction: &Transaction,
        retry_count: u32,
        retry_in: Duration,
        pagination: Pagination,
    ) -> Result<Option<Transaction>> {
        let pagination: Vec<_> = pagination.into();
        for _ in 0..retry_count {
            let response = http_client::get(
                &format!(
                    "http://{}{}",
                    self.torii_url,
                    uri::PENDING_TRANSACTIONS_ON_LEADER_URI
                ),
                Vec::new(),
                pagination.clone(),
            )?;
            if response.status() == StatusCode::OK {
                let pending_transactions: PendingTransactions =
                    VersionedPendingTransactions::decode_versioned(response.body())?
                        .into_v1()
                        .ok_or_else(|| error!("Expected pending transaction message version 1."))?
                        .into();
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
                thread::sleep(retry_in)
            } else {
                return Err(error!(
                    "Failed to make query request with HTTP status: {}",
                    response.status()
                ));
            }
        }
        Ok(None)
    }

    /// Tries to find the original transaction in the pending tx queue on the leader peer.
    /// Should be used for an MST case.
    ///
    /// # Errors
    /// Fails if sending request fails
    pub fn get_original_transaction(
        &mut self,
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
    pub fn new(url: &str, event_filter: EventFilter) -> Result<EventIterator> {
        let mut stream = http_client::web_socket_connect(url)?;
        stream.write_message(WebSocketMessage::Text(
            VersionedSubscriptionRequest::from(SubscriptionRequest(event_filter))
                .to_versioned_json_str()?,
        ))?;
        Ok(EventIterator { stream })
    }
}

impl Iterator for EventIterator {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.stream.read_message() {
                Ok(WebSocketMessage::Text(message)) => {
                    match VersionedEvent::from_versioned_json_str(&message) {
                        Ok(event) => {
                            let event: Event =
                                event.into_v1().expect("Expected event version 1.").into();
                            return match self.stream.write_message(WebSocketMessage::Text(
                                VersionedEventReceived::from(EventReceived)
                                    .to_versioned_json_str()
                                    .expect("Failed to serialize receipt."),
                            )) {
                                Ok(_) => Some(Ok(event)),
                                Err(err) => Some(Err(error!("Failed to send receipt: {}", err))),
                            };
                        }
                        Err(err) => return Some(Err(err.into())),
                    }
                }
                Ok(_) => continue,
                Err(WebSocketError::ConnectionClosed) | Err(WebSocketError::AlreadyClosed) => {
                    return None
                }
                Err(err) => return Some(Err(err.into())),
            }
        }
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("public_key", &self.key_pair.public_key)
            .field("torii_url", &self.torii_url)
            .finish()
    }
}

pub mod account {
    //! Module with queries for account
    use super::*;

    /// Get query to get all accounts
    pub fn all() -> QueryRequest {
        QueryRequest::new(FindAllAccounts::new().into())
    }

    /// Get query to get account by id
    pub fn by_id(account_id: impl Into<EvaluatesTo<AccountId>>) -> QueryRequest {
        QueryRequest::new(FindAccountById::new(account_id).into())
    }
}

pub mod asset {
    //! Module with queries for assets
    use super::*;

    /// Get query to get all assets
    pub fn all() -> QueryRequest {
        QueryRequest::new(FindAllAssets::new().into())
    }

    /// Get query to get all asset definitions
    pub fn all_definitions() -> QueryRequest {
        QueryRequest::new(FindAllAssetsDefinitions::new().into())
    }

    /// Get query to get all assets by account id
    pub fn by_account_id(
        account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>,
    ) -> QueryRequest {
        QueryRequest::new(FindAssetsByAccountId::new(account_id).into())
    }

    /// Get query to get all assets by account id and definition id
    pub fn by_account_id_and_definition_id(
        account_id: impl Into<EvaluatesTo<AccountId>>,
        asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>,
    ) -> QueryRequest {
        QueryRequest::new(
            FindAssetsByAccountIdAndAssetDefinitionId::new(account_id, asset_definition_id).into(),
        )
    }
}

pub mod domain {
    //! Module with queries for domains
    use super::*;

    /// Get query to get all domains
    pub fn all() -> QueryRequest {
        QueryRequest::new(FindAllDomains::new().into())
    }

    /// Get query to get all domain by name
    pub fn by_name(domain_name: impl Into<EvaluatesTo<String>>) -> QueryRequest {
        QueryRequest::new(FindDomainByName::new(domain_name).into())
    }
}

/// URI that `Client` uses to route outgoing requests.
//TODO: remove duplication with `iroha::torii::uri`.
pub mod uri {
    //! Module with uri constants

    /// Query URI is used to handle incoming Query requests.
    pub const QUERY_URI: &str = "/query";
    /// Instructions URI is used to handle incoming ISI requests.
    pub const INSTRUCTIONS_URI: &str = "/instruction";
    /// Block URI is used to handle incoming Block requests.
    pub const CONSENSUS_URI: &str = "/consensus";
    /// Health URI is used to handle incoming Healthcheck requests.
    pub const HEALTH_URI: &str = "/health";
    /// Metrics URI is used to export metrics according to [Prometheus
    /// Guidance](https://prometheus.io/docs/instrumenting/writing_exporters/).
    pub const METRICS_URI: &str = "/metrics";
    /// The URI used for block synchronization.
    pub const BLOCK_SYNC_URI: &str = "/block";
    /// The web socket uri used to subscribe to pipeline and data events.
    pub const SUBSCRIPTION_URI: &str = "/events";
    /// Get pending transactions on leader.
    pub const PENDING_TRANSACTIONS_ON_LEADER_URI: &str = "/pending_transactions_on_leader";
}
