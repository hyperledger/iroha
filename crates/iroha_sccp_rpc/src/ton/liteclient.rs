//! TON `liteServer.*` query client (spec §4.13.3, §7.1, §7.2 step 3, §8).
//!
//! [`LiteClient`] is a blocking liteclient over ADNL-TCP ([`super::adnl`])
//! bound to one [`LiteServerSet`]. It serves the queries SCCP needs:
//! masterchain info, block lookup, block proofs (key-block hops and back
//! links), blocks, single transactions, transaction history for discovery,
//! get-methods and `sendMessage`, plus block headers, shard-block proofs,
//! config parameters, account states and the server time for the evidence
//! builders. Answers come back as typed values whose proofs and blocks are raw
//! bag-of-cells bytes, or as the raw TL answer ([`LiteClient::query_raw`]) for
//! journaling. Nothing here verifies them:
//! `iroha_sccp` does, so a lying liteserver can only cause rejected
//! submissions. The typed calls only reject answers that do not echo the
//! request (another block than the one asked for), because such an answer is
//! useless whatever its proofs say.
//!
//! The client keeps one ADNL session open to the liteserver that answered
//! last. Each query starts there and walks the list round-robin; a server that
//! cannot be reached, fails the handshake, times out, breaks framing, sends an
//! undecodable or mismatched answer, sends an answer above the query's cap
//! ([`LiteQuery::max_answer_bytes`]), or answers `liteServer.error` with a
//! [`LITE_SERVER_FAILOVER_CODES`](super::schema::LITE_SERVER_FAILOVER_CODES)
//! code hands the query to the next one. Other `liteServer.error` codes are
//! answers about the query and are returned at once, and the next query
//! starts at the next liteserver. After a fully failed round the next one
//! starts after the [`FailoverPolicy`] backoff. A session idle for
//! [`LiteClientConfig::keepalive_interval`] is probed with `tcp.ping` before
//! reuse and replaced when the probe fails.
//!
//! Every connect, probe and query has one wall-clock deadline: its timeout
//! from its start, or the caller's [`PollBudget`] deadline when that comes
//! first. The keeper's list starts at a seeded index
//! ([`LiteClient::from_keeper_config`]).

use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use iroha_config::parameters::{actual::SccpLightClientKeeper, defaults};

use super::{
    adnl::{AdnlConnection, AdnlError, DEFAULT_MAX_PACKET_BYTES},
    peers::{LiteServer, LiteServerSet, PeerError},
    schema::{
        AccountId, AccountState, AnswerError, BlockData, BlockHeader, BlockId, BlockIdExt,
        ConfigInfo, CurrentTime, LiteAnswer, LiteQuery, LiteServerError, LookupKey,
        MasterchainInfo, PartialBlockProof, RunMethodResult, SendMsgStatus, ShardBlockProof,
        TransactionInfo, TransactionList, WaitMasterchainSeqno, wrap_query,
    },
};
use crate::endpoints::{
    FailoverPolicy, PollBudget, Sleeper, ThreadSleeper, attempt_deadline, within_budget,
};

/// Default idle time after which a session is probed with `tcp.ping` before
/// reuse.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Transport limits of one [`LiteClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiteClientConfig {
    /// Total wall-clock time of connecting and the ADNL handshake (and of a
    /// keep-alive probe) before failing over.
    pub connect_timeout: Duration,
    /// Total wall-clock time of one query on one liteserver, answer included,
    /// before failing over.
    pub request_timeout: Duration,
    /// Idle time after which a session is probed before reuse.
    pub keepalive_interval: Duration,
    /// Largest accepted ADNL packet; each query's answer cap
    /// ([`LiteQuery::max_answer_bytes`]) is clipped to it.
    pub max_packet_bytes: usize,
}

impl LiteClientConfig {
    /// Limits for the in-node keeper: its `request_timeout` for connecting and
    /// for each query, and the default keep-alive and packet bounds.
    pub fn from_keeper_config(keeper: &SccpLightClientKeeper) -> Self {
        Self {
            connect_timeout: keeper.request_timeout,
            request_timeout: keeper.request_timeout,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            max_packet_bytes: DEFAULT_MAX_PACKET_BYTES,
        }
    }

    /// The same limits with another packet bound.
    #[must_use]
    pub fn with_max_packet_bytes(mut self, max_packet_bytes: usize) -> Self {
        self.max_packet_bytes = max_packet_bytes;
        self
    }
}

impl Default for LiteClientConfig {
    fn default() -> Self {
        let timeout =
            Duration::from_millis(defaults::sccp::light_client_keeper::REQUEST_TIMEOUT_MS);
        Self {
            connect_timeout: timeout,
            request_timeout: timeout,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            max_packet_bytes: DEFAULT_MAX_PACKET_BYTES,
        }
    }
}

/// What an ADNL error interrupted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Connecting and the handshake.
    Connect,
    /// A keep-alive probe of an idle session.
    KeepAlive,
    /// A query.
    Query,
}

impl Stage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::KeepAlive => "keep-alive",
            Self::Query => "query",
        }
    }
}

/// Why a liteclient request failed.
///
/// Liteservers are named `ip:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiteClientError {
    /// The liteserver list is invalid.
    Peers(PeerError),
    /// A caller argument is outside what the request accepts.
    InvalidRequest(String),
    /// Connecting, the handshake, framing or the session failed.
    Adnl {
        /// The liteserver.
        server: String,
        /// What was interrupted.
        stage: Stage,
        /// The ADNL error.
        error: AdnlError,
    },
    /// The liteserver answered `liteServer.error`.
    LiteServer {
        /// The liteserver.
        server: String,
        /// The error answer.
        error: LiteServerError,
    },
    /// The answer is not the expected TL, or does not echo the request.
    InvalidResponse {
        /// The liteserver.
        server: String,
        /// What is wrong.
        detail: String,
    },
    /// Every attempt of every round failed with a failover error.
    Exhausted {
        /// Each failed attempt, in order.
        failures: Vec<LiteAttemptFailure>,
    },
    /// The caller's [`PollBudget`] ran out before an attempt answered.
    BudgetExhausted {
        /// Each failed attempt, in order.
        failures: Vec<LiteAttemptFailure>,
    },
}

impl LiteClientError {
    /// Whether this error moves the query to the next liteserver: every ADNL
    /// failure, every invalid answer, and `liteServer.error` codes of
    /// [`LITE_SERVER_FAILOVER_CODES`](super::schema::LITE_SERVER_FAILOVER_CODES).
    pub fn is_failover(&self) -> bool {
        match self {
            Self::Adnl { .. } | Self::InvalidResponse { .. } => true,
            Self::LiteServer { error, .. } => error.is_failover(),
            Self::Peers(_)
            | Self::InvalidRequest(_)
            | Self::Exhausted { .. }
            | Self::BudgetExhausted { .. } => false,
        }
    }

    /// Whether this answer is a reason to start the next query at another
    /// liteserver: a `liteServer.error` that answers the query (failover
    /// errors move on anyway). The answer itself is still returned.
    pub fn discredits_server(&self) -> bool {
        matches!(self, Self::LiteServer { error, .. } if !error.is_failover())
    }

    /// Whether the session that produced this error must be dropped (its
    /// cipher streams may be out of step).
    fn breaks_session(&self) -> bool {
        matches!(self, Self::Adnl { .. })
    }

    /// The last attempt's error for [`Self::Exhausted`] and
    /// [`Self::BudgetExhausted`], otherwise `self`.
    pub fn last_failure(&self) -> &Self {
        match self {
            Self::Exhausted { failures } | Self::BudgetExhausted { failures } => {
                failures.last().map_or(self, |last| &last.error)
            }
            _ => self,
        }
    }

    /// The `liteServer.error` answer, if this is one (also as the last failure
    /// of [`Self::Exhausted`]).
    pub fn lite_server_error(&self) -> Option<&LiteServerError> {
        match self.last_failure() {
            Self::LiteServer { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for LiteClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peers(error) => write!(formatter, "invalid TON liteserver list: {error}"),
            Self::InvalidRequest(detail) => write!(formatter, "invalid liteserver query: {detail}"),
            Self::Adnl {
                server,
                stage,
                error,
            } => write!(formatter, "{server}: {} failed: {error}", stage.as_str()),
            Self::LiteServer { server, error } => write!(formatter, "{server}: {error}"),
            Self::InvalidResponse { server, detail } => {
                write!(formatter, "{server}: invalid answer: {detail}")
            }
            Self::Exhausted { failures } => {
                write!(
                    formatter,
                    "every TON liteserver failed ({} attempts)",
                    failures.len()
                )?;
                if let Some(last) = failures.last() {
                    write!(formatter, "; last: {last}")?;
                }
                Ok(())
            }
            Self::BudgetExhausted { failures } => {
                write!(
                    formatter,
                    "the poll budget ran out after {} failed liteserver attempt(s)",
                    failures.len()
                )?;
                if let Some(last) = failures.last() {
                    write!(formatter, "; last: {last}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LiteClientError {}

impl From<PeerError> for LiteClientError {
    fn from(error: PeerError) -> Self {
        Self::Peers(error)
    }
}

/// One failed attempt of a query that failed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteAttemptFailure {
    /// The liteserver that failed.
    pub server: String,
    /// Zero-based failover round.
    pub round: u32,
    /// The failover error.
    pub error: LiteClientError,
}

impl fmt::Display for LiteAttemptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "round {}: {}", self.round, self.error)
    }
}

/// The open session.
struct Session {
    index: usize,
    connection: AdnlConnection,
}

/// A blocking liteclient with failover across a [`LiteServerSet`].
pub struct LiteClient {
    servers: LiteServerSet,
    config: LiteClientConfig,
    policy: FailoverPolicy,
    sleeper: Arc<dyn Sleeper>,
    budget: PollBudget,
    session: Mutex<Option<Session>>,
}

impl fmt::Debug for LiteClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiteClient")
            .field("servers", &self.servers)
            .field("config", &self.config)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl LiteClient {
    /// A client over `servers`, without a poll budget. Queries start at the
    /// list's preferred liteserver (the first one, unless the list was
    /// seeded).
    pub fn new(servers: LiteServerSet, config: LiteClientConfig, policy: FailoverPolicy) -> Self {
        Self {
            servers,
            config,
            policy,
            sleeper: Arc::new(ThreadSleeper),
            budget: PollBudget::new(),
            session: Mutex::new(None),
        }
    }

    /// The in-node keeper's client: its liteserver list and limits. `seed`
    /// seeds both the backoff jitter and the starting liteserver, so
    /// validators sharing the compiled list start at different liteservers.
    ///
    /// # Errors
    /// If the configured list is invalid.
    pub fn from_keeper_config(
        keeper: &SccpLightClientKeeper,
        seed: u64,
    ) -> Result<Self, LiteClientError> {
        Ok(Self::new(
            LiteServerSet::from_keeper_config(keeper)?.with_seeded_start(seed),
            LiteClientConfig::from_keeper_config(keeper),
            FailoverPolicy::with_seed(seed),
        ))
    }

    /// Replaces the sleeper used between failover rounds.
    #[must_use]
    pub fn with_sleeper(mut self, sleeper: Arc<dyn Sleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Bounds every query by `budget` (see [`PollBudget`]).
    #[must_use]
    pub fn with_budget(mut self, budget: PollBudget) -> Self {
        self.budget = budget;
        self
    }

    /// The poll budget.
    pub fn budget(&self) -> &PollBudget {
        &self.budget
    }

    /// Moves the next query to the liteserver after the one that answered
    /// last, for callers whose verification rejected that liteserver's data.
    /// `TonBuilder::rotate_endpoints` calls it, and the keeper does so after a
    /// build that failed.
    // TODO(WP9): the keeper does not observe on-chain rejections of its
    // submitted advances, and the wallet and CLI do not rotate after a local
    // verification failure yet.
    pub fn rotate_preferred(&self) {
        self.servers.rotate_preferred();
    }

    /// The liteserver list.
    pub fn servers(&self) -> &LiteServerSet {
        &self.servers
    }

    /// The transport limits.
    pub fn config(&self) -> &LiteClientConfig {
        &self.config
    }

    /// Closes the open session, if any.
    pub fn disconnect(&self) {
        *self.lock_session() = None;
    }

    /// Whether a session is open.
    pub fn is_connected(&self) -> bool {
        self.lock_session().is_some()
    }

    /// Probes the open session with `tcp.ping` if it has been idle for
    /// [`LiteClientConfig::keepalive_interval`]; returns whether a probe was
    /// sent. A failed probe closes the session.
    ///
    /// # Errors
    /// The probe's failure.
    pub fn keep_alive(&self) -> Result<bool, LiteClientError> {
        let mut slot = self.lock_session();
        let Some(session) = slot.as_mut() else {
            return Ok(false);
        };
        if session.connection.idle_for() < self.config.keepalive_interval {
            return Ok(false);
        }
        let deadline = self.deadline(self.config.connect_timeout);
        match session.connection.ping(deadline) {
            Ok(()) => Ok(true),
            Err(error) => {
                let server = self.servers.servers()[session.index].label().to_owned();
                *slot = None;
                Err(LiteClientError::Adnl {
                    server,
                    stage: Stage::KeepAlive,
                    error,
                })
            }
        }
    }

    /// Sends `query` (behind `liteServer.waitMasterchainSeqno` when `wait` is
    /// given) and returns the raw TL answer, which is never a
    /// `liteServer.error`.
    ///
    /// # Errors
    /// An invalid request, a non-failover `liteServer.error`, or
    /// [`LiteClientError::Exhausted`].
    pub fn query_raw(
        &self,
        query: &LiteQuery,
        wait: Option<WaitMasterchainSeqno>,
    ) -> Result<Vec<u8>, LiteClientError> {
        let wrapped = wrapped(query, wait)?;
        let cap = query.max_answer_bytes();
        self.run(|connection, server| self.exchange(connection, server, &wrapped, cap))
    }

    /// Sends `query` and decodes the answer as `T`, without checking that it
    /// echoes the request.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; an answer that is not a `T` fails over.
    pub fn query<T: LiteAnswer>(
        &self,
        query: &LiteQuery,
        wait: Option<WaitMasterchainSeqno>,
    ) -> Result<T, LiteClientError> {
        self.typed(query, wait, |_: &T| Ok(()))
    }

    /// `liteServer.getMasterchainInfo`.
    ///
    /// # Errors
    /// As [`Self::query_raw`].
    pub fn get_masterchain_info(&self) -> Result<MasterchainInfo, LiteClientError> {
        self.typed(
            &LiteQuery::GetMasterchainInfo,
            None,
            |info: &MasterchainInfo| {
                ensure(
                    info.last.is_masterchain(),
                    "the last block is not a masterchain block",
                )
            },
        )
    }

    /// `liteServer.lookupBlock`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; an answer from another workchain (or with
    /// another sequence number for [`LookupKey::Seqno`]) fails over.
    pub fn lookup_block(
        &self,
        id: BlockId,
        key: LookupKey,
    ) -> Result<BlockHeader, LiteClientError> {
        self.typed(
            &LiteQuery::LookupBlock { id, key },
            None,
            |header: &BlockHeader| {
                ensure(
                    header.id.workchain == id.workchain
                        && (key != LookupKey::Seqno || header.id.seqno == id.seqno),
                    "the block does not match the lookup",
                )
            },
        )
    }

    /// `liteServer.getBlockHeader`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; a header of another block fails over.
    pub fn get_block_header(
        &self,
        id: BlockIdExt,
        mode: u32,
    ) -> Result<BlockHeader, LiteClientError> {
        self.typed(
            &LiteQuery::GetBlockHeader { id, mode },
            None,
            |header: &BlockHeader| ensure(header.id == id, "the header is of another block"),
        )
    }

    /// `liteServer.getBlockProof` from the trusted masterchain block `known`
    /// to `target` (the server's last block when `None`). A partial answer
    /// (`complete == false`) is continued by asking again from its `to`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; a proof that starts elsewhere, or a complete
    /// proof that ends elsewhere, fails over.
    pub fn get_block_proof(
        &self,
        known: BlockIdExt,
        target: Option<BlockIdExt>,
    ) -> Result<PartialBlockProof, LiteClientError> {
        self.typed(
            &LiteQuery::GetBlockProof { known, target },
            None,
            |proof: &PartialBlockProof| {
                ensure(proof.from == known, "the proof starts at another block")?;
                ensure(
                    !proof.complete || target.is_none_or(|target| proof.to == target),
                    "the complete proof ends at another block",
                )
            },
        )
    }

    /// `liteServer.getBlock`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; another block fails over.
    pub fn get_block(&self, id: BlockIdExt) -> Result<BlockData, LiteClientError> {
        self.typed(&LiteQuery::GetBlock { id }, None, |block: &BlockData| {
            ensure(block.id == id, "the data is of another block")
        })
    }

    /// `liteServer.getOneTransaction`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; a transaction of another block fails over.
    pub fn get_one_transaction(
        &self,
        id: BlockIdExt,
        account: AccountId,
        lt: u64,
    ) -> Result<TransactionInfo, LiteClientError> {
        self.typed(
            &LiteQuery::GetOneTransaction { id, account, lt },
            None,
            |info: &TransactionInfo| ensure(info.id == id, "the transaction is of another block"),
        )
    }

    /// `liteServer.getTransactions`: up to `count` transactions of `account`,
    /// newest first, starting at the transaction `(lt, hash)`. Used to
    /// discover the block of a burn.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; more blocks than requested fail over.
    pub fn get_transactions(
        &self,
        count: u32,
        account: AccountId,
        lt: u64,
        hash: [u8; 32],
    ) -> Result<TransactionList, LiteClientError> {
        self.typed(
            &LiteQuery::GetTransactions {
                count,
                account,
                lt,
                hash,
            },
            None,
            |list: &TransactionList| {
                ensure(
                    u32::try_from(list.ids.len()).is_ok_and(|len| len <= count),
                    "more transactions than requested",
                )
            },
        )
    }

    /// `liteServer.runSmcMethod` against masterchain block `id`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; a result for another block fails over.
    pub fn run_smc_method(
        &self,
        mode: u32,
        id: BlockIdExt,
        account: AccountId,
        method_id: u64,
        params: Vec<u8>,
    ) -> Result<RunMethodResult, LiteClientError> {
        self.typed(
            &LiteQuery::RunSmcMethod {
                mode,
                id,
                account,
                method_id,
                params,
            },
            None,
            |result: &RunMethodResult| ensure(result.id == id, "the result is of another block"),
        )
    }

    /// `liteServer.sendMessage` of an external message `BoC`. A timed-out
    /// attempt is retried on the next liteserver; external messages carry
    /// their own replay protection.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; a rejected message is a
    /// [`LiteClientError::LiteServer`] answer.
    pub fn send_message(&self, body: Vec<u8>) -> Result<SendMsgStatus, LiteClientError> {
        self.query(&LiteQuery::SendMessage { body }, None)
    }

    /// `liteServer.getShardBlockProof` of a shard block.
    ///
    /// # Errors
    /// As [`Self::query_raw`].
    pub fn get_shard_block_proof(
        &self,
        id: BlockIdExt,
    ) -> Result<ShardBlockProof, LiteClientError> {
        self.query(&LiteQuery::GetShardBlockProof { id }, None)
    }

    /// `liteServer.getConfigParams` at masterchain block `id`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; parameters of another block fail over.
    pub fn get_config_params(
        &self,
        mode: u32,
        id: BlockIdExt,
        params: Vec<i32>,
    ) -> Result<ConfigInfo, LiteClientError> {
        self.typed(
            &LiteQuery::GetConfigParams { mode, id, params },
            None,
            |info: &ConfigInfo| ensure(info.id == id, "the parameters are of another block"),
        )
    }

    /// `liteServer.getAccountState` at masterchain block `id`.
    ///
    /// # Errors
    /// As [`Self::query_raw`]; a state at another block fails over.
    pub fn get_account_state(
        &self,
        id: BlockIdExt,
        account: AccountId,
    ) -> Result<AccountState, LiteClientError> {
        self.typed(
            &LiteQuery::GetAccountState { id, account },
            None,
            |state: &AccountState| ensure(state.id == id, "the state is at another block"),
        )
    }

    /// `liteServer.getTime`.
    ///
    /// # Errors
    /// As [`Self::query_raw`].
    pub fn get_time(&self) -> Result<CurrentTime, LiteClientError> {
        self.query(&LiteQuery::GetTime, None)
    }

    fn typed<T: LiteAnswer>(
        &self,
        query: &LiteQuery,
        wait: Option<WaitMasterchainSeqno>,
        check: impl Fn(&T) -> Result<(), String>,
    ) -> Result<T, LiteClientError> {
        let wrapped = wrapped(query, wait)?;
        let cap = query.max_answer_bytes();
        self.run(|connection, server| {
            let answer = self.exchange(connection, server, &wrapped, cap)?;
            let invalid = |detail: String| LiteClientError::InvalidResponse {
                server: server.label().to_owned(),
                detail,
            };
            let value = T::decode_answer(&answer).map_err(|error| match error {
                AnswerError::LiteServer(error) => LiteClientError::LiteServer {
                    server: server.label().to_owned(),
                    error,
                },
                AnswerError::Malformed(error) => invalid(error.to_string()),
            })?;
            check(&value).map_err(invalid)?;
            Ok(value)
        })
    }

    /// The deadline of an operation of at most `timeout` starting now,
    /// clipped to the poll budget.
    fn deadline(&self, timeout: Duration) -> Instant {
        attempt_deadline(Instant::now(), timeout, self.budget.deadline())
    }

    /// One query on one session, with an answer of at most `cap` bytes: the
    /// raw answer, or its `liteServer.error`.
    fn exchange(
        &self,
        connection: &mut AdnlConnection,
        server: &LiteServer,
        wrapped: &[u8],
        cap: usize,
    ) -> Result<Vec<u8>, LiteClientError> {
        let deadline = self.deadline(self.config.request_timeout);
        let answer = connection
            .query_bounded(wrapped, deadline, cap)
            .map_err(|error| LiteClientError::Adnl {
                server: server.label().to_owned(),
                stage: Stage::Query,
                error,
            })?;
        if let Some(error) = LiteServerError::from_answer(&answer) {
            return Err(LiteClientError::LiteServer {
                server: server.label().to_owned(),
                error,
            });
        }
        Ok(answer)
    }

    fn lock_session(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `attempt` with failover (see the module documentation).
    fn run<T>(
        &self,
        mut attempt: impl FnMut(&mut AdnlConnection, &LiteServer) -> Result<T, LiteClientError>,
    ) -> Result<T, LiteClientError> {
        let mut slot = self.lock_session();
        let count = self.servers.len();
        let mut failures = Vec::new();
        let budget = self.budget.deadline();
        for round in 0..self.policy.rounds.get() {
            if round > 0 {
                let delay = self.policy.round_delay(round - 1, None);
                if !within_budget(budget, Instant::now().checked_add(delay)) {
                    return Err(LiteClientError::BudgetExhausted { failures });
                }
                self.sleeper.sleep(delay);
            }
            let start = self.servers.preferred();
            for offset in 0..count {
                if !within_budget(budget, Some(Instant::now())) {
                    return Err(LiteClientError::BudgetExhausted { failures });
                }
                let index = (start + offset) % count;
                let server = &self.servers.servers()[index];
                let result = self
                    .session(&mut slot, index)
                    .and_then(|connection| attempt(connection, server));
                match result {
                    Ok(value) => {
                        self.servers.set_preferred(index);
                        return Ok(value);
                    }
                    Err(error) => {
                        if error.breaks_session() {
                            *slot = None;
                        }
                        if !error.is_failover() {
                            if error.discredits_server() {
                                self.servers.set_preferred((index + 1) % count);
                            }
                            return Err(error);
                        }
                        failures.push(LiteAttemptFailure {
                            server: server.label().to_owned(),
                            round,
                            error,
                        });
                    }
                }
            }
        }
        Err(LiteClientError::Exhausted { failures })
    }

    /// The session with liteserver `index`: the open one (probed first when
    /// idle), or a new one.
    fn session<'s>(
        &self,
        slot: &'s mut Option<Session>,
        index: usize,
    ) -> Result<&'s mut AdnlConnection, LiteClientError> {
        let mut current = slot.take().filter(|session| session.index == index);
        if let Some(session) = current.as_mut() {
            let deadline = self.deadline(self.config.connect_timeout);
            if session.connection.idle_for() >= self.config.keepalive_interval
                && session.connection.ping(deadline).is_err()
            {
                current = None;
            }
        }
        let session = match current {
            Some(session) => session,
            None => Session {
                index,
                connection: self.connect(index)?,
            },
        };
        Ok(&mut slot.insert(session).connection)
    }

    /// A new session with liteserver `index`.
    fn connect(&self, index: usize) -> Result<AdnlConnection, LiteClientError> {
        let server = &self.servers.servers()[index];
        let deadline = self.deadline(self.config.connect_timeout);
        AdnlConnection::connect(
            server.address(),
            server.public_key(),
            deadline,
            self.config.max_packet_bytes,
        )
        .map_err(|error| LiteClientError::Adnl {
            server: server.label().to_owned(),
            stage: Stage::Connect,
            error,
        })
    }
}

/// The `liteServer.query` of a request.
fn wrapped(
    query: &LiteQuery,
    wait: Option<WaitMasterchainSeqno>,
) -> Result<Vec<u8>, LiteClientError> {
    let request = query.encode().map_err(LiteClientError::InvalidRequest)?;
    wrap_query(&request, wait).map_err(|error| LiteClientError::InvalidRequest(error.to_string()))
}

fn ensure(condition: bool, detail: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(detail.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use crate::{endpoints::Backoff, ton::schema::SHARD_FULL};

    const KEY: &str = "n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=";

    #[derive(Default)]
    struct CountingSleeper(Mutex<Vec<Duration>>);

    impl Sleeper for CountingSleeper {
        fn sleep(&self, duration: Duration) {
            self.0.lock().expect("lock").push(duration);
        }
    }

    /// Distinct loopback ports nothing listens on (bound together, then
    /// released).
    fn closed_ports(count: usize) -> Vec<u16> {
        let listeners: Vec<TcpListener> = (0..count)
            .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind"))
            .collect();
        listeners
            .iter()
            .map(|listener| listener.local_addr().expect("address").port())
            .collect()
    }

    fn policy(rounds: u32) -> FailoverPolicy {
        FailoverPolicy::new(
            std::num::NonZeroU32::new(rounds).expect("nonzero"),
            Backoff::new(Duration::from_millis(1), Duration::from_millis(4), 3),
        )
    }

    #[test]
    fn keeper_config_sets_timeouts_and_defaults() {
        let keeper = SccpLightClientKeeper::default();
        let config = LiteClientConfig::from_keeper_config(&keeper);
        assert_eq!(config.request_timeout, keeper.request_timeout);
        assert_eq!(config.connect_timeout, keeper.request_timeout);
        assert_eq!(config, LiteClientConfig::default());
        assert_eq!(config.with_max_packet_bytes(1).max_packet_bytes, 1);
        let client = LiteClient::from_keeper_config(&keeper, 7).expect("client");
        assert_eq!(
            client.servers().len(),
            defaults::sccp::endpoints::TON_LITESERVERS.len()
        );
        assert_eq!(
            client.servers().preferred(),
            crate::endpoints::start_index(7, client.servers().len()),
            "the keeper's list starts at the seeded index"
        );
        assert_eq!(client.budget().deadline(), None);
        let budget = PollBudget::new();
        let client = client.with_budget(budget.clone());
        let _guard = budget.start(Duration::from_secs(1));
        assert!(client.budget().deadline().is_some());
        let before = client.servers().preferred();
        client.rotate_preferred();
        assert_eq!(
            client.servers().preferred(),
            (before + 1) % client.servers().len()
        );
        assert_eq!(client.config(), &config);
        assert!(!client.is_connected());
        assert!(format!("{client:?}").contains("LiteClient"));
    }

    #[test]
    fn failover_errors_are_classified() {
        let adnl = LiteClientError::Adnl {
            server: "s".to_owned(),
            stage: Stage::Query,
            error: AdnlError::Timeout,
        };
        assert!(adnl.is_failover());
        assert!(adnl.breaks_session());
        let not_ready = LiteClientError::LiteServer {
            server: "s".to_owned(),
            error: LiteServerError {
                code: 651,
                message: "not in db".to_owned(),
            },
        };
        assert!(not_ready.is_failover());
        assert!(!not_ready.breaks_session());
        let rejected = LiteClientError::LiteServer {
            server: "s".to_owned(),
            error: LiteServerError {
                code: 0,
                message: "cannot apply external message".to_owned(),
            },
        };
        assert!(!rejected.is_failover());
        assert!(rejected.discredits_server());
        assert!(
            !not_ready.discredits_server(),
            "failover errors move on anyway"
        );
        assert!(!adnl.discredits_server());
        assert_eq!(
            rejected.lite_server_error().map(|error| error.code),
            Some(0)
        );
        let invalid = LiteClientError::InvalidResponse {
            server: "s".to_owned(),
            detail: "x".to_owned(),
        };
        assert!(invalid.is_failover());
        assert!(!LiteClientError::InvalidRequest("x".to_owned()).is_failover());
        let exhausted = LiteClientError::Exhausted {
            failures: vec![LiteAttemptFailure {
                server: "s".to_owned(),
                round: 0,
                error: not_ready.clone(),
            }],
        };
        assert!(!exhausted.is_failover());
        assert_eq!(exhausted.last_failure(), &not_ready);
        assert_eq!(
            exhausted.lite_server_error().map(|error| error.code),
            Some(651)
        );
        assert!(exhausted.to_string().contains("last: round 0"));
        let spent = LiteClientError::BudgetExhausted {
            failures: vec![LiteAttemptFailure {
                server: "s".to_owned(),
                round: 0,
                error: not_ready.clone(),
            }],
        };
        assert!(!spent.is_failover());
        assert!(!spent.discredits_server());
        assert_eq!(spent.last_failure(), &not_ready);
        assert!(spent.to_string().contains("poll budget"));
        for error in [
            adnl,
            not_ready,
            rejected,
            invalid,
            exhausted,
            LiteClientError::Peers(LiteServerSet::parse(&[]).expect_err("empty")),
            LiteClientError::InvalidRequest("x".to_owned()),
            LiteClientError::Exhausted {
                failures: Vec::new(),
            },
        ] {
            assert!(!error.to_string().is_empty());
        }
        for stage in [Stage::Connect, Stage::KeepAlive, Stage::Query] {
            assert!(!stage.as_str().is_empty());
        }
    }

    #[test]
    fn unreachable_servers_exhaust_every_round() {
        let entries: Vec<String> = closed_ports(2)
            .into_iter()
            .map(|port| format!("127.0.0.1:{port}:{KEY}"))
            .collect();
        let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
        let servers = LiteServerSet::parse(&entries).expect("servers");
        let sleeper = Arc::new(CountingSleeper::default());
        let config = LiteClientConfig {
            connect_timeout: Duration::from_millis(500),
            ..LiteClientConfig::default()
        };
        let client = LiteClient::new(servers, config, policy(2)).with_sleeper(sleeper.clone());
        let error = client.get_time().expect_err("nothing listens");
        let LiteClientError::Exhausted { failures } = &error else {
            panic!("unexpected {error:?}");
        };
        assert_eq!(failures.len(), 4);
        assert!(failures.iter().all(|failure| matches!(
            failure.error,
            LiteClientError::Adnl {
                stage: Stage::Connect,
                ..
            }
        )));
        assert_eq!(failures[3].round, 1);
        assert_eq!(sleeper.0.lock().expect("lock").len(), 1);
        assert!(!client.is_connected());
        assert_eq!(client.keep_alive(), Ok(false));
        client.disconnect();
    }

    #[test]
    fn spent_budgets_stop_queries_before_connecting() {
        let entries: Vec<String> = closed_ports(2)
            .into_iter()
            .map(|port| format!("127.0.0.1:{port}:{KEY}"))
            .collect();
        let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
        let servers = LiteServerSet::parse(&entries).expect("servers");
        let budget = PollBudget::new();
        let client = LiteClient::new(servers, LiteClientConfig::default(), policy(3))
            .with_budget(budget.clone());
        budget.set_deadline(Some(Instant::now()));
        let error = client.get_time().expect_err("spent budget");
        assert!(
            matches!(&error, LiteClientError::BudgetExhausted { failures } if failures.is_empty()),
            "{error:?}"
        );
        assert!(!client.is_connected());
    }

    #[test]
    fn invalid_requests_are_refused_before_connecting() {
        let entry = format!("127.0.0.1:{}:{KEY}", closed_ports(1)[0]);
        let servers = LiteServerSet::parse(&[&entry]).expect("servers");
        let client = LiteClient::new(servers, LiteClientConfig::default(), policy(1));
        let shard = BlockIdExt {
            workchain: 0,
            shard: SHARD_FULL,
            seqno: 1,
            root_hash: [0; 32],
            file_hash: [0; 32],
        };
        let error = client
            .get_block_proof(shard, None)
            .expect_err("shard block");
        assert!(matches!(error, LiteClientError::InvalidRequest(_)));
        assert!(matches!(
            client.send_message(Vec::new()),
            Err(LiteClientError::InvalidRequest(_))
        ));
    }

    #[test]
    fn echo_checks_accept_matching_answers_only() {
        assert_eq!(ensure(true, "x"), Ok(()));
        assert_eq!(ensure(false, "x"), Err("x".to_owned()));
        assert!(wrapped(&LiteQuery::GetTime, None).is_ok());
        assert!(matches!(
            wrapped(&LiteQuery::SendMessage { body: Vec::new() }, None),
            Err(LiteClientError::InvalidRequest(_))
        ));
    }
}
