//! The `liteServer.*` TL schema subset used by SCCP (spec §4.13.3, §7.2).
//!
//! Requests ([`LiteQuery`]) serialize to the exact TL of `lite_api.tl`; the
//! liteclient wraps them in `liteServer.query` (optionally behind
//! `liteServer.waitMasterchainSeqno`) and `adnl.message.query`. Answers decode
//! into typed values whose proofs, blocks, transactions and states stay raw
//! bag-of-cells bytes: this module never parses a `BoC` and verifies nothing.
//! Proof verification belongs to `iroha_sccp` (the TON light client), which
//! consumes these bytes.
//!
//! Every answer is boxed. A `liteServer.error` in place of the expected
//! constructor decodes to [`LiteServerError`]; any other constructor, a
//! truncated value or trailing bytes is malformed.
//!
//! The ids follow the current upstream `lite_api.tl`. In particular the
//! signatures of a forward block link are a polymorphic
//! `liteServer.SignatureSet`: `liteServer.signatureSet.ordinary` (catchain
//! consensus, keeping the pre-simplex id `0xf644a6e6`) or
//! `liteServer.signatureSet.simplex` (simplex consensus, which TON mainnet runs;
//! it adds the session id, slot and signed candidate). Both decode into
//! [`SignatureSet`].

use std::fmt;

use super::tl::{TlError, TlErrorKind, TlReader, TlWriter};

/// Workchain id of the masterchain.
pub const MASTERCHAIN: i32 = -1;
/// Workchain id of the basechain.
pub const BASECHAIN: i32 = 0;
/// Shard id of an unsplit workchain (the masterchain is never split).
pub const SHARD_FULL: u64 = 0x8000_0000_0000_0000;
/// Most transactions one `liteServer.getTransactions` returns.
pub const MAX_TRANSACTIONS_PER_QUERY: u32 = 16;
/// Largest vector accepted in an answer.
const MAX_ANSWER_VECTOR: usize = 1 << 16;
/// Bytes of a `tonNode.blockIdExt`.
const BLOCK_ID_EXT_BYTES: usize = 80;
/// `runSmcMethod` mode bits the schema defines (proofs, state proof, result,
/// `init_c7`, `lib_extras`).
pub const RUN_SMC_METHOD_MODE_MASK: u32 = 0x1F;
/// Most config parameters one `liteServer.getConfigParams` requests.
pub const MAX_CONFIG_PARAMS_PER_QUERY: usize = 256;
/// Answer cap of small queries (masterchain info, time, lookups, headers,
/// `sendMessage` status): recorded answers are under 1 KiB.
pub const SMALL_ANSWER_BYTES: usize = 256 * 1024;
/// Answer cap of queries that carry proofs, states or transactions: recorded
/// answers are tens of KiB.
pub const PROOF_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// Answer cap of `getBlockProof`: a chain of key-block hops of about 40 KiB
/// each.
pub const BLOCK_PROOF_ANSWER_BYTES: usize = 8 * 1024 * 1024;
/// Answer cap of `getBlock`: a whole block bag of cells (TON's hard block
/// limit is a few MiB).
pub const BLOCK_ANSWER_BYTES: usize = 16 * 1024 * 1024;

/// Constructor ids of `lite_api.tl`.
pub mod id {
    /// `liteServer.error code:int message:string = liteServer.Error`.
    pub const ERROR: u32 = 0xbba9_e148;
    /// `liteServer.query data:bytes = Object`.
    pub const QUERY: u32 = 0x798c_06df;
    /// `liteServer.waitMasterchainSeqno seqno:int timeout_ms:int = Object`.
    pub const WAIT_MASTERCHAIN_SEQNO: u32 = 0xbaea_b892;
    /// `liteServer.getMasterchainInfo = liteServer.MasterchainInfo`.
    pub const GET_MASTERCHAIN_INFO: u32 = 0x89b5_e62e;
    /// `liteServer.masterchainInfo last state_root_hash init`.
    pub const MASTERCHAIN_INFO: u32 = 0x8583_2881;
    /// `liteServer.lookupBlock mode id lt:mode.1?long utime:mode.2?int`.
    pub const LOOKUP_BLOCK: u32 = 0xfac8_f71e;
    /// `liteServer.getBlockHeader id mode`.
    pub const GET_BLOCK_HEADER: u32 = 0x21ec_069e;
    /// `liteServer.blockHeader id mode header_proof`.
    pub const BLOCK_HEADER: u32 = 0x752d_8219;
    /// `liteServer.getBlockProof mode known_block target_block:mode.0?`.
    pub const GET_BLOCK_PROOF: u32 = 0x8aea_9c44;
    /// `liteServer.partialBlockProof complete from to steps`.
    pub const PARTIAL_BLOCK_PROOF: u32 = 0x8ed0_d2c1;
    /// `liteServer.blockLinkBack`.
    pub const BLOCK_LINK_BACK: u32 = 0xef7e_1bef;
    /// `liteServer.blockLinkForward`.
    pub const BLOCK_LINK_FORWARD: u32 = 0x520f_ce1c;
    /// `liteServer.signatureSet.ordinary#f644a6e6` (catchain consensus; the
    /// explicit id is the pre-simplex `liteServer.signatureSet` constructor).
    pub const SIGNATURE_SET_ORDINARY: u32 = 0xf644_a6e6;
    /// `liteServer.signatureSet.simplex cc_seqno validator_set_hash signatures
    /// session_id slot candidate` (simplex consensus).
    pub const SIGNATURE_SET_SIMPLEX: u32 = 0xac24_9800;
    /// `liteServer.getBlock id`.
    pub const GET_BLOCK: u32 = 0x6377_cf0d;
    /// `liteServer.blockData id data`.
    pub const BLOCK_DATA: u32 = 0xa574_ed6c;
    /// `liteServer.getOneTransaction id account lt`.
    pub const GET_ONE_TRANSACTION: u32 = 0xd40f_24ea;
    /// `liteServer.transactionInfo id proof transaction`.
    pub const TRANSACTION_INFO: u32 = 0x0ede_ed47;
    /// `liteServer.getTransactions count account lt hash`.
    pub const GET_TRANSACTIONS: u32 = 0x1c40_e7a1;
    /// `liteServer.transactionList ids transactions`.
    pub const TRANSACTION_LIST: u32 = 0x6f26_c60b;
    /// `liteServer.runSmcMethod mode id account method_id params`.
    pub const RUN_SMC_METHOD: u32 = 0x5cc6_5dd2;
    /// `liteServer.runMethodResult`.
    pub const RUN_METHOD_RESULT: u32 = 0xa39a_616b;
    /// `liteServer.sendMessage body`.
    pub const SEND_MESSAGE: u32 = 0x690a_d482;
    /// `liteServer.sendMsgStatus status`.
    pub const SEND_MSG_STATUS: u32 = 0x3950_e597;
    /// `liteServer.getShardBlockProof id`.
    pub const GET_SHARD_BLOCK_PROOF: u32 = 0x4ca6_0350;
    /// `liteServer.shardBlockProof masterchain_id links`.
    pub const SHARD_BLOCK_PROOF: u32 = 0x1d62_a07a;
    /// `liteServer.getConfigParams mode id param_list`.
    pub const GET_CONFIG_PARAMS: u32 = 0x2a11_1c19;
    /// `liteServer.configInfo mode id state_proof config_proof`.
    pub const CONFIG_INFO: u32 = 0xae7b_272f;
    /// `liteServer.getAccountState id account`.
    pub const GET_ACCOUNT_STATE: u32 = 0x6b89_0e25;
    /// `liteServer.accountState id shardblk shard_proof proof state`.
    pub const ACCOUNT_STATE: u32 = 0x7079_c751;
    /// `liteServer.getTime = liteServer.CurrentTime`.
    pub const GET_TIME: u32 = 0x16ad_5a34;
    /// `liteServer.currentTime now`.
    pub const CURRENT_TIME: u32 = 0xe953_000d;
}

/// `liteServer.error` codes that mean "this liteserver cannot serve the query
/// now" rather than "the query is wrong": `651` not ready (the block or state
/// is not, or no longer, in this server's database), `652` timeout and `653`
/// cancelled. Another liteserver may have it, so these fail over.
pub const LITE_SERVER_FAILOVER_CODES: [i32; 3] = [651, 652, 653];

/// A `liteServer.error` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteServerError {
    /// Error code.
    pub code: i32,
    /// Sanitized, bounded message.
    pub message: String,
}

impl LiteServerError {
    /// Whether another liteserver may answer the same query
    /// ([`LITE_SERVER_FAILOVER_CODES`]).
    pub fn is_failover(&self) -> bool {
        LITE_SERVER_FAILOVER_CODES.contains(&self.code)
    }

    /// Decodes a raw answer if it is a `liteServer.error`.
    pub fn from_answer(answer: &[u8]) -> Option<Self> {
        let mut reader = TlReader::new(answer);
        reader
            .expect_constructor(id::ERROR, "liteServer.error")
            .ok()?;
        let error = Self::read_body(&mut reader).ok()?;
        reader.finish().ok()?;
        Some(error)
    }

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        let code = reader.i32()?;
        let message = reader.bytes()?;
        Ok(Self {
            code,
            message: crate::http::sanitize_message(&String::from_utf8_lossy(message)),
        })
    }
}

impl fmt::Display for LiteServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "liteServer.error {}: {}",
            self.code, self.message
        )
    }
}

impl std::error::Error for LiteServerError {}

/// Why an answer did not decode to the expected value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerError {
    /// The liteserver answered with `liteServer.error`.
    LiteServer(LiteServerError),
    /// The answer is not the expected TL.
    Malformed(TlError),
}

impl fmt::Display for AnswerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiteServer(error) => error.fmt(formatter),
            Self::Malformed(error) => write!(formatter, "malformed liteserver answer: {error}"),
        }
    }
}

impl std::error::Error for AnswerError {}

impl From<TlError> for AnswerError {
    fn from(error: TlError) -> Self {
        Self::Malformed(error)
    }
}

/// A boxed `liteServer.*` answer type.
pub trait LiteAnswer: Sized {
    /// The answer constructor.
    const CONSTRUCTOR: u32;
    /// The constructor name, for errors.
    const NAME: &'static str;

    /// Reads the fields after the constructor.
    ///
    /// # Errors
    /// If the fields are malformed.
    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError>;

    /// Decodes a whole raw answer.
    ///
    /// # Errors
    /// [`AnswerError::LiteServer`] for a `liteServer.error`,
    /// [`AnswerError::Malformed`] for anything but exactly one value of this
    /// type.
    fn decode_answer(answer: &[u8]) -> Result<Self, AnswerError> {
        let mut reader = TlReader::new(answer);
        let constructor = reader.u32()?;
        if constructor == id::ERROR {
            let error = LiteServerError::read_body(&mut reader)?;
            reader.finish()?;
            return Err(AnswerError::LiteServer(error));
        }
        if constructor != Self::CONSTRUCTOR {
            return Err(AnswerError::Malformed(TlError {
                offset: 0,
                kind: TlErrorKind::UnexpectedConstructor {
                    expected: Self::NAME,
                    found: constructor,
                },
            }));
        }
        let value = Self::read_body(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}

/// `tonNode.blockId workchain shard seqno`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId {
    /// Workchain id.
    pub workchain: i32,
    /// Shard id (prefix with a terminating one bit).
    pub shard: u64,
    /// Sequence number.
    pub seqno: u32,
}

impl BlockId {
    /// A masterchain block id.
    pub const fn masterchain(seqno: u32) -> Self {
        Self {
            workchain: MASTERCHAIN,
            shard: SHARD_FULL,
            seqno,
        }
    }

    fn write(&self, writer: &mut TlWriter) {
        writer.i32(self.workchain).u64(self.shard).u32(self.seqno);
    }
}

/// `tonNode.blockIdExt workchain shard seqno root_hash file_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockIdExt {
    /// Workchain id.
    pub workchain: i32,
    /// Shard id.
    pub shard: u64,
    /// Sequence number.
    pub seqno: u32,
    /// Representation hash of the block root cell.
    pub root_hash: [u8; 32],
    /// SHA-256 of the block file.
    pub file_hash: [u8; 32],
}

impl BlockIdExt {
    /// The short id.
    pub const fn id(&self) -> BlockId {
        BlockId {
            workchain: self.workchain,
            shard: self.shard,
            seqno: self.seqno,
        }
    }

    /// Whether the block is a masterchain block.
    pub const fn is_masterchain(&self) -> bool {
        self.workchain == MASTERCHAIN
    }

    fn write(&self, writer: &mut TlWriter) {
        self.id().write(writer);
        writer.int256(&self.root_hash).int256(&self.file_hash);
    }

    fn read(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            workchain: reader.i32()?,
            shard: reader.u64()?,
            seqno: reader.u32()?,
            root_hash: reader.int256()?,
            file_hash: reader.int256()?,
        })
    }
}

impl fmt::Display for BlockIdExt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "({},{:016x},{}):{}",
            self.workchain,
            self.shard,
            self.seqno,
            hex::encode_upper(self.root_hash)
        )
    }
}

/// `tonNode.zeroStateIdExt workchain root_hash file_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZeroStateIdExt {
    /// Workchain id.
    pub workchain: i32,
    /// Root hash of the zero state.
    pub root_hash: [u8; 32],
    /// File hash of the zero state.
    pub file_hash: [u8; 32],
}

/// `liteServer.accountId workchain id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId {
    /// Workchain id.
    pub workchain: i32,
    /// 256-bit account address.
    pub address: [u8; 32],
}

impl AccountId {
    fn write(&self, writer: &mut TlWriter) {
        writer.i32(self.workchain).int256(&self.address);
    }
}

/// How `liteServer.lookupBlock` finds a block of a shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupKey {
    /// By the sequence number of the given id (mode bit 0).
    Seqno,
    /// The block whose logical-time range contains `lt` (mode bit 1).
    Lt(u64),
    /// The block generated at or before `utime` (mode bit 2).
    Utime(u32),
}

impl LookupKey {
    /// The `mode` bit of this key.
    pub const fn mode(self) -> u32 {
        match self {
            Self::Seqno => 1,
            Self::Lt(_) => 2,
            Self::Utime(_) => 4,
        }
    }
}

/// `liteServer.waitMasterchainSeqno`: ask the liteserver to wait (up to
/// `timeout_ms`) until it knows masterchain block `seqno` before answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WaitMasterchainSeqno {
    /// Masterchain sequence number to wait for.
    pub seqno: u32,
    /// Longest wait, in milliseconds.
    pub timeout_ms: u32,
}

/// One `liteServer.*` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiteQuery {
    /// `liteServer.getMasterchainInfo`.
    GetMasterchainInfo,
    /// `liteServer.lookupBlock`.
    LookupBlock {
        /// The shard (and, for [`LookupKey::Seqno`], the sequence number).
        id: BlockId,
        /// What to look up by.
        key: LookupKey,
    },
    /// `liteServer.getBlockHeader`.
    GetBlockHeader {
        /// The block.
        id: BlockIdExt,
        /// Header proof mode bits.
        mode: u32,
    },
    /// `liteServer.getBlockProof`: a proof chain from a trusted masterchain
    /// block to a target (the server's last block when absent).
    GetBlockProof {
        /// The trusted masterchain block.
        known: BlockIdExt,
        /// The masterchain block to prove.
        target: Option<BlockIdExt>,
    },
    /// `liteServer.getBlock`.
    GetBlock {
        /// The block.
        id: BlockIdExt,
    },
    /// `liteServer.getOneTransaction`.
    GetOneTransaction {
        /// The block holding the transaction.
        id: BlockIdExt,
        /// The account.
        account: AccountId,
        /// Logical time of the transaction.
        lt: u64,
    },
    /// `liteServer.getTransactions`: up to `count` transactions of an
    /// account, newest first, starting at `(lt, hash)`.
    GetTransactions {
        /// Number of transactions (1..=16).
        count: u32,
        /// The account.
        account: AccountId,
        /// Logical time of the newest transaction.
        lt: u64,
        /// Hash of the newest transaction.
        hash: [u8; 32],
    },
    /// `liteServer.runSmcMethod`.
    RunSmcMethod {
        /// Result and proof mode bits ([`RUN_SMC_METHOD_MODE_MASK`]).
        mode: u32,
        /// A masterchain block.
        id: BlockIdExt,
        /// The contract.
        account: AccountId,
        /// Get-method id ([`method_id`]).
        method_id: u64,
        /// Serialized `VmStack` `BoC` of the arguments.
        params: Vec<u8>,
    },
    /// `liteServer.sendMessage`.
    SendMessage {
        /// External message `BoC`.
        body: Vec<u8>,
    },
    /// `liteServer.getShardBlockProof`: the links from a shard block to the
    /// masterchain block that registers it.
    GetShardBlockProof {
        /// The shard block.
        id: BlockIdExt,
    },
    /// `liteServer.getConfigParams`.
    GetConfigParams {
        /// Mode bits.
        mode: u32,
        /// A masterchain block.
        id: BlockIdExt,
        /// Config parameter numbers.
        params: Vec<i32>,
    },
    /// `liteServer.getAccountState`.
    GetAccountState {
        /// A masterchain block.
        id: BlockIdExt,
        /// The account.
        account: AccountId,
    },
    /// `liteServer.getTime`.
    GetTime,
}

impl LiteQuery {
    /// The schema name of the request.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::GetMasterchainInfo => "liteServer.getMasterchainInfo",
            Self::LookupBlock { .. } => "liteServer.lookupBlock",
            Self::GetBlockHeader { .. } => "liteServer.getBlockHeader",
            Self::GetBlockProof { .. } => "liteServer.getBlockProof",
            Self::GetBlock { .. } => "liteServer.getBlock",
            Self::GetOneTransaction { .. } => "liteServer.getOneTransaction",
            Self::GetTransactions { .. } => "liteServer.getTransactions",
            Self::RunSmcMethod { .. } => "liteServer.runSmcMethod",
            Self::SendMessage { .. } => "liteServer.sendMessage",
            Self::GetShardBlockProof { .. } => "liteServer.getShardBlockProof",
            Self::GetConfigParams { .. } => "liteServer.getConfigParams",
            Self::GetAccountState { .. } => "liteServer.getAccountState",
            Self::GetTime => "liteServer.getTime",
        }
    }

    /// The largest answer this query accepts, sized to the real answers with
    /// headroom; the liteclient clips it to its packet bound and refuses a
    /// larger answer unread (a failover error).
    pub const fn max_answer_bytes(&self) -> usize {
        match self {
            Self::GetMasterchainInfo
            | Self::LookupBlock { .. }
            | Self::GetBlockHeader { .. }
            | Self::SendMessage { .. }
            | Self::GetTime => SMALL_ANSWER_BYTES,
            Self::GetOneTransaction { .. }
            | Self::GetTransactions { .. }
            | Self::RunSmcMethod { .. }
            | Self::GetShardBlockProof { .. }
            | Self::GetConfigParams { .. }
            | Self::GetAccountState { .. } => PROOF_ANSWER_BYTES,
            Self::GetBlockProof { .. } => BLOCK_PROOF_ANSWER_BYTES,
            Self::GetBlock { .. } => BLOCK_ANSWER_BYTES,
        }
    }

    /// Checks the arguments the schema or the liteserver bound.
    ///
    /// # Errors
    /// A description of the rejected argument.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::GetBlockProof { known, target }
                if !known.is_masterchain()
                    || target.is_some_and(|target| !target.is_masterchain()) =>
            {
                return Err("block proofs link masterchain blocks only".to_owned());
            }
            Self::GetTransactions { count, .. }
                if *count == 0 || *count > MAX_TRANSACTIONS_PER_QUERY =>
            {
                return Err(format!(
                    "getTransactions returns 1..={MAX_TRANSACTIONS_PER_QUERY} transactions"
                ));
            }
            Self::RunSmcMethod { mode, .. } if mode & !RUN_SMC_METHOD_MODE_MASK != 0 => {
                return Err(format!(
                    "runSmcMethod mode {mode:#x} sets bits outside {RUN_SMC_METHOD_MODE_MASK:#x}"
                ));
            }
            Self::RunSmcMethod { id, .. } if !id.is_masterchain() => {
                return Err("get-methods run against a masterchain block".to_owned());
            }
            Self::SendMessage { body } if body.is_empty() => {
                return Err("an external message must not be empty".to_owned());
            }
            Self::GetConfigParams { id, .. } if !id.is_masterchain() => {
                return Err("configuration lives in masterchain blocks".to_owned());
            }
            Self::GetConfigParams { params, .. }
                if params.is_empty() || params.len() > MAX_CONFIG_PARAMS_PER_QUERY =>
            {
                return Err(format!(
                    "getConfigParams requests 1..={MAX_CONFIG_PARAMS_PER_QUERY} parameters"
                ));
            }
            Self::GetAccountState { id, .. } if !id.is_masterchain() => {
                return Err("account states are read at a masterchain block".to_owned());
            }
            _ => {}
        }
        Ok(())
    }

    /// The request TL (the `data` of `liteServer.query`).
    ///
    /// # Errors
    /// As [`Self::validate`], or a body too long for TL.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let too_long = |error: TlError| error.to_string();
        let mut writer;
        match self {
            Self::GetMasterchainInfo => writer = TlWriter::boxed(id::GET_MASTERCHAIN_INFO),
            Self::LookupBlock { id, key } => {
                writer = TlWriter::boxed(id::LOOKUP_BLOCK);
                writer.u32(key.mode());
                id.write(&mut writer);
                match key {
                    LookupKey::Seqno => {}
                    LookupKey::Lt(lt) => {
                        writer.u64(*lt);
                    }
                    LookupKey::Utime(utime) => {
                        writer.u32(*utime);
                    }
                }
            }
            Self::GetBlockHeader { id, mode } => {
                writer = TlWriter::boxed(id::GET_BLOCK_HEADER);
                id.write(&mut writer);
                writer.u32(*mode);
            }
            Self::GetBlockProof { known, target } => {
                writer = TlWriter::boxed(id::GET_BLOCK_PROOF);
                writer.u32(u32::from(target.is_some()));
                known.write(&mut writer);
                if let Some(target) = target {
                    target.write(&mut writer);
                }
            }
            Self::GetBlock { id } => {
                writer = TlWriter::boxed(id::GET_BLOCK);
                id.write(&mut writer);
            }
            Self::GetOneTransaction { id, account, lt } => {
                writer = TlWriter::boxed(id::GET_ONE_TRANSACTION);
                id.write(&mut writer);
                account.write(&mut writer);
                writer.u64(*lt);
            }
            Self::GetTransactions {
                count,
                account,
                lt,
                hash,
            } => {
                writer = TlWriter::boxed(id::GET_TRANSACTIONS);
                writer.u32(*count);
                account.write(&mut writer);
                writer.u64(*lt).int256(hash);
            }
            Self::RunSmcMethod {
                mode,
                id,
                account,
                method_id,
                params,
            } => {
                writer = TlWriter::boxed(id::RUN_SMC_METHOD);
                writer.u32(*mode);
                id.write(&mut writer);
                account.write(&mut writer);
                writer.u64(*method_id);
                writer.bytes(params).map_err(too_long)?;
            }
            Self::SendMessage { body } => {
                writer = TlWriter::boxed(id::SEND_MESSAGE);
                writer.bytes(body).map_err(too_long)?;
            }
            Self::GetShardBlockProof { id } => {
                writer = TlWriter::boxed(id::GET_SHARD_BLOCK_PROOF);
                id.write(&mut writer);
            }
            Self::GetConfigParams { mode, id, params } => {
                writer = TlWriter::boxed(id::GET_CONFIG_PARAMS);
                writer.u32(*mode);
                id.write(&mut writer);
                writer.u32(u32::try_from(params.len()).map_err(|error| error.to_string())?);
                for param in params {
                    writer.i32(*param);
                }
            }
            Self::GetAccountState { id, account } => {
                writer = TlWriter::boxed(id::GET_ACCOUNT_STATE);
                id.write(&mut writer);
                account.write(&mut writer);
            }
            Self::GetTime => writer = TlWriter::boxed(id::GET_TIME),
        }
        Ok(writer.finish())
    }
}

/// `liteServer.query data` around a request TL, optionally preceded by
/// `liteServer.waitMasterchainSeqno`.
///
/// # Errors
/// If the request is too long for TL.
pub fn wrap_query(request: &[u8], wait: Option<WaitMasterchainSeqno>) -> Result<Vec<u8>, TlError> {
    let mut data = TlWriter::new();
    if let Some(wait) = wait {
        data.u32(id::WAIT_MASTERCHAIN_SEQNO)
            .u32(wait.seqno)
            .u32(wait.timeout_ms);
    }
    data.raw(request);
    let mut writer = TlWriter::boxed(id::QUERY);
    writer.bytes(&data.finish())?;
    Ok(writer.finish())
}

/// Splits `liteServer.query data` into the optional wait prefix and the
/// request TL (the inverse of [`wrap_query`]).
///
/// # Errors
/// If `query` is not a `liteServer.query`.
pub fn unwrap_query(query: &[u8]) -> Result<(Option<WaitMasterchainSeqno>, Vec<u8>), TlError> {
    let mut reader = TlReader::new(query);
    reader.expect_constructor(id::QUERY, "liteServer.query")?;
    let data = reader.bytes()?;
    reader.finish()?;
    let mut inner = TlReader::new(data);
    let wait = if data.len() >= 12 && data[..4] == id::WAIT_MASTERCHAIN_SEQNO.to_le_bytes() {
        inner.u32()?;
        Some(WaitMasterchainSeqno {
            seqno: inner.u32()?,
            timeout_ms: inner.u32()?,
        })
    } else {
        None
    };
    let request = inner.take(inner.remaining())?.to_vec();
    Ok((wait, request))
}

/// The id of a TVM get-method: `(CRC-16/XMODEM(name) & 0xffff) | 0x10000`.
pub fn method_id(name: &str) -> u64 {
    let mut crc: u16 = 0;
    for byte in name.bytes() {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x1021
            };
        }
    }
    u64::from(crc) | 0x1_0000
}

/// The `BoC` of an empty `VmStack` (`vm_stack#_ depth:(## 24) = 0`), the
/// `params` of a get-method without arguments.
pub const EMPTY_VM_STACK_BOC: [u8; 16] = [
    0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
];

/// `liteServer.masterchainInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasterchainInfo {
    /// The server's last masterchain block.
    pub last: BlockIdExt,
    /// Root hash of its state.
    pub state_root_hash: [u8; 32],
    /// The masterchain zero state.
    pub init: ZeroStateIdExt,
}

impl LiteAnswer for MasterchainInfo {
    const CONSTRUCTOR: u32 = id::MASTERCHAIN_INFO;
    const NAME: &'static str = "liteServer.masterchainInfo";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            last: BlockIdExt::read(reader)?,
            state_root_hash: reader.int256()?,
            init: ZeroStateIdExt {
                workchain: reader.i32()?,
                root_hash: reader.int256()?,
                file_hash: reader.int256()?,
            },
        })
    }
}

/// `liteServer.blockHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block.
    pub id: BlockIdExt,
    /// Mode bits of the proof.
    pub mode: u32,
    /// `BoC` of the Merkle proof of the block header.
    pub header_proof: Vec<u8>,
}

impl LiteAnswer for BlockHeader {
    const CONSTRUCTOR: u32 = id::BLOCK_HEADER;
    const NAME: &'static str = "liteServer.blockHeader";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            id: BlockIdExt::read(reader)?,
            mode: reader.u32()?,
            header_proof: reader.bytes_vec()?,
        })
    }
}

/// `liteServer.signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Short id of the signing validator.
    pub node_id_short: [u8; 32],
    /// Ed25519 signature.
    pub signature: Vec<u8>,
}

/// `liteServer.signatureSet.ordinary`: signatures of a block produced under
/// catchain consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdinarySignatureSet {
    /// Short hash of the validator subset.
    pub validator_set_hash: u32,
    /// Catchain sequence number of the session.
    pub catchain_seqno: u32,
    /// The signatures.
    pub signatures: Vec<Signature>,
}

/// `liteServer.signatureSet.simplex`: signatures of a block produced under
/// simplex consensus, with the session and slot the signatures bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplexSignatureSet {
    /// Catchain (validator session) sequence number.
    pub cc_seqno: u32,
    /// Short hash of the validator subset.
    pub validator_set_hash: u32,
    /// The signatures.
    pub signatures: Vec<Signature>,
    /// Simplex session id.
    pub session_id: [u8; 32],
    /// Simplex slot of the block.
    pub slot: u32,
    /// The signed candidate data, as serialized by the liteserver.
    pub candidate: Vec<u8>,
}

/// `liteServer.SignatureSet`: the validator signatures of a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureSet {
    /// Catchain consensus.
    Ordinary(OrdinarySignatureSet),
    /// Simplex consensus.
    Simplex(SimplexSignatureSet),
}

impl SignatureSet {
    /// The signatures.
    pub fn signatures(&self) -> &[Signature] {
        match self {
            Self::Ordinary(set) => &set.signatures,
            Self::Simplex(set) => &set.signatures,
        }
    }

    /// Short hash of the validator subset.
    pub fn validator_set_hash(&self) -> u32 {
        match self {
            Self::Ordinary(set) => set.validator_set_hash,
            Self::Simplex(set) => set.validator_set_hash,
        }
    }

    /// Catchain (validator session) sequence number.
    pub fn catchain_seqno(&self) -> u32 {
        match self {
            Self::Ordinary(set) => set.catchain_seqno,
            Self::Simplex(set) => set.cc_seqno,
        }
    }

    fn read_signatures(reader: &mut TlReader<'_>) -> Result<Vec<Signature>, TlError> {
        let count = reader.vector_len(36, MAX_ANSWER_VECTOR)?;
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(Signature {
                node_id_short: reader.int256()?,
                signature: reader.bytes_vec()?,
            });
        }
        Ok(signatures)
    }

    fn read(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        let start = reader.offset();
        match reader.u32()? {
            id::SIGNATURE_SET_ORDINARY => Ok(Self::Ordinary(OrdinarySignatureSet {
                validator_set_hash: reader.u32()?,
                catchain_seqno: reader.u32()?,
                signatures: Self::read_signatures(reader)?,
            })),
            id::SIGNATURE_SET_SIMPLEX => Ok(Self::Simplex(SimplexSignatureSet {
                cc_seqno: reader.u32()?,
                validator_set_hash: reader.u32()?,
                signatures: Self::read_signatures(reader)?,
                session_id: reader.int256()?,
                slot: reader.u32()?,
                candidate: reader.bytes_vec()?,
            })),
            found => Err(TlError {
                offset: start,
                kind: TlErrorKind::UnexpectedConstructor {
                    expected: "liteServer.SignatureSet",
                    found,
                },
            }),
        }
    }
}

/// `liteServer.blockLinkBack`: `to` is an ancestor of `from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLinkBack {
    /// Whether `to` is a key block.
    pub to_key_block: bool,
    /// The known block.
    pub from: BlockIdExt,
    /// The older block.
    pub to: BlockIdExt,
    /// `BoC` proving `to`'s header.
    pub dest_proof: Vec<u8>,
    /// `BoC` proving `from`'s state root.
    pub proof: Vec<u8>,
    /// `BoC` proving `to` in `from`'s `OldMcBlocksInfo`.
    pub state_proof: Vec<u8>,
}

/// `liteServer.blockLinkForward`: `to` is a descendant of `from`, signed by
/// the validators `from`'s configuration names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLinkForward {
    /// Whether `to` is a key block.
    pub to_key_block: bool,
    /// The known block.
    pub from: BlockIdExt,
    /// The newer block.
    pub to: BlockIdExt,
    /// `BoC` proving `to`'s header.
    pub dest_proof: Vec<u8>,
    /// `BoC` proving the validator configuration in `from`.
    pub config_proof: Vec<u8>,
    /// Validator signatures of `to`.
    pub signatures: SignatureSet,
}

/// One step of a [`PartialBlockProof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockLink {
    /// A backward link.
    Back(BlockLinkBack),
    /// A forward link.
    Forward(BlockLinkForward),
}

impl BlockLink {
    /// The known block of the step.
    pub fn from(&self) -> &BlockIdExt {
        match self {
            Self::Back(link) => &link.from,
            Self::Forward(link) => &link.from,
        }
    }

    /// The block the step proves.
    pub fn to(&self) -> &BlockIdExt {
        match self {
            Self::Back(link) => &link.to,
            Self::Forward(link) => &link.to,
        }
    }

    fn read(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        let start = reader.offset();
        match reader.u32()? {
            id::BLOCK_LINK_BACK => Ok(Self::Back(BlockLinkBack {
                to_key_block: reader.bool()?,
                from: BlockIdExt::read(reader)?,
                to: BlockIdExt::read(reader)?,
                dest_proof: reader.bytes_vec()?,
                proof: reader.bytes_vec()?,
                state_proof: reader.bytes_vec()?,
            })),
            id::BLOCK_LINK_FORWARD => Ok(Self::Forward(BlockLinkForward {
                to_key_block: reader.bool()?,
                from: BlockIdExt::read(reader)?,
                to: BlockIdExt::read(reader)?,
                dest_proof: reader.bytes_vec()?,
                config_proof: reader.bytes_vec()?,
                signatures: SignatureSet::read(reader)?,
            })),
            found => Err(TlError {
                offset: start,
                kind: TlErrorKind::UnexpectedConstructor {
                    expected: "liteServer.BlockLink",
                    found,
                },
            }),
        }
    }
}

/// `liteServer.partialBlockProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialBlockProof {
    /// Whether the steps reach the target; otherwise ask again from `to`.
    pub complete: bool,
    /// The known block.
    pub from: BlockIdExt,
    /// The block the steps reach.
    pub to: BlockIdExt,
    /// The links, in order.
    pub steps: Vec<BlockLink>,
}

impl LiteAnswer for PartialBlockProof {
    const CONSTRUCTOR: u32 = id::PARTIAL_BLOCK_PROOF;
    const NAME: &'static str = "liteServer.partialBlockProof";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        let complete = reader.bool()?;
        let from = BlockIdExt::read(reader)?;
        let to = BlockIdExt::read(reader)?;
        let count = reader.vector_len(4 + 4 + 2 * BLOCK_ID_EXT_BYTES, MAX_ANSWER_VECTOR)?;
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            steps.push(BlockLink::read(reader)?);
        }
        Ok(Self {
            complete,
            from,
            to,
            steps,
        })
    }
}

/// `liteServer.blockData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockData {
    /// The block.
    pub id: BlockIdExt,
    /// The block `BoC`.
    pub data: Vec<u8>,
}

impl LiteAnswer for BlockData {
    const CONSTRUCTOR: u32 = id::BLOCK_DATA;
    const NAME: &'static str = "liteServer.blockData";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            id: BlockIdExt::read(reader)?,
            data: reader.bytes_vec()?,
        })
    }
}

/// `liteServer.transactionInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInfo {
    /// The block holding the transaction.
    pub id: BlockIdExt,
    /// `BoC` proving the transaction in the block.
    pub proof: Vec<u8>,
    /// The transaction `BoC` (empty when the block has no such transaction).
    pub transaction: Vec<u8>,
}

impl LiteAnswer for TransactionInfo {
    const CONSTRUCTOR: u32 = id::TRANSACTION_INFO;
    const NAME: &'static str = "liteServer.transactionInfo";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            id: BlockIdExt::read(reader)?,
            proof: reader.bytes_vec()?,
            transaction: reader.bytes_vec()?,
        })
    }
}

/// `liteServer.transactionList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionList {
    /// The block of each transaction, newest first.
    pub ids: Vec<BlockIdExt>,
    /// One `BoC` with a root per transaction, in the same order.
    pub transactions: Vec<u8>,
}

impl LiteAnswer for TransactionList {
    const CONSTRUCTOR: u32 = id::TRANSACTION_LIST;
    const NAME: &'static str = "liteServer.transactionList";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        let count = reader.vector_len(BLOCK_ID_EXT_BYTES, MAX_ANSWER_VECTOR)?;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push(BlockIdExt::read(reader)?);
        }
        Ok(Self {
            ids,
            transactions: reader.bytes_vec()?,
        })
    }
}

/// `liteServer.runMethodResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunMethodResult {
    /// Mode bits of the answer.
    pub mode: u32,
    /// The masterchain block.
    pub id: BlockIdExt,
    /// The shard block holding the account state.
    pub shardblk: BlockIdExt,
    /// Shard proof `BoC` (mode bit 0).
    pub shard_proof: Option<Vec<u8>>,
    /// Account proof `BoC` (mode bit 0).
    pub proof: Option<Vec<u8>>,
    /// State proof `BoC` (mode bit 1).
    pub state_proof: Option<Vec<u8>>,
    /// `c7` `BoC` (mode bit 3).
    pub init_c7: Option<Vec<u8>>,
    /// Library extras `BoC` (mode bit 4).
    pub lib_extras: Option<Vec<u8>>,
    /// TVM exit code.
    pub exit_code: i32,
    /// Result `VmStack` `BoC` (mode bit 2).
    pub result: Option<Vec<u8>>,
}

impl LiteAnswer for RunMethodResult {
    const CONSTRUCTOR: u32 = id::RUN_METHOD_RESULT;
    const NAME: &'static str = "liteServer.runMethodResult";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        let mode = reader.u32()?;
        let optional = |bit: u32, reader: &mut TlReader<'_>| {
            if mode & (1 << bit) == 0 {
                Ok(None)
            } else {
                reader.bytes_vec().map(Some)
            }
        };
        let id = BlockIdExt::read(reader)?;
        let shardblk = BlockIdExt::read(reader)?;
        let shard_proof = optional(0, reader)?;
        let proof = optional(0, reader)?;
        let state_proof = optional(1, reader)?;
        let init_c7 = optional(3, reader)?;
        let lib_extras = optional(4, reader)?;
        let exit_code = reader.i32()?;
        let result = optional(2, reader)?;
        Ok(Self {
            mode,
            id,
            shardblk,
            shard_proof,
            proof,
            state_proof,
            init_c7,
            lib_extras,
            exit_code,
            result,
        })
    }
}

/// `liteServer.sendMsgStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendMsgStatus {
    /// `1` when the message was accepted for broadcast.
    pub status: i32,
}

impl LiteAnswer for SendMsgStatus {
    const CONSTRUCTOR: u32 = id::SEND_MSG_STATUS;
    const NAME: &'static str = "liteServer.sendMsgStatus";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            status: reader.i32()?,
        })
    }
}

/// `liteServer.shardBlockLink`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardBlockLink {
    /// A block on the path.
    pub id: BlockIdExt,
    /// `BoC` proving the link.
    pub proof: Vec<u8>,
}

/// `liteServer.shardBlockProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardBlockProof {
    /// The masterchain block the links start at.
    pub masterchain_id: BlockIdExt,
    /// The links down to the shard block.
    pub links: Vec<ShardBlockLink>,
}

impl LiteAnswer for ShardBlockProof {
    const CONSTRUCTOR: u32 = id::SHARD_BLOCK_PROOF;
    const NAME: &'static str = "liteServer.shardBlockProof";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        let masterchain_id = BlockIdExt::read(reader)?;
        let count = reader.vector_len(BLOCK_ID_EXT_BYTES + 4, MAX_ANSWER_VECTOR)?;
        let mut links = Vec::with_capacity(count);
        for _ in 0..count {
            links.push(ShardBlockLink {
                id: BlockIdExt::read(reader)?,
                proof: reader.bytes_vec()?,
            });
        }
        Ok(Self {
            masterchain_id,
            links,
        })
    }
}

/// `liteServer.configInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigInfo {
    /// Mode bits of the answer.
    pub mode: u32,
    /// The masterchain block.
    pub id: BlockIdExt,
    /// `BoC` proving the state root.
    pub state_proof: Vec<u8>,
    /// `BoC` proving the requested parameters.
    pub config_proof: Vec<u8>,
}

impl LiteAnswer for ConfigInfo {
    const CONSTRUCTOR: u32 = id::CONFIG_INFO;
    const NAME: &'static str = "liteServer.configInfo";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            mode: reader.u32()?,
            id: BlockIdExt::read(reader)?,
            state_proof: reader.bytes_vec()?,
            config_proof: reader.bytes_vec()?,
        })
    }
}

/// `liteServer.accountState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    /// The masterchain block.
    pub id: BlockIdExt,
    /// The shard block holding the state.
    pub shardblk: BlockIdExt,
    /// `BoC` proving the shard block in the masterchain block.
    pub shard_proof: Vec<u8>,
    /// `BoC` proving the account in the shard state.
    pub proof: Vec<u8>,
    /// The `Account` `BoC` (empty for a nonexistent account).
    pub state: Vec<u8>,
}

impl LiteAnswer for AccountState {
    const CONSTRUCTOR: u32 = id::ACCOUNT_STATE;
    const NAME: &'static str = "liteServer.accountState";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self {
            id: BlockIdExt::read(reader)?,
            shardblk: BlockIdExt::read(reader)?,
            shard_proof: reader.bytes_vec()?,
            proof: reader.bytes_vec()?,
            state: reader.bytes_vec()?,
        })
    }
}

/// `liteServer.currentTime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentTime {
    /// The liteserver's Unix time.
    pub now: u32,
}

impl LiteAnswer for CurrentTime {
    const CONSTRUCTOR: u32 = id::CURRENT_TIME;
    const NAME: &'static str = "liteServer.currentTime";

    fn read_body(reader: &mut TlReader<'_>) -> Result<Self, TlError> {
        Ok(Self { now: reader.u32()? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ton::tl::constructor_id;

    fn block(workchain: i32, seqno: u32, tag: u8) -> BlockIdExt {
        BlockIdExt {
            workchain,
            shard: SHARD_FULL,
            seqno,
            root_hash: [tag; 32],
            file_hash: [tag.wrapping_add(1); 32],
        }
    }

    fn account() -> AccountId {
        AccountId {
            workchain: BASECHAIN,
            address: [0xAB; 32],
        }
    }

    /// Every constructor id with its normalized `lite_api.tl` line.
    const SCHEMA_LINES: &[(u32, &str)] = &[
        (
            id::ERROR,
            "liteServer.error code:int message:string = liteServer.Error",
        ),
        (id::QUERY, "liteServer.query data:bytes = Object"),
        (
            id::WAIT_MASTERCHAIN_SEQNO,
            "liteServer.waitMasterchainSeqno seqno:int timeout_ms:int = Object",
        ),
        (
            id::GET_MASTERCHAIN_INFO,
            "liteServer.getMasterchainInfo = liteServer.MasterchainInfo",
        ),
        (
            id::MASTERCHAIN_INFO,
            "liteServer.masterchainInfo last:tonNode.blockIdExt state_root_hash:int256 init:tonNode.zeroStateIdExt = liteServer.MasterchainInfo",
        ),
        (
            id::LOOKUP_BLOCK,
            "liteServer.lookupBlock mode:# id:tonNode.blockId lt:mode.1?long utime:mode.2?int = liteServer.BlockHeader",
        ),
        (
            id::GET_BLOCK_HEADER,
            "liteServer.getBlockHeader id:tonNode.blockIdExt mode:# = liteServer.BlockHeader",
        ),
        (
            id::BLOCK_HEADER,
            "liteServer.blockHeader id:tonNode.blockIdExt mode:# header_proof:bytes = liteServer.BlockHeader",
        ),
        (
            id::GET_BLOCK_PROOF,
            "liteServer.getBlockProof mode:# known_block:tonNode.blockIdExt target_block:mode.0?tonNode.blockIdExt = liteServer.PartialBlockProof",
        ),
        (
            id::PARTIAL_BLOCK_PROOF,
            "liteServer.partialBlockProof complete:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt steps:vector liteServer.BlockLink = liteServer.PartialBlockProof",
        ),
        (
            id::BLOCK_LINK_BACK,
            "liteServer.blockLinkBack to_key_block:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt dest_proof:bytes proof:bytes state_proof:bytes = liteServer.BlockLink",
        ),
        (
            id::BLOCK_LINK_FORWARD,
            "liteServer.blockLinkForward to_key_block:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt dest_proof:bytes config_proof:bytes signatures:liteServer.SignatureSet = liteServer.BlockLink",
        ),
        (
            id::SIGNATURE_SET_SIMPLEX,
            "liteServer.signatureSet.simplex cc_seqno:int validator_set_hash:int signatures:vector liteServer.signature session_id:int256 slot:int candidate:bytes = liteServer.SignatureSet",
        ),
        (
            // The ordinary set keeps the id of the pre-simplex line.
            id::SIGNATURE_SET_ORDINARY,
            "liteServer.signatureSet validator_set_hash:int catchain_seqno:int signatures:vector liteServer.signature = liteServer.SignatureSet",
        ),
        (
            id::GET_BLOCK,
            "liteServer.getBlock id:tonNode.blockIdExt = liteServer.BlockData",
        ),
        (
            id::BLOCK_DATA,
            "liteServer.blockData id:tonNode.blockIdExt data:bytes = liteServer.BlockData",
        ),
        (
            id::GET_ONE_TRANSACTION,
            "liteServer.getOneTransaction id:tonNode.blockIdExt account:liteServer.accountId lt:long = liteServer.TransactionInfo",
        ),
        (
            id::TRANSACTION_INFO,
            "liteServer.transactionInfo id:tonNode.blockIdExt proof:bytes transaction:bytes = liteServer.TransactionInfo",
        ),
        (
            id::GET_TRANSACTIONS,
            "liteServer.getTransactions count:# account:liteServer.accountId lt:long hash:int256 = liteServer.TransactionList",
        ),
        (
            id::TRANSACTION_LIST,
            "liteServer.transactionList ids:vector tonNode.blockIdExt transactions:bytes = liteServer.TransactionList",
        ),
        (
            id::RUN_SMC_METHOD,
            "liteServer.runSmcMethod mode:# id:tonNode.blockIdExt account:liteServer.accountId method_id:long params:bytes = liteServer.RunMethodResult",
        ),
        (
            id::RUN_METHOD_RESULT,
            "liteServer.runMethodResult mode:# id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:mode.0?bytes proof:mode.0?bytes state_proof:mode.1?bytes init_c7:mode.3?bytes lib_extras:mode.4?bytes exit_code:int result:mode.2?bytes = liteServer.RunMethodResult",
        ),
        (
            id::SEND_MESSAGE,
            "liteServer.sendMessage body:bytes = liteServer.SendMsgStatus",
        ),
        (
            id::SEND_MSG_STATUS,
            "liteServer.sendMsgStatus status:int = liteServer.SendMsgStatus",
        ),
        (
            id::GET_SHARD_BLOCK_PROOF,
            "liteServer.getShardBlockProof id:tonNode.blockIdExt = liteServer.ShardBlockProof",
        ),
        (
            id::SHARD_BLOCK_PROOF,
            "liteServer.shardBlockProof masterchain_id:tonNode.blockIdExt links:vector liteServer.shardBlockLink = liteServer.ShardBlockProof",
        ),
        (
            id::GET_CONFIG_PARAMS,
            "liteServer.getConfigParams mode:# id:tonNode.blockIdExt param_list:vector int = liteServer.ConfigInfo",
        ),
        (
            id::CONFIG_INFO,
            "liteServer.configInfo mode:# id:tonNode.blockIdExt state_proof:bytes config_proof:bytes = liteServer.ConfigInfo",
        ),
        (
            id::GET_ACCOUNT_STATE,
            "liteServer.getAccountState id:tonNode.blockIdExt account:liteServer.accountId = liteServer.AccountState",
        ),
        (
            id::ACCOUNT_STATE,
            "liteServer.accountState id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:bytes proof:bytes state:bytes = liteServer.AccountState",
        ),
        (id::GET_TIME, "liteServer.getTime = liteServer.CurrentTime"),
        (
            id::CURRENT_TIME,
            "liteServer.currentTime now:int = liteServer.CurrentTime",
        ),
    ];

    #[test]
    fn constructor_ids_match_the_schema_lines() {
        for (value, line) in SCHEMA_LINES {
            assert_eq!(constructor_id(line), *value, "{line}");
        }
    }

    #[test]
    fn answer_caps_follow_the_query() {
        let id = BlockIdExt {
            workchain: MASTERCHAIN,
            shard: SHARD_FULL,
            seqno: 1,
            root_hash: [0; 32],
            file_hash: [0; 32],
        };
        assert_eq!(
            LiteQuery::GetMasterchainInfo.max_answer_bytes(),
            SMALL_ANSWER_BYTES
        );
        assert_eq!(LiteQuery::GetTime.max_answer_bytes(), SMALL_ANSWER_BYTES);
        assert_eq!(
            LiteQuery::GetBlock { id }.max_answer_bytes(),
            BLOCK_ANSWER_BYTES
        );
        assert_eq!(
            LiteQuery::GetBlockProof {
                known: id,
                target: None
            }
            .max_answer_bytes(),
            BLOCK_PROOF_ANSWER_BYTES
        );
        assert_eq!(
            LiteQuery::GetShardBlockProof { id }.max_answer_bytes(),
            PROOF_ANSWER_BYTES
        );
        // Every cap fits the default packet bound.
        const { assert!(BLOCK_ANSWER_BYTES <= crate::ton::adnl::DEFAULT_MAX_PACKET_BYTES) };
    }

    #[test]
    fn get_method_ids_use_crc16_xmodem() {
        // CRC-16/XMODEM check value.
        assert_eq!(method_id("123456789"), 0x1_31C3);
        assert_eq!(method_id("seqno"), 85_143);
        assert_eq!(method_id("get_jetton_data"), 0x1_9E2D);
    }

    #[test]
    fn lookup_requests_encode_exact_tl() {
        let query = LiteQuery::GetMasterchainInfo;
        assert_eq!(
            query.encode().expect("encode"),
            id::GET_MASTERCHAIN_INFO.to_le_bytes()
        );

        let lookup = LiteQuery::LookupBlock {
            id: BlockId::masterchain(7),
            key: LookupKey::Utime(0x0102_0304),
        }
        .encode()
        .expect("encode");
        let mut expected = id::LOOKUP_BLOCK.to_le_bytes().to_vec();
        expected.extend_from_slice(&4_u32.to_le_bytes());
        expected.extend_from_slice(&(-1_i32).to_le_bytes());
        expected.extend_from_slice(&SHARD_FULL.to_le_bytes());
        expected.extend_from_slice(&7_u32.to_le_bytes());
        expected.extend_from_slice(&0x0102_0304_u32.to_le_bytes());
        assert_eq!(lookup, expected);
        assert_eq!(LookupKey::Seqno.mode(), 1);
        assert_eq!(LookupKey::Lt(5).mode(), 2);
        let by_lt = LiteQuery::LookupBlock {
            id: BlockId::masterchain(0),
            key: LookupKey::Lt(5),
        }
        .encode()
        .expect("encode");
        assert_eq!(by_lt.len(), 4 + 4 + 16 + 8);
        let by_seqno = LiteQuery::LookupBlock {
            id: BlockId::masterchain(3),
            key: LookupKey::Seqno,
        }
        .encode()
        .expect("encode");
        assert_eq!(by_seqno.len(), 4 + 4 + 16);
    }

    #[test]
    fn requests_encode_exact_tl() {
        let masterchain = block(MASTERCHAIN, 10, 1);
        let without_target = LiteQuery::GetBlockProof {
            known: masterchain,
            target: None,
        }
        .encode()
        .expect("encode");
        assert_eq!(without_target.len(), 4 + 4 + 80);
        assert_eq!(&without_target[4..8], &0_u32.to_le_bytes());
        let with_target = LiteQuery::GetBlockProof {
            known: masterchain,
            target: Some(block(MASTERCHAIN, 11, 2)),
        }
        .encode()
        .expect("encode");
        assert_eq!(with_target.len(), 4 + 4 + 160);
        assert_eq!(&with_target[4..8], &1_u32.to_le_bytes());

        let run = LiteQuery::RunSmcMethod {
            mode: 4,
            id: masterchain,
            account: account(),
            method_id: method_id("seqno"),
            params: EMPTY_VM_STACK_BOC.to_vec(),
        }
        .encode()
        .expect("encode");
        // mode, block, account, method id, then 16 bytes behind a 1-byte length.
        assert_eq!(run.len(), 4 + 4 + 80 + 36 + 8 + 20);

        let config = LiteQuery::GetConfigParams {
            mode: 0,
            id: masterchain,
            params: vec![34, 28, 15],
        }
        .encode()
        .expect("encode");
        assert_eq!(config.len(), 4 + 4 + 80 + 4 + 12);

        let transactions = LiteQuery::GetTransactions {
            count: 3,
            account: account(),
            lt: 9,
            hash: [5; 32],
        }
        .encode()
        .expect("encode");
        assert_eq!(transactions.len(), 4 + 4 + 36 + 8 + 32);

        for query in [
            LiteQuery::GetBlockHeader {
                id: masterchain,
                mode: 0,
            },
            LiteQuery::GetBlock { id: masterchain },
            LiteQuery::GetOneTransaction {
                id: block(BASECHAIN, 1, 3),
                account: account(),
                lt: 1,
            },
            LiteQuery::SendMessage { body: vec![1] },
            LiteQuery::GetShardBlockProof {
                id: block(BASECHAIN, 1, 3),
            },
            LiteQuery::GetAccountState {
                id: masterchain,
                account: account(),
            },
            LiteQuery::GetTime,
        ] {
            let encoded = query.encode().expect("encode");
            assert_eq!(encoded.len() % 4, 0, "{}", query.name());
            assert!(query.name().starts_with("liteServer."));
        }
    }

    #[test]
    fn invalid_requests_are_refused() {
        let masterchain = block(MASTERCHAIN, 10, 1);
        let shard = block(BASECHAIN, 10, 1);
        for query in [
            LiteQuery::GetBlockProof {
                known: shard,
                target: None,
            },
            LiteQuery::GetBlockProof {
                known: masterchain,
                target: Some(shard),
            },
            LiteQuery::GetTransactions {
                count: 0,
                account: account(),
                lt: 0,
                hash: [0; 32],
            },
            LiteQuery::GetTransactions {
                count: MAX_TRANSACTIONS_PER_QUERY + 1,
                account: account(),
                lt: 0,
                hash: [0; 32],
            },
            LiteQuery::RunSmcMethod {
                mode: 0x20,
                id: masterchain,
                account: account(),
                method_id: 0,
                params: Vec::new(),
            },
            LiteQuery::RunSmcMethod {
                mode: 4,
                id: shard,
                account: account(),
                method_id: 0,
                params: Vec::new(),
            },
            LiteQuery::SendMessage { body: Vec::new() },
            LiteQuery::GetConfigParams {
                mode: 0,
                id: masterchain,
                params: Vec::new(),
            },
            LiteQuery::GetConfigParams {
                mode: 0,
                id: shard,
                params: vec![34],
            },
            LiteQuery::GetConfigParams {
                mode: 0,
                id: masterchain,
                params: vec![0; MAX_CONFIG_PARAMS_PER_QUERY + 1],
            },
            LiteQuery::GetAccountState {
                id: shard,
                account: account(),
            },
        ] {
            assert!(query.encode().is_err(), "{query:?}");
        }
    }

    #[test]
    fn queries_wrap_and_unwrap() {
        let request = LiteQuery::GetTime.encode().expect("encode");
        let wrapped = wrap_query(&request, None).expect("wrap");
        assert_eq!(
            wrapped,
            [
                id::QUERY.to_le_bytes().as_slice(),
                &[4],
                &request,
                &[0, 0, 0]
            ]
            .concat()
        );
        assert_eq!(
            unwrap_query(&wrapped).expect("unwrap"),
            (None, request.clone())
        );
        let wait = WaitMasterchainSeqno {
            seqno: 42,
            timeout_ms: 5_000,
        };
        let waiting = wrap_query(&request, Some(wait)).expect("wrap");
        assert_eq!(
            unwrap_query(&waiting).expect("unwrap"),
            (Some(wait), request)
        );
        assert!(unwrap_query(&[0; 8]).is_err());
    }

    fn answer(constructor: u32, body: impl FnOnce(&mut TlWriter)) -> Vec<u8> {
        let mut writer = TlWriter::boxed(constructor);
        body(&mut writer);
        writer.finish()
    }

    #[test]
    fn errors_decode_in_place_of_any_answer() {
        let error = answer(id::ERROR, |writer| {
            writer.i32(651).bytes(b"not\nready").expect("bytes");
        });
        let decoded = MasterchainInfo::decode_answer(&error).expect_err("error answer");
        let AnswerError::LiteServer(error_value) = &decoded else {
            panic!("unexpected {decoded:?}");
        };
        assert_eq!(error_value.code, 651);
        assert_eq!(error_value.message, "not ready");
        assert!(error_value.is_failover());
        assert!(decoded.to_string().contains("651"));
        assert_eq!(
            LiteServerError::from_answer(&error),
            Some(error_value.clone())
        );
        assert_eq!(
            LiteServerError::from_answer(&id::GET_TIME.to_le_bytes()),
            None
        );
        let final_answer = LiteServerError {
            code: 0,
            message: String::new(),
        };
        assert!(!final_answer.is_failover());
    }

    #[test]
    fn unexpected_or_trailing_answers_are_malformed() {
        let time = answer(id::CURRENT_TIME, |writer| {
            writer.u32(1_700_000_000);
        });
        assert_eq!(
            CurrentTime::decode_answer(&time).expect("time"),
            CurrentTime { now: 1_700_000_000 }
        );
        let error = MasterchainInfo::decode_answer(&time).expect_err("wrong type");
        assert!(matches!(
            error,
            AnswerError::Malformed(TlError {
                kind: TlErrorKind::UnexpectedConstructor { .. },
                ..
            })
        ));
        assert!(error.to_string().contains("liteServer.masterchainInfo"));
        let mut trailing = time.clone();
        trailing.extend_from_slice(&[0; 4]);
        assert!(CurrentTime::decode_answer(&trailing).is_err());
        assert!(CurrentTime::decode_answer(&time[..6]).is_err());
    }

    #[test]
    fn run_method_results_honour_mode_bits() {
        let masterchain = block(MASTERCHAIN, 1, 1);
        for mode in [0_u32, 4, 7, 0x1F] {
            let encoded = answer(id::RUN_METHOD_RESULT, |writer| {
                writer.u32(mode);
                masterchain.write(writer);
                masterchain.write(writer);
                for bit in [0, 0, 1, 3, 4] {
                    if mode & (1 << bit) != 0 {
                        writer.bytes(&[bit; 3]).expect("bytes");
                    }
                }
                writer.i32(-13);
                if mode & 4 != 0 {
                    writer.bytes(b"stack").expect("bytes");
                }
            });
            let result = RunMethodResult::decode_answer(&encoded).expect("decode");
            assert_eq!(result.mode, mode);
            assert_eq!(result.exit_code, -13);
            assert_eq!(result.shard_proof.is_some(), mode & 1 != 0);
            assert_eq!(
                result.proof.as_deref(),
                (mode & 1 != 0).then_some(&[0_u8; 3][..])
            );
            assert_eq!(result.state_proof.is_some(), mode & 2 != 0);
            assert_eq!(
                result.init_c7.as_deref(),
                (mode & 8 != 0).then_some(&[3_u8; 3][..])
            );
            assert_eq!(result.lib_extras.is_some(), mode & 16 != 0);
            assert_eq!(
                result.result.as_deref(),
                (mode & 4 != 0).then_some(&b"stack"[..])
            );
        }
    }

    #[test]
    fn block_links_decode_both_directions() {
        let from = block(MASTERCHAIN, 5, 1);
        let to = block(MASTERCHAIN, 9, 2);
        let encoded = answer(id::PARTIAL_BLOCK_PROOF, |writer| {
            writer.bool(true);
            from.write(writer);
            to.write(writer);
            writer.u32(3);
            writer.u32(id::BLOCK_LINK_BACK).bool(false);
            to.write(writer);
            from.write(writer);
            for proof in [&b"d"[..], b"p", b"s"] {
                writer.bytes(proof).expect("bytes");
            }
            writer.u32(id::BLOCK_LINK_FORWARD).bool(true);
            from.write(writer);
            to.write(writer);
            writer.bytes(b"dest").expect("bytes");
            writer.bytes(b"config").expect("bytes");
            writer
                .u32(id::SIGNATURE_SET_ORDINARY)
                .u32(0xAABB_CCDD)
                .u32(77)
                .u32(1);
            writer.int256(&[9; 32]).bytes(&[1; 64]).expect("bytes");
            writer.u32(id::BLOCK_LINK_FORWARD).bool(false);
            from.write(writer);
            to.write(writer);
            writer.bytes(b"dest").expect("bytes");
            writer.bytes(b"config").expect("bytes");
            writer
                .u32(id::SIGNATURE_SET_SIMPLEX)
                .u32(78)
                .u32(0x1122_3344)
                .u32(2);
            writer.int256(&[5; 32]).bytes(&[2; 64]).expect("bytes");
            writer.int256(&[6; 32]).bytes(&[3; 64]).expect("bytes");
            writer
                .int256(&[7; 32])
                .u32(12)
                .bytes(b"candidate")
                .expect("bytes");
        });
        let proof = PartialBlockProof::decode_answer(&encoded).expect("decode");
        assert!(proof.complete);
        assert_eq!(proof.steps.len(), 3);
        assert_eq!(proof.steps[0].from(), &to);
        assert_eq!(proof.steps[0].to(), &from);
        let BlockLink::Forward(forward) = &proof.steps[1] else {
            panic!("expected a forward link");
        };
        assert!(forward.to_key_block);
        assert_eq!(proof.steps[1].from(), &from);
        assert_eq!(proof.steps[1].to(), &to);
        assert_eq!(forward.signatures.validator_set_hash(), 0xAABB_CCDD);
        assert_eq!(forward.signatures.catchain_seqno(), 77);
        assert_eq!(forward.signatures.signatures()[0].signature, vec![1; 64]);
        assert!(matches!(forward.signatures, SignatureSet::Ordinary(_)));
        let BlockLink::Forward(simplex_link) = &proof.steps[2] else {
            panic!("expected a forward link");
        };
        let SignatureSet::Simplex(simplex) = &simplex_link.signatures else {
            panic!("expected a simplex signature set");
        };
        assert_eq!(simplex_link.signatures.catchain_seqno(), 78);
        assert_eq!(simplex_link.signatures.validator_set_hash(), 0x1122_3344);
        assert_eq!(simplex_link.signatures.signatures().len(), 2);
        assert_eq!(simplex.session_id, [7; 32]);
        assert_eq!(simplex.slot, 12);
        assert_eq!(simplex.candidate, b"candidate");

        let mut unknown_set = answer(id::PARTIAL_BLOCK_PROOF, |writer| {
            writer.bool(true);
            from.write(writer);
            to.write(writer);
            writer.u32(1).u32(id::BLOCK_LINK_FORWARD).bool(false);
            from.write(writer);
            to.write(writer);
            writer.bytes(b"dest").expect("bytes");
            writer.bytes(b"config").expect("bytes");
            writer.u32(0x0BAD_5E75).u32(0).u32(0).u32(0);
        });
        unknown_set.extend_from_slice(&[0; 64]);
        let error = PartialBlockProof::decode_answer(&unknown_set).expect_err("unknown set");
        assert!(error.to_string().contains("liteServer.SignatureSet"));

        let mut unknown = answer(id::PARTIAL_BLOCK_PROOF, |writer| {
            writer.bool(false);
            from.write(writer);
            to.write(writer);
            writer.u32(1).u32(0xDEAD_BEEF);
        });
        unknown.extend_from_slice(&[0; 256]);
        assert!(PartialBlockProof::decode_answer(&unknown).is_err());
    }

    #[test]
    fn block_ids_display_and_convert() {
        let id = block(MASTERCHAIN, 12, 0xAB);
        assert_eq!(id.id(), BlockId::masterchain(12));
        assert!(id.is_masterchain());
        assert!(id.to_string().starts_with("(-1,8000000000000000,12):ABAB"));
        assert_eq!(BlockId::masterchain(1).shard, SHARD_FULL);
    }

    #[test]
    fn empty_vm_stack_boc_is_one_24_bit_cell() {
        // Magic, flags/size, offset size, 1 cell, 1 root, 0 absent, 5 bytes.
        assert_eq!(&EMPTY_VM_STACK_BOC[..4], &[0xb5, 0xee, 0x9c, 0x72]);
        // Cell descriptors: no refs, 24 bits = 3 full bytes (d2 = 6).
        assert_eq!(&EMPTY_VM_STACK_BOC[11..], &[0x00, 0x06, 0x00, 0x00, 0x00]);
    }
}
