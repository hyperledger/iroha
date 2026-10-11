//! Native TON masterchain finality and source-message verification for SCCP.
//!
//! TON does not sign application-specific bridge statements. Validators sign a
//! native `BlockIdExt`, either directly (ordinary catchain finality) or through
//! the Simplex `consensus.dataToSign` transcript. This module therefore holds
//! the native primitives behind `light_client::ton`: it opens canonical `BoC`s
//! against authenticated root hashes, verifies the native signature transcript
//! and validator roster, follows authenticated block references, opens the
//! finalized shard descriptor, and parses the concrete account transaction and
//! external-out message. No caller-provided event fields are trusted
//! independently of authenticated TON cells.
//! Native TL-B constructors are retained, and shard prefixes are converted to
//! terminated shard ids only after decoding their exact wire representation.

use super::H256;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::fmt;
/// TON mainnet global identifier.
const TON_MAINNET_GLOBAL_ID: i32 = -239;
/// TON masterchain workchain.
const TON_MASTERCHAIN_WORKCHAIN: i32 = -1;
/// TON all-shards masterchain shard id.
const TON_MASTERCHAIN_SHARD: u64 = 0x8000_0000_0000_0000;
/// TON basechain workchain.
const TON_BASECHAIN_WORKCHAIN: i32 = 0;
/// Standard TON internal address (`addr_std` without anycast).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TonStdAddress {
    /// Signed workchain id.
    workchain: i32,
    /// 256-bit account id.
    account: [u8; 32],
}
use sha2::{Digest as _, Sha256, Sha512};

const TON_BOC_MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];
const TON_BLOCK_CONSTRUCTOR: u32 = 0x11ef_55aa;
const TON_BLOCK_INFO_CONSTRUCTOR: u32 = 0x9bc7_a987;
const TON_BLOCK_EXTRA_CONSTRUCTOR: u32 = 0x4a33_f6fd;
const TON_GLOBAL_VERSION_CONSTRUCTOR: u8 = 0xc4;
const TON_SHARD_STATE_CONSTRUCTOR: u32 = 0x9023_afe2;
const TON_MC_BLOCK_EXTRA_CONSTRUCTOR: u16 = 0xcca5;
const TON_TRANSACTION_CONSTRUCTOR: u8 = 0x7;
const TON_ACCOUNT_BLOCK_CONSTRUCTOR: u8 = 0x5;
const TON_VALIDATOR_CONSTRUCTOR: u8 = 0x53;
const TON_VALIDATOR_ADDR_CONSTRUCTOR: u8 = 0x73;
const TON_VALIDATORS_CONSTRUCTOR: u8 = 0x11;
const TON_VALIDATORS_EXT_CONSTRUCTOR: u8 = 0x12;
const TON_ED25519_PUBKEY_TLB_CONSTRUCTOR: u32 = 0x8e81_278a;
const TON_CATCHAIN_CONFIG_CONSTRUCTOR: u8 = 0xc1;
const TON_CATCHAIN_CONFIG_NEW_CONSTRUCTOR: u8 = 0xc2;
const TON_CONFIG_CURRENT_VALIDATORS: u32 = 34;
const TON_CONFIG_CATCHAIN: u32 = 28;
const TON_PUB_ED25519_TL_CONSTRUCTOR: u32 = 0x4813_b4c6;
const TON_BLOCK_ID_TL_CONSTRUCTOR: u32 = 0xc50b_6e70;
const TON_CONSENSUS_DATA_TO_SIGN_TL_CONSTRUCTOR: u32 = 0xa8e3_3df8;
const TON_CONSENSUS_CANDIDATE_ID_TL_CONSTRUCTOR: u32 = 0xb691_cd3f;
const TON_CONSENSUS_CANDIDATE_PARENT_TL_CONSTRUCTOR: u32 = 0x1a4b_9af1;
const TON_CONSENSUS_CANDIDATE_WITHOUT_PARENTS_TL_CONSTRUCTOR: u32 = 0x22cb_cca9;
const TON_CONSENSUS_CANDIDATE_ORDINARY_TL_CONSTRUCTOR: u32 = 0xe8f9_bcdc;
const TON_CONSENSUS_CANDIDATE_EMPTY_TL_CONSTRUCTOR: u32 = 0x72b4_d933;
const TON_CONSENSUS_SIMPLEX_FINALIZE_TL_CONSTRUCTOR: u32 = 0x40a7_e105;
const TON_MAX_CELL_DATA_BYTES: usize = 128;
const TON_MAX_BOC_BYTES: usize = 256 * 1024;
const TON_MAX_BOC_CELLS: usize = 8_192;
const TON_MAX_REFS: usize = 4;
/// Maximum cell depth admitted by TON's reference cell traits.
const TON_MAX_CELL_DEPTH: u16 = 1_024;
const TON_MAX_VALIDATORS: usize = 1_024;
const TON_MAX_SIGNATURES: usize = 1_024;
const TON_MAX_TOTAL_VALIDATOR_WEIGHT: u64 = 1_u64 << 61;
const TON_SHARD_ACCOUNT_KEY_BITS: u16 = 256;
const TON_ACCOUNT_TRANSACTION_KEY_BITS: u16 = 64;
const TON_OUT_MESSAGE_KEY_BITS: u16 = 15;
const TON_CONFIG_KEY_BITS: u16 = 32;
const TON_VALIDATOR_SET_KEY_BITS: u16 = 16;

/// Native TON extended block identifier.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ton_native::TonBlockIdExtV1")]
pub struct TonBlockIdExtV1 {
    /// Signed workchain identifier.
    pub workchain: i32,
    /// TON full-shard identifier.
    #[norito(with = "crate::json_utils::u64_string")]
    pub shard: u64,
    /// Block sequence number.
    pub seqno: u32,
    /// TON representation hash of the block root cell.
    #[norito(with = "crate::json_utils::hex32")]
    pub root_hash: H256,
    /// SHA-256 file hash carried by native block references and signatures.
    #[norito(with = "crate::json_utils::hex32")]
    pub file_hash: H256,
}

/// One validator in the exact native order used for TON set hashing.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ton_native::TonValidatorV1")]
pub struct TonValidatorV1 {
    /// Raw Ed25519 public key from `ValidatorDescr`.
    #[norito(with = "crate::json_utils::hex32")]
    pub public_key: H256,
    /// Positive native validator weight.
    #[norito(with = "crate::json_utils::u64_string")]
    pub weight: u64,
    /// Raw ADNL address committed by the native validator-list hash.
    #[norito(with = "crate::json_utils::hex32")]
    pub adnl_address: H256,
}

/// Exact active masterchain validator subset of one catchain session.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ton_native::TonValidatorSetV1")]
pub struct TonValidatorSetV1 {
    /// Catchain sequence number used to derive this subset.
    pub catchain_seqno: u32,
    /// Native CRC32C `validator_list_hash_short`.
    pub validator_list_hash_short: u32,
    /// Validators in exact native set order.
    pub validators: Vec<TonValidatorV1>,
}

/// Full config-34 roster (with the config-28 shuffle flag) read from a key block's state; the
/// light client's TON epoch stores it for the next set transition.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ton_native::TonValidatorConfigV1")]
pub struct TonValidatorConfigV1 {
    /// Inclusive UNIX activation time encoded by config 34.
    pub valid_since: u32,
    /// Exclusive UNIX end time encoded by config 34.
    pub valid_until: u32,
    /// Number of leading validators eligible for the masterchain subset.
    pub main_validator_count: u16,
    /// Config-28 masterchain shuffle flag.
    pub shuffle_masterchain_validators: bool,
    /// Complete config-34 roster in dictionary-index order.
    pub validators: Vec<TonValidatorV1>,
}

/// One validator signature over a native TON finality transcript.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ton_native::TonValidatorSignatureV1")]
pub struct TonValidatorSignatureV1 {
    /// SHA-256 short id of boxed TL `pub.ed25519`.
    #[norito(with = "crate::json_utils::hex32")]
    pub node_id_short: H256,
    /// Canonical 64-byte Ed25519 signature.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub signature: Vec<u8>,
}

/// Ordinary catchain signatures over boxed TL `ton.blockId`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ton_native::TonOrdinaryBlockSignaturesV1")]
pub struct TonOrdinaryBlockSignaturesV1 {
    /// Native catchain sequence number.
    pub catchain_seqno: u32,
    /// Native validator-list hash.
    pub validator_list_hash_short: u32,
    /// Strictly node-id-ordered unique native signatures.
    pub signatures: Vec<TonValidatorSignatureV1>,
}

/// Simplex final signatures over the official nested TL transcript.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ton_native::TonSimplexBlockSignaturesV1")]
pub struct TonSimplexBlockSignaturesV1 {
    /// Native catchain sequence number.
    pub catchain_seqno: u32,
    /// Native validator-list hash.
    pub validator_list_hash_short: u32,
    /// Simplex session identifier.
    #[norito(with = "crate::json_utils::hex32")]
    pub session_id: H256,
    /// Simplex slot in this session.
    pub slot: u32,
    /// Exact boxed TL `consensus.CandidateHashData` bytes.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub candidate_data: Vec<u8>,
    /// Strictly node-id-ordered unique native final signatures.
    pub signatures: Vec<TonValidatorSignatureV1>,
}

/// Closed native TON block-signature transcript.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "finality", content = "signatures", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::ton_native::TonBlockSignaturesV1")]
pub enum TonBlockSignaturesV1 {
    /// Ordinary catchain final signatures.
    Ordinary(TonOrdinaryBlockSignaturesV1),
    /// Simplex finalize-vote signatures.
    Simplex(TonSimplexBlockSignaturesV1),
}

/// Fail-closed native TON verification error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TonNativeSourceError {
    /// The exact network identity was wrong.
    WrongNetwork,
    /// Proof framing exceeded a deterministic resource cap.
    ResourceLimit,
    /// A `BoC` was malformed, noncanonical, unsupported, or not rooted as claimed.
    InvalidBoc,
    /// A masterchain block id or header, or an `OldMcBlocksInfo` back-link, did not match.
    BrokenMasterchainLink,
    /// The active validator roster or its native hash was invalid.
    InvalidValidatorSet,
    /// A key-block validator transition was absent or unauthenticated.
    InvalidValidatorTransition,
    /// Native final signatures were malformed, duplicated, unknown, or below quorum.
    InvalidSignatures,
    /// Simplex candidate data or its official transcript was malformed or selected another block.
    InvalidSimplexTranscript,
    /// The finalized masterchain block did not authenticate the claimed shard block.
    ShardNotFinalized,
    /// The selected account block or transaction was absent or malformed.
    InvalidTransaction,
    /// Transaction compute/action phases did not complete successfully.
    UnsuccessfulTransaction,
    /// The selected outbound message was absent, bounced, or not emitted by the source bridge.
    InvalidOutboundMessage,
}

impl fmt::Display for TonNativeSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongNetwork => "native TON network identity mismatch",
            Self::ResourceLimit => "native TON proof exceeds a resource limit",
            Self::InvalidBoc => "invalid or unsupported TON BoC",
            Self::BrokenMasterchainLink => "broken TON masterchain block link",
            Self::InvalidValidatorSet => "invalid TON validator set",
            Self::InvalidValidatorTransition => "unauthenticated TON validator-set transition",
            Self::InvalidSignatures => "invalid TON finality signatures",
            Self::InvalidSimplexTranscript => "invalid TON Simplex finality transcript",
            Self::ShardNotFinalized => "TON shard block is not finalized by the masterchain",
            Self::InvalidTransaction => "invalid TON source transaction",
            Self::UnsuccessfulTransaction => "TON source transaction did not succeed",
            Self::InvalidOutboundMessage => "invalid TON source outbound message",
        })
    }
}

impl std::error::Error for TonNativeSourceError {}

fn nonzero(hash: &H256) -> bool {
    hash.iter().any(|byte| *byte != 0)
}

fn valid_block_id(block: TonBlockIdExtV1) -> bool {
    block.seqno != 0 && nonzero(&block.root_hash) && nonzero(&block.file_hash)
}

fn push_i32_le(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
std::thread_local! {
    static TON_ROSTER_KEY_PARSE_COUNT: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

fn parse_ton_validator_public_key(public_key: &H256) -> Option<()> {
    #[cfg(test)]
    TON_ROSTER_KEY_PARSE_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    iroha_crypto::ed25519_parse_public_key(public_key).ok()?;
    Some(())
}

/// Return the native short node id of one strict Ed25519 validator key.
pub fn ton_validator_node_id_short_v1(public_key: &H256) -> Option<H256> {
    parse_ton_validator_public_key(public_key)?;
    Some(ton_validator_node_id_short_from_validated(public_key))
}

fn ton_validator_node_id_short_from_validated(public_key: &H256) -> H256 {
    let mut boxed = Vec::with_capacity(36);
    push_u32_le(&mut boxed, TON_PUB_ED25519_TL_CONSTRUCTOR);
    boxed.extend_from_slice(public_key);
    Sha256::digest(&boxed).into()
}

/// Reproduce TON's native CRC32C validator-list hash exactly.
pub fn ton_validator_list_hash_short_v1(
    catchain_seqno: u32,
    validators: &[TonValidatorV1],
) -> Option<u32> {
    validate_validator_roster(validators)?;
    ton_validator_list_hash_short_from_validated(catchain_seqno, validators)
}

fn ton_validator_list_hash_short_from_validated(
    catchain_seqno: u32,
    validators: &[TonValidatorV1],
) -> Option<u32> {
    let mut bytes = Vec::with_capacity(12usize.checked_add(validators.len().checked_mul(72)?)?);
    push_i32_le(&mut bytes, -1_877_581_587);
    push_u32_le(&mut bytes, catchain_seqno);
    push_u32_le(&mut bytes, u32::try_from(validators.len()).ok()?);
    for validator in validators {
        bytes.extend_from_slice(&validator.public_key);
        push_u64_le(&mut bytes, validator.weight);
        bytes.extend_from_slice(&validator.adnl_address);
    }
    Some(ton_crc32c(&bytes))
}

fn validate_validator_roster(validators: &[TonValidatorV1]) -> Option<u64> {
    if validators.is_empty() || validators.len() > TON_MAX_VALIDATORS {
        return None;
    }
    let mut keys = BTreeSet::new();
    let mut node_ids = BTreeSet::new();
    let mut adnl = BTreeSet::new();
    let mut total = 0_u64;
    for validator in validators {
        if validator.weight == 0 || !keys.insert(validator.public_key) {
            return None;
        }
        // `validator#53` has no ADNL field and the reference implementation
        // hashes an all-zero address for it. Nonzero ADNL identities, when
        // present, must still be unique.
        if nonzero(&validator.adnl_address) && !adnl.insert(validator.adnl_address) {
            return None;
        }
        parse_ton_validator_public_key(&validator.public_key)?;
        let node_id = ton_validator_node_id_short_from_validated(&validator.public_key);
        if !node_ids.insert(node_id) {
            return None;
        }
        total = total.checked_add(validator.weight)?;
    }
    (total != 0 && total <= TON_MAX_TOTAL_VALIDATOR_WEIGHT).then_some(total)
}

fn validate_active_validator_set(set: &TonValidatorSetV1) -> Option<u64> {
    let total = validate_validator_roster(&set.validators)?;
    (ton_validator_list_hash_short_from_validated(set.catchain_seqno, &set.validators)?
        == set.validator_list_hash_short)
        .then_some(total)
}

fn validate_validator_config(config: &TonValidatorConfigV1) -> Option<()> {
    if config.valid_since >= config.valid_until
        || config.main_validator_count == 0
        || usize::from(config.main_validator_count) > config.validators.len()
    {
        return None;
    }
    validate_validator_roster(&config.validators)?;
    Some(())
}

/// Serialize the boxed TL block identifier from its root and file hashes.
pub fn ton_block_id_tl_bytes(block: TonBlockIdExtV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    push_u32_le(&mut out, TON_BLOCK_ID_TL_CONSTRUCTOR);
    out.extend_from_slice(&block.root_hash);
    out.extend_from_slice(&block.file_hash);
    out
}

fn push_tl_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let len = bytes.len();
    if len < 254 {
        out.push(u8::try_from(len).ok()?);
        out.extend_from_slice(bytes);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        return Some(());
    }
    if len > 0x00ff_ffff {
        return None;
    }
    out.push(254);
    out.push(u8::try_from(len & 0xff).ok()?);
    out.push(u8::try_from((len >> 8) & 0xff).ok()?);
    out.push(u8::try_from((len >> 16) & 0xff).ok()?);
    out.extend_from_slice(bytes);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    Some(())
}

struct TlCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TlCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.offset.checked_add(N)?;
        let value = self.bytes.get(self.offset..end)?.try_into().ok()?;
        self.offset = end;
        Some(value)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take()?))
    }

    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take()?))
    }

    fn h256(&mut self) -> Option<H256> {
        self.take()
    }

    fn exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn parse_tl_block_id_ext_bare(cursor: &mut TlCursor<'_>) -> Option<TonBlockIdExtV1> {
    Some(TonBlockIdExtV1 {
        workchain: cursor.i32()?,
        shard: cursor.u64()?,
        seqno: cursor.u32()?,
        root_hash: cursor.h256()?,
        file_hash: cursor.h256()?,
    })
}

fn parse_tl_candidate_id(cursor: &mut TlCursor<'_>) -> Option<()> {
    (cursor.u32()? == TON_CONSENSUS_CANDIDATE_ID_TL_CONSTRUCTOR).then_some(())?;
    (cursor.i32()? >= 0).then_some(())?;
    cursor.h256()?;
    Some(())
}

fn parse_simplex_candidate_data(bytes: &[u8]) -> Option<TonBlockIdExtV1> {
    let mut cursor = TlCursor::new(bytes);
    let constructor = cursor.u32()?;
    // The schema spells this field `block:tonNode.blockIdExt`; lower-case
    // constructor names are bare in TL, so the nested block carries no
    // `tonNode.blockIdExt` constructor id.
    let block = parse_tl_block_id_ext_bare(&mut cursor)?;
    match constructor {
        TON_CONSENSUS_CANDIDATE_ORDINARY_TL_CONSTRUCTOR => {
            cursor.h256()?;
            match cursor.u32()? {
                TON_CONSENSUS_CANDIDATE_PARENT_TL_CONSTRUCTOR => {
                    parse_tl_candidate_id(&mut cursor)?;
                }
                TON_CONSENSUS_CANDIDATE_WITHOUT_PARENTS_TL_CONSTRUCTOR => {}
                _ => return None,
            }
        }
        TON_CONSENSUS_CANDIDATE_EMPTY_TL_CONSTRUCTOR => {
            // `parent:consensus.candidateId` is likewise a bare field.
            (cursor.i32()? >= 0).then_some(())?;
            cursor.h256()?;
        }
        _ => return None,
    }
    cursor.exhausted().then_some(block)
}

fn simplex_finality_transcript(
    block: TonBlockIdExtV1,
    signatures: &TonSimplexBlockSignaturesV1,
) -> Option<Vec<u8>> {
    if signatures.slot > i32::MAX.cast_unsigned()
        || signatures.candidate_data.is_empty()
        || signatures.candidate_data.len() > 4 * 1024
        || parse_simplex_candidate_data(&signatures.candidate_data)? != block
        || !nonzero(&signatures.session_id)
    {
        return None;
    }
    let candidate_hash: H256 = Sha256::digest(&signatures.candidate_data).into();
    let mut candidate_id = Vec::with_capacity(40);
    push_u32_le(&mut candidate_id, TON_CONSENSUS_CANDIDATE_ID_TL_CONSTRUCTOR);
    push_u32_le(&mut candidate_id, signatures.slot);
    candidate_id.extend_from_slice(&candidate_hash);
    let mut finalize_vote = Vec::with_capacity(44);
    push_u32_le(
        &mut finalize_vote,
        TON_CONSENSUS_SIMPLEX_FINALIZE_TL_CONSTRUCTOR,
    );
    finalize_vote.extend_from_slice(&candidate_id);
    let mut transcript = Vec::with_capacity(84);
    push_u32_le(&mut transcript, TON_CONSENSUS_DATA_TO_SIGN_TL_CONSTRUCTOR);
    transcript.extend_from_slice(&signatures.session_id);
    push_tl_bytes(&mut transcript, &finalize_vote)?;
    Some(transcript)
}

fn ton_block_signatures_are_canonically_ordered(signatures: &TonBlockSignaturesV1) -> bool {
    let entries = match signatures {
        TonBlockSignaturesV1::Ordinary(proof) => proof.signatures.as_slice(),
        TonBlockSignaturesV1::Simplex(proof) => proof.signatures.as_slice(),
    };
    entries
        .windows(2)
        .all(|pair| pair[0].node_id_short < pair[1].node_id_short)
}

fn verify_block_signatures(
    block: TonBlockIdExtV1,
    active: &TonValidatorSetV1,
    signatures: &TonBlockSignaturesV1,
) -> Result<(), TonNativeSourceError> {
    let total_weight =
        validate_active_validator_set(active).ok_or(TonNativeSourceError::InvalidValidatorSet)?;
    let (catchain_seqno, validator_hash, entries, transcript) = match signatures {
        TonBlockSignaturesV1::Ordinary(proof) => (
            proof.catchain_seqno,
            proof.validator_list_hash_short,
            proof.signatures.as_slice(),
            ton_block_id_tl_bytes(block),
        ),
        TonBlockSignaturesV1::Simplex(proof) => (
            proof.catchain_seqno,
            proof.validator_list_hash_short,
            proof.signatures.as_slice(),
            simplex_finality_transcript(block, proof)
                .ok_or(TonNativeSourceError::InvalidSimplexTranscript)?,
        ),
    };
    if catchain_seqno != active.catchain_seqno
        || validator_hash != active.validator_list_hash_short
        || entries.is_empty()
        || entries.len() > TON_MAX_SIGNATURES
        || !ton_block_signatures_are_canonically_ordered(signatures)
    {
        return Err(TonNativeSourceError::InvalidSignatures);
    }
    let by_node = active
        .validators
        .iter()
        .map(|validator| {
            (
                ton_validator_node_id_short_from_validated(&validator.public_key),
                validator,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut signed_weight = 0_u64;
    let mut raw_signatures = Vec::<&[u8]>::with_capacity(entries.len());
    let mut raw_keys = Vec::<&[u8]>::with_capacity(entries.len());
    let mut messages = Vec::<&[u8]>::with_capacity(entries.len());
    for signature in entries {
        if signature.signature.len() != 64 || !seen.insert(signature.node_id_short) {
            return Err(TonNativeSourceError::InvalidSignatures);
        }
        let validator = by_node
            .get(&signature.node_id_short)
            .copied()
            .ok_or(TonNativeSourceError::InvalidSignatures)?;
        signed_weight = signed_weight
            .checked_add(validator.weight)
            .ok_or(TonNativeSourceError::InvalidSignatures)?;
        raw_signatures.push(signature.signature.as_slice());
        raw_keys.push(validator.public_key.as_slice());
        messages.push(transcript.as_slice());
    }
    if u128::from(signed_weight) * 3 <= u128::from(total_weight) * 2 {
        return Err(TonNativeSourceError::InvalidSignatures);
    }
    // Signer keys are decoded only by the batch verifier, which
    // `ed25519_signature_checks` charges; roster parsing above only hashes.
    iroha_crypto::ed25519_verify_batch_deterministic(&messages, &raw_signatures, &raw_keys)
        .map_err(|_| TonNativeSourceError::InvalidSignatures)
}

fn ton_crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

/// One raw `BoC` cell: descriptors, data bytes and child indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TonBocCell {
    pub(crate) descriptor: u8,
    pub(crate) data_descriptor: u8,
    pub(crate) data: Vec<u8>,
    pub(crate) refs: Vec<usize>,
    pub(crate) exotic: bool,
}

/// A parsed `BoC`: root indices and cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TonBoc {
    pub(crate) roots: Vec<usize>,
    pub(crate) cells: Vec<TonBocCell>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TonCellStructuralKey {
    descriptor: u8,
    data_descriptor: u8,
    data: Vec<u8>,
    child_classes: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TonCellType {
    Ordinary,
    PrunedBranch,
    MerkleProof,
    MerkleUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TonPrunedBranch {
    mask: u8,
    hashes: Vec<H256>,
    depths: Vec<u16>,
}

/// Level mask, hashes and depths of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TonComputedCell {
    pub(crate) mask: u8,
    pub(crate) hashes: [H256; 4],
    pub(crate) depths: [u16; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TonBitReader<'a> {
    cell: &'a TonBocCell,
    bit_len: usize,
    bit_offset: usize,
    ref_offset: usize,
}

fn ton_read_sized_uint(bytes: &[u8], cursor: &mut usize, size: usize) -> Option<usize> {
    if !(1..=8).contains(&size) {
        return None;
    }
    let end = cursor.checked_add(size)?;
    let mut value = 0_usize;
    for byte in bytes.get(*cursor..end)? {
        value = value.checked_shl(8)?.checked_add(usize::from(*byte))?;
    }
    *cursor = end;
    Some(value)
}

/// Read the payload bit length, rejecting inconsistent descriptors or terminator bits.
pub fn ton_cell_serialized_bit_len(data_descriptor: u8, data: &[u8]) -> Option<usize> {
    if data_descriptor & 1 == 0 {
        let byte_len = usize::from(data_descriptor) / 2;
        return (byte_len == data.len()).then_some(byte_len.checked_mul(8)?);
    }
    let full_bytes = usize::from(data_descriptor).checked_add(1)? / 2;
    let floor_bytes = usize::from(data_descriptor) / 2;
    if full_bytes != data.len() || floor_bytes.checked_add(1)? != full_bytes {
        return None;
    }
    let last = *data.last()?;
    if last == 0 {
        return None;
    }
    let tail_bits = 7_usize.checked_sub(usize::try_from(last.trailing_zeros()).ok()?)?;
    floor_bytes.checked_mul(8)?.checked_add(tail_bits)
}

impl<'a> TonBitReader<'a> {
    fn new(cell: &'a TonBocCell) -> Option<Self> {
        Some(Self {
            cell,
            bit_len: ton_cell_serialized_bit_len(cell.data_descriptor, &cell.data)?,
            bit_offset: 0,
            ref_offset: 0,
        })
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.bit_offset >= self.bit_len {
            return None;
        }
        let byte = *self.cell.data.get(self.bit_offset / 8)?;
        let shift = 7_usize.checked_sub(self.bit_offset % 8)?;
        self.bit_offset = self.bit_offset.checked_add(1)?;
        Some(((byte >> shift) & 1) != 0)
    }

    fn read_u64(&mut self, bits: usize) -> Option<u64> {
        if bits > 64 {
            return None;
        }
        let mut value = 0_u64;
        for _ in 0..bits {
            value = value.checked_shl(1)?;
            if self.read_bit()? {
                value = value.checked_add(1)?;
            }
        }
        Some(value)
    }

    fn read_usize(&mut self, bits: usize) -> Option<usize> {
        usize::try_from(self.read_u64(bits)?).ok()
    }

    fn read_i32(&mut self, bits: usize) -> Option<i32> {
        if bits == 0 || bits > 32 {
            return None;
        }
        let raw = u32::try_from(self.read_u64(bits)?).ok()?;
        if bits == 32 {
            return Some(i32::from_be_bytes(raw.to_be_bytes()));
        }
        let sign = 1_u32 << (bits - 1);
        let extended = if raw & sign == 0 {
            raw
        } else {
            raw | (!0_u32 << bits)
        };
        Some(i32::from_be_bytes(extended.to_be_bytes()))
    }

    fn read_h256(&mut self) -> Option<H256> {
        let mut out = [0_u8; 32];
        for byte in &mut out {
            *byte = u8::try_from(self.read_u64(8)?).ok()?;
        }
        Some(out)
    }

    fn skip_bits(&mut self, bits: usize) -> Option<()> {
        if self.remaining_bits()? < bits {
            return None;
        }
        self.bit_offset = self.bit_offset.checked_add(bits)?;
        Some(())
    }

    fn read_ref(&mut self) -> Option<usize> {
        let index = *self.cell.refs.get(self.ref_offset)?;
        self.ref_offset = self.ref_offset.checked_add(1)?;
        Some(index)
    }

    fn remaining_bits(&self) -> Option<usize> {
        self.bit_len.checked_sub(self.bit_offset)
    }

    fn remaining_refs(&self) -> Option<usize> {
        self.cell.refs.len().checked_sub(self.ref_offset)
    }

    fn exhausted(&self) -> bool {
        self.remaining_bits() == Some(0) && self.remaining_refs() == Some(0)
    }
}

fn ton_cell_type(cell: &TonBocCell) -> Option<TonCellType> {
    if !cell.exotic {
        return Some(TonCellType::Ordinary);
    }
    match *cell.data.first()? {
        1 => Some(TonCellType::PrunedBranch),
        3 => Some(TonCellType::MerkleProof),
        4 => Some(TonCellType::MerkleUpdate),
        _ => None,
    }
}

fn ton_level_mask_value(mask: u8) -> u8 {
    mask & 0x07
}

fn ton_level_mask_level(mask: u8) -> u8 {
    let mask = ton_level_mask_value(mask);
    if mask == 0 {
        0
    } else {
        8 - u8::try_from(mask.leading_zeros()).expect("u8 leading-zero count fits")
    }
}

fn ton_level_mask_hash_index(mask: u8) -> usize {
    usize::try_from(ton_level_mask_value(mask).count_ones()).expect("three-bit popcount fits")
}

fn ton_level_mask_apply(mask: u8, level: u8) -> u8 {
    if level == 0 {
        0
    } else {
        ton_level_mask_value(mask) & ((1_u8 << level) - 1)
    }
}

fn ton_level_mask_is_significant(mask: u8, level: u8) -> bool {
    level == 0 || ((ton_level_mask_value(mask) >> (level - 1)) & 1) != 0
}

fn ton_child_hash_depth(computed: &TonComputedCell, level: u8) -> Option<(H256, u16)> {
    let index = usize::from(level.min(3));
    let depth = *computed.depths.get(index)?;
    (depth <= TON_MAX_CELL_DEPTH).then_some((*computed.hashes.get(index)?, depth))
}

fn ton_parse_pruned_branch(cell: &TonBocCell) -> Option<TonPrunedBranch> {
    if cell.data_descriptor & 1 != 0
        || usize::from(cell.data_descriptor) / 2 != cell.data.len()
        || !cell.refs.is_empty()
        || cell.data.len() < 2
        || cell.data.first().copied()? != 1
    {
        return None;
    }
    if cell.data.len() == 35 {
        let depth = u16::from_be_bytes(cell.data.get(33..35)?.try_into().ok()?);
        if depth > TON_MAX_CELL_DEPTH {
            return None;
        }
        return Some(TonPrunedBranch {
            mask: 1,
            hashes: vec![cell.data.get(1..33)?.try_into().ok()?],
            depths: vec![depth],
        });
    }
    let raw_mask = *cell.data.get(1)?;
    if raw_mask & !0x07 != 0 {
        return None;
    }
    let mask = raw_mask;
    let level = ton_level_mask_level(mask);
    if !(1..=3).contains(&level) {
        return None;
    }
    let count = ton_level_mask_hash_index(mask);
    if cell.data.len() != 2_usize.checked_add(count.checked_mul(34)?)? {
        return None;
    }
    let mut hashes = Vec::with_capacity(count);
    for index in 0..count {
        let start = 2_usize.checked_add(index.checked_mul(32)?)?;
        hashes.push(
            cell.data
                .get(start..start.checked_add(32)?)?
                .try_into()
                .ok()?,
        );
    }
    let depths_start = 2_usize.checked_add(count.checked_mul(32)?)?;
    let mut depths = Vec::with_capacity(count);
    for index in 0..count {
        let start = depths_start.checked_add(index.checked_mul(2)?)?;
        let depth = u16::from_be_bytes(
            cell.data
                .get(start..start.checked_add(2)?)?
                .try_into()
                .ok()?,
        );
        if depth > TON_MAX_CELL_DEPTH {
            return None;
        }
        depths.push(depth);
    }
    Some(TonPrunedBranch {
        mask,
        hashes,
        depths,
    })
}

/// Parse a bounded `BoC` header and cell table, or `None` when it is malformed.
/// Parse a bounded TON bag of cells, rejecting malformed headers, cells and references.
pub fn parse_ton_boc(bytes: &[u8]) -> Option<TonBoc> {
    if bytes.len() < 6 || bytes.len() > TON_MAX_BOC_BYTES || bytes.get(..4)? != TON_BOC_MAGIC {
        return None;
    }
    let mut cursor = 4_usize;
    let flags_size = *bytes.get(cursor)?;
    cursor += 1;
    let has_index = flags_size & 0x80 != 0;
    let has_crc32c = flags_size & 0x40 != 0;
    let has_cache_bits = flags_size & 0x20 != 0;
    let flags = (flags_size >> 3) & 0x03;
    let size_bytes = usize::from(flags_size & 0x07);
    let offset_bytes = usize::from(*bytes.get(cursor)?);
    cursor += 1;
    // Cache bits annotate index entries (liteserver `getBlock` sets them); they need an index.
    if (has_cache_bits && !has_index)
        || flags != 0
        || !(1..=4).contains(&size_bytes)
        || !(1..=8).contains(&offset_bytes)
    {
        return None;
    }
    let cells_count = ton_read_sized_uint(bytes, &mut cursor, size_bytes)?;
    let roots_count = ton_read_sized_uint(bytes, &mut cursor, size_bytes)?;
    let absent_count = ton_read_sized_uint(bytes, &mut cursor, size_bytes)?;
    let total_cells_size = ton_read_sized_uint(bytes, &mut cursor, offset_bytes)?;
    if cells_count == 0 || cells_count > TON_MAX_BOC_CELLS || roots_count != 1 || absent_count != 0
    {
        return None;
    }
    let root = ton_read_sized_uint(bytes, &mut cursor, size_bytes)?;
    if root >= cells_count {
        return None;
    }
    let roots = vec![root];
    let index_offsets = if has_index {
        let mut offsets = Vec::with_capacity(cells_count);
        let mut previous = 0_usize;
        for index in 0..cells_count {
            let entry = ton_read_sized_uint(bytes, &mut cursor, offset_bytes)?;
            // With cache bits, each entry is `offset · 2 + cache flag`.
            let offset = if has_cache_bits { entry >> 1 } else { entry };
            if offset < previous || offset > total_cells_size {
                return None;
            }
            if index + 1 == cells_count && offset != total_cells_size {
                return None;
            }
            previous = offset;
            offsets.push(offset);
        }
        Some(offsets)
    } else {
        None
    };
    let cell_data_start = cursor;
    let cell_data_end = cell_data_start.checked_add(total_cells_size)?;
    let expected_end = cell_data_end.checked_add(if has_crc32c { 4 } else { 0 })?;
    if expected_end != bytes.len() {
        return None;
    }
    if has_crc32c {
        let expected = ton_crc32c(bytes.get(..cell_data_end)?).to_le_bytes();
        if bytes.get(cell_data_end..expected_end)? != expected {
            return None;
        }
    }
    let cell_data = bytes.get(cell_data_start..cell_data_end)?;
    let mut cell_cursor = 0_usize;
    let mut cells = Vec::with_capacity(cells_count);
    for cell_index in 0..cells_count {
        let descriptor = *cell_data.get(cell_cursor)?;
        cell_cursor += 1;
        let data_descriptor = *cell_data.get(cell_cursor)?;
        cell_cursor += 1;
        let refs_count = usize::from(descriptor & 0x07);
        let exotic = descriptor & 0x08 != 0;
        let has_hashes = descriptor & 0x10 != 0;
        let data_bytes = usize::from(data_descriptor).checked_add(1)? / 2;
        if refs_count > TON_MAX_REFS || data_bytes > TON_MAX_CELL_DATA_BYTES {
            return None;
        }
        if has_hashes {
            // Liteservers may serialize cached hashes and depths (one per significant level).
            // They are skipped: every hash is recomputed from the cell contents, and the
            // canonical form never carries them.
            let levels = usize::try_from((descriptor >> 5).count_ones()).ok()? + 1;
            cell_cursor = cell_cursor.checked_add(levels.checked_mul(32 + 2)?)?;
        }
        let data_end = cell_cursor.checked_add(data_bytes)?;
        let data = cell_data.get(cell_cursor..data_end)?.to_vec();
        ton_cell_serialized_bit_len(data_descriptor, &data)?;
        cell_cursor = data_end;
        let mut refs = Vec::with_capacity(refs_count);
        for _ in 0..refs_count {
            let reference = ton_read_sized_uint(cell_data, &mut cell_cursor, size_bytes)?;
            if reference >= cells_count || reference <= cell_index {
                return None;
            }
            refs.push(reference);
        }
        if index_offsets
            .as_ref()
            .is_some_and(|offsets| offsets.get(cell_index) != Some(&cell_cursor))
        {
            return None;
        }
        cells.push(TonBocCell {
            descriptor: descriptor & !0x10,
            data_descriptor,
            data,
            refs,
            exotic,
        });
    }
    (cell_cursor == cell_data.len()).then_some(TonBoc { roots, cells })
}

fn ton_minimum_sized_uint_bytes(value: usize) -> usize {
    let significant_bits =
        usize::try_from(usize::BITS - value.leading_zeros()).expect("usize bit width fits usize");
    significant_bits.div_ceil(8).max(1)
}

fn ton_write_sized_uint(out: &mut Vec<u8>, value: usize, size: usize) -> Option<()> {
    if !(1..=8).contains(&size) || ton_minimum_sized_uint_bytes(value) > size {
        return None;
    }
    let encoded = u64::try_from(value).ok()?.to_be_bytes();
    out.extend_from_slice(encoded.get(8_usize.checked_sub(size)?..)?);
    Some(())
}

fn ton_canonical_cell_order(boc: &TonBoc, root: usize) -> Option<Vec<usize>> {
    fn visit(
        boc: &TonBoc,
        index: usize,
        visiting: &mut [bool],
        visited: &mut [bool],
        postorder: &mut Vec<usize>,
    ) -> Option<()> {
        if *visited.get(index)? {
            return Some(());
        }
        if *visiting.get(index)? {
            return None;
        }
        *visiting.get_mut(index)? = true;
        for reference in boc.cells.get(index)?.refs.iter().rev() {
            visit(boc, *reference, visiting, visited, postorder)?;
        }
        *visiting.get_mut(index)? = false;
        *visited.get_mut(index)? = true;
        postorder.push(index);
        Some(())
    }

    let mut visiting = vec![false; boc.cells.len()];
    let mut visited = vec![false; boc.cells.len()];
    let mut postorder = Vec::with_capacity(boc.cells.len());
    visit(boc, root, &mut visiting, &mut visited, &mut postorder)?;
    if visited.iter().any(|seen| !seen) {
        return None;
    }
    postorder.reverse();
    (postorder.first() == Some(&root)).then_some(postorder)
}

fn ton_reject_duplicate_subgraphs(boc: &TonBoc) -> Option<()> {
    let mut class_by_cell = vec![0_usize; boc.cells.len()];
    let mut classes = BTreeMap::<TonCellStructuralKey, usize>::new();
    for index in (0..boc.cells.len()).rev() {
        let cell = boc.cells.get(index)?;
        let key = TonCellStructuralKey {
            descriptor: cell.descriptor,
            data_descriptor: cell.data_descriptor,
            data: cell.data.clone(),
            child_classes: cell
                .refs
                .iter()
                .map(|reference| class_by_cell.get(*reference).copied())
                .collect::<Option<Vec<_>>>()?,
        };
        let class = classes.len().checked_add(1)?;
        if classes.insert(key, class).is_some() {
            // Canonical BoCs share one cell for one structural subtree. Two
            // byte-identical subgraphs would otherwise give the same TON root
            // while changing the observation proof bytes and CAS digest.
            return None;
        }
        *class_by_cell.get_mut(index)? = class;
    }
    Some(())
}

/// Encode the selected root in canonical cell order, rejecting invalid or duplicate subgraphs.
pub fn encode_canonical_ton_boc(boc: &TonBoc, root: usize) -> Option<Vec<u8>> {
    let order = ton_canonical_cell_order(boc, root)?;
    ton_reject_duplicate_subgraphs(boc)?;
    let mut canonical_index = vec![usize::MAX; boc.cells.len()];
    for (index, old_index) in order.iter().copied().enumerate() {
        *canonical_index.get_mut(old_index)? = index;
    }
    let size_bytes = ton_minimum_sized_uint_bytes(order.len());
    if size_bytes > 4 {
        return None;
    }
    let mut cell_data = Vec::new();
    for old_index in &order {
        let cell = boc.cells.get(*old_index)?;
        if usize::from(cell.descriptor & 0x07) != cell.refs.len()
            || (cell.descriptor & 0x08 != 0) != cell.exotic
            || cell.descriptor & 0x10 != 0
            || cell.data_descriptor & 1 != 0 && cell.data.last() == Some(&0x80)
        {
            return None;
        }
        if ton_cell_type(cell)? == TonCellType::PrunedBranch && cell.data.len() == 35 {
            // The historical implicit-mask form is representation-malleable
            // with the explicit final-V1 pruned-branch encoding.
            return None;
        }
        cell_data.push(cell.descriptor);
        cell_data.push(cell.data_descriptor);
        cell_data.extend_from_slice(&cell.data);
        for reference in &cell.refs {
            let mapped = *canonical_index.get(*reference)?;
            if mapped == usize::MAX || mapped <= *canonical_index.get(*old_index)? {
                return None;
            }
            let encoded = u64::try_from(mapped).ok()?.to_be_bytes();
            cell_data.extend_from_slice(encoded.get(8_usize.checked_sub(size_bytes)?..)?);
        }
    }
    let offset_bytes = ton_minimum_sized_uint_bytes(cell_data.len());
    if offset_bytes > 8 {
        return None;
    }
    let mut out = Vec::with_capacity(
        6_usize
            .checked_add(size_bytes.checked_mul(3)?)?
            .checked_add(offset_bytes)?
            .checked_add(size_bytes)?
            .checked_add(cell_data.len())?,
    );
    out.extend_from_slice(&TON_BOC_MAGIC);
    out.push(u8::try_from(size_bytes).ok()?); // no index, CRC, cache bits, or flags
    out.push(u8::try_from(offset_bytes).ok()?);
    ton_write_sized_uint(&mut out, order.len(), size_bytes)?;
    ton_write_sized_uint(&mut out, 1, size_bytes)?;
    ton_write_sized_uint(&mut out, 0, size_bytes)?;
    ton_write_sized_uint(&mut out, cell_data.len(), offset_bytes)?;
    ton_write_sized_uint(&mut out, 0, size_bytes)?; // canonical root is cell zero
    out.extend_from_slice(&cell_data);
    Some(out)
}

fn parse_canonical_single_root_boc(bytes: &[u8]) -> Option<(TonBoc, Vec<TonComputedCell>, usize)> {
    let boc = parse_ton_boc(bytes)?;
    let root = *boc.roots.first()?;
    if boc.roots.len() != 1 || root != 0 {
        return None;
    }
    match ton_cell_type(boc.cells.get(root)?)? {
        TonCellType::Ordinary => {}
        TonCellType::MerkleProof => {
            let child = *boc.cells.get(root)?.refs.first()?;
            if ton_cell_type(boc.cells.get(child)?)? != TonCellType::Ordinary {
                return None;
            }
        }
        TonCellType::PrunedBranch | TonCellType::MerkleUpdate => return None,
    }
    for (index, cell) in boc.cells.iter().enumerate() {
        if index != root && ton_cell_type(cell)? == TonCellType::MerkleProof {
            // A proof envelope has one root wrapper at most. Native block
            // MerkleUpdate cells remain valid typed block content.
            return None;
        }
    }
    // Validate descriptors, exotic payloads, and the 1,024-cell depth bound
    // iteratively before the canonical-order DFS. This prevents a deeply
    // nested hostile BOC from reaching recursive canonicalization first.
    let computed = ton_boc_cell_hashes(&boc)?;
    if encode_canonical_ton_boc(&boc, root)?.as_slice() != bytes {
        return None;
    }
    Some((boc, computed, root))
}

/// Re-encode a single-root `BoC` (any serialization flags) in the canonical proof form the
/// light client accepts: checksum-free, unindexed, minimal widths, root index zero.
#[must_use]
pub fn ton_canonical_boc_v1(bytes: &[u8]) -> Option<Vec<u8>> {
    let boc = parse_ton_boc(bytes)?;
    if boc.roots.len() != 1 {
        return None;
    }
    ton_boc_cell_hashes(&boc)?;
    encode_canonical_ton_boc(&boc, *boc.roots.first()?)
}

/// The payload of the `sccp_transfer_to_taira` external-out message `message_index` of
/// `minter`'s transaction `transaction_boc` at `transaction_lt` (wallets read the burned payload
/// they claim from it; the light client re-verifies everything).
#[must_use]
pub fn ton_sccp_transfer_payload_v1(
    transaction_boc: &[u8],
    minter: H256,
    transaction_lt: u64,
    message_index: u16,
) -> Option<Vec<u8>> {
    let (boc, _computed, root) = parse_single_root_boc(transaction_boc)?;
    let transaction = ton_parse_transaction(&boc, root, minter, transaction_lt)?;
    let message = ton_transaction_out_message(&boc, transaction, message_index)?;
    match ton_parse_sccp_ext_out(&boc, message, &minter)? {
        TonSccpEventV1::TransferToTaira { payload, .. } => Some(payload),
        TonSccpEventV1::Voided { .. } => None,
    }
}

/// Seqno, key-block flag and `prev_key_block_seqno` of a masterchain block header proof
/// (builders; the proof must be canonical, see [`ton_canonical_boc_v1`]).
#[must_use]
pub fn ton_header_key_block_v1(header_proof: &[u8]) -> Option<(u32, bool, u32)> {
    let (boc, computed, root) = parse_canonical_single_root_boc(header_proof)?;
    let info = ton_parse_block(&boc, &computed, root)?.info;
    Some((info.seqno, info.key_block, info.prev_key_block_seqno))
}

/// Derive the authenticated root hash only when a proof `BoC` has the one
/// canonical final-V1 byte representation.
///
/// Canonical proof `BoC`s are single-root, unindexed, checksum-free, use minimal
/// integer widths and root index zero, contain no unreachable or duplicate
/// structural subgraphs, and admit at most one root Merkle-proof wrapper.
#[must_use]
pub fn ton_canonical_boc_single_root_hash_v1(bytes: &[u8]) -> Option<H256> {
    let (boc, computed, root) = parse_canonical_single_root_boc(bytes)?;
    ton_proven_root_hash(&boc, &computed, root)
}

fn ton_boc_child_for_hash_level(
    cell_type: TonCellType,
    computed: &TonComputedCell,
    level: u8,
) -> Option<(H256, u16)> {
    let child_level = match cell_type {
        TonCellType::MerkleProof | TonCellType::MerkleUpdate => level.checked_add(1)?,
        TonCellType::Ordinary | TonCellType::PrunedBranch => level,
    };
    ton_child_hash_depth(computed, child_level)
}

/// Compute every cell's level mask, per-level hashes and depths bottom-up.
/// Compute the level hashes and depths of every cell, rejecting invalid cell structure.
pub fn ton_boc_cell_hashes(boc: &TonBoc) -> Option<Vec<TonComputedCell>> {
    let empty = TonComputedCell {
        mask: 0,
        hashes: [[0_u8; 32]; 4],
        depths: [0_u16; 4],
    };
    let mut computed = vec![empty; boc.cells.len()];
    for index in (0..boc.cells.len()).rev() {
        let cell = boc.cells.get(index)?;
        let cell_type = ton_cell_type(cell)?;
        let pruned = match cell_type {
            TonCellType::PrunedBranch => Some(ton_parse_pruned_branch(cell)?),
            _ => None,
        };
        let mask = match cell_type {
            TonCellType::Ordinary => cell.refs.iter().try_fold(0_u8, |mask, reference| {
                Some(mask | computed.get(*reference)?.mask)
            })?,
            TonCellType::PrunedBranch => pruned.as_ref()?.mask,
            TonCellType::MerkleProof => {
                if cell.data_descriptor & 1 != 0 || cell.data.len() != 35 || cell.refs.len() != 1 {
                    return None;
                }
                let reference = *cell.refs.first()?;
                let (child_hash, child_depth) = ton_child_hash_depth(computed.get(reference)?, 0)?;
                if cell.data.get(1..33)? != child_hash
                    || u16::from_be_bytes(cell.data.get(33..35)?.try_into().ok()?) != child_depth
                {
                    return None;
                }
                ton_level_mask_value(computed.get(reference)?.mask >> 1)
            }
            TonCellType::MerkleUpdate => {
                if cell.data_descriptor & 1 != 0 || cell.data.len() != 69 || cell.refs.len() != 2 {
                    return None;
                }
                for (position, hash_offset, depth_offset) in
                    [(0_usize, 1_usize, 65_usize), (1, 33, 67)]
                {
                    let reference = *cell.refs.get(position)?;
                    let (child_hash, child_depth) =
                        ton_child_hash_depth(computed.get(reference)?, 0)?;
                    if cell.data.get(hash_offset..hash_offset + 32)? != child_hash
                        || u16::from_be_bytes(
                            cell.data
                                .get(depth_offset..depth_offset + 2)?
                                .try_into()
                                .ok()?,
                        ) != child_depth
                    {
                        return None;
                    }
                }
                ton_level_mask_value(
                    (computed.get(*cell.refs.first()?)?.mask
                        | computed.get(*cell.refs.get(1)?)?.mask)
                        >> 1,
                )
            }
        };
        if (cell.descriptor >> 5) & 0x07 != mask {
            return None;
        }
        let total_hash_count = ton_level_mask_hash_index(mask).checked_add(1)?;
        let hash_count = if cell_type == TonCellType::PrunedBranch {
            1
        } else {
            total_hash_count
        };
        let hash_offset = total_hash_count.checked_sub(hash_count)?;
        let mut hashes = Vec::<H256>::with_capacity(hash_count);
        let mut depths = Vec::<u16>::with_capacity(hash_count);
        let level = ton_level_mask_level(mask);
        let mut hash_index = 0_usize;
        for level_index in 0..=level {
            if !ton_level_mask_is_significant(mask, level_index) {
                continue;
            }
            if hash_index < hash_offset {
                hash_index += 1;
                continue;
            }
            let current_data: &[u8] = if hash_index == hash_offset {
                if level_index != 0 && cell_type != TonCellType::PrunedBranch {
                    return None;
                }
                &cell.data
            } else {
                hashes.get(hash_index.checked_sub(hash_offset)?.checked_sub(1)?)?
            };
            let mut current_depth = 0_u16;
            for reference in &cell.refs {
                let (_, child_depth) = ton_boc_child_for_hash_level(
                    cell_type,
                    computed.get(*reference)?,
                    level_index,
                )?;
                current_depth = current_depth.max(child_depth);
            }
            if !cell.refs.is_empty() {
                current_depth = current_depth.checked_add(1)?;
            }
            if current_depth > TON_MAX_CELL_DEPTH {
                return None;
            }
            let descriptor = u8::try_from(cell.refs.len()).ok()?
                | if cell_type == TonCellType::Ordinary {
                    0
                } else {
                    0x08
                }
                | ton_level_mask_apply(mask, level_index).checked_shl(5)?;
            let mut repr = Vec::with_capacity(
                2_usize
                    .checked_add(current_data.len())?
                    .checked_add(cell.refs.len().checked_mul(34)?)?,
            );
            repr.push(descriptor);
            repr.push(cell.data_descriptor);
            repr.extend_from_slice(current_data);
            for reference in &cell.refs {
                let (_, child_depth) = ton_boc_child_for_hash_level(
                    cell_type,
                    computed.get(*reference)?,
                    level_index,
                )?;
                repr.extend_from_slice(&child_depth.to_be_bytes());
            }
            for reference in &cell.refs {
                let (child_hash, _) = ton_boc_child_for_hash_level(
                    cell_type,
                    computed.get(*reference)?,
                    level_index,
                )?;
                repr.extend_from_slice(&child_hash);
            }
            hashes.push(Sha256::digest(&repr).into());
            depths.push(current_depth);
            hash_index += 1;
        }
        if hashes.len() != hash_count || depths.len() != hash_count {
            return None;
        }
        let mut resolved_hashes = [[0_u8; 32]; 4];
        let mut resolved_depths = [0_u16; 4];
        for resolved_level in 0_u8..4 {
            let resolved_index =
                ton_level_mask_hash_index(ton_level_mask_apply(mask, resolved_level));
            if let Some(pruned) = &pruned {
                if resolved_index == ton_level_mask_hash_index(mask) {
                    resolved_hashes[usize::from(resolved_level)] = *hashes.first()?;
                    resolved_depths[usize::from(resolved_level)] = *depths.first()?;
                } else {
                    resolved_hashes[usize::from(resolved_level)] =
                        *pruned.hashes.get(resolved_index)?;
                    resolved_depths[usize::from(resolved_level)] =
                        *pruned.depths.get(resolved_index)?;
                }
            } else {
                resolved_hashes[usize::from(resolved_level)] = *hashes.get(resolved_index)?;
                resolved_depths[usize::from(resolved_level)] = *depths.get(resolved_index)?;
            }
        }
        if resolved_depths
            .iter()
            .any(|depth| *depth > TON_MAX_CELL_DEPTH)
        {
            return None;
        }
        computed[index] = TonComputedCell {
            mask,
            hashes: resolved_hashes,
            depths: resolved_depths,
        };
    }
    Some(computed)
}

fn parse_single_root_boc(bytes: &[u8]) -> Option<(TonBoc, Vec<TonComputedCell>, usize)> {
    let boc = parse_ton_boc(bytes)?;
    if boc.roots.len() != 1 {
        return None;
    }
    let root = *boc.roots.first()?;
    let computed = ton_boc_cell_hashes(&boc)?;
    Some((boc, computed, root))
}

fn ton_merkle_opened_index(boc: &TonBoc, mut index: usize) -> Option<usize> {
    let mut remaining = boc.cells.len().checked_add(1)?;
    loop {
        remaining = remaining.checked_sub(1)?;
        match ton_cell_type(boc.cells.get(index)?)? {
            TonCellType::Ordinary | TonCellType::PrunedBranch => return Some(index),
            TonCellType::MerkleProof => {
                index = *boc.cells.get(index)?.refs.first()?;
            }
            TonCellType::MerkleUpdate => return None,
        }
    }
}

fn ton_virtual_root_index(boc: &TonBoc, index: usize) -> Option<usize> {
    let index = ton_merkle_opened_index(boc, index)?;
    (ton_cell_type(boc.cells.get(index)?)? == TonCellType::Ordinary).then_some(index)
}

fn ton_original_tree_hash(computed: &[TonComputedCell], index: usize) -> Option<H256> {
    Some(computed.get(index)?.hashes[0])
}

fn ton_proven_root_hash(boc: &TonBoc, computed: &[TonComputedCell], root: usize) -> Option<H256> {
    match ton_cell_type(boc.cells.get(root)?)? {
        TonCellType::Ordinary => ton_original_tree_hash(computed, root),
        TonCellType::MerkleProof => boc.cells.get(root)?.data.get(1..33)?.try_into().ok(),
        TonCellType::PrunedBranch | TonCellType::MerkleUpdate => None,
    }
}

/// Derive the authenticated hash-zero identity of one bounded single-root `BoC`.
pub fn ton_boc_single_root_hash_v1(bytes: &[u8]) -> Option<H256> {
    let (boc, computed, root) = parse_single_root_boc(bytes)?;
    ton_proven_root_hash(&boc, &computed, root)
}

fn ton_hashmap_uint_len_bits(max_value: usize) -> usize {
    usize::try_from(usize::BITS - max_value.leading_zeros()).expect("usize width fits")
}

fn ton_key_bit(key: &[u8], bit_len: u16, offset: usize) -> Option<bool> {
    if offset >= usize::from(bit_len) || key.len() != usize::from(bit_len).div_ceil(8) {
        return None;
    }
    let shift = 7_usize.checked_sub(offset % 8)?;
    Some((key[offset / 8] >> shift) & 1 != 0)
}

fn ton_read_hashmap_label(
    reader: &mut TonBitReader<'_>,
    key: &[u8],
    key_bit_len: u16,
    key_offset: usize,
    maximum: usize,
) -> Option<usize> {
    let long_or_same = reader.read_bit()?;
    let length;
    if !long_or_same {
        let mut unary = 0_usize;
        while reader.read_bit()? {
            unary = unary.checked_add(1)?;
            if unary > maximum {
                return None;
            }
        }
        length = unary;
        for index in 0..length {
            if reader.read_bit()? != ton_key_bit(key, key_bit_len, key_offset + index)? {
                return None;
            }
        }
    } else if !reader.read_bit()? {
        length = reader.read_usize(ton_hashmap_uint_len_bits(maximum))?;
        if length > maximum {
            return None;
        }
        for index in 0..length {
            if reader.read_bit()? != ton_key_bit(key, key_bit_len, key_offset + index)? {
                return None;
            }
        }
    } else {
        let value = reader.read_bit()?;
        length = reader.read_usize(ton_hashmap_uint_len_bits(maximum))?;
        if length > maximum {
            return None;
        }
        for index in 0..length {
            if value != ton_key_bit(key, key_bit_len, key_offset + index)? {
                return None;
            }
        }
    }
    Some(length)
}

fn ton_read_hashmap_label_bits(reader: &mut TonBitReader<'_>, maximum: usize) -> Option<Vec<bool>> {
    let long_or_same = reader.read_bit()?;
    let length;
    let mut bits = Vec::new();
    if !long_or_same {
        let mut unary = 0_usize;
        while reader.read_bit()? {
            unary = unary.checked_add(1)?;
            if unary > maximum {
                return None;
            }
        }
        length = unary;
        for _ in 0..length {
            bits.push(reader.read_bit()?);
        }
    } else if !reader.read_bit()? {
        length = reader.read_usize(ton_hashmap_uint_len_bits(maximum))?;
        if length > maximum {
            return None;
        }
        for _ in 0..length {
            bits.push(reader.read_bit()?);
        }
    } else {
        let value = reader.read_bit()?;
        length = reader.read_usize(ton_hashmap_uint_len_bits(maximum))?;
        if length > maximum {
            return None;
        }
        bits.resize(length, value);
    }
    Some(bits)
}

fn ton_hashmap_ref_value(boc: &TonBoc, root: usize, key: &[u8], key_bit_len: u16) -> Option<usize> {
    let mut cell_index = ton_virtual_root_index(boc, root)?;
    let mut key_offset = 0_usize;
    let mut remaining = usize::from(key_bit_len);
    for _ in 0..=boc.cells.len() {
        cell_index = ton_virtual_root_index(boc, cell_index)?;
        let cell = boc.cells.get(cell_index)?;
        (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
        let mut reader = TonBitReader::new(cell)?;
        let label = ton_read_hashmap_label(&mut reader, key, key_bit_len, key_offset, remaining)?;
        key_offset = key_offset.checked_add(label)?;
        remaining = remaining.checked_sub(label)?;
        if remaining == 0 {
            if reader.remaining_bits()? != 0 || reader.remaining_refs()? != 1 {
                return None;
            }
            return ton_virtual_root_index(boc, reader.read_ref()?);
        }
        if reader.remaining_bits()? != 0 || reader.remaining_refs()? != 2 {
            return None;
        }
        let branch = ton_key_bit(key, key_bit_len, key_offset)?;
        key_offset += 1;
        remaining -= 1;
        let left = reader.read_ref()?;
        let right = reader.read_ref()?;
        cell_index = if branch { right } else { left };
    }
    None
}

fn ton_hashmap_aug_leaf_reader<'a>(
    boc: &'a TonBoc,
    root: usize,
    key: &[u8],
    key_bit_len: u16,
    skip_extra: fn(&mut TonBitReader<'_>) -> Option<()>,
) -> Option<TonBitReader<'a>> {
    let mut cell_index = ton_virtual_root_index(boc, root)?;
    let mut key_offset = 0_usize;
    let mut remaining = usize::from(key_bit_len);
    for _ in 0..=boc.cells.len() {
        cell_index = ton_virtual_root_index(boc, cell_index)?;
        let cell = boc.cells.get(cell_index)?;
        (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
        let mut reader = TonBitReader::new(cell)?;
        let label = ton_read_hashmap_label(&mut reader, key, key_bit_len, key_offset, remaining)?;
        key_offset += label;
        remaining -= label;
        if remaining == 0 {
            return Some(reader);
        }
        if reader.remaining_refs()? < 2 {
            return None;
        }
        let branch = ton_key_bit(key, key_bit_len, key_offset)?;
        key_offset += 1;
        remaining -= 1;
        let left = reader.read_ref()?;
        let right = reader.read_ref()?;
        skip_extra(&mut reader)?;
        if !reader.exhausted() {
            return None;
        }
        cell_index = if branch { right } else { left };
    }
    None
}

fn ton_skip_var_uint(reader: &mut TonBitReader<'_>, length_bits: usize) -> Option<()> {
    let byte_len = reader.read_usize(length_bits)?;
    reader.skip_bits(byte_len.checked_mul(8)?)
}

fn ton_skip_grams(reader: &mut TonBitReader<'_>) -> Option<()> {
    ton_skip_var_uint(reader, 4)
}

fn ton_skip_currency_collection(reader: &mut TonBitReader<'_>) -> Option<()> {
    ton_skip_grams(reader)?;
    if reader.read_bit()? {
        reader.read_ref()?;
    }
    Some(())
}

fn ton_skip_storage_used(reader: &mut TonBitReader<'_>) -> Option<()> {
    ton_skip_var_uint(reader, 3)?;
    ton_skip_var_uint(reader, 3)
}

fn ton_read_shard_ident(reader: &mut TonBitReader<'_>) -> Option<(i32, u64)> {
    if reader.read_u64(2)? != 0 {
        return None;
    }
    let prefix_bits = reader.read_usize(6)?;
    if prefix_bits > 60 {
        return None;
    }
    let workchain = reader.read_i32(32)?;
    let prefix = reader.read_u64(64)?;
    let terminator = 1_u64 << (63 - prefix_bits);
    // ShardIdent stores only the high prefix bits. BlockIdExt's in-memory
    // shard id additionally carries the terminator immediately below them.
    if prefix & (terminator | (terminator - 1)) != 0 {
        return None;
    }
    Some((workchain, prefix | terminator))
}

fn ton_parse_ext_block_ref(
    boc: &TonBoc,
    cell_index: usize,
    workchain: i32,
    shard: u64,
) -> Option<TonBlockIdExtV1> {
    let index = ton_virtual_root_index(boc, cell_index)?;
    let cell = boc.cells.get(index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    reader.read_u64(64)?; // end_lt
    let seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    let root_hash = reader.read_h256()?;
    let file_hash = reader.read_h256()?;
    reader.exhausted().then_some(TonBlockIdExtV1 {
        workchain,
        shard,
        seqno,
        root_hash,
        file_hash,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent TL-B BlockInfo flag bits"
)]
struct TonParsedBlockInfo {
    not_master: bool,
    after_merge: bool,
    before_split: bool,
    after_split: bool,
    key_block: bool,
    seqno: u32,
    workchain: i32,
    shard: u64,
    gen_utime: u32,
    validator_list_hash_short: u32,
    catchain_seqno: u32,
    min_ref_mc_seqno: u32,
    prev_key_block_seqno: u32,
    previous: Option<TonBlockIdExtV1>,
    /// Both predecessors of a block after a merge (left child shard, right child shard).
    merged_previous: Option<(TonBlockIdExtV1, TonBlockIdExtV1)>,
    master_ref: Option<TonBlockIdExtV1>,
}

/// The predecessors of a `BlockInfo`: one block, or both blocks merged into this one.
type TonBlkPrevInfo = (
    Option<TonBlockIdExtV1>,
    Option<(TonBlockIdExtV1, TonBlockIdExtV1)>,
);

/// Resolve `prev_ref:^(BlkPrevInfo after_merge)` of a block in `workchain`/`shard`.
fn ton_parse_prev_ref(
    boc: &TonBoc,
    previous_ref_index: usize,
    workchain: i32,
    shard: u64,
    after_merge: bool,
    after_split: bool,
) -> Option<TonBlkPrevInfo> {
    // After a split the predecessor lives in the parent shard; after a merge the two
    // predecessors live in the child shards, referenced from the `prev_blks_info` cell.
    if after_merge {
        let pair = ton_virtual_root_index(boc, previous_ref_index)?;
        let cell = boc.cells.get(pair)?;
        let mut pair_reader = TonBitReader::new(cell)?;
        let left = pair_reader.read_ref()?;
        let right = pair_reader.read_ref()?;
        if !pair_reader.exhausted() {
            return None;
        }
        return Some((
            None,
            Some((
                ton_parse_ext_block_ref(boc, left, workchain, ton_shard_child(shard, false)?)?,
                ton_parse_ext_block_ref(boc, right, workchain, ton_shard_child(shard, true)?)?,
            )),
        ));
    }
    let previous_shard = if after_split {
        ton_shard_parent(shard)?
    } else {
        shard
    };
    Some((
        Some(ton_parse_ext_block_ref(
            boc,
            previous_ref_index,
            workchain,
            previous_shard,
        )?),
        None,
    ))
}

fn ton_parse_block_info(boc: &TonBoc, cell_index: usize) -> Option<TonParsedBlockInfo> {
    let index = ton_virtual_root_index(boc, cell_index)?;
    let cell = boc.cells.get(index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    if u32::try_from(reader.read_u64(32)?).ok()? != TON_BLOCK_INFO_CONSTRUCTOR {
        return None;
    }
    reader.read_u64(32)?; // version
    let not_master = reader.read_bit()?;
    let after_merge = reader.read_bit()?;
    let before_split = reader.read_bit()?;
    let after_split = reader.read_bit()?;
    reader.read_bit()?; // want_split
    reader.read_bit()?; // want_merge
    let key_block = reader.read_bit()?;
    let vert_seqno_incr = reader.read_bit()?;
    let flags = u8::try_from(reader.read_u64(8)?).ok()?;
    if flags > 1 || (key_block && not_master) {
        return None;
    }
    let seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    let vert_seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    if vert_seqno < u32::from(vert_seqno_incr) {
        return None;
    }
    let (workchain, shard) = ton_read_shard_ident(&mut reader)?;
    let gen_utime = u32::try_from(reader.read_u64(32)?).ok()?;
    let start_lt = reader.read_u64(64)?;
    let end_lt = reader.read_u64(64)?;
    if seqno == 0 || start_lt >= end_lt {
        return None;
    }
    let validator_list_hash_short = u32::try_from(reader.read_u64(32)?).ok()?;
    let catchain_seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    let min_ref_mc_seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    let prev_key_block_seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    if flags & 1 != 0 {
        if reader.read_u64(8)? != u64::from(TON_GLOBAL_VERSION_CONSTRUCTOR) {
            return None;
        }
        reader.read_u64(32)?; // global version
        reader.read_u64(64)?; // capabilities
    }
    let master_ref_index = if not_master {
        Some(reader.read_ref()?)
    } else {
        None
    };
    let previous_ref_index = reader.read_ref()?;
    if vert_seqno_incr {
        reader.read_ref()?;
    }
    if !reader.exhausted() {
        return None;
    }
    let (previous, merged_previous) = ton_parse_prev_ref(
        boc,
        previous_ref_index,
        workchain,
        shard,
        after_merge,
        after_split,
    )?;
    let master_ref = match master_ref_index {
        Some(reference) => Some(ton_parse_ext_block_ref(
            boc,
            reference,
            TON_MASTERCHAIN_WORKCHAIN,
            TON_MASTERCHAIN_SHARD,
        )?),
        None => None,
    };
    Some(TonParsedBlockInfo {
        not_master,
        after_merge,
        before_split,
        after_split,
        key_block,
        seqno,
        workchain,
        shard,
        gen_utime,
        validator_list_hash_short,
        catchain_seqno,
        min_ref_mc_seqno,
        prev_key_block_seqno,
        previous,
        merged_previous,
        master_ref,
    })
}

#[derive(Debug)]
struct TonParsedBlock {
    global_id: i32,
    info: TonParsedBlockInfo,
    /// `state_update` new hash, or `None` when the proof prunes the `state_update` cell (a
    /// liteserver header, shard-link or transaction proof that does not need it).
    new_state_hash: Option<H256>,
    extra_index: usize,
}

fn ton_parse_block(
    boc: &TonBoc,
    computed: &[TonComputedCell],
    root: usize,
) -> Option<TonParsedBlock> {
    let index = ton_virtual_root_index(boc, root)?;
    let cell = boc.cells.get(index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    if u32::try_from(reader.read_u64(32)?).ok()? != TON_BLOCK_CONSTRUCTOR {
        return None;
    }
    let global_id = reader.read_i32(32)?;
    let info_index = reader.read_ref()?;
    reader.read_ref()?; // value_flow
    let state_update_index = reader.read_ref()?;
    let extra_index = reader.read_ref()?;
    if !reader.exhausted() {
        return None;
    }
    let state_update = boc.cells.get(state_update_index)?;
    let new_state_hash = match ton_cell_type(state_update)? {
        // Liteservers prune the update when the proof only opens the header or the account
        // blocks; the pruned cell still commits to it through the root hash.
        TonCellType::PrunedBranch => None,
        TonCellType::MerkleUpdate
            if state_update.data.len() == 69
                && state_update.refs.len() == 2
                && state_update.data.first().copied()? == 4 =>
        {
            // Cell-hash evaluation already checked both embedded hashes/depths against
            // the referenced old/new state cells.
            computed.get(state_update_index)?;
            Some(state_update.data.get(33..65)?.try_into().ok()?)
        }
        _ => return None,
    };
    Some(TonParsedBlock {
        global_id,
        info: ton_parse_block_info(boc, info_index)?,
        new_state_hash,
        extra_index,
    })
}

#[derive(Clone, Copy, Debug)]
struct TonMasterchainExtra {
    shard_hashes_root: Option<usize>,
}

fn ton_parse_masterchain_extra(
    boc: &TonBoc,
    block_extra_index: usize,
) -> Option<TonMasterchainExtra> {
    let extra_index = ton_virtual_root_index(boc, block_extra_index)?;
    let extra_cell = boc.cells.get(extra_index)?;
    (ton_cell_type(extra_cell)? == TonCellType::Ordinary).then_some(())?;
    let mut extra = TonBitReader::new(extra_cell)?;
    if extra.read_u64(32)? != u64::from(TON_BLOCK_EXTRA_CONSTRUCTOR) {
        return None;
    }
    extra.read_ref()?; // in_msg_descr
    extra.read_ref()?; // out_msg_descr
    extra.read_ref()?; // account_blocks
    extra.skip_bits(512)?; // rand_seed, created_by
    if !extra.read_bit()? {
        return None;
    }
    let custom_index = extra.read_ref()?;
    if !extra.exhausted() {
        return None;
    }
    let custom_index = ton_virtual_root_index(boc, custom_index)?;
    let custom_cell = boc.cells.get(custom_index)?;
    (ton_cell_type(custom_cell)? == TonCellType::Ordinary).then_some(())?;
    let mut custom = TonBitReader::new(custom_cell)?;
    if u16::try_from(custom.read_u64(16)?).ok()? != TON_MC_BLOCK_EXTRA_CONSTRUCTOR {
        return None;
    }
    let key_block = custom.read_bit()?;
    let shard_hashes_root = if custom.read_bit()? {
        Some(custom.read_ref()?)
    } else {
        None
    };
    if custom.read_bit()? {
        custom.read_ref()?; // shard-fees HashmapAug root
    }
    // HashmapAugE carries its aggregate even when empty.
    ton_skip_currency_collection(&mut custom)?;
    ton_skip_currency_collection(&mut custom)?;
    custom.read_ref()?; // previous signatures/recover/mint auxiliary cell
    if key_block {
        custom.read_h256()?; // config contract address
        custom.read_ref()?; // config dictionary
    }
    custom
        .exhausted()
        .then_some(TonMasterchainExtra { shard_hashes_root })
}

fn ton_read_validator_descr(reader: &mut TonBitReader<'_>) -> Option<TonValidatorV1> {
    let constructor = u8::try_from(reader.read_u64(8)?).ok()?;
    if !matches!(
        constructor,
        TON_VALIDATOR_CONSTRUCTOR | TON_VALIDATOR_ADDR_CONSTRUCTOR
    ) {
        return None;
    }
    if u32::try_from(reader.read_u64(32)?).ok()? != TON_ED25519_PUBKEY_TLB_CONSTRUCTOR {
        return None;
    }
    let public_key = reader.read_h256()?;
    let weight = reader.read_u64(64)?;
    if weight == 0 {
        return None;
    }
    let adnl_address = if constructor == TON_VALIDATOR_ADDR_CONSTRUCTOR {
        reader.read_h256()?
    } else {
        [0_u8; 32]
    };
    Some(TonValidatorV1 {
        public_key,
        weight,
        adnl_address,
    })
}

fn bits_to_u16(bits: &[bool]) -> Option<u16> {
    if bits.len() > 16 {
        return None;
    }
    let mut value = 0_u16;
    for bit in bits {
        value = value.checked_shl(1)?;
        if *bit {
            value = value.checked_add(1)?;
        }
    }
    Some(value)
}

fn ton_collect_validator_edge(
    boc: &TonBoc,
    reader: &mut TonBitReader<'_>,
    remaining: usize,
    prefix: &mut Vec<bool>,
    output: &mut Vec<(u16, TonValidatorV1)>,
    budget: &mut usize,
) -> Option<()> {
    if *budget == 0 || output.len() >= TON_MAX_VALIDATORS {
        return None;
    }
    *budget -= 1;
    let label = ton_read_hashmap_label_bits(reader, remaining)?;
    let label_len = label.len();
    prefix.extend(label);
    let remaining = remaining.checked_sub(label_len)?;
    if remaining == 0 {
        let key = bits_to_u16(prefix)?;
        let validator = ton_read_validator_descr(reader)?;
        if !reader.exhausted() {
            return None;
        }
        output.push((key, validator));
        prefix.truncate(prefix.len().checked_sub(label_len)?);
        return Some(());
    }
    if reader.remaining_bits()? != 0 || reader.remaining_refs()? != 2 {
        return None;
    }
    let left = reader.read_ref()?;
    let right = reader.read_ref()?;
    for (bit, child) in [(false, left), (true, right)] {
        let child = ton_virtual_root_index(boc, child)?;
        let cell = boc.cells.get(child)?;
        (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
        let mut child_reader = TonBitReader::new(cell)?;
        prefix.push(bit);
        ton_collect_validator_edge(
            boc,
            &mut child_reader,
            remaining.checked_sub(1)?,
            prefix,
            output,
            budget,
        )?;
        prefix.pop();
    }
    prefix.truncate(prefix.len().checked_sub(label_len)?);
    Some(())
}

fn ton_parse_validator_config(boc: &TonBoc, cell_index: usize) -> Option<TonValidatorConfigV1> {
    let cell_index = ton_virtual_root_index(boc, cell_index)?;
    let cell = boc.cells.get(cell_index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    let constructor = u8::try_from(reader.read_u64(8)?).ok()?;
    if !matches!(
        constructor,
        TON_VALIDATORS_CONSTRUCTOR | TON_VALIDATORS_EXT_CONSTRUCTOR
    ) {
        return None;
    }
    let valid_since = u32::try_from(reader.read_u64(32)?).ok()?;
    let valid_until = u32::try_from(reader.read_u64(32)?).ok()?;
    let total = u16::try_from(reader.read_u64(16)?).ok()?;
    let main_validator_count = u16::try_from(reader.read_u64(16)?).ok()?;
    if valid_since >= valid_until
        || total == 0
        || usize::from(total) > TON_MAX_VALIDATORS
        || main_validator_count == 0
        || main_validator_count > total
    {
        return None;
    }
    let declared_total_weight = if constructor == TON_VALIDATORS_EXT_CONSTRUCTOR {
        Some(reader.read_u64(64)?)
    } else {
        None
    };
    let mut validators = Vec::with_capacity(usize::from(total));
    let mut prefix = Vec::with_capacity(16);
    let mut budget = boc.cells.len().checked_add(1)?;
    if constructor == TON_VALIDATORS_EXT_CONSTRUCTOR {
        if !reader.read_bit()? || reader.remaining_bits()? != 0 || reader.remaining_refs()? != 1 {
            return None;
        }
        let root = ton_virtual_root_index(boc, reader.read_ref()?)?;
        let root_cell = boc.cells.get(root)?;
        let mut root_reader = TonBitReader::new(root_cell)?;
        ton_collect_validator_edge(
            boc,
            &mut root_reader,
            usize::from(TON_VALIDATOR_SET_KEY_BITS),
            &mut prefix,
            &mut validators,
            &mut budget,
        )?;
    } else {
        ton_collect_validator_edge(
            boc,
            &mut reader,
            usize::from(TON_VALIDATOR_SET_KEY_BITS),
            &mut prefix,
            &mut validators,
            &mut budget,
        )?;
    }
    validators.sort_by_key(|(key, _)| *key);
    if validators.len() != usize::from(total)
        || validators
            .iter()
            .enumerate()
            .any(|(index, (key, _))| usize::from(*key) != index)
    {
        return None;
    }
    let validators = validators
        .into_iter()
        .map(|(_, validator)| validator)
        .collect::<Vec<_>>();
    let total_weight = validate_validator_roster(&validators)?;
    if declared_total_weight.is_some_and(|declared| declared != total_weight) {
        return None;
    }
    Some(TonValidatorConfigV1 {
        valid_since,
        valid_until,
        main_validator_count,
        shuffle_masterchain_validators: false,
        validators,
    })
}

fn ton_parse_catchain_shuffle(boc: &TonBoc, cell_index: usize) -> Option<bool> {
    let cell_index = ton_virtual_root_index(boc, cell_index)?;
    let cell = boc.cells.get(cell_index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    let constructor = u8::try_from(reader.read_u64(8)?).ok()?;
    let shuffle = match constructor {
        TON_CATCHAIN_CONFIG_CONSTRUCTOR => false,
        TON_CATCHAIN_CONFIG_NEW_CONSTRUCTOR => {
            if reader.read_u64(7)? != 0 {
                return None;
            }
            reader.read_bit()?
        }
        _ => return None,
    };
    for _ in 0..4 {
        if reader.read_u64(32)? == 0 {
            return None;
        }
    }
    reader.exhausted().then_some(shuffle)
}

fn ton_config_from_dictionary(boc: &TonBoc, root: usize) -> Option<TonValidatorConfigV1> {
    let validators_cell = ton_hashmap_ref_value(
        boc,
        root,
        &TON_CONFIG_CURRENT_VALIDATORS.to_be_bytes(),
        TON_CONFIG_KEY_BITS,
    )?;
    let catchain_cell = ton_hashmap_ref_value(
        boc,
        root,
        &TON_CONFIG_CATCHAIN.to_be_bytes(),
        TON_CONFIG_KEY_BITS,
    )?;
    let mut config = ton_parse_validator_config(boc, validators_cell)?;
    config.shuffle_masterchain_validators = ton_parse_catchain_shuffle(boc, catchain_cell)?;
    Some(config)
}

struct TonValidatorPrng {
    seed: H256,
    shard: u64,
    workchain: i32,
    catchain_seqno: u32,
    block: [u8; 64],
    position: usize,
}

impl TonValidatorPrng {
    fn masterchain(catchain_seqno: u32) -> Self {
        Self {
            seed: [0_u8; 32],
            shard: TON_MASTERCHAIN_SHARD,
            workchain: TON_MASTERCHAIN_WORKCHAIN,
            catchain_seqno,
            block: [0_u8; 64],
            position: 8,
        }
    }

    fn increment_seed(&mut self) {
        for byte in self.seed.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
    }

    fn next_u64(&mut self) -> u64 {
        if self.position >= 8 {
            let mut input = [0_u8; 48];
            input[..32].copy_from_slice(&self.seed);
            input[32..40].copy_from_slice(&self.shard.to_be_bytes());
            input[40..44].copy_from_slice(&self.workchain.to_be_bytes());
            input[44..48].copy_from_slice(&self.catchain_seqno.to_be_bytes());
            self.block.copy_from_slice(&Sha512::digest(input));
            self.increment_seed();
            self.position = 0;
        }
        let start = self.position * 8;
        self.position += 1;
        u64::from_be_bytes(
            self.block[start..start + 8]
                .try_into()
                .expect("fixed SHA-512 chunk"),
        )
    }

    fn next_ranged(&mut self, range: u64) -> u64 {
        u64::try_from((u128::from(range) * u128::from(self.next_u64())) >> 64)
            .expect("high half of a u64 product fits in u64")
    }
}

fn ton_select_masterchain_validator_set(
    config: &TonValidatorConfigV1,
    catchain_seqno: u32,
) -> Option<TonValidatorSetV1> {
    validate_validator_config(config)?;
    let count = usize::from(config.main_validator_count).min(config.validators.len());
    let validators = if config.shuffle_masterchain_validators {
        let mut indices = vec![0_usize; count];
        let mut prng = TonValidatorPrng::masterchain(catchain_seqno);
        for index in 0..count {
            let selected =
                usize::try_from(prng.next_ranged(u64::try_from(index + 1).ok()?)).ok()?;
            indices[index] = indices[selected];
            indices[selected] = index;
        }
        indices
            .into_iter()
            .map(|index| config.validators.get(index).copied())
            .collect::<Option<Vec<_>>>()?
    } else {
        config.validators.get(..count)?.to_vec()
    };
    let validator_list_hash_short =
        ton_validator_list_hash_short_from_validated(catchain_seqno, &validators)?;
    Some(TonValidatorSetV1 {
        catchain_seqno,
        validator_list_hash_short,
        validators,
    })
}

fn ton_shard_parent(shard: u64) -> Option<u64> {
    let terminator = shard & shard.wrapping_neg();
    let parent_terminator = terminator.checked_shl(1).filter(|value| *value != 0)?;
    Some((shard & !(terminator | parent_terminator)) | parent_terminator)
}

fn ton_shard_child(shard: u64, right: bool) -> Option<u64> {
    let terminator = shard & shard.wrapping_neg();
    if terminator <= 1 {
        return None;
    }
    let delta = terminator >> 1;
    Some(if right {
        shard.checked_add(delta)?
    } else {
        shard.checked_sub(delta)?
    })
}

fn ton_parse_shard_descriptor(
    reader: &mut TonBitReader<'_>,
    workchain: i32,
    shard: u64,
) -> Option<(TonBlockIdExtV1, u32)> {
    let constructor = u8::try_from(reader.read_u64(4)?).ok()?;
    if !matches!(constructor, 0x0b | 0x0a) {
        return None;
    }
    let seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    let registered_masterchain_seqno = u32::try_from(reader.read_u64(32)?).ok()?;
    let start_lt = reader.read_u64(64)?;
    let end_lt = reader.read_u64(64)?;
    let root_hash = reader.read_h256()?;
    let file_hash = reader.read_h256()?;
    if seqno == 0
        || registered_masterchain_seqno == 0
        || start_lt >= end_lt
        || !nonzero(&root_hash)
        || !nonzero(&file_hash)
    {
        return None;
    }
    Some((
        TonBlockIdExtV1 {
            workchain,
            shard,
            seqno,
            root_hash,
            file_hash,
        },
        registered_masterchain_seqno,
    ))
}

fn ton_select_shard_descriptor(
    boc: &TonBoc,
    shard_hashes_root: usize,
    address: TonStdAddress,
) -> Option<(TonBlockIdExtV1, u32)> {
    let bin_tree =
        ton_hashmap_ref_value(boc, shard_hashes_root, &address.workchain.to_be_bytes(), 32)?;
    let mut cell_index = bin_tree;
    let mut shard = TON_MASTERCHAIN_SHARD;
    for depth in 0..=60_usize {
        cell_index = ton_virtual_root_index(boc, cell_index)?;
        let cell = boc.cells.get(cell_index)?;
        (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
        let mut reader = TonBitReader::new(cell)?;
        if !reader.read_bit()? {
            return ton_parse_shard_descriptor(&mut reader, address.workchain, shard);
        }
        if reader.remaining_bits()? != 0 || reader.remaining_refs()? != 2 {
            return None;
        }
        let left = reader.read_ref()?;
        let right = reader.read_ref()?;
        let go_right = ton_key_bit(&address.account, 256, depth)?;
        shard = ton_shard_child(shard, go_right)?;
        cell_index = if go_right { right } else { left };
    }
    None
}

fn ton_parse_block_extra_account_blocks(boc: &TonBoc, extra_index: usize) -> Option<usize> {
    let index = ton_virtual_root_index(boc, extra_index)?;
    let cell = boc.cells.get(index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    if reader.read_u64(32)? != u64::from(TON_BLOCK_EXTRA_CONSTRUCTOR) {
        return None;
    }
    reader.read_ref()?; // in_msg_descr
    reader.read_ref()?; // out_msg_descr
    let account_blocks = reader.read_ref()?;
    reader.skip_bits(512)?;
    if reader.read_bit()? {
        reader.read_ref()?;
    }
    reader.exhausted().then_some(account_blocks)
}

fn ton_hashmap_aug_e_root(
    boc: &TonBoc,
    wrapper_index: usize,
    skip_extra: fn(&mut TonBitReader<'_>) -> Option<()>,
) -> Option<usize> {
    let index = ton_virtual_root_index(boc, wrapper_index)?;
    let cell = boc.cells.get(index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    if !reader.read_bit()? {
        skip_extra(&mut reader)?;
        return reader.exhausted().then_some(usize::MAX);
    }
    let root = reader.read_ref()?;
    skip_extra(&mut reader)?;
    reader.exhausted().then_some(root)
}

#[derive(Clone, Copy, Debug)]
struct TonParsedTransaction {
    out_message_count: u16,
    auxiliary_index: usize,
    description_index: usize,
}

fn ton_parse_transaction(
    boc: &TonBoc,
    transaction_index: usize,
    expected_account: H256,
    expected_lt: u64,
) -> Option<TonParsedTransaction> {
    let index = ton_virtual_root_index(boc, transaction_index)?;
    let cell = boc.cells.get(index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    let mut reader = TonBitReader::new(cell)?;
    if u8::try_from(reader.read_u64(4)?).ok()? != TON_TRANSACTION_CONSTRUCTOR
        || reader.read_h256()? != expected_account
    {
        return None;
    }
    let logical_time = reader.read_u64(64)?;
    if logical_time != expected_lt || logical_time == 0 {
        return None;
    }
    reader.read_h256()?; // previous transaction hash
    let previous_logical_time = reader.read_u64(64)?;
    if previous_logical_time >= logical_time {
        return None;
    }
    reader.read_u64(32)?; // now
    let out_message_count = u16::try_from(reader.read_u64(15)?).ok()?;
    if out_message_count == 0 || out_message_count > 512 {
        return None;
    }
    let original_status = u8::try_from(reader.read_u64(2)?).ok()?;
    let end_status = u8::try_from(reader.read_u64(2)?).ok()?;
    if original_status != 2 || end_status != 2 {
        return None;
    }
    let auxiliary_index = reader.read_ref()?;
    ton_skip_currency_collection(&mut reader)?;
    let state_update = reader.read_ref()?;
    let description_index = reader.read_ref()?;
    if !reader.exhausted() {
        return None;
    }
    let state_update = ton_virtual_root_index(boc, state_update)?;
    let update_cell = boc.cells.get(state_update)?;
    let mut update_reader = TonBitReader::new(update_cell)?;
    if update_reader.read_u64(8)? != 0x72 {
        return None;
    }
    let old_account_hash = update_reader.read_h256()?;
    let new_account_hash = update_reader.read_h256()?;
    if !update_reader.exhausted() || !nonzero(&old_account_hash) || !nonzero(&new_account_hash) {
        return None;
    }
    Some(TonParsedTransaction {
        out_message_count,
        auxiliary_index,
        description_index,
    })
}

fn ton_skip_account_status_change(reader: &mut TonBitReader<'_>) -> Option<()> {
    if reader.read_bit()? {
        reader.read_bit()?;
    }
    Some(())
}

fn ton_skip_storage_phase(reader: &mut TonBitReader<'_>) -> Option<()> {
    ton_skip_grams(reader)?;
    if reader.read_bit()? {
        ton_skip_grams(reader)?;
    }
    ton_skip_account_status_change(reader)
}

fn ton_skip_credit_phase(reader: &mut TonBitReader<'_>) -> Option<()> {
    if reader.read_bit()? {
        ton_skip_grams(reader)?;
    }
    ton_skip_currency_collection(reader)
}

fn ton_parse_vm_compute_phase(boc: &TonBoc, reader: &mut TonBitReader<'_>) -> Option<bool> {
    if !reader.read_bit()? {
        // Every compute-skipped reason is a failed source event.
        if reader.read_u64(2)? == 3 && reader.read_bit()? {
            return None;
        }
        return Some(false);
    }
    let success = reader.read_bit()?;
    reader.read_bit()?; // msg_state_used
    reader.read_bit()?; // account_activated
    ton_skip_grams(reader)?;
    let details = reader.read_ref()?;
    let details = ton_virtual_root_index(boc, details)?;
    let cell = boc.cells.get(details)?;
    let mut details = TonBitReader::new(cell)?;
    ton_skip_var_uint(&mut details, 3)?;
    ton_skip_var_uint(&mut details, 3)?;
    if details.read_bit()? {
        ton_skip_var_uint(&mut details, 2)?;
    }
    details.read_i32(8)?; // mode
    let exit_code = details.read_i32(32)?;
    if details.read_bit()? {
        details.read_i32(32)?;
    }
    details.read_u64(32)?;
    details.read_h256()?;
    details.read_h256()?;
    if !details.exhausted() {
        return None;
    }
    Some(success && matches!(exit_code, 0 | 1))
}

fn ton_parse_action_phase(
    boc: &TonBoc,
    action_index: usize,
    expected_messages: u16,
) -> Option<bool> {
    let index = ton_virtual_root_index(boc, action_index)?;
    let cell = boc.cells.get(index)?;
    let mut reader = TonBitReader::new(cell)?;
    let success = reader.read_bit()?;
    let valid = reader.read_bit()?;
    let no_funds = reader.read_bit()?;
    ton_skip_account_status_change(&mut reader)?;
    if reader.read_bit()? {
        ton_skip_grams(&mut reader)?;
    }
    if reader.read_bit()? {
        ton_skip_grams(&mut reader)?;
    }
    let result_code = reader.read_i32(32)?;
    if reader.read_bit()? {
        reader.read_i32(32)?;
    }
    let total_actions = u16::try_from(reader.read_u64(16)?).ok()?;
    let special_actions = u16::try_from(reader.read_u64(16)?).ok()?;
    let skipped_actions = u16::try_from(reader.read_u64(16)?).ok()?;
    let messages_created = u16::try_from(reader.read_u64(16)?).ok()?;
    reader.read_h256()?;
    ton_skip_storage_used(&mut reader)?;
    if !reader.exhausted()
        || total_actions < messages_created
        || special_actions > total_actions
        || messages_created != expected_messages
    {
        return None;
    }
    Some(success && valid && !no_funds && result_code == 0 && skipped_actions == 0)
}

fn ton_skip_bounce_phase(reader: &mut TonBitReader<'_>) -> Option<()> {
    // `tr_phase_bounce_ok$1` carries `StorageUsed` and two `Grams`; `tr_phase_bounce_nofunds$01`
    // carries `StorageUsed` and one `Grams`; `tr_phase_bounce_negfunds$00` carries nothing.
    let bounce_ok = reader.read_bit()?;
    if bounce_ok || reader.read_bit()? {
        ton_skip_storage_used(reader)?;
        ton_skip_grams(reader)?;
        if bounce_ok {
            ton_skip_grams(reader)?;
        }
    }
    Some(())
}

fn ton_transaction_succeeded(boc: &TonBoc, transaction: TonParsedTransaction) -> Option<bool> {
    let index = ton_virtual_root_index(boc, transaction.description_index)?;
    let cell = boc.cells.get(index)?;
    let mut reader = TonBitReader::new(cell)?;
    if reader.read_u64(4)? != 0 {
        return Some(false);
    }
    reader.read_bit()?; // credit_first
    if reader.read_bit()? {
        ton_skip_storage_phase(&mut reader)?;
    }
    if reader.read_bit()? {
        ton_skip_credit_phase(&mut reader)?;
    }
    let compute_success = ton_parse_vm_compute_phase(boc, &mut reader)?;
    let action_index = if reader.read_bit()? {
        Some(reader.read_ref()?)
    } else {
        None
    };
    let aborted = reader.read_bit()?;
    if reader.read_bit()? {
        ton_skip_bounce_phase(&mut reader)?;
    }
    let destroyed = reader.read_bit()?;
    if !reader.exhausted() {
        return None;
    }
    let action_success = action_index
        .and_then(|action| ton_parse_action_phase(boc, action, transaction.out_message_count))
        .unwrap_or(false);
    Some(compute_success && action_success && !aborted && !destroyed)
}

fn ton_transaction_out_message(
    boc: &TonBoc,
    transaction: TonParsedTransaction,
    message_index: u16,
) -> Option<usize> {
    if message_index >= transaction.out_message_count || message_index >= (1 << 15) {
        return None;
    }
    let auxiliary = ton_virtual_root_index(boc, transaction.auxiliary_index)?;
    let cell = boc.cells.get(auxiliary)?;
    let mut reader = TonBitReader::new(cell)?;
    if reader.read_bit()? {
        reader.read_ref()?;
    }
    if !reader.read_bit()? {
        return None;
    }
    let root = reader.read_ref()?;
    if !reader.exhausted() {
        return None;
    }
    let key = message_index.checked_shl(1)?.to_be_bytes();
    ton_hashmap_ref_value(boc, root, &key, TON_OUT_MESSAGE_KEY_BITS)
}

fn ton_read_internal_address(reader: &mut TonBitReader<'_>) -> Option<TonStdAddress> {
    if !reader.read_bit()? {
        return None;
    }
    let variable = reader.read_bit()?;
    if reader.read_bit()? {
        let depth = reader.read_usize(5)?;
        if depth == 0 || depth > 30 {
            return None;
        }
        reader.skip_bits(depth)?;
    }
    let (workchain, account) = if variable {
        let length = reader.read_usize(9)?;
        if length != 256 {
            return None;
        }
        (reader.read_i32(32)?, reader.read_h256()?)
    } else {
        (reader.read_i32(8)?, reader.read_h256()?)
    };
    Some(TonStdAddress { workchain, account })
}

fn ton_read_canonical_var_uint(
    reader: &mut TonBitReader<'_>,
    length_bits: usize,
    maximum_bytes: usize,
) -> Option<u128> {
    let byte_len = reader.read_usize(length_bits)?;
    if byte_len >= maximum_bytes || byte_len > 16 {
        return None;
    }
    if byte_len == 0 {
        return Some(0);
    }
    let first = u8::try_from(reader.read_u64(8)?).ok()?;
    if first == 0 {
        return None;
    }
    let mut value = u128::from(first);
    for _ in 1..byte_len {
        value = value
            .checked_shl(8)?
            .checked_add(u128::from(u8::try_from(reader.read_u64(8)?).ok()?))?;
    }
    Some(value)
}

fn ton_read_canonical_coins(reader: &mut TonBitReader<'_>) -> Option<u128> {
    ton_read_canonical_var_uint(reader, 4, 16)
}

fn ton_read_canonical_std_address(reader: &mut TonBitReader<'_>) -> Option<TonStdAddress> {
    if !reader.read_bit()? || reader.read_bit()? || reader.read_bit()? {
        // Exactly `addr_std$10`, with no anycast prefix.
        return None;
    }
    let address = TonStdAddress {
        workchain: reader.read_i32(8)?,
        account: reader.read_h256()?,
    };
    (address.workchain == TON_BASECHAIN_WORKCHAIN && nonzero(&address.account)).then_some(address)
}

// ---------------------------------------------------------------------------------------------
// Light-client entry points (`light_client::ton`)
// ---------------------------------------------------------------------------------------------

/// Config 15 constructor-free layout: `validators_elected_for elections_start_before
/// elections_end_before stake_held_for`, four `uint32`.
const TON_CONFIG_ELECTION_TIMINGS: u32 = 15;
const TON_MC_STATE_EXTRA_CONSTRUCTOR: u16 = 0xcc26;
const TON_SCCP_TRANSFER_TO_TAIRA_OP: u32 = 0x5343_5454;
const TON_SCCP_VOIDED_OP: u32 = 0x5343_564f;
const TON_SNAKE_CHUNK_BYTES: usize = 127;
const TON_MAX_SNAKE_BYTES: usize = 4 * 1024;

/// An opened masterchain block header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TonMcHeaderV1 {
    /// Block id (the signed identity).
    pub(crate) block_id: TonBlockIdExtV1,
    /// Generation time (seconds).
    pub(crate) gen_utime: u32,
    /// Whether the block is a key block.
    pub(crate) key_block: bool,
    /// Key block whose config names this block's validators.
    pub(crate) prev_key_block_seqno: u32,
    /// Catchain session of the signing validator subset.
    pub(crate) catchain_seqno: u32,
    /// `validator_list_hash_short` of the signing subset.
    pub(crate) validator_list_hash_short: u32,
    /// Post-state hash (`state_update` new hash), when the header proof opens `state_update`;
    /// key-block hops, bootstraps and back-links need it.
    pub(crate) new_state_hash: Option<H256>,
}

/// Validator epoch read from a key block's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TonEpochConfigV1 {
    /// Config 34 (with the config-28 shuffle flag).
    pub(crate) validators: TonValidatorConfigV1,
    /// Config 15 `stake_held_for` (seconds).
    pub(crate) stake_held_for: u32,
}

/// An opened shard block header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TonShardHeaderV1 {
    /// Block id.
    pub(crate) block_id: TonBlockIdExtV1,
    /// Predecessor (after a split: in the parent shard).
    pub(crate) previous: Option<TonBlockIdExtV1>,
    /// Both predecessors after a merge.
    pub(crate) merged_previous: Option<(TonBlockIdExtV1, TonBlockIdExtV1)>,
    /// Generation time (seconds).
    pub(crate) gen_utime: u32,
}

/// An SCCP external-out message of the minter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TonSccpEventV1 {
    /// `sccp_transfer_to_taira`.
    TransferToTaira {
        /// Message id the minter computed.
        message_id: H256,
        /// Minter outbound nonce.
        nonce: u64,
        /// Burning owner (workchain 0 account id).
        sender: H256,
        /// Burned amount.
        amount: u128,
        /// Canonical payload bytes.
        payload: Vec<u8>,
    },
    /// `sccp_voided` (`message_id = 0` for frozen voids).
    Voided {
        /// Voided message id, or zero.
        message_id: H256,
        /// First voided nonce.
        first_nonce: u64,
        /// Voided nonces.
        count: u16,
    },
}

fn ton_open_canonical(
    bytes: &[u8],
    root_hash: &H256,
) -> Result<(TonBoc, Vec<TonComputedCell>, usize), TonNativeSourceError> {
    if bytes.is_empty() || bytes.len() > TON_MAX_BOC_BYTES {
        return Err(TonNativeSourceError::ResourceLimit);
    }
    let (boc, computed, root) =
        parse_canonical_single_root_boc(bytes).ok_or(TonNativeSourceError::InvalidBoc)?;
    if ton_proven_root_hash(&boc, &computed, root) != Some(*root_hash) {
        return Err(TonNativeSourceError::InvalidBoc);
    }
    Ok((boc, computed, root))
}

/// Open a masterchain block header proof rooted at `block_id.root_hash`; when `account` is
/// given, also select the shard block registered for that basechain account (the proof must
/// include the `ShardHashes` path).
pub fn ton_open_masterchain_block(
    block_id: TonBlockIdExtV1,
    header_proof: &[u8],
    account: Option<H256>,
) -> Result<(TonMcHeaderV1, Option<TonBlockIdExtV1>), TonNativeSourceError> {
    if block_id.workchain != TON_MASTERCHAIN_WORKCHAIN
        || block_id.shard != TON_MASTERCHAIN_SHARD
        || !valid_block_id(block_id)
    {
        return Err(TonNativeSourceError::BrokenMasterchainLink);
    }
    let (boc, computed, root) = ton_open_canonical(header_proof, &block_id.root_hash)?;
    let block = ton_parse_block(&boc, &computed, root).ok_or(TonNativeSourceError::InvalidBoc)?;
    if block.global_id != TON_MAINNET_GLOBAL_ID {
        return Err(TonNativeSourceError::WrongNetwork);
    }
    let info = block.info;
    if info.not_master
        || info.workchain != TON_MASTERCHAIN_WORKCHAIN
        || info.shard != TON_MASTERCHAIN_SHARD
        || info.seqno != block_id.seqno
    {
        return Err(TonNativeSourceError::BrokenMasterchainLink);
    }
    let shard = match account {
        None => None,
        Some(account) => {
            let extra = ton_parse_masterchain_extra(&boc, block.extra_index)
                .ok_or(TonNativeSourceError::ShardNotFinalized)?;
            let root = extra
                .shard_hashes_root
                .ok_or(TonNativeSourceError::ShardNotFinalized)?;
            let (shard_block, _) = ton_select_shard_descriptor(
                &boc,
                root,
                TonStdAddress {
                    workchain: TON_BASECHAIN_WORKCHAIN,
                    account,
                },
            )
            .ok_or(TonNativeSourceError::ShardNotFinalized)?;
            Some(shard_block)
        }
    };
    Ok((
        TonMcHeaderV1 {
            block_id,
            gen_utime: info.gen_utime,
            key_block: info.key_block,
            prev_key_block_seqno: info.prev_key_block_seqno,
            catchain_seqno: info.catchain_seqno,
            validator_list_hash_short: info.validator_list_hash_short,
            new_state_hash: block.new_state_hash,
        },
        shard,
    ))
}

/// Verify `signatures` over `header` by the masterchain subset of `epoch` for the header's
/// catchain session (more than two thirds of the subset weight).
pub fn ton_verify_masterchain_signatures(
    header: &TonMcHeaderV1,
    epoch: &TonValidatorConfigV1,
    signatures: &TonBlockSignaturesV1,
) -> Result<(), TonNativeSourceError> {
    let subset = ton_select_masterchain_validator_set(epoch, header.catchain_seqno)
        .ok_or(TonNativeSourceError::InvalidValidatorSet)?;
    if subset.validator_list_hash_short != header.validator_list_hash_short {
        return Err(TonNativeSourceError::InvalidValidatorSet);
    }
    verify_block_signatures(header.block_id, &subset, signatures)
}

/// Walk `ShardStateUnsplit` of the masterchain to its `McStateExtra` cell.
fn ton_mc_state_extra(boc: &TonBoc, root: usize) -> Option<usize> {
    let index = ton_virtual_root_index(boc, root)?;
    let cell = boc.cells.get(index)?;
    let mut reader = TonBitReader::new(cell)?;
    if u32::try_from(reader.read_u64(32)?).ok()? != TON_SHARD_STATE_CONSTRUCTOR
        || reader.read_i32(32)? != TON_MAINNET_GLOBAL_ID
    {
        return None;
    }
    let (workchain, shard) = ton_read_shard_ident(&mut reader)?;
    if workchain != TON_MASTERCHAIN_WORKCHAIN || shard != TON_MASTERCHAIN_SHARD {
        return None;
    }
    reader.skip_bits(32 + 32 + 32 + 64 + 32)?;
    reader.read_ref()?; // out_msg_queue_info
    reader.read_bit()?; // before_split
    reader.read_ref()?; // accounts
    reader.read_ref()?; // balances, libraries, master_ref
    if !reader.read_bit()? {
        return None;
    }
    let custom = reader.read_ref()?;
    reader.exhausted().then_some(custom)?;
    ton_virtual_root_index(boc, custom)
}

/// Open the validator epoch (configs 34, 28 and 15) from a masterchain state proof rooted at
/// `state_hash`.
pub fn ton_open_state_config(
    state_hash: &H256,
    config_proof: &[u8],
) -> Result<TonEpochConfigV1, TonNativeSourceError> {
    let invalid = TonNativeSourceError::InvalidValidatorTransition;
    let (boc, _computed, root) = ton_open_canonical(config_proof, state_hash)?;
    let extra = ton_mc_state_extra(&boc, root).ok_or(invalid)?;
    let cell = boc.cells.get(extra).ok_or(invalid)?;
    let mut reader = TonBitReader::new(cell).ok_or(invalid)?;
    if u16::try_from(reader.read_u64(16).ok_or(invalid)?).ok()
        != Some(TON_MC_STATE_EXTRA_CONSTRUCTOR)
    {
        return Err(invalid);
    }
    if reader.read_bit().ok_or(invalid)? {
        reader.read_ref().ok_or(invalid)?; // shard_hashes
    }
    reader.read_h256().ok_or(invalid)?; // config address
    let dictionary = reader.read_ref().ok_or(invalid)?;
    let validators = ton_config_from_dictionary(&boc, dictionary).ok_or(invalid)?;
    let timings = ton_hashmap_ref_value(
        &boc,
        dictionary,
        &TON_CONFIG_ELECTION_TIMINGS.to_be_bytes(),
        TON_CONFIG_KEY_BITS,
    )
    .ok_or(invalid)?;
    let mut timings = TonBitReader::new(boc.cells.get(timings).ok_or(invalid)?).ok_or(invalid)?;
    timings.skip_bits(96).ok_or(invalid)?;
    let stake_held_for =
        u32::try_from(timings.read_u64(32).ok_or(invalid)?).map_err(|_| invalid)?;
    if !timings.exhausted() {
        return Err(invalid);
    }
    Ok(TonEpochConfigV1 {
        validators,
        stake_held_for,
    })
}

/// Look up masterchain block `seqno` in `OldMcBlocksInfo` of a masterchain state proof rooted
/// at `state_hash` (the back-link from a fresh block to an older one).
pub fn ton_open_previous_masterchain_block(
    state_hash: &H256,
    state_proof: &[u8],
    seqno: u32,
) -> Result<TonBlockIdExtV1, TonNativeSourceError> {
    fn skip_key_max_lt(reader: &mut TonBitReader<'_>) -> Option<()> {
        reader.skip_bits(65)
    }
    let broken = TonNativeSourceError::BrokenMasterchainLink;
    let (boc, _computed, root) = ton_open_canonical(state_proof, state_hash)?;
    let extra = ton_mc_state_extra(&boc, root).ok_or(broken)?;
    let mut reader = TonBitReader::new(boc.cells.get(extra).ok_or(broken)?).ok_or(broken)?;
    reader.skip_bits(16).ok_or(broken)?;
    if reader.read_bit().ok_or(broken)? {
        reader.read_ref().ok_or(broken)?;
    }
    reader.read_h256().ok_or(broken)?;
    reader.read_ref().ok_or(broken)?; // config dictionary
    let auxiliary = ton_virtual_root_index(&boc, reader.read_ref().ok_or(broken)?).ok_or(broken)?;
    let mut auxiliary = TonBitReader::new(boc.cells.get(auxiliary).ok_or(broken)?).ok_or(broken)?;
    auxiliary.skip_bits(16 + 65).ok_or(broken)?; // flags, validator_info
    if !auxiliary.read_bit().ok_or(broken)? {
        return Err(broken);
    }
    let prev_blocks = auxiliary.read_ref().ok_or(broken)?;
    let mut leaf =
        ton_hashmap_aug_leaf_reader(&boc, prev_blocks, &seqno.to_be_bytes(), 32, skip_key_max_lt)
            .ok_or(broken)?;
    leaf.skip_bits(65).ok_or(broken)?; // KeyMaxLt
    leaf.read_bit().ok_or(broken)?; // key flag
    leaf.read_u64(64).ok_or(broken)?; // end_lt
    if u32::try_from(leaf.read_u64(32).ok_or(broken)?).ok() != Some(seqno) {
        return Err(broken);
    }
    let block = TonBlockIdExtV1 {
        workchain: TON_MASTERCHAIN_WORKCHAIN,
        shard: TON_MASTERCHAIN_SHARD,
        seqno,
        root_hash: leaf.read_h256().ok_or(broken)?,
        file_hash: leaf.read_h256().ok_or(broken)?,
    };
    if !leaf.exhausted() || !valid_block_id(block) {
        return Err(broken);
    }
    Ok(block)
}

/// Open a basechain shard block header proof rooted at `block_id.root_hash`.
pub fn ton_open_shard_block(
    block_id: TonBlockIdExtV1,
    header_proof: &[u8],
) -> Result<TonShardHeaderV1, TonNativeSourceError> {
    if block_id.workchain != TON_BASECHAIN_WORKCHAIN || !valid_block_id(block_id) {
        return Err(TonNativeSourceError::ShardNotFinalized);
    }
    let (boc, computed, root) = ton_open_canonical(header_proof, &block_id.root_hash)?;
    let block = ton_parse_block(&boc, &computed, root).ok_or(TonNativeSourceError::InvalidBoc)?;
    let info = block.info;
    if block.global_id != TON_MAINNET_GLOBAL_ID
        || !info.not_master
        || info.workchain != block_id.workchain
        || info.shard != block_id.shard
        || info.seqno != block_id.seqno
    {
        return Err(TonNativeSourceError::ShardNotFinalized);
    }
    Ok(TonShardHeaderV1 {
        block_id,
        previous: info.previous,
        merged_previous: info.merged_previous,
        gen_utime: info.gen_utime,
    })
}

fn ton_read_snake_bytes(boc: &TonBoc, index: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut next = Some(index);
    while let Some(index) = next {
        let index = ton_virtual_root_index(boc, index)?;
        let cell = boc.cells.get(index)?;
        let mut reader = TonBitReader::new(cell)?;
        let bits = reader.remaining_bits()?;
        if bits == 0 || bits % 8 != 0 || bits / 8 > TON_SNAKE_CHUNK_BYTES {
            return None;
        }
        for _ in 0..bits / 8 {
            out.push(u8::try_from(reader.read_u64(8)?).ok()?);
        }
        next = match reader.remaining_refs()? {
            0 => None,
            1 if bits / 8 == TON_SNAKE_CHUNK_BYTES => Some(reader.read_ref()?),
            _ => return None,
        };
        if out.len() > TON_MAX_SNAKE_BYTES {
            return None;
        }
    }
    Some(out)
}

fn ton_parse_sccp_ext_out(boc: &TonBoc, message: usize, minter: &H256) -> Option<TonSccpEventV1> {
    let index = ton_virtual_root_index(boc, message)?;
    let mut reader = TonBitReader::new(boc.cells.get(index)?)?;
    if reader.read_u64(2)? != 0b11 {
        return None;
    }
    let source = ton_read_internal_address(&mut reader)?;
    if source.workchain != TON_BASECHAIN_WORKCHAIN || source.account != *minter {
        return None;
    }
    match reader.read_u64(2)? {
        0b00 => {}
        0b01 => {
            let length = reader.read_usize(9)?;
            reader.skip_bits(length)?;
        }
        _ => return None,
    }
    reader.skip_bits(64 + 32)?; // created_lt, created_at
    if reader.read_bit()? {
        return None; // no StateInit on an event
    }
    let mut body = if reader.read_bit()? {
        let reference = reader.read_ref()?;
        reader.exhausted().then_some(())?;
        TonBitReader::new(boc.cells.get(ton_virtual_root_index(boc, reference)?)?)?
    } else {
        reader
    };
    let op = u32::try_from(body.read_u64(32)?).ok()?;
    let message_id = body.read_h256()?;
    let event = match op {
        TON_SCCP_TRANSFER_TO_TAIRA_OP => {
            let nonce = body.read_u64(64)?;
            let sender = ton_read_canonical_std_address(&mut body)?;
            let amount = ton_read_canonical_coins(&mut body)?;
            let payload = ton_read_snake_bytes(boc, body.read_ref()?)?;
            TonSccpEventV1::TransferToTaira {
                message_id,
                nonce,
                sender: sender.account,
                amount,
                payload,
            }
        }
        TON_SCCP_VOIDED_OP => TonSccpEventV1::Voided {
            message_id,
            first_nonce: body.read_u64(64)?,
            count: u16::try_from(body.read_u64(16)?).ok()?,
        },
        _ => return None,
    };
    body.exhausted().then_some(event)
}

/// The transaction reference of `account` at `lt` in a block's `account_blocks`, possibly a
/// pruned branch: its (merkle-opened) cell index.
fn ton_transaction_ref_in_block(
    boc: &TonBoc,
    account_blocks_wrapper: usize,
    account: H256,
    transaction_lt: u64,
) -> Option<usize> {
    let root = ton_hashmap_aug_e_root(boc, account_blocks_wrapper, ton_skip_currency_collection)?;
    if root == usize::MAX {
        return None;
    }
    let mut leaf = ton_hashmap_aug_leaf_reader(
        boc,
        root,
        &account,
        TON_SHARD_ACCOUNT_KEY_BITS,
        ton_skip_currency_collection,
    )?;
    ton_skip_currency_collection(&mut leaf)?;
    if u8::try_from(leaf.read_u64(4)?).ok()? != TON_ACCOUNT_BLOCK_CONSTRUCTOR
        || leaf.read_h256()? != account
    {
        return None;
    }
    let mut reader = leaf;
    let key = transaction_lt.to_be_bytes();
    let mut key_offset = 0_usize;
    let mut remaining = usize::from(TON_ACCOUNT_TRANSACTION_KEY_BITS);
    for _ in 0..=boc.cells.len() {
        let label = ton_read_hashmap_label(
            &mut reader,
            &key,
            TON_ACCOUNT_TRANSACTION_KEY_BITS,
            key_offset,
            remaining,
        )?;
        key_offset += label;
        remaining -= label;
        if remaining == 0 {
            ton_skip_currency_collection(&mut reader)?;
            return ton_merkle_opened_index(boc, reader.read_ref()?);
        }
        let go_right = ton_key_bit(&key, TON_ACCOUNT_TRANSACTION_KEY_BITS, key_offset)?;
        key_offset += 1;
        remaining -= 1;
        let left = reader.read_ref()?;
        let right = reader.read_ref()?;
        let child = ton_virtual_root_index(boc, if go_right { right } else { left })?;
        reader = TonBitReader::new(boc.cells.get(child)?)?;
    }
    None
}

/// Open the SCCP event of `minter` in the event block: the transaction at `transaction_lt`
/// (whose cell the block proof may prune; `transaction_boc` supplies it), which must have
/// succeeded, and its external-out message `message_index`.
pub fn ton_open_sccp_event(
    block_id: TonBlockIdExtV1,
    block_proof: &[u8],
    transaction_boc: &[u8],
    minter: H256,
    transaction_lt: u64,
    message_index: u16,
) -> Result<TonSccpEventV1, TonNativeSourceError> {
    let invalid = TonNativeSourceError::InvalidTransaction;
    let (boc, computed, root) = ton_open_canonical(block_proof, &block_id.root_hash)?;
    let block = ton_parse_block(&boc, &computed, root).ok_or(TonNativeSourceError::InvalidBoc)?;
    if block.info.seqno != block_id.seqno || block.info.shard != block_id.shard {
        return Err(TonNativeSourceError::ShardNotFinalized);
    }
    let account_blocks =
        ton_parse_block_extra_account_blocks(&boc, block.extra_index).ok_or(invalid)?;
    let reference = ton_transaction_ref_in_block(&boc, account_blocks, minter, transaction_lt)
        .ok_or(invalid)?;
    let transaction_hash = ton_original_tree_hash(&computed, reference).ok_or(invalid)?;
    let (tx_boc, _tx_computed, tx_root) = ton_open_canonical(transaction_boc, &transaction_hash)?;
    let transaction =
        ton_parse_transaction(&tx_boc, tx_root, minter, transaction_lt).ok_or(invalid)?;
    if ton_transaction_succeeded(&tx_boc, transaction) != Some(true) {
        return Err(TonNativeSourceError::UnsuccessfulTransaction);
    }
    let message = ton_transaction_out_message(&tx_boc, transaction, message_index)
        .ok_or(TonNativeSourceError::InvalidOutboundMessage)?;
    ton_parse_sccp_ext_out(&tx_boc, message, &minter)
        .ok_or(TonNativeSourceError::InvalidOutboundMessage)
}

#[cfg(test)]
#[path = "test_fixtures/ton_mainnet_capture_tests.rs"]
mod mainnet_capture_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, Signature};

    const TON_BLOCK_ID_EXT_TL_CONSTRUCTOR: u32 = 0x6752_eb78;

    fn hex32(value: &str) -> H256 {
        assert_eq!(value.len(), 64);
        let mut out = [0_u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&value[offset..offset + 2], 16).expect("valid fixture hex");
        }
        out
    }

    fn fixture_block() -> TonBlockIdExtV1 {
        TonBlockIdExtV1 {
            workchain: TON_MASTERCHAIN_WORKCHAIN,
            shard: TON_MASTERCHAIN_SHARD,
            seqno: 42,
            root_hash: [0x11; 32],
            file_hash: [0x22; 32],
        }
    }

    fn fixture_validator(seed: u8, weight: u64) -> (KeyPair, TonValidatorV1) {
        let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture Ed25519 key");
        let (algorithm, raw) = pair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key bytes");
        assert_eq!(algorithm, Algorithm::Ed25519);
        let public_key = raw.try_into().expect("Ed25519 public keys are 32 bytes");
        (
            pair,
            TonValidatorV1 {
                public_key,
                weight,
                adnl_address: [seed; 32],
            },
        )
    }

    fn signed_entry(
        pair: &KeyPair,
        validator: TonValidatorV1,
        transcript: &[u8],
    ) -> TonValidatorSignatureV1 {
        TonValidatorSignatureV1 {
            node_id_short: ton_validator_node_id_short_v1(&validator.public_key)
                .expect("fixture node id"),
            signature: Signature::try_new(pair.private_key(), transcript)
                .expect("fixture signature")
                .payload()
                .to_vec(),
        }
    }

    fn ordinary_cell(data: Vec<u8>, refs: Vec<usize>) -> TonBocCell {
        TonBocCell {
            descriptor: u8::try_from(refs.len()).expect("fixture ref count"),
            data_descriptor: u8::try_from(data.len() * 2).expect("fixture cell byte count"),
            data,
            refs,
            exotic: false,
        }
    }

    fn pruned_branch_cell(mask: u8, hashes: &[H256], depths: &[u16]) -> TonBocCell {
        let count = ton_level_mask_hash_index(mask);
        assert_eq!(hashes.len(), count);
        assert_eq!(depths.len(), count);
        let mut data = vec![1, mask];
        for hash in hashes {
            data.extend_from_slice(hash);
        }
        for depth in depths {
            data.extend_from_slice(&depth.to_be_bytes());
        }
        TonBocCell {
            descriptor: 0x08 | (mask << 5),
            data_descriptor: u8::try_from(data.len() * 2).expect("fixture cell byte count"),
            data,
            refs: Vec::new(),
            exotic: true,
        }
    }

    fn merkle_proof_cell(reference: usize, child_mask: u8, hash: H256, depth: u16) -> TonBocCell {
        let mut data = vec![3];
        data.extend_from_slice(&hash);
        data.extend_from_slice(&depth.to_be_bytes());
        TonBocCell {
            descriptor: 0x09 | (ton_level_mask_value(child_mask >> 1) << 5),
            data_descriptor: u8::try_from(data.len() * 2).expect("fixture cell byte count"),
            data,
            refs: vec![reference],
            exotic: true,
        }
    }

    fn reset_roster_key_parse_count() {
        TON_ROSTER_KEY_PARSE_COUNT.with(|count| count.set(0));
    }

    fn roster_key_parse_count() -> usize {
        TON_ROSTER_KEY_PARSE_COUNT.with(core::cell::Cell::get)
    }

    #[derive(Default)]
    struct TestBits(Vec<bool>);

    impl TestBits {
        fn bit(&mut self, value: bool) {
            self.0.push(value);
        }

        fn uint(&mut self, value: u64, width: usize) {
            for shift in (0..width).rev() {
                self.bit(value & (1_u64 << shift) != 0);
            }
        }

        fn bytes(&mut self, value: &[u8]) {
            for byte in value {
                self.uint(u64::from(*byte), 8);
            }
        }

        fn cell(self, refs: Vec<usize>) -> TonBocCell {
            let bit_len = self.0.len();
            let byte_len = bit_len.div_ceil(8);
            let mut data = vec![0_u8; byte_len];
            for (index, bit) in self.0.into_iter().enumerate() {
                if bit {
                    data[index / 8] |= 1 << (7 - index % 8);
                }
            }
            let data_descriptor = if bit_len.is_multiple_of(8) {
                byte_len * 2
            } else {
                data[bit_len / 8] |= 1 << (7 - bit_len % 8);
                byte_len * 2 - 1
            };
            TonBocCell {
                descriptor: u8::try_from(refs.len()).expect("fixture ref count"),
                data_descriptor: u8::try_from(data_descriptor).expect("fixture data descriptor"),
                data,
                refs,
                exotic: false,
            }
        }
    }

    fn serialize_test_boc(boc: &TonBoc) -> Vec<u8> {
        assert_eq!(boc.roots, [0]);
        assert!(boc.cells.len() < 256);
        let total_cells_size = boc
            .cells
            .iter()
            .map(|cell| 2 + cell.data.len() + cell.refs.len())
            .sum::<usize>();
        assert!(total_cells_size < usize::from(u16::MAX));
        let offset_bytes = if total_cells_size < 256 { 1 } else { 2 };
        let mut out = TON_BOC_MAGIC.to_vec();
        out.extend_from_slice(&[
            1,
            offset_bytes,
            u8::try_from(boc.cells.len()).expect("fixture cell count"),
            1,
            0,
        ]);
        if offset_bytes == 1 {
            out.push(u8::try_from(total_cells_size).expect("fixture serialized size"));
        } else {
            out.extend_from_slice(
                &u16::try_from(total_cells_size)
                    .expect("fixture serialized size")
                    .to_be_bytes(),
            );
        }
        out.push(0);
        for cell in &boc.cells {
            out.push(cell.descriptor);
            out.push(cell.data_descriptor);
            out.extend_from_slice(&cell.data);
            out.extend(
                cell.refs
                    .iter()
                    .map(|reference| u8::try_from(*reference).expect("fixture reference")),
            );
        }
        out
    }

    fn simplex_candidate_without_parents(block: TonBlockIdExtV1) -> Vec<u8> {
        let mut candidate = Vec::new();
        push_u32_le(
            &mut candidate,
            TON_CONSENSUS_CANDIDATE_ORDINARY_TL_CONSTRUCTOR,
        );
        push_i32_le(&mut candidate, block.workchain);
        push_u64_le(&mut candidate, block.shard);
        push_u32_le(&mut candidate, block.seqno);
        candidate.extend_from_slice(&block.root_hash);
        candidate.extend_from_slice(&block.file_hash);
        candidate.extend_from_slice(&[0x33; 32]);
        push_u32_le(
            &mut candidate,
            TON_CONSENSUS_CANDIDATE_WITHOUT_PARENTS_TL_CONSTRUCTOR,
        );
        candidate
    }

    fn masterchain_continuation_fixture(
        previous: TonBlockIdExtV1,
        active: &TonValidatorSetV1,
    ) -> (TonBlockIdExtV1, Vec<u8>, H256, H256) {
        let old_state = ordinary_cell(vec![0xa1], Vec::new());
        let new_state = ordinary_cell(vec![0xa2], Vec::new());
        let state_cells = TonBoc {
            roots: vec![0],
            cells: vec![old_state.clone(), new_state.clone()],
        };
        let state_hashes = ton_boc_cell_hashes(&state_cells).expect("state hashes");
        let old_state_hash = state_hashes[0].hashes[0];
        let new_state_hash = state_hashes[1].hashes[0];

        let mut root = TestBits::default();
        root.uint(u64::from(TON_BLOCK_CONSTRUCTOR), 32);
        root.uint(
            u64::from(u32::from_be_bytes(TON_MAINNET_GLOBAL_ID.to_be_bytes())),
            32,
        );

        let mut info = TestBits::default();
        info.uint(u64::from(TON_BLOCK_INFO_CONSTRUCTOR), 32);
        info.uint(0, 32); // version
        for _ in 0..8 {
            info.bit(false);
        }
        info.uint(1, 8); // gen_software is present
        info.uint(u64::from(previous.seqno + 1), 32);
        info.uint(0, 32); // vertical seqno
        info.uint(0, 2); // ShardIdent constructor
        info.uint(0, 6); // masterchain prefix length
        info.uint(u64::from(u32::MAX), 32);
        info.uint(0, 64); // on-wire shard prefix excludes the terminator
        info.uint(1, 32); // generation time
        info.uint(1, 64); // start logical time
        info.uint(2, 64); // end logical time
        info.uint(u64::from(active.validator_list_hash_short), 32);
        info.uint(u64::from(active.catchain_seqno), 32);
        info.uint(0, 32); // minimum referenced masterchain seqno
        info.uint(0, 32); // previous key-block seqno
        info.uint(u64::from(TON_GLOBAL_VERSION_CONSTRUCTOR), 8);
        info.uint(12, 32); // global version
        info.uint(0, 64); // capabilities

        let mut previous_ref = TestBits::default();
        previous_ref.uint(1, 64); // end logical time
        previous_ref.uint(u64::from(previous.seqno), 32);
        previous_ref.bytes(&previous.root_hash);
        previous_ref.bytes(&previous.file_hash);

        let mut update_data = vec![4];
        update_data.extend_from_slice(&old_state_hash);
        update_data.extend_from_slice(&new_state_hash);
        update_data.extend_from_slice(&state_hashes[0].depths[0].to_be_bytes());
        update_data.extend_from_slice(&state_hashes[1].depths[0].to_be_bytes());
        let state_update = TonBocCell {
            descriptor: 0x0a,
            data_descriptor: u8::try_from(update_data.len() * 2)
                .expect("fixture update descriptor"),
            data: update_data,
            refs: vec![3, 4],
            exotic: true,
        };

        let mut extra = TestBits::default();
        extra.uint(u64::from(TON_BLOCK_EXTRA_CONSTRUCTOR), 32);
        extra.bytes(&[0; 64]); // random seed and creator
        extra.bit(true); // custom masterchain extra is present
        let mut custom = TestBits::default();
        custom.uint(u64::from(TON_MC_BLOCK_EXTRA_CONSTRUCTOR), 16);
        custom.bit(false); // not a key block
        custom.bit(false); // no ShardHashes dictionary needed for this finality-only fixture
        custom.bit(false); // no shard-fees dictionary
        for _ in 0..2 {
            custom.uint(0, 4); // zero grams
            custom.bit(false); // no extra currencies
        }

        let boc = TonBoc {
            roots: vec![0],
            cells: vec![
                root.cell(vec![1, 8, 2, 5]),
                info.cell(vec![6]),
                state_update,
                old_state,
                new_state,
                extra.cell(vec![8, 8, 8, 7]),
                previous_ref.cell(Vec::new()),
                custom.cell(vec![8]),
                ordinary_cell(Vec::new(), Vec::new()),
            ],
        };
        // Finality admission requires one shared cell per structural subtree
        // and canonical topological ordering, including ignored empty cells.
        let bytes = encode_canonical_ton_boc(&boc, 0).expect("canonical continuation fixture");
        let block_id = TonBlockIdExtV1 {
            workchain: TON_MASTERCHAIN_WORKCHAIN,
            shard: TON_MASTERCHAIN_SHARD,
            seqno: previous.seqno + 1,
            root_hash: ton_boc_single_root_hash_v1(&bytes).expect("fixture block root"),
            file_hash: Sha256::digest(&bytes).into(),
        };
        (block_id, bytes, old_state_hash, new_state_hash)
    }

    #[test]
    fn shard_ident_decodes_native_prefix_without_block_id_terminator() {
        // Wire vectors follow TON ShardIdent::pack: shard & (shard - 1),
        // https://github.com/ton-blockchain/ton/blob/master/crypto/block/block-parse.cpp.
        let parse = |prefix_bits: u8, workchain: i32, prefix: u64| {
            let mut wire = vec![prefix_bits]; // $00 followed by six prefix-length bits
            wire.extend_from_slice(&workchain.to_be_bytes());
            wire.extend_from_slice(&prefix.to_be_bytes());
            let cell = ordinary_cell(wire, Vec::new());
            ton_read_shard_ident(&mut TonBitReader::new(&cell).expect("wire cell"))
        };
        assert_eq!(parse(0, -1, 0), Some((-1, 0x8000_0000_0000_0000)));
        assert_eq!(parse(0, 0, 0), Some((0, 0x8000_0000_0000_0000)));
        assert_eq!(parse(1, 0, 0), Some((0, 0x4000_0000_0000_0000)));
        assert_eq!(
            parse(1, 0, 0x8000_0000_0000_0000),
            Some((0, 0xc000_0000_0000_0000))
        );
        assert_eq!(parse(60, 0, 0x10), Some((0, 0x18)));
        for (bits, prefix) in [(0, 1), (0, 1 << 63), (1, 1 << 62), (60, 8), (61, 0)] {
            assert_eq!(parse(bits, 0, prefix), None);
        }
    }

    #[test]
    fn block_extra_requires_native_implicit_constructor() {
        // block_extra's implicit TL-B CRC32 tag is 0x4a33f6fd. Keep these
        // literal bytes independent of the parser constant and fixture helper.
        let mut extra = vec![0x4a, 0x33, 0xf6, 0xfd];
        extra.extend_from_slice(&[0; 64]);
        extra.push(0xc0); // custom present, then the cell top-up bit
        let mut custom = TestBits::default();
        custom.uint(0xcca5, 16);
        custom.bit(false); // not a key block
        custom.bit(false); // empty ShardHashes
        custom.bit(false); // empty ShardFees
        custom.uint(0, 10); // two empty CurrencyCollections
        let boc = TonBoc {
            roots: vec![0],
            cells: vec![
                TonBocCell {
                    descriptor: 4,
                    data_descriptor: 137,
                    data: extra,
                    refs: vec![1, 1, 1, 2],
                    exotic: false,
                },
                ordinary_cell(Vec::new(), Vec::new()),
                custom.cell(vec![3]),
                ordinary_cell(Vec::new(), Vec::new()),
            ],
        };
        let parsed = ton_parse_masterchain_extra(&boc, 0).expect("native BlockExtra");
        assert!(parsed.shard_hashes_root.is_none());
        assert_eq!(ton_parse_block_extra_account_blocks(&boc, 0), Some(1));
        for omit in [false, true] {
            let mut malformed = boc.clone();
            if omit {
                malformed.cells[0].data.drain(..4);
                malformed.cells[0].data_descriptor -= 8;
            } else {
                malformed.cells[0].data[0] ^= 1;
            }
            assert!(ton_parse_masterchain_extra(&malformed, 0).is_none());
            assert_eq!(ton_parse_block_extra_account_blocks(&malformed, 0), None);
        }
    }

    #[test]
    fn block_info_requires_capabilities_constructor_when_software_is_present() {
        let (_, validator) = fixture_validator(1, 1);
        let validators = vec![validator];
        let validator_list_hash_short =
            ton_validator_list_hash_short_v1(7, &validators).expect("fixture set hash");
        let checkpoint = TonBlockIdExtV1 {
            seqno: 1,
            ..fixture_block()
        };
        let (_, bytes, _, _) = masterchain_continuation_fixture(
            checkpoint,
            &TonValidatorSetV1 {
                catchain_seqno: 7,
                validator_list_hash_short,
                validators,
            },
        );
        let boc = parse_ton_boc(&bytes).expect("block fixture");
        let expected = ton_parse_block_info(&boc, 1).expect("native software extension");
        let software_offset = boc.cells[1].data.len() - 13;
        assert_eq!(boc.cells[1].data[9], 1);
        assert_eq!(boc.cells[1].data[software_offset], 0xc4);

        let mut absent = boc.clone();
        absent.cells[1].data[9] = 0;
        absent.cells[1].data.truncate(software_offset);
        absent.cells[1].data_descriptor -= 26;
        assert_eq!(ton_parse_block_info(&absent, 1), Some(expected));
        for omit in [false, true] {
            let mut malformed = boc.clone();
            if omit {
                malformed.cells[1].data.remove(software_offset);
                malformed.cells[1].data_descriptor -= 2;
            } else {
                malformed.cells[1].data[software_offset] ^= 1;
            }
            assert_eq!(ton_parse_block_info(&malformed, 1), None);
        }
    }

    #[test]
    fn prev_ref_resolves_predecessor_shards_across_splits_and_merges() {
        const LEFT: u64 = 0x4000_0000_0000_0000;
        const WHOLE: u64 = 0x8000_0000_0000_0000;
        const RIGHT: u64 = 0xc000_0000_0000_0000;
        let ext_block_ref = |seqno: u32, hash: u8| {
            let mut data = (u64::from(seqno) * 1_000).to_be_bytes().to_vec(); // end_lt
            data.extend_from_slice(&seqno.to_be_bytes());
            data.extend_from_slice(&[hash; 32]);
            data.extend_from_slice(&[!hash; 32]);
            ordinary_cell(data, Vec::new())
        };
        let block = |shard: u64, seqno: u32, hash: u8| TonBlockIdExtV1 {
            workchain: 0,
            shard,
            seqno,
            root_hash: [hash; 32],
            file_hash: [!hash; 32],
        };
        let boc = TonBoc {
            roots: vec![0],
            cells: vec![
                ordinary_cell(Vec::new(), vec![1, 2]),
                ext_block_ref(9, 0x11),
                ext_block_ref(8, 0x22),
            ],
        };
        assert_eq!(
            ton_parse_prev_ref(&boc, 1, 0, LEFT, false, false),
            Some((Some(block(LEFT, 9, 0x11)), None))
        );
        assert_eq!(
            ton_parse_prev_ref(&boc, 1, 0, LEFT, false, true),
            Some((Some(block(WHOLE, 9, 0x11)), None))
        );
        assert_eq!(
            ton_parse_prev_ref(&boc, 0, 0, WHOLE, true, false),
            Some((None, Some((block(LEFT, 9, 0x11), block(RIGHT, 8, 0x22)))))
        );
        // The whole-workchain shard has no parent it could have split from.
        assert_eq!(ton_parse_prev_ref(&boc, 1, 0, WHOLE, false, true), None);
        // `prev_blks_info` holds exactly the two predecessor references.
        let mut padded = boc.clone();
        padded.cells[0] = ordinary_cell(vec![0], vec![1, 2]);
        assert_eq!(ton_parse_prev_ref(&padded, 0, 0, WHOLE, true, false), None);
    }

    #[test]
    fn shard_descriptor_rejects_unregistered_nonzero_shard_block() {
        let expected = TonBlockIdExtV1 {
            workchain: 0,
            shard: 0x8000_0000_0000_0000,
            seqno: 17,
            root_hash: [0x71; 32],
            file_hash: [0x72; 32],
        };
        for constructor in [0x0a, 0x0b] {
            for registered_seqno in [0_u32, 1, 16] {
                let mut bits = TestBits::default();
                bits.uint(constructor, 4);
                bits.uint(u64::from(expected.seqno), 32);
                bits.uint(u64::from(registered_seqno), 32);
                bits.uint(42, 64);
                bits.uint(43, 64);
                bits.bytes(&expected.root_hash);
                bits.bytes(&expected.file_hash);
                let cell = bits.cell(Vec::new());
                let mut reader = TonBitReader::new(&cell).expect("shard descriptor cell");
                assert_eq!(
                    ton_parse_shard_descriptor(&mut reader, expected.workchain, expected.shard),
                    (registered_seqno != 0).then_some((expected, registered_seqno))
                );
            }
        }
    }

    #[test]
    fn validator_node_id_and_roster_hash_match_native_vectors() {
        let keys = [
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            hex32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
        ];
        assert_eq!(
            ton_validator_node_id_short_v1(&keys[0]),
            Some(hex32(
                "1ebe11eac72c9c99edca05d0fe3bbf1bdbfd5225d20862df516e14dece65d11e"
            ))
        );
        let validators = keys
            .into_iter()
            .zip([1_u64, 2, 3])
            .zip([1_u8, 2, 3])
            .map(|((public_key, weight), adnl)| TonValidatorV1 {
                public_key,
                weight,
                adnl_address: [adnl; 32],
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ton_validator_list_hash_short_v1(17, &validators),
            Some(0x9a58_6c28)
        );

        let mut duplicate = validators.clone();
        duplicate[2].public_key = duplicate[0].public_key;
        assert_eq!(ton_validator_list_hash_short_v1(17, &duplicate), None);
        duplicate = validators.clone();
        duplicate[2].adnl_address = duplicate[0].adnl_address;
        assert_eq!(ton_validator_list_hash_short_v1(17, &duplicate), None);

        let invalid_key = [0xff; 32];
        assert_eq!(ton_validator_node_id_short_v1(&invalid_key), None);
        duplicate = validators;
        duplicate[2].public_key = invalid_key;
        assert_eq!(ton_validator_list_hash_short_v1(17, &duplicate), None);
    }

    /// Config 28 sets the shuffle flag; with it, the masterchain subset of a catchain session is
    /// a seeded permutation of the first `main` validators (the mainnet capture tests check the
    /// order against real headers' `validator_list_hash_short`).
    #[test]
    fn config_28_shuffle_flag_permutes_the_masterchain_subset_per_session() {
        let catchain = |data: Vec<u8>| TonBoc {
            roots: vec![0],
            cells: vec![ordinary_cell(data, Vec::new())],
        };
        let lifetimes = |values: [u32; 4]| {
            values
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>()
        };
        let live = lifetimes([250, 250, 1_000, 7]);
        // `catchain_config#c1` has no flag; `catchain_config_new#c2` has 7 zero flag bits and
        // then `shuffle_mc_validators`.
        for (head, expected) in [
            (vec![TON_CATCHAIN_CONFIG_CONSTRUCTOR], Some(false)),
            (vec![TON_CATCHAIN_CONFIG_NEW_CONSTRUCTOR, 0x00], Some(false)),
            (vec![TON_CATCHAIN_CONFIG_NEW_CONSTRUCTOR, 0x01], Some(true)),
            (vec![TON_CATCHAIN_CONFIG_NEW_CONSTRUCTOR, 0x02], None),
            (vec![0xc3, 0x01], None),
        ] {
            let data = [head.clone(), live.clone()].concat();
            assert_eq!(
                ton_parse_catchain_shuffle(&catchain(data), 0),
                expected,
                "{head:02x?}"
            );
        }
        let zero_lifetime = [
            vec![TON_CATCHAIN_CONFIG_NEW_CONSTRUCTOR, 0x01],
            lifetimes([250, 0, 1_000, 7]),
        ]
        .concat();
        assert_eq!(
            ton_parse_catchain_shuffle(&catchain(zero_lifetime), 0),
            None
        );

        let validators = (1..=7_u8)
            .map(|seed| fixture_validator(seed, 10 + u64::from(seed)).1)
            .collect::<Vec<_>>();
        let shuffled = TonValidatorConfigV1 {
            valid_since: 1,
            valid_until: 2,
            main_validator_count: 5,
            shuffle_masterchain_validators: true,
            validators: validators.clone(),
        };
        let plain = TonValidatorConfigV1 {
            shuffle_masterchain_validators: false,
            ..shuffled.clone()
        };
        assert_eq!(
            ton_select_masterchain_validator_set(&plain, 9)
                .expect("subset")
                .validators,
            validators[..5]
        );
        let sorted = |set: &[TonValidatorV1]| {
            let mut keys = set.iter().map(|v| v.public_key).collect::<Vec<_>>();
            keys.sort_unstable();
            keys
        };
        let mut orders = BTreeSet::new();
        for seqno in 0..16 {
            let subset = ton_select_masterchain_validator_set(&shuffled, seqno).expect("subset");
            assert_eq!(
                Some(&subset),
                ton_select_masterchain_validator_set(&shuffled, seqno).as_ref(),
                "deterministic"
            );
            assert_eq!(subset.catchain_seqno, seqno);
            assert_eq!(
                sorted(&subset.validators),
                sorted(&validators[..5]),
                "a permutation of the main validators"
            );
            assert_eq!(
                Some(subset.validator_list_hash_short),
                ton_validator_list_hash_short_from_validated(seqno, &subset.validators),
                "the hash covers the shuffled order"
            );
            orders.insert(
                subset
                    .validators
                    .iter()
                    .map(|v| v.public_key)
                    .collect::<Vec<_>>(),
            );
        }
        assert!(
            orders.len() > 1,
            "the order depends on the catchain session"
        );
    }

    #[test]
    fn ordinary_signatures_require_unique_strictly_more_than_two_thirds_weight() {
        let block = fixture_block();
        let transcript = ton_block_id_tl_bytes(block);
        let fixtures = (1_u8..=3)
            .map(|seed| fixture_validator(seed, 1))
            .collect::<Vec<_>>();
        let validators = fixtures
            .iter()
            .map(|(_, validator)| *validator)
            .collect::<Vec<_>>();
        let hash = ton_validator_list_hash_short_v1(9, &validators).expect("fixture set hash");
        let active = TonValidatorSetV1 {
            catchain_seqno: 9,
            validator_list_hash_short: hash,
            validators,
        };
        let mut entries = fixtures
            .iter()
            .map(|(pair, validator)| signed_entry(pair, *validator, &transcript))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.node_id_short);
        let proof = |signatures| {
            TonBlockSignaturesV1::Ordinary(TonOrdinaryBlockSignaturesV1 {
                catchain_seqno: 9,
                validator_list_hash_short: hash,
                signatures,
            })
        };

        assert_eq!(
            verify_block_signatures(block, &active, &proof(entries[..2].to_vec())),
            Err(TonNativeSourceError::InvalidSignatures)
        );
        reset_roster_key_parse_count();
        assert_eq!(
            verify_block_signatures(block, &active, &proof(entries.clone())),
            Ok(())
        );
        assert_eq!(
            roster_key_parse_count(),
            active.validators.len(),
            "signature verification must charge one roster-key pass separately from signer checks"
        );
        let mut out_of_order = entries.clone();
        out_of_order.swap(0, 1);
        assert_eq!(
            verify_block_signatures(block, &active, &proof(out_of_order)),
            Err(TonNativeSourceError::InvalidSignatures)
        );
        assert_eq!(
            verify_block_signatures(
                block,
                &active,
                &proof(vec![
                    entries[0].clone(),
                    entries[0].clone(),
                    entries[2].clone()
                ]),
            ),
            Err(TonNativeSourceError::InvalidSignatures)
        );
        let (unknown_pair, unknown_validator) = fixture_validator(9, 1);
        let unknown = signed_entry(&unknown_pair, unknown_validator, &transcript);
        assert_eq!(
            verify_block_signatures(
                block,
                &active,
                &proof(vec![entries[0].clone(), entries[1].clone(), unknown]),
            ),
            Err(TonNativeSourceError::InvalidSignatures)
        );
        let mut corrupted = entries;
        corrupted[2].signature[0] ^= 0x80;
        assert_eq!(
            verify_block_signatures(block, &active, &proof(corrupted)),
            Err(TonNativeSourceError::InvalidSignatures)
        );
    }

    #[test]
    fn simplex_transcript_is_exact_and_slot_is_a_nonnegative_tl_int() {
        let block = fixture_block();
        let candidate_data = simplex_candidate_without_parents(block);
        assert_eq!(parse_simplex_candidate_data(&candidate_data), Some(block));
        let mut signatures = TonSimplexBlockSignaturesV1 {
            catchain_seqno: 1,
            validator_list_hash_short: 2,
            session_id: [0x44; 32],
            slot: u32::MAX >> 1,
            candidate_data: candidate_data.clone(),
            signatures: Vec::new(),
        };
        let transcript = simplex_finality_transcript(block, &signatures).expect("valid transcript");
        assert_eq!(transcript.len(), 84);
        assert_eq!(
            &transcript[..4],
            &TON_CONSENSUS_DATA_TO_SIGN_TL_CONSTRUCTOR.to_le_bytes()
        );
        assert_eq!(&transcript[4..36], &signatures.session_id);
        assert_eq!(transcript[36], 44);
        assert_eq!(
            &transcript[37..41],
            &TON_CONSENSUS_SIMPLEX_FINALIZE_TL_CONSTRUCTOR.to_le_bytes()
        );
        assert_eq!(
            &transcript[41..45],
            &TON_CONSENSUS_CANDIDATE_ID_TL_CONSTRUCTOR.to_le_bytes()
        );
        assert_eq!(&transcript[45..49], &i32::MAX.to_le_bytes());
        assert_eq!(&transcript[81..], &[0, 0, 0]);

        signatures.slot = (u32::MAX >> 1) + 1;
        assert_eq!(simplex_finality_transcript(block, &signatures), None);
        signatures.slot = 1;
        signatures.candidate_data.push(0);
        assert_eq!(simplex_finality_transcript(block, &signatures), None);

        let mut boxed_nested = candidate_data;
        boxed_nested.splice(4..4, TON_BLOCK_ID_EXT_TL_CONSTRUCTOR.to_le_bytes());
        assert_eq!(parse_simplex_candidate_data(&boxed_nested), None);
    }

    #[test]
    fn boc_parser_matches_empty_cell_hash_and_crc_vectors() {
        const EMPTY: &[u8] = &[
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        const EMPTY_WITH_CRC: &[u8] = &[
            0xb5, 0xee, 0x9c, 0x72, 0x41, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x4c,
            0xac, 0xb9, 0xcd,
        ];
        let expected = hex32("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7");
        assert_eq!(ton_boc_single_root_hash_v1(EMPTY), Some(expected));
        let mut proof_data = vec![3];
        proof_data.extend_from_slice(&expected);
        proof_data.extend_from_slice(&0_u16.to_be_bytes());
        let merkle_proof = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![
                TonBocCell {
                    descriptor: 0x09,
                    data_descriptor: 70,
                    data: proof_data,
                    refs: vec![1],
                    exotic: true,
                },
                ordinary_cell(Vec::new(), Vec::new()),
            ],
        });
        assert_eq!(ton_boc_single_root_hash_v1(&merkle_proof), Some(expected));
        let unused_cell = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![
                ordinary_cell(Vec::new(), Vec::new()),
                ordinary_cell(vec![0x42], Vec::new()),
            ],
        });
        assert_eq!(ton_boc_single_root_hash_v1(&unused_cell), Some(expected));
        assert_eq!(ton_boc_single_root_hash_v1(EMPTY_WITH_CRC), Some(expected));
        let mut corrupted = EMPTY_WITH_CRC.to_vec();
        *corrupted.last_mut().expect("fixture crc") ^= 1;
        assert_eq!(ton_boc_single_root_hash_v1(&corrupted), None);
        let mut trailing = EMPTY.to_vec();
        trailing.push(0);
        assert_eq!(ton_boc_single_root_hash_v1(&trailing), None);
    }

    #[test]
    fn canonical_boc_gate_accepts_only_one_canonical_representation() {
        const EMPTY: &[u8] = &[
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        const EMPTY_WITH_CRC: &[u8] = &[
            0xb5, 0xee, 0x9c, 0x72, 0x41, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x4c,
            0xac, 0xb9, 0xcd,
        ];
        const NONMINIMAL_SIZE_WIDTH: &[u8] = &[
            0xb5, 0xee, 0x9c, 0x72, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00,
        ];
        const NONMINIMAL_OFFSET_WIDTH: &[u8] = &[
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let expected = hex32("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7");
        assert_eq!(ton_canonical_boc_single_root_hash_v1(EMPTY), Some(expected));
        assert!(parse_ton_boc(EMPTY_WITH_CRC).is_some());
        assert!(parse_ton_boc(NONMINIMAL_SIZE_WIDTH).is_some());
        assert!(parse_ton_boc(NONMINIMAL_OFFSET_WIDTH).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(EMPTY_WITH_CRC), None);
        assert_eq!(
            ton_canonical_boc_single_root_hash_v1(NONMINIMAL_SIZE_WIDTH),
            None
        );
        assert_eq!(
            ton_canonical_boc_single_root_hash_v1(NONMINIMAL_OFFSET_WIDTH),
            None
        );

        let mut unreachable = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![
                ordinary_cell(Vec::new(), Vec::new()),
                ordinary_cell(vec![0x42], Vec::new()),
            ],
        });
        assert!(parse_ton_boc(&unreachable).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(&unreachable), None);
        // Selecting the second cell as root leaves the first one unreachable as
        // well as violating canonical root index zero.
        unreachable[10] = 1;
        assert!(parse_ton_boc(&unreachable).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(&unreachable), None);
    }

    #[test]
    fn canonical_boc_gate_rejects_duplicate_and_alternate_dags() {
        let duplicate = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![
                ordinary_cell(vec![0x10], vec![1, 2]),
                ordinary_cell(vec![0x20], Vec::new()),
                ordinary_cell(vec![0x20], Vec::new()),
            ],
        });
        assert!(parse_ton_boc(&duplicate).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(&duplicate), None);

        let alternate = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![
                // Logical reference order is A then B, but the cell table puts
                // B before A. Both parents share the same canonical child.
                ordinary_cell(vec![0x10], vec![2, 1]),
                ordinary_cell(vec![0xb0], vec![3]),
                ordinary_cell(vec![0xa0], vec![3]),
                ordinary_cell(vec![0xc0], Vec::new()),
            ],
        });
        assert!(parse_ton_boc(&alternate).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(&alternate), None);

        let canonical_graph = TonBoc {
            roots: vec![0],
            cells: vec![
                ordinary_cell(vec![0x10], vec![1, 2]),
                ordinary_cell(vec![0xa0], vec![3]),
                ordinary_cell(vec![0xb0], vec![3]),
                ordinary_cell(vec![0xc0], Vec::new()),
            ],
        };
        let canonical = serialize_test_boc(&canonical_graph);
        assert_eq!(
            encode_canonical_ton_boc(&canonical_graph, 0),
            Some(canonical.clone())
        );
        assert!(ton_canonical_boc_single_root_hash_v1(&canonical).is_some());
    }

    #[test]
    fn canonical_boc_gate_enforces_raw_level_masks_tuple_counts_and_max_depth() {
        let sparse = TonBoc {
            roots: vec![0],
            cells: vec![pruned_branch_cell(0x02, &[[0x41; 32]], &[7])],
        };
        assert!(
            ton_boc_cell_hashes(&sparse).is_some(),
            "one set level carries exactly one stored hash/depth tuple"
        );

        // Construct two valid stored tuples, then claim a one-bit mask so
        // malformed input reaches the parser instead of failing the fixture helper.
        let mut malformed = pruned_branch_cell(0x03, &[[0x41; 32], [0x42; 32]], &[7, 8]);
        malformed.descriptor = 0x08 | (0x02 << 5);
        malformed.data[1] = 0x02;
        let extra_tuple = TonBoc {
            roots: vec![0],
            cells: vec![malformed],
        };
        assert!(ton_boc_cell_hashes(&extra_tuple).is_none());

        let mut high_bit_alias = pruned_branch_cell(0x01, &[[0x51; 32]], &[9]);
        high_bit_alias.data[1] |= 0x08;
        let high_bit_alias = TonBoc {
            roots: vec![0],
            cells: vec![high_bit_alias],
        };
        assert!(ton_boc_cell_hashes(&high_bit_alias).is_none());

        let excessive_pruned_depth = TonBoc {
            roots: vec![0],
            cells: vec![pruned_branch_cell(
                0x01,
                &[[0x61; 32]],
                &[TON_MAX_CELL_DEPTH + 1],
            )],
        };
        assert!(ton_boc_cell_hashes(&excessive_pruned_depth).is_none());

        let cells = (0..=usize::from(TON_MAX_CELL_DEPTH))
            .map(|index| {
                ordinary_cell(
                    Vec::new(),
                    (index < usize::from(TON_MAX_CELL_DEPTH))
                        .then_some(index + 1)
                        .into_iter()
                        .collect(),
                )
            })
            .collect();
        let boundary = TonBoc {
            roots: vec![0],
            cells,
        };
        assert!(ton_boc_cell_hashes(&boundary).is_some());

        let excessive = TonBoc {
            roots: vec![0],
            cells: (0..=usize::from(TON_MAX_CELL_DEPTH) + 1)
                .map(|index| {
                    ordinary_cell(
                        Vec::new(),
                        (index <= usize::from(TON_MAX_CELL_DEPTH))
                            .then_some(index + 1)
                            .into_iter()
                            .collect(),
                    )
                })
                .collect(),
        };
        assert!(ton_boc_cell_hashes(&excessive).is_none());
    }

    #[test]
    fn canonical_boc_gate_rejects_tail_alias_legacy_pruning_and_nested_wrappers() {
        let zero_bit_alias = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x01, 0x80,
        ];
        assert!(parse_ton_boc(&zero_bit_alias).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(&zero_bit_alias), None);

        let byte_aligned_tail_alias = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![TonBocCell {
                descriptor: 0,
                data_descriptor: 3,
                data: vec![0x42, 0x80],
                refs: Vec::new(),
                exotic: false,
            }],
        });
        assert!(parse_ton_boc(&byte_aligned_tail_alias).is_some());
        assert_eq!(
            ton_canonical_boc_single_root_hash_v1(&byte_aligned_tail_alias),
            None
        );

        let mut root = ordinary_cell(vec![0x41], vec![1]);
        root.descriptor |= 1 << 5;
        let mut legacy_data = vec![1];
        legacy_data.extend_from_slice(&[0x51; 32]);
        legacy_data.extend_from_slice(&1_u16.to_be_bytes());
        let legacy = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![
                root,
                TonBocCell {
                    descriptor: 0x08 | (1 << 5),
                    data_descriptor: 70,
                    data: legacy_data,
                    refs: Vec::new(),
                    exotic: true,
                },
            ],
        });
        assert!(parse_single_root_boc(&legacy).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(&legacy), None);

        let leaf = TonBoc {
            roots: vec![0],
            cells: vec![ordinary_cell(vec![0x42], Vec::new())],
        };
        let leaf_hashes = ton_boc_cell_hashes(&leaf).expect("leaf hashes");
        let inner = TonBoc {
            roots: vec![0],
            cells: vec![
                merkle_proof_cell(
                    1,
                    leaf_hashes[0].mask,
                    leaf_hashes[0].hashes[0],
                    leaf_hashes[0].depths[0],
                ),
                ordinary_cell(vec![0x42], Vec::new()),
            ],
        };
        let inner_hashes = ton_boc_cell_hashes(&inner).expect("inner hashes");
        let nested = serialize_test_boc(&TonBoc {
            roots: vec![0],
            cells: vec![
                merkle_proof_cell(
                    1,
                    inner_hashes[0].mask,
                    inner_hashes[0].hashes[0],
                    inner_hashes[0].depths[0],
                ),
                merkle_proof_cell(
                    2,
                    leaf_hashes[0].mask,
                    leaf_hashes[0].hashes[0],
                    leaf_hashes[0].depths[0],
                ),
                ordinary_cell(vec![0x42], Vec::new()),
            ],
        });
        assert!(parse_single_root_boc(&nested).is_some());
        assert_eq!(ton_canonical_boc_single_root_hash_v1(&nested), None);
    }

    #[test]
    fn canonical_coins_are_minimal_and_below_two_to_the_120() {
        let mut maximum = TestBits::default();
        maximum.uint(15, 4);
        maximum.bytes(&[0xff; 15]);
        let maximum = maximum.cell(Vec::new());
        let mut reader = TonBitReader::new(&maximum).expect("maximum coins reader");
        assert_eq!(
            ton_read_canonical_coins(&mut reader),
            Some((1_u128 << 120) - 1)
        );
        assert!(reader.exhausted());

        let mut zero = TestBits::default();
        zero.uint(0, 4);
        let zero = zero.cell(Vec::new());
        let mut reader = TonBitReader::new(&zero).expect("zero coins reader");
        assert_eq!(ton_read_canonical_coins(&mut reader), Some(0));
        assert!(reader.exhausted());

        let mut nonminimal = TestBits::default();
        nonminimal.uint(2, 4);
        nonminimal.bytes(&[0, 1]);
        let nonminimal = nonminimal.cell(Vec::new());
        let mut reader = TonBitReader::new(&nonminimal).expect("nonminimal coins reader");
        assert_eq!(ton_read_canonical_coins(&mut reader), None);
    }

    #[test]
    fn block_signature_envelope_requires_strict_node_id_order() {
        let signature = |id| TonValidatorSignatureV1 {
            node_id_short: [id; 32],
            signature: vec![id; 64],
        };
        let ordinary = |signatures| {
            TonBlockSignaturesV1::Ordinary(TonOrdinaryBlockSignaturesV1 {
                catchain_seqno: 1,
                validator_list_hash_short: 1,
                signatures,
            })
        };
        assert!(ton_block_signatures_are_canonically_ordered(&ordinary(
            vec![signature(1), signature(2), signature(3),]
        )));
        assert!(!ton_block_signatures_are_canonically_ordered(&ordinary(
            vec![signature(1), signature(1),]
        )));
        assert!(!ton_block_signatures_are_canonically_ordered(&ordinary(
            vec![signature(2), signature(1),]
        )));

        let simplex = TonBlockSignaturesV1::Simplex(TonSimplexBlockSignaturesV1 {
            catchain_seqno: 1,
            validator_list_hash_short: 1,
            session_id: [0x44; 32],
            slot: 1,
            candidate_data: vec![1],
            signatures: vec![signature(1), signature(2)],
        });
        assert!(ton_block_signatures_are_canonically_ordered(&simplex));
    }

    #[test]
    fn boc_hash_zero_preserves_original_tree_identity_across_pruned_levels() {
        let complete = TonBoc {
            roots: vec![0],
            cells: vec![
                ordinary_cell(vec![0x41], vec![1]),
                ordinary_cell(vec![0x42], Vec::new()),
            ],
        };
        let complete_hashes = ton_boc_cell_hashes(&complete).expect("complete tree hashes");
        let expected_root = complete_hashes[0].hashes[0];
        let child_hash = complete_hashes[1].hashes[0];
        let child_depth = complete_hashes[1].depths[0];

        for mask in [1_u8, 3, 7] {
            let count = usize::from(ton_level_mask_level(mask));
            let mut root = ordinary_cell(vec![0x41], vec![1]);
            root.descriptor |= mask << 5;
            let stored_hashes = [child_hash; 3];
            let stored_depths = [child_depth; 3];
            let pruned = TonBoc {
                roots: vec![0],
                cells: vec![
                    root,
                    pruned_branch_cell(mask, &stored_hashes[..count], &stored_depths[..count]),
                ],
            };
            let computed = ton_boc_cell_hashes(&pruned).expect("pruned proof hashes");
            assert_eq!(computed[0].hashes[0], expected_root);
            assert_ne!(
                computed[0].hashes[3], expected_root,
                "higher virtual hashes must not replace TON hash-zero identity"
            );
            assert_eq!(
                ton_boc_single_root_hash_v1(&serialize_test_boc(&pruned)),
                Some(expected_root)
            );
        }
    }

    #[test]
    fn virtual_root_resolution_unwraps_nested_merkle_proofs() {
        let leaf = TonBoc {
            roots: vec![0],
            cells: vec![ordinary_cell(vec![0x42], Vec::new())],
        };
        let leaf_hashes = ton_boc_cell_hashes(&leaf).expect("leaf hashes");
        let inner = TonBoc {
            roots: vec![0],
            cells: vec![
                merkle_proof_cell(
                    1,
                    leaf_hashes[0].mask,
                    leaf_hashes[0].hashes[0],
                    leaf_hashes[0].depths[0],
                ),
                ordinary_cell(vec![0x42], Vec::new()),
            ],
        };
        let inner_hashes = ton_boc_cell_hashes(&inner).expect("inner proof hashes");
        let nested = TonBoc {
            roots: vec![0],
            cells: vec![
                merkle_proof_cell(
                    1,
                    inner_hashes[0].mask,
                    inner_hashes[0].hashes[0],
                    inner_hashes[0].depths[0],
                ),
                merkle_proof_cell(
                    2,
                    leaf_hashes[0].mask,
                    leaf_hashes[0].hashes[0],
                    leaf_hashes[0].depths[0],
                ),
                ordinary_cell(vec![0x42], Vec::new()),
            ],
        };
        assert!(ton_boc_cell_hashes(&nested).is_some());
        assert_eq!(ton_virtual_root_index(&nested, 0), Some(2));
        assert_eq!(
            ton_boc_single_root_hash_v1(&serialize_test_boc(&nested)),
            Some(inner_hashes[0].hashes[0])
        );

        let terminal = pruned_branch_cell(7, &[[0x71; 32], [0x72; 32], [0x73; 32]], &[5, 6, 7]);
        let terminal_boc = TonBoc {
            roots: vec![0],
            cells: vec![terminal.clone()],
        };
        let terminal_hashes = ton_boc_cell_hashes(&terminal_boc).expect("terminal proof hashes");
        let inner_cell = merkle_proof_cell(
            1,
            terminal_hashes[0].mask,
            terminal_hashes[0].hashes[0],
            terminal_hashes[0].depths[0],
        );
        let inner_boc = TonBoc {
            roots: vec![0],
            cells: vec![inner_cell.clone(), terminal.clone()],
        };
        let inner_hashes = ton_boc_cell_hashes(&inner_boc).expect("level-three proof hashes");
        let middle_cell = merkle_proof_cell(
            1,
            inner_hashes[0].mask,
            inner_hashes[0].hashes[0],
            inner_hashes[0].depths[0],
        );
        let mut shifted_inner = inner_cell.clone();
        shifted_inner.refs = vec![2];
        let middle_boc = TonBoc {
            roots: vec![0],
            cells: vec![middle_cell.clone(), shifted_inner.clone(), terminal.clone()],
        };
        let middle_hashes = ton_boc_cell_hashes(&middle_boc).expect("level-two proof hashes");
        let outer_cell = merkle_proof_cell(
            1,
            middle_hashes[0].mask,
            middle_hashes[0].hashes[0],
            middle_hashes[0].depths[0],
        );
        let mut shifted_middle = middle_cell;
        shifted_middle.refs = vec![2];
        shifted_inner.refs = vec![3];
        let nested_pruned = TonBoc {
            roots: vec![0],
            cells: vec![outer_cell, shifted_middle, shifted_inner, terminal],
        };
        let nested_hashes =
            ton_boc_cell_hashes(&nested_pruned).expect("nested pruned proof hashes");
        assert_eq!(ton_merkle_opened_index(&nested_pruned, 0), Some(3));
        assert_eq!(ton_virtual_root_index(&nested_pruned, 0), None);
        assert_eq!(ton_original_tree_hash(&nested_hashes, 3), Some([0x71; 32]));
    }

    #[test]
    fn transaction_parser_opens_a_merkle_wrapped_hash_update() {
        let account = [0x31; 32];
        let old_account_hash = [0x41; 32];
        let new_account_hash = [0x42; 32];
        let mut transaction = TestBits::default();
        transaction.uint(u64::from(TON_TRANSACTION_CONSTRUCTOR), 4);
        transaction.bytes(&account);
        transaction.uint(10, 64);
        transaction.bytes(&[0x51; 32]);
        transaction.uint(9, 64);
        transaction.uint(1, 32);
        transaction.uint(1, 15);
        transaction.uint(2, 2);
        transaction.uint(2, 2);
        transaction.uint(0, 4); // zero grams
        transaction.bit(false); // no extra currencies

        let mut hash_update_data = vec![0x72];
        hash_update_data.extend_from_slice(&old_account_hash);
        hash_update_data.extend_from_slice(&new_account_hash);
        let hash_update = TonBoc {
            roots: vec![0],
            cells: vec![ordinary_cell(hash_update_data.clone(), Vec::new())],
        };
        let update_hashes = ton_boc_cell_hashes(&hash_update).expect("HashUpdate hashes");
        let mut description = ordinary_cell(Vec::new(), vec![5]);
        description.descriptor |= 7 << 5;
        let mut transaction = transaction.cell(vec![1, 2, 4]);
        transaction.descriptor |= 7 << 5;
        let boc = TonBoc {
            roots: vec![0],
            cells: vec![
                transaction,
                ordinary_cell(Vec::new(), Vec::new()),
                merkle_proof_cell(
                    3,
                    update_hashes[0].mask,
                    update_hashes[0].hashes[0],
                    update_hashes[0].depths[0],
                ),
                ordinary_cell(hash_update_data, Vec::new()),
                description,
                pruned_branch_cell(7, &[[0x81; 32], [0x82; 32], [0x83; 32]], &[1, 2, 3]),
            ],
        };
        assert!(ton_boc_cell_hashes(&boc).is_some());
        let parsed =
            ton_parse_transaction(&boc, 0, account, 10).expect("wrapped HashUpdate must parse");
        assert_eq!(parsed.out_message_count, 1);
        assert_eq!(parsed.auxiliary_index, 1);
        assert_eq!(parsed.description_index, 4);
    }

    #[test]
    fn boc_parser_rejects_noncanonical_intermediate_index_offsets() {
        // Root cell (three serialized bytes) references one empty child (two
        // bytes), so the only canonical cumulative index is [3, 5].
        let indexed = [
            0xb5, 0xee, 0x9c, 0x72, 0x81, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00, 0x03, 0x05, 0x01,
            0x00, 0x01, 0x00, 0x00,
        ];
        assert!(parse_ton_boc(&indexed).is_some());
        let mut malformed = indexed;
        malformed[11] = 2;
        assert_eq!(parse_ton_boc(&malformed), None);
    }

    #[test]
    fn boc_parser_enforces_byte_and_cell_caps_before_allocation() {
        assert_eq!(TON_MAX_BOC_BYTES, 256 * 1024);
        assert_eq!(TON_MAX_BOC_CELLS, 8_192);
        let mut oversized = vec![0_u8; TON_MAX_BOC_BYTES + 1];
        oversized[..4].copy_from_slice(&TON_BOC_MAGIC);
        assert_eq!(parse_ton_boc(&oversized), None);

        // size_bytes=2, offset_bytes=1, cells_count=8193. The parser must
        // reject the declared count before attempting to allocate cell data.
        let excessive_cells = [
            0xb5, 0xee, 0x9c, 0x72, 0x02, 0x01, 0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        assert_eq!(parse_ton_boc(&excessive_cells), None);
    }

    #[test]
    fn boc_parser_rejects_maximum_multi_root_framing_at_the_header() {
        let count = u16::try_from(TON_MAX_BOC_CELLS).expect("TON cell cap fits u16");
        let total_cells_size = count.checked_mul(2).expect("empty cells fit u16");
        let mut multi_root = TON_BOC_MAGIC.to_vec();
        multi_root.extend_from_slice(&[2, 2]);
        multi_root.extend_from_slice(&count.to_be_bytes());
        multi_root.extend_from_slice(&count.to_be_bytes());
        multi_root.extend_from_slice(&0_u16.to_be_bytes());
        multi_root.extend_from_slice(&total_cells_size.to_be_bytes());
        for root in 0..count {
            multi_root.extend_from_slice(&root.to_be_bytes());
        }
        for _ in 0..count {
            multi_root.extend_from_slice(&[0, 0]);
        }
        assert_eq!(multi_root.len(), 14 + 4 * usize::from(count));
        assert_eq!(parse_ton_boc(&multi_root), None);
    }
}
