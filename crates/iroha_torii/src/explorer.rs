//! Explorer DTOs and bounded collection projections for Torii's app API.
//!
//! The six world-backed collection routes use canonical, filter-bound seek cursors. A request
//! returns at most 100 matches and applies secondary filters to at most 512 visible candidate keys,
//! so sparse secondary filters cannot turn one read-admission token into a ledger-scale scan.
//! Authorization filtering precedes cursor accounting so a continuation never exposes a hidden
//! entity key. Block, transaction, and instruction history use a separate cursor that pins the
//! committed chain snapshot and the caller's visible dataspace set; transaction and instruction
//! continuations use authorized entrypoint hashes rather than physical block offsets.
use crate::{
    json_macros::{JsonDeserialize, JsonSerialize},
    routing::DataspaceReadVisibility,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroha_core::state::WorldReadOnly;
use iroha_crypto::HashOf;
use iroha_data_model::{
    HasMetadata, Identifiable,
    account::{AccountEntry, AccountId},
    asset::{AssetDefinition, AssetDefinitionId, AssetEntry, AssetId, Mintable},
    domain::Domain,
    isi::{
        CustomInstruction, ExecuteTrigger, GrantBox, InstructionBox, Log, MintBox, RegisterBox,
        RemoveAssetKeyValue, RemoveKeyValueBox, RevokeBox, SetAssetKeyValue, SetKeyValueBox,
        SetParameter, TransferAssetBatch, TransferBox, UnregisterBox, Upgrade,
        mint_burn::BurnBox,
        runtime_upgrade::{ActivateRuntimeUpgrade, CancelRuntimeUpgrade, ProposeRuntimeUpgrade},
    },
    nft::{NftEntry, NftId},
    rwa::{RwaEntry, RwaId, RwaParentRef},
    sorafs_uri::SorafsUri,
    transaction::signed::TransactionEntrypoint,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::{metadata::Metadata, name::Name, topology::DataSpaceId};
use iroha_primitives::numeric::{Numeric, Quantity};
use iroha_torii_shared::qr::{EcLevel, QrCode, QrError};
use mv::storage::StorageReadOnly;
use norito::json::{self, Map, Value};
use sha2::{Digest as _, Sha256};
use std::{
    fmt,
    ops::Bound::{Excluded, Unbounded},
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
const ACCOUNT_QR_DIMENSION_PX: u32 = 192;
const ACCOUNT_QR_ERROR_CORRECTION: EcLevel = EcLevel::M;
const ACCOUNT_QR_ERROR_CORRECTION_LABEL: &str = "M";
/// Default number of matching world records returned by an Explorer cursor page.
pub(crate) const EXPLORER_CURSOR_DEFAULT_LIMIT: u32 = 25;
/// Hard ceiling for matching world records returned by one Explorer cursor page.
pub(crate) const EXPLORER_CURSOR_MAX_LIMIT: u32 = 100;
/// Hard ceiling for candidate keys inspected by one Explorer cursor page.
pub(crate) const EXPLORER_CURSOR_MAX_SCAN: usize = 512;
const EXPLORER_CURSOR_MAGIC: [u8; 4] = *b"IXC1";
const EXPLORER_CURSOR_FILTER_DOMAIN: &[u8] = b"iroha-explorer-filter-v2";
const EXPLORER_CURSOR_MAX_KEY_BYTES: usize = 1_024;
const EXPLORER_CURSOR_MAX_ENCODED_BYTES: usize = 1_424;
const EXPLORER_HISTORY_CURSOR_MAGIC: [u8; 4] = *b"IHC2";
const EXPLORER_HISTORY_FILTER_DOMAIN: &[u8] = b"iroha-explorer-history-filter-v2";
const EXPLORER_HISTORY_CURSOR_FRAME_BYTES: usize = 4 + 1 + 8 + 32 + 32 + 32 + 8 + 32 + 4;
const EXPLORER_HISTORY_CURSOR_MAX_ENCODED_BYTES: usize = 208;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum ExplorerCursorCollection {
    Accounts = 1,
    Domains = 2,
    AssetDefinitions = 3,
    Assets = 4,
    Nfts = 5,
    Rwas = 6,
}
impl ExplorerCursorCollection {
    const fn tag(self) -> u8 {
        self as u8
    }
}
/// Explorer cursor-page failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExplorerCursorError {
    /// The requested page limit is outside the first-release bound.
    InvalidLimit,
    /// The cursor is not the unique canonical base64url representation.
    InvalidEncoding,
    /// The cursor is malformed or exceeds its fixed transport bound.
    InvalidFrame,
    /// The cursor belongs to another collection or filter set.
    ScopeMismatch,
    /// The cursor contains a non-canonical collection key.
    InvalidKey,
    /// The cursor names a committed snapshot that this node cannot validate.
    InvalidSnapshot,
    /// Visibility could not be resolved within the bounded raw candidate scan.
    ScanLimitExceeded,
    /// Selection, cursor scratch or response encoding exceeded the retained byte owner.
    ByteLimitExceeded,
}
impl fmt::Display for ExplorerCursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimit => "limit must be between 1 and 100",
            Self::InvalidEncoding => "cursor is not canonical base64url without padding",
            Self::InvalidFrame => "cursor frame is malformed or too large",
            Self::ScopeMismatch => "cursor does not belong to these filters",
            Self::InvalidKey => "cursor contains a non-canonical collection key",
            Self::InvalidSnapshot => "cursor snapshot is not available on this node",
            Self::ByteLimitExceeded => "Explorer response exceeded the retained byte capacity",
            Self::ScanLimitExceeded => {
                "Explorer visibility scan exceeded the bounded candidate limit"
            }
        })
    }
}
impl std::error::Error for ExplorerCursorError {}
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AccountCounters {
    domains: u32,
    assets: u32,
    nfts: u32,
}
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DomainCounters {
    accounts: u32,
    assets: u32,
    nfts: u32,
}
/// Cursor controls shared by the six world-backed Explorer collections.
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(crate) struct ExplorerCursorQuery {
    /// Opaque cursor returned by the preceding request with the same filters.
    #[norito(default)]
    pub cursor: Option<String>,
    /// Maximum matching records to return.
    #[norito(default = "default_cursor_limit")]
    pub limit: u32,
}
impl ExplorerCursorQuery {
    pub(crate) fn validated_limit(&self) -> Result<usize, ExplorerCursorError> {
        if self.limit == 0 || self.limit > EXPLORER_CURSOR_MAX_LIMIT {
            return Err(ExplorerCursorError::InvalidLimit);
        }
        Ok(usize::try_from(self.limit).expect("bounded u32 Explorer limit fits usize"))
    }
}
/// Seek-pagination metadata for a bounded world-backed Explorer collection.
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerCursorMeta {
    /// Maximum matching records requested for this page.
    pub limit: u32,
    /// Opaque resume token, or `None` after the candidate range is exhausted.
    pub next_cursor: Option<String>,
    /// Whether the maintained candidate range has more keys to inspect.
    pub has_more: bool,
}

/// Chain-history collections with independent cursor domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ExplorerHistoryCollection {
    /// Committed blocks, newest first.
    Blocks = 1,
    /// Committed transactions, newest block first.
    Transactions = 2,
    /// The latest-transactions route.
    LatestTransactions = 3,
    /// Committed instructions, newest block first.
    Instructions = 4,
    /// The latest-instructions route.
    LatestInstructions = 5,
}

impl ExplorerHistoryCollection {
    const fn tag(self) -> u8 {
        self as u8
    }

    const fn position_is_canonical(self, position: ExplorerHistoryPosition) -> bool {
        if position.height == 0 {
            return false;
        }
        match self {
            Self::Blocks => position.entrypoint_hash.is_none() && position.instruction_index == 0,
            Self::Transactions | Self::LatestTransactions => {
                position.entrypoint_hash.is_some() && position.instruction_index == 0
            }
            Self::Instructions | Self::LatestInstructions => position.entrypoint_hash.is_some(),
        }
    }
}

/// Chain-history scan or visible resume position.
///
/// Encoded transaction and instruction cursors accept only positions with a stable entrypoint hash;
/// hashless start positions remain internal to one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExplorerHistoryPosition {
    /// One-based committed block height.
    pub height: u64,
    /// Stable hash of the next caller-visible external entrypoint.
    pub entrypoint_hash: Option<HashOf<TransactionEntrypoint>>,
    /// Zero-based explicit instruction index within the visible entrypoint.
    pub instruction_index: u32,
}

impl ExplorerHistoryPosition {
    /// Construct a block position.
    pub(crate) const fn block(height: u64) -> Self {
        Self {
            height,
            entrypoint_hash: None,
            instruction_index: 0,
        }
    }

    /// Construct an internal start-of-block transaction scan position.
    pub(crate) const fn transaction_start(height: u64) -> Self {
        Self {
            height,
            entrypoint_hash: None,
            instruction_index: 0,
        }
    }

    /// Construct a stable caller-visible transaction position.
    pub(crate) const fn transaction(
        height: u64,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) -> Self {
        Self {
            height,
            entrypoint_hash: Some(entrypoint_hash),
            instruction_index: 0,
        }
    }

    /// Construct an internal start-of-block instruction scan position.
    pub(crate) const fn instruction_start(height: u64) -> Self {
        Self {
            height,
            entrypoint_hash: None,
            instruction_index: 0,
        }
    }

    /// Construct a stable caller-visible instruction position.
    pub(crate) const fn instruction(
        height: u64,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
        instruction_index: u32,
    ) -> Self {
        Self {
            height,
            entrypoint_hash: Some(entrypoint_hash),
            instruction_index,
        }
    }
}

/// Validated state carried by a chain-history cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExplorerHistoryCursor {
    /// Height of the immutable committed snapshot selected by the first page.
    pub snapshot_height: u64,
    /// Hash of the committed block at `snapshot_height`.
    pub snapshot_hash: [u8; 32],
    /// Next candidate to inspect.
    pub position: ExplorerHistoryPosition,
}

/// Seek-pagination metadata for a snapshot-bound Explorer history page.
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerHistoryCursorMeta {
    /// Maximum matching records requested for this page.
    pub limit: u32,
    /// Height of the committed snapshot retained across pages.
    pub snapshot_height: u64,
    /// Hash of the committed block at `snapshot_height`, or `None` for an empty chain.
    pub snapshot_hash: Option<String>,
    /// Opaque resume token, or `None` after the snapshot range is exhausted.
    pub next_cursor: Option<String>,
    /// Whether the snapshot range has more candidates to inspect.
    pub has_more: bool,
}

/// Compute the canonical digest of all filters accepted by one history route.
pub(crate) fn explorer_history_filter_digest(
    collection: ExplorerHistoryCollection,
    filters: &[Option<String>],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EXPLORER_HISTORY_FILTER_DOMAIN);
    hasher.update([collection.tag()]);
    hasher.update(
        u32::try_from(filters.len())
            .expect("fixed Explorer history filter list fits u32")
            .to_be_bytes(),
    );
    for filter in filters {
        match filter {
            Some(value) => {
                hasher.update([1]);
                hasher.update(
                    u32::try_from(value.len())
                        .expect("bounded Explorer filter length fits u32")
                        .to_be_bytes(),
                );
                hasher.update(value.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher.finalize().into()
}

fn encode_explorer_history_cursor(
    collection: ExplorerHistoryCollection,
    filter_digest: [u8; 32],
    visibility_digest: [u8; 32],
    cursor: ExplorerHistoryCursor,
) -> Result<String, ExplorerCursorError> {
    if cursor.position.height > cursor.snapshot_height
        || !collection.position_is_canonical(cursor.position)
    {
        return Err(ExplorerCursorError::InvalidKey);
    }
    let mut frame = [0_u8; EXPLORER_HISTORY_CURSOR_FRAME_BYTES];
    frame[..4].copy_from_slice(&EXPLORER_HISTORY_CURSOR_MAGIC);
    frame[4] = collection.tag();
    frame[5..13].copy_from_slice(&cursor.snapshot_height.to_be_bytes());
    frame[13..45].copy_from_slice(&cursor.snapshot_hash);
    frame[45..77].copy_from_slice(&filter_digest);
    frame[77..109].copy_from_slice(&visibility_digest);
    frame[109..117].copy_from_slice(&cursor.position.height.to_be_bytes());
    if let Some(hash) = cursor.position.entrypoint_hash {
        frame[117..149].copy_from_slice(hash.as_ref());
    }
    frame[149..153].copy_from_slice(&cursor.position.instruction_index.to_be_bytes());
    explorer_base64_frame(&frame)
}

/// Decode and scope-check a snapshot-bound history cursor.
pub(crate) fn decode_explorer_history_cursor(
    encoded: &str,
    collection: ExplorerHistoryCollection,
    filter_digest: [u8; 32],
    visibility_digest: [u8; 32],
) -> Result<ExplorerHistoryCursor, ExplorerCursorError> {
    if encoded.is_empty() || encoded.len() > EXPLORER_HISTORY_CURSOR_MAX_ENCODED_BYTES {
        return Err(ExplorerCursorError::InvalidFrame);
    }
    let mut frame = [0_u8; EXPLORER_HISTORY_CURSOR_FRAME_BYTES];
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(encoded.as_bytes(), &mut frame)
        .map_err(|_| ExplorerCursorError::InvalidEncoding)?;
    if decoded_len != frame.len() || explorer_base64_frame(&frame)? != encoded {
        return Err(ExplorerCursorError::InvalidEncoding);
    }
    if frame.len() != EXPLORER_HISTORY_CURSOR_FRAME_BYTES
        || frame[..4] != EXPLORER_HISTORY_CURSOR_MAGIC
        || frame[4] != collection.tag()
        || frame[45..77] != filter_digest
        || frame[77..109] != visibility_digest
    {
        return Err(
            if frame.len() == EXPLORER_HISTORY_CURSOR_FRAME_BYTES
                && frame[..4] == EXPLORER_HISTORY_CURSOR_MAGIC
            {
                ExplorerCursorError::ScopeMismatch
            } else {
                ExplorerCursorError::InvalidFrame
            },
        );
    }
    let snapshot_height = u64::from_be_bytes(
        frame[5..13]
            .try_into()
            .expect("fixed Explorer cursor snapshot-height slice"),
    );
    let snapshot_hash = frame[13..45]
        .try_into()
        .expect("fixed Explorer cursor snapshot-hash slice");
    let position = ExplorerHistoryPosition {
        height: u64::from_be_bytes(
            frame[109..117]
                .try_into()
                .expect("fixed Explorer cursor position-height slice"),
        ),
        entrypoint_hash: decode_explorer_history_entrypoint_hash(
            frame[117..149]
                .try_into()
                .expect("fixed Explorer cursor entrypoint-hash slice"),
        )?,
        instruction_index: u32::from_be_bytes(
            frame[149..153]
                .try_into()
                .expect("fixed Explorer cursor instruction-index slice"),
        ),
    };
    if snapshot_height == 0
        || position.height > snapshot_height
        || !collection.position_is_canonical(position)
    {
        return Err(ExplorerCursorError::InvalidKey);
    }
    Ok(ExplorerHistoryCursor {
        snapshot_height,
        snapshot_hash,
        position,
    })
}

fn decode_explorer_history_entrypoint_hash(
    bytes: [u8; 32],
) -> Result<Option<HashOf<TransactionEntrypoint>>, ExplorerCursorError> {
    if bytes == [0; 32] {
        return Ok(None);
    }
    let hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
        iroha_crypto::Hash::prehashed(bytes),
    );
    if hash.as_ref() != &bytes {
        return Err(ExplorerCursorError::InvalidKey);
    }
    Ok(Some(hash))
}

/// Build response metadata and, when needed, an opaque cursor for the next candidate.
pub(crate) fn explorer_history_cursor_meta(
    collection: ExplorerHistoryCollection,
    filter_digest: [u8; 32],
    visibility_digest: [u8; 32],
    limit: u32,
    snapshot_height: u64,
    snapshot_hash: Option<[u8; 32]>,
    next_position: Option<ExplorerHistoryPosition>,
) -> Result<ExplorerHistoryCursorMeta, ExplorerCursorError> {
    let next_cursor = match (snapshot_hash, next_position) {
        (Some(snapshot_hash), Some(position)) => Some(encode_explorer_history_cursor(
            collection,
            filter_digest,
            visibility_digest,
            ExplorerHistoryCursor {
                snapshot_height,
                snapshot_hash,
                position,
            },
        )?),
        (None, None) | (Some(_), None) => None,
        (None, Some(_)) => return Err(ExplorerCursorError::InvalidSnapshot),
    };
    Ok(ExplorerHistoryCursorMeta {
        limit,
        snapshot_height,
        snapshot_hash: snapshot_hash.map(hex::encode),
        has_more: next_cursor.is_some(),
        next_cursor,
    })
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAccountDto<'world> {
    pub id: &'world AccountId,
    pub network_prefix: u16,
    pub metadata: &'world Metadata,
    pub owned_domains: u32,
    pub owned_assets: u32,
    pub owned_nfts: u32,
}
impl<'world> ExplorerAccountDto<'world> {
    pub(crate) fn from_entry(entry: AccountEntry<'world>, counts: AccountCounters) -> Self {
        Self {
            id: entry.id,
            network_prefix: iroha_data_model::account::address::chain_discriminant(),
            metadata: entry.value.metadata(),
            owned_domains: counts.domains,
            owned_assets: counts.assets,
            owned_nfts: counts.nfts,
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAccountsPage<'world> {
    pub pagination: ExplorerCursorMeta,
    pub items: Vec<ExplorerAccountDto<'world>>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAccountQrDto {
    pub canonical_id: String,
    pub literal: String,
    pub network_prefix: u16,
    pub error_correction: &'static str,
    pub modules: u32,
    pub qr_version: u8,
    pub svg: String,
}
impl ExplorerAccountQrDto {
    pub(crate) fn build(account_id: &AccountId) -> Result<Self, QrError> {
        let network_prefix = iroha_data_model::account::address::chain_discriminant();
        let literal = account_id.to_string();
        let (svg, qr_version) = render_account_qr_svg(&literal)?;
        Ok(Self {
            canonical_id: account_id.to_string(),
            literal,
            network_prefix,
            error_correction: ACCOUNT_QR_ERROR_CORRECTION_LABEL,
            modules: ACCOUNT_QR_DIMENSION_PX,
            qr_version,
            svg,
        })
    }
}
fn render_account_qr_svg(input: &str) -> Result<(String, u8), QrError> {
    let code = QrCode::with_error_correction_level(input.as_bytes(), ACCOUNT_QR_ERROR_CORRECTION)?;
    let version = code.version();
    let svg = code.to_svg(ACCOUNT_QR_DIMENSION_PX, "#000000", "#FFFFFF");
    Ok((svg, version))
}
pub(crate) fn metadata_to_json(metadata: &Metadata) -> Value {
    norito::json::to_value(metadata).unwrap_or_else(|_| Value::Object(Map::new()))
}
const fn default_cursor_limit() -> u32 {
    EXPLORER_CURSOR_DEFAULT_LIMIT
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerDomainDto<'world> {
    pub id: &'world DomainId,
    pub logo: Option<&'world SorafsUri>,
    pub metadata: &'world Metadata,
    pub owned_by: &'world AccountId,
    pub accounts: u32,
    pub assets: u32,
    pub nfts: u32,
}
impl<'world> ExplorerDomainDto<'world> {
    pub(crate) fn from_domain(domain: &'world Domain, counts: DomainCounters) -> Self {
        Self {
            id: domain.id(),
            logo: domain.logo().as_ref(),
            metadata: domain.metadata(),
            owned_by: domain.owned_by(),
            accounts: counts.accounts,
            assets: counts.assets,
            nfts: counts.nfts,
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerDomainsPage<'world> {
    pub pagination: ExplorerCursorMeta,
    pub items: Vec<ExplorerDomainDto<'world>>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAssetDefinitionDto<'world> {
    pub id: &'world AssetDefinitionId,
    /// Immutable domain home, absent for direct-dataspace and global definitions.
    pub owning_domain: Option<&'world DomainId>,
    /// Immutable direct dataspace home as an exact decimal string; never a balance bucket.
    pub owning_dataspace: Option<String>,
    pub mintable: ExplorerMintable,
    pub logo: Option<&'world SorafsUri>,
    pub metadata: &'world Metadata,
    pub owned_by: &'world AccountId,
    pub assets: u32,
    pub total_quantity: &'world Quantity,
    pub locked_quantity: Option<&'world Quantity>,
    pub circulating_quantity: Option<Quantity>,
}
impl<'world> ExplorerAssetDefinitionDto<'world> {
    pub(crate) fn from_definition_with_asset_count(
        definition: &'world AssetDefinition,
        assets: u32,
        owning_dataspace: Option<DataSpaceId>,
    ) -> Self {
        Self {
            id: definition.id(),
            owning_domain: definition.owning_domain().as_ref(),
            owning_dataspace: owning_dataspace.map(|dataspace| dataspace.as_u64().to_string()),
            mintable: ExplorerMintable(definition.mintable()),
            logo: definition.logo().as_ref(),
            metadata: definition.metadata(),
            owned_by: definition.owned_by(),
            assets,
            total_quantity: definition.total_quantity(),
            locked_quantity: None,
            circulating_quantity: None,
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAssetDefinitionsPage<'world> {
    pub pagination: ExplorerCursorMeta,
    pub items: Vec<ExplorerAssetDefinitionDto<'world>>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerEconometricsVelocityWindowDto {
    pub key: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub transfers: u64,
    pub unique_senders: u64,
    pub unique_receivers: u64,
    pub amount: Quantity,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerEconometricsIssuanceWindowDto {
    pub key: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub mint_count: u64,
    pub burn_count: u64,
    pub minted: Quantity,
    pub burned: Quantity,
    pub net: Numeric,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerEconometricsIssuanceSeriesPointDto {
    pub bucket_start_ms: u64,
    pub minted: Quantity,
    pub burned: Quantity,
    pub net: Numeric,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAssetDefinitionEconometricsDto {
    pub definition_id: String,
    pub computed_at_ms: u64,
    pub velocity_windows: Vec<ExplorerEconometricsVelocityWindowDto>,
    pub issuance_windows: Vec<ExplorerEconometricsIssuanceWindowDto>,
    pub issuance_series: Vec<ExplorerEconometricsIssuanceSeriesPointDto>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerEconometricsLorenzPointDto {
    pub population: f64,
    pub share: f64,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerEconometricsDistributionSnapshotDto {
    pub gini: f64,
    pub hhi: f64,
    pub theil: f64,
    pub entropy: f64,
    pub entropy_normalized: f64,
    pub nakamoto_33: u64,
    pub nakamoto_51: u64,
    pub nakamoto_67: u64,
    pub top1: f64,
    pub top5: f64,
    pub top10: f64,
    pub median: Option<Quantity>,
    pub p90: Option<Quantity>,
    pub p99: Option<Quantity>,
    pub lorenz: Vec<ExplorerEconometricsLorenzPointDto>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerEconometricsTopHolderDto {
    pub account_id: String,
    pub balance: Quantity,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAssetDefinitionSnapshotDto {
    pub definition_id: String,
    pub computed_at_ms: u64,
    pub holders_total: u64,
    pub total_supply: Quantity,
    pub top_holders: Vec<ExplorerEconometricsTopHolderDto>,
    pub distribution: ExplorerEconometricsDistributionSnapshotDto,
}
/// Borrowed text projection for IDs whose native JSON representation is structured.
/// Their native formatter visits bounded components without an owned literal.
#[derive(Clone, Debug)]
pub(crate) struct ExplorerText<'world, T: ?Sized>(&'world T);
impl<T: fmt::Display + ?Sized> json::FastJsonWrite for ExplorerText<'_, T> {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_display_to(self.0, out)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExplorerMintable(Mintable);
impl fmt::Display for ExplorerMintable {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Mintable::Infinitely => out.write_str("Infinitely"),
            Mintable::Once => out.write_str("Once"),
            Mintable::Not => out.write_str("Not"),
            Mintable::Limited(tokens) => write!(out, "Limited({})", tokens.value()),
        }
    }
}
impl json::FastJsonWrite for ExplorerMintable {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_display_to(self, out)
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAssetDto<'world> {
    pub id: &'world AssetId,
    pub definition_id: &'world AssetDefinitionId,
    pub account_id: &'world AccountId,
    pub value: &'world Quantity,
}
impl<'world> ExplorerAssetDto<'world> {
    pub(crate) fn from_entry(entry: AssetEntry<'world>) -> Self {
        Self {
            id: entry.id,
            definition_id: entry.id.definition(),
            account_id: entry.id.account(),
            value: entry.value.as_ref(),
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerAssetsPage<'world> {
    pub pagination: ExplorerCursorMeta,
    pub items: Vec<ExplorerAssetDto<'world>>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerNftDto<'world> {
    pub id: &'world NftId,
    pub owned_by: &'world AccountId,
    pub metadata: &'world Metadata,
}
impl<'world> ExplorerNftDto<'world> {
    pub(crate) fn from_entry(entry: NftEntry<'world>) -> Self {
        Self {
            id: entry.id,
            owned_by: &entry.value.owned_by,
            metadata: &entry.value.content,
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerNftsPage<'world> {
    pub pagination: ExplorerCursorMeta,
    pub items: Vec<ExplorerNftDto<'world>>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerRwaParentDto<'world> {
    pub rwa: ExplorerText<'world, RwaId>,
    pub quantity: &'world Quantity,
}
impl<'world> ExplorerRwaParentDto<'world> {
    fn from_parent(parent: &'world RwaParentRef) -> Self {
        Self {
            rwa: ExplorerText(parent.rwa()),
            quantity: parent.quantity(),
        }
    }
}
/// Canonical parent DTOs are projected one at a time from the retained World slice.
#[derive(Clone, Debug)]
pub(crate) struct ExplorerRwaParents<'world>(&'world [RwaParentRef]);
impl json::FastJsonWrite for ExplorerRwaParents<'_> {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('[')?;
            for (index, parent) in self.0.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                json::JsonSerialize::json_serialize_to(
                    &ExplorerRwaParentDto::from_parent(parent),
                    out,
                )?;
            }
            out.push(']')
        })();
        out.end_container();
        result
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerRwaDto<'world> {
    pub id: ExplorerText<'world, RwaId>,
    pub owned_by: &'world AccountId,
    pub quantity: &'world Quantity,
    pub held_quantity: &'world Quantity,
    pub primary_reference: &'world str,
    pub status: Option<&'world Name>,
    pub is_frozen: bool,
    pub metadata: &'world Metadata,
    pub parents: ExplorerRwaParents<'world>,
}
impl<'world> ExplorerRwaDto<'world> {
    pub(crate) fn from_entry(entry: RwaEntry<'world>) -> Self {
        let value = entry.value.as_ref();
        Self {
            id: ExplorerText(entry.id),
            owned_by: &value.owned_by,
            quantity: &value.quantity,
            held_quantity: &value.held_quantity,
            primary_reference: &value.primary_reference,
            status: value.status.as_ref(),
            is_frozen: value.is_frozen,
            metadata: &value.metadata,
            parents: ExplorerRwaParents(&value.parents),
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerRwasPage<'world> {
    pub pagination: ExplorerCursorMeta,
    pub items: Vec<ExplorerRwaDto<'world>>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerNetworkMetricsDto {
    pub peers: u64,
    pub domains: u64,
    pub accounts: u64,
    pub assets: u64,
    pub transactions_accepted: u64,
    pub transactions_rejected: u64,
    pub block: u64,
    pub block_created_at: Option<crate::explorer_history::HistoryTime>,
    pub finalized_block: u64,
    pub avg_commit_time: Option<ExplorerDurationDto>,
    pub avg_block_time: Option<ExplorerDurationDto>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerDurationDto {
    pub ms: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExplorerInstructionKind {
    Register,
    Unregister,
    Mint,
    Burn,
    Transfer,
    SetKeyValue,
    RemoveKeyValue,
    Grant,
    Revoke,
    ExecuteTrigger,
    SetParameter,
    Upgrade,
    Log,
    Custom,
}
impl ExplorerInstructionKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Register => "Register",
            Self::Unregister => "Unregister",
            Self::Mint => "Mint",
            Self::Burn => "Burn",
            Self::Transfer => "Transfer",
            Self::SetKeyValue => "SetKeyValue",
            Self::RemoveKeyValue => "RemoveKeyValue",
            Self::Grant => "Grant",
            Self::Revoke => "Revoke",
            Self::ExecuteTrigger => "ExecuteTrigger",
            Self::SetParameter => "SetParameter",
            Self::Upgrade => "Upgrade",
            Self::Log => "Log",
            Self::Custom => "Custom",
        }
    }
}
impl std::str::FromStr for ExplorerInstructionKind {
    type Err = ();
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "register" => Ok(Self::Register),
            "unregister" => Ok(Self::Unregister),
            "mint" => Ok(Self::Mint),
            "burn" => Ok(Self::Burn),
            "transfer" => Ok(Self::Transfer),
            "setkeyvalue" | "set_key_value" => Ok(Self::SetKeyValue),
            "removekeyvalue" | "remove_key_value" => Ok(Self::RemoveKeyValue),
            "grant" => Ok(Self::Grant),
            "revoke" => Ok(Self::Revoke),
            "executetrigger" | "execute_trigger" => Ok(Self::ExecuteTrigger),
            "setparameter" | "set_parameter" => Ok(Self::SetParameter),
            "upgrade" => Ok(Self::Upgrade),
            "log" => Ok(Self::Log),
            "custom" => Ok(Self::Custom),
            _ => Err(()),
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
pub(crate) struct ExplorerHealthDto {
    pub head_height: u64,
    pub head_created_at: Option<crate::explorer_history::HistoryTime>,
    pub sampled_at: crate::explorer_history::HistoryTime,
}
pub(crate) fn instruction_kind(instruction: &InstructionBox) -> ExplorerInstructionKind {
    let wire_id = instruction_wire_id(instruction);
    match wire_id {
        id if id == RegisterBox::WIRE_ID
            || id == iroha_data_model::isi::RegisterDataspaceAssetDefinition::WIRE_ID =>
        {
            ExplorerInstructionKind::Register
        }
        id if id == UnregisterBox::WIRE_ID => ExplorerInstructionKind::Unregister,
        id if id == MintBox::WIRE_ID => ExplorerInstructionKind::Mint,
        id if id == BurnBox::WIRE_ID => ExplorerInstructionKind::Burn,
        id if id == TransferBox::WIRE_ID || id == TransferAssetBatch::WIRE_ID => {
            ExplorerInstructionKind::Transfer
        }
        id if id == SetKeyValueBox::WIRE_ID => ExplorerInstructionKind::SetKeyValue,
        id if id == RemoveKeyValueBox::WIRE_ID => ExplorerInstructionKind::RemoveKeyValue,
        id if id == GrantBox::WIRE_ID => ExplorerInstructionKind::Grant,
        id if id == RevokeBox::WIRE_ID => ExplorerInstructionKind::Revoke,
        id if id == ExecuteTrigger::WIRE_ID => ExplorerInstructionKind::ExecuteTrigger,
        id if id == SetParameter::WIRE_ID => ExplorerInstructionKind::SetParameter,
        id if id == Upgrade::WIRE_ID
            || id == ProposeRuntimeUpgrade::WIRE_ID
            || id == ActivateRuntimeUpgrade::WIRE_ID
            || id == CancelRuntimeUpgrade::WIRE_ID =>
        {
            ExplorerInstructionKind::Upgrade
        }
        id if id == Log::WIRE_ID => ExplorerInstructionKind::Log,
        id if id == CustomInstruction::WIRE_ID => ExplorerInstructionKind::Custom,
        _ => {
            let any = (**instruction).as_any();
            if any.downcast_ref::<RegisterBox>().is_some()
                || any
                    .downcast_ref::<iroha_data_model::isi::RegisterDataspaceAssetDefinition>()
                    .is_some()
            {
                ExplorerInstructionKind::Register
            } else if any.downcast_ref::<UnregisterBox>().is_some() {
                ExplorerInstructionKind::Unregister
            } else if any.downcast_ref::<MintBox>().is_some() {
                ExplorerInstructionKind::Mint
            } else if any.downcast_ref::<BurnBox>().is_some() {
                ExplorerInstructionKind::Burn
            } else if any.downcast_ref::<TransferBox>().is_some()
                || any.downcast_ref::<TransferAssetBatch>().is_some()
            {
                ExplorerInstructionKind::Transfer
            } else if any.downcast_ref::<SetKeyValueBox>().is_some()
                || any.downcast_ref::<SetAssetKeyValue>().is_some()
            {
                ExplorerInstructionKind::SetKeyValue
            } else if any.downcast_ref::<RemoveKeyValueBox>().is_some()
                || any.downcast_ref::<RemoveAssetKeyValue>().is_some()
            {
                ExplorerInstructionKind::RemoveKeyValue
            } else if any.downcast_ref::<GrantBox>().is_some() {
                ExplorerInstructionKind::Grant
            } else if any.downcast_ref::<RevokeBox>().is_some() {
                ExplorerInstructionKind::Revoke
            } else if any.downcast_ref::<ExecuteTrigger>().is_some() {
                ExplorerInstructionKind::ExecuteTrigger
            } else if any.downcast_ref::<SetParameter>().is_some() {
                ExplorerInstructionKind::SetParameter
            } else if any.downcast_ref::<Upgrade>().is_some()
                || any.downcast_ref::<ProposeRuntimeUpgrade>().is_some()
                || any.downcast_ref::<ActivateRuntimeUpgrade>().is_some()
                || any.downcast_ref::<CancelRuntimeUpgrade>().is_some()
            {
                ExplorerInstructionKind::Upgrade
            } else if any.downcast_ref::<Log>().is_some() {
                ExplorerInstructionKind::Log
            } else {
                ExplorerInstructionKind::Custom
            }
        }
    }
}
fn instruction_wire_id(instruction: &InstructionBox) -> &str {
    iroha_data_model::isi::instruction_wire_id(instruction)
        .expect("explorer instruction must have a canonical V1 wire identifier")
}
fn duration_to_rfc3339(duration: Duration) -> String {
    const FALLBACK: &str = "1970-01-01T00:00:00Z";
    let nanos = i128::from(duration.as_secs())
        .saturating_mul(1_000_000_000)
        .saturating_add(i128::from(duration.subsec_nanos()));
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| FALLBACK.to_string())
}
pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
pub(crate) fn explorer_history_key_text<T: json::JsonSerialize + ?Sized>(
    value: &T,
) -> Result<String, ExplorerCursorError> {
    explorer_checked_key_text(value, EXPLORER_CURSOR_MAX_KEY_BYTES)
}
pub(crate) fn explorer_history_scalar_text(value: u64) -> Result<String, ExplorerCursorError> {
    let encoded = json::to_json_bounded_boxed(&value, 20)
        .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
    String::from_utf8(encoded.into_vec()).map_err(|_| ExplorerCursorError::InvalidKey)
}
pub(crate) fn explorer_history_literal_text(value: &str) -> Result<String, ExplorerCursorError> {
    let mut bytes = explorer_exact_vec(value.len(), EXPLORER_CURSOR_MAX_KEY_BYTES)?;
    bytes.extend_from_slice(value.as_bytes());
    String::from_utf8(bytes).map_err(|_| ExplorerCursorError::InvalidKey)
}
fn explorer_checked_key_text<T: json::JsonSerialize + ?Sized>(
    value: &T,
    max_bytes: usize,
) -> Result<String, ExplorerCursorError> {
    let encoded_bound = max_bytes
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(ExplorerCursorError::ByteLimitExceeded)?;
    let encoded = json::to_json_bounded_boxed(value, encoded_bound)
        .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
    let text = std::str::from_utf8(&encoded).map_err(|_| ExplorerCursorError::InvalidKey)?;
    let mut preflight = json::Parser::new(text);
    preflight
        .skip_string_bounded(max_bytes)
        .map_err(|_| ExplorerCursorError::InvalidKey)?;
    json::from_slice::<String>(&encoded).map_err(|_| ExplorerCursorError::ByteLimitExceeded)
}
/// Borrow one optional selector as the checked JSON serializer hashed by
/// [`explorer_filter_digest`]: an unsizing coercion, never an owned copy.
fn explorer_filter<T: json::JsonSerialize>(value: Option<&T>) -> Option<&dyn json::JsonSerialize> {
    let value: &dyn json::JsonSerialize = value?;
    Some(value)
}
fn explorer_filter_digest(
    collection: ExplorerCursorCollection,
    filters: &[Option<&dyn json::JsonSerialize>],
    visibility_digest: [u8; 32],
    byte_budget: usize,
) -> Result<[u8; 32], ExplorerCursorError> {
    let mut hasher = Sha256::new();
    hasher.update(EXPLORER_CURSOR_FILTER_DOMAIN);
    hasher.update([collection.tag()]);
    hasher.update(
        u32::try_from(filters.len())
            .expect("fixed Explorer filter list fits u32")
            .to_be_bytes(),
    );
    for filter in filters {
        match filter {
            Some(value) => {
                // Native checked ID serializers own their formatter scratch. Preserve the
                // original digest's decoded text bytes, without Display-owned ID copies.
                let text = explorer_checked_key_text(*value, byte_budget)?;
                hasher.update([1]);
                hasher.update(
                    u32::try_from(text.len())
                        .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?
                        .to_be_bytes(),
                );
                hasher.update(text.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher.update(visibility_digest);
    Ok(hasher.finalize().into())
}
fn explorer_exact_vec<T>(count: usize, byte_budget: usize) -> Result<Vec<T>, ExplorerCursorError> {
    let bytes = std::alloc::Layout::array::<T>(count)
        .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?
        .size();
    if bytes > byte_budget {
        return Err(ExplorerCursorError::ByteLimitExceeded);
    }
    norito::core::reserve_decode_allocation(bytes)
        .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
    crate::torii_routed_read_exact_vec(count, "Explorer selected records", bytes)
        .map_err(|_| ExplorerCursorError::ByteLimitExceeded)
}
fn explorer_iterator<'world, T, I: Iterator<Item = T> + 'world>(
    iterator: I,
) -> Result<Box<dyn Iterator<Item = T> + 'world>, ExplorerCursorError> {
    norito::core::reserve_decode_allocation(std::mem::size_of::<I>())
        .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
    Ok(Box::new(iterator))
}
fn explorer_base64_frame(frame: &[u8]) -> Result<String, ExplorerCursorError> {
    let length = frame
        .len()
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(ExplorerCursorError::ByteLimitExceeded)?
        / 3;
    let mut encoded = explorer_exact_vec::<u8>(length, EXPLORER_CURSOR_MAX_ENCODED_BYTES)?;
    encoded.resize(length, 0);
    let written = URL_SAFE_NO_PAD
        .encode_slice(frame, &mut encoded)
        .map_err(|_| ExplorerCursorError::InvalidEncoding)?;
    if written != length {
        return Err(ExplorerCursorError::InvalidEncoding);
    }
    String::from_utf8(encoded).map_err(|_| ExplorerCursorError::InvalidEncoding)
}
fn encode_explorer_cursor(
    collection: ExplorerCursorCollection,
    filter_digest: [u8; 32],
    key: &str,
) -> Result<String, ExplorerCursorError> {
    if key.is_empty() || key.len() > EXPLORER_CURSOR_MAX_KEY_BYTES {
        return Err(ExplorerCursorError::InvalidKey);
    }
    let key_len = u16::try_from(key.len()).map_err(|_| ExplorerCursorError::InvalidKey)?;
    let mut frame = explorer_exact_vec::<u8>(
        4 + 1 + 32 + 2 + key.len(),
        EXPLORER_CURSOR_MAX_ENCODED_BYTES,
    )?;
    frame.extend_from_slice(&EXPLORER_CURSOR_MAGIC);
    frame.push(collection.tag());
    frame.extend_from_slice(&filter_digest);
    frame.extend_from_slice(&key_len.to_be_bytes());
    frame.extend_from_slice(key.as_bytes());
    explorer_base64_frame(&frame)
}
fn decode_explorer_cursor_key(
    cursor: &str,
    collection: ExplorerCursorCollection,
    filter_digest: [u8; 32],
) -> Result<String, ExplorerCursorError> {
    if cursor.is_empty() || cursor.len() > EXPLORER_CURSOR_MAX_ENCODED_BYTES {
        return Err(ExplorerCursorError::InvalidFrame);
    }
    let decoded_bound = cursor.len().div_ceil(4) * 3;
    let mut frame = explorer_exact_vec::<u8>(decoded_bound, EXPLORER_CURSOR_MAX_ENCODED_BYTES)?;
    frame.resize(decoded_bound, 0);
    let written = URL_SAFE_NO_PAD
        .decode_slice(cursor.as_bytes(), &mut frame)
        .map_err(|_| ExplorerCursorError::InvalidEncoding)?;
    frame.truncate(written);
    if explorer_base64_frame(&frame)? != cursor {
        return Err(ExplorerCursorError::InvalidEncoding);
    }
    const HEADER_LEN: usize = 4 + 1 + 32 + 2;
    if frame.len() < HEADER_LEN || frame[..4] != EXPLORER_CURSOR_MAGIC {
        return Err(ExplorerCursorError::InvalidFrame);
    }
    if frame[4] != collection.tag() || frame[5..37] != filter_digest {
        return Err(ExplorerCursorError::ScopeMismatch);
    }
    let key_len = usize::from(u16::from_be_bytes([frame[37], frame[38]]));
    if key_len == 0
        || key_len > EXPLORER_CURSOR_MAX_KEY_BYTES
        || frame.len() != HEADER_LEN + key_len
    {
        return Err(ExplorerCursorError::InvalidFrame);
    }
    let mut key = explorer_exact_vec::<u8>(key_len, EXPLORER_CURSOR_MAX_KEY_BYTES)?;
    key.extend_from_slice(&frame[HEADER_LEN..]);
    String::from_utf8(key).map_err(|_| ExplorerCursorError::InvalidKey)
}
trait ExplorerCursorKeyText {
    fn checked_cursor_text(&self) -> Result<String, ExplorerCursorError>;
}
impl<K: ExplorerCursorKeyText + ?Sized> ExplorerCursorKeyText for &K {
    fn checked_cursor_text(&self) -> Result<String, ExplorerCursorError> {
        (*self).checked_cursor_text()
    }
}
macro_rules! impl_explorer_native_cursor_text {
    ($($key:ty),+ $(,)?) => { $(
        impl ExplorerCursorKeyText for $key {
            fn checked_cursor_text(&self) -> Result<String, ExplorerCursorError> {
                explorer_checked_key_text(self, EXPLORER_CURSOR_MAX_KEY_BYTES)
            }
        }
    )+ };
}
impl_explorer_native_cursor_text!(AccountId, DomainId, AssetDefinitionId, AssetId, NftId);
macro_rules! impl_explorer_display_cursor_text {
    ($($key:ty),+ $(,)?) => { $(
        impl ExplorerCursorKeyText for $key {
            fn checked_cursor_text(&self) -> Result<String, ExplorerCursorError> {
                explorer_checked_key_text(&ExplorerText(self), EXPLORER_CURSOR_MAX_KEY_BYTES)
            }
        }
    )+ };
}
impl_explorer_display_cursor_text!(RwaId);
#[cfg(test)]
impl ExplorerCursorKeyText for u32 {
    fn checked_cursor_text(&self) -> Result<String, ExplorerCursorError> {
        explorer_checked_key_text(&ExplorerText(self), EXPLORER_CURSOR_MAX_KEY_BYTES)
    }
}
trait CanonicalExplorerCursorKey: ExplorerCursorKeyText + Sized {
    fn parse_canonical_cursor_key(key: &str) -> Result<Self, ExplorerCursorError>;
}
fn require_canonical_cursor_text<K: ExplorerCursorKeyText>(
    key: &str,
    parsed: K,
) -> Result<K, ExplorerCursorError> {
    if parsed.checked_cursor_text()? != key {
        return Err(ExplorerCursorError::InvalidKey);
    }
    Ok(parsed)
}
impl CanonicalExplorerCursorKey for AccountId {
    fn parse_canonical_cursor_key(key: &str) -> Result<Self, ExplorerCursorError> {
        let parsed = json::JsonObjectKeyOwned::from_json_key_text(key).map_err(|error| {
            if matches!(
                error,
                json::Error::DecodeResourceLimit
                    | json::Error::DecodeResource(
                        norito::core::DecodeResourceError::ArchiveLengthExceeded { .. }
                            | norito::core::DecodeResourceError::SequenceLengthExceeded { .. }
                            | norito::core::DecodeResourceError::FieldLengthExceeded { .. }
                            | norito::core::DecodeResourceError::TotalElementsExceeded { .. }
                            | norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                    )
            ) {
                ExplorerCursorError::ByteLimitExceeded
            } else {
                ExplorerCursorError::InvalidKey
            }
        })?;
        require_canonical_cursor_text(key, parsed)
    }
}
impl CanonicalExplorerCursorKey for DomainId {
    fn parse_canonical_cursor_key(key: &str) -> Result<Self, ExplorerCursorError> {
        let parsed = json::JsonObjectKeyOwned::from_json_key_text(key).map_err(|error| {
            if matches!(
                error,
                json::Error::DecodeResourceLimit
                    | json::Error::DecodeResource(
                        norito::core::DecodeResourceError::ArchiveLengthExceeded { .. }
                            | norito::core::DecodeResourceError::SequenceLengthExceeded { .. }
                            | norito::core::DecodeResourceError::FieldLengthExceeded { .. }
                            | norito::core::DecodeResourceError::TotalElementsExceeded { .. }
                            | norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                    )
            ) {
                ExplorerCursorError::ByteLimitExceeded
            } else {
                ExplorerCursorError::InvalidKey
            }
        })?;
        require_canonical_cursor_text(key, parsed)
    }
}
impl CanonicalExplorerCursorKey for AssetId {
    fn parse_canonical_cursor_key(key: &str) -> Result<Self, ExplorerCursorError> {
        let encoded = json::to_json_bounded_boxed(key, EXPLORER_CURSOR_MAX_KEY_BYTES * 6 + 2)
            .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
        let parsed = json::from_slice::<Self>(&encoded).map_err(|error| {
            if matches!(
                error,
                json::Error::DecodeResourceLimit
                    | json::Error::DecodeResource(
                        norito::core::DecodeResourceError::ArchiveLengthExceeded { .. }
                            | norito::core::DecodeResourceError::SequenceLengthExceeded { .. }
                            | norito::core::DecodeResourceError::FieldLengthExceeded { .. }
                            | norito::core::DecodeResourceError::TotalElementsExceeded { .. }
                            | norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                    )
            ) {
                ExplorerCursorError::ByteLimitExceeded
            } else {
                ExplorerCursorError::InvalidKey
            }
        })?;
        require_canonical_cursor_text(key, parsed)
    }
}
macro_rules! impl_canonical_explorer_cursor_key_from_str {
    ($($key:ty),+ $(,)?) => { $(
        impl CanonicalExplorerCursorKey for $key {
            fn parse_canonical_cursor_key(key: &str) -> Result<Self, ExplorerCursorError> {
                let parsed = key.parse::<Self>().map_err(|_| ExplorerCursorError::InvalidKey)?;
                require_canonical_cursor_text(key, parsed)
            }
        }
    )+ };
}
impl_canonical_explorer_cursor_key_from_str!(AssetDefinitionId);
impl CanonicalExplorerCursorKey for NftId {
    fn parse_canonical_cursor_key(key: &str) -> Result<Self, ExplorerCursorError> {
        let (name, domain) = key.split_once('$').ok_or(ExplorerCursorError::InvalidKey)?;
        let name = json::JsonObjectKeyOwned::from_json_key_text(name)
            .map_err(explorer_identifier_decode_error)?;
        let domain = json::JsonObjectKeyOwned::from_json_key_text(domain)
            .map_err(explorer_identifier_decode_error)?;
        require_canonical_cursor_text(key, NftId::new(domain, name))
    }
}
impl CanonicalExplorerCursorKey for RwaId {
    fn parse_canonical_cursor_key(key: &str) -> Result<Self, ExplorerCursorError> {
        let (hash, domain) = key.split_once('$').ok_or(ExplorerCursorError::InvalidKey)?;
        if hash.len() != iroha_crypto::Hash::LENGTH * 2 {
            return Err(ExplorerCursorError::InvalidKey);
        }
        norito::core::reserve_decode_allocation(iroha_crypto::Hash::LENGTH)
            .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
        let hash = hash.parse().map_err(|_| ExplorerCursorError::InvalidKey)?;
        let domain = json::JsonObjectKeyOwned::from_json_key_text(domain)
            .map_err(explorer_identifier_decode_error)?;
        require_canonical_cursor_text(key, RwaId::new(domain, hash))
    }
}
fn explorer_identifier_decode_error(error: json::Error) -> ExplorerCursorError {
    if matches!(
        error,
        json::Error::DecodeResourceLimit
            | json::Error::DecodeResource(
                norito::core::DecodeResourceError::ArchiveLengthExceeded { .. }
                    | norito::core::DecodeResourceError::SequenceLengthExceeded { .. }
                    | norito::core::DecodeResourceError::FieldLengthExceeded { .. }
                    | norito::core::DecodeResourceError::TotalElementsExceeded { .. }
                    | norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            )
    ) {
        ExplorerCursorError::ByteLimitExceeded
    } else {
        ExplorerCursorError::InvalidKey
    }
}
fn canonical_cursor_key<K>(
    cursor: Option<&str>,
    collection: ExplorerCursorCollection,
    filter_digest: [u8; 32],
) -> Result<Option<K>, ExplorerCursorError>
where
    K: CanonicalExplorerCursorKey,
{
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let key = decode_explorer_cursor_key(cursor, collection, filter_digest)?;
    let parsed = K::parse_canonical_cursor_key(&key)?;
    Ok(Some(parsed))
}
#[derive(Debug)]
struct ExplorerScanPage<K, T> {
    items: Vec<T>,
    last_scanned: Option<K>,
    #[cfg(test)]
    scanned: usize,
    has_more: bool,
}
fn collect_explorer_cursor_page<I, Candidate, K, T>(
    candidates: I,
    limit: usize,
    byte_budget: usize,
    key_of: impl Fn(&Candidate) -> K,
    visible: impl Fn(&Candidate) -> bool,
    include: impl Fn(&Candidate) -> bool,
    project: impl Fn(Candidate) -> Result<T, ExplorerCursorError>,
) -> Result<ExplorerScanPage<K, T>, ExplorerCursorError>
where
    I: IntoIterator<Item = Candidate>,
{
    let scan_budget = limit
        .saturating_mul(8)
        .max(limit)
        .min(EXPLORER_CURSOR_MAX_SCAN);
    // Keep authorization outside the bounded secondary-filter scan. Besides making `has_more`
    // describe only the caller-visible range, this ensures `last_scanned` can be serialized into a
    // reversible cursor without disclosing a hidden entity key. Raw authorization work retains an
    // independent hard cap; a page fails closed when that cap cannot prove a safe continuation.
    let mut candidates = candidates.into_iter();
    let mut items = explorer_exact_vec::<T>(limit, byte_budget)?;
    let mut last_scanned = None;
    let mut scanned = 0_usize;
    let mut raw_scanned = 0_usize;
    let mut exhausted = false;
    while items.len() < limit && scanned < scan_budget {
        if raw_scanned == EXPLORER_CURSOR_MAX_SCAN {
            if candidates.size_hint().1 == Some(0) {
                exhausted = true;
                break;
            }
            return Err(ExplorerCursorError::ScanLimitExceeded);
        }
        let Some(candidate) = candidates.next() else {
            exhausted = true;
            break;
        };
        raw_scanned = raw_scanned.saturating_add(1);
        if !visible(&candidate) {
            continue;
        }
        last_scanned = Some(key_of(&candidate));
        scanned = scanned.saturating_add(1);
        if include(&candidate) {
            items.push(project(candidate)?);
        }
    }
    let has_more = if exhausted {
        false
    } else {
        loop {
            if raw_scanned == EXPLORER_CURSOR_MAX_SCAN {
                if candidates.size_hint().1 == Some(0) {
                    break false;
                }
                return Err(ExplorerCursorError::ScanLimitExceeded);
            }
            let Some(candidate) = candidates.next() else {
                break false;
            };
            raw_scanned = raw_scanned.saturating_add(1);
            if visible(&candidate) {
                break true;
            }
        }
    };
    Ok(ExplorerScanPage {
        items,
        last_scanned,
        #[cfg(test)]
        scanned,
        has_more,
    })
}
fn explorer_cursor_meta<K: ExplorerCursorKeyText>(
    collection: ExplorerCursorCollection,
    filter_digest: [u8; 32],
    limit: u32,
    last_scanned: Option<&K>,
    has_more: bool,
) -> Result<ExplorerCursorMeta, ExplorerCursorError> {
    let next_cursor = if has_more {
        let last_scanned = last_scanned.ok_or(ExplorerCursorError::InvalidFrame)?;
        Some(encode_explorer_cursor(
            collection,
            filter_digest,
            &last_scanned.checked_cursor_text()?,
        )?)
    } else {
        None
    };
    Ok(ExplorerCursorMeta {
        limit,
        next_cursor,
        has_more,
    })
}
pub(crate) fn account_counters_from_world(
    world: &impl WorldReadOnly,
    id: &AccountId,
    visibility: &DataspaceReadVisibility,
) -> AccountCounters {
    AccountCounters {
        domains: world.domains_by_owner().get(id).map_or(0, |domains| {
            saturating_usize_to_u32(
                domains
                    .iter()
                    .filter(|domain| visibility.allows_domain(world, domain))
                    .count(),
            )
        }),
        assets: world.assets_by_account().get(id).map_or(0, |assets| {
            saturating_usize_to_u32(
                assets
                    .iter()
                    .filter(|asset| visibility.allows_asset(world, asset))
                    .count(),
            )
        }),
        nfts: world.nfts_by_owner().get(id).map_or(0, |nfts| {
            saturating_usize_to_u32(
                nfts.iter()
                    .filter(|nft| visibility.allows_nft(world, nft))
                    .count(),
            )
        }),
    }
}
pub(crate) fn domain_counters_from_world(
    world: &impl WorldReadOnly,
    id: &DomainId,
    visibility: &DataspaceReadVisibility,
) -> DomainCounters {
    let accounts = world
        .account_scope_domain_key(id)
        .and_then(|key| world.account_scope_accounts().get(&key))
        .map_or(0, |accounts| {
            saturating_usize_to_u32(
                accounts
                    .iter()
                    .filter(|account| visibility.allows_account(world, account))
                    .count(),
            )
        });
    DomainCounters {
        accounts,
        assets: world.assets_by_domain().get(id).map_or(0, |assets| {
            saturating_usize_to_u32(
                assets
                    .iter()
                    .filter(|asset| visibility.allows_asset(world, asset))
                    .count(),
            )
        }),
        nfts: world.nfts_by_domain().get(id).map_or(0, |nfts| {
            saturating_usize_to_u32(
                nfts.iter()
                    .filter(|nft| visibility.allows_nft(world, nft))
                    .count(),
            )
        }),
    }
}
pub(crate) fn definition_instance_count_from_world(
    world: &impl WorldReadOnly,
    id: &AssetDefinitionId,
    visibility: &DataspaceReadVisibility,
) -> u32 {
    world.asset_definition_assets().get(id).map_or(0, |assets| {
        saturating_usize_to_u32(
            assets
                .iter()
                .filter(|asset| visibility.allows_asset(world, asset))
                .count(),
        )
    })
}
fn account_holds_definition_from_world(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> bool {
    world
        .asset_definition_holders()
        .get(definition)
        .map_or(false, |holders| holders.contains(account))
}
pub(crate) fn accounts_page_for_filters<'world>(
    world: &'world impl WorldReadOnly,
    domain_filter: Option<&'world DomainId>,
    definition_filter: Option<&'world AssetDefinitionId>,
    visibility: &'world DataspaceReadVisibility,
    query: &ExplorerCursorQuery,
    byte_budget: usize,
) -> Result<ExplorerAccountsPage<'world>, ExplorerCursorError> {
    let limit = query.validated_limit()?;
    let filter_digest = explorer_filter_digest(
        ExplorerCursorCollection::Accounts,
        &[
            explorer_filter(domain_filter),
            explorer_filter(definition_filter),
        ],
        visibility.visible_route_set_digest(),
        byte_budget,
    )?;
    let after = canonical_cursor_key::<AccountId>(
        query.cursor.as_deref(),
        ExplorerCursorCollection::Accounts,
        filter_digest,
    )?;
    let selectors_visible = domain_filter
        .is_none_or(|domain| visibility.allows_domain(world, domain))
        && definition_filter
            .is_none_or(|definition| visibility.allows_asset_definition(world, definition));
    let domain_accounts = if let Some(domain) = domain_filter {
        // The reverse index is the committed domain authority. Charge the one
        // bounded lookup-name copy; do not clone account alias/domain graphs.
        norito::core::reserve_decode_allocation(domain.name().as_ref().len())
            .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
        world
            .account_scope_domain_key(domain)
            .and_then(|key| world.account_scope_accounts().get(&key))
    } else {
        None
    };
    let accounts: Box<dyn Iterator<Item = AccountEntry<'world>> + 'world> = if !selectors_visible {
        explorer_iterator(std::iter::empty())?
    } else if let Some(definition) = definition_filter {
        let holders = world.asset_definition_holders().get(definition);
        let account_ids: Box<dyn Iterator<Item = &'world AccountId> + 'world> = match holders {
            Some(holders) => match after {
                Some(after) => explorer_iterator(holders.range((Excluded(after), Unbounded)))?,
                None => explorer_iterator(holders.iter())?,
            },
            None => explorer_iterator(std::iter::empty())?,
        };
        explorer_iterator(account_ids.filter_map(move |account_id| {
            world
                .accounts()
                .get_key_value(account_id)
                .map(|(id, value)| AccountEntry::new(id, value))
        }))?
    } else if domain_filter.is_some() {
        let account_ids = domain_accounts;
        let account_ids: Box<dyn Iterator<Item = &'world AccountId> + 'world> = match account_ids {
            Some(account_ids) => match after {
                Some(after) => explorer_iterator(account_ids.range((Excluded(after), Unbounded)))?,
                None => explorer_iterator(account_ids.iter())?,
            },
            None => explorer_iterator(std::iter::empty())?,
        };
        explorer_iterator(account_ids.filter_map(move |account_id| {
            world
                .accounts()
                .get_key_value(account_id)
                .map(|(id, value)| AccountEntry::new(id, value))
        }))?
    } else {
        match after {
            Some(after) => explorer_iterator(
                world
                    .accounts()
                    .range((Excluded(after), Unbounded))
                    .map(|(id, value)| AccountEntry::new(id, value)),
            )?,
            None => explorer_iterator(world.accounts_iter())?,
        }
    };
    let scanned = collect_explorer_cursor_page(
        accounts,
        limit,
        byte_budget,
        |entry| entry.id,
        |entry| visibility.allows_account(world, entry.id()),
        |entry| {
            (domain_filter.is_none()
                || domain_accounts.is_some_and(|accounts| accounts.contains(entry.id())))
                && definition_filter.is_none_or(|definition| {
                    account_holds_definition_from_world(world, definition, entry.id())
                })
        },
        |entry| {
            let counts = account_counters_from_world(world, entry.id(), visibility);
            Ok(ExplorerAccountDto::from_entry(entry, counts))
        },
    )?;
    let pagination = explorer_cursor_meta(
        ExplorerCursorCollection::Accounts,
        filter_digest,
        query.limit,
        scanned.last_scanned.as_ref(),
        scanned.has_more,
    )?;
    Ok(ExplorerAccountsPage {
        pagination,
        items: scanned.items,
    })
}
pub(crate) fn domains_page_for_filters<'world>(
    world: &'world impl WorldReadOnly,
    owned_by: Option<&'world AccountId>,
    visibility: &'world DataspaceReadVisibility,
    query: &ExplorerCursorQuery,
    byte_budget: usize,
) -> Result<ExplorerDomainsPage<'world>, ExplorerCursorError> {
    let limit = query.validated_limit()?;
    let filter_digest = explorer_filter_digest(
        ExplorerCursorCollection::Domains,
        &[explorer_filter(owned_by)],
        visibility.visible_route_set_digest(),
        byte_budget,
    )?;
    let after = canonical_cursor_key::<DomainId>(
        query.cursor.as_deref(),
        ExplorerCursorCollection::Domains,
        filter_digest,
    )?;
    let domains: Box<dyn Iterator<Item = &'world Domain> + 'world> = if owned_by
        .is_some_and(|owner| !visibility.allows_account(world, owner))
    {
        explorer_iterator(std::iter::empty())?
    } else if let Some(owner) = owned_by {
        let domain_ids = world.domains_by_owner().get(owner);
        let domain_ids: Box<dyn Iterator<Item = &'world DomainId> + 'world> = match domain_ids {
            Some(domain_ids) => match after {
                Some(after) => explorer_iterator(domain_ids.range((Excluded(after), Unbounded)))?,
                None => explorer_iterator(domain_ids.iter())?,
            },
            None => explorer_iterator(std::iter::empty())?,
        };
        explorer_iterator(domain_ids.filter_map(|domain_id| world.domains().get(domain_id)))?
    } else {
        match after {
            Some(after) => explorer_iterator(
                world
                    .domains()
                    .range((Excluded(after), Unbounded))
                    .map(|(_, domain)| domain),
            )?,
            None => explorer_iterator(world.domains_iter())?,
        }
    };
    let scanned = collect_explorer_cursor_page(
        domains,
        limit,
        byte_budget,
        |domain| (*domain).id(),
        |domain| visibility.allows_domain(world, domain.id()),
        |domain| owned_by.is_none_or(|owner| domain.owned_by() == owner),
        |domain| {
            norito::core::reserve_decode_allocation(domain.id().name().as_ref().len())
                .map_err(|_| ExplorerCursorError::ByteLimitExceeded)?;
            let counts = domain_counters_from_world(world, domain.id(), visibility);
            Ok(ExplorerDomainDto::from_domain(domain, counts))
        },
    )?;
    let pagination = explorer_cursor_meta(
        ExplorerCursorCollection::Domains,
        filter_digest,
        query.limit,
        scanned.last_scanned.as_ref(),
        scanned.has_more,
    )?;
    Ok(ExplorerDomainsPage {
        pagination,
        items: scanned.items,
    })
}
pub(crate) fn asset_definitions_page_for_filters<'world>(
    world: &'world impl WorldReadOnly,
    owning_domain_filter: Option<&'world DomainId>,
    owner_filter: Option<&'world AccountId>,
    visibility: &'world DataspaceReadVisibility,
    query: &ExplorerCursorQuery,
    byte_budget: usize,
) -> Result<ExplorerAssetDefinitionsPage<'world>, ExplorerCursorError> {
    let limit = query.validated_limit()?;
    let filter_digest = explorer_filter_digest(
        ExplorerCursorCollection::AssetDefinitions,
        &[
            explorer_filter(owning_domain_filter),
            explorer_filter(owner_filter),
        ],
        visibility.visible_route_set_digest(),
        byte_budget,
    )?;
    let after = canonical_cursor_key::<AssetDefinitionId>(
        query.cursor.as_deref(),
        ExplorerCursorCollection::AssetDefinitions,
        filter_digest,
    )?;
    let selectors_visible = owning_domain_filter
        .is_none_or(|domain| visibility.allows_domain(world, domain))
        && owner_filter.is_none_or(|owner| visibility.allows_account(world, owner));
    let definitions: Box<dyn Iterator<Item = &'world AssetDefinition> + 'world> =
        if !selectors_visible {
            explorer_iterator(std::iter::empty())?
        } else if let Some(owner) = owner_filter {
            let definition_ids = world.asset_definitions_by_owner().get(owner);
            let definition_ids: Box<dyn Iterator<Item = &'world AssetDefinitionId> + 'world> =
                match definition_ids {
                    Some(definition_ids) => match after {
                        Some(after) => {
                            explorer_iterator(definition_ids.range((Excluded(after), Unbounded)))?
                        }
                        None => explorer_iterator(definition_ids.iter())?,
                    },
                    None => explorer_iterator(std::iter::empty())?,
                };
            explorer_iterator(definition_ids.filter_map(|id| world.asset_definitions().get(id)))?
        } else if let Some(domain) = owning_domain_filter {
            let definition_ids = world.domain_asset_definitions().get(domain);
            let definition_ids: Box<dyn Iterator<Item = &'world AssetDefinitionId> + 'world> =
                match definition_ids {
                    Some(definition_ids) => match after {
                        Some(after) => {
                            explorer_iterator(definition_ids.range((Excluded(after), Unbounded)))?
                        }
                        None => explorer_iterator(definition_ids.iter())?,
                    },
                    None => explorer_iterator(std::iter::empty())?,
                };
            explorer_iterator(definition_ids.filter_map(|id| world.asset_definitions().get(id)))?
        } else {
            match after {
                Some(after) => explorer_iterator(
                    world
                        .asset_definitions()
                        .range((Excluded(after), Unbounded))
                        .map(|(_, definition)| definition),
                )?,
                None => explorer_iterator(world.asset_definitions_iter())?,
            }
        };
    let scanned = collect_explorer_cursor_page(
        definitions,
        limit,
        byte_budget,
        |definition| (*definition).id(),
        |definition| visibility.allows_asset_definition(world, definition.id()),
        |definition| {
            owning_domain_filter.is_none_or(|domain| {
                world.asset_definition_domains().get(definition.id()) == Some(domain)
            }) && owner_filter.is_none_or(|owner| definition.owned_by() == owner)
        },
        |definition| {
            Ok(
                ExplorerAssetDefinitionDto::from_definition_with_asset_count(
                    definition,
                    definition_instance_count_from_world(world, definition.id(), visibility),
                    world
                        .asset_definition_dataspace(definition.id())
                        .map_err(|_| ExplorerCursorError::InvalidSnapshot)?,
                ),
            )
        },
    )?;
    let pagination = explorer_cursor_meta(
        ExplorerCursorCollection::AssetDefinitions,
        filter_digest,
        query.limit,
        scanned.last_scanned.as_ref(),
        scanned.has_more,
    )?;
    Ok(ExplorerAssetDefinitionsPage {
        pagination,
        items: scanned.items,
    })
}
pub(crate) fn assets_page_for_filters<'world>(
    world: &'world impl WorldReadOnly,
    owned_by: Option<&'world AccountId>,
    definition_filter: Option<&'world AssetDefinitionId>,
    asset_filter: Option<&'world AssetId>,
    visibility: &'world DataspaceReadVisibility,
    query: &ExplorerCursorQuery,
    byte_budget: usize,
) -> Result<ExplorerAssetsPage<'world>, ExplorerCursorError> {
    let limit = query.validated_limit()?;
    let filter_digest = explorer_filter_digest(
        ExplorerCursorCollection::Assets,
        &[
            explorer_filter(owned_by),
            explorer_filter(definition_filter),
            explorer_filter(asset_filter),
        ],
        visibility.visible_route_set_digest(),
        byte_budget,
    )?;
    let after = canonical_cursor_key::<AssetId>(
        query.cursor.as_deref(),
        ExplorerCursorCollection::Assets,
        filter_digest,
    )?;
    if let (Some(after), Some(owner)) = (after.as_ref(), owned_by)
        && after.account() != owner
    {
        return Err(ExplorerCursorError::InvalidKey);
    }
    if let (Some(after), Some(owner), Some(definition)) =
        (after.as_ref(), owned_by, definition_filter)
        && (after.account() != owner || after.definition() != definition)
    {
        return Err(ExplorerCursorError::InvalidKey);
    }
    let selectors_visible = owned_by.is_none_or(|owner| visibility.allows_account(world, owner))
        && definition_filter
            .is_none_or(|definition| visibility.allows_asset_definition(world, definition))
        && asset_filter.is_none_or(|asset| visibility.allows_asset(world, asset));
    let assets: Box<dyn Iterator<Item = AssetEntry<'world>> + 'world> = if !selectors_visible {
        explorer_iterator(std::iter::empty())?
    } else if let Some(asset_id) = asset_filter {
        let entry = after
            .as_ref()
            .is_none_or(|after| asset_id > after)
            .then(|| world.assets().get_key_value(asset_id))
            .flatten()
            .map(|(id, value)| AssetEntry::new(id, value));
        explorer_iterator(entry.into_iter())?
    } else if let Some(owner) = owned_by {
        if let Some(definition) = definition_filter {
            match after {
                Some(after) => explorer_iterator(
                    world
                        .assets()
                        .range((Excluded(after), Unbounded))
                        .take_while(move |(id, _)| {
                            id.account() == owner && id.definition() == definition
                        })
                        .map(|(id, value)| AssetEntry::new(id, value)),
                )?,
                None => explorer_iterator(
                    world.assets_in_account_by_definition_iter(owner, definition),
                )?,
            }
        } else {
            match after {
                Some(after) => explorer_iterator(
                    world
                        .assets()
                        .range((Excluded(after), Unbounded))
                        .take_while(move |(id, _)| id.account() == owner)
                        .map(|(id, value)| AssetEntry::new(id, value)),
                )?,
                None => explorer_iterator(world.assets_in_account_iter(owner))?,
            }
        }
    } else if let Some(definition) = definition_filter {
        let asset_ids = world.asset_definition_assets().get(definition);
        let asset_ids: Box<dyn Iterator<Item = &'world AssetId> + 'world> = match asset_ids {
            Some(asset_ids) => match after {
                Some(after) => explorer_iterator(asset_ids.range((Excluded(after), Unbounded)))?,
                None => explorer_iterator(asset_ids.iter())?,
            },
            None => explorer_iterator(std::iter::empty())?,
        };
        explorer_iterator(asset_ids.filter_map(move |asset_id| {
            world
                .assets()
                .get_key_value(asset_id)
                .map(|(id, value)| AssetEntry::new(id, value))
        }))?
    } else {
        match after {
            Some(after) => explorer_iterator(
                world
                    .assets()
                    .range((Excluded(after), Unbounded))
                    .map(|(id, value)| AssetEntry::new(id, value)),
            )?,
            None => explorer_iterator(world.assets_iter())?,
        }
    };
    let scanned = collect_explorer_cursor_page(
        assets,
        limit,
        byte_budget,
        |entry| entry.id,
        |asset| visibility.allows_asset(world, asset.id()),
        |asset| {
            asset_filter.is_none_or(|expected| asset.id() == expected)
                && owned_by.is_none_or(|owner| asset.id().account() == owner)
                && definition_filter.is_none_or(|definition| asset.id().definition() == definition)
        },
        |entry| Ok(ExplorerAssetDto::from_entry(entry)),
    )?;
    let pagination = explorer_cursor_meta(
        ExplorerCursorCollection::Assets,
        filter_digest,
        query.limit,
        scanned.last_scanned.as_ref(),
        scanned.has_more,
    )?;
    Ok(ExplorerAssetsPage {
        pagination,
        items: scanned.items,
    })
}
pub(crate) fn nfts_page_for_filters<'world>(
    world: &'world impl WorldReadOnly,
    owned_by: Option<&'world AccountId>,
    domain_filter: Option<&'world DomainId>,
    visibility: &'world DataspaceReadVisibility,
    query: &ExplorerCursorQuery,
    byte_budget: usize,
) -> Result<ExplorerNftsPage<'world>, ExplorerCursorError> {
    let limit = query.validated_limit()?;
    let filter_digest = explorer_filter_digest(
        ExplorerCursorCollection::Nfts,
        &[explorer_filter(owned_by), explorer_filter(domain_filter)],
        visibility.visible_route_set_digest(),
        byte_budget,
    )?;
    let after = canonical_cursor_key::<NftId>(
        query.cursor.as_deref(),
        ExplorerCursorCollection::Nfts,
        filter_digest,
    )?;
    if owned_by.is_none()
        && let (Some(after), Some(domain)) = (after.as_ref(), domain_filter)
        && after.domain() != domain
    {
        return Err(ExplorerCursorError::InvalidKey);
    }
    let selectors_visible = owned_by.is_none_or(|owner| visibility.allows_account(world, owner))
        && domain_filter.is_none_or(|domain| visibility.allows_domain(world, domain));
    let nfts: Box<dyn Iterator<Item = NftEntry<'world>> + 'world> = if !selectors_visible {
        explorer_iterator(std::iter::empty())?
    } else if let Some(owner) = owned_by {
        let nft_ids = world.nfts_by_owner().get(owner);
        let nft_ids: Box<dyn Iterator<Item = &'world NftId> + 'world> = match nft_ids {
            Some(nft_ids) => match after {
                Some(after) => explorer_iterator(nft_ids.range((Excluded(after), Unbounded)))?,
                None => explorer_iterator(nft_ids.iter())?,
            },
            None => explorer_iterator(std::iter::empty())?,
        };
        explorer_iterator(nft_ids.filter_map(move |nft_id| {
            world
                .nfts()
                .get_key_value(nft_id)
                .map(|(id, value)| NftEntry::new(id, value))
        }))?
    } else if let Some(domain) = domain_filter {
        let nft_ids = world.nfts_by_domain().get(domain);
        let nft_ids: Box<dyn Iterator<Item = &'world NftId> + 'world> = match nft_ids {
            Some(nft_ids) => match after {
                Some(after) => explorer_iterator(nft_ids.range((Excluded(after), Unbounded)))?,
                None => explorer_iterator(nft_ids.iter())?,
            },
            None => explorer_iterator(std::iter::empty())?,
        };
        explorer_iterator(nft_ids.filter_map(move |nft_id| {
            world
                .nfts()
                .get_key_value(nft_id)
                .map(|(id, value)| NftEntry::new(id, value))
        }))?
    } else {
        match after {
            Some(after) => explorer_iterator(
                world
                    .nfts()
                    .range((Excluded(after), Unbounded))
                    .map(|(id, value)| NftEntry::new(id, value)),
            )?,
            None => explorer_iterator(world.nfts_iter())?,
        }
    };
    let scanned = collect_explorer_cursor_page(
        nfts,
        limit,
        byte_budget,
        |entry| entry.id,
        |nft| visibility.allows_nft(world, nft.id()),
        |nft| {
            owned_by.is_none_or(|owner| nft.value().owned_by == *owner)
                && domain_filter.is_none_or(|domain| nft.id().domain() == domain)
        },
        |entry| Ok(ExplorerNftDto::from_entry(entry)),
    )?;
    let pagination = explorer_cursor_meta(
        ExplorerCursorCollection::Nfts,
        filter_digest,
        query.limit,
        scanned.last_scanned.as_ref(),
        scanned.has_more,
    )?;
    Ok(ExplorerNftsPage {
        pagination,
        items: scanned.items,
    })
}
pub(crate) fn rwas_page_for_filters<'world>(
    world: &'world impl WorldReadOnly,
    owned_by: Option<&'world AccountId>,
    domain_filter: Option<&'world DomainId>,
    visibility: &'world DataspaceReadVisibility,
    query: &ExplorerCursorQuery,
    byte_budget: usize,
) -> Result<ExplorerRwasPage<'world>, ExplorerCursorError> {
    let limit = query.validated_limit()?;
    let filter_digest = explorer_filter_digest(
        ExplorerCursorCollection::Rwas,
        &[explorer_filter(owned_by), explorer_filter(domain_filter)],
        visibility.visible_route_set_digest(),
        byte_budget,
    )?;
    let after = canonical_cursor_key::<iroha_data_model::rwa::RwaId>(
        query.cursor.as_deref(),
        ExplorerCursorCollection::Rwas,
        filter_digest,
    )?;
    if owned_by.is_none()
        && let (Some(after), Some(domain)) = (after.as_ref(), domain_filter)
        && after.domain() != domain
    {
        return Err(ExplorerCursorError::InvalidKey);
    }
    let selectors_visible = owned_by.is_none_or(|owner| visibility.allows_account(world, owner))
        && domain_filter.is_none_or(|domain| visibility.allows_domain(world, domain));
    let rwas: Box<dyn Iterator<Item = RwaEntry<'world>> + 'world> = if !selectors_visible {
        explorer_iterator(std::iter::empty())?
    } else if let Some(owner) = owned_by {
        let rwa_ids = world.rwas_by_owner().get(owner);
        let rwa_ids: Box<dyn Iterator<Item = &'world iroha_data_model::rwa::RwaId> + 'world> =
            match rwa_ids {
                Some(rwa_ids) => match after {
                    Some(after) => explorer_iterator(rwa_ids.range((Excluded(after), Unbounded)))?,
                    None => explorer_iterator(rwa_ids.iter())?,
                },
                None => explorer_iterator(std::iter::empty())?,
            };
        explorer_iterator(rwa_ids.filter_map(move |rwa_id| {
            world
                .rwas()
                .get_key_value(rwa_id)
                .map(|(id, value)| RwaEntry::new(id, value))
        }))?
    } else if let Some(domain) = domain_filter {
        match after {
            Some(after) => explorer_iterator(
                world
                    .rwas()
                    .range((Excluded(after), Unbounded))
                    .take_while(move |(id, _)| id.domain() == domain)
                    .map(|(id, value)| RwaEntry::new(id, value)),
            )?,
            None => explorer_iterator(world.rwas_in_domain_iter(domain))?,
        }
    } else {
        match after {
            Some(after) => explorer_iterator(
                world
                    .rwas()
                    .range((Excluded(after), Unbounded))
                    .map(|(id, value)| RwaEntry::new(id, value)),
            )?,
            None => explorer_iterator(world.rwas_iter())?,
        }
    };
    let scanned = collect_explorer_cursor_page(
        rwas,
        limit,
        byte_budget,
        |entry| entry.id,
        |rwa| visibility.allows_rwa(world, rwa.id()),
        |rwa| {
            owned_by.is_none_or(|owner| rwa.value().owned_by == *owner)
                && domain_filter.is_none_or(|domain| rwa.id().domain() == domain)
        },
        |entry| Ok(ExplorerRwaDto::from_entry(entry)),
    )?;
    let pagination = explorer_cursor_meta(
        ExplorerCursorCollection::Rwas,
        filter_digest,
        query.limit,
        scanned.last_scanned.as_ref(),
        scanned.has_more,
    )?;
    Ok(ExplorerRwasPage {
        pagination,
        items: scanned.items,
    })
}
pub(crate) fn block_created_at(duration: Duration) -> String {
    duration_to_rfc3339(duration)
}
fn saturating_usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
/// Commit Explorer fixture lots through `RegisterRwa`, the only writer of the RWA table and
/// its owner index. Each lot is `(domain, owner, quantity)`; the domain and the owner must
/// already exist. Identifiers are generated, so callers read them back from the World.
#[cfg(test)]
pub(crate) fn register_rwa_lots_for_tests(
    state: &iroha_core::state::State,
    lots: &[(&DomainId, &AccountId, u32)],
) {
    use iroha_core::smartcontracts::Execute as _;
    use iroha_data_model::{
        block::BlockHeader,
        isi::rwa::RegisterRwa,
        rwa::{NewRwa, RwaControlPolicy},
    };
    let height = std::num::NonZeroU64::new(1).expect("fixture height is non-zero");
    let mut block = state.block(BlockHeader::new(height, None, None, 0, 0));
    let mut transaction = block.transaction();
    // A generated identifier is derived from the entrypoint hash and a per-transaction ordinal.
    transaction.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
        [0xB1; iroha_crypto::Hash::LENGTH],
    ));
    for (index, &(domain, owner, quantity)) in lots.iter().enumerate() {
        RegisterRwa {
            rwa: NewRwa::new(
                domain.clone(),
                Quantity::from(quantity),
                iroha_primitives::numeric::NumericSpec::integer(),
                format!("https://example.org/lot/{index}"),
                None,
                Metadata::default(),
                Vec::new(),
                RwaControlPolicy::default(),
            ),
        }
        .execute(owner, &mut transaction)
        .expect("register fixture lot");
    }
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit fixture lots");
}
#[cfg(test)]
mod tests {
    use iroha_core::state::World;
    use iroha_data_model::{
        NetworkId, Registrable, ValidationFail,
        account::{Account, AccountDetails},
        asset::{AssetDefinitionAlias, AssetDefinitionId, AssetId, definition::MintabilityTokens},
        block::{BlockHeader, builder::BlockBuilder},
        common::{Owned, Ref},
        domain::Domain,
        isi::{Register, Transfer},
        nft::{NftData, NftId},
        smart_contract::ContractAddress,
        transaction::{
            error::TransactionRejectionReason,
            executable::{ContractInvocation, Executable},
            signed::{SignedTransaction, TransactionBuilder, TransactionResult},
        },
        trigger::DataTriggerSequence,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::numeric::Quantity;
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};
    use std::{iter, num::NonZeroU32, time::Duration as StdDuration};
    fn test_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xA1; iroha_crypto::Hash::LENGTH]),
        ))
    }
    #[test]
    fn legacy_world_offset_page_helpers_cannot_reenter() {
        let source = include_str!("explorer.rs");
        for name in [
            "accounts_page",
            "domains_page",
            "asset_definitions_page",
            "assets_page",
            "nfts_page",
            "rwas_page",
        ] {
            let declared = source.lines().map(str::trim_start).any(|line| {
                let line = line.strip_prefix("pub(crate) ").unwrap_or(line);
                line.strip_prefix("fn ")
                    .and_then(|rest| rest.strip_prefix(name))
                    .and_then(|tail| tail.as_bytes().first())
                    .is_some_and(|byte| matches!(byte, b'(' | b'<'))
            });
            assert!(!declared, "legacy offset helper `{name}` must stay removed");
        }
    }
    #[test]
    fn asset_definition_owning_domain_filter_uses_stored_ownership() {
        let domain_id =
            DomainId::try_new("owned_explorer", "universal").expect("domain identifier");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "coin".parse().expect("asset name"),
        );
        let alias: AssetDefinitionAlias = "coin#owned_explorer.universal"
            .parse()
            .expect("qualified asset alias");
        let definition = AssetDefinition::numeric(
            definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        )
        .with_alias(Some(alias))
        .build(&ALICE_ID);
        let world = World::with_assets(
            [Domain::new(domain_id.clone()).build(&ALICE_ID)],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [definition],
            [],
            [],
        );
        let view = world.view();
        assert_eq!(
            view.asset_definition_domains().get(&definition_id),
            Some(&domain_id),
            "fixture must retain exact authoritative domain context"
        );
        let query = ExplorerCursorQuery {
            cursor: None,
            limit: EXPLORER_CURSOR_MAX_LIMIT,
        };
        let visibility = DataspaceReadVisibility::new(
            std::collections::BTreeSet::from([iroha_model_base::topology::DataSpaceId::UNIVERSAL]),
            false,
        );
        let domain_page = asset_definitions_page_for_filters(
            &view,
            Some(&domain_id),
            None,
            &visibility,
            &query,
            64 * 1024,
        )
        .expect("domain-filtered page");
        assert_eq!(domain_page.items.len(), 1);
        assert_eq!(domain_page.items[0].id, &definition_id);
        assert_eq!(domain_page.items[0].owning_domain, Some(&domain_id));
        let domain_and_owner_page = asset_definitions_page_for_filters(
            &view,
            Some(&domain_id),
            Some(&ALICE_ID),
            &visibility,
            &query,
            64 * 1024,
        )
        .expect("domain-and-owner-filtered page");
        assert_eq!(domain_and_owner_page.items.len(), 1);
        assert_eq!(domain_and_owner_page.items[0].id, &definition_id);

        let hidden_visibility = DataspaceReadVisibility::default();
        let hidden_page = asset_definitions_page_for_filters(
            &view,
            Some(&domain_id),
            Some(&ALICE_ID),
            &hidden_visibility,
            &query,
            64 * 1024,
        )
        .expect("hidden selector must be indistinguishable from an empty result");
        assert!(hidden_page.items.is_empty());
        assert!(!hidden_page.pagination.has_more);
        assert!(hidden_page.pagination.next_cursor.is_none());
    }
    use super::*;
    use nonzero_ext::nonzero;
    #[test]
    fn instruction_kind_filter_accepts_camelcase_and_snake_case() {
        for raw in ["SetKeyValue", "set_key_value"] {
            assert_eq!(
                raw.parse::<ExplorerInstructionKind>()
                    .expect("set-key-value kind"),
                ExplorerInstructionKind::SetKeyValue
            );
        }
        for raw in ["ExecuteTrigger", "execute_trigger"] {
            assert_eq!(
                raw.parse::<ExplorerInstructionKind>()
                    .expect("execute-trigger kind"),
                ExplorerInstructionKind::ExecuteTrigger
            );
        }
        for retired in [
            "KagemushaTopUp",
            "kagemusha_top_up",
            "KagemushaRedemption",
            "kagemusha_redemption",
        ] {
            assert!(
                retired.parse::<ExplorerInstructionKind>().is_err(),
                "{retired} is not an explorer instruction kind"
            );
        }
    }
    #[test]
    fn history_cursor_is_snapshot_filter_visibility_and_route_bound() {
        let collection = ExplorerHistoryCollection::Transactions;
        let filter_digest =
            explorer_history_filter_digest(collection, &[Some("authority".to_owned()), None]);
        let visibility_digest = [0x22; 32];
        let snapshot_hash = [0x33; 32];
        let entrypoint_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x55; iroha_crypto::Hash::LENGTH]),
        );
        let position = ExplorerHistoryPosition::transaction(41, entrypoint_hash);
        let meta = explorer_history_cursor_meta(
            collection,
            filter_digest,
            visibility_digest,
            17,
            42,
            Some(snapshot_hash),
            Some(position),
        )
        .expect("history cursor metadata");
        assert_eq!(meta.limit, 17);
        assert_eq!(meta.snapshot_height, 42);
        assert_eq!(
            meta.snapshot_hash.as_deref(),
            Some(hex::encode(snapshot_hash).as_str())
        );
        assert!(meta.has_more);
        let encoded = meta.next_cursor.expect("continuation cursor");
        let decoded =
            decode_explorer_history_cursor(&encoded, collection, filter_digest, visibility_digest)
                .expect("valid scoped history cursor");
        assert_eq!(decoded.snapshot_height, 42);
        assert_eq!(decoded.snapshot_hash, snapshot_hash);
        assert_eq!(decoded.position, position);

        let different_filter = explorer_history_filter_digest(
            collection,
            &[Some("another-authority".to_owned()), None],
        );
        assert_eq!(
            decode_explorer_history_cursor(
                &encoded,
                collection,
                different_filter,
                visibility_digest,
            ),
            Err(ExplorerCursorError::ScopeMismatch),
        );
        assert_eq!(
            decode_explorer_history_cursor(&encoded, collection, filter_digest, [0x44; 32],),
            Err(ExplorerCursorError::ScopeMismatch),
        );
        assert_eq!(
            decode_explorer_history_cursor(
                &encoded,
                ExplorerHistoryCollection::LatestTransactions,
                filter_digest,
                visibility_digest,
            ),
            Err(ExplorerCursorError::ScopeMismatch),
        );
    }
    #[test]
    fn history_cursor_stable_key_is_independent_of_hidden_entrypoint_positions() {
        let collection = ExplorerHistoryCollection::Instructions;
        let filter_digest = explorer_history_filter_digest(collection, &[]);
        let visibility_digest = [0x22; 32];
        let snapshot_hash = [0x33; 32];
        let entrypoint_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x55; iroha_crypto::Hash::LENGTH]),
        );
        let encode_after_hidden_rows = |_hidden_before: usize| {
            encode_explorer_history_cursor(
                collection,
                filter_digest,
                visibility_digest,
                ExplorerHistoryCursor {
                    snapshot_height: 42,
                    snapshot_hash,
                    position: ExplorerHistoryPosition::instruction(41, entrypoint_hash, 7),
                },
            )
            .expect("stable visible instruction cursor")
        };

        assert_eq!(
            encode_after_hidden_rows(0),
            encode_after_hidden_rows(37),
            "hidden physical rows must not change a visible continuation key",
        );
        assert_eq!(
            encode_explorer_history_cursor(
                ExplorerHistoryCollection::Transactions,
                explorer_history_filter_digest(ExplorerHistoryCollection::Transactions, &[]),
                visibility_digest,
                ExplorerHistoryCursor {
                    snapshot_height: 42,
                    snapshot_hash,
                    position: ExplorerHistoryPosition::transaction_start(41),
                },
            ),
            Err(ExplorerCursorError::InvalidKey),
            "an internal physical scan sentinel must never be serialized",
        );

        let encoded = encode_after_hidden_rows(0);
        let mut malformed_frame = URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("canonical history cursor frame");
        malformed_frame[148] &= !1;
        let malformed = URL_SAFE_NO_PAD.encode(malformed_frame);
        assert_eq!(
            decode_explorer_history_cursor(
                &malformed,
                collection,
                filter_digest,
                visibility_digest,
            ),
            Err(ExplorerCursorError::InvalidKey),
            "a malformed stable anchor hash must fail as a generic invalid key",
        );
    }
    #[test]
    fn explorer_cursor_is_canonical_collection_and_filter_bound() {
        let filters = [explorer_filter(Some(&"wonderland.universal")), None];
        let visibility_digest = [0x11; 32];
        let digest = explorer_filter_digest(
            ExplorerCursorCollection::Accounts,
            &filters,
            visibility_digest,
            64 * 1024,
        )
        .expect("bounded fixture digest");
        let cursor = encode_explorer_cursor(
            ExplorerCursorCollection::Accounts,
            digest,
            &ALICE_ID.to_string(),
        )
        .expect("bounded canonical cursor");
        let decoded = canonical_cursor_key::<AccountId>(
            Some(&cursor),
            ExplorerCursorCollection::Accounts,
            digest,
        )
        .expect("canonical account cursor")
        .expect("cursor key");
        assert_eq!(decoded, ALICE_ID.clone());
        let other_filters = [explorer_filter(Some(&"garden.universal")), None];
        let other_digest = explorer_filter_digest(
            ExplorerCursorCollection::Accounts,
            &other_filters,
            visibility_digest,
            64 * 1024,
        )
        .expect("bounded fixture digest");
        assert_eq!(
            canonical_cursor_key::<AccountId>(
                Some(&cursor),
                ExplorerCursorCollection::Accounts,
                other_digest,
            )
            .unwrap_err(),
            ExplorerCursorError::ScopeMismatch,
        );
        let other_visibility_digest = explorer_filter_digest(
            ExplorerCursorCollection::Accounts,
            &filters,
            [0x22; 32],
            64 * 1024,
        )
        .expect("bounded fixture digest");
        assert_eq!(
            canonical_cursor_key::<AccountId>(
                Some(&cursor),
                ExplorerCursorCollection::Accounts,
                other_visibility_digest,
            )
            .unwrap_err(),
            ExplorerCursorError::ScopeMismatch,
        );
        assert_eq!(
            canonical_cursor_key::<AccountId>(
                Some(&cursor),
                ExplorerCursorCollection::Domains,
                digest,
            )
            .unwrap_err(),
            ExplorerCursorError::ScopeMismatch,
        );
        assert_eq!(
            decode_explorer_cursor_key(
                &format!("{cursor}="),
                ExplorerCursorCollection::Accounts,
                digest,
            )
            .unwrap_err(),
            ExplorerCursorError::InvalidEncoding,
        );
    }
    #[test]
    fn explorer_cursor_uses_canonical_typed_identifier_decoders() {
        let account_digest = explorer_filter_digest(
            ExplorerCursorCollection::Accounts,
            &[None, None],
            [0; 32],
            64 * 1024,
        )
        .expect("bounded fixture digest");
        let noncanonical_account = format!(" {} ", &*ALICE_ID);
        let account_cursor = encode_explorer_cursor(
            ExplorerCursorCollection::Accounts,
            account_digest,
            &noncanonical_account,
        )
        .expect("bounded non-canonical account cursor");
        assert_eq!(
            canonical_cursor_key::<AccountId>(
                Some(&account_cursor),
                ExplorerCursorCollection::Accounts,
                account_digest,
            )
            .unwrap_err(),
            ExplorerCursorError::InvalidKey,
            "cursor decoding must not inherit AccountId parser whitespace normalization",
        );
        let domain =
            DomainId::try_new("wonderland", "universal").expect("canonical domain identifier");
        let domain_digest = explorer_filter_digest(
            ExplorerCursorCollection::Domains,
            &[None],
            [0; 32],
            64 * 1024,
        )
        .expect("bounded fixture digest");
        let domain_cursor = encode_explorer_cursor(
            ExplorerCursorCollection::Domains,
            domain_digest,
            &domain.to_string(),
        )
        .expect("bounded canonical domain cursor");
        assert_eq!(
            canonical_cursor_key::<DomainId>(
                Some(&domain_cursor),
                ExplorerCursorCollection::Domains,
                domain_digest,
            )
            .expect("canonical domain cursor")
            .expect("cursor key"),
            domain,
        );
        let noncanonical_domain_cursor = encode_explorer_cursor(
            ExplorerCursorCollection::Domains,
            domain_digest,
            "Wonderland.Universal",
        )
        .expect("bounded non-canonical domain cursor");
        assert_eq!(
            canonical_cursor_key::<DomainId>(
                Some(&noncanonical_domain_cursor),
                ExplorerCursorCollection::Domains,
                domain_digest,
            )
            .unwrap_err(),
            ExplorerCursorError::InvalidKey,
        );
    }
    #[test]
    fn explorer_cursor_query_defaults_and_rejects_retired_page_fields() {
        let query: ExplorerCursorQuery =
            json::from_str("{}").expect("default Explorer cursor query");
        assert_eq!(query.limit, EXPLORER_CURSOR_DEFAULT_LIMIT);
        assert!(query.cursor.is_none());
        assert_eq!(query.validated_limit(), Ok(25));
        let oversized: ExplorerCursorQuery =
            json::from_str(r#"{"limit":101}"#).expect("typed oversized limit");
        assert_eq!(
            oversized.validated_limit(),
            Err(ExplorerCursorError::InvalidLimit),
        );
        assert!(
            json::from_str::<ExplorerCursorQuery>(r#"{"page":1,"per_page":10}"#).is_err(),
            "first-release cursor routes must reject retired offset/page controls",
        );
    }
    #[test]
    fn sparse_cursor_scan_is_bounded_and_does_not_skip_first_unreturned_match() {
        let mut after = None;
        let mut pages = 0_usize;
        loop {
            let candidates = (after.map_or(0, |value| value + 1))..2_000;
            let page = collect_explorer_cursor_page(
                candidates,
                1,
                64 * 1024,
                |candidate| *candidate,
                |_| true,
                |candidate| *candidate == 1_000,
                |candidate| Ok(candidate),
            )
            .expect("bounded visible scan");
            assert!(
                page.scanned <= 8,
                "one-token sparse scan exceeded its budget"
            );
            pages = pages.saturating_add(1);
            if let Some(item) = page.items.first() {
                assert_eq!(*item, 1_000, "the first matching key must not be skipped");
                assert_eq!(page.last_scanned, Some(1_000));
                break;
            }
            assert!(page.has_more, "sparse scan stopped before the matching key");
            after = page.last_scanned;
            assert!(pages < 200, "bounded continuation failed to make progress");
        }
    }
    #[test]
    fn hidden_candidates_never_become_reversible_cursor_boundaries() {
        let page = collect_explorer_cursor_page(
            0_u32..40,
            1,
            64 * 1024,
            |candidate| *candidate,
            |candidate| *candidate % 2 == 0,
            |_| false,
            |candidate| Ok(candidate),
        )
        .expect("bounded authorized page");
        assert_eq!(page.scanned, 8);
        assert_eq!(page.last_scanned, Some(14));
        assert!(page.has_more);

        let digest =
            explorer_filter_digest(ExplorerCursorCollection::Accounts, &[], [0; 32], 64 * 1024)
                .expect("bounded fixture digest");
        let meta = explorer_cursor_meta(
            ExplorerCursorCollection::Accounts,
            digest,
            1,
            page.last_scanned.as_ref(),
            page.has_more,
        )
        .expect("visible cursor boundary");
        let encoded = meta.next_cursor.expect("visible continuation cursor");
        let decoded =
            decode_explorer_cursor_key(&encoded, ExplorerCursorCollection::Accounts, digest)
                .expect("reversible cursor key");
        assert_eq!(decoded, "14");
        assert!(
            decoded.parse::<u32>().is_ok_and(|key| key % 2 == 0),
            "a reversible cursor must never carry a hidden candidate key",
        );

        let hidden_tail = collect_explorer_cursor_page(
            0_u32..40,
            1,
            64 * 1024,
            |candidate| *candidate,
            |candidate| *candidate == 0,
            |_| false,
            |candidate| Ok(candidate),
        )
        .expect("bounded hidden tail");
        assert!(!hidden_tail.has_more);
    }
    #[test]
    fn hidden_candidate_scan_fails_closed_at_raw_work_limit() {
        let inspected = std::cell::Cell::new(0_usize);
        let error = collect_explorer_cursor_page(
            0_u32..600,
            1,
            64 * 1024,
            |candidate| *candidate,
            |candidate| {
                inspected.set(inspected.get().saturating_add(1));
                *candidate == 599
            },
            |_| false,
            |candidate| Ok(candidate),
        )
        .expect_err("a visible candidate beyond the raw scan bound must fail closed");
        assert_eq!(error, ExplorerCursorError::ScanLimitExceeded);
        assert_eq!(inspected.get(), EXPLORER_CURSOR_MAX_SCAN);
    }
    #[test]
    fn metadata_conversion_handles_entries() {
        let mut metadata = Metadata::default();
        let previous = metadata.insert("key".parse().unwrap(), json::Value::String("value".into()));
        assert!(previous.is_none(), "test metadata should start empty");
        let cloned = metadata_to_json(&metadata);
        match cloned {
            Value::Object(map) => {
                let value = map
                    .get("key")
                    .expect("metadata should contain inserted key");
                assert_eq!(value.as_str(), Some("value"));
            }
            _ => panic!("metadata should serialize into object"),
        }
    }
    #[test]
    fn mintable_label_matches_variants() {
        assert_eq!(
            ExplorerMintable(Mintable::Infinitely).to_string(),
            "Infinitely"
        );
        assert_eq!(ExplorerMintable(Mintable::Once).to_string(), "Once");
        assert_eq!(ExplorerMintable(Mintable::Not).to_string(), "Not");
        let tokens = MintabilityTokens::try_new(3).expect("non-zero tokens");
        assert_eq!(
            ExplorerMintable(Mintable::Limited(tokens)).to_string(),
            "Limited(3)"
        );
    }
    fn assert_explorer_wire<T: json::JsonSerialize>(value: &T, expected: Value) {
        let ordinary = json::to_vec(value).expect("ordinary canonical DTO");
        assert_eq!(json::from_slice::<Value>(&ordinary).unwrap(), expected);
        let bounded = json::to_json_bounded_boxed(value, ordinary.len())
            .expect("exact canonical DTO boundary");
        assert_eq!(&*bounded, ordinary.as_slice());
        assert!(json::to_json_bounded_boxed(value, ordinary.len() - 1).is_err());
    }
    #[test]
    fn domain_dto_reflects_counts() {
        let mut domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("test", "universal").expect("domain name"),
        )
        .with_logo("sorafs://manifest/logo.png".parse().unwrap())
        .build(&ALICE_ID);
        domain.metadata_mut().insert(
            "label".parse().unwrap(),
            json::Value::String("value".into()),
        );
        let counts = DomainCounters {
            accounts: 2,
            assets: 3,
            nfts: 4,
        };
        let dto = ExplorerDomainDto::from_domain(&domain, counts);
        assert_eq!(dto.accounts, 2);
        assert_eq!(dto.assets, 3);
        assert_eq!(dto.nfts, 4);
        assert_eq!(dto.owned_by, &*ALICE_ID);
        assert!(std::ptr::eq(dto.metadata, domain.metadata()));
        assert_explorer_wire(
            &dto,
            norito::json!({
                "id": (domain.id().to_string()), "logo": "sorafs://manifest/logo.png", "metadata": {"label":"value"},
                "owned_by": (ALICE_ID.to_string()), "accounts":2, "assets":3, "nfts":4
            }),
        );
    }
    #[test]
    fn account_dto_omits_redundant_i105_address_field() {
        let details = Owned::new(AccountDetails::new(
            Metadata::default(),
            None,
            None,
            Vec::new(),
        ));
        let account_id = ALICE_ID.clone();
        let entry = Ref::new(&account_id, &details);
        let dto = ExplorerAccountDto::from_entry(
            entry,
            AccountCounters {
                domains: 1,
                assets: 2,
                nfts: 3,
            },
        );
        let expected_id = account_id.to_string();
        assert_eq!(dto.id, &account_id);
        assert_eq!(
            dto.network_prefix,
            iroha_data_model::account::address::chain_discriminant()
        );
        assert_eq!(dto.owned_domains, 1);
        assert_eq!(dto.owned_assets, 2);
        assert_eq!(dto.owned_nfts, 3);
        let payload = norito::json::to_value(&dto).expect("dto json");
        let object = payload
            .as_object()
            .expect("dto should serialize as an object");
        assert_eq!(
            object.get("id").and_then(Value::as_str),
            Some(expected_id.as_str())
        );
        assert!(
            !object.contains_key("i105_address"),
            "explorer account detail should not emit redundant i105_address"
        );
        assert!(std::ptr::eq(dto.metadata, details.metadata()));
        assert_explorer_wire(
            &dto,
            norito::json!({
                "id": expected_id, "network_prefix": (dto.network_prefix),
                "metadata": {}, "owned_domains":1, "owned_assets":2, "owned_nfts":3
            }),
        );
    }
    #[test]
    fn asset_definition_dto_contains_metadata() {
        let def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let mut definition = {
            let __asset_definition_id = def_id.clone();
            iroha_data_model::asset::definition::AssetDefinition::numeric(
                __asset_definition_id,
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        definition.set_mintable(Mintable::Once);
        definition.total_quantity = Quantity::from(100u32);
        definition.metadata_mut().insert(
            "ticker".parse().unwrap(),
            json::Value::String("ROSE".into()),
        );
        let dto =
            ExplorerAssetDefinitionDto::from_definition_with_asset_count(&definition, 7, None);
        assert_eq!(dto.mintable.to_string(), "Once");
        assert_eq!(dto.assets, 7);
        assert_eq!(dto.total_quantity, &Quantity::from(100_u32));
        assert!(dto.locked_quantity.is_none());
        assert!(dto.circulating_quantity.is_none());
        assert_eq!(dto.owned_by, &*ALICE_ID);
        assert_eq!(dto.owning_domain, None);
        assert_eq!(dto.owning_dataspace, None);
        let direct = ExplorerAssetDefinitionDto::from_definition_with_asset_count(
            &definition,
            7,
            Some(DataSpaceId::new(8_648_377_547_929_788_715)),
        );
        assert_eq!(
            direct.owning_dataspace.as_deref(),
            Some("8648377547929788715")
        );
        assert!(direct.owning_domain.is_none());
        assert!(std::ptr::eq(dto.metadata, definition.metadata()));
        assert_explorer_wire(
            &dto,
            norito::json!({
                "id":(def_id.to_string()), "owning_domain":null, "owning_dataspace":null, "mintable":"Once", "logo":null,
                "metadata":{"ticker":"ROSE"}, "owned_by":(ALICE_ID.to_string()), "assets":7,
                "total_quantity":"100", "locked_quantity":null, "circulating_quantity":null
            }),
        );
    }
    #[test]
    fn asset_dto_formats_value() {
        let def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::new(def_id, ALICE_ID.clone());
        let value = Owned::new(Quantity::from(42u32));
        let entry = Ref::new(&asset_id, &value);
        let dto = ExplorerAssetDto::from_entry(entry);
        assert_eq!(dto.id, &asset_id);
        assert_eq!(dto.value, &Quantity::from(42_u32));
        assert_eq!(dto.account_id, &*ALICE_ID);
        assert_explorer_wire(
            &dto,
            norito::json!({
                "id":(asset_id.to_string()), "definition_id":(asset_id.definition().to_string()),
                "account_id":(ALICE_ID.to_string()), "value":"42"
            }),
        );
    }
    #[test]
    fn nft_dto_includes_metadata() {
        let nft_id: NftId = "rose$wonderland.universal".parse().expect("nft id");
        let mut data = NftData {
            content: Metadata::default(),
            owned_by: ALICE_ID.clone(),
        };
        data.content.insert(
            "artist".parse().unwrap(),
            json::Value::String("Alice".into()),
        );
        let value = Owned::new(data);
        let entry = Ref::new(&nft_id, &value);
        let dto = ExplorerNftDto::from_entry(entry);
        assert_eq!(dto.id, &nft_id);
        assert_eq!(dto.owned_by, &*ALICE_ID);
        let payload = json::to_value(&dto).expect("canonical NFT DTO");
        assert_eq!(
            payload.get("id").and_then(Value::as_str),
            Some(nft_id.to_string().as_str())
        );
        assert_eq!(
            payload
                .get("metadata")
                .and_then(|metadata| metadata.get("artist"))
                .and_then(Value::as_str),
            Some("Alice")
        );
        assert!(std::ptr::eq(dto.metadata, &value.content));
        assert_explorer_wire(
            &dto,
            norito::json!({
                "id":(nft_id.to_string()), "owned_by":(ALICE_ID.to_string()), "metadata":{"artist":"Alice"}
            }),
        );
    }
    #[test]
    fn borrowed_metadata_refuses_body_without_copying_the_world_graph() {
        let mut metadata = Metadata::default();
        metadata.insert(
            "large".parse().unwrap(),
            Value::String("x".repeat(256 * 1024)),
        );
        let details = Owned::new(AccountDetails::new(metadata, None, None, Vec::new()));
        let limits =
            |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 32);
        let (dto, construction) = norito::core::with_decode_limits_measured(limits(0), || {
            ExplorerAccountDto::from_entry(
                Ref::new(&ALICE_ID, &details),
                AccountCounters::default(),
            )
        });
        assert_eq!(construction.total_allocated_bytes(), 0);
        assert!(std::ptr::eq(dto.metadata, details.metadata()));
        let (encoded, usage) = norito::core::with_decode_limits_measured(limits(4096), || {
            json::to_json_bounded_boxed(&dto, 1024)
        });
        assert!(encoded.is_err());
        assert!(
            usage.total_allocated_bytes() < 4096,
            "oversized metadata must fail during count, before a destination or metadata graph copy"
        );
    }
    #[test]
    fn rwa_parent_projection_borrows_slice_and_preserves_text_quantities() {
        use iroha_data_model::rwa::{RwaControlPolicy, RwaData};
        let id = RwaId::generated(
            DomainId::try_new("vault", "universal").unwrap(),
            iroha_crypto::Hash::prehashed([0x31; 32]),
        );
        let parent = RwaParentRef::new(id.clone(), Quantity::from(3_u32));
        let value = Owned::new(RwaData {
            quantity: Quantity::from(7_u32),
            spec: iroha_primitives::numeric::NumericSpec::default(),
            primary_reference: "https://example.org/certificate".to_owned(),
            status: Some("held".parse().unwrap()),
            metadata: Metadata::default(),
            parents: vec![parent.clone()],
            controls: RwaControlPolicy::default(),
            owned_by: ALICE_ID.clone(),
            is_frozen: true,
            held_quantity: Quantity::from(2_u32),
        });
        let dto = ExplorerRwaDto::from_entry(Ref::new(&id, &value));
        assert!(std::ptr::eq(dto.metadata, &value.metadata));
        assert_eq!(dto.parents.0.as_ptr(), value.parents.as_ptr());
        assert_explorer_wire(
            &dto,
            norito::json!({
                "id":(id.to_string()), "owned_by":(ALICE_ID.to_string()), "quantity":"7", "held_quantity":"2",
                "primary_reference":"https://example.org/certificate", "status":"held", "is_frozen":true,
                "metadata":{}, "parents":[{"rwa":(id.to_string()),"quantity":"3"}]
            }),
        );
        let many = vec![parent; 2048];
        let projected = ExplorerRwaParents(&many);
        let (encoded, usage) = norito::core::with_decode_limits_measured(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || json::to_json_bounded_boxed(&projected, 64),
        );
        assert!(encoded.is_err());
        assert_eq!(
            usage.total_allocated_bytes(),
            0,
            "an oversized borrowed parent list must stop before any destination or parent Vec allocation"
        );
    }
    #[test]
    fn committed_account_visibility_is_borrowed_and_preserves_private_root_isolation() {
        use iroha_data_model::block::consensus::SumeragiRootScope;
        let mut world = World::with_assets(
            [],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
            ],
            [],
            [],
            [],
        );
        crate::test_utils::bind_fixture_root(&mut world, SumeragiRootScope::Global);
        let global = world.view();
        let public = DataspaceReadVisibility::new(
            std::collections::BTreeSet::from([DataSpaceId::UNIVERSAL]),
            false,
        );
        let old_scopes = global.account_dataspaces(&ALICE_ID).unwrap();
        assert!(!old_scopes.is_empty());
        let expected = old_scopes
            .iter()
            .all(|scope| *scope == DataSpaceId::UNIVERSAL);
        let (allowed, usage) = norito::core::with_decode_limits_measured(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || public.allows_account(&global, &ALICE_ID),
        );
        assert_eq!(allowed, expected);
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert!(!DataspaceReadVisibility::default().allows_account(&global, &ALICE_ID));
        let exact = DataspaceReadVisibility::exact_account(
            std::collections::BTreeSet::from([DataSpaceId::UNIVERSAL]),
            ALICE_ID.clone(),
        );
        assert!(exact.allows_account(&global, &ALICE_ID));
        assert!(!exact.allows_account(&global, &BOB_ID));
        drop(global);
        let private = DataSpaceId::new(7);
        crate::test_utils::bind_fixture_root(
            &mut world,
            SumeragiRootScope::Dataspace {
                parent_network_id: test_network_id(),
                dataspace_id: private,
            },
        );
        let private_world = world.view();
        assert!(!public.allows_account(&private_world, &ALICE_ID));
        assert!(
            DataspaceReadVisibility::new(std::collections::BTreeSet::from([private]), false)
                .allows_account(&private_world, &ALICE_ID)
        );
    }
    #[test]
    fn explorer_filter_digest_preserves_decoded_text_and_refuses_unfunded_id_scratch() {
        let domain = DomainId::try_new("vault", "universal").unwrap();
        let values = [domain.to_string(), ALICE_ID.to_string()];
        let mut expected = Sha256::new();
        expected.update(EXPLORER_CURSOR_FILTER_DOMAIN);
        expected.update([ExplorerCursorCollection::Accounts.tag()]);
        expected.update(2_u32.to_be_bytes());
        for value in &values {
            expected.update([1]);
            expected.update((value.len() as u32).to_be_bytes());
            expected.update(value.as_bytes());
        }
        expected.update([0x11; 32]);
        let filters = [
            explorer_filter(Some(&domain)),
            explorer_filter(Some(&*ALICE_ID)),
        ];
        assert_eq!(
            explorer_filter_digest(
                ExplorerCursorCollection::Accounts,
                &filters,
                [0x11; 32],
                64 * 1024
            )
            .unwrap(),
            <[u8; 32]>::from(expected.finalize())
        );
        assert!(
            norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
                || {
                    explorer_filter_digest(
                        ExplorerCursorCollection::Accounts,
                        &filters,
                        [0x11; 32],
                        64 * 1024,
                    )
                }
            )
            .is_err()
        );
    }
    #[test]
    fn explorer_filter_borrows_the_selector_and_keeps_absence() {
        let domain = DomainId::try_new("vault", "universal").unwrap();
        let borrowed = explorer_filter(Some(&domain)).expect("present selector");
        assert!(std::ptr::addr_eq(
            std::ptr::from_ref(borrowed),
            std::ptr::from_ref(&domain)
        ));
        assert_eq!(
            json::to_json(borrowed).unwrap(),
            json::to_json(&domain).unwrap()
        );
        assert!(explorer_filter::<DomainId>(None).is_none());
        let absent = [explorer_filter::<DomainId>(None)];
        let present = [explorer_filter(Some(&domain))];
        assert_ne!(
            explorer_filter_digest(ExplorerCursorCollection::Domains, &absent, [0; 32], 1024)
                .unwrap(),
            explorer_filter_digest(ExplorerCursorCollection::Domains, &present, [0; 32], 1024)
                .unwrap(),
        );
    }
    /// Byte budget of the selector-binding page fixtures.
    const SELECTOR_PAGE_BUDGET: usize = 64 * 1024;
    /// Listed key texts with the pagination of one world-collection page.
    type SelectorPage = Result<(Vec<String>, ExplorerCursorMeta), ExplorerCursorError>;
    /// The decoded JSON text of one identifier, taken from the ordinary serializer and not
    /// from the selector helper under test.
    fn canonical_text<T: json::JsonSerialize>(value: &T) -> String {
        match json::to_value(value).expect("identifier JSON") {
            Value::String(text) => text,
            other => panic!("an identifier must serialize as one JSON string, got {other:?}"),
        }
    }
    /// Independent oracle for the world cursor issued to a global reader: the collection
    /// tag, each selector's presence flag and text in route order, the visibility digest
    /// and the last listed key.
    fn selector_cursor_oracle(
        collection: ExplorerCursorCollection,
        selectors: &[Option<String>],
        key: &str,
    ) -> String {
        let mut digest = Sha256::new();
        digest.update(EXPLORER_CURSOR_FILTER_DOMAIN);
        digest.update([collection.tag()]);
        digest.update(
            u32::try_from(selectors.len())
                .expect("selector count fits u32")
                .to_be_bytes(),
        );
        for selector in selectors {
            match selector {
                Some(text) => {
                    digest.update([1]);
                    digest.update(
                        u32::try_from(text.len())
                            .expect("selector length fits u32")
                            .to_be_bytes(),
                    );
                    digest.update(text.as_bytes());
                }
                None => digest.update([0]),
            }
        }
        digest.update(DataspaceReadVisibility::all_for_tests().visible_route_set_digest());
        encode_explorer_cursor(collection, digest.finalize().into(), key).expect("oracle cursor")
    }
    /// Page two records one at a time under one selector combination and return the query
    /// that carries its continuation cursor. The cursor must equal the oracle for exactly
    /// `selectors` and must resume under the same combination.
    #[track_caller]
    fn issue_selector_bound_cursor(
        collection: ExplorerCursorCollection,
        selectors: &[Option<String>],
        expected: [&str; 2],
        page: impl Fn(&ExplorerCursorQuery) -> SelectorPage,
    ) -> ExplorerCursorQuery {
        let (listed, pagination) = page(&ExplorerCursorQuery {
            cursor: None,
            limit: 1,
        })
        .expect("first page");
        assert_eq!(listed, [expected[0]]);
        assert!(pagination.has_more);
        let cursor = pagination.next_cursor.expect("continuation cursor");
        assert_eq!(
            cursor,
            selector_cursor_oracle(collection, selectors, expected[0]),
            "the cursor must bind exactly these selectors in route order"
        );
        let resume = ExplorerCursorQuery {
            cursor: Some(cursor),
            limit: 1,
        };
        let (listed, pagination) = page(&resume).expect("resumed page");
        assert_eq!(listed, [expected[1]]);
        assert!(!pagination.has_more);
        assert!(pagination.next_cursor.is_none());
        resume
    }
    /// A cursor replayed under another selector combination is out of scope.
    #[track_caller]
    fn assert_out_of_selector_scope(page: SelectorPage) {
        assert_eq!(page.err(), Some(ExplorerCursorError::ScopeMismatch));
    }
    /// A World in which the selectors of the world collections match two records each.
    struct SelectorWorld {
        world: World,
        /// Owned by ALICE.
        alpha: DomainId,
        /// Owned by ALICE.
        beta: DomainId,
        /// Owned by BOB.
        gamma: DomainId,
        /// Owned by ALICE in `alpha`; held by ALICE and by BOB.
        coin: AssetDefinitionId,
        /// Owned by ALICE in `alpha`; held by ALICE and by BOB.
        gem: AssetDefinitionId,
    }
    /// The four balances of [`SelectorWorld`] in committed key order.
    fn selector_world_assets(fixture: &SelectorWorld) -> [AssetId; 4] {
        let mut assets = [
            AssetId::new(fixture.coin.clone(), ALICE_ID.clone()),
            AssetId::new(fixture.coin.clone(), BOB_ID.clone()),
            AssetId::new(fixture.gem.clone(), ALICE_ID.clone()),
            AssetId::new(fixture.gem.clone(), BOB_ID.clone()),
        ];
        assets.sort();
        assets
    }
    fn selector_world() -> SelectorWorld {
        let domain = |name: &str| DomainId::try_new(name, "universal").expect("fixture domain");
        let (alpha, beta, gamma) = (domain("alpha"), domain("beta"), domain("gamma"));
        let definition_id = |name: &str| {
            AssetDefinitionId::derive_from_components(
                alpha.clone(),
                name.parse().expect("fixture asset name"),
            )
        };
        let (coin, gem) = (definition_id("coin"), definition_id("gem"));
        let definition = |id: &AssetDefinitionId, name: &str| {
            AssetDefinition::numeric(
                id.clone(),
                name.to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                Some(alpha.clone()),
            )
            .build(&ALICE_ID)
        };
        let balance = |id: &AssetDefinitionId, holder: &AccountId, quantity: u32| {
            iroha_data_model::asset::Asset::new(
                AssetId::new(id.clone(), holder.clone()),
                Quantity::from(quantity),
            )
        };
        let nft = |id: &str, owner: &AccountId| {
            iroha_data_model::nft::Nft::new(id.parse().expect("fixture NFT"), Metadata::default())
                .build(owner)
        };
        let world = World::with_assets(
            [
                Domain::new(alpha.clone()).build(&ALICE_ID),
                Domain::new(beta.clone()).build(&ALICE_ID),
                Domain::new(gamma.clone()).build(&BOB_ID),
            ],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
            ],
            [definition(&coin, "coin"), definition(&gem, "gem")],
            [
                balance(&coin, &ALICE_ID, 5),
                balance(&coin, &BOB_ID, 7),
                balance(&gem, &ALICE_ID, 3),
                balance(&gem, &BOB_ID, 2),
            ],
            [
                nft("one$alpha.universal", &ALICE_ID),
                nft("two$alpha.universal", &ALICE_ID),
                nft("three$gamma.universal", &BOB_ID),
            ],
        );
        SelectorWorld {
            world,
            alpha,
            beta,
            gamma,
            coin,
            gem,
        }
    }
    #[test]
    fn accounts_page_binds_domain_and_definition_selectors_into_its_cursor() {
        let fixture = selector_world();
        let view = fixture.world.view();
        let all = DataspaceReadVisibility::all_for_tests();
        let page = |domain: Option<&DomainId>,
                    definition: Option<&AssetDefinitionId>,
                    query: &ExplorerCursorQuery|
         -> SelectorPage {
            accounts_page_for_filters(&view, domain, definition, &all, query, SELECTOR_PAGE_BUDGET)
                .map(|page| {
                    let listed = page.items.iter().map(|item| canonical_text(item.id));
                    (listed.collect(), page.pagination)
                })
        };
        let mut accounts = [ALICE_ID.clone(), BOB_ID.clone()];
        accounts.sort();
        let accounts = accounts.map(|account| canonical_text(&account));
        let expected = [accounts[0].as_str(), accounts[1].as_str()];

        // Both accounts hold `coin`.
        let by_definition = issue_selector_bound_cursor(
            ExplorerCursorCollection::Accounts,
            &[None, Some(canonical_text(&fixture.coin))],
            expected,
            |query| page(None, Some(&fixture.coin), query),
        );
        assert_out_of_selector_scope(page(None, Some(&fixture.gem), &by_definition));
        assert_out_of_selector_scope(page(None, None, &by_definition));
        assert_out_of_selector_scope(page(
            Some(&fixture.alpha),
            Some(&fixture.coin),
            &by_definition,
        ));

        let unfiltered = issue_selector_bound_cursor(
            ExplorerCursorCollection::Accounts,
            &[None, None],
            expected,
            |query| page(None, None, query),
        );
        assert_out_of_selector_scope(page(None, Some(&fixture.coin), &unfiltered));

        // The fixture binds no account to a domain, so a domain selector lists nothing and
        // issues no cursor. Replay the cursor the route would issue under it instead.
        let by_domain = ExplorerCursorQuery {
            cursor: Some(selector_cursor_oracle(
                ExplorerCursorCollection::Accounts,
                &[Some(canonical_text(&fixture.alpha)), None],
                expected[0],
            )),
            limit: 1,
        };
        let (listed, pagination) = page(Some(&fixture.alpha), None, &by_domain)
            .expect("the domain selector accepts its own cursor");
        assert!(listed.is_empty());
        assert!(!pagination.has_more);
        assert_out_of_selector_scope(page(Some(&fixture.beta), None, &by_domain));
        assert_out_of_selector_scope(page(None, None, &by_domain));
        assert_out_of_selector_scope(page(Some(&fixture.alpha), Some(&fixture.coin), &by_domain));
    }
    #[test]
    fn domains_page_binds_the_owner_selector_into_its_cursor() {
        let fixture = selector_world();
        let view = fixture.world.view();
        let all = DataspaceReadVisibility::all_for_tests();
        let page = |owner: Option<&AccountId>, query: &ExplorerCursorQuery| -> SelectorPage {
            domains_page_for_filters(&view, owner, &all, query, SELECTOR_PAGE_BUDGET).map(|page| {
                let listed = page.items.iter().map(|item| canonical_text(item.id));
                (listed.collect(), page.pagination)
            })
        };
        let mut owned = [fixture.alpha.clone(), fixture.beta.clone()];
        owned.sort();
        let owned = owned.map(|domain| canonical_text(&domain));

        let by_owner = issue_selector_bound_cursor(
            ExplorerCursorCollection::Domains,
            &[Some(canonical_text(&*ALICE_ID))],
            [owned[0].as_str(), owned[1].as_str()],
            |query| page(Some(&ALICE_ID), query),
        );
        assert_out_of_selector_scope(page(Some(&BOB_ID), &by_owner));
        assert_out_of_selector_scope(page(None, &by_owner));
    }
    #[test]
    fn asset_definitions_page_binds_domain_and_owner_selectors_into_its_cursor() {
        let fixture = selector_world();
        let view = fixture.world.view();
        let all = DataspaceReadVisibility::all_for_tests();
        let page = |domain: Option<&DomainId>,
                    owner: Option<&AccountId>,
                    query: &ExplorerCursorQuery|
         -> SelectorPage {
            asset_definitions_page_for_filters(
                &view,
                domain,
                owner,
                &all,
                query,
                SELECTOR_PAGE_BUDGET,
            )
            .map(|page| {
                let listed = page.items.iter().map(|item| canonical_text(item.id));
                (listed.collect(), page.pagination)
            })
        };
        let mut definitions = [fixture.coin.clone(), fixture.gem.clone()];
        definitions.sort();
        let definitions = definitions.map(|definition| canonical_text(&definition));
        let expected = [definitions[0].as_str(), definitions[1].as_str()];

        let by_domain = issue_selector_bound_cursor(
            ExplorerCursorCollection::AssetDefinitions,
            &[Some(canonical_text(&fixture.alpha)), None],
            expected,
            |query| page(Some(&fixture.alpha), None, query),
        );
        assert_out_of_selector_scope(page(Some(&fixture.gamma), None, &by_domain));
        assert_out_of_selector_scope(page(None, None, &by_domain));
        assert_out_of_selector_scope(page(Some(&fixture.alpha), Some(&ALICE_ID), &by_domain));

        let by_owner = issue_selector_bound_cursor(
            ExplorerCursorCollection::AssetDefinitions,
            &[None, Some(canonical_text(&*ALICE_ID))],
            expected,
            |query| page(None, Some(&ALICE_ID), query),
        );
        assert_out_of_selector_scope(page(None, Some(&BOB_ID), &by_owner));
        assert_out_of_selector_scope(page(None, None, &by_owner));
        assert_out_of_selector_scope(page(Some(&fixture.alpha), Some(&ALICE_ID), &by_owner));
    }
    #[test]
    fn assets_page_binds_owner_definition_and_asset_selectors_into_its_cursor() {
        let fixture = selector_world();
        let view = fixture.world.view();
        let all = DataspaceReadVisibility::all_for_tests();
        let page = |owner: Option<&AccountId>,
                    definition: Option<&AssetDefinitionId>,
                    asset: Option<&AssetId>,
                    query: &ExplorerCursorQuery|
         -> SelectorPage {
            assets_page_for_filters(
                &view,
                owner,
                definition,
                asset,
                &all,
                query,
                SELECTOR_PAGE_BUDGET,
            )
            .map(|page| {
                let listed = page.items.iter().map(|item| canonical_text(item.id));
                (listed.collect(), page.pagination)
            })
        };
        let assets = selector_world_assets(&fixture);
        let texts = |keep: &dyn Fn(&AssetId) -> bool| -> Vec<String> {
            let kept = assets.iter().filter(|asset| keep(asset));
            kept.map(canonical_text).collect()
        };

        let held_by_alice = texts(&|asset| asset.account() == &*ALICE_ID);
        let by_owner = issue_selector_bound_cursor(
            ExplorerCursorCollection::Assets,
            &[Some(canonical_text(&*ALICE_ID)), None, None],
            [held_by_alice[0].as_str(), held_by_alice[1].as_str()],
            |query| page(Some(&ALICE_ID), None, None, query),
        );
        assert_out_of_selector_scope(page(Some(&BOB_ID), None, None, &by_owner));
        assert_out_of_selector_scope(page(None, None, None, &by_owner));
        assert_out_of_selector_scope(page(Some(&ALICE_ID), Some(&fixture.coin), None, &by_owner));
        assert_out_of_selector_scope(page(Some(&ALICE_ID), None, Some(&assets[3]), &by_owner));

        let coins = texts(&|asset| asset.definition() == &fixture.coin);
        let by_definition = issue_selector_bound_cursor(
            ExplorerCursorCollection::Assets,
            &[None, Some(canonical_text(&fixture.coin)), None],
            [coins[0].as_str(), coins[1].as_str()],
            |query| page(None, Some(&fixture.coin), None, query),
        );
        assert_out_of_selector_scope(page(None, Some(&fixture.gem), None, &by_definition));
        assert_out_of_selector_scope(page(None, None, None, &by_definition));
        assert_out_of_selector_scope(page(
            Some(&ALICE_ID),
            Some(&fixture.coin),
            None,
            &by_definition,
        ));

        // An exact-asset selector lists at most one record and so issues no cursor. Replay
        // the cursor the route would issue under it after a preceding key instead.
        let (first, last) = (&assets[0], &assets[3]);
        let by_asset = ExplorerCursorQuery {
            cursor: Some(selector_cursor_oracle(
                ExplorerCursorCollection::Assets,
                &[None, None, Some(canonical_text(last))],
                &canonical_text(first),
            )),
            limit: 1,
        };
        let (listed, pagination) = page(None, None, Some(last), &by_asset)
            .expect("the asset selector accepts its own cursor");
        assert_eq!(listed, [canonical_text(last)]);
        assert!(!pagination.has_more);
        assert_out_of_selector_scope(page(None, None, Some(&assets[1]), &by_asset));
        assert_out_of_selector_scope(page(None, None, None, &by_asset));
        assert_out_of_selector_scope(page(None, Some(last.definition()), None, &by_asset));
    }
    #[test]
    fn nfts_page_binds_owner_and_domain_selectors_into_its_cursor() {
        let fixture = selector_world();
        let view = fixture.world.view();
        let all = DataspaceReadVisibility::all_for_tests();
        let page = |owner: Option<&AccountId>,
                    domain: Option<&DomainId>,
                    query: &ExplorerCursorQuery|
         -> SelectorPage {
            nfts_page_for_filters(&view, owner, domain, &all, query, SELECTOR_PAGE_BUDGET).map(
                |page| {
                    let listed = page.items.iter().map(|item| canonical_text(item.id));
                    (listed.collect(), page.pagination)
                },
            )
        };
        let mut nfts: [NftId; 2] = ["one$alpha.universal", "two$alpha.universal"]
            .map(|id| id.parse().expect("fixture NFT"));
        nfts.sort();
        let nfts = nfts.map(|nft| canonical_text(&nft));
        let expected = [nfts[0].as_str(), nfts[1].as_str()];

        let by_owner = issue_selector_bound_cursor(
            ExplorerCursorCollection::Nfts,
            &[Some(canonical_text(&*ALICE_ID)), None],
            expected,
            |query| page(Some(&ALICE_ID), None, query),
        );
        assert_out_of_selector_scope(page(Some(&BOB_ID), None, &by_owner));
        assert_out_of_selector_scope(page(None, None, &by_owner));
        assert_out_of_selector_scope(page(Some(&ALICE_ID), Some(&fixture.alpha), &by_owner));

        let by_domain = issue_selector_bound_cursor(
            ExplorerCursorCollection::Nfts,
            &[None, Some(canonical_text(&fixture.alpha))],
            expected,
            |query| page(None, Some(&fixture.alpha), query),
        );
        assert_out_of_selector_scope(page(None, Some(&fixture.gamma), &by_domain));
        assert_out_of_selector_scope(page(None, None, &by_domain));
        assert_out_of_selector_scope(page(Some(&ALICE_ID), Some(&fixture.alpha), &by_domain));
    }
    #[test]
    fn rwas_page_binds_owner_and_domain_selectors_into_its_cursor() {
        let SelectorWorld {
            world,
            alpha,
            gamma,
            ..
        } = selector_world();
        let state = iroha_core::state::State::new_with_pre_genesis_nexus_for_testing(
            world,
            iroha_config::parameters::actual::Nexus::default(),
            iroha_core::query::store::LiveQueryStore::start_test(),
        );
        register_rwa_lots_for_tests(
            &state,
            &[
                (&alpha, &ALICE_ID, 7),
                (&alpha, &ALICE_ID, 9),
                (&gamma, &BOB_ID, 5),
            ],
        );
        let view = state.world_view();
        let all = DataspaceReadVisibility::all_for_tests();
        let page = |owner: Option<&AccountId>,
                    domain: Option<&DomainId>,
                    query: &ExplorerCursorQuery|
         -> SelectorPage {
            rwas_page_for_filters(&view, owner, domain, &all, query, SELECTOR_PAGE_BUDGET).map(
                |page| {
                    let listed = page.items.iter().map(|item| item.id.0.to_string());
                    (listed.collect(), page.pagination)
                },
            )
        };
        // `RegisterRwa` generates the identifiers: read ALICE's two `alpha` lots back from
        // the primary table, which iterates in key order.
        let lots: Vec<String> = view
            .rwas_iter()
            .filter(|lot| lot.value().owned_by == *ALICE_ID && lot.id().domain() == &alpha)
            .map(|lot| lot.id().to_string())
            .collect();
        assert_eq!(lots.len(), 2);
        assert_eq!(view.rwas_iter().count(), 3);
        let expected = [lots[0].as_str(), lots[1].as_str()];

        let by_owner = issue_selector_bound_cursor(
            ExplorerCursorCollection::Rwas,
            &[Some(canonical_text(&*ALICE_ID)), None],
            expected,
            |query| page(Some(&ALICE_ID), None, query),
        );
        assert_out_of_selector_scope(page(Some(&BOB_ID), None, &by_owner));
        assert_out_of_selector_scope(page(None, None, &by_owner));
        assert_out_of_selector_scope(page(Some(&ALICE_ID), Some(&alpha), &by_owner));

        let by_domain = issue_selector_bound_cursor(
            ExplorerCursorCollection::Rwas,
            &[None, Some(canonical_text(&alpha))],
            expected,
            |query| page(None, Some(&alpha), query),
        );
        assert_out_of_selector_scope(page(None, Some(&gamma), &by_domain));
        assert_out_of_selector_scope(page(None, None, &by_domain));
        assert_out_of_selector_scope(page(Some(&ALICE_ID), Some(&alpha), &by_domain));
    }
    #[test]
    fn explorer_selection_admits_exact_layout_before_projecting() {
        let projected = std::cell::Cell::new(0);
        let bytes = 2 * std::mem::size_of::<u32>();
        let select = |budget| {
            collect_explorer_cursor_page(
                0_u32..3,
                2,
                budget,
                |candidate| *candidate,
                |_| true,
                |_| true,
                |candidate| {
                    projected.set(projected.get() + 1);
                    Ok(candidate)
                },
            )
        };
        assert_eq!(
            select(bytes - 1).unwrap_err(),
            ExplorerCursorError::ByteLimitExceeded
        );
        assert_eq!(projected.get(), 0);
        let (page, usage) = norito::core::with_decode_limits_measured(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 32),
            || select(bytes),
        );
        let page = page.unwrap();
        assert_eq!(page.items, [0, 1]);
        assert_eq!(page.items.capacity(), 2);
        assert_eq!(usage.total_allocated_bytes(), bytes);
    }
    #[test]
    fn block_dto_counts_rejections() {
        let tx = TransactionBuilder::new(
            test_network_id(),
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(iter::empty::<iroha_data_model::isi::InstructionBox>())
        .sign(ALICE_KEYPAIR.private_key());
        let header = BlockHeader::new(nonzero!(3_u64), None, None, 1_700_000_000_000, 0);
        let mut builder = BlockBuilder::new(header);
        builder.push_transaction(tx);
        let mut block = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
        crate::test_utils::attach_fixture_execution_outputs(
            &mut block,
            vec![
                iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                    iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                        input_index: 0,
                        result: iroha_data_model::transaction::TransactionResult::new(Err(
                            TransactionRejectionReason::Validation(ValidationFail::InternalError(
                                "boom".to_string(),
                            )),
                        )),
                        completions: vec![],
                    },
                ),
            ],
        );
        let dto = crate::explorer_history::HistoryBlockRow::from_block(&block, |_| true);
        assert_eq!(dto.height, 3);
        assert_eq!(dto.transactions_total, 1);
        assert_eq!(dto.transactions_rejected, 1);
        assert_eq!(
            json::to_value(&dto.created_at).unwrap().as_str(),
            Some("2023-11-14T22:13:20Z")
        );
        assert!(dto.transactions_hash.is_some());
    }
    #[test]
    fn block_dto_from_hash_only_reports_verified_hash_fields() {
        let prev_hash = HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x11; iroha_crypto::Hash::LENGTH]),
        );
        let hash = HashOf::<BlockHeader>::from_untyped_unchecked(iroha_crypto::Hash::prehashed(
            [0x22; iroha_crypto::Hash::LENGTH],
        ));
        let dto =
            crate::explorer_history::HistoryBlockRow::from_hash_only(2, hash, Some(prev_hash));
        assert_eq!(dto.height, 2);
        assert_eq!(dto.hash, hash);
        assert_eq!(dto.prev_block_hash, Some(prev_hash));
        assert_eq!(json::to_value(&dto.created_at).unwrap().as_str(), Some(""));
        assert_eq!(dto.transactions_hash, None);
        assert_eq!(dto.transactions_rejected, 0);
        assert_eq!(dto.transactions_total, 0);
    }
    #[test]
    fn block_dto_counts_sealed_commitment_entrypoints() {
        let network_id = test_network_id();
        let tx = TransactionBuilder::new(
            network_id,
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .sign(ALICE_KEYPAIR.private_key());
        let reveal_deadline_height = 5;
        let commitment =
            iroha_data_model::transaction::signed::compute_sealed_transaction_commitment(
                &network_id,
                &tx,
                [0x41; 32],
                reveal_deadline_height,
            );
        let payload = iroha_data_model::transaction::signed::SealedTransactionCommitmentPayload {
            network_id,
            authority: ALICE_ID.clone(),
            commitment,
            reveal_after_height: 2,
            reveal_deadline_height,
            nonce: None,
        };
        let sealed_commitment =
            iroha_data_model::transaction::signed::SignedSealedTransactionCommitment::sign(
                payload,
                ALICE_KEYPAIR.private_key(),
            );
        let header = BlockHeader::new(nonzero!(4_u64), None, None, 1_700_000_001_000, 0);
        let mut builder = BlockBuilder::new(header);
        builder.push_sealed_transaction_commitment(sealed_commitment);
        let mut block = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
        crate::test_utils::attach_fixture_execution_outputs(
            &mut block,
            vec![
                iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                    iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                        input_index: 0,
                        result: iroha_data_model::transaction::TransactionResult::new(Err(
                            TransactionRejectionReason::Validation(ValidationFail::InternalError(
                                "boom".to_string(),
                            )),
                        )),
                        completions: vec![],
                    },
                ),
            ],
        );
        let dto = crate::explorer_history::HistoryBlockRow::from_block(&block, |_| true);
        assert_eq!(dto.height, 4);
        assert_eq!(dto.transactions_total, 1);
        assert_eq!(dto.transactions_rejected, 1);
        assert!(dto.transactions_hash.is_some());
    }
    #[test]
    fn timestamp_format_handles_epoch() {
        let formatted = block_created_at(Duration::from_millis(0));
        assert_eq!(formatted, "1970-01-01T00:00:00Z");
    }
    #[test]
    fn network_metrics_json_serializes_valid_timestamp_once() {
        let timestamp = "2026-02-16T17:14:37.843Z";
        let mut dto = ExplorerNetworkMetricsDto {
            peers: 4,
            domains: 8,
            accounts: 258,
            assets: 17,
            transactions_accepted: 405,
            transactions_rejected: 61,
            block: 422,
            block_created_at: Some(crate::explorer_history::HistoryTime(Duration::from_millis(
                1771262077843,
            ))),
            finalized_block: 422,
            avg_commit_time: Some(ExplorerDurationDto { ms: 302 }),
            avg_block_time: Some(ExplorerDurationDto { ms: 877_364 }),
        };
        let bytes = norito::json::to_json_bounded_boxed(&dto, 4096)
            .expect("metrics dto should serialize within its finite response");
        let encoded = std::str::from_utf8(&bytes).expect("metrics payload should be utf-8");
        let payload = norito::json::from_str::<Value>(&encoded)
            .expect("serialized metrics json must be parseable");
        assert_eq!(payload["block_created_at"].as_str(), Some(timestamp));
        assert_eq!(
            encoded.matches(timestamp).count(),
            1,
            "timestamp should appear exactly once in serialized payload"
        );
        assert!(norito::json::to_json_bounded_boxed(&dto, encoded.len() - 1).is_err());
        dto.block_created_at = None;
        let payload = norito::json::to_value(&dto).expect("metrics without a finalized block");
        assert!(payload["block_created_at"].is_null());
    }
    include!("explorer_history_projection_tests.rs");
    #[test]
    fn instruction_kind_classifies_register_and_transfer() {
        let register = Register::domain(iroha_data_model::domain::Domain::new(
            DomainId::try_new("test", "universal").expect("domain id"),
        ));
        let register_box: InstructionBox = register.into();
        assert_eq!(
            instruction_kind(&register_box),
            ExplorerInstructionKind::Register
        );
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let direct_registration: InstructionBox =
            iroha_data_model::isi::RegisterDataspaceAssetDefinition::new(
                DataSpaceId::new(7),
                AssetDefinition::numeric(
                    asset_def.clone(),
                    "Rose",
                    iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                    None,
                ),
            )
            .expect("valid direct registration")
            .into();
        assert_eq!(
            instruction_kind(&direct_registration),
            ExplorerInstructionKind::Register
        );
        let asset_id = AssetId::new(asset_def.clone(), ALICE_ID.clone());
        let transfer = Transfer::asset_quantity(asset_id, 1u32, BOB_ID.clone());
        let transfer_box: InstructionBox = transfer.into();
        assert_eq!(
            instruction_kind(&transfer_box),
            ExplorerInstructionKind::Transfer
        );
    }
}
