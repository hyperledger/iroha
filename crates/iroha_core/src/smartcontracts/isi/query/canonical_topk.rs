//! Bounded canonical top-K materialization for server-owned query fanout.
use iroha_data_model::{
    prelude::Pagination,
    query::{QueryOutputBatchBox, error::QueryExecutionFail as Error},
};
use norito::core::NoritoSerialize;
use std::{collections::BTreeSet, io::Cursor};
/// Conservative deterministic charge for the retained `Vec` handle, one
/// `BTreeSet` slot, allocator bookkeeping, and tree-node slack of one item.
///
/// Canonical frame bytes are charged separately. This deliberately exceeds
/// the current standard-library layout so the configured retained-byte limit
/// remains an upper envelope instead of tracking payload buffers alone.
pub const CANONICAL_QUERY_RETAINED_ITEM_OVERHEAD_BYTES: u64 = 512;
/// Conservative deterministic allocator-bookkeeping charge for the final
/// output column. Its backing allocation is charged separately from the exact
/// per-arm inline item size and is reserved at its final capacity up front.
pub const CANONICAL_QUERY_OUTPUT_CONTAINER_OVERHEAD_BYTES: u64 = 512;
/// Resident upper envelope for one source row admitted by canonical fanout.
///
/// The first-release fanout sources yield name-backed `RoleId` or `TriggerId`
/// values. Names are limited to 255 bytes; this allowance also covers their
/// fixed Rust wrappers and allocator bookkeeping.
pub const CANONICAL_QUERY_PREBOUNDED_SOURCE_BYTES: u64 = 1024;
/// Deterministic fixed allowance for reconstructing one admitted identifier.
///
/// This covers the one-element sequence plan and output slot, short-value padding in the legacy
/// archived-field adapters, allocator metadata, and the fixed Rust wrappers. Variable frame,
/// identifier, and name buffers are charged separately from their exact lengths.
const CANONICAL_QUERY_ID_DECODE_FIXED_OVERHEAD_BYTES: u64 = 512;
/// Resource ceilings for canonical query output produced by a server-owned ephemeral fanout lane.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CanonicalQueryOutputLimits {
    max_items: u64,
    max_source_item_bytes: u64,
    max_encoded_item_bytes: u64,
    max_retained_bytes: u64,
    max_decode_allocated_bytes: u64,
}
impl CanonicalQueryOutputLimits {
    /// Construct exact canonical-output ceilings.
    #[must_use]
    pub const fn new(
        max_items: u64,
        max_source_item_bytes: u64,
        max_encoded_item_bytes: u64,
        max_retained_bytes: u64,
        max_decode_allocated_bytes: u64,
    ) -> Self {
        Self {
            max_items,
            max_source_item_bytes,
            max_encoded_item_bytes,
            max_retained_bytes,
            max_decode_allocated_bytes,
        }
    }
    /// Maximum number of unique canonical candidates retained.
    #[must_use]
    pub const fn max_items(self) -> u64 {
        self.max_items
    }
    /// Maximum resident bytes admitted for one prebounded local source row.
    #[must_use]
    pub const fn max_source_item_bytes(self) -> u64 {
        self.max_source_item_bytes
    }
    /// Maximum canonical frame size of one projected item.
    #[must_use]
    pub const fn max_encoded_item_bytes(self) -> u64 {
        self.max_encoded_item_bytes
    }
    /// Maximum total bytes retained by the canonical top-K set.
    #[must_use]
    pub const fn max_retained_bytes(self) -> u64 {
        self.max_retained_bytes
    }
    /// Maximum cumulative allocation reserved while reconstructing the final page.
    #[must_use]
    pub const fn max_decode_allocated_bytes(self) -> u64 {
        self.max_decode_allocated_bytes
    }
}
/// A deterministic, byte-bounded accumulator for projected query rows.
///
/// Each row is retained as the canonical framed encoding of a one-row
/// [`QueryOutputBatchBox`]. Framing preserves the exact enum discriminant,
/// while a [`BTreeSet`] supplies deterministic ordering and deduplication.
#[derive(Debug)]
pub struct CanonicalQueryOutputAccumulator {
    keep: u64,
    max_encoded_item_bytes: u64,
    max_retained_bytes: u64,
    max_decode_allocated_bytes: u64,
    retained_bytes: u64,
    prototype: Option<QueryOutputBatchBox>,
    items: BTreeSet<Vec<u8>>,
}
impl CanonicalQueryOutputAccumulator {
    /// Construct an empty accumulator with exact item, transient-frame,
    /// retained-byte, and reconstruction-allocation ceilings.
    #[must_use]
    pub fn new(
        keep: u64,
        max_encoded_item_bytes: u64,
        max_retained_bytes: u64,
        max_decode_allocated_bytes: u64,
    ) -> Self {
        Self {
            keep,
            max_encoded_item_bytes,
            max_retained_bytes,
            max_decode_allocated_bytes,
            retained_bytes: 0,
            prototype: None,
            items: BTreeSet::new(),
        }
    }
    /// Admit every row in one projected output column.
    ///
    /// The first canonical-fanout release admits only `RoleId` and `TriggerId` columns. Their
    /// name-backed rows and serializers are protocol-bounded before this method performs exact
    /// sizing. Every other variant fails closed before inspecting or serializing a candidate.
    ///
    /// Empty batches pin the expected variant. Every later batch must have the
    /// exact same discriminant. Multi-row batches are split into canonical
    /// one-row frames before deduplication.
    ///
    /// # Errors
    /// Returns [`Error::Conversion`] for a variant mismatch or codec failure,
    /// [`Error::GasBudgetExceeded`] when one candidate exceeds its transient frame ceiling, or
    /// [`Error::CapacityLimit`] when the retained top-K set cannot fit its byte ceiling.
    pub fn push_batch(&mut self, batch: QueryOutputBatchBox) -> Result<(), Error> {
        if !matches!(
            &batch,
            QueryOutputBatchBox::RoleId(_) | QueryOutputBatchBox::TriggerId(_)
        ) {
            return Err(Error::Conversion(
                "canonical fanout accepts only prebounded RoleId or TriggerId output".to_owned(),
            ));
        }
        self.push_batch_admitted(batch)
    }
    fn push_batch_admitted(&mut self, batch: QueryOutputBatchBox) -> Result<(), Error> {
        self.pin_variant(&batch)?;
        macro_rules! push_rows {
            ($variant:ident, $values:ident) => {
                for value in $values {
                    self.push_one(QueryOutputBatchBox::$variant(vec![value]))?;
                }
            };
        }
        match batch {
            QueryOutputBatchBox::PublicKey(values) => push_rows!(PublicKey, values),
            QueryOutputBatchBox::String(values) => push_rows!(String, values),
            QueryOutputBatchBox::Metadata(values) => push_rows!(Metadata, values),
            QueryOutputBatchBox::Json(values) => push_rows!(Json, values),
            QueryOutputBatchBox::Numeric(values) => push_rows!(Numeric, values),
            QueryOutputBatchBox::Name(values) => push_rows!(Name, values),
            QueryOutputBatchBox::DomainId(values) => push_rows!(DomainId, values),
            QueryOutputBatchBox::Domain(values) => push_rows!(Domain, values),
            QueryOutputBatchBox::AccountId(values) => push_rows!(AccountId, values),
            QueryOutputBatchBox::Account(values) => push_rows!(Account, values),
            QueryOutputBatchBox::AssetId(values) => push_rows!(AssetId, values),
            QueryOutputBatchBox::Asset(values) => push_rows!(Asset, values),
            QueryOutputBatchBox::AssetDefinitionId(values) => {
                push_rows!(AssetDefinitionId, values);
            }
            QueryOutputBatchBox::AssetDefinition(values) => {
                push_rows!(AssetDefinition, values);
            }
            QueryOutputBatchBox::RepoAgreement(values) => push_rows!(RepoAgreement, values),
            QueryOutputBatchBox::NftId(values) => push_rows!(NftId, values),
            QueryOutputBatchBox::Nft(values) => push_rows!(Nft, values),
            QueryOutputBatchBox::RwaId(values) => push_rows!(RwaId, values),
            QueryOutputBatchBox::Rwa(values) => push_rows!(Rwa, values),
            QueryOutputBatchBox::Role(values) => push_rows!(Role, values),
            QueryOutputBatchBox::Parameter(values) => push_rows!(Parameter, values),
            QueryOutputBatchBox::Permission(values) => push_rows!(Permission, values),
            QueryOutputBatchBox::CommittedTransaction(values) => {
                push_rows!(CommittedTransaction, values);
            }
            QueryOutputBatchBox::TransactionResult(values) => {
                push_rows!(TransactionResult, values);
            }
            QueryOutputBatchBox::TransactionResultHash(values) => {
                push_rows!(TransactionResultHash, values);
            }
            QueryOutputBatchBox::TransactionEntrypoint(values) => {
                push_rows!(TransactionEntrypoint, values);
            }
            QueryOutputBatchBox::TransactionEntrypointHash(values) => {
                push_rows!(TransactionEntrypointHash, values);
            }
            QueryOutputBatchBox::Peer(values) => push_rows!(Peer, values),
            QueryOutputBatchBox::RoleId(values) => push_rows!(RoleId, values),
            QueryOutputBatchBox::TriggerId(values) => push_rows!(TriggerId, values),
            QueryOutputBatchBox::Trigger(values) => push_rows!(Trigger, values),
            QueryOutputBatchBox::Action(values) => push_rows!(Action, values),
            QueryOutputBatchBox::Block(values) => push_rows!(Block, values),
            QueryOutputBatchBox::BlockHeader(values) => push_rows!(BlockHeader, values),
            QueryOutputBatchBox::BlockHeaderHash(values) => {
                push_rows!(BlockHeaderHash, values);
            }
            QueryOutputBatchBox::ProofRecord(values) => push_rows!(ProofRecord, values),
            QueryOutputBatchBox::OracleFeedConfig(values) => {
                push_rows!(OracleFeedConfig, values);
            }
            QueryOutputBatchBox::OracleFeedEventRecord(values) => {
                push_rows!(OracleFeedEventRecord, values);
            }
            QueryOutputBatchBox::OracleProviderStatsRecord(values) => {
                push_rows!(OracleProviderStatsRecord, values);
            }
            QueryOutputBatchBox::OracleDispute(values) => push_rows!(OracleDispute, values),
            QueryOutputBatchBox::OracleChangeProposal(values) => {
                push_rows!(OracleChangeProposal, values);
            }
            QueryOutputBatchBox::TwitterBindingRecord(values) => {
                push_rows!(TwitterBindingRecord, values);
            }
            QueryOutputBatchBox::DefiOracleAttestation(values) => {
                push_rows!(DefiOracleAttestation, values);
            }
            QueryOutputBatchBox::AssetEscrowRecord(values) => {
                push_rows!(AssetEscrowRecord, values);
            }
            QueryOutputBatchBox::FeeSponsorProgram(values) => {
                push_rows!(FeeSponsorProgram, values);
            }
            QueryOutputBatchBox::FeeSponsorProgramId(values) => {
                push_rows!(FeeSponsorProgramId, values);
            }
            QueryOutputBatchBox::BondRecord(values) => {
                push_rows!(BondRecord, values);
            }
        }
        Ok(())
    }
    /// Reconstruct the retained canonical page in byte order.
    ///
    /// Pagination is applied only after all routes or source rows have been admitted. Each selected
    /// frame is decoded under the configured explicit allocation ceiling and rechecked for one row
    /// and the pinned variant. Reconstruction consumes set entries progressively; its peak is
    /// bounded by the retained-byte envelope plus the decode/output allocation envelope.
    /// The final per-arm output `Vec` is charged from `size_of::<Item>()` and
    /// reserved at the exact selected count only after aggregate admission, so
    /// geometric growth and old/new backing-allocation overlap are impossible.
    ///
    /// # Errors
    /// Returns an error for missing type information, pagination wider than
    /// the retained prefix, a bounded-decode failure, or a variant mismatch.
    pub fn finish(self, pagination: Pagination) -> Result<QueryOutputBatchBox, Error> {
        let required = match pagination.limit_value() {
            Some(limit) => pagination
                .offset_value()
                .checked_add(limit.get())
                .ok_or(Error::CapacityLimit)?,
            None => self.keep,
        };
        if required > self.keep {
            return Err(Error::CapacityLimit);
        }
        let Some(prototype) = self.prototype else {
            return Err(Error::Conversion(
                "canonical query output has no pinned batch variant".to_owned(),
            ));
        };
        let skip = usize::try_from(pagination.offset_value()).unwrap_or(usize::MAX);
        let take = pagination.limit_value().map_or(usize::MAX, |limit| {
            usize::try_from(limit.get()).unwrap_or(usize::MAX)
        });
        let selected_count = self.items.len().saturating_sub(skip).min(take);
        let output_container_allocation =
            output_container_allocation_charge(&prototype, selected_count)?;
        let required_decode_allocation = self.items.iter().skip(skip).take(take).try_fold(
            output_container_allocation,
            |total, bytes| {
                let profile = candidate_decode_profile(&prototype, bytes)?;
                total
                    .checked_add(profile.allocation_charge)
                    .ok_or(Error::CapacityLimit)
            },
        )?;
        if required_decode_allocation > self.max_decode_allocated_bytes {
            return Err(Error::CapacityLimit);
        }
        let (mut output, allocated_container_charge) =
            empty_batch_with_capacity_like(&prototype, selected_count)?;
        debug_assert_eq!(allocated_container_charge, output_container_allocation);
        for bytes in self.items.into_iter().skip(skip).take(take) {
            let profile = candidate_decode_profile(&prototype, &bytes)?;
            let decoded = decode_candidate(&bytes, profile.limits)?;
            if decoded.len() != 1
                || core::mem::discriminant(&decoded) != core::mem::discriminant(&output)
            {
                return Err(Error::Conversion(
                    "canonical query item changed its pinned batch variant".to_owned(),
                ));
            }
            output.extend(decoded).map_err(|_| {
                Error::Conversion("canonical query item has a mismatched batch variant".to_owned())
            })?;
        }
        Ok(output)
    }
    fn pin_variant(&mut self, batch: &QueryOutputBatchBox) -> Result<(), Error> {
        if let Some(prototype) = &self.prototype {
            if core::mem::discriminant(prototype) != core::mem::discriminant(batch) {
                return Err(Error::Conversion(
                    "canonical query output batches have different variants".to_owned(),
                ));
            }
            return Ok(());
        }
        self.prototype = Some(empty_batch_like(batch));
        Ok(())
    }
    fn push_one(&mut self, candidate: QueryOutputBatchBox) -> Result<(), Error> {
        let encoded_len = exact_canonical_frame_len(&candidate, self.max_encoded_item_bytes)?;
        if self.keep == 0 {
            return Ok(());
        }
        // Prove the temporary candidate allocation cannot overflow and is
        // bounded independently of the retained set before allocating it.
        let candidate_charge =
            canonical_query_candidate_allocation_bytes(encoded_len).ok_or(Error::CapacityLimit)?;
        let transient_limit = self
            .max_retained_bytes
            .checked_add(
                canonical_query_candidate_allocation_bytes(self.max_encoded_item_bytes)
                    .ok_or(Error::CapacityLimit)?,
            )
            .ok_or(Error::CapacityLimit)?;
        if self
            .retained_bytes
            .checked_add(candidate_charge)
            .is_none_or(|bytes| bytes > transient_limit)
        {
            return Err(Error::CapacityLimit);
        }
        let bytes = encode_canonical_preflighted(&candidate, encoded_len)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != encoded_len {
            return Err(Error::Conversion(
                "canonical query item length changed after preflight".to_owned(),
            ));
        }
        if self.items.contains(&bytes) {
            return Ok(());
        }
        let full = u64::try_from(self.items.len()).unwrap_or(u64::MAX) >= self.keep;
        if full
            && self
                .items
                .last()
                .is_some_and(|worst| bytes.as_slice() >= worst.as_slice())
        {
            return Ok(());
        }
        let removed_len = if full {
            self.items.last().map_or(0, |worst| {
                canonical_query_candidate_allocation_bytes(
                    u64::try_from(worst.len()).unwrap_or(u64::MAX),
                )
                .unwrap_or(u64::MAX)
            })
        } else {
            0
        };
        let next_retained = self
            .retained_bytes
            .checked_sub(removed_len)
            .and_then(|bytes| bytes.checked_add(candidate_charge))
            .filter(|bytes| *bytes <= self.max_retained_bytes)
            .ok_or(Error::CapacityLimit)?;
        if full {
            let _ = self.items.pop_last();
        }
        let inserted = self.items.insert(bytes);
        debug_assert!(inserted, "duplicates were checked before insertion");
        self.retained_bytes = next_retained;
        Ok(())
    }
}
fn exact_canonical_frame_len<T: NoritoSerialize>(value: &T, limit: u64) -> Result<u64, Error> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    // Reject from the allocation-free derive path before the verifying
    // serialization pass can create scratch for any owned nested field.
    let payload_len = value.encoded_len_exact().ok_or_else(|| {
        Error::Conversion(
            "canonical query item has no allocation-free exact encoded length".to_owned(),
        )
    })?;
    let align = norito::core::archived_payload_align::<T>();
    let padding = if align <= 1 {
        0
    } else {
        let remainder = norito::core::Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    };
    let preflight_len = norito::core::Header::SIZE
        .checked_add(padding)
        .and_then(|framing| framing.checked_add(payload_len))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(Error::CapacityLimit)?;
    if preflight_len > limit {
        return Err(Error::GasBudgetExceeded);
    }
    let encoded_len = norito::core::encoded_frame_len(value).map_err(|error| {
        Error::Conversion(format!("failed to measure canonical query item: {error}"))
    })?;
    let encoded_len = u64::try_from(encoded_len).map_err(|_| Error::CapacityLimit)?;
    if encoded_len != preflight_len {
        return Err(Error::Conversion(
            "canonical query item exact length changed during verification".to_owned(),
        ));
    }
    Ok(encoded_len)
}
fn canonical_frame_buffer_bytes(encoded_len: u64) -> Result<u64, Error> {
    const MIN_DIRECT_PAYLOAD_CAPACITY: u64 = 1024;
    let header = u64::try_from(norito::core::Header::SIZE).map_err(|_| Error::CapacityLimit)?;
    let align = norito::core::archived_payload_align::<QueryOutputBatchBox>();
    let padding = if align <= 1 {
        0
    } else {
        let remainder = norito::core::Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    };
    let headroom = header
        .checked_add(u64::try_from(padding).map_err(|_| Error::CapacityLimit)?)
        .ok_or(Error::CapacityLimit)?;
    Ok(encoded_len.max(
        headroom
            .checked_add(MIN_DIRECT_PAYLOAD_CAPACITY)
            .ok_or(Error::CapacityLimit)?,
    ))
}
/// Return the complete resident allocation charge for one canonical candidate.
///
/// The charge includes the canonical frame buffer's real reserved capacity as
/// well as the retained `BTreeSet` node, `Vec` handle, and allocator overhead.
/// It deliberately excludes the source row and final reconstruction column,
/// which have separate phases and limits. `None` reports arithmetic overflow.
#[must_use]
pub fn canonical_query_candidate_allocation_bytes(encoded_frame_bytes: u64) -> Option<u64> {
    canonical_frame_buffer_bytes(encoded_frame_bytes)
        .ok()?
        .checked_add(CANONICAL_QUERY_RETAINED_ITEM_OVERHEAD_BYTES)
}
fn encode_canonical_preflighted(
    value: &QueryOutputBatchBox,
    encoded_len: u64,
) -> Result<Vec<u8>, Error> {
    let capacity = usize::try_from(canonical_frame_buffer_bytes(encoded_len)?)
        .map_err(|_| Error::CapacityLimit)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::CapacityLimit)?;
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::to_bytes_in(value, &mut bytes).map_err(|error| {
        Error::Conversion(format!("failed to encode canonical query item: {error}"))
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != encoded_len {
        return Err(Error::Conversion(
            "canonical query item length changed after preflight".to_owned(),
        ));
    }
    Ok(bytes)
}
fn empty_batch_like(batch: &QueryOutputBatchBox) -> QueryOutputBatchBox {
    macro_rules! empty_arms {
        ($($variant:ident),+ $(,)?) => {
            match batch {
                $(QueryOutputBatchBox::$variant(_) => QueryOutputBatchBox::$variant(Vec::new()),)+
            }
        };
    }
    empty_arms!(
        PublicKey,
        String,
        Metadata,
        Json,
        Numeric,
        Name,
        DomainId,
        Domain,
        AccountId,
        Account,
        AssetId,
        Asset,
        AssetDefinitionId,
        AssetDefinition,
        RepoAgreement,
        NftId,
        Nft,
        RwaId,
        Rwa,
        Role,
        Parameter,
        Permission,
        CommittedTransaction,
        TransactionResult,
        TransactionResultHash,
        TransactionEntrypoint,
        TransactionEntrypointHash,
        Peer,
        RoleId,
        TriggerId,
        Trigger,
        Action,
        Block,
        BlockHeader,
        BlockHeaderHash,
        ProofRecord,
        OracleFeedConfig,
        OracleFeedEventRecord,
        OracleProviderStatsRecord,
        OracleDispute,
        OracleChangeProposal,
        TwitterBindingRecord,
        DefiOracleAttestation,
        AssetEscrowRecord,
        FeeSponsorProgram,
        FeeSponsorProgramId,
        BondRecord,
    )
}
fn empty_batch_with_capacity_like(
    batch: &QueryOutputBatchBox,
    capacity: usize,
) -> Result<(QueryOutputBatchBox, u64), Error> {
    fn column<T>(_prototype: &[T], capacity: usize) -> Result<Vec<T>, Error> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| Error::CapacityLimit)?;
        Ok(values)
    }
    let charge = output_container_allocation_charge(batch, capacity)?;
    macro_rules! capacity_arms {
        ($($variant:ident),+ $(,)?) => {
            match batch {
                $(
                    QueryOutputBatchBox::$variant(values) => {
                        let values = column(values, capacity)?;
                        Ok((QueryOutputBatchBox::$variant(values), charge))
                    }
                )+
            }
        };
    }
    capacity_arms!(
        PublicKey,
        String,
        Metadata,
        Json,
        Numeric,
        Name,
        DomainId,
        Domain,
        AccountId,
        Account,
        AssetId,
        Asset,
        AssetDefinitionId,
        AssetDefinition,
        RepoAgreement,
        NftId,
        Nft,
        RwaId,
        Rwa,
        Role,
        Parameter,
        Permission,
        CommittedTransaction,
        TransactionResult,
        TransactionResultHash,
        TransactionEntrypoint,
        TransactionEntrypointHash,
        Peer,
        RoleId,
        TriggerId,
        Trigger,
        Action,
        Block,
        BlockHeader,
        BlockHeaderHash,
        ProofRecord,
        OracleFeedConfig,
        OracleFeedEventRecord,
        OracleProviderStatsRecord,
        OracleDispute,
        OracleChangeProposal,
        TwitterBindingRecord,
        DefiOracleAttestation,
        AssetEscrowRecord,
        FeeSponsorProgram,
        FeeSponsorProgramId,
        BondRecord,
    )
}
fn output_container_allocation_charge(
    batch: &QueryOutputBatchBox,
    capacity: usize,
) -> Result<u64, Error> {
    fn column<T>(_prototype: &[T], capacity: usize) -> Result<u64, Error> {
        let inline_bytes = core::mem::size_of::<T>()
            .checked_mul(capacity)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(Error::CapacityLimit)?;
        if capacity == 0 {
            Ok(0)
        } else {
            inline_bytes
                .checked_add(CANONICAL_QUERY_OUTPUT_CONTAINER_OVERHEAD_BYTES)
                .ok_or(Error::CapacityLimit)
        }
    }
    macro_rules! charge_arms {
        ($($variant:ident),+ $(,)?) => {
            match batch {
                $(QueryOutputBatchBox::$variant(values) => column(values, capacity),)+
            }
        };
    }
    charge_arms!(
        PublicKey,
        String,
        Metadata,
        Json,
        Numeric,
        Name,
        DomainId,
        Domain,
        AccountId,
        Account,
        AssetId,
        Asset,
        AssetDefinitionId,
        AssetDefinition,
        RepoAgreement,
        NftId,
        Nft,
        RwaId,
        Rwa,
        Role,
        Parameter,
        Permission,
        CommittedTransaction,
        TransactionResult,
        TransactionResultHash,
        TransactionEntrypoint,
        TransactionEntrypointHash,
        Peer,
        RoleId,
        TriggerId,
        Trigger,
        Action,
        Block,
        BlockHeader,
        BlockHeaderHash,
        ProofRecord,
        OracleFeedConfig,
        OracleFeedEventRecord,
        OracleProviderStatsRecord,
        OracleDispute,
        OracleChangeProposal,
        TwitterBindingRecord,
        DefiOracleAttestation,
        AssetEscrowRecord,
        FeeSponsorProgram,
        FeeSponsorProgramId,
        BondRecord,
    )
}
fn decode_candidate(
    bytes: &[u8],
    limits: norito::DecodeLimits,
) -> Result<QueryOutputBatchBox, Error> {
    // Every frame in the set was produced locally by
    // `encode_canonical_preflighted`; bounded reconstruction therefore does
    // not need canonical decode's allocate-and-reencode verification pass.
    norito::decode_from_bytes_with_limits(bytes, limits).map_err(|error| {
        Error::Conversion(format!(
            "failed to reconstruct bounded canonical query item: {error}"
        ))
    })
}
#[derive(Debug, Clone, Copy)]
struct CandidateDecodeProfile {
    limits: norito::DecodeLimits,
    allocation_charge: u64,
}
fn candidate_decode_profile(
    prototype: &QueryOutputBatchBox,
    bytes: &[u8],
) -> Result<CandidateDecodeProfile, Error> {
    if !matches!(
        prototype,
        QueryOutputBatchBox::RoleId(_) | QueryOutputBatchBox::TriggerId(_)
    ) {
        #[cfg(test)]
        {
            let limits = norito::canonical_decode_limits(bytes.len());
            return Ok(CandidateDecodeProfile {
                limits,
                allocation_charge: u64::try_from(limits.max_total_allocated_bytes())
                    .unwrap_or(u64::MAX),
            });
        }
        #[cfg(not(test))]
        {
            return Err(Error::Conversion(
                "canonical reconstruction accepts only RoleId or TriggerId output".to_owned(),
            ));
        }
    }
    canonical_id_decode_profile(bytes)
}
fn canonical_id_decode_profile(bytes: &[u8]) -> Result<CandidateDecodeProfile, Error> {
    fn malformed() -> Error {
        Error::Conversion("malformed internally retained canonical identifier frame".to_owned())
    }
    fn exact_length_prefixed_payload(bytes: &[u8]) -> Result<&[u8], Error> {
        let (length, prefix) =
            norito::core::inspect_len_from_slice(bytes).map_err(|_| malformed())?;
        let end = prefix.checked_add(length).ok_or_else(malformed)?;
        if end != bytes.len() {
            return Err(malformed());
        }
        bytes.get(prefix..end).ok_or_else(malformed)
    }
    let header = norito::core::Header::read(Cursor::new(bytes)).map_err(|_| malformed())?;
    if header.compression != norito::core::Compression::None
        || header.schema != norito::schema::identity::frame_hash::<QueryOutputBatchBox>()
        || header.flags != norito::core::header_flags::COMPACT_LEN
    {
        return Err(malformed());
    }
    let payload_len = usize::try_from(header.length).map_err(|_| malformed())?;
    let align = norito::core::archived_payload_align::<QueryOutputBatchBox>();
    let padding = if align <= 1 {
        0
    } else {
        let remainder = norito::core::Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    };
    let payload_start = norito::core::Header::SIZE
        .checked_add(padding)
        .ok_or_else(malformed)?;
    let payload_end = payload_start
        .checked_add(payload_len)
        .ok_or_else(malformed)?;
    if payload_end != bytes.len()
        || bytes
            .get(norito::core::Header::SIZE..payload_start)
            .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
    {
        return Err(malformed());
    }
    let payload = bytes
        .get(payload_start..payload_end)
        .ok_or_else(malformed)?;
    let enum_fields = payload.get(4..).ok_or_else(malformed)?;
    let _flags = norito::core::DecodeFlagsGuard::enter(header.flags);
    let sequence = exact_length_prefixed_payload(enum_fields)?;
    let count_bytes: [u8; 8] = sequence
        .get(..8)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    if u64::from_le_bytes(count_bytes) != 1 {
        return Err(malformed());
    }
    let identifier = exact_length_prefixed_payload(sequence.get(8..).ok_or_else(malformed)?)?;
    let name_wire = exact_length_prefixed_payload(identifier)?;
    let name = exact_length_prefixed_payload(name_wire)?;
    if name.is_empty()
        || name.len() > iroha_model_base::name::MAX_NAME_BYTES
        || core::str::from_utf8(name).is_err()
    {
        return Err(malformed());
    }
    // The current unpacked decoder has a fixed, schema-audited allocation
    // graph: one possible root realignment, two sequence-field buffers, three
    // identifier-field passes (length, canonical decode, possible realignment),
    // two Name-wire buffers, and the final canonical Name payload. The fixed
    // allowance above covers short archived padding and container bookkeeping.
    let allocation_charge = [
        payload.len(),
        sequence.len(),
        sequence.len(),
        identifier.len(),
        identifier.len(),
        identifier.len(),
        name_wire.len(),
        name_wire.len(),
        name.len(),
    ]
    .into_iter()
    .try_fold(
        CANONICAL_QUERY_ID_DECODE_FIXED_OVERHEAD_BYTES,
        |total, bytes| total.checked_add(u64::try_from(bytes).ok()?),
    )
    .ok_or(Error::CapacityLimit)?;
    // Canonical reconstruction checks the complete borrowed enum payload as
    // well as its nested fields. The exact root span includes the discriminant
    // and field prefix; every nested field above is contained within it.
    let max_field_bytes = payload.len();
    let limits = norito::DecodeLimits::new(
        1,
        max_field_bytes,
        1,
        usize::try_from(allocation_charge).map_err(|_| Error::CapacityLimit)?,
        8,
    );
    Ok(CandidateDecodeProfile {
        limits,
        allocation_charge,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        query::{QueryOutputBatchBox, parameters::Pagination},
        role::RoleId,
    };
    use nonzero_ext::nonzero;
    use std::collections::BTreeSet;
    const GENEROUS_ITEM_BYTES: u64 = 1024 * 1024;
    const GENEROUS_RETAINED_BYTES: u64 = 8 * 1024 * 1024;
    const GENEROUS_DECODE_BYTES: u64 = 8 * 1024 * 1024;
    fn string_frame(value: &str) -> Vec<u8> {
        norito::encode_canonical(&QueryOutputBatchBox::String(vec![value.to_owned()]))
            .expect("encode string candidate")
    }
    fn reference_strings(values: &[&str], pagination: Pagination, keep: usize) -> Vec<String> {
        let frames: BTreeSet<_> = values.iter().map(|value| string_frame(value)).collect();
        let skip = usize::try_from(pagination.offset_value()).unwrap_or(usize::MAX);
        let take = pagination.limit_value().map_or(usize::MAX, |limit| {
            usize::try_from(limit.get()).unwrap_or(usize::MAX)
        });
        frames
            .into_iter()
            .take(keep)
            .skip(skip)
            .take(take)
            .map(|bytes| {
                let QueryOutputBatchBox::String(mut values) =
                    norito::decode_canonical(&bytes).expect("decode reference candidate")
                else {
                    panic!("reference candidate changed variant")
                };
                values.pop().expect("one reference row")
            })
            .collect()
    }
    fn collect_strings(values: &[&str], keep: u64, pagination: Pagination) -> Vec<String> {
        let mut accumulator = CanonicalQueryOutputAccumulator::new(
            keep,
            GENEROUS_ITEM_BYTES,
            GENEROUS_RETAINED_BYTES,
            GENEROUS_DECODE_BYTES,
        );
        accumulator
            .push_batch_admitted(QueryOutputBatchBox::String(
                values.iter().map(|value| (*value).to_owned()).collect(),
            ))
            .expect("admit strings");
        let QueryOutputBatchBox::String(values) =
            accumulator.finish(pagination).expect("finish strings")
        else {
            panic!("string accumulator changed variant")
        };
        values
    }
    #[test]
    fn canonical_top_k_finds_a_late_small_item_that_native_first_k_misses() {
        let all = ["route-z", "route-y", "route-x", "route-a"];
        let mut by_frame: Vec<_> = all
            .iter()
            .map(|value| (string_frame(value), *value))
            .collect();
        by_frame.sort_by(|left, right| left.0.cmp(&right.0));
        let late_small = by_frame[0].1;
        let mut insertion: Vec<_> = all
            .iter()
            .copied()
            .filter(|value| *value != late_small)
            .collect();
        insertion.push(late_small);
        let actual = collect_strings(&insertion, 2, Pagination::default());
        assert!(actual.iter().any(|value| value == late_small));
        assert!(!insertion[..2].contains(&late_small));
        assert_eq!(
            actual,
            reference_strings(&insertion, Pagination::default(), 2)
        );
    }
    #[test]
    fn canonical_encoder_uses_the_exact_preflighted_frame_buffer() {
        let candidate = QueryOutputBatchBox::String(vec!["x".repeat(4 * 1024)]);
        let encoded_len =
            exact_canonical_frame_len(&candidate, GENEROUS_ITEM_BYTES).expect("preflight frame");
        let charged_capacity = usize::try_from(
            canonical_frame_buffer_bytes(encoded_len).expect("measure frame buffer"),
        )
        .expect("frame capacity fits usize");
        let actual = encode_canonical_preflighted(&candidate, encoded_len)
            .expect("encode into preflighted frame buffer");
        let reference = norito::encode_canonical(&candidate).expect("encode reference frame");
        assert_eq!(actual, reference);
        assert_eq!(actual.len(), usize::try_from(encoded_len).unwrap());
        assert!(actual.capacity() >= charged_capacity);
    }
    #[test]
    fn canonical_accumulator_matches_reference_set_dedupes_and_is_permutation_invariant() {
        let first = ["gamma", "alpha", "beta", "alpha", "delta"];
        let second = ["delta", "alpha", "gamma", "beta", "alpha"];
        let expected = reference_strings(&first, Pagination::default(), 4);
        assert_eq!(collect_strings(&first, 4, Pagination::default()), expected);
        assert_eq!(collect_strings(&second, 4, Pagination::default()), expected);
    }
    #[test]
    fn canonical_accumulator_applies_offset_and_limit_only_at_finish() {
        let values = ["five", "four", "three", "two", "one"];
        let pagination = Pagination::new(Some(nonzero!(2_u64)), 1);
        assert_eq!(
            collect_strings(&values, 3, pagination),
            reference_strings(&values, pagination, 3),
        );
    }
    #[test]
    fn canonical_accumulator_rejects_variant_mismatch_even_for_empty_batches() {
        let mut accumulator = CanonicalQueryOutputAccumulator::new(
            1,
            GENEROUS_ITEM_BYTES,
            GENEROUS_RETAINED_BYTES,
            GENEROUS_DECODE_BYTES,
        );
        accumulator
            .push_batch_admitted(QueryOutputBatchBox::String(Vec::new()))
            .expect("pin string variant");
        let error = accumulator
            .push_batch_admitted(QueryOutputBatchBox::Numeric(Vec::new()))
            .expect_err("a different empty variant must fail");
        assert!(matches!(error, Error::Conversion(_)));
    }
    #[test]
    fn public_accumulator_rejects_unproven_variants_before_exact_sizing() {
        let mut accumulator = CanonicalQueryOutputAccumulator::new(1, 0, 0, 0);
        let error = accumulator
            .push_batch(QueryOutputBatchBox::String(vec!["x".repeat(1024 * 1024)]))
            .expect_err("an unproven output variant must fail before its exact sizing path");
        assert!(matches!(error, Error::Conversion(_)));
        assert!(accumulator.prototype.is_none());
        assert!(accumulator.items.is_empty());
    }
    #[test]
    fn canonical_accumulator_has_an_exhaustive_empty_variant_path() {
        macro_rules! assert_empty_variants {
            ($($variant:ident),+ $(,)?) => {
                $(
                    let batch = QueryOutputBatchBox::$variant(Vec::new());
                    let expected = core::mem::discriminant(&batch);
                    let mut accumulator = CanonicalQueryOutputAccumulator::new(
                        1,
                        GENEROUS_ITEM_BYTES,
                        GENEROUS_RETAINED_BYTES,
                        GENEROUS_DECODE_BYTES,
                    );
                    accumulator.push_batch_admitted(batch).expect("pin empty variant");
                    let output = accumulator
                        .finish(Pagination::default())
                        .expect("finish empty variant");
                    assert_eq!(core::mem::discriminant(&output), expected);
                    assert!(output.is_empty());
                )+
            };
        }
        assert_empty_variants!(
            PublicKey,
            String,
            Metadata,
            Json,
            Numeric,
            Name,
            DomainId,
            Domain,
            AccountId,
            Account,
            AssetId,
            Asset,
            AssetDefinitionId,
            AssetDefinition,
            RepoAgreement,
            NftId,
            Nft,
            RwaId,
            Rwa,
            Role,
            Parameter,
            Permission,
            CommittedTransaction,
            TransactionResult,
            TransactionResultHash,
            TransactionEntrypoint,
            TransactionEntrypointHash,
            Peer,
            RoleId,
            TriggerId,
            Trigger,
            Action,
            Block,
            BlockHeader,
            BlockHeaderHash,
            ProofRecord,
            OracleFeedConfig,
            OracleFeedEventRecord,
            OracleProviderStatsRecord,
            OracleDispute,
            OracleChangeProposal,
            TwitterBindingRecord,
            DefiOracleAttestation,
            AssetEscrowRecord,
            FeeSponsorProgram,
            FeeSponsorProgramId,
            BondRecord,
        );
    }
    #[test]
    fn canonical_accumulator_enforces_exact_candidate_and_retained_byte_bounds() {
        let candidate = QueryOutputBatchBox::String(vec!["bounded".to_owned()]);
        let encoded = exact_canonical_frame_len(&candidate, u64::MAX).expect("measure candidate");
        let retained_charge = canonical_query_candidate_allocation_bytes(encoded)
            .expect("measure complete candidate allocation");
        let mut exact = CanonicalQueryOutputAccumulator::new(
            1,
            encoded,
            retained_charge,
            GENEROUS_DECODE_BYTES,
        );
        exact
            .push_batch_admitted(candidate.clone())
            .expect("exact bounds fit");
        let mut transient = CanonicalQueryOutputAccumulator::new(
            1,
            encoded.saturating_sub(1),
            retained_charge,
            GENEROUS_DECODE_BYTES,
        );
        let error = transient
            .push_batch_admitted(candidate.clone())
            .expect_err("oversized transient candidate must fail before retention");
        assert!(matches!(error, Error::GasBudgetExceeded));
        assert!(transient.items.is_empty());
        let mut retained = CanonicalQueryOutputAccumulator::new(
            1,
            encoded,
            retained_charge.saturating_sub(1),
            GENEROUS_DECODE_BYTES,
        );
        let error = retained
            .push_batch_admitted(candidate)
            .expect_err("retained bytes must be exact");
        assert!(matches!(error, Error::CapacityLimit));
        assert!(retained.items.is_empty());
    }
    #[test]
    fn canonical_accumulator_charges_fixed_overhead_for_many_tiny_items() {
        let values: Vec<_> = (0_u8..64).map(|value| format!("{value:02x}")).collect();
        let frames: BTreeSet<_> = values.iter().map(|value| string_frame(value)).collect();
        let exact_retained = frames.iter().fold(0_u64, |total, frame| {
            total
                .checked_add(
                    canonical_query_candidate_allocation_bytes(
                        u64::try_from(frame.len()).expect("frame length fits u64"),
                    )
                    .expect("candidate allocation charge fits"),
                )
                .expect("test retained charge fits")
        });
        let max_item = frames
            .iter()
            .map(|frame| u64::try_from(frame.len()).expect("frame length fits u64"))
            .max()
            .expect("non-empty frames");
        let batch = QueryOutputBatchBox::String(values);
        let mut exact = CanonicalQueryOutputAccumulator::new(
            64,
            max_item,
            exact_retained,
            GENEROUS_DECODE_BYTES,
        );
        exact
            .push_batch_admitted(batch.clone())
            .expect("exact many-item retained budget fits");
        assert_eq!(exact.retained_bytes, exact_retained);
        let mut short = CanonicalQueryOutputAccumulator::new(
            64,
            max_item,
            exact_retained.saturating_sub(1),
            GENEROUS_DECODE_BYTES,
        );
        let error = short
            .push_batch_admitted(batch)
            .expect_err("one missing overhead byte must fail closed");
        assert!(matches!(error, Error::CapacityLimit));
    }
    #[test]
    fn canonical_accumulator_enforces_aggregate_decode_allocation_bound() {
        const PAGE_ITEMS: u16 = 512;
        let values: Vec<RoleId> = (0_u16..PAGE_ITEMS)
            .map(|index| {
                let prefix = format!("decode{index:04x}");
                let value = format!(
                    "{prefix}{}",
                    "x".repeat(iroha_model_base::name::MAX_NAME_BYTES - prefix.len())
                );
                value.parse().expect("maximum-width role ID")
            })
            .collect();
        let frames: BTreeSet<_> = values
            .iter()
            .map(|value| {
                norito::encode_canonical(&QueryOutputBatchBox::RoleId(vec![value.clone()]))
                    .expect("encode role ID candidate")
            })
            .collect();
        let prototype = QueryOutputBatchBox::RoleId(Vec::new());
        let output_container_allocation =
            output_container_allocation_charge(&prototype, frames.len())
                .expect("measure reference output container");
        let exact_decode = frames
            .iter()
            .try_fold(output_container_allocation, |total, frame| {
                let profile = candidate_decode_profile(&prototype, frame)
                    .expect("measure identifier decode profile");
                total
                    .checked_add(profile.allocation_charge)
                    .ok_or(Error::CapacityLimit)
            })
            .expect("test decode charge fits");
        let retained = frames
            .iter()
            .try_fold(0_u64, |total, frame| {
                total
                    .checked_add(
                        canonical_query_candidate_allocation_bytes(
                            u64::try_from(frame.len()).expect("frame length fits u64"),
                        )
                        .expect("candidate allocation charge fits"),
                    )
                    .ok_or(Error::CapacityLimit)
            })
            .expect("test retained charge fits");
        let max_item = frames
            .iter()
            .map(|frame| u64::try_from(frame.len()).expect("frame length fits u64"))
            .max()
            .expect("non-empty frames");
        let batch = QueryOutputBatchBox::RoleId(values);
        let mut exact = CanonicalQueryOutputAccumulator::new(
            u64::from(PAGE_ITEMS),
            max_item,
            retained,
            exact_decode,
        );
        exact.push_batch(batch.clone()).expect("admit exact batch");
        let QueryOutputBatchBox::RoleId(output) = exact
            .finish(Pagination::default())
            .expect("exact aggregate decode budget fits")
        else {
            panic!("role-ID reconstruction changed variant")
        };
        assert_eq!(output.len(), usize::from(PAGE_ITEMS));
        let mut short = CanonicalQueryOutputAccumulator::new(
            u64::from(PAGE_ITEMS),
            max_item,
            retained,
            exact_decode.saturating_sub(1),
        );
        short.push_batch(batch).expect("admit short-decode batch");
        let error = short
            .finish(Pagination::default())
            .expect_err("aggregate decode allowance must not reset per item");
        assert!(matches!(error, Error::CapacityLimit));
    }
    #[test]
    fn canonical_identifier_decode_limits_match_both_real_decoders() {
        let maximum_name = format!(
            "id{}",
            "x".repeat(iroha_model_base::name::MAX_NAME_BYTES - 2)
        );
        let batches = [
            QueryOutputBatchBox::RoleId(vec![maximum_name.parse().expect("maximum-width role ID")]),
            QueryOutputBatchBox::TriggerId(vec![
                maximum_name.parse().expect("maximum-width trigger ID"),
            ]),
        ];
        for batch in batches {
            let prototype = empty_batch_like(&batch);
            let frame = norito::encode_canonical(&batch).expect("encode identifier candidate");
            let profile = candidate_decode_profile(&prototype, &frame)
                .expect("derive identifier decode profile");
            let output_charge = output_container_allocation_charge(&prototype, 1)
                .expect("measure identifier output container");
            let exact_decode = output_charge
                .checked_add(profile.allocation_charge)
                .expect("identifier decode charge fits");
            let encoded = u64::try_from(frame.len()).expect("identifier frame length fits");
            let retained = canonical_query_candidate_allocation_bytes(encoded)
                .expect("identifier candidate charge fits");
            let mut exact =
                CanonicalQueryOutputAccumulator::new(1, encoded, retained, exact_decode);
            exact.push_batch(batch.clone()).expect("admit identifier");
            let output = exact
                .finish(Pagination::default())
                .expect("schema-specific limits admit the real identifier decoder");
            assert_eq!(output.len(), 1);
            assert_eq!(
                core::mem::discriminant(&output),
                core::mem::discriminant(&prototype)
            );
            let mut short = CanonicalQueryOutputAccumulator::new(
                1,
                encoded,
                retained,
                exact_decode.saturating_sub(1),
            );
            short.push_batch(batch).expect("admit identifier");
            let error = short
                .finish(Pagination::default())
                .expect_err("D - 1 must fail before reserving the output column");
            assert!(matches!(error, Error::CapacityLimit));
        }
    }
    #[test]
    fn canonical_identifier_field_limit_binds_the_complete_root_payload() {
        for length in [1, iroha_model_base::name::MAX_NAME_BYTES] {
            let name = "x".repeat(length);
            for batch in [
                QueryOutputBatchBox::RoleId(vec![name.parse().unwrap()]),
                QueryOutputBatchBox::TriggerId(vec![name.parse().unwrap()]),
            ] {
                let frame = norito::encode_canonical(&batch).unwrap();
                let profile = canonical_id_decode_profile(&frame).unwrap();
                let header = norito::core::Header::read(Cursor::new(&frame)).unwrap();
                let payload_bytes = usize::try_from(header.length).unwrap();
                let limits = profile.limits;
                assert_eq!(limits.max_field_bytes(), payload_bytes);
                let decoded = decode_candidate(&frame, limits).expect("exact root span fits");
                assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
                let short = norito::DecodeLimits::new(
                    limits.max_sequence_elements(),
                    payload_bytes - 1,
                    limits.max_total_elements(),
                    limits.max_total_allocated_bytes(),
                    limits.max_nesting_depth(),
                );
                assert!(matches!(
                    norito::decode_from_bytes_with_limits::<QueryOutputBatchBox>(&frame, short),
                    Err(norito::Error::FieldLengthExceeded { length, limit })
                        if length == header.length && limit == header.length - 1
                ));
            }
        }
    }
    #[test]
    fn canonical_identifier_decode_profile_rejects_another_frame_identity() {
        for batch in [
            QueryOutputBatchBox::RoleId(vec!["owner".parse().unwrap()]),
            QueryOutputBatchBox::TriggerId(vec!["owner".parse().unwrap()]),
        ] {
            let frame = norito::encode_canonical(&batch).unwrap();
            let view = norito::core::from_bytes_view(&frame).unwrap();
            assert_eq!(
                view.schema(),
                norito::schema::identity::frame_hash::<QueryOutputBatchBox>()
            );
            canonical_id_decode_profile(&frame).expect("the canonical identifier frame is valid");

            // Only replace the schema field at its fixed Norito header offset; the
            // identifier payload, checksum, flags, padding and lengths remain intact.
            let mut foreign = frame.clone();
            foreign[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<u8>());
            let foreign_view = norito::core::from_bytes_view(&foreign).unwrap();
            assert_eq!(foreign_view.as_bytes(), view.as_bytes());
            assert!(matches!(
                canonical_id_decode_profile(&foreign),
                Err(Error::Conversion(message))
                    if message == "malformed internally retained canonical identifier frame"
            ));
        }
    }
    #[test]
    fn canonical_reconstruction_presizes_the_large_block_arm_and_charges_inline_bytes() {
        let capacity = 17;
        let (batch, charge) =
            empty_batch_with_capacity_like(&QueryOutputBatchBox::Block(Vec::new()), capacity)
                .expect("reserve block output");
        let expected =
            u64::try_from(core::mem::size_of::<iroha_data_model::block::SignedBlock>() * capacity)
                .expect("block container bytes fit")
                .saturating_add(CANONICAL_QUERY_OUTPUT_CONTAINER_OVERHEAD_BYTES);
        assert_eq!(charge, expected);
        let QueryOutputBatchBox::Block(blocks) = batch else {
            panic!("block prototype changed variant")
        };
        assert!(blocks.capacity() >= capacity);
        assert!(blocks.is_empty());
    }
}
