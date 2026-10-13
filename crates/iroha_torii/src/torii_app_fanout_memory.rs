// Deterministic memory accounting for generic application-API fanout.
/// Logical bytes charged for one `BTreeMap` entry in an owned JSON object.
///
/// Norito's native `Value` uses `BTreeMap<String, Value>`. The standard
/// library stores multiple entries per node, but the layout is private. One page per entry
/// therefore covers a node allocation, parent/edge slack, the inline key/value handles, and
/// allocator metadata without depending on that private layout.
const TORII_FANOUT_JSON_OBJECT_ENTRY_BYTES: usize = 4 * 1024;
/// Logical bytes charged for an owned JSON object's root handle.
const TORII_FANOUT_JSON_OBJECT_BASE_BYTES: usize = 256;
/// Parser-frame allowance per admitted JSON level.
const TORII_FANOUT_JSON_PARSER_FRAME_BYTES: usize = 1024;
/// `Vec` initially reserves at least this many non-zero-sized JSON values.
const TORII_FANOUT_JSON_ARRAY_MIN_SLOTS: usize = 4;
/// Geometric `Vec` growth stays below two requested element slots.
const TORII_FANOUT_JSON_ARRAY_GROWTH_FACTOR: usize = 2;
/// Norito's escaped-string parser starts its byte buffer at this capacity.
const TORII_FANOUT_JSON_STRING_MIN_CAPACITY: usize = 16;
/// Decode-context, cursor, guard, and fixed alignment scratch per Norito route.
const TORII_APP_FANOUT_NORITO_FIXED_BYTES: usize = 4 * 1024;
/// Physical allowance for collection nodes not charged exactly by Norito.
///
/// Norito now charges its standard collection nodes, but dynamically boxed values, reference-count
/// headers, non-byte fixed-array staging, and some schema-specific validation scratch remain
/// outside that counter. One page per admitted element is retained as a secondary envelope; fixed
/// roots must also fit the separate route allowance. Any production DTO needs a complete
/// reachability audit before it can implement the sealed marker below.
const TORII_APP_FANOUT_NORITO_UNTRACKED_ELEMENT_BYTES: usize = 4 * 1024;
/// Physical-to-logical allowance for allocator/container capacity slack in
/// allocations that Norito does charge.
const TORII_APP_FANOUT_NORITO_TRACKED_ALLOCATION_FACTOR: usize = 2;
/// Resource names reported by bounded generic fanout accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToriiAppFanoutResource {
    RawBytes,
    EncodedStringBytes,
    DecodedStringBytes,
    Values,
    ArrayEntries,
    ObjectEntries,
    NestingDepth,
    DecodedGraphBytes,
    WorkingSetBytes,
    Arithmetic,
}
/// Fail-closed error from generic fanout preflight or logical admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ToriiAppFanoutMemoryError {
    resource: ToriiAppFanoutResource,
    attempted: usize,
    limit: usize,
    offset: Option<usize>,
    detail: &'static str,
}
impl ToriiAppFanoutMemoryError {
    const fn resource(resource: ToriiAppFanoutResource, attempted: usize, limit: usize) -> Self {
        Self {
            resource,
            attempted,
            limit,
            offset: None,
            detail: "resource limit exceeded",
        }
    }
    const fn syntax(offset: usize, detail: &'static str) -> Self {
        Self {
            resource: ToriiAppFanoutResource::RawBytes,
            attempted: offset,
            limit: offset,
            offset: Some(offset),
            detail,
        }
    }
    const fn overflow(detail: &'static str) -> Self {
        Self {
            resource: ToriiAppFanoutResource::Arithmetic,
            attempted: usize::MAX,
            limit: usize::MAX,
            offset: None,
            detail,
        }
    }
}
impl core::fmt::Display for ToriiAppFanoutMemoryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(offset) = self.offset {
            return write!(
                formatter,
                "invalid proxied JSON at byte {offset}: {}",
                self.detail
            );
        }
        write!(
            formatter,
            "generic fanout {:?} charge {} exceeds limit {} ({})",
            self.resource, self.attempted, self.limit, self.detail
        )
    }
}
impl std::error::Error for ToriiAppFanoutMemoryError {}
/// Fixed, non-reflective diagnostic for a hostile upstream decoder failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToriiAppFanoutDecodeFailure {
    Json,
    Norito,
}
impl core::fmt::Display for ToriiAppFanoutDecodeFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Json => "proxied JSON response failed bounded decoding",
            Self::Norito => "proxied Norito response failed bounded decoding",
        })
    }
}
impl std::error::Error for ToriiAppFanoutDecodeFailure {}
/// Consume a potentially hostile JSON parser error without retaining or
/// formatting its attacker-controlled duplicate key or message payload.
fn sanitize_torii_app_fanout_json_error(_: norito::json::Error) -> ToriiAppFanoutDecodeFailure {
    ToriiAppFanoutDecodeFailure::Json
}
/// Consume a potentially hostile Norito decoder error without reflecting any
/// payload-derived detail into diagnostics.
fn sanitize_torii_app_fanout_norito_error(_: norito::Error) -> ToriiAppFanoutDecodeFailure {
    ToriiAppFanoutDecodeFailure::Norito
}
/// Independent syntax/resource ceilings applied before constructing a JSON `Value` graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ToriiFanoutJsonLimits {
    raw_bytes: usize,
    encoded_string_bytes: usize,
    decoded_string_bytes: usize,
    values: usize,
    array_entries: usize,
    object_entries: usize,
    nesting_depth: usize,
    decoded_graph_bytes: usize,
}
impl ToriiFanoutJsonLimits {}
/// Allocation-relevant facts obtained without allocating an owned JSON value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ToriiFanoutJsonProfile {
    raw_bytes: usize,
    encoded_string_bytes: usize,
    decoded_string_bytes: usize,
    values: usize,
    arrays: usize,
    array_entries: usize,
    objects: usize,
    object_entries: usize,
    max_nesting_depth: usize,
    string_capacity_bytes: usize,
    max_escaped_string_capacity_bytes: usize,
    decoded_graph_bytes: usize,
    parser_scratch_bytes: usize,
}
impl ToriiFanoutJsonProfile {
    /// Raw body plus the complete parser/owned-graph overlap.
    fn decode_peak_bytes(self) -> Result<usize, ToriiAppFanoutMemoryError> {
        checked_fanout_sum([
            self.raw_bytes,
            self.decoded_graph_bytes,
            self.parser_scratch_bytes,
        ])
    }
    fn finish(mut self, limits: ToriiFanoutJsonLimits) -> Result<Self, ToriiAppFanoutMemoryError> {
        let value_bytes = core::mem::size_of::<norito::json::Value>();
        let value_nodes = checked_fanout_mul(self.values, value_bytes)?;
        let array_minimum = checked_fanout_mul(
            checked_fanout_mul(self.arrays, TORII_FANOUT_JSON_ARRAY_MIN_SLOTS)?,
            value_bytes,
        )?;
        let array_growth = checked_fanout_mul(
            checked_fanout_mul(self.array_entries, TORII_FANOUT_JSON_ARRAY_GROWTH_FACTOR)?,
            value_bytes,
        )?;
        let object_roots = checked_fanout_mul(self.objects, TORII_FANOUT_JSON_OBJECT_BASE_BYTES)?;
        let object_nodes =
            checked_fanout_mul(self.object_entries, TORII_FANOUT_JSON_OBJECT_ENTRY_BYTES)?;
        self.decoded_graph_bytes = checked_fanout_sum([
            value_nodes,
            array_minimum,
            array_growth,
            object_roots,
            object_nodes,
            self.string_capacity_bytes,
        ])?;
        // The frame Vec grows geometrically. Error cleanup can additionally
        // move every parsed Value through one pending Vec while the source
        // containers are being dismantled. The scanner validates lexical JSON
        // without copying hostile keys; duplicate-key rejection remains in the
        // real parser, so its complete failure-path cleanup is charged here.
        let parser_frames =
            checked_fanout_mul(self.max_nesting_depth, TORII_FANOUT_JSON_PARSER_FRAME_BYTES)?;
        let cleanup_slots = checked_fanout_mul(
            checked_fanout_mul(self.values, TORII_FANOUT_JSON_ARRAY_GROWTH_FACTOR)?,
            value_bytes,
        )?;
        // The escaped-string slow path now moves its geometric Vec into a
        // String. Keep the former Vec-plus-String overlap charge anyway: it
        // also covers the largest in-progress escaped token on a parser-error
        // path while all earlier strings and containers are still live.
        self.parser_scratch_bytes = checked_fanout_sum([
            parser_frames,
            cleanup_slots,
            self.max_escaped_string_capacity_bytes,
        ])?;
        ensure_fanout_limit(
            ToriiAppFanoutResource::DecodedGraphBytes,
            self.decoded_graph_bytes,
            limits.decoded_graph_bytes,
        )?;
        Ok(self)
    }
}
fn checked_fanout_sum<const N: usize>(
    terms: [usize; N],
) -> Result<usize, ToriiAppFanoutMemoryError> {
    terms.into_iter().try_fold(0usize, |total, term| {
        total
            .checked_add(term)
            .ok_or_else(|| ToriiAppFanoutMemoryError::overflow("logical byte sum overflow"))
    })
}
fn checked_fanout_mul(lhs: usize, rhs: usize) -> Result<usize, ToriiAppFanoutMemoryError> {
    lhs.checked_mul(rhs)
        .ok_or_else(|| ToriiAppFanoutMemoryError::overflow("logical byte product overflow"))
}
fn ensure_fanout_limit(
    resource: ToriiAppFanoutResource,
    attempted: usize,
    limit: usize,
) -> Result<(), ToriiAppFanoutMemoryError> {
    if attempted > limit {
        return Err(ToriiAppFanoutMemoryError::resource(
            resource, attempted, limit,
        ));
    }
    Ok(())
}
include!("torii_app_fanout_json_preflight.rs");
/// Explicit decode plan for one route's Norito response.
#[derive(Clone, Copy, Debug)]
struct ToriiFanoutNoritoDecodePlan {
    limits: norito::DecodeLimits,
    retained_charge_bytes: usize,
    temporary_charge_bytes: usize,
}
mod torii_app_fanout_norito_dto_sealed {
    pub trait Sealed {}
}
/// Closed set of Torii response DTOs whose complete decode and source graphs
/// have been audited against [`ToriiFanoutNoritoDecodePlan`].
///
/// There are deliberately no production implementations yet. `ProofRecord` can clone a 64 MiB
/// bridge proof before coordinator admission, `Asset` can clone an account-controller graph before
/// admission, account metadata's `Json` decoder builds an uncharged semantic graph, and committed
/// transactions reach dynamically boxed instructions. Admitting any of those types here before both
/// source and decoder roots are bounded would turn this marker into a false memory-safety claim.
// TODO: Add one concrete implementation at a time after its authoritative
// source path and every reachable decoder allocation are pre-admission bounded,
// and lift the test-only `include!` gate in lib.rs in the same change.
trait ToriiAppFanoutNoritoDto:
    torii_app_fanout_norito_dto_sealed::Sealed
    + norito::NoritoSerialize
    + for<'de> norito::NoritoDeserialize<'de>
{
}
/// Decode one admitted, canonical-layout route response sequentially.
///
/// The header is checked first and non-default or compressed frames fail closed. This avoids
/// per-worker decoder contexts without guessing wire flags.
fn decode_torii_app_fanout_norito<T>(
    bytes: &[u8],
    plan: ToriiFanoutNoritoDecodePlan,
) -> Result<T, ToriiAppFanoutDecodeFailure>
where
    T: ToriiAppFanoutNoritoDto,
{
    let header = norito::core::Header::read(std::io::Cursor::new(bytes))
        .map_err(sanitize_torii_app_fanout_norito_error)?;
    if header.compression != norito::Compression::None
        || header.flags != norito::default_encode_flags()
    {
        return Err(ToriiAppFanoutDecodeFailure::Norito);
    }
    norito::decode_from_bytes_with_limits(bytes, plan.limits)
        .map_err(sanitize_torii_app_fanout_norito_error)
}
/// Logical high-water ledger for one sequential generic app-API fanout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ToriiAppFanoutMemoryBudget {
    capacity_bytes: usize,
    retained_bytes: usize,
}
impl ToriiAppFanoutMemoryBudget {
    #[cfg(test)]
    fn new(capacity_bytes: usize) -> Result<Self, ToriiAppFanoutMemoryError> {
        Self::new_inner(capacity_bytes)
    }
    fn new_inner(capacity_bytes: usize) -> Result<Self, ToriiAppFanoutMemoryError> {
        if capacity_bytes == 0 {
            return Err(ToriiAppFanoutMemoryError::resource(
                ToriiAppFanoutResource::WorkingSetBytes,
                1,
                0,
            ));
        }
        Ok(Self {
            capacity_bytes,
            retained_bytes: 0,
        })
    }
    fn retained_bytes(self) -> usize {
        self.retained_bytes
    }
    fn remaining_bytes(self) -> Result<usize, ToriiAppFanoutMemoryError> {
        self.capacity_bytes
            .checked_sub(self.retained_bytes)
            .ok_or_else(|| {
                ToriiAppFanoutMemoryError::overflow(
                    "retained fanout bytes exceed working-set capacity",
                )
            })
    }
    /// Admit raw bytes, the complete owned graph, parser frames, string
    /// capacity, and error-cleanup scratch before calling `from_slice<Value>`.
    fn admit_json_decode(
        self,
        profile: ToriiFanoutJsonProfile,
    ) -> Result<(), ToriiAppFanoutMemoryError> {
        self.admit_temporary(profile.decode_peak_bytes()?)
    }
    /// Split remaining Norito capacity across the routes that may still
    /// succeed. Only the closed, source-audited DTO set can obtain this plan.
    fn norito_decode_plan<T>(
        self,
        raw_body_bytes: usize,
        routes_remaining: usize,
        max_nesting_depth: usize,
    ) -> Result<ToriiFanoutNoritoDecodePlan, ToriiAppFanoutMemoryError>
    where
        T: ToriiAppFanoutNoritoDto,
    {
        if routes_remaining == 0 {
            return Err(ToriiAppFanoutMemoryError::resource(
                ToriiAppFanoutResource::Values,
                1,
                0,
            ));
        }
        let remaining = self.remaining_bytes()?;
        ensure_fanout_limit(ToriiAppFanoutResource::RawBytes, raw_body_bytes, remaining)?;
        let after_raw = remaining - raw_body_bytes;
        let route_slice_bytes = after_raw / routes_remaining;
        let variable_bytes = route_slice_bytes
            .checked_sub(TORII_APP_FANOUT_NORITO_FIXED_BYTES)
            .ok_or_else(|| {
                ToriiAppFanoutMemoryError::resource(
                    ToriiAppFanoutResource::DecodedGraphBytes,
                    TORII_APP_FANOUT_NORITO_FIXED_BYTES,
                    route_slice_bytes,
                )
            })?;
        let tracked_physical_bytes = variable_bytes / 2;
        let tracked_logical_bytes =
            tracked_physical_bytes / TORII_APP_FANOUT_NORITO_TRACKED_ALLOCATION_FACTOR;
        let untracked_node_bytes = variable_bytes - tracked_physical_bytes;
        let max_elements = untracked_node_bytes / TORII_APP_FANOUT_NORITO_UNTRACKED_ELEMENT_BYTES;
        if tracked_logical_bytes == 0 {
            return Err(ToriiAppFanoutMemoryError::resource(
                ToriiAppFanoutResource::DecodedGraphBytes,
                1,
                0,
            ));
        }
        let depth = max_nesting_depth.min(norito::core::MAX_VALUE_NESTING_DEPTH);
        Ok(ToriiFanoutNoritoDecodePlan {
            limits: norito::DecodeLimits::new(
                max_elements,
                tracked_logical_bytes,
                max_elements,
                tracked_logical_bytes,
                depth,
            ),
            // Retain the fixed allowance too. Some schema-bounded heaps (for
            // example BigInt limbs) survive in the returned DTO even though
            // Norito does not currently charge them.
            retained_charge_bytes: route_slice_bytes,
            temporary_charge_bytes: route_slice_bytes,
        })
    }
    fn retain_norito_decode(
        &mut self,
        plan: ToriiFanoutNoritoDecodePlan,
    ) -> Result<(), ToriiAppFanoutMemoryError> {
        self.retain(plan.retained_charge_bytes)
    }
    /// Pre-admit merge graphs, canonical keys, candidate frames, or a final
    /// response while all currently charged values remain live.
    fn admit_temporary(self, bytes: usize) -> Result<(), ToriiAppFanoutMemoryError> {
        let peak = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(|| ToriiAppFanoutMemoryError::overflow("working-set phase sum overflow"))?;
        ensure_fanout_limit(
            ToriiAppFanoutResource::WorkingSetBytes,
            peak,
            self.capacity_bytes,
        )
    }
    fn retain(&mut self, bytes: usize) -> Result<(), ToriiAppFanoutMemoryError> {
        self.admit_temporary(bytes)?;
        self.retained_bytes = self.retained_bytes.checked_add(bytes).ok_or_else(|| {
            ToriiAppFanoutMemoryError::overflow("retained working-set byte sum overflow")
        })?;
        Ok(())
    }
    fn release(&mut self, bytes: usize) -> Result<(), ToriiAppFanoutMemoryError> {
        self.retained_bytes = self.retained_bytes.checked_sub(bytes).ok_or_else(|| {
            ToriiAppFanoutMemoryError::overflow(
                "released fanout bytes exceed retained working-set bytes",
            )
        })?;
        Ok(())
    }
}
#[cfg(test)]
include!("tests/lib_routed_reads/app_fanout_memory_bounds.rs");
