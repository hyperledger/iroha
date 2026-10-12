// Response-corridor memory accounting for application-API routed reads.
// Local producer coverage is separate and exhaustively inventoried in the
// routed-read source-bound tests.
// Axum 0.8.9 collects at most two dynamic parameters on the routed-read
// catalog below. Its empty `Vec` grows to four `(Arc<str>, Arc<str>)` slots;
// each key/value Arc owns two atomic counters and alignment padding. Decoded
// value payload bytes share the outer request phase because percent decoding
// only shrinks the raw target. Parameter names are fixed catalog data and fit
// the separately named key allowance (source-regressed by the HTTP inventory).
const APP_ROUTED_READ_MAX_URL_PARAMETERS_V1: usize = 2;
const APP_ROUTED_READ_URL_PARAMETER_VEC_CAPACITY_V1: usize = 4;
const APP_ROUTED_READ_URL_PARAMETER_KEY_BYTES_V1: usize = 64;
fn app_routed_read_url_parameter_fixed_bytes() -> Option<usize> {
    routed_read_url_parameter_fixed_bytes(
        APP_ROUTED_READ_MAX_URL_PARAMETERS_V1,
        APP_ROUTED_READ_URL_PARAMETER_KEY_BYTES_V1,
    )
}
// Keep the original application catalog allowance; SCCP supplies its actual
// three-key control route geometry without increasing the working-set limit.
fn routed_read_url_parameter_fixed_bytes(parameters: usize, key_bytes: usize) -> Option<usize> {
    if parameters > APP_ROUTED_READ_URL_PARAMETER_VEC_CAPACITY_V1 {
        return None;
    }

    let arc_handle_bytes = core::mem::size_of::<std::sync::Arc<str>>();
    let arc_control_and_padding = core::mem::size_of::<usize>()
        .checked_mul(2)?
        .checked_add(core::mem::align_of::<usize>().saturating_sub(1))?;
    APP_ROUTED_READ_URL_PARAMETER_VEC_CAPACITY_V1
        .checked_mul(arc_handle_bytes.checked_mul(2)?)?
        .checked_add(
            parameters
                .checked_mul(2)?
                .checked_mul(arc_control_and_padding)?,
        )?
        .checked_add(key_bytes)
}
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "app_api")]
struct ToriiRoutedReadDecodePlan {
    limits: norito::DecodeLimits,
    canonical_limit_bytes: usize,
}
#[derive(Debug)]
#[cfg(feature = "app_api")]
struct ToriiBoundedNoritoPayload<T> {
    value: T,
    canonical_bytes: Vec<u8>,
}
/// Logical ledger backed by one existing query-fanout working-set permit.
///
/// Route bodies are decoded sequentially. Norito's measured decode scope records every allocation
/// request made by JSON or binary decoders, so a successful value can be retained against the
/// aggregate phase without a guessed per-element allowance or a per-route fair split. Candidate
/// encodings and the final response use their existing independent envelope phases.
#[derive(Debug)]
struct ToriiRoutedReadMemoryBudget {
    envelope: QueryFanoutMemoryEnvelope,
    configured_body_limit_bytes: usize,
    #[cfg(feature = "app_api")]
    retained_decoded_bytes: usize,
    #[cfg(feature = "app_api")]
    retained_canonical_bytes: usize,
    #[cfg(feature = "app_api")]
    merge_allocated_bytes: usize,
}
impl ToriiRoutedReadMemoryBudget {
    fn new(working_set_bytes: usize, configured_body_limit_bytes: usize) -> Result<Self, Response> {
        Ok(Self::from_envelope(
            QueryFanoutMemoryEnvelope::for_body_admission(working_set_bytes)?,
            configured_body_limit_bytes,
        ))
    }
    /// Derive the corridor from the geometry retained by its actual owner.
    fn from_envelope(
        envelope: QueryFanoutMemoryEnvelope,
        configured_body_limit_bytes: usize,
    ) -> Self {
        Self {
            envelope,
            configured_body_limit_bytes,
            #[cfg(feature = "app_api")]
            retained_decoded_bytes: 0,
            #[cfg(feature = "app_api")]
            retained_canonical_bytes: 0,
            #[cfg(feature = "app_api")]
            merge_allocated_bytes: 0,
        }
    }
    /// Bound the complete routed request retained across transport retries.
    #[cfg(feature = "app_api")]
    fn admit_request_bytes(&self, bytes: usize) -> Result<(), Response> {
        torii_routed_read_ensure(
            "request representation",
            bytes,
            self.envelope.route_body_bytes,
        )?;
        if !self.app_request_phases_fit(bytes) {
            return Err(torii_routed_read_capacity_response(
                "application request high-water",
                bytes,
                self.envelope.route_body_bytes,
            ));
        }
        Ok(())
    }
    /// Prove every App request representation fits beside each fanout phase.
    #[cfg(feature = "app_api")]
    fn app_request_phases_fit(&self, bytes: usize) -> bool {
        self.app_request_high_water_bytes(bytes)
            .is_some_and(|total| total <= self.envelope.working_set_bytes)
    }
    fn app_request_high_water_bytes(&self, bytes: usize) -> Option<usize> {
        const INNER_REQUEST_REPRESENTATIONS: usize = 3;
        let fixed_overhead = query_fanout_fixed_overhead_bytes()?;
        let inner_requests = bytes.checked_mul(INNER_REQUEST_REPRESENTATIONS)?;
        // This is a phase maximum, not five identical owners. Before handler
        // execution, raw URI and decoded Axum URL parameters overlap. Later,
        // request parts/UrlParams are gone while the exact body, owned Path and
        // typed DTO overlap the normalized, active, and sanitizer/transport
        // inner request shapes. The typed DTO cannot borrow request-decode:
        // route/source work reuses that transient while the DTO stays live.
        let outer_and_typed_requests = self.envelope.route_body_bytes.checked_mul(2)?;
        // `HyperTokioIo` exposes at most one fixed 8 KiB read chunk to Hyper.
        // Configuration proves it fits one route-body phase, while this term
        // charges its actual overlap with the exact outer destination.
        let transport_frame =
            usize::try_from(iroha_config::parameters::defaults::torii::HTTP_READ_CHUNK_BYTES_V1)
                .ok()?;
        let path_parameter_fixed = app_routed_read_url_parameter_fixed_bytes()?;
        let local_scan = checked_sum([
            self.envelope.request_decode_allocated_bytes,
            self.envelope.accumulator_retained_bytes,
            self.envelope.accumulator_retained_bytes,
            self.envelope.candidate_allocation_bytes,
            self.envelope.candidate_encoded_bytes,
        ])?;
        let remote_decode = checked_sum([
            self.envelope.request_decode_allocated_bytes,
            self.envelope.accumulator_retained_bytes,
            self.envelope.route_body_bytes,
            self.envelope.route_body_bytes,
            self.envelope.decode_allocated_bytes,
        ])?;
        let merge_candidate = checked_sum([
            self.envelope.request_decode_allocated_bytes,
            self.envelope.accumulator_retained_bytes,
            self.envelope.decode_allocated_bytes,
            self.envelope.candidate_allocation_bytes,
            self.envelope.candidate_encoded_bytes,
            self.envelope.candidate_encoded_bytes,
        ])?;
        let singular_compare = checked_sum([
            self.envelope.request_decode_allocated_bytes,
            self.envelope.decode_allocated_bytes,
            self.envelope.decode_allocated_bytes,
            self.envelope.decode_allocated_bytes,
            self.envelope.candidate_encoded_bytes,
            self.envelope.candidate_encoded_bytes,
            self.envelope.candidate_encoded_bytes,
        ])?;
        let final_encode = checked_sum([
            self.envelope.decode_allocated_bytes,
            self.envelope.final_body_bytes,
            self.envelope.final_body_bytes,
        ])?;
        let proxy_copy = self.envelope.final_body_bytes.checked_mul(2)?;
        let peak = local_scan
            .max(remote_decode)
            .max(merge_candidate)
            .max(singular_compare)
            .max(final_encode)
            .max(proxy_copy);
        fixed_overhead
            .checked_add(transport_frame)
            .and_then(|fixed| fixed.checked_add(path_parameter_fixed))
            .and_then(|fixed| fixed.checked_add(outer_and_typed_requests))
            .and_then(|fixed| fixed.checked_add(inner_requests))
            .and_then(|fixed| fixed.checked_add(peak))
    }
    fn route_body_limit(&self) -> usize {
        self.configured_body_limit_bytes
            .min(self.envelope.route_body_bytes)
    }
}
#[cfg(feature = "app_api")]
impl ToriiRoutedReadMemoryBudget {
    fn final_body_limit(&self) -> usize {
        self.configured_body_limit_bytes
            .min(self.envelope.final_body_bytes)
    }
    fn canonical_remaining(&self) -> Result<usize, Response> {
        let remaining = self
            .envelope
            .candidate_encoded_bytes
            .checked_sub(self.retained_canonical_bytes)
            .ok_or_else(torii_routed_read_accounting_response)?;
        if remaining == 0 {
            return Err(torii_routed_read_capacity_response(
                "candidate encodings",
                1,
                0,
            ));
        }
        Ok(remaining)
    }
    fn decode_plan(&self, raw_body_bytes: usize) -> Result<ToriiRoutedReadDecodePlan, Response> {
        torii_routed_read_ensure("raw route body", raw_body_bytes, self.route_body_limit())?;
        let phase_bytes = self.envelope.decode_allocated_bytes;
        if phase_bytes == 0 {
            return Err(torii_routed_read_capacity_response(
                "decode allocations",
                1,
                0,
            ));
        }
        Ok(ToriiRoutedReadDecodePlan {
            // Core charges at least one allocation byte for every sequence
            // element. Using the physical phase for all four dimensions keeps
            // compressed expansion bounded without inventing a route cap.
            limits: norito::DecodeLimits::new(
                phase_bytes,
                phase_bytes,
                phase_bytes,
                phase_bytes,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
            canonical_limit_bytes: self.canonical_remaining()?,
        })
    }
    fn json_profile(
        &self,
        body: &[u8],
        plan: ToriiRoutedReadDecodePlan,
    ) -> Result<norito::json::JsonPreflightProfile, Response> {
        norito::json::preflight_slice(
            body,
            norito::json::JsonPreflightLimits::from_decode_limits(
                self.route_body_limit(),
                plan.limits,
            ),
        )
        .map_err(torii_routed_read_json_preflight_response)
    }
    fn retain_decode_usage(
        &mut self,
        usage: norito::core::DecodeAllocationUsage,
    ) -> Result<(), Response> {
        let decoded_bytes = usage.total_allocated_bytes();
        torii_routed_read_ensure(
            "current decode allocations",
            decoded_bytes,
            self.envelope.decode_allocated_bytes,
        )?;
        self.admit_retained_allocation(decoded_bytes)
    }
    fn admit_retained_allocation(&mut self, bytes: usize) -> Result<(), Response> {
        let retained = self
            .retained_decoded_bytes
            .checked_add(bytes)
            .ok_or_else(torii_routed_read_accounting_response)?;
        torii_routed_read_ensure(
            "retained decoded values and collection storage",
            retained,
            self.envelope.accumulator_retained_bytes,
        )?;
        self.retained_decoded_bytes = retained;
        Ok(())
    }
    /// Allocate a retained payload vector inside the accumulator phase.
    fn try_retained_vec<T>(&mut self, capacity: usize) -> Result<Vec<T>, Response> {
        let mut values = Vec::new();
        self.ensure_retained_vec_capacity(&mut values, capacity)?;
        Ok(values)
    }
    /// Grow a retained payload vector only after its requested Rust-layout capacity is admitted.
    /// Growth allocates the exact replacement layout, moves the initialized prefix, and only then
    /// releases the old layout. The old allocation during that transfer fits in the second
    /// accumulator phase because it is no larger than the newly admitted allocation.
    #[allow(unsafe_code)]
    fn ensure_retained_vec_capacity<T>(
        &mut self,
        values: &mut Vec<T>,
        additional: usize,
    ) -> Result<(), Response> {
        let required = values
            .len()
            .checked_add(additional)
            .ok_or_else(torii_routed_read_accounting_response)?;
        if required <= values.capacity() {
            return Ok(());
        }
        let element_bytes = core::mem::size_of::<T>();
        let old_bytes = values
            .capacity()
            .checked_mul(element_bytes)
            .ok_or_else(torii_routed_read_accounting_response)?;
        let requested_bytes = required
            .checked_mul(element_bytes)
            .ok_or_else(torii_routed_read_accounting_response)?;
        let requested_extra = requested_bytes
            .checked_sub(old_bytes)
            .ok_or_else(torii_routed_read_accounting_response)?;
        self.admit_retained_allocation(requested_extra)?;
        let old_len = values.len();
        let mut replacement =
            torii_routed_read_exact_vec::<T>(required, "retained payload vector", requested_bytes)?;
        if element_bytes != 0 {
            // SAFETY: `replacement` owns exactly `required >= old_len`
            // uninitialized slots. Copying transfers the initialized prefix;
            // clearing the old length prevents either value from being
            // dropped twice when the old allocation is released below.
            unsafe {
                core::ptr::copy_nonoverlapping(values.as_ptr(), replacement.as_mut_ptr(), old_len);
                replacement.set_len(old_len);
                values.set_len(0);
            }
        }
        *values = replacement;
        Ok(())
    }
    fn push_retained<T>(&mut self, values: &mut Vec<T>, value: T) -> Result<(), Response> {
        self.ensure_retained_vec_capacity(values, 1)?;
        values.push(value);
        Ok(())
    }
    fn retain_canonical_bytes(&mut self, bytes: usize) -> Result<(), Response> {
        let retained = self
            .retained_canonical_bytes
            .checked_add(bytes)
            .ok_or_else(torii_routed_read_accounting_response)?;
        torii_routed_read_ensure(
            "retained candidate encodings",
            retained,
            self.envelope.candidate_encoded_bytes,
        )?;
        self.retained_canonical_bytes = retained;
        Ok(())
    }
    /// Retain the allocator-visible capacity of a canonical byte vector.
    fn retain_canonical_capacity(&mut self, capacity: usize) -> Result<(), Response> {
        self.retain_canonical_bytes(capacity)
    }
    /// Start a JSON merge after its decode-time canonical probes were dropped.
    fn begin_json_merge(&mut self) {
        self.retained_canonical_bytes = 0;
        self.merge_allocated_bytes = 0;
    }
    /// Start a typed merge whose canonical frames remain owned by payloads.
    fn begin_typed_merge(&mut self) {
        self.merge_allocated_bytes = 0;
    }
    fn admit_merge_allocation(&mut self, bytes: usize) -> Result<(), Response> {
        let total = self
            .merge_allocated_bytes
            .checked_add(bytes)
            .ok_or_else(torii_routed_read_accounting_response)?;
        torii_routed_read_ensure(
            "merge allocations",
            total,
            self.envelope.candidate_allocation_bytes,
        )?;
        self.merge_allocated_bytes = total;
        Ok(())
    }
    /// Pre-admit standard-library B-tree nodes used by a merge index.
    fn admit_merge_btree<K, V>(&mut self, maps: usize, entries: usize) -> Result<(), Response> {
        let bytes = norito::core::owned_btree_maps_allocation_bytes::<K, V>(maps, entries)
            .map_err(|_| torii_routed_read_accounting_response())?;
        self.admit_merge_allocation(bytes)
    }
    /// Allocate a merge vector only after its complete Rust-layout request is
    /// admitted by the existing candidate-allocation phase.
    fn try_merge_vec<T>(&mut self, capacity: usize) -> Result<Vec<T>, Response> {
        let bytes = capacity
            .checked_mul(core::mem::size_of::<T>())
            .ok_or_else(torii_routed_read_accounting_response)?;
        self.admit_merge_allocation(bytes)?;
        torii_routed_read_exact_vec(capacity, "merge vector", bytes)
    }
    /// Encode one transient canonical key inside the space left beside keys that the merge has
    /// actually retained. Callers commit its byte length only if they keep the returned allocation.
    fn canonical_json_candidate(&self, value: &Value) -> Result<Vec<u8>, Response> {
        let limit = self.canonical_remaining()?;
        norito::json::to_json_bounded_boxed(value, limit)
            .map(Vec::from)
            .map_err(|_| torii_routed_read_json_encode_response())
    }
    /// Decode and inspect one typed JSON candidate without retaining a second representation.
    ///
    /// The borrowed `Value` remains the canonical row representation. Its temporary JSON bytes and
    /// typed value occupy the candidate-encoding and transient decode phases respectively, and both
    /// are dropped before this method returns.
    fn inspect_typed_json_candidate<T, D, F>(
        &self,
        value: &Value,
        invalid_message: &'static str,
        decode: D,
        inspect: F,
    ) -> Result<(), Response>
    where
        D: FnOnce(&Value) -> Result<T, norito::json::Error>,
        F: FnOnce(&T) -> Result<(), Response>,
    {
        let canonical_limit = self.canonical_remaining()?;
        let _canonical = norito::json::to_json_bounded_boxed(value, canonical_limit)
            .map_err(|_| torii_routed_read_json_encode_response())?;
        let allocation_limit = self.envelope.decode_allocated_bytes;
        if allocation_limit == 0 {
            return Err(torii_routed_read_capacity_response(
                "typed candidate decode allocations",
                1,
                0,
            ));
        }
        let limits = norito::DecodeLimits::new(
            allocation_limit,
            allocation_limit,
            allocation_limit,
            allocation_limit,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        );
        let (typed, usage) = norito::core::with_decode_limits_measured(limits, || decode(value));
        let typed = typed.map_err(|error| {
            if error.is_decode_resource_limit() {
                torii_routed_read_json_decode_response(error)
            } else {
                torii_internal_json_error(invalid_message)
            }
        })?;
        torii_routed_read_ensure(
            "typed candidate decode allocations",
            usage.total_allocated_bytes(),
            allocation_limit,
        )?;
        inspect(&typed)
    }
    fn json_response<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        value: &T,
    ) -> Result<Response, Response> {
        let body = self.json_body(value)?;
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .body(Body::from(Bytes::from(body)))
            .expect("build preflighted routed-read JSON response"))
    }
    fn json_body<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        value: &T,
    ) -> Result<Box<[u8]>, Response> {
        let limit = self.final_body_limit();
        norito::json::to_json_bounded_boxed(value, limit)
            .map_err(|_| torii_routed_read_json_encode_response())
    }
    /// Verify that native `Value` parser charges cover every owned graph node.
    fn verify_json_value_usage(
        &self,
        profile: norito::json::JsonPreflightProfile,
        usage: norito::core::DecodeAllocationUsage,
    ) -> Result<(), Response> {
        let graph_bytes = torii_routed_read_json_value_graph_bytes(profile)?;
        torii_routed_read_ensure(
            "decoded JSON graph",
            graph_bytes,
            self.envelope.decode_allocated_bytes,
        )?;
        if usage.total_allocated_bytes() < graph_bytes {
            return Err(torii_proxy_error_response(
                StatusCode::BAD_GATEWAY,
                "route_unavailable",
                "proxied JSON decoder did not account for its complete owned value graph",
            ));
        }
        Ok(())
    }
}
/// Allocate a `Vec` with exactly the admitted non-ZST element layout.
///
/// `Vec::try_reserve_exact` is permitted to return spare capacity. Observing and charging that
/// excess after allocation is too late for a strict peak proof, so routed-read retained and merge
/// vectors use the allocator directly after their complete byte request has been admitted.
#[allow(unsafe_code)]
#[cfg(feature = "app_api")]
fn torii_routed_read_exact_vec<T>(
    capacity: usize,
    label: &'static str,
    admitted_bytes: usize,
) -> Result<Vec<T>, Response> {
    if capacity == 0 || core::mem::size_of::<T>() == 0 {
        return Ok(Vec::new());
    }
    let layout = std::alloc::Layout::array::<T>(capacity)
        .map_err(|_| torii_routed_read_allocation_response(label, admitted_bytes))?;
    debug_assert_eq!(layout.size(), admitted_bytes);
    // SAFETY: `layout` is non-zero and describes exactly `capacity` elements.
    // Null is rejected before ownership is constructed; `Vec` later
    // deallocates the identical capacity/alignment layout.
    let allocation = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    let allocation = core::ptr::NonNull::new(allocation)
        .ok_or_else(|| torii_routed_read_allocation_response(label, admitted_bytes))?;
    // SAFETY: the allocation above owns `capacity` uninitialized `T` slots.
    Ok(unsafe { Vec::from_raw_parts(allocation.as_ptr(), 0, capacity) })
}
/// Heap bytes reachable from a native JSON `Value` after parsing.
///
/// Strings and arrays use the parser's exact-reserve requests. The lexical profile sums Norito
/// core's original parser allocation charge separately for every object, including the leaf/split
/// boundary, so empty and differently sized objects cannot inflate one another's topology charge.
/// The parser separately charges any
/// allocator capacity returned above an exact-reserve request.
#[cfg(feature = "app_api")]
fn torii_routed_read_json_value_graph_bytes(
    profile: norito::json::JsonPreflightProfile,
) -> Result<usize, Response> {
    let array_bytes = profile
        .array_entries()
        .checked_mul(core::mem::size_of::<Value>())
        .ok_or_else(torii_routed_read_accounting_response)?;
    let object_bytes = profile.object_btree_allocation_bytes();
    profile
        .string_capacity_bytes()
        .checked_add(array_bytes)
        .and_then(|bytes| bytes.checked_add(object_bytes))
        .ok_or_else(torii_routed_read_accounting_response)
}
#[cfg(feature = "app_api")]
fn torii_routed_read_request_bytes(
    path_args: &[String],
    path_arg_capacity: usize,
    query_string: Option<&String>,
    body_capacity: usize,
) -> Result<usize, Response> {
    let path_container_bytes = path_arg_capacity
        .checked_mul(core::mem::size_of::<String>())
        .ok_or_else(torii_routed_read_accounting_response)?;
    let initial_bytes = body_capacity
        .checked_add(path_container_bytes)
        .ok_or_else(torii_routed_read_accounting_response)?;
    path_args
        .iter()
        .try_fold(initial_bytes, |bytes, arg| {
            bytes.checked_add(arg.capacity())
        })
        .and_then(|bytes| bytes.checked_add(query_string.map_or(0, String::capacity)))
        .ok_or_else(torii_routed_read_accounting_response)
}
#[cfg(feature = "app_api")]
fn torii_routed_read_ensure(
    phase: &'static str,
    attempted: usize,
    limit: usize,
) -> Result<(), Response> {
    if attempted > limit {
        return Err(torii_routed_read_capacity_response(phase, attempted, limit));
    }
    Ok(())
}
#[cfg(feature = "app_api")]
fn torii_routed_read_capacity_response(
    phase: &'static str,
    attempted: usize,
    limit: usize,
) -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        format!(
            "proxied application response exceeded its admitted {phase} bound (attempted {attempted}, limit {limit})"
        ),
    )
}
#[cfg(feature = "app_api")]
fn torii_routed_read_accounting_response() -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        "proxied application response memory accounting overflowed",
    )
}
#[cfg(feature = "app_api")]
fn torii_routed_read_allocation_response(phase: &'static str, bytes: usize) -> Response {
    torii_proxy_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "route_unavailable",
        format!("failed to reserve the admitted {bytes}-byte {phase}"),
    )
}
#[cfg(feature = "app_api")]
fn torii_routed_read_json_preflight_response(error: norito::json::JsonPreflightError) -> Response {
    if error.resource_kind().is_some() {
        return torii_routed_read_capacity_response(
            "JSON lexical resource",
            error.attempted(),
            error.limit(),
        );
    }
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        "proxied JSON response failed bounded lexical validation",
    )
}
/// Consume a hostile parser error without reflecting payload-derived text.
#[cfg(feature = "app_api")]
fn torii_routed_read_json_decode_response(_: norito::json::Error) -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        "proxied JSON response failed bounded decoding",
    )
}
/// Consume a hostile binary decoder error without reflecting payload bytes.
#[cfg(feature = "app_api")]
fn torii_routed_read_norito_decode_response(_: norito::Error) -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        "proxied Norito response failed bounded decoding",
    )
}
#[cfg(feature = "app_api")]
fn torii_routed_read_body_response() -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        "proxied application response body exceeded its admitted bound",
    )
}
#[cfg(feature = "app_api")]
fn torii_routed_read_norito_encode_response() -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        "proxied Norito response exceeded its bounded canonical representation",
    )
}
#[cfg(feature = "app_api")]
fn torii_routed_read_json_encode_response() -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_GATEWAY,
        "route_unavailable",
        "proxied JSON response exceeded its bounded canonical representation",
    )
}
#[cfg(all(test, feature = "app_api"))]
include!("tests/lib_routed_reads/routed_read_memory_bounds.rs");
