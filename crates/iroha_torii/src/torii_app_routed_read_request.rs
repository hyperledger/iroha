// Allocation-bounded request decoding for application-API routed reads.
/// Maximum number of non-empty form pairs accepted by the V1 routed-read control plane.
///
/// Current endpoint DTOs use fewer than sixteen fields. Sixty-four pairs leave room for composed
/// first-release filters while bounding duplicate detection to 4,096 key comparisons.
const TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1: usize = 64;
#[derive(Clone, Copy, Debug)]
struct ToriiRoutedReadRequestDecodePlan {
    raw_input_limit_bytes: usize,
    expanded_query_limit_bytes: usize,
    component_limit_bytes: usize,
    typed_limits: norito::DecodeLimits,
}
impl ToriiRoutedReadMemoryBudget {
    #[cfg(feature = "app_api")]
    fn request_decode_plan(&self) -> Result<ToriiRoutedReadRequestDecodePlan, Response> {
        let bytes = self.route_body_limit();
        if !self.app_request_phases_fit(bytes) {
            return Err(torii_routed_read_request_capacity_response(
                "application request high-water",
                bytes,
                self.envelope.route_body_bytes,
            ));
        }
        self.request_decode_plan_with_path_fixed(app_routed_read_url_parameter_fixed_bytes())
    }
    fn request_decode_plan_for_path(
        &self,
        path: &str,
    ) -> Result<ToriiRoutedReadRequestDecodePlan, Response> {
        let mut parameters = 0usize;
        let mut key_bytes = 0usize;
        for segment in path.split('/') {
            if let Some(key) = segment
                .strip_prefix('{')
                .and_then(|segment| segment.strip_suffix('}'))
            {
                parameters = parameters.saturating_add(1);
                key_bytes = key_bytes.saturating_add(key.len());
            }
        }
        self.request_decode_plan_with_path_fixed(routed_read_url_parameter_fixed_bytes(
            parameters, key_bytes,
        ))
    }
    fn request_decode_plan_with_path_fixed(
        &self,
        path_fixed: Option<usize>,
    ) -> Result<ToriiRoutedReadRequestDecodePlan, Response> {
        let phase_bytes = self.envelope.request_decode_allocated_bytes;
        if phase_bytes == 0 {
            return Err(torii_routed_read_request_capacity_response(
                "typed decode allocations",
                1,
                0,
            ));
        }
        let baseline_fixed = app_routed_read_url_parameter_fixed_bytes();
        let fits = |bytes: usize| {
            self.app_request_high_water_bytes(bytes)
                .and_then(|total| total.checked_sub(baseline_fixed?))
                .and_then(|total| total.checked_add(path_fixed?))
                .is_some_and(|total| total <= self.envelope.working_set_bytes)
        };
        if !fits(0) {
            return Err(torii_routed_read_request_capacity_response(
                "request path geometry",
                usize::MAX,
                self.envelope.working_set_bytes,
            ));
        }
        // Shrink the accepted target if the exact path graph requires more
        // space. The original total and every response/decode phase stay fixed.
        let mut low = 0usize;
        let mut high = self.route_body_limit();
        while low < high {
            let mid = low + (high - low) / 2 + 1;
            if fits(mid) {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        let raw_input_limit_bytes = low;
        Ok(ToriiRoutedReadRequestDecodePlan {
            raw_input_limit_bytes,
            // Form decoding can expand percent-decoded controls when they are
            // escaped into JSON. The exact two-unit final-body phase is idle
            // during request decoding and bounds that intermediate document.
            expanded_query_limit_bytes: self.envelope.final_body_bytes,
            component_limit_bytes: raw_input_limit_bytes,
            typed_limits: norito::DecodeLimits::new(
                phase_bytes,
                phase_bytes,
                phase_bytes,
                phase_bytes,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
        })
    }
}
/// Configuration geometry only validates framing before acquiring the owner.
#[cfg(all(test, feature = "app_api"))]
fn torii_routed_read_request_preflight_plan(
    app: &SharedAppState,
) -> Result<ToriiRoutedReadRequestDecodePlan, Response> {
    ToriiRoutedReadMemoryBudget::new(
        app.query_fanout_working_set_bytes,
        app.torii_proxy_max_response_bytes,
    )?
    .request_decode_plan()
}
#[cfg(feature = "app_api")]
fn torii_routed_read_request_decode_plan(
    app: &SharedAppState,
) -> Result<ToriiRoutedReadRequestDecodePlan, Response> {
    ToriiRoutedReadMemoryBudget::from_envelope(
        current_routed_read_memory_envelope(app)?,
        app.torii_proxy_max_response_bytes,
    )
    .request_decode_plan()
}
impl ToriiRoutedReadRequestDecodePlan {
    fn admit_raw_input(self, bytes: usize) -> Result<(), Response> {
        if bytes > self.raw_input_limit_bytes {
            return Err(torii_routed_read_request_capacity_response(
                "raw input",
                bytes,
                self.raw_input_limit_bytes,
            ));
        }
        Ok(())
    }
    #[cfg(feature = "app_api")]
    fn preflight_json(self, bytes: &[u8]) -> Result<norito::json::JsonPreflightProfile, Response> {
        self.admit_raw_input(bytes.len())?;
        norito::json::preflight_slice(
            bytes,
            norito::json::JsonPreflightLimits::from_decode_limits(
                self.raw_input_limit_bytes,
                self.typed_limits,
            ),
        )
        .map_err(torii_routed_read_request_preflight_response)
    }
}
#[cfg(feature = "app_api")]
fn decode_torii_proxy_json_body<T>(
    plan: ToriiRoutedReadRequestDecodePlan,
    body: &[u8],
    label: &str,
) -> Result<T, Response>
where
    T: norito::json::JsonDeserializeOwned,
{
    let _profile = plan.preflight_json(body)?;
    decode_torii_routed_read_typed_json(plan, body, label)
}
#[cfg(feature = "app_api")]
fn decode_torii_proxy_query<T>(
    plan: ToriiRoutedReadRequestDecodePlan,
    query_string: Option<&str>,
) -> Result<T, Response>
where
    T: norito::json::JsonDeserializeOwned,
{
    decode_torii_proxy_query_with_coercion(plan, query_string, true)
}
#[cfg(feature = "app_api")]
fn decode_torii_proxy_string_query<T>(
    plan: ToriiRoutedReadRequestDecodePlan,
    query_string: Option<&str>,
) -> Result<T, Response>
where
    T: norito::json::JsonDeserializeOwned,
{
    decode_torii_proxy_query_with_coercion(plan, query_string, false)
}
#[cfg(feature = "app_api")]
fn decode_torii_proxy_query_with_coercion<T>(
    plan: ToriiRoutedReadRequestDecodePlan,
    query_string: Option<&str>,
    coerce_scalars: bool,
) -> Result<T, Response>
where
    T: norito::json::JsonDeserializeOwned,
{
    if query_string == Some("") {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_request",
            "A present proxied query must contain at least one key=value pair.",
        ));
    }
    let raw = query_string.unwrap_or_default();
    plan.admit_raw_input(raw.len())?;
    let pair_count = torii_form_pairs(raw.as_bytes()).count();
    if pair_count > TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1 {
        return Err(torii_routed_read_request_capacity_response(
            "form pair count",
            pair_count,
            TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1,
        ));
    }
    validate_app_routed_read_form(raw.as_bytes(), plan)?;
    // The checked serializer performs an allocation-free count, then writes
    // one exact intermediate JSON allocation. It owns at most one exact
    // decoded key or value component at a time. The component is dropped
    // before the typed decode starts, so the peak is raw request
    // representations + one component + the two-unit JSON document, or raw
    // representations + the JSON document + one typed-decode phase. Both fit
    // the admitted App request geometry.
    let query = ToriiRoutedReadFormJson {
        raw,
        plan,
        coerce_scalars,
    };
    let json = norito::json::to_json_bounded_boxed(&query, plan.expanded_query_limit_bytes)
        .map_err(|error| {
            torii_routed_read_form_encode_response(error, plan.expanded_query_limit_bytes)
        })?;
    decode_torii_routed_read_typed_json(plan, &json, "query parameters")
}
#[cfg(feature = "app_api")]
fn decode_current_app_routed_read_json<T>(body: &[u8]) -> Option<Result<T, Response>>
where
    T: norito::json::JsonDeserializeOwned,
{
    current_app_routed_read_decode_plan().map(|plan| {
        let _profile = plan
            .preflight_json(body)
            .map_err(map_app_routed_read_request_response)?;
        decode_app_routed_read_typed_json(plan, body, "request JSON")
    })
}
#[cfg(feature = "app_api")]
macro_rules! decode_admitted_app_routed_read_json {
    ($body:expr, $fallback:expr) => {{
        match decode_current_app_routed_read_json($body) {
            Some(Ok(value)) => value,
            Some(Err(response)) => return Ok(response),
            None => $fallback,
        }
    }};
}
#[cfg(feature = "app_api")]
fn decode_current_app_routed_read_norito<T>(body: &[u8]) -> Option<Result<T, Response>>
where
    T: crate::utils::extractors::SupportsNoritoDecode + 'static,
{
    current_app_routed_read_decode_plan().map(|plan| {
        plan.admit_raw_input(body.len())
            .map_err(map_app_routed_read_request_response)?;
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(plan.typed_limits, || T::decode_norito(body));
        match decoded {
            Ok(value)
                if usage.total_allocated_bytes()
                    <= plan.typed_limits.max_total_allocated_bytes() =>
            {
                Ok(value)
            }
            Ok(_) | Err(_)
                if usage.total_allocated_bytes()
                    > plan.typed_limits.max_total_allocated_bytes() =>
            {
                Err(app_routed_read_request_capacity_response(
                    "typed Norito decode allocations",
                    usage.total_allocated_bytes(),
                    plan.typed_limits.max_total_allocated_bytes(),
                ))
            }
            Ok(value) => Ok(value),
            Err(error) if error.is_decode_resource_limit() => {
                Err(app_routed_read_request_capacity_response(
                    "typed Norito decode resources",
                    plan.typed_limits
                        .max_total_allocated_bytes()
                        .saturating_add(1),
                    plan.typed_limits.max_total_allocated_bytes(),
                ))
            }
            Err(_) => Err(torii_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "request_norito_invalid",
                "The Norito body failed bounded decoding.",
            )),
        }
    })
}
fn decode_current_app_routed_read_query<T>(
    query: &str,
    coerce_scalars: bool,
) -> Option<Result<T, Response>>
where
    T: norito::json::JsonDeserializeOwned,
{
    current_app_routed_read_decode_plan().map(|plan| {
        plan.admit_raw_input(query.len())
            .map_err(map_app_routed_read_request_response)?;
        let pairs = torii_form_pairs(query.as_bytes());
        let pair_count = pairs.count();
        if pair_count > TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1 {
            return Err(app_routed_read_request_capacity_response(
                "form pair count",
                pair_count,
                TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1,
            ));
        }
        validate_app_routed_read_form(query.as_bytes(), plan)?;
        // Canonicalization owns its explicit two-unit destination and one
        // component at a time. It deliberately runs outside the typed P-sized
        // decode scope; the exact JSON allocation is dropped only after the
        // subsequent measured typed decode returns.
        let form = ToriiRoutedReadFormJson {
            raw: query,
            plan,
            coerce_scalars,
        };
        let json = norito::json::to_json_bounded_boxed(&form, plan.expanded_query_limit_bytes)
            .map_err(|error| {
                app_routed_read_form_encode_response(error, plan.expanded_query_limit_bytes)
            })?;
        decode_app_routed_read_typed_json(plan, &json, "query parameters")
    })
}
fn validate_app_routed_read_form(
    raw: &[u8],
    plan: ToriiRoutedReadRequestDecodePlan,
) -> Result<(), Response> {
    if !raw.is_empty() {
        for sequence in raw.split(|byte| *byte == b'&') {
            if sequence.is_empty() {
                return Err(torii_proxy_error_response(
                    StatusCode::BAD_REQUEST,
                    "request_query_invalid",
                    "Query parameters must not contain empty segments.",
                ));
            }
            let mut separators = sequence
                .iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'=');
            let Some((separator, _)) = separators.next() else {
                return Err(torii_proxy_error_response(
                    StatusCode::BAD_REQUEST,
                    "request_query_invalid",
                    "Every query parameter must use key=value framing.",
                ));
            };
            if separator == 0 || separator + 1 == sequence.len() {
                return Err(torii_proxy_error_response(
                    StatusCode::BAD_REQUEST,
                    "request_query_invalid",
                    "Query parameter names and values must be non-empty.",
                ));
            }
        }
    }
    for (index, pair) in torii_form_pairs(raw).enumerate() {
        validate_app_routed_read_form_component(pair.key)?;
        validate_app_routed_read_form_component(pair.value)?;
        let key =
            torii_exact_form_component(pair.key, plan.component_limit_bytes).map_err(|error| {
                app_routed_read_form_encode_response(error, plan.component_limit_bytes)
            })?;
        let value = torii_exact_form_component(pair.value, plan.component_limit_bytes).map_err(
            |error| app_routed_read_form_encode_response(error, plan.component_limit_bytes),
        )?;
        if std::str::from_utf8(&key)
            .into_iter()
            .chain(std::str::from_utf8(&value))
            .flat_map(str::chars)
            .any(char::is_control)
        {
            return Err(torii_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "request_query_invalid",
                "Query parameters must not contain control characters.",
            ));
        }
        if torii_form_pairs(raw).skip(index + 1).any(|later| {
            key.iter()
                .copied()
                .eq(ToriiFormDecodedBytes::new(later.key))
        }) {
            return Err(torii_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "request_query_invalid",
                "Query parameters contain a duplicate decoded key.",
            ));
        }
    }
    Ok(())
}
fn validate_app_routed_read_form_component(raw: &[u8]) -> Result<(), Response> {
    // Ordinary RFC 3986 / HTML-form spelling; see `utils::decode_component`.
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'%' => {
                let escape = raw.get(index + 1..index + 3);
                if !escape.is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit)) {
                    return Err(torii_proxy_error_response(
                        StatusCode::BAD_REQUEST,
                        "request_query_invalid",
                        "Query parameters contain an incomplete percent escape; write a literal `%` as `%25`.",
                    ));
                }
                index += 3;
            }
            byte if byte.is_ascii_graphic() => index += 1,
            _ => {
                return Err(torii_proxy_error_response(
                    StatusCode::BAD_REQUEST,
                    "request_query_invalid",
                    "Query parameters must percent-encode spaces, control characters and non-ASCII bytes.",
                ));
            }
        }
    }
    Ok(())
}
fn decode_app_routed_read_typed_json<T>(
    plan: ToriiRoutedReadRequestDecodePlan,
    bytes: &[u8],
    _label: &str,
) -> Result<T, Response>
where
    T: norito::json::JsonDeserializeOwned,
{
    let (decoded, usage) = norito::core::with_decode_limits_measured(plan.typed_limits, || {
        norito::json::from_slice::<T>(bytes)
    });
    match decoded {
        Ok(value)
            if usage.total_allocated_bytes() <= plan.typed_limits.max_total_allocated_bytes() =>
        {
            Ok(value)
        }
        Ok(_) | Err(_)
            if usage.total_allocated_bytes() > plan.typed_limits.max_total_allocated_bytes() =>
        {
            Err(app_routed_read_request_capacity_response(
                "typed decode allocations",
                usage.total_allocated_bytes(),
                plan.typed_limits.max_total_allocated_bytes(),
            ))
        }
        Ok(value) => Ok(value),
        Err(error) if error.is_decode_resource_limit() => {
            Err(app_routed_read_request_capacity_response(
                "typed decode resources",
                plan.typed_limits
                    .max_total_allocated_bytes()
                    .saturating_add(1),
                plan.typed_limits.max_total_allocated_bytes(),
            ))
        }
        Err(_) => Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_json_invalid",
            "The JSON request failed bounded decoding.",
        )),
    }
}
fn map_app_routed_read_request_response(mut response: Response) -> Response {
    if response.status() == StatusCode::BAD_REQUEST {
        response = torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_json_invalid",
            "The JSON request failed bounded lexical validation.",
        );
    }
    response
}
fn app_routed_read_request_capacity_response(
    phase: &'static str,
    attempted: usize,
    limit: usize,
) -> Response {
    torii_proxy_error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "query_capacity_exceeded",
        format!(
            "Application routed-read request exceeded its admitted {phase} bound (attempted {attempted}, limit {limit})."
        ),
    )
}
fn app_routed_read_form_encode_response(
    error: norito::json::BoundedJsonError,
    limit: usize,
) -> Response {
    match error {
        norito::json::BoundedJsonError::BodyTooLarge => app_routed_read_request_capacity_response(
            "expanded form JSON",
            limit.saturating_add(1),
            limit,
        ),
        norito::json::BoundedJsonError::AllocationFailed
        | norito::json::BoundedJsonError::ScopedDecodeResource(_)
        | norito::json::BoundedJsonError::DecodeResource(_) => torii_proxy_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "route_unavailable",
            "The admitted query canonicalization destination could not be allocated.",
        ),
        norito::json::BoundedJsonError::Unsupported
        | norito::json::BoundedJsonError::LengthMismatch => torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_query_invalid",
            "Query parameters failed bounded canonicalization.",
        ),
    }
}
#[cfg(feature = "app_api")]
fn decode_torii_routed_read_typed_json<T>(
    plan: ToriiRoutedReadRequestDecodePlan,
    bytes: &[u8],
    _label: &str,
) -> Result<T, Response>
where
    T: norito::json::JsonDeserializeOwned,
{
    let (decoded, usage) = norito::core::with_decode_limits_measured(plan.typed_limits, || {
        norito::json::from_slice::<T>(bytes)
    });
    match decoded {
        Ok(value) => {
            if usage.total_allocated_bytes() > plan.typed_limits.max_total_allocated_bytes() {
                return Err(torii_routed_read_request_capacity_response(
                    "typed decode allocations",
                    usage.total_allocated_bytes(),
                    plan.typed_limits.max_total_allocated_bytes(),
                ));
            }
            Ok(value)
        }
        Err(error) if error.is_decode_resource_limit() => {
            Err(torii_routed_read_request_capacity_response(
                "typed decode resources",
                plan.typed_limits
                    .max_total_allocated_bytes()
                    .saturating_add(1),
                plan.typed_limits.max_total_allocated_bytes(),
            ))
        }
        Err(_) => Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_request",
            "proxied application request failed bounded JSON decoding",
        )),
    }
}
#[cfg(feature = "app_api")]
fn torii_routed_read_request_preflight_response(
    error: norito::json::JsonPreflightError,
) -> Response {
    if error.resource_kind().is_some() {
        return torii_routed_read_request_capacity_response(
            "JSON lexical resource",
            error.attempted(),
            error.limit(),
        );
    }
    torii_proxy_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_proxy_request",
        "proxied application request failed bounded JSON lexical validation",
    )
}
fn torii_routed_read_request_capacity_response(
    phase: &'static str,
    attempted: usize,
    limit: usize,
) -> Response {
    torii_proxy_error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "query_capacity_exceeded",
        format!(
            "proxied application request exceeded its admitted {phase} bound (attempted {attempted}, limit {limit})"
        ),
    )
}
#[cfg(feature = "app_api")]
fn torii_routed_read_form_encode_response(
    error: norito::json::BoundedJsonError,
    limit: usize,
) -> Response {
    match error {
        norito::json::BoundedJsonError::BodyTooLarge => {
            torii_routed_read_request_capacity_response(
                "expanded form JSON",
                limit.saturating_add(1),
                limit,
            )
        }
        norito::json::BoundedJsonError::AllocationFailed
        | norito::json::BoundedJsonError::ScopedDecodeResource(_)
        | norito::json::BoundedJsonError::DecodeResource(_) => torii_proxy_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "route_unavailable",
            "proxied form query could not reserve its admitted JSON destination",
        ),
        norito::json::BoundedJsonError::Unsupported
        | norito::json::BoundedJsonError::LengthMismatch => torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_request",
            "proxied form query failed bounded canonicalization",
        ),
    }
}
#[derive(Clone, Copy)]
struct ToriiFormPair<'a> {
    key: &'a [u8],
    value: &'a [u8],
}
fn torii_form_pairs(raw: &[u8]) -> impl Iterator<Item = ToriiFormPair<'_>> {
    raw.split(|byte| *byte == b'&')
        .filter(|sequence| !sequence.is_empty())
        .map(|sequence| {
            let separator = sequence
                .iter()
                .position(|byte| *byte == b'=')
                .unwrap_or(sequence.len());
            let key = &sequence[..separator];
            let value = if separator < sequence.len() {
                &sequence[separator + 1..]
            } else {
                &[]
            };
            ToriiFormPair { key, value }
        })
}
#[derive(Clone)]
struct ToriiFormDecodedBytes<'a> {
    raw: &'a [u8],
    index: usize,
}
impl<'a> ToriiFormDecodedBytes<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, index: 0 }
    }
}
impl Iterator for ToriiFormDecodedBytes<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        let byte = *self.raw.get(self.index)?;
        if byte == b'+' {
            self.index += 1;
            return Some(b' ');
        }
        if byte == b'%'
            && let (Some(high), Some(low)) = (
                self.raw
                    .get(self.index + 1)
                    .and_then(|byte| torii_hex(*byte)),
                self.raw
                    .get(self.index + 2)
                    .and_then(|byte| torii_hex(*byte)),
            )
        {
            self.index += 3;
            return Some((high << 4) | low);
        }
        self.index += 1;
        Some(byte)
    }
}
const fn torii_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
#[allow(unsafe_code)]
fn torii_exact_form_component(
    raw: &[u8],
    limit: usize,
) -> Result<Box<[u8]>, norito::json::BoundedJsonError> {
    if !torii_form_component_has_valid_percent_encoding(raw) {
        return Err(norito::json::BoundedJsonError::Unsupported);
    }
    let length = ToriiFormDecodedBytes::new(raw).count();
    if length > limit {
        return Err(norito::json::BoundedJsonError::BodyTooLarge);
    }
    let mut output = torii_allocate_exact_bytes(length)?;
    for (slot, byte) in output.iter_mut().zip(ToriiFormDecodedBytes::new(raw)) {
        slot.write(byte);
    }
    // SAFETY: the decoded iterator yields exactly `length` bytes, so every
    // element in the allocation was initialized by the loop above.
    let output = unsafe { Box::from_raw(Box::into_raw(output) as *mut [u8]) };
    if std::str::from_utf8(&output).is_err() {
        return Err(norito::json::BoundedJsonError::Unsupported);
    }
    Ok(output)
}
fn torii_form_component_has_valid_percent_encoding(raw: &[u8]) -> bool {
    let mut index = 0;
    while index < raw.len() {
        if raw[index] != b'%' {
            index += 1;
            continue;
        }
        if raw
            .get(index + 1)
            .and_then(|byte| torii_hex(*byte))
            .is_none()
            || raw
                .get(index + 2)
                .and_then(|byte| torii_hex(*byte))
                .is_none()
        {
            return false;
        }
        index += 3;
    }
    true
}
#[allow(unsafe_code)]
fn torii_allocate_exact_bytes(
    length: usize,
) -> Result<Box<[std::mem::MaybeUninit<u8>]>, norito::json::BoundedJsonError> {
    if length == 0 {
        return Ok(Vec::new().into_boxed_slice());
    }
    let layout = std::alloc::Layout::array::<std::mem::MaybeUninit<u8>>(length)
        .map_err(|_| norito::json::BoundedJsonError::AllocationFailed)?;
    // SAFETY: `layout` is non-zero and was constructed for exactly `length`
    // bytes. Null is handled before the pointer becomes an owning box.
    let allocation = unsafe { std::alloc::alloc(layout) }.cast::<std::mem::MaybeUninit<u8>>();
    if allocation.is_null() {
        return Err(norito::json::BoundedJsonError::AllocationFailed);
    }
    let slice = std::ptr::slice_from_raw_parts_mut(allocation, length);
    // SAFETY: the allocation owns exactly the layout of this boxed slice.
    Ok(unsafe { Box::from_raw(slice) })
}
struct ToriiRoutedReadFormJson<'a> {
    raw: &'a str,
    plan: ToriiRoutedReadRequestDecodePlan,
    coerce_scalars: bool,
}
impl norito::json::FastJsonWrite for ToriiRoutedReadFormJson<'_> {
    fn write_json(&self, output: &mut String) {
        norito::json::write_json_unbounded(self, output);
    }
    fn write_json_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        let pair_count = torii_form_pairs(self.raw.as_bytes()).count();
        if pair_count > TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1 {
            return Err(norito::json::BoundedJsonError::BodyTooLarge);
        }
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push('{')?;
            let mut first = true;
            for pair in torii_form_pairs(self.raw.as_bytes()) {
                let key = torii_exact_form_component(pair.key, self.plan.component_limit_bytes)?;
                let key_text = std::str::from_utf8(&key)
                    .map_err(|_| norito::json::BoundedJsonError::Unsupported)?;
                if !first {
                    output.push(',')?;
                }
                first = false;
                norito::json::write_json_string_to(key_text, output)?;
                drop(key);
                output.push(':')?;
                let value =
                    torii_exact_form_component(pair.value, self.plan.component_limit_bytes)?;
                let value = std::str::from_utf8(&value)
                    .map_err(|_| norito::json::BoundedJsonError::Unsupported)?;
                if self.coerce_scalars {
                    torii_write_form_scalar(value, output)?;
                } else {
                    norito::json::write_json_string_to(value, output)?;
                }
            }
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}
fn torii_write_form_scalar(
    value: &str,
    output: &mut dyn norito::json::JsonWriteSink,
) -> Result<(), norito::json::BoundedJsonError> {
    use norito::json::JsonSerialize as _;
    if value == "null" {
        output.push_str("null")
    } else if value == "true" {
        output.push_str("true")
    } else if value == "false" {
        output.push_str("false")
    } else if torii_canonical_unsigned_decimal(value)
        && let Ok(value) = value.parse::<u64>()
    {
        value.json_serialize_to(output)
    } else if torii_canonical_negative_decimal(value)
        && let Ok(value) = value.parse::<i64>()
    {
        value.json_serialize_to(output)
    } else {
        norito::json::write_json_string_to(value, output)
    }
}
fn torii_canonical_unsigned_decimal(raw: &str) -> bool {
    raw == "0"
        || raw.as_bytes().split_first().is_some_and(|(first, rest)| {
            matches!(*first, b'1'..=b'9') && rest.iter().all(u8::is_ascii_digit)
        })
}
fn torii_canonical_negative_decimal(raw: &str) -> bool {
    raw.strip_prefix('-')
        .is_some_and(|magnitude| magnitude != "0" && torii_canonical_unsigned_decimal(magnitude))
}
#[cfg(all(test, feature = "app_api"))]
mod torii_routed_read_request_tests {
    use super::*;
    #[test]
    fn form_decoder_accepts_only_exact_utf8() {
        let valid: &[&[u8]] = &[
            b"plain",
            b"plus+space",
            b"percent%20space",
            b"%F0%9F%92%96",
            b"%2B+%25",
        ];
        for raw in valid {
            let encoded = [b"k=".as_slice(), *raw].concat();
            let expected = url::form_urlencoded::parse(&encoded)
                .next()
                .expect("one form pair")
                .1
                .into_owned();
            let actual =
                torii_exact_form_component(raw, usize::MAX).expect("corpus component decodes");
            assert_eq!(std::str::from_utf8(&actual).expect("valid UTF-8"), expected);
        }
        for raw in [
            b"%00%9F%92%96".as_slice(),
            b"%E2%82tail".as_slice(),
            b"bad%GGpercent".as_slice(),
        ] {
            assert!(
                matches!(
                    torii_exact_form_component(raw, usize::MAX),
                    Err(norito::json::BoundedJsonError::Unsupported)
                ),
                "raw={}",
                String::from_utf8_lossy(raw)
            );
        }
    }
    #[test]
    fn query_pair_limit_is_exact_with_unique_keys() {
        let phase = 64 * 1024;
        let plan =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .expect("test geometry")
                .request_decode_plan()
                .expect("request plan");
        let exact = (0..TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1)
            .map(|index| format!("k{index}={index}"))
            .collect::<Vec<_>>()
            .join("&");
        let decoded = decode_torii_proxy_query::<norito::json::Value>(plan, Some(&exact))
            .expect("exact pair count decodes");
        assert_eq!(
            decoded.as_object().map(norito::json::Map::len),
            Some(TORII_ROUTED_READ_MAX_QUERY_PAIRS_V1)
        );
        let oversized = format!("{exact}&overflow=1");
        let response = decode_torii_proxy_query::<norito::json::Value>(plan, Some(&oversized))
            .expect_err("pair limit plus one is rejected");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[test]
    fn proxy_queries_reject_duplicate_decoded_keys_and_malformed_percent_encoding() {
        let phase = 64 * 1024;
        let plan =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .expect("test geometry")
                .request_decode_plan()
                .expect("request plan");
        for query in [
            "limit=7&limit=9",
            "%6cimit=7&limit=9",
            "limit=%",
            "limit=%FF",
        ] {
            let response = decode_torii_proxy_query::<Value>(plan, Some(query))
                .expect_err("noncanonical query must fail");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query={query}");
            assert_eq!(
                response
                    .headers()
                    .get("x-iroha-reject-code")
                    .and_then(|value| value.to_str().ok()),
                Some("request_query_invalid"),
                "query={query}"
            );
        }
        for query in ["hash=a&hash=b", "%68ash=a&hash=b", "hash=%", "hash=%C0%AF"] {
            let response =
                decode_torii_proxy_string_query::<PipelineStatusQuery>(plan, Some(query))
                    .expect_err("noncanonical string query must fail");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query={query}");
            assert_eq!(
                response
                    .headers()
                    .get("x-iroha-reject-code")
                    .and_then(|value| value.to_str().ok()),
                Some("request_query_invalid"),
                "query={query}"
            );
        }
    }
    #[test]
    fn routed_queries_decode_rfc3986_spellings_and_reject_bad_framing() {
        let phase = 64 * 1024;
        let plan =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .expect("test geometry")
                .request_decode_plan()
                .expect("request plan");
        for query in [
            "",
            "&",
            "limit",
            "=7",
            "limit=",
            "limit=7&",
            "&limit=7",
            "limit=7&&offset=0",
            "label=%0A",
        ] {
            let response = decode_torii_proxy_query::<norito::json::Value>(plan, Some(query))
                .expect_err("malformed query must fail");
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "query={query:?}"
            );
        }
        for (query, key, expected) in [
            ("%6Cimit=x", "limit", "x"),
            ("label=%41bc", "label", "Abc"),
            ("label=raw/value", "label", "raw/value"),
            ("label=raw~value", "label", "raw~value"),
            ("label=a=b", "label", "a=b"),
            ("label=one%20two", "label", "one two"),
        ] {
            let decoded = decode_torii_proxy_query::<norito::json::Value>(plan, Some(query))
                .unwrap_or_else(|_| panic!("{query:?} decodes"));
            assert_eq!(decoded[key].as_str(), Some(expected), "query={query:?}");
        }
        let decoded = decode_torii_proxy_query::<norito::json::Value>(
            plan,
            Some("label=raw%2Fvalue%7Eok&space=one+two&star=one*two"),
        )
        .expect("form spellings decode");
        assert_eq!(decoded["label"].as_str(), Some("raw/value~ok"));
        assert_eq!(decoded["space"].as_str(), Some("one two"));
        assert_eq!(decoded["star"].as_str(), Some("one*two"));
    }
    #[test]
    fn routed_query_scalar_coercion_is_exact() {
        let phase = 64 * 1024;
        let plan =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .expect("test geometry")
                .request_decode_plan()
                .expect("request plan");
        let decoded = decode_torii_proxy_query::<norito::json::Value>(
            plan,
            Some(
                "zero=0&integer=42&negative=-42&boolean=true&upper=TRUE&leading=01&negative_zero=-0&float=1.0&spaced=+42+",
            ),
        )
        .expect("canonical query decodes");
        assert_eq!(decoded["zero"].as_u64(), Some(0));
        assert_eq!(decoded["integer"].as_u64(), Some(42));
        assert_eq!(decoded["negative"].as_i64(), Some(-42));
        assert_eq!(decoded["boolean"].as_bool(), Some(true));
        for (key, expected) in [
            ("upper", "TRUE"),
            ("leading", "01"),
            ("negative_zero", "-0"),
            ("float", "1.0"),
            ("spaced", " 42 "),
        ] {
            assert_eq!(decoded[key].as_str(), Some(expected), "key={key}");
        }
    }
    #[test]
    fn string_query_mode_preserves_decimal_and_whitespace_values() {
        let phase = 64 * 1024;
        let plan =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .expect("test geometry")
                .request_decode_plan()
                .expect("request plan");
        let hash = "11".repeat(32);
        let raw = format!("hash=+{hash}+&scope=+local+");
        let decoded = decode_torii_proxy_string_query::<PipelineStatusQuery>(plan, Some(&raw))
            .expect("string query values decode verbatim");
        let expected_hash = format!(" {hash} ");
        assert_eq!(decoded.hash.as_deref(), Some(expected_hash.as_str()));
        assert_eq!(decoded.scope.as_deref(), Some(" local "));
    }
    #[test]
    fn json_body_preflights_and_maps_resource_failures_to_413() {
        let phase = 4 * 1024;
        let plan =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .expect("test geometry")
                .request_decode_plan()
                .expect("request plan");
        let valid = br#"{"limit":7}"#;
        let decoded = decode_torii_proxy_json_body::<Value>(plan, valid, "list filter")
            .expect("small request decodes");
        assert_eq!(decoded["limit"].as_u64(), Some(7));
        let oversized = vec![b' '; plan.raw_input_limit_bytes + 1];
        let response = decode_torii_proxy_json_body::<Value>(plan, &oversized, "list filter")
            .expect_err("raw limit plus one is rejected");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[test]
    fn production_form_decoder_does_not_reintroduce_allocating_url_parser() {
        let source = include_str!("torii_app_routed_read_request.rs");
        let production = source
            .split_once(r#"#[cfg(all(test, feature = "app_api"))]"#)
            .map_or(source, |(production, _)| production);
        assert!(!production.contains("url::form_urlencoded"));
        assert!(!production.contains("norito::json::Map"));
        assert!(!production.contains("norito::json::from_value"));
    }
}

#[cfg(all(test, feature = "app_api"))]
mod service_request_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::{audit, error};
    use norito::json::{BoundedJsonError, FastJsonWrite};

    fn plan() -> ToriiRoutedReadRequestDecodePlan {
        let phase = 64 * 1024;
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .unwrap()
            .request_decode_plan()
            .unwrap()
    }
    #[test]
    fn original_form_json_keeps_original_decode_plan_and_input_refusal_depth() {
        for coerce_scalars in [false, true] {
            let source = ToriiRoutedReadFormJson {
                raw: "name=%C3%A9&limit=7&enabled=true",
                plan: plan(),
                coerce_scalars,
            };
            let mut expected = String::new();
            source.write_json(&mut expected);
            audit(&expected, |sink| source.write_json_to(sink));
        }
        let source = ToriiRoutedReadFormJson {
            raw: "name=%FF",
            plan: plan(),
            coerce_scalars: false,
        };
        error(BoundedJsonError::Unsupported, |sink| {
            source.write_json_to(sink)
        });
    }
}
