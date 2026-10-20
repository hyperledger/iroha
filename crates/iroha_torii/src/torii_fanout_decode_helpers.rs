#[cfg(test)]
#[derive(Debug)]
struct ToriiFanoutDecodeBudget {
    retained_bytes: usize,
    max_retained_bytes: usize,
}
#[cfg(test)]
impl ToriiFanoutDecodeBudget {
    fn new(max_retained_bytes: usize) -> Self {
        Self {
            retained_bytes: 0,
            max_retained_bytes: max_retained_bytes.max(1),
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn remaining(&self) -> Result<usize, Response> {
        let remaining = self
            .max_retained_bytes
            .checked_sub(self.retained_bytes)
            .ok_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::BAD_GATEWAY,
                    "route_unavailable",
                    "cross-dataspace response decode accounting is inconsistent",
                )
            })?;
        if remaining == 0 {
            return Err(torii_proxy_error_response(
                StatusCode::BAD_GATEWAY,
                "route_unavailable",
                format!(
                    "cross-dataspace response exceeds the configured {}-byte aggregate decode budget",
                    self.max_retained_bytes
                ),
            ));
        }
        Ok(remaining)
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn charge(&mut self, bytes: usize) -> Result<(), Response> {
        self.retained_bytes = self
            .retained_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.max_retained_bytes)
            .ok_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::BAD_GATEWAY,
                    "route_unavailable",
                    format!(
                        "cross-dataspace response exceeds the configured {}-byte aggregate decode budget",
                        self.max_retained_bytes
                    ),
                )
            })?;
        Ok(())
    }
}
/// Fixed logical allowance for coordinator metadata and response framing.
const QUERY_FANOUT_BASE_OVERHEAD_BYTES: usize = 64 * 1024;
/// Conservative logical charge for one route while the deduplicating
/// `BTreeMap` and final route `Vec` overlap.
const QUERY_FANOUT_ROUTE_OVERHEAD_BYTES: usize = 1024;
/// Fixed scratch used while validating the largest protocol-admitted public
/// key. Exact public-key sizing is allocation-free, but validation still owns
/// this bounded temporary beside the request representation.
const QUERY_FANOUT_PUBLIC_KEY_VALIDATION_SCRATCH_BYTES: usize =
    iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES;
/// Conservative number of simultaneously represented validator identities
/// while Core's bounded manifest result is transformed into a retry candidate.
const QUERY_FANOUT_CANDIDATE_IDENTITY_REPRESENTATIONS: usize = 3;
/// Per-candidate allowance for `Vec`/tree nodes, enum/string handles, allocator
/// bookkeeping, and retry metadata beyond the bounded identity and URL bytes.
const QUERY_FANOUT_CANDIDATE_CONTAINER_OVERHEAD_BYTES: usize = 4 * 1024;
/// Query-sized representations simultaneously live while an authoritative
/// HTTP bridge serializes one attempt: coordinator source, retry template,
/// attempt value, payload destination, and two nested derived-codec spills.
#[cfg(test)]
const QUERY_FANOUT_HTTP_SIGNED_REQUEST_REPRESENTATIONS: usize = 6;
/// P2P adds the outer `NetworkMessage` derived-codec spill before the exact
/// actor-wire byte lease takes ownership.
const QUERY_FANOUT_P2P_SIGNED_REQUEST_REPRESENTATIONS: usize = 7;
/// Worst protocol transport representation count used by admission.
const QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS: usize =
    QUERY_FANOUT_P2P_SIGNED_REQUEST_REPRESENTATIONS;
/// One independently measured canonical verified-request representation.
const QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS: usize = 1;
/// Equal high-water phases in the coordinator working set.
///
/// The seventh unit covers the singular producer corridor while a previously successful route
/// remains retained: request decode, retained first output, an owned persisted/source projection,
/// the current decoded output, the destination frame, and two canonicalization scratch units can
/// coexist. Routes still execute sequentially.
const QUERY_FANOUT_PHASE_COUNT: usize = 7;
/// Conservative pre-body units: 7Q + E + 7P.
const QUERY_FANOUT_PREBODY_UNITS: usize = QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS
    + QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS
    + QUERY_FANOUT_PHASE_COUNT;
fn checked_sum<const N: usize>(terms: [usize; N]) -> Option<usize> {
    terms.into_iter().try_fold(0_usize, usize::checked_add)
}
/// Fixed memory that can be reached while an ingress reservation owns route
/// classification and the protocol-bounded route catalogue.
fn query_ingress_fixed_overhead_bytes() -> Option<usize> {
    let route_catalogue = QUERY_FANOUT_ROUTE_OVERHEAD_BYTES
        .checked_mul(iroha_data_model::nexus::MAX_ACTIVE_EXECUTION_LANES)?;
    checked_sum([
        QUERY_FANOUT_BASE_OVERHEAD_BYTES,
        route_catalogue,
        QUERY_FANOUT_PUBLIC_KEY_VALIDATION_SCRATCH_BYTES,
    ])
}
/// Maximum candidate-list high water for one sequentially resolved route.
///
/// Core admits at most 256 manifest validators. Until the routing-only Core seam can return a
/// single representation, account for three simultaneous identity/key payloads, one bounded
/// manifest URL, and explicit container slack for every selected status. This bound is
/// intentionally independent of the total online/world peer population and is not multiplied by
/// lanes: candidate resolution is sequential.
fn query_fanout_candidate_snapshot_overhead_bytes() -> Option<usize> {
    let identities = iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES
        .checked_mul(QUERY_FANOUT_CANDIDATE_IDENTITY_REPRESENTATIONS)?;
    let per_candidate = checked_sum([
        identities,
        iroha_core::governance::manifest::MANIFEST_SOURCE_MAX_VALUE_BYTES_V1,
        QUERY_FANOUT_CANDIDATE_CONTAINER_OVERHEAD_BYTES,
    ])?;
    per_candidate.checked_mul(iroha_core::governance::manifest::LANE_MANIFEST_MAX_VALIDATORS_V1)
}
/// Complete fixed envelope for one admitted fanout.
fn query_fanout_fixed_overhead_bytes() -> Option<usize> {
    checked_sum([
        query_ingress_fixed_overhead_bytes()?,
        query_fanout_candidate_snapshot_overhead_bytes()?,
    ])
}
/// Deterministic phase geometry for one signed-query fanout.
///
/// This is logical admission accounting, not an estimate of allocator internals. The request and
/// fixed allowance remain live for the operation. The remaining bytes are divided into seven equal
/// parts so that every high-water phase fits in one working-set reservation:
///
/// - request decode + retained first singular output + the accumulated raw route body +
///   one concurrently held transport chunk + decoded route output;
/// - final decoded output + the exact direct-streamed response body + one
///   cache-free identifier encoder scratch allowance;
/// - response body + proxy snapshot copy; and
/// - request decode + retained first singular output + the retained Core builder + the current
///   source/output corridor + the destination canonical frame + two
///   canonicalization scratch units. Routes execute sequentially.
///
/// Application collection reads also use these phase ceilings for retained rows and merge
/// scratch, with their own admission accounting. Signed iterable queries never fan out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "Byte units are explicit for every independently admitted allocation phase."
)]
struct QueryFanoutMemoryEnvelope {
    working_set_bytes: usize,
    request_bytes: usize,
    request_decode_allocated_bytes: usize,
    accumulator_retained_bytes: usize,
    route_body_bytes: usize,
    decode_allocated_bytes: usize,
    candidate_allocation_bytes: usize,
    candidate_encoded_bytes: usize,
    final_body_bytes: usize,
}
impl QueryFanoutMemoryEnvelope {
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn for_request_lengths(
        working_set_bytes: usize,
        signed_query_bytes: usize,
        verified_request_bytes: usize,
    ) -> Result<Self, Response> {
        let admission_unit = Self::body_admission_unit(working_set_bytes)?;
        if signed_query_bytes > admission_unit || verified_request_bytes > admission_unit {
            return Err(torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                format!(
                    "signed-query fanout request frames ({signed_query_bytes} signed, {verified_request_bytes} verified) exceed the admitted {admission_unit}-byte per-frame limit"
                ),
            ));
        }
        // Routes execute sequentially, so the transport wrapper depth does not
        // multiply by route or candidate count. The current retry template and
        // derived codecs nevertheless overlap seven query-sized
        // representations before the P2P actor lease owns the wire bytes (six
        // for HTTP, plus the outer NetworkMessage spill for P2P). Charge that
        // proven worst case together with the independently measured verified
        // request instead of assuming either representation is shorter.
        let request_bytes = Self::retained_request_bytes(
            signed_query_bytes,
            verified_request_bytes,
        )
        .ok_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "query_capacity_exceeded",
                    "signed-query fanout request retention accounting overflows the platform address space",
                )
            })?;
        Self::new(working_set_bytes, request_bytes)
    }
    fn retained_request_bytes(
        signed_query_bytes: usize,
        verified_request_bytes: usize,
    ) -> Option<usize> {
        signed_query_bytes
            .checked_mul(QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS)?
            .checked_add(
                verified_request_bytes
                    .checked_mul(QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS)?,
            )
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn for_body_admission(working_set_bytes: usize) -> Result<Self, Response> {
        let phase_bytes = Self::body_admission_unit(working_set_bytes)?;
        Self::with_phase_bytes(working_set_bytes, 0, phase_bytes)
    }
    /// Original admission for local finality GETs, which decode no request body
    /// and retain no signed-query representations. Cold source and response caps
    /// stay unchanged; only genuinely absent request phases are released to the
    /// producer. This must never reinterpret an already admitted outer request.
    #[expect(
        clippy::result_large_err,
        reason = "Capacity rejections retain the complete Axum response inline without adding a box allocation."
    )]
    fn for_bodyless_finality(working_set_bytes: usize) -> Result<Self, Response> {
        let mut envelope = Self::for_body_admission(working_set_bytes)?;
        envelope.request_decode_allocated_bytes = 0;
        Ok(envelope)
    }
    #[expect(
        clippy::result_large_err,
        reason = "Capacity rejections retain the complete Axum response inline without adding a box allocation."
    )]
    fn body_admission_unit(working_set_bytes: usize) -> Result<usize, Response> {
        // Before decoding, the exact verified-request frame is unknown. Reserve
        // seven signed-query-sized transport representations, one verified
        // frame, and seven high-water phases up front. Once Q and E are
        // measured, the exact envelope can only make a phase larger, never
        // smaller.
        let fixed_overhead = query_fanout_fixed_overhead_bytes().ok_or_else(|| {
            torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "signed-query fanout fixed-overhead accounting overflows the platform address space",
            )
        })?;
        working_set_bytes
            .checked_sub(fixed_overhead)
            .map(|remaining| remaining / QUERY_FANOUT_PREBODY_UNITS)
            .filter(|unit| *unit > 1)
            .ok_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "query_capacity_exceeded",
                    format!(
                        "signed-query fanout requires more than {fixed_overhead} bytes of working-set capacity"
                    ),
                )
            })
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn new(working_set_bytes: usize, request_bytes: usize) -> Result<Self, Response> {
        let fixed_overhead = query_fanout_fixed_overhead_bytes().ok_or_else(|| {
            torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "signed-query fanout fixed-overhead accounting overflows the platform address space",
            )
        })?;
        let phase_bytes = working_set_bytes
            .checked_sub(request_bytes)
            .and_then(|remaining| remaining.checked_sub(fixed_overhead))
            .map(|remaining| remaining / QUERY_FANOUT_PHASE_COUNT)
            .filter(|phase| *phase > 0)
            .ok_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "query_capacity_exceeded",
                    format!(
                        "signed-query fanout request requires {request_bytes} bytes inside a {working_set_bytes}-byte working-set reservation"
                    ),
                )
            })?;
        Self::with_phase_bytes(working_set_bytes, request_bytes, phase_bytes)
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn with_phase_bytes(
        working_set_bytes: usize,
        request_bytes: usize,
        phase_bytes: usize,
    ) -> Result<Self, Response> {
        if phase_bytes < 2 {
            return Err(torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "signed-query fanout phase cannot admit the request and its local clone",
            ));
        }
        let final_body_bytes = phase_bytes.checked_mul(2).ok_or_else(|| {
            torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "signed-query fanout response budget overflows the platform address space",
            )
        })?;
        let envelope = Self {
            working_set_bytes,
            request_bytes,
            request_decode_allocated_bytes: phase_bytes,
            accumulator_retained_bytes: phase_bytes,
            route_body_bytes: phase_bytes,
            decode_allocated_bytes: phase_bytes,
            candidate_allocation_bytes: phase_bytes,
            candidate_encoded_bytes: phase_bytes,
            final_body_bytes,
        };
        if envelope.phases_fit() {
            Ok(envelope)
        } else {
            Err(torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "signed-query fanout phase accounting exceeds its working-set reservation",
            ))
        }
    }
    fn phases_fit(self) -> bool {
        let Some(fixed_overhead) = query_fanout_fixed_overhead_bytes() else {
            return false;
        };
        let Some(fixed) = self.request_bytes.checked_add(fixed_overhead) else {
            return false;
        };
        let Some(remote_decode) = checked_sum([
            self.request_decode_allocated_bytes,
            self.decode_allocated_bytes,
            self.route_body_bytes,
            self.route_body_bytes,
            self.decode_allocated_bytes,
        ]) else {
            return false;
        };
        let Some(final_encode) = checked_sum([
            self.decode_allocated_bytes,
            self.final_body_bytes,
            self.final_body_bytes,
        ]) else {
            return false;
        };
        let Some(proxy_copy) = self.final_body_bytes.checked_mul(2) else {
            return false;
        };
        let Some(singular_compare) = checked_sum([
            self.request_decode_allocated_bytes,
            self.decode_allocated_bytes,
            self.decode_allocated_bytes,
            self.decode_allocated_bytes,
            self.candidate_encoded_bytes,
            self.candidate_encoded_bytes,
            self.candidate_encoded_bytes,
        ]) else {
            return false;
        };
        let peak = remote_decode
            .max(final_encode)
            .max(proxy_copy)
            .max(singular_compare);
        fixed
            .checked_add(peak)
            .is_some_and(|total| total <= self.working_set_bytes)
    }
    fn execution_budget(self) -> iroha_core::smartcontracts::isi::query::QueryExecutionBudget {
        let max_units = self
            .working_set_bytes
            .checked_sub(self.request_bytes)
            .and_then(|remaining| {
                remaining.checked_sub(
                    query_fanout_fixed_overhead_bytes()
                        .expect("validated fanout fixed overhead fits usize"),
                )
            })
            .expect("validated fanout envelope has a non-negative execution budget");
        iroha_core::smartcontracts::isi::query::QueryExecutionBudget::from_weighted_limit(
            u64::try_from(max_units).unwrap_or(u64::MAX),
            1,
            1,
        )
    }
    fn singular_output_limits(
        self,
    ) -> iroha_core::smartcontracts::isi::query::SingularQueryOutputLimits {
        iroha_core::smartcontracts::isi::query::SingularQueryOutputLimits::new(
            u64::try_from(self.candidate_encoded_bytes).unwrap_or(u64::MAX),
            u64::try_from(self.decode_allocated_bytes).unwrap_or(u64::MAX),
        )
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn request_decode_limits(self, encoded_len: usize) -> Result<norito::DecodeLimits, Response> {
        // The coordinator retains the verified request while one local route
        // owns a decoded clone. Each representation receives half of the one
        // request-decode phase, so their overlap cannot silently double D.
        Self::decode_limits_for(encoded_len, self.request_decode_allocated_bytes / 2)
    }
    fn query_scope_limits(self) -> QueryScopeMemoryLimits {
        // The verified request keeps half of D. Scope classification may own a
        // nested decoded query and one extracted routing identifier at once,
        // so each receives one quarter of D and the combined request phase
        // remains bounded.
        QueryScopeMemoryLimits {
            decode_allocated_bytes: self.request_decode_allocated_bytes / 4,
            canonical_encoded_bytes: self.candidate_encoded_bytes,
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn response_decode_limits(self, encoded_len: usize) -> Result<norito::DecodeLimits, Response> {
        Self::decode_limits_for(encoded_len, self.decode_allocated_bytes)
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn decode_limits_for(
        encoded_len: usize,
        max_allocated_bytes: usize,
    ) -> Result<norito::DecodeLimits, Response> {
        let element_limit = encoded_len.checked_mul(8).ok_or_else(|| {
            torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "signed-query decode element limit overflows the platform address space",
            )
        })?;
        Ok(norito::DecodeLimits::new(
            element_limit,
            encoded_len,
            element_limit,
            max_allocated_bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ))
    }
}
/// Allocation and canonical-encoding ceilings for routing-scope inspection.
///
/// These limits always come from the reservation currently held by the
/// caller. In particular, HTTP ingress cannot borrow the larger fanout limits
/// before it has successfully promoted to a fanout reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QueryScopeMemoryLimits {
    decode_allocated_bytes: usize,
    canonical_encoded_bytes: usize,
}
impl QueryScopeMemoryLimits {
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn decode_limits(self, encoded_len: usize) -> Result<norito::DecodeLimits, Response> {
        QueryFanoutMemoryEnvelope::decode_limits_for(encoded_len, self.decode_allocated_bytes)
    }
}
/// Fraction of the configured query memory pool reserved for bounded HTTP
/// ingress. The remaining three quarters back complete fanout working sets.
const QUERY_INGRESS_POOL_DIVISOR: usize = 4;
/// Independent signed-query bodies that may be read concurrently.
const QUERY_INGRESS_SLOT_COUNT: usize = 4;
/// Maximum simultaneous variable-size ingress representations during bounded routing-scope
/// classification: decoded signed query, its canonical frame, a nested decoded scope query, that
/// query's canonical-check frame, and one derived-codec scratch representation.
const QUERY_INGRESS_PHASE_UNITS: usize = 5;
/// Complete memory reservation for one signed-query body before its route is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "Byte units distinguish admitted ingress and canonicalization allocations."
)]
struct QueryIngressMemoryEnvelope {
    slot_bytes: usize,
    body_bytes: usize,
    decode_allocated_bytes: usize,
    canonical_encoded_bytes: usize,
    scope_decode_allocated_bytes: usize,
    scope_canonical_encoded_bytes: usize,
}
/// Complete memory admitted while one authenticated peer delivers an internal
/// Torii proxy request over HTTP.
///
/// A dedicated single-slot bridge lane holds this complete reservation before polling the body. The
/// high-water phases cover the signed raw frame plus the decoded request, and then the moved
/// decoded envelope, one shared outbound frame and bounded codec scratch. Candidate attempts
/// are sequential and retain at most one bounded retry diagnostic beside the next response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "Byte units are explicit for each retained and transient proxy allocation."
)]
struct ToriiProxyHttpIngressEnvelope {
    working_set_bytes: usize,
    body_bytes: usize,
    decode_allocated_bytes: usize,
    forwarded_request_bytes: usize,
    forwarding_transient_bytes: usize,
}
impl ToriiProxyHttpIngressEnvelope {
    fn from_max_content_bytes(max_content_bytes: usize) -> Option<Self> {
        let fixed_overhead = query_fanout_fixed_overhead_bytes()?
            .checked_add(TORII_PROXY_RETRYABLE_RETAINED_BODY_BYTES_V1)?;
        if max_content_bytes == 0 {
            return None;
        }
        // The middleware owns the raw body only through decoding. After that,
        // one bounded shared frame is reused by every remote transport attempt.
        // Local dispatch and bounded codec scratch share this five-representation peak.
        let variable_bytes = max_content_bytes.checked_mul(5)?;
        let working_set_bytes = fixed_overhead.checked_add(variable_bytes)?;
        let envelope = Self {
            working_set_bytes,
            body_bytes: max_content_bytes,
            decode_allocated_bytes: max_content_bytes,
            forwarded_request_bytes: max_content_bytes,
            forwarding_transient_bytes: max_content_bytes,
        };
        envelope.phases_fit().then_some(envelope)
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn decode_limits(self) -> Result<norito::DecodeLimits, Response> {
        QueryFanoutMemoryEnvelope::decode_limits_for(self.body_bytes, self.decode_allocated_bytes)
    }
    fn phases_fit(self) -> bool {
        let decode_peak = self.body_bytes.checked_add(self.decode_allocated_bytes);
        let forwarding_peak = checked_sum([
            self.forwarded_request_bytes,
            self.forwarding_transient_bytes,
            self.forwarding_transient_bytes,
            self.forwarding_transient_bytes,
            self.forwarding_transient_bytes,
        ]);
        decode_peak
            .into_iter()
            .chain(forwarding_peak)
            .max()
            .and_then(|peak| {
                peak.checked_add(
                    query_fanout_fixed_overhead_bytes()?
                        .checked_add(TORII_PROXY_RETRYABLE_RETAINED_BODY_BYTES_V1)?,
                )
            })
            .is_some_and(|total| total <= self.working_set_bytes)
    }
}
impl QueryIngressMemoryEnvelope {
    fn from_slot_bytes(slot_bytes: usize, max_unit_bytes: usize) -> Option<Self> {
        let unit = (slot_bytes.checked_sub(query_ingress_fixed_overhead_bytes()?)?
            / QUERY_INGRESS_PHASE_UNITS)
            .min(max_unit_bytes);
        if unit == 0 {
            return None;
        }
        let envelope = Self {
            slot_bytes,
            body_bytes: unit,
            decode_allocated_bytes: unit,
            canonical_encoded_bytes: unit,
            scope_decode_allocated_bytes: unit,
            scope_canonical_encoded_bytes: unit,
        };
        envelope.phases_fit().then_some(envelope)
    }
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn request_decode_limits(
        self,
        provisional_fanout: QueryFanoutMemoryEnvelope,
    ) -> Result<norito::DecodeLimits, Response> {
        // Promotion retains this decoded request while a local route may own
        // one bounded clone. Each side receives at most half of fanout's D
        // phase even when the independent ingress slot could admit more.
        QueryFanoutMemoryEnvelope::decode_limits_for(
            self.body_bytes,
            self.decode_allocated_bytes
                .min(provisional_fanout.request_decode_allocated_bytes / 2),
        )
    }
    /// Decode limits for JSON ingress while two allocation units can coexist.
    ///
    /// Unlike the direct Norito path above, a JSON wrapper can still own its decoded base64 string
    /// buffer while the nested Norito payload is being reconstructed. The JSON path therefore
    /// receives at most two ingress allocation units for that transient. The independent fanout
    /// half-phase remains an upper bound so ingress cannot borrow memory it will not own after
    /// promotion.
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn json_request_two_unit_decode_limits(
        self,
        provisional_fanout: QueryFanoutMemoryEnvelope,
    ) -> Result<norito::DecodeLimits, Response> {
        let json_decode_allocated_bytes =
            self.decode_allocated_bytes.checked_mul(2).ok_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "query_capacity_exceeded",
                    "signed-query JSON decode budget overflows the platform address space",
                )
            })?;
        QueryFanoutMemoryEnvelope::decode_limits_for(
            self.body_bytes,
            json_decode_allocated_bytes.min(provisional_fanout.request_decode_allocated_bytes / 2),
        )
    }
    fn query_scope_limits(self) -> QueryScopeMemoryLimits {
        QueryScopeMemoryLimits {
            decode_allocated_bytes: self.scope_decode_allocated_bytes,
            canonical_encoded_bytes: self.scope_canonical_encoded_bytes,
        }
    }
    fn phases_fit(self) -> bool {
        let Some(fixed_overhead) = query_ingress_fixed_overhead_bytes() else {
            return false;
        };
        let Some(body_decode) = checked_sum([self.body_bytes, self.decode_allocated_bytes]) else {
            return false;
        };
        let Some(canonicalize) = checked_sum([
            self.decode_allocated_bytes,
            self.canonical_encoded_bytes,
            self.canonical_encoded_bytes,
        ]) else {
            return false;
        };
        let Some(scope_classification) = checked_sum([
            self.decode_allocated_bytes,
            self.canonical_encoded_bytes,
            self.scope_decode_allocated_bytes,
            self.scope_canonical_encoded_bytes,
            self.scope_canonical_encoded_bytes,
        ]) else {
            return false;
        };
        fixed_overhead
            .checked_add(body_decode.max(canonicalize).max(scope_classification))
            .is_some_and(|bytes| bytes <= self.slot_bytes)
    }
}
#[cfg(test)]
mod query_ingress_json_decode_limit_tests {
    use super::*;
    #[test]
    fn json_base64_and_nested_decode_peak_fits_the_five_unit_ingress_slot() {
        let fixed = query_ingress_fixed_overhead_bytes().expect("fixed ingress overhead fits");
        let unit = 17;
        let slot = fixed + QUERY_INGRESS_PHASE_UNITS * unit;
        let ingress = QueryIngressMemoryEnvelope::from_slot_bytes(slot, usize::MAX)
            .expect("exact five-unit ingress slot fits");
        let provisional = QueryFanoutMemoryEnvelope::for_body_admission(64_000_000)
            .expect("test fanout envelope fits");
        let limits = ingress
            .json_request_two_unit_decode_limits(provisional)
            .expect("two-unit JSON decode limits fit");
        assert_eq!(limits.max_total_allocated_bytes(), 2 * unit);
        let json_decode_peak = fixed
            .checked_add(ingress.body_bytes)
            .and_then(|bytes| bytes.checked_add(limits.max_total_allocated_bytes()))
            .expect("test peak fits usize");
        assert!(json_decode_peak <= ingress.slot_bytes);
        assert!(ingress.phases_fit());
    }
}
/// Split of the configured aggregate query-memory pool into an independent
/// pre-body lane and complete fanout working-set reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QueryMemoryGeometry {
    ingress: QueryIngressMemoryEnvelope,
    ingress_slots: NonZeroUsize,
    fanout_pool_bytes: usize,
    fanout_working_set_bytes: usize,
    fanout_slots: NonZeroUsize,
}
fn query_memory_geometry(
    aggregate_bytes: usize,
    max_working_set_bytes: usize,
    max_content_bytes: usize,
    max_concurrent_fanouts: usize,
) -> Option<QueryMemoryGeometry> {
    let ingress_pool_bytes = aggregate_bytes / QUERY_INGRESS_POOL_DIVISOR;
    let fanout_pool_bytes = aggregate_bytes.checked_sub(ingress_pool_bytes)?;
    // One working set must include the fixed routing/candidate catalogue and
    // every simultaneously live representation of the admitted body. A small
    // listener limit therefore reduces the slot weight (and can increase safe
    // concurrency); it must not make the slot smaller than its fixed state.
    // The per-query ceiling is independent of aggregate concurrency. When the
    // configured body exceeds that ceiling or the pool, the phase-derived
    // query-body limit shrinks while the general Torii body limit remains
    // unchanged. Raising aggregate capacity never raises one request's limits.
    // One request-decode phase is shared by the retained request and its local clone.
    // Keep a byte for each owner even when the listener admits only one body byte.
    let desired_fanout_working_set = max_content_bytes
        .max(2)
        .checked_mul(QUERY_FANOUT_PREBODY_UNITS)
        .and_then(|bytes| bytes.checked_add(query_fanout_fixed_overhead_bytes()?));
    let available_working_set_bytes = fanout_pool_bytes.min(max_working_set_bytes);
    let fanout_working_set_bytes = desired_fanout_working_set
        .map_or(available_working_set_bytes, |desired| {
            desired.min(available_working_set_bytes)
        });
    let provisional_fanout =
        QueryFanoutMemoryEnvelope::for_body_admission(fanout_working_set_bytes).ok()?;
    let ingress_slots = NonZeroUsize::new(QUERY_INGRESS_SLOT_COUNT)?;
    let ingress_slot_bytes = ingress_pool_bytes / ingress_slots.get();
    let ingress_unit_cap = max_content_bytes.min(provisional_fanout.route_body_bytes);
    let ingress =
        QueryIngressMemoryEnvelope::from_slot_bytes(ingress_slot_bytes, ingress_unit_cap)?;
    let fanout_slots = query_fanout_slot_count(
        fanout_pool_bytes,
        fanout_working_set_bytes,
        max_concurrent_fanouts,
    )?;
    let ingress_reserved = ingress_slot_bytes.checked_mul(ingress_slots.get())?;
    let fanout_reserved = fanout_working_set_bytes.checked_mul(fanout_slots.get())?;
    ingress_reserved
        .checked_add(fanout_reserved)
        .filter(|reserved| *reserved <= aggregate_bytes)?;
    Some(QueryMemoryGeometry {
        ingress,
        ingress_slots,
        fanout_pool_bytes,
        fanout_working_set_bytes,
        fanout_slots,
    })
}
fn query_fanout_slot_count(
    max_retained_bytes: usize,
    working_set_bytes: usize,
    max_concurrent_queries: usize,
) -> Option<NonZeroUsize> {
    let working_set_bytes = NonZeroUsize::new(working_set_bytes)?;
    if max_retained_bytes < working_set_bytes.get() {
        return None;
    }
    NonZeroUsize::new(
        (max_retained_bytes / working_set_bytes.get()).min(max_concurrent_queries.max(1)),
    )
}
fn take_nonzero_generation(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(
            AtomicOrdering::Relaxed,
            AtomicOrdering::Relaxed,
            |current| (current != 0).then(|| current.checked_add(1)).flatten(),
        )
        .ok()
}
static NEXT_BYTE_WEIGHTED_POOL_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_ORDINARY_QUERY_POLICY_GENERATION: AtomicU64 = AtomicU64::new(1);
fn next_byte_weighted_pool_generation() -> u64 {
    take_nonzero_generation(&NEXT_BYTE_WEIGHTED_POOL_GENERATION)
        .expect("byte-weighted memory pool generation must not wrap")
}
fn next_ordinary_query_policy_generation() -> u64 {
    take_nonzero_generation(&NEXT_ORDINARY_QUERY_POLICY_GENERATION)
        .expect("ordinary query policy generation must not wrap")
}
fn weighted_permit_count(bytes: u64, bytes_per_permit: NonZeroU64) -> Option<u32> {
    if bytes == 0 {
        return Some(0);
    }
    let quantum = bytes_per_permit.get();
    let permits = (bytes / quantum).checked_add(u64::from(!bytes.is_multiple_of(quantum)))?;
    u32::try_from(permits).ok()
}
/// One app-local byte-weighted admission pool.
///
/// Tokio exposes weighted acquisition through a `u32` permit count, while its semaphore has a
/// platform-dependent larger maximum. The pool therefore chooses a conservative byte quantum and
/// never represents more bytes than the configured capacity.
#[derive(Clone, Debug)]
struct ByteWeightedMemoryPool {
    semaphore: Arc<tokio::sync::Semaphore>,
    bytes_per_permit: NonZeroU64,
    total_permits: NonZeroU32,
    generation: u64,
}
impl ByteWeightedMemoryPool {
    fn new(pool_bytes: usize) -> Option<Self> {
        let max_permits = tokio::sync::Semaphore::MAX_PERMITS
            .min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
        Self::with_max_permits(pool_bytes, max_permits)
    }
    fn with_max_permits(pool_bytes: usize, max_permits: usize) -> Option<Self> {
        let pool_bytes = u64::try_from(pool_bytes).ok()?;
        let max_permits = max_permits
            .min(tokio::sync::Semaphore::MAX_PERMITS)
            .min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
        let max_permits = u64::try_from(max_permits)
            .ok()
            .filter(|value| *value != 0)?;
        if pool_bytes == 0 {
            return None;
        }
        // Division plus a remainder bit is ceil-division without the usual
        // `bytes + divisor - 1` overflow near `u64::MAX`.
        let bytes_per_permit =
            (pool_bytes / max_permits).checked_add(u64::from(pool_bytes % max_permits != 0))?;
        let bytes_per_permit = NonZeroU64::new(bytes_per_permit)?;
        let total_permits = pool_bytes / bytes_per_permit.get();
        let total_permits = NonZeroU32::new(u32::try_from(total_permits).ok()?)?;
        Some(Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(
                usize::try_from(total_permits.get()).ok()?,
            )),
            bytes_per_permit,
            total_permits,
            generation: next_byte_weighted_pool_generation(),
        })
    }
    fn permits_for_parts<const N: usize>(&self, byte_parts: [u64; N]) -> Option<NonZeroU32> {
        let permits = byte_parts.into_iter().try_fold(0_u32, |total, bytes| {
            total.checked_add(weighted_permit_count(bytes, self.bytes_per_permit)?)
        })?;
        let permits = NonZeroU32::new(permits)?;
        (permits.get() <= self.total_permits.get()).then_some(permits)
    }
    fn can_reserve_parts<const N: usize>(&self, byte_parts: [u64; N]) -> bool {
        self.permits_for_parts(byte_parts).is_some()
    }
    fn try_acquire_parts<const N: usize>(
        &self,
        byte_parts: [u64; N],
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let permits = self.permits_for_parts(byte_parts)?;
        self.semaphore
            .clone()
            .try_acquire_many_owned(permits.get())
            .ok()
    }
    fn capacity_bytes(&self) -> u64 {
        u64::from(self.total_permits.get())
            .checked_mul(self.bytes_per_permit.get())
            .expect("weighted query pool capacity was validated at construction")
    }
    #[cfg(test)]
    fn available_bytes(&self) -> u64 {
        u64::try_from(self.semaphore.available_permits())
            .ok()
            .and_then(|permits| permits.checked_mul(self.bytes_per_permit.get()))
            .expect("weighted query pool availability cannot exceed validated capacity")
    }
    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
    fn generation(&self) -> u64 {
        self.generation
    }
}
/// Immutable app-local limits used for every ordinary query on one Torii.
///
/// This deliberately does not read the process-global app endpoint limits at
/// request time. Multiple Torii instances in one process therefore cannot
/// invalidate one another's cursor policies through the legacy global setter.
#[derive(Clone, Copy, Debug)]
struct OrdinaryQueryServerPolicy {
    limits: iroha_core::smartcontracts::isi::query::OrdinaryQueryExecutionLimits,
    singular_output_limits: iroha_core::smartcontracts::isi::query::SingularQueryOutputLimits,
    singular_execution_reservation_bytes: u64,
    max_fetch_size: u64,
}
impl OrdinaryQueryServerPolicy {
    fn new(
        app_limits: routing::AppQueryLimits,
        ingress: QueryIngressMemoryEnvelope,
        fanout: QueryFanoutMemoryEnvelope,
    ) -> Option<Self> {
        use iroha_core::smartcontracts::isi::query::{
            ORDINARY_NAME_ID_SOURCE_BYTES, OrdinaryQueryExecutionLimits,
        };
        let max_page_items = app_limits.max_fetch_size;
        let max_source_item_bytes = ORDINARY_NAME_ID_SOURCE_BYTES;
        let max_response_bytes = u64::try_from(fanout.final_body_bytes).ok()?;
        let max_cursor_retained_items = max_page_items;
        let max_cursor_value_bytes =
            max_cursor_retained_items.checked_mul(max_source_item_bytes)?;
        let max_request_graph_bytes = u64::try_from(ingress.decode_allocated_bytes).ok()?;
        let max_revalidation_archive_bytes = u64::try_from(ingress.canonical_encoded_bytes).ok()?;
        let revalidation_decode_limits = QueryFanoutMemoryEnvelope::decode_limits_for(
            ingress.canonical_encoded_bytes,
            ingress.decode_allocated_bytes,
        )
        .ok()?;
        let required_execution = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            max_page_items,
            max_source_item_bytes,
            max_response_bytes,
            max_request_graph_bytes,
            max_revalidation_archive_bytes,
            revalidation_decode_limits,
        )
        .ok()?;
        // Core's minimum owns one bounded encoded response. The narrow
        // ordinary iterable closure and fixed-width ABI scalar use this
        // smaller geometry. State-backed singular requests instead reserve
        // the complete fanout-derived working set below. Torii can also own a
        // proxy snapshot or actor-wire copy while either the Norito or JSON
        // body is live, so charge that copied body separately here.
        let transport_copy_bytes = max_response_bytes
            .checked_add(u64::try_from(TORII_PROXY_REQUEST_FRAME_OVERHEAD_BYTES_V1).ok()?)?;
        let execution_headroom_bytes = required_execution.checked_add(transport_copy_bytes)?;
        let max_cursor_retained_bytes =
            OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
                max_cursor_retained_items,
                max_source_item_bytes,
                max_cursor_value_bytes,
                max_revalidation_archive_bytes,
            )
            .ok()?;
        let limits = OrdinaryQueryExecutionLimits::try_new(
            next_ordinary_query_policy_generation(),
            fanout.execution_budget(),
            max_page_items,
            execution_headroom_bytes,
            max_source_item_bytes,
            max_response_bytes,
            max_cursor_retained_items,
            max_cursor_value_bytes,
            max_cursor_retained_bytes,
            max_request_graph_bytes,
            max_revalidation_archive_bytes,
            revalidation_decode_limits,
        )
        .ok()?;
        let singular_output_limits = fanout.singular_output_limits();
        let singular_execution_reservation_bytes = u64::try_from(fanout.working_set_bytes).ok()?;
        Some(Self {
            limits,
            singular_output_limits,
            singular_execution_reservation_bytes,
            max_fetch_size: app_limits.max_fetch_size,
        })
    }
    fn start_reservation_parts(self) -> [u64; 2] {
        [
            self.limits.execution_headroom_bytes(),
            self.limits.max_cursor_retained_bytes(),
        ]
    }
    fn execution_reservation_parts(self) -> [u64; 1] {
        [self.limits.execution_headroom_bytes()]
    }
    fn singular_execution_reservation_parts(self) -> [u64; 1] {
        [self.singular_execution_reservation_bytes]
    }
}
/// Direct, move-only ownership of one ordinary-query weighted reservation.
#[derive(Debug)]
struct ToriiOrdinaryQueryMemoryReservation {
    permit: tokio::sync::OwnedSemaphorePermit,
    bytes_per_permit: NonZeroU64,
    pool_generation: u64,
}
impl iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryReservation
    for ToriiOrdinaryQueryMemoryReservation
{
    fn reserved_bytes(&self) -> u64 {
        u64::try_from(self.permit.num_permits())
            .ok()
            .and_then(|permits| permits.checked_mul(self.bytes_per_permit.get()))
            .expect("ordinary query permit weight stays within its validated pool")
    }
    fn pool_generation(&self) -> u64 {
        self.pool_generation
    }
    fn split_off(
        &mut self,
        bytes: u64,
    ) -> Option<Box<dyn iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryReservation>>
    {
        let permits = weighted_permit_count(bytes, self.bytes_per_permit)?;
        let permits = NonZeroU32::new(permits)?;
        let permit = self.permit.split(usize::try_from(permits.get()).ok()?)?;
        Some(Box::new(Self {
            permit,
            bytes_per_permit: self.bytes_per_permit,
            pool_generation: self.pool_generation,
        }))
    }
}
fn try_acquire_ordinary_query_memory(
    app: &SharedAppState,
    stored_start: bool,
    singular: bool,
) -> Result<iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryLease, Error> {
    let permit = if singular {
        app.query_fanout_inflight.try_acquire_parts(
            app.ordinary_query_policy
                .singular_execution_reservation_parts(),
        )
    } else if stored_start {
        app.query_fanout_inflight
            .try_acquire_parts(app.ordinary_query_policy.start_reservation_parts())
    } else {
        app.query_fanout_inflight
            .try_acquire_parts(app.ordinary_query_policy.execution_reservation_parts())
    }
    .ok_or_else(|| {
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ))
    })?;
    Ok(
        iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryLease::new(
            ToriiOrdinaryQueryMemoryReservation {
                permit,
                bytes_per_permit: app.query_fanout_inflight.bytes_per_permit,
                pool_generation: app.query_fanout_inflight.generation(),
            },
        ),
    )
}
async fn acquire_query_ingress_memory(
    app: &SharedAppState,
) -> Result<tokio::sync::OwnedSemaphorePermit, Response> {
    let capacity_response = || {
        torii_proxy_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "query_capacity_exceeded",
            "signed-query ingress memory capacity is exhausted",
        )
    };
    if app.query_queue_timeout.is_zero() {
        return app
            .query_ingress_inflight
            .clone()
            .try_acquire_owned()
            .map_err(|_| capacity_response());
    }
    tokio::time::timeout(
        app.query_queue_timeout,
        app.query_ingress_inflight.clone().acquire_owned(),
    )
    .await
    .map_err(|_| capacity_response())?
    .map_err(|_| capacity_response())
}
#[derive(Clone)]
struct ToriiProxyMemoryReservation {
    /// Held only so the memory permit is released when the last clone drops.
    _permit: Arc<tokio::sync::OwnedSemaphorePermit>,
}
impl ToriiProxyMemoryReservation {
    fn new(permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            _permit: Arc::new(permit),
        }
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn acquire_torii_proxy_memory(
    app: &SharedAppState,
) -> Result<ToriiProxyMemoryReservation, Response> {
    // A waiter would retain its decoded request and candidate catalogue while
    // another complete W-sized proxy graph owns the only slot. Proxy promotion
    // is therefore always fail-fast; the ordinary query queue timeout does not
    // apply to this independent all-variant memory lane.
    try_acquire_torii_proxy_memory(app)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn try_acquire_torii_proxy_memory(
    app: &SharedAppState,
) -> Result<ToriiProxyMemoryReservation, Response> {
    app.torii_proxy_memory_inflight
        .clone()
        .try_acquire_owned()
        .map(ToriiProxyMemoryReservation::new)
        .map_err(|_| {
            torii_proxy_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "proxy_capacity_exceeded",
                "Torii proxy memory capacity is exhausted",
            )
        })
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn try_acquire_torii_proxy_receiver_memory(
    app: &SharedAppState,
) -> Result<ToriiProxyMemoryReservation, Response> {
    app.torii_proxy_receiver_memory_inflight
        .clone()
        .try_acquire_owned()
        .map(ToriiProxyMemoryReservation::new)
        .map_err(|_| {
            torii_proxy_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "proxy_capacity_exceeded",
                "Torii proxy receiver memory capacity is exhausted",
            )
        })
}
fn hold_torii_proxy_memory_in_response_body(
    response: Response,
    reservation: ToriiProxyMemoryReservation,
) -> Response {
    use http_body_util::BodyExt as _;
    let (parts, body) = response.into_parts();
    let guarded_body = body.map_frame(move |frame| {
        let _reservation = &reservation;
        frame
    });
    Response::from_parts(parts, Body::new(guarded_body))
}
/// Promote an already-admitted body to a complete fanout working set without
/// waiting while it occupies the independent ingress lane.
///
/// Failing fast here prevents a full fanout queue from pinning every ingress
/// permit and starving ordinary signed-query body decoding.
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn try_acquire_query_fanout_memory(
    app: &SharedAppState,
) -> Result<QueryFanoutMemoryReservation, Response> {
    #[cfg(feature = "app_api")]
    if let Some(reservation) = current_collection_read_memory_reservation(app)
        .or_else(|| current_app_routed_read_fanout_reservation(app))
    {
        return Ok(reservation);
    }
    try_acquire_new_query_fanout_memory(app)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn try_acquire_new_query_fanout_memory(
    app: &SharedAppState,
) -> Result<QueryFanoutMemoryReservation, Response> {
    let envelope =
        QueryFanoutMemoryEnvelope::for_body_admission(app.query_fanout_working_set_bytes)?;
    try_acquire_query_memory_envelope(app, envelope)
}
#[expect(
    clippy::result_large_err,
    reason = "Capacity rejections retain the complete Axum response inline without adding a box allocation."
)]
fn try_acquire_bodyless_finality_memory(
    app: &SharedAppState,
) -> Result<QueryFanoutMemoryReservation, Response> {
    let envelope =
        QueryFanoutMemoryEnvelope::for_bodyless_finality(app.query_fanout_working_set_bytes)?;
    try_acquire_query_memory_envelope(app, envelope)
}
#[expect(
    clippy::result_large_err,
    reason = "Capacity rejections retain the complete Axum response inline without adding a box allocation."
)]
fn try_acquire_query_memory_envelope(
    app: &SharedAppState,
    envelope: QueryFanoutMemoryEnvelope,
) -> Result<QueryFanoutMemoryReservation, Response> {
    app.query_fanout_inflight
        .try_acquire_parts([
            u64::try_from(app.query_fanout_working_set_bytes).map_err(|_| {
                torii_proxy_error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "query_capacity_exceeded",
                    "cross-dataspace query fanout memory weight is not representable",
                )
            })?,
        ])
        .map(|permit| {
            QueryFanoutMemoryReservation::from_admitted_fanout(
                permit,
                envelope,
                app.query_fanout_inflight.generation(),
            )
        })
        .ok_or_else(|| {
            torii_proxy_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "query_capacity_exceeded",
                "cross-dataspace query fanout memory capacity is exhausted",
            )
        })?
}
/// Queue a bodyless HTTP read before polling its body or decoding its query. The
/// listener already bounds its raw HTTP head; the separate waiter count bounds
/// how many of those heads remain here. No signed-query ingress permit or decoded
/// request is pinned while waiting for the complete fanout working set.
async fn acquire_app_routed_read_http_memory(
    app: &SharedAppState,
    accepts_body: bool,
) -> Result<QueryFanoutMemoryReservation, Response> {
    if accepts_body || app.query_queue_timeout.is_zero() {
        return try_acquire_new_query_fanout_memory(app);
    }
    let unavailable = || {
        torii_proxy_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "query_capacity_exceeded",
            "bodyless query capacity did not become available within the bounded admission queue",
        )
    };
    let _waiter = app
        .app_routed_read_waiters
        .clone()
        .try_acquire_owned()
        .map_err(|_| unavailable())?;
    let bytes = u64::try_from(app.query_fanout_working_set_bytes).map_err(|_| unavailable())?;
    let permits = app
        .query_fanout_inflight
        .permits_for_parts([bytes])
        .ok_or_else(unavailable)?;
    let acquired = tokio::time::timeout(
        app.query_queue_timeout,
        app.query_fanout_inflight
            .semaphore
            .clone()
            .acquire_many_owned(permits.get()),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())?;
    QueryFanoutMemoryReservation::from_admitted_fanout(
        acquired,
        QueryFanoutMemoryEnvelope::for_body_admission(app.query_fanout_working_set_bytes)?,
        app.query_fanout_inflight.generation(),
    )
}
fn hold_query_fanout_memory_in_response_body(
    response: Response,
    reservation: QueryFanoutMemoryReservation,
) -> Response {
    hold_query_fanout_memory_reservation_in_response_body(response, reservation)
}
/// Cloneable ownership token used to transfer one fanout reservation across
/// response-body and proxy-snapshot representations without reacquiring it.
#[derive(Clone)]
struct QueryFanoutMemoryReservation {
    /// Original native producer counters and finite source/response backing.
    /// These controls are reclaimed before the final permit returns query credit.
    producer: Option<iroha_allocation::ChargedShared<history_producer::ProducerBudget>>,
    /// Only acquisition from the query pool grants routed-read admission.
    /// Other native response owners use this token solely for body custody.
    admission: Option<AdmittedQueryFanoutMemory>,
    /// Last to drop: the native query control and its layout charge precede credit release.
    _permit: RetainedFanoutPermit,
}

type AdmittedFanoutPermit = iroha_allocation::shared::Shared<
    iroha_allocation::AllocationCharge,
    tokio::sync::OwnedSemaphorePermit,
>;

#[derive(Clone)]
enum RetainedFanoutPermit {
    Query {
        _permit: AdmittedFanoutPermit,
    },
    /// This other native pool retains responses but never grants query production.
    Response {
        _permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    },
}

#[derive(Clone, Copy)]
struct AdmittedQueryFanoutMemory {
    /// Exact admitted geometry; consumers must not reconstruct larger limits.
    envelope: QueryFanoutMemoryEnvelope,
    /// Prevent task-local ownership from being borrowed by another app's pool.
    pool_generation: u64,
}

impl QueryFanoutMemoryReservation {
    /// Retain response custody without granting query-pool admission.
    fn new(permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            _permit: RetainedFanoutPermit::Response {
                _permit: Arc::new(permit),
            },
            admission: None,
            producer: None,
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn from_admitted_fanout(
        permit: tokio::sync::OwnedSemaphorePermit,
        envelope: QueryFanoutMemoryEnvelope,
        pool_generation: u64,
    ) -> Result<Self, Response> {
        let producer = history_producer::ProducerBudget::from_admitted(envelope, pool_generation)
            .map_err(IntoResponse::into_response)?;
        let layout = AdmittedFanoutPermit::layout();
        let mut reserved = producer
            .response_metadata()
            .try_reserve(layout)
            .map_err(|_| crate::native_projection_response::capacity().into_response())?;
        let charge = reserved
            .try_split(layout)
            .expect("the exact native query control was admitted");
        // Shared reclaims its original allocation, then drops this layout charge,
        // and only then destroys the semaphore permit on its native stack. An Arc
        // containing the permit would refund before its enclosing control freed.
        let permit = match AdmittedFanoutPermit::try_new(charge, permit) {
            Ok(permit) => permit,
            Err((charge, permit, _)) => {
                drop(charge);
                drop(reserved);
                drop(producer);
                drop(permit);
                return Err(crate::native_projection_response::capacity().into_response());
            }
        };
        Ok(Self {
            _permit: RetainedFanoutPermit::Query { _permit: permit },
            admission: Some(AdmittedQueryFanoutMemory {
                envelope,
                pool_generation,
            }),
            producer: Some(producer),
        })
    }

    fn belongs_to(&self, app: &SharedAppState) -> bool {
        self.admission.is_some_and(|admission| {
            admission.pool_generation == app.query_fanout_inflight.generation()
        })
    }

    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn admitted_envelope(
        &self,
        app: &SharedAppState,
    ) -> Result<QueryFanoutMemoryEnvelope, Response> {
        self.admission
            .filter(|admission| admission.pool_generation == app.query_fanout_inflight.generation())
            .map(|admission| admission.envelope)
            .ok_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_server_error",
                    "The routed-read memory owner has no matching admission geometry.",
                )
            })
    }
}
/// Bind asynchronous CPU admission to its outer HTTP or collection memory owner.
fn current_query_fanout_memory_for_state(app: &AppState) -> Option<QueryFanoutMemoryReservation> {
    #[cfg(feature = "app_api")]
    {
        let matches_pool = |reservation: &QueryFanoutMemoryReservation| {
            reservation.admission.is_some_and(|admission| {
                admission.pool_generation == app.query_fanout_inflight.generation()
            })
        };
        COLLECTION_READ_MEMORY_RESERVATION
            .try_with(Clone::clone)
            .ok()
            .filter(matches_pool)
            .or_else(|| {
                APP_ROUTED_READ_HTTP_ADMISSION
                    .try_with(|admission| admission.reservation.clone())
                    .ok()
                    .filter(matches_pool)
            })
    }
    #[cfg(not(feature = "app_api"))]
    {
        let _ = app;
        None
    }
}
/// Cloneable response-only owner for a move-only ordinary-query lease.
#[derive(Clone, Debug)]
struct OrdinaryQueryResponseMemory {
    /// Held only so the query memory lease is released when the last clone drops.
    _lease: Arc<iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryLease>,
}
impl OrdinaryQueryResponseMemory {
    fn new(lease: iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryLease) -> Self {
        Self {
            _lease: Arc::new(lease),
        }
    }
}
fn hold_ordinary_query_memory_in_response_body(
    mut response: Response,
    reservation: OrdinaryQueryResponseMemory,
) -> Response {
    use http_body_util::BodyExt as _;
    response.extensions_mut().insert(reservation.clone());
    let (parts, body) = response.into_parts();
    let guarded_body = body.map_frame(move |frame| {
        let _reservation = &reservation;
        frame
    });
    Response::from_parts(parts, Body::new(guarded_body))
}
#[cfg(feature = "connect")]
fn take_ordinary_query_memory_reservation(
    response: &mut Response,
) -> Option<OrdinaryQueryResponseMemory> {
    response
        .extensions_mut()
        .remove::<OrdinaryQueryResponseMemory>()
}
fn hold_query_fanout_memory_reservation_in_response_body(
    mut response: Response,
    reservation: QueryFanoutMemoryReservation,
) -> Response {
    if reservation.admission.is_some() {
        return response_memory_custody::hold(response, reservation);
    }
    // Native proof producers already attach their original physical memory token to
    // EncodedBody-owned Bytes. Body-only custody never promotes those tokens to query admission.
    use http_body_util::BodyExt as _;
    response.extensions_mut().insert(reservation.clone());
    let (parts, body) = response.into_parts();
    let guarded_body = body.map_frame(move |frame| {
        let _reservation = &reservation;
        frame
    });
    Response::from_parts(parts, Body::new(guarded_body))
}
#[cfg(feature = "connect")]
fn take_query_fanout_memory_reservation(
    response: &mut Response,
) -> Option<QueryFanoutMemoryReservation> {
    response
        .extensions_mut()
        .remove::<QueryFanoutMemoryReservation>()
}
fn should_skip_singleton_routed_query_route_error(response: &Response) -> bool {
    response.status() == StatusCode::NOT_FOUND
        || torii_response_has_reject_code(response, "route_unavailable")
}
/// Fixed-size summary of skippable routed-query failures.
///
/// A route response can own a bounded but still large body. Only these two
/// bits survive into the next route; [`Self::record_and_drop`] destroys the
/// response (and therefore its body stream) immediately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SkippedRoutedQueryErrors {
    saw_not_found: bool,
    saw_route_unavailable: bool,
}
impl SkippedRoutedQueryErrors {
    fn record_and_drop(&mut self, response: Response) {
        if torii_response_has_reject_code(&response, "route_unavailable") {
            self.saw_route_unavailable = true;
        } else {
            debug_assert_eq!(response.status(), StatusCode::NOT_FOUND);
            self.saw_not_found = true;
        }
        drop(response);
    }
    fn into_response(self) -> Response {
        if self.saw_route_unavailable {
            return torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "one or more queried dataspace routes were unavailable",
            );
        }
        if self.saw_not_found {
            return torii_proxy_error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "query result was not found in any dataspace",
            );
        }
        torii_proxy_error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "query result was not found in any dataspace",
        )
    }
}
/// A fixed-size absence summary; route bodies and decoded selectors never cross route boundaries.
#[derive(Debug, Default)]
struct SingularRoutedQueryErrors {
    skipped: SkippedRoutedQueryErrors,
    saw_matching_asset_absence: bool,
    saw_other_not_found: bool,
}
impl SingularRoutedQueryErrors {
    async fn record_and_drop(
        &mut self,
        response: Response,
        verified_request_frame: &[u8],
        envelope: QueryFanoutMemoryEnvelope,
        body_read_timeout: Duration,
    ) -> Result<(), Response> {
        if torii_response_has_reject_code(&response, "route_unavailable") {
            self.skipped.record_and_drop(response);
            return Ok(());
        }
        debug_assert_eq!(response.status(), StatusCode::NOT_FOUND);
        self.skipped.saw_not_found = true;
        // Decode the already charged request frame in its existing request phase. The selector
        // stays borrowed from this transient request while one bounded error is authenticated.
        let request =
            decode_verified_singular_fanout_request_bounded(verified_request_frame, envelope)?;
        let iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetById(query),
        ) = &request.request
        else {
            self.saw_other_not_found = true;
            drop(response);
            return Ok(());
        };
        if matching_singular_asset_absence(response, &query.id, envelope, body_read_timeout).await?
        {
            self.saw_matching_asset_absence = true;
        } else {
            self.saw_other_not_found = true;
        }
        Ok(())
    }
    fn into_response(
        self,
        verified_request_frame: &[u8],
        envelope: QueryFanoutMemoryEnvelope,
        format: ResponseFormat,
    ) -> Response {
        if self.skipped.saw_route_unavailable
            || self.saw_other_not_found
            || !self.saw_matching_asset_absence
        {
            return self.skipped.into_response();
        }
        let request =
            match decode_verified_singular_fanout_request_bounded(verified_request_frame, envelope)
            {
                Ok(request) => request,
                Err(response) => return response,
            };
        let iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetById(query),
        ) = request.request
        else {
            return self.skipped.into_response();
        };
        let error = ErrorEnvelope::new(
            "query_asset_not_found",
            "the requested asset was not found in any selected dataspace",
        )
        .with_details(ErrorDetails {
            query_asset_not_found: Some(query.id),
            ..Default::default()
        });
        let mut response = match format {
            ResponseFormat::Norito => {
                let _flags =
                    norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
                match utils::encode_norito_bounded(&error, envelope.final_body_bytes) {
                    Ok(bytes) => signed_query_fanout_response_from_norito_bytes(bytes),
                    Err(error) => return bounded_signed_query_fanout_encode_error_response(error),
                }
            }
            ResponseFormat::Json => {
                match utils::encode_json_bounded(&error, envelope.final_body_bytes) {
                    Ok(json) => signed_query_fanout_response_from_json(json),
                    Err(error) => {
                        return bounded_signed_query_fanout_json_encode_error_response(error);
                    }
                }
            }
        };
        *response.status_mut() = StatusCode::NOT_FOUND;
        response.headers_mut().insert(
            HeaderName::from_static("x-iroha-reject-code"),
            HeaderValue::from_static("query_asset_not_found"),
        );
        response
    }
}
/// Prove one selector-bound absence within the existing raw-body, decode and encoder phases.
async fn matching_singular_asset_absence(
    response: Response,
    expected: &iroha_data_model::asset::AssetId,
    envelope: QueryFanoutMemoryEnvelope,
    body_read_timeout: Duration,
) -> Result<bool, Response> {
    if response.status() != StatusCode::NOT_FOUND {
        drop(response);
        return Ok(false);
    }
    let invalid = || {
        torii_proxy_error_response(
            StatusCode::BAD_GATEWAY,
            "route_unavailable",
            "routed asset absence did not carry a canonical matching error envelope",
        )
    };
    let mut content_types = response
        .headers()
        .get_all(axum::http::header::CONTENT_TYPE)
        .iter();
    if content_types.next().map(HeaderValue::as_bytes) != Some(utils::NORITO_MIME_TYPE.as_bytes())
        || content_types.next().is_some()
    {
        drop(response);
        return Ok(false);
    }
    let declared_code_matches = response
        .headers()
        .contains_key("x-iroha-reject-code")
        .then(|| torii_response_has_reject_code(&response, "query_asset_not_found"));
    let (parts, body) = response.into_parts();
    // Body ownership carries any response lease until collection/cancellation completes. The
    // extension copy is released now, and no part of this response survives the next route.
    drop(parts);
    let bytes = tokio::time::timeout(
        body_read_timeout,
        axum::body::to_bytes(body, envelope.route_body_bytes),
    )
    .await
    .map_err(|_| invalid())?
    .map_err(|_| invalid())?;
    let error: ErrorEnvelope = norito::decode_from_bytes_with_limits(
        &bytes,
        envelope.response_decode_limits(bytes.len())?,
    )
    .map_err(|_| invalid())?;
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let canonical = utils::encode_norito_bounded(&error, envelope.candidate_encoded_bytes)
        .map_err(|_| invalid())?;
    if canonical.as_slice() != bytes.as_ref() {
        return Err(invalid());
    }
    if error.code() != "query_asset_not_found" {
        return Ok(false);
    }
    if declared_code_matches == Some(false)
        || error
            .details
            .as_ref()
            .and_then(|details| details.query_asset_not_found.as_ref())
            != Some(expected)
    {
        return Err(invalid());
    }
    Ok(true)
}
