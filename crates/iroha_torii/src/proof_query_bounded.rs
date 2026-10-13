#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_bounded_proof_query(
    dto: crate::routing::ProofFindByIdQueryDto,
    envelope: QueryFanoutMemoryEnvelope,
) -> Result<SignedQuery, Response> {
    use iroha_data_model::query::{QueryRequest, SingularQueryBox};
    use iroha_version::codec::DecodeVersioned as _;
    if dto.signed_query_b64.len() > canonical_base64_max_len(envelope.route_body_bytes) {
        return Err(torii_proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "query_capacity_exceeded",
            "proof signed-query envelope exceeds its admitted request limit",
        ));
    }
    if !dto.signed_query_b64.len().is_multiple_of(4) {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_query_payload",
            "proof signed-query envelope is not canonical padded base64",
        ));
    }
    let padding = if dto.signed_query_b64.ends_with("==") {
        2
    } else if dto.signed_query_b64.ends_with('=') {
        1
    } else {
        0
    };
    let decoded_len = (dto.signed_query_b64.len() / 4)
        .checked_mul(3)
        .and_then(|len| len.checked_sub(padding))
        .ok_or_else(|| {
            torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "proof signed-query envelope length exceeds the platform address space",
            )
        })?;
    if decoded_len > envelope.route_body_bytes {
        return Err(torii_proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "query_capacity_exceeded",
            "proof signed-query envelope exceeds its admitted request limit",
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(decoded_len).map_err(|_| {
        torii_proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "query_capacity_exceeded",
            "failed to reserve the admitted proof signed-query envelope",
        )
    })?;
    bytes.resize(decoded_len, 0);
    let written = BASE64_STANDARD
        .decode_slice(dto.signed_query_b64.as_bytes(), &mut bytes)
        .map_err(|_| {
            torii_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_query_payload",
                "proof signed-query envelope is not valid base64",
            )
        })?;
    if written != decoded_len {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_query_payload",
            "proof signed-query envelope has a non-canonical decoded length",
        ));
    }
    if BASE64_STANDARD.encode(&bytes) != dto.signed_query_b64 {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_query_payload",
            "proof signed-query envelope must use canonical padded base64",
        ));
    }
    let decode_limits = envelope.request_decode_limits(bytes.len())?;
    let signed = norito::with_decode_limits_scope(decode_limits, || {
        SignedQuery::decode_all_versioned(&bytes)
    })
    .map_err(|error| {
        if error.is_decode_resource_limit() {
            torii_proxy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                "proof signed-query envelope exceeds its admitted decode limit",
            )
        } else {
            torii_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_query_payload",
                "proof signed-query envelope is not valid versioned Norito",
            )
        }
    })?;
    if !matches!(
        signed.request(),
        QueryRequest::Singular(SingularQueryBox::FindProofRecordById(_))
    ) {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_query_payload",
            "proof signed-query envelope must contain FindProofRecordById",
        ));
    }
    Ok(signed)
}
async fn execute_bounded_proof_query(
    app: &SharedAppState,
    dto: crate::routing::ProofFindByIdQueryDto,
    format: ResponseFormat,
) -> Result<Response, Error> {
    let reservation = match try_acquire_query_fanout_memory(app) {
        Ok(reservation) => reservation,
        Err(response) => return Ok(response),
    };
    let provisional =
        match QueryFanoutMemoryEnvelope::for_body_admission(app.query_fanout_working_set_bytes) {
            Ok(envelope) => envelope,
            Err(response) => {
                return Ok(hold_query_fanout_memory_in_response_body(
                    response,
                    reservation,
                ));
            }
        };
    let signed = match decode_bounded_proof_query(dto, provisional) {
        Ok(signed) => signed,
        Err(response) => {
            return Ok(hold_query_fanout_memory_in_response_body(
                response,
                reservation,
            ));
        }
    };
    let query_bytes =
        match encode_signed_query_versioned_bounded(&signed, provisional.route_body_bytes) {
            Ok(bytes) => bytes,
            Err(response) => {
                return Ok(hold_query_fanout_memory_in_response_body(
                    response,
                    reservation,
                ));
            }
        };
    let envelope = match exact_query_fanout_envelope(
        app.query_fanout_working_set_bytes,
        query_bytes.len(),
        &signed.payload,
    ) {
        Ok(envelope) => envelope,
        Err(response) => {
            return Ok(hold_query_fanout_memory_in_response_body(
                response,
                reservation,
            ));
        }
    };
    let verified =
        routing::verify_signed_query_request(signed, app.signed_query_admission.as_ref())?;
    drop(query_bytes);
    let query_response = match execute_torii_verified_query_route_scan_locally(
        app,
        verified,
        envelope,
        reservation.clone(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => {
            return Ok(hold_query_fanout_memory_in_response_body(
                response,
                reservation,
            ));
        }
    };
    let response =
        bounded_singular_fanout_response(query_response, format, envelope.final_body_bytes);
    Ok(hold_query_fanout_memory_in_response_body(
        response,
        reservation,
    ))
}
