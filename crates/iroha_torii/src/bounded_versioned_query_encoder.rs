// Bounded versioned query payload encoding; included at the original crate-root scope.
struct FixedCapacityNoritoWriter<'a> {
    bytes: &'a mut Vec<u8>,
    max_bytes: usize,
}
impl std::io::Write for FixedCapacityNoritoWriter<'_> {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        let remaining = self
            .max_bytes
            .checked_sub(self.bytes.len())
            .ok_or_else(|| std::io::Error::other("Norito writer exceeded its admitted bound"))?;
        if chunk.len() > remaining {
            return Err(std::io::Error::other(
                "Norito payload exceeded its counted bound",
            ));
        }
        self.bytes.extend_from_slice(chunk);
        Ok(chunk.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn encode_versioned_norito_bounded<T>(value: &T, max_bytes: usize) -> Result<Vec<u8>, Response>
where
    T: iroha_version::Version + norito::core::SerializePayload,
{
    // Count a real serialization into a sink. `encoded_len_exact` is an
    // optimization hint and cannot be trusted as an admission boundary for a
    // custom erased query implementation.
    let payload_bytes =
        norito::codec::encode_adaptive_into(value, &mut std::io::sink()).map_err(|_| {
            torii_proxy_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_encoding_failed",
                "failed to count the signed-query versioned frame",
            )
        })?;
    let encoded_bytes = payload_bytes.checked_add(1).ok_or_else(|| {
        torii_proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "query_capacity_exceeded",
            "signed-query versioned frame length overflows the platform address space",
        )
    })?;
    if encoded_bytes > max_bytes {
        return Err(torii_proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "query_capacity_exceeded",
            format!(
                "signed-query versioned frame requires {encoded_bytes} bytes but its admitted request limit is {max_bytes} bytes"
            ),
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(encoded_bytes).map_err(|_| {
        torii_proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "query_capacity_exceeded",
            "failed to reserve the admitted signed-query versioned frame",
        )
    })?;
    bytes.push(iroha_version::Version::version(value));
    let written = {
        let mut writer = FixedCapacityNoritoWriter {
            bytes: &mut bytes,
            max_bytes: encoded_bytes,
        };
        norito::codec::encode_adaptive_into(value, &mut writer).map_err(|_| {
            torii_proxy_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_encoding_failed",
                "failed to encode the admitted signed-query versioned frame",
            )
        })?
    };
    if written != payload_bytes || bytes.len() != encoded_bytes {
        return Err(torii_proxy_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "query_encoding_failed",
            format!(
                "signed-query length changed between preflight ({encoded_bytes}) and encoding ({})",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn encode_signed_query_versioned_bounded(
    query: &SignedQuery,
    max_bytes: usize,
) -> Result<Vec<u8>, Response> {
    encode_versioned_norito_bounded(query, max_bytes)
}
