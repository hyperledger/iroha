//! Selective transaction evidence under the ordinary Explorer visibility boundary.
//!
//! The authenticated history carrier stays private. Only the selected Network input,
//! its joined output and their Merkle paths leave this producer, alongside the original
//! compact certificate. Consumers must verify that certificate from their own root.

use super::*;
use iroha_crypto::MerkleProof;
use iroha_data_model::block::execution_output::ExecutionOutputV1;
use norito::json::{BoundedJsonError, FastJsonWrite, JsonWriteSink};

const ENDPOINT: &str = "/v1/explorer/transactions/{hash}/proof";
/// Public JSON carrier ceiling, additionally restricted by the admitted query budget.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(crate::json_macros::JsonSerialize)]
struct TransactionProof<'a> {
    version: u8,
    network_id: &'a dm::NetworkId,
    block_height: u64,
    block_header: BlockHeader,
    transaction: TransactionProjection<'a>,
    certificate: CertificateProjection<'a>,
}

// Exactly CommittedTransaction's native JSON layout, borrowing both potentially large
// model values. The shared model decoder and inclusion verifier exercise this projection.
#[derive(crate::json_macros::JsonSerialize)]
struct TransactionProjection<'a> {
    block_hash: HashOf<BlockHeader>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    entrypoint_proof: MerkleProof<TransactionEntrypoint>,
    entrypoint: &'a TransactionEntrypoint,
    output_hash: HashOf<ExecutionOutputV1>,
    output_proof: MerkleProof<ExecutionOutputV1>,
    output: &'a ExecutionOutputV1,
}

#[derive(crate::json_macros::JsonSerialize)]
struct CertificateProjection<'a> {
    consensus_header: Base64Bytes<'a>,
    commit_qc: Base64Bytes<'a>,
    result_preimage: Base64Bytes<'a>,
}

struct Base64Bytes<'a>(&'a [u8]);
impl FastJsonWrite for Base64Bytes<'_> {
    fn write_json(&self, out: &mut String) {
        norito::json::write_json_unbounded(self, out);
    }

    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        norito::json::write_base64_json_to(self.0, out)
    }
}

/// Produce one bounded selective proof under an already admitted Explorer read.
pub(crate) async fn admitted(
    state: Arc<CoreState>,
    telemetry: MaybeTelemetry,
    visibility: DataspaceReadVisibility,
    identifier: String,
    admission: crate::QueryAdmissionPermit,
) -> Result<AxResponse, Error> {
    run_admitted_blocking(admission, "Explorer proof worker failed", move || {
        response(state, telemetry, visibility, identifier)
    })
    .await
}

pub(super) fn response(
    state: Arc<CoreState>,
    telemetry: MaybeTelemetry,
    visibility: DataspaceReadVisibility,
    identifier: String,
) -> Result<AxResponse, Error> {
    response_with_limit(state, telemetry, visibility, identifier, MAX_RESPONSE_BYTES)
}

pub(super) fn response_with_limit(
    state: Arc<CoreState>,
    telemetry: MaybeTelemetry,
    visibility: DataspaceReadVisibility,
    identifier: String,
    maximum_response_bytes: usize,
) -> Result<AxResponse, Error> {
    let started = std::time::Instant::now();
    let result = (|| {
        let detail = find_transaction_detail(
            state.as_ref(),
            state.committed_height() as u64,
            &visibility,
            identifier,
        )?;
        let row = detail.0;
        let block = row.block.as_ref();
        let height = block.header().height().get();
        // Genesis has no quorum certificate. Do not present its unsigned execution as
        // ordinary finalized transaction evidence.
        if height < 2 {
            return Err(explorer_not_found());
        }
        let owner = crate::history_producer::HistoryProducerOwner::current()?;
        let proof = projection(state.network_id_ref(), &row, &owner)?;
        require_history_anchor(&state, height, block.hash())?;
        let mut response =
            owner.json_with_limit(&proof, maximum_response_bytes.min(MAX_RESPONSE_BYTES))?;
        require_history_anchor(&state, height, block.hash())?;
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("private, no-store"),
        );
        Ok(response)
    })();
    record_explorer_endpoint_result(&telemetry, ENDPOINT, started, &result);
    result
}

fn projection<'a>(
    network_id: &'a dm::NetworkId,
    row: &'a crate::explorer_history::HistoryTransactionRow,
    owner: &crate::history_producer::HistoryProducerOwner,
) -> Result<TransactionProof<'a>, Error> {
    let invalid = || query_internal_error("canonical transaction proof source is inconsistent");
    let block = row.block.as_ref();
    let input_index = u32::try_from(row.entrypoint_index).map_err(|_| invalid())?;
    let entrypoint = block
        .network_entrypoint_at(row.entrypoint_index)
        .ok_or_else(invalid)?;
    if entrypoint.hash() != row.entrypoint_hash {
        return Err(invalid());
    }
    let (output_index, _) = block.network_output_at(input_index).ok_or_else(invalid)?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or_else(invalid)?;

    // The complete input tree is temporary; bound its construction queue and tree
    // backing plus both <=32-node paths before allocation. The output tree is already
    // retained by the authenticated block. No transaction or output graph is cloned.
    let scratch_bytes = block
        .network_entrypoint_count()
        .checked_next_power_of_two()
        .and_then(|count| count.checked_mul(4))
        .and_then(|count| count.checked_add(64))
        .and_then(|count| {
            count.checked_mul(std::mem::size_of::<Option<HashOf<TransactionEntrypoint>>>())
        })
        .ok_or_else(history_capacity_error)?;
    if scratch_bytes > owner.retained_bytes() {
        return Err(history_capacity_error());
    }
    owner
        .scope(|| norito::core::reserve_decode_allocation(scratch_bytes))
        .map_err(|_| history_capacity_error())?;
    let entrypoint_proof = block.network_input_proof(input_index).ok_or_else(invalid)?;
    let output_proof = block.output_proof(output_index).ok_or_else(invalid)?;
    let certificate = block.commit_certificate().ok_or_else(invalid)?;
    for (bytes, limit) in [
        (certificate.consensus_header(), 64 * 1024),
        (certificate.commit_qc(), 4 * 1024),
        (certificate.result_preimage(), 64 * 1024),
    ] {
        if bytes.is_empty() || bytes.len() > limit {
            return Err(invalid());
        }
    }
    Ok(TransactionProof {
        version: 1,
        network_id,
        block_height: block.header().height().get(),
        block_header: block.header(),
        transaction: TransactionProjection {
            block_hash: block.hash(),
            entrypoint_hash: row.entrypoint_hash,
            entrypoint_proof,
            entrypoint,
            output_hash: HashOf::new(output),
            output_proof,
            output,
        },
        certificate: CertificateProjection {
            consensus_header: Base64Bytes(certificate.consensus_header()),
            commit_qc: Base64Bytes(certificate.commit_qc()),
            result_preimage: Base64Bytes(certificate.result_preimage()),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explorer_transaction_proof_base64_preserves_padding_and_exact_sink_bounds() {
        for (bytes, expected) in [
            (b"".as_slice(), "\"\""),
            (b"f".as_slice(), "\"Zg==\""),
            (b"fo".as_slice(), "\"Zm8=\""),
            (b"foo".as_slice(), "\"Zm9v\""),
            (b"\xfb\xff".as_slice(), "\"+/8=\""),
        ] {
            let value = Base64Bytes(bytes);
            assert_eq!(
                norito::json::to_json_bounded(&value, expected.len()).unwrap(),
                expected,
            );
            let mut ordinary = String::new();
            value.write_json(&mut ordinary);
            assert_eq!(ordinary, expected);
            for limit in 0..expected.len() {
                assert_eq!(
                    norito::json::to_json_bounded(&value, limit),
                    Err(BoundedJsonError::BodyTooLarge),
                    "certificate bytes must not escape the JSON sink limit {limit}",
                );
            }
        }
    }

    #[test]
    fn explorer_transaction_proof_certificate_has_one_cumulative_output_bound() {
        let certificate = CertificateProjection {
            consensus_header: Base64Bytes(b"f"),
            commit_qc: Base64Bytes(b"fo"),
            result_preimage: Base64Bytes(b"foo"),
        };
        let expected = r#"{"consensus_header":"Zg==","commit_qc":"Zm8=","result_preimage":"Zm9v"}"#;
        assert_eq!(
            norito::json::to_json_bounded(&certificate, expected.len()).unwrap(),
            expected,
        );
        assert_eq!(
            norito::json::to_json_bounded(&certificate, expected.len() - 1),
            Err(BoundedJsonError::BodyTooLarge),
        );
    }
}
