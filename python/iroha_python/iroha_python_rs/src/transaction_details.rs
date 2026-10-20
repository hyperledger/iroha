//! Exact original transaction-details receipts under the existing selective verifier.
//!
//! The signed hash-only query preserves Torii's self/participant/operator policy.
//! No decoder grants read permission, finality, current state or route authority.
use super::*;
use iroha_torii_shared::PipelineTransactionDetailsResponse;

fn exact_entrypoint_hash(value: &str) -> PyResult<HashOf<TransactionEntrypoint>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !matches!(
            value.as_bytes()[63],
            b'1' | b'3' | b'5' | b'7' | b'9' | b'b' | b'd' | b'f'
        )
    {
        return Err(PyValueError::new_err(
            "transaction hash must be exact lowercase marked hexadecimal",
        ));
    }
    let parsed = parse_typed_hash::<TransactionEntrypoint>(value, "transaction hash")?;
    if hex_encode(parsed.as_ref()) != value {
        return Err(PyValueError::new_err(
            "transaction hash must be exact lowercase marked hexadecimal",
        ));
    }
    Ok(parsed)
}

/// Build one canonical signed details query without adding an authority predicate.
#[pyfunction]
#[pyo3(signature = (authority, private_key, network_id, transaction_hash, *, chain_discriminant))]
pub(super) fn build_find_transaction_details_query(
    py: Python<'_>,
    authority: &str,
    private_key: &Bound<'_, PyBytes>,
    network_id: &PyNetworkId,
    transaction_hash: &str,
    #[pyo3(from_py_with = exact_chain_discriminant)] chain_discriminant: u16,
) -> PyResult<Py<PyBytes>> {
    if !private_key.is_exact_instance_of::<PyBytes>() || private_key.as_bytes().len() != 32 {
        return Err(PyValueError::new_err(
            "query private key must be exact 32-byte Ed25519 bytes",
        ));
    }
    parse_selected_account_id(authority, "query authority", chain_discriminant)?;
    let expected = exact_entrypoint_hash(transaction_hash)?;
    let predicate = CompoundPredicate::<CommittedTransaction>::from_filters(CommittedTxFilters {
        entry_eq: Some(expected),
        ..CommittedTxFilters::default()
    });
    let request = QueryRequest::Start(QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindTransactions),
        item: QueryItemKind::CommittedTransaction,
        predicate_bytes: norito::codec::Encode::encode(&predicate),
        selector_bytes: norito::codec::Encode::encode(
            &SelectorTuple::<CommittedTransaction>::default(),
        ),
        params: QueryParams::default(),
    });
    let wire = sign_query_request(
        authority,
        private_key.as_bytes(),
        network_id.as_inner(),
        request,
    )?;
    Ok(PyBytes::new(py, &wire).unbind())
}

pub(super) fn decode_bound_details(
    expected: HashOf<TransactionEntrypoint>,
    wire: &[u8],
) -> PyResult<CommittedTransaction> {
    if wire.is_empty() || wire.len() > 32 * 1024 * 1024 {
        return Err(PyValueError::new_err(
            "details response must contain 1..32 MiB",
        ));
    }
    let details: PipelineTransactionDetailsResponse =
        norito::decode_canonical_for_admission(wire, norito::canonical_decode_limits(wire.len()))
            .map_err(|e| {
            PyValueError::new_err(format!(
                "invalid canonical transaction details response: {e}"
            ))
        })?;
    // Match the server's exact native hash spelling and the selected row separately.
    // Do not accept signed inner hashes as aliases for an outer reveal entrypoint.
    if details.hash != expected.to_string() || details.transaction.entrypoint_hash != expected {
        return Err(PyValueError::new_err(
            "details response hash or row differs from requested transaction",
        ));
    }
    Ok(details.transaction)
}

/// Read a bound carrier hint only. This does not authenticate execution or finality.
#[pyfunction]
pub(super) fn transaction_details_carrier_block_hash(
    transaction_hash: &str,
    details_response_bytes: &Bound<'_, PyBytes>,
) -> PyResult<String> {
    if !details_response_bytes.is_exact_instance_of::<PyBytes>() {
        return Err(PyTypeError::new_err(
            "details response must be exact immutable bytes",
        ));
    }
    let row = decode_bound_details(
        exact_entrypoint_hash(transaction_hash)?,
        details_response_bytes.as_bytes(),
    )?;
    Ok(hex_encode(row.block_hash.as_ref()))
}

/// Authenticate exact original details bytes and project using the sole output producer.
#[pyfunction]
#[pyo3(signature = (transaction_hash, details_response_bytes, native_finality_proof_chain_json, expected_network_id, expected_chain, trusted_checkpoint, *, expected_chain_discriminant))]
pub(super) fn verify_transaction_details_inclusion(
    py: Python<'_>,
    transaction_hash: &str,
    details_response_bytes: &Bound<'_, PyBytes>,
    native_finality_proof_chain_json: &str,
    expected_network_id: &PyNetworkId,
    expected_chain: &str,
    trusted_checkpoint: &Bound<'_, PyBytes>,
    #[pyo3(from_py_with = exact_chain_discriminant)] expected_chain_discriminant: u16,
) -> PyResult<(String, Py<PyBytes>)> {
    if !details_response_bytes.is_exact_instance_of::<PyBytes>()
        || !trusted_checkpoint.is_exact_instance_of::<PyBytes>()
    {
        return Err(PyTypeError::new_err(
            "details response and checkpoint must be exact immutable bytes",
        ));
    }
    let expected = exact_entrypoint_hash(transaction_hash)?;
    let (committed, page) = committed_transaction_verification::authenticate_selected_response(
        expected,
        details_response_bytes.as_bytes(),
        native_finality_proof_chain_json,
        *expected_network_id.as_inner(),
        expected_chain,
        trusted_checkpoint.as_bytes(),
        |wire| decode_bound_details(expected, wire),
    )?;
    project_authenticated_committed_transaction(
        py,
        committed,
        page,
        expected_network_id,
        expected_chain_discriminant,
    )
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(
        build_find_transaction_details_query,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        transaction_details_carrier_block_hash,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        verify_transaction_details_inclusion,
        module
    )?)
}
