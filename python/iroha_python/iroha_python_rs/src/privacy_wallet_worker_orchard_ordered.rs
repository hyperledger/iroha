/// Decode the explicit ordered variant; absence alone selects standalone execution.
///
/// The public intent and execution plan each carry this same closed object. Its bytes are
/// covered by the existing public-intent digest held by the native witness handle. This is an
/// additive typed operation within IPWW v1, not a second framing or lifecycle protocol.
fn validate_orchard_contract_calls_v1(
    value: Option<&norito::json::Value>,
    protocol: &str,
    error: WorkerError,
) -> Result<Option<OrchardOrderedContractCallsV1>, WorkerError> {
    use iroha_data_model::transaction::executable::ContractInvocation;

    let Some(value) = value else {
        return Ok(None);
    };
    if protocol != PrivacyProtocolIdV1::OrchardHalo2ActionsV1.canonical_label() {
        return Err(error);
    }
    let object = value.as_object().ok_or(error)?;
    if object.len() != 3
        || !["schema_version", "before", "after"]
            .iter()
            .all(|field| object.contains_key(*field))
        || object
            .get("schema_version")
            .and_then(norito::json::Value::as_u64)
            != Some(1)
    {
        return Err(error);
    }
    let before = object
        .get("before")
        .and_then(norito::json::Value::as_array)
        .ok_or(error)?;
    let after = object
        .get("after")
        .and_then(norito::json::Value::as_array)
        .ok_or(error)?;
    let limit = usize::try_from(
        iroha_data_model::parameter::TransactionParameters::default()
            .max_instructions()
            .get(),
    )
    .map_err(|_| error)?;
    if before.is_empty()
        || after.is_empty()
        || before.len() >= limit
        || after.len() >= limit
        || before
            .len()
            .checked_add(after.len())
            .and_then(|count| count.checked_add(1))
            .is_none_or(|count| count > limit)
    {
        return Err(error);
    }
    let decode_call = |value: &norito::json::Value| -> Result<ContractInvocation, WorkerError> {
        let call = value.as_object().ok_or(error)?;
        // The derived model decoder alone is not the closed public request contract.
        if call.len() != 4
            || ![
                "contract_address",
                "expected_code_hash",
                "entrypoint",
                "arguments",
            ]
            .iter()
            .all(|field| call.contains_key(*field))
        {
            return Err(error);
        }
        norito::json::from_value(value.clone()).map_err(|_| error)
    };
    let before = before.iter().map(decode_call).collect::<Result<_, _>>()?;
    let after = after.iter().map(decode_call).collect::<Result<_, _>>()?;
    OrchardOrderedContractCallsV1::try_new(before, after)
        .map(Some)
        .map_err(|_| error)
}

/// Inspect both actual public wire encodings against the independently retained request.
fn inspect_ordered_response_v1(
    response: &SignedActionResponseV1,
    expected_context: &PrivacyActionTransactionContextV1,
    expected_calls: &OrchardOrderedContractCallsV1,
) -> Result<(), WorkerError> {
    use iroha_data_model::transaction::SignedTransaction;
    use iroha_version::codec::DecodeVersioned;

    let adaptive: SignedTransaction =
        norito::codec::decode_adaptive(&response.adaptive_signed_transaction)
            .map_err(|_| WorkerError::NativeSelfInspectionFailed)?;
    let versioned = SignedTransaction::decode_all_versioned(&response.versioned_signed_transaction)
        .map_err(|_| WorkerError::NativeSelfInspectionFailed)?;
    for signed in [&adaptive, &versioned] {
        let inspected = inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
            signed,
            expected_context,
            expected_calls,
        )
        .map_err(|_| WorkerError::NativeSelfInspectionFailed)?;
        if inspected.action().transaction_hash() != response.transaction_hash {
            return Err(WorkerError::NativeSelfInspectionFailed);
        }
    }
    Ok(())
}
