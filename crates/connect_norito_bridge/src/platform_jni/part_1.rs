pub(super) fn throw_java_illegal_argument(env: &mut jni::JNIEnv<'_>, message: String) {
    let _ = env.throw_new("java/lang/IllegalArgumentException", message);
}
pub(super) fn throw_java_illegal_state(env: &mut jni::JNIEnv<'_>, message: String) {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}
pub(super) fn catch_unwind_to_java<T, F>(env: &mut jni::JNIEnv<'_>, label: &str, f: F) -> Option<T>
where
    F: FnOnce() -> T,
{
    use std::panic::{AssertUnwindSafe, catch_unwind};
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Some(value),
        Err(_) => {
            throw_java_illegal_state(env, format!("{label} panicked"));
            None
        }
    }
}
pub(super) fn read_java_byte_array(
    env: &mut jni::JNIEnv<'_>,
    array: &jni::objects::JByteArray<'_>,
    context: &str,
) -> Option<Vec<u8>> {
    let _len = match env.get_array_length(array) {
        Ok(value) => value,
        Err(err) => {
            throw_java_illegal_argument(
                env,
                format!("{context} failed to read array length: {err}"),
            );
            return None;
        }
    } as usize;
    env.convert_byte_array(array).map_or_else(
        |err| {
            throw_java_illegal_state(
                env,
                format!("{context} failed to read array contents: {err}"),
            );
            None
        },
        Some,
    )
}
pub(super) fn read_java_byte_array_bounded(
    env: &mut jni::JNIEnv<'_>,
    array: &jni::objects::JByteArray<'_>,
    context: &str,
    maximum: usize,
) -> Option<Vec<u8>> {
    let len = match env.get_array_length(array) {
        Ok(value) => usize::try_from(value).ok(),
        Err(err) => {
            throw_java_illegal_argument(
                env,
                format!("{context} failed to read array length: {err}"),
            );
            return None;
        }
    }?;
    if len == 0 || len > maximum {
        throw_java_illegal_argument(env, format!("{context} must contain 1..{maximum} bytes"));
        return None;
    }
    env.convert_byte_array(array).map_or_else(
        |err| {
            throw_java_illegal_state(
                env,
                format!("{context} failed to read array contents: {err}"),
            );
            None
        },
        Some,
    )
}
pub(super) fn java_validation_fee_policy_proof_result(
    env: &mut jni::JNIEnv<'_>,
    body: impl FnOnce(&mut jni::JNIEnv<'_>) -> Result<Vec<u8>, String>,
) -> jni::sys::jbyteArray {
    match body(env).and_then(|bytes| {
        env.byte_array_from_slice(&bytes)
            .map(jni::objects::JByteArray::into_raw)
            .map_err(|error| error.to_string())
    }) {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, format!("validation-fee consensus proof: {message}"));
            std::ptr::null_mut()
        }
    }
}
pub(super) fn java_native_validation_fee_current_policy_proof_request_v1(
    env: &mut jni::JNIEnv<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_validation_fee_policy_proof_result(env, |env| {
        let checkpoint = read_java_byte_array_bounded(
            env,
            &trusted_checkpoint,
            "trustedCheckpoint",
            iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
        )
        .ok_or_else(|| {
            "trustedCheckpoint must contain one bounded canonical checkpoint".to_owned()
        })?;
        validation_fee_current_policy_proof_request_v1(&checkpoint)
            .map_err(|_| "trusted checkpoint was rejected".to_owned())
    })
}
pub(super) fn java_native_validation_fee_current_policy_proof_verify_v1(
    env: &mut jni::JNIEnv<'_>,
    proof_norito: jni::objects::JByteArray<'_>,
    network_id: jni::objects::JByteArray<'_>,
    policy_chain_genesis_hash: jni::objects::JByteArray<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = read_java_byte_array_bounded(
            env,
            &proof_norito,
            "proofNorito",
            VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES,
        )
        .ok_or_else(|| "proofNorito must be a bounded nonempty archive".to_owned())?;
        let network_id: [u8; 32] = read_java_byte_array_bounded(env, &network_id, "networkId", 32)
            .ok_or_else(|| "networkId must contain exactly 32 bytes".to_owned())?
            .try_into()
            .map_err(|_| "networkId must contain exactly 32 bytes".to_owned())?;
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::prehashed(network_id)),
        );
        let policy_chain_genesis_hash: [u8; 32] = read_java_byte_array_bounded(
            env,
            &policy_chain_genesis_hash,
            "policyChainGenesisHash",
            32,
        )
        .ok_or_else(|| "policyChainGenesisHash must contain exactly 32 bytes".to_owned())?
        .try_into()
        .map_err(|_| "policyChainGenesisHash must contain exactly 32 bytes".to_owned())?;
        let checkpoint = read_java_byte_array_bounded(
            env,
            &trusted_checkpoint,
            "trustedCheckpoint",
            iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
        )
        .ok_or_else(|| {
            "trustedCheckpoint must contain one bounded canonical checkpoint".to_owned()
        })?;
        let (projection, promoted) = validation_fee_current_policy_proof_verify_v1(
            &proof,
            network_id,
            policy_chain_genesis_hash,
            &checkpoint,
        )
        .map_err(|_| {
            "proof, finality, registry, or immutable deployment binding was rejected".to_owned()
        })?;
        java_byte_array_pair(env, &projection, &promoted)
    }));
    match result {
        Ok(Ok(array)) => array,
        Ok(Err(message)) => {
            throw_java_illegal_argument(env, format!("validation-fee consensus proof: {message}"));
            std::ptr::null_mut()
        }
        Err(_) => {
            throw_java_illegal_state(env, "validation-fee consensus proof panicked".to_owned());
            std::ptr::null_mut()
        }
    }
}
/// Report the exact native ABI required by the validation-fee proof bridge.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_validationfee_ValidationFeeConsensusProofBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}
/// JNI projection of the complete-checkpoint request encoder.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_validationfee_ValidationFeeConsensusProofBridge_nativeEncodeCurrentPolicyProofRequestV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_native_validation_fee_current_policy_proof_request_v1(&mut env, trusted_checkpoint)
}
/// JNI verifier returning the projection JSON and promoted canonical checkpoint as two arrays.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_validationfee_ValidationFeeConsensusProofBridge_nativeVerifyCurrentPolicyProofV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    proof_norito: jni::objects::JByteArray<'_>,
    network_id: jni::objects::JByteArray<'_>,
    policy_chain_genesis_hash: jni::objects::JByteArray<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    java_native_validation_fee_current_policy_proof_verify_v1(
        &mut env,
        proof_norito,
        network_id,
        policy_chain_genesis_hash,
        trusted_checkpoint,
    )
}
fn java_retail_fee_assessment_operation(
    env: &mut jni::JNIEnv<'_>,
    input: jni::objects::JByteArray<'_>,
    maximum_input_bytes: usize,
    operation: fn(&[u8]) -> BridgeResult<Vec<u8>>,
) -> jni::sys::jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = read_java_byte_array_bounded(env, &input, "input", maximum_input_bytes)
            .ok_or_else(|| "input must contain one bounded nonempty payload".to_owned())?;
        let output =
            operation(&bytes).map_err(|_| "invalid retail fee assessment or intent".to_owned())?;
        env.byte_array_from_slice(&output)
            .map(jni::objects::JByteArray::into_raw)
            .map_err(|error| error.to_string())
    }));
    match result {
        Ok(Ok(array)) => array,
        Ok(Err(message)) => {
            throw_java_illegal_argument(env, message);
            std::ptr::null_mut()
        }
        Err(_) => {
            throw_java_illegal_state(env, "retail fee codec panicked".to_owned());
            std::ptr::null_mut()
        }
    }
}
/// Reports the exact bridge ABI required by the retail assessment codec.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}
/// Native canonical retail fee codec.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeIntentHashV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    input: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_retail_fee_assessment_operation(
        &mut env,
        input,
        RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES,
        retail_fee_intent_hash_v1,
    )
}
/// Native canonical retail fee codec.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeAssessmentMarkerV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    input: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_retail_fee_assessment_operation(
        &mut env,
        input,
        RETAIL_FEE_ASSESSMENT_MAX_BYTES,
        retail_fee_assessment_marker_v1,
    )
}
/// Native canonical retail fee codec.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeDecodeAssessmentV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    input: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_retail_fee_assessment_operation(
        &mut env,
        input,
        RETAIL_FEE_MARKER_MAX_BYTES,
        retail_fee_assessment_decode_v1,
    )
}
pub(super) fn java_sorafs_reference_generated_at(
    generated_at: jni::sys::jlong,
) -> Result<u64, String> {
    u64::try_from(generated_at).map_err(|_| "generatedAtUnix must be non-negative".to_owned())
}
pub(super) fn read_java_sorafs_reference_byte_array(
    env: &mut jni::JNIEnv<'_>,
    array: &jni::objects::JByteArray<'_>,
    field: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let length = env
        .get_array_length(array)
        .map_err(|error| format!("failed to read {field} length: {error}"))?;
    let length = usize::try_from(length).map_err(|_| format!("{field} length is invalid"))?;
    if length > maximum {
        return Err(format!("{field} must be at most {maximum} bytes"));
    }
    read_java_byte_array(env, array, field)
        .ok_or_else(|| format!("failed to read {field} contents"))
}
pub(super) fn read_java_sorafs_reference_byte_array_vector(
    env: &mut jni::JNIEnv<'_>,
    values: &jni::objects::JObjectArray<'_>,
    field: &str,
    expected_count: Option<usize>,
    maximum_count: usize,
    maximum_bytes: usize,
) -> Result<Vec<Vec<u8>>, String> {
    let count = env
        .get_array_length(values)
        .map_err(|error| format!("failed to read {field} count: {error}"))?;
    let count = usize::try_from(count).map_err(|_| format!("{field} count is invalid"))?;
    if count == 0 || count > maximum_count {
        return Err(format!("{field} must contain 1..{maximum_count} entries"));
    }
    if let Some(expected_count) = expected_count
        && count != expected_count
    {
        return Err(format!(
            "{field} must contain exactly {expected_count} entries"
        ));
    }
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let object = env
            .get_object_array_element(
                values,
                i32::try_from(index).map_err(|_| format!("{field} count is invalid"))?,
            )
            .map_err(|error| format!("failed to read {field}[{index}]: {error}"))?;
        if object.is_null() {
            return Err(format!("{field}[{index}] must be a byte array"));
        }
        let array = jni::objects::JByteArray::from(object);
        result.push(read_java_sorafs_reference_byte_array(
            env,
            &array,
            &format!("{field}[{index}]"),
            maximum_bytes,
        )?);
    }
    Ok(result)
}
pub(super) unsafe fn java_sorafs_reference_buffer_bytes(
    buffer: sorafs_reference_ffi::SorafsReferenceFfiBuffer,
) -> Vec<u8> {
    let bytes = if buffer.ptr.is_null() || buffer.len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(buffer.ptr.cast_const(), buffer.len) }.to_vec()
    };
    unsafe { sorafs_reference_ffi::sorafs_reference_free_buffer(buffer) };
    bytes
}
pub(super) unsafe fn java_sorafs_reference_buffer_to_array(
    env: &mut jni::JNIEnv<'_>,
    buffer: sorafs_reference_ffi::SorafsReferenceFfiBuffer,
    context: &str,
) -> Result<jni::sys::jbyteArray, String> {
    let bytes = unsafe { java_sorafs_reference_buffer_bytes(buffer) };
    if bytes.is_empty() {
        return Err(format!("{context} returned empty outcome JSON"));
    }
    env.byte_array_from_slice(&bytes)
        .map(|array| array.into_raw())
        .map_err(|err| err.to_string())
}
pub(super) fn java_sorafs_reference_validate_orderbook_payload_json(
    env: &mut jni::JNIEnv<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let payload_bytes = read_java_byte_array(env, &payload, "noritoBytes")
            .ok_or_else(|| "invalid orderbook payload bytes".to_owned())?;
        let label_bytes = read_java_byte_array(env, &label, "label")
            .ok_or_else(|| "invalid orderbook label bytes".to_owned())?;
        let kind = u32::try_from(kind).map_err(|_| "kind must be non-negative".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_orderbook_json(
                kind,
                payload_bytes.as_ptr(),
                payload_bytes.len(),
                label_bytes.as_ptr(),
                label_bytes.len(),
                generated_at,
            )
        };
        unsafe { java_sorafs_reference_buffer_to_array(env, buffer, "SoraFS orderbook validation") }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_pop_payload_json(
    env: &mut jni::JNIEnv<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let payload_bytes = read_java_byte_array(env, &payload, "noritoBytes")
            .ok_or_else(|| "invalid PoP payload bytes".to_owned())?;
        let label_bytes = read_java_byte_array(env, &label, "label")
            .ok_or_else(|| "invalid PoP label bytes".to_owned())?;
        let kind = u32::try_from(kind).map_err(|_| "kind must be non-negative".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_pop_json(
                kind,
                payload_bytes.as_ptr(),
                payload_bytes.len(),
                label_bytes.as_ptr(),
                label_bytes.len(),
                generated_at,
            )
        };
        unsafe { java_sorafs_reference_buffer_to_array(env, buffer, "SoraFS PoP validation") }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_hedging_payload_json(
    env: &mut jni::JNIEnv<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let payload_bytes = read_java_byte_array(env, &payload, "noritoBytes")
            .ok_or_else(|| "invalid hedging payload bytes".to_owned())?;
        let label_bytes = read_java_byte_array(env, &label, "label")
            .ok_or_else(|| "invalid hedging label bytes".to_owned())?;
        let kind = u32::try_from(kind).map_err(|_| "kind must be non-negative".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_hedging_json(
                kind,
                payload_bytes.as_ptr(),
                payload_bytes.len(),
                label_bytes.as_ptr(),
                label_bytes.len(),
                generated_at,
            )
        };
        unsafe { java_sorafs_reference_buffer_to_array(env, buffer, "SoraFS hedging validation") }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json(
    env: &mut jni::JNIEnv<'_>,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let payload_bytes = read_java_byte_array(env, &payload, "noritoBytes")
            .ok_or_else(|| "invalid appeal-finance CancelAssetLock payload bytes".to_owned())?;
        let label_bytes = read_java_byte_array(env, &label, "label")
            .ok_or_else(|| "invalid appeal-finance CancelAssetLock label bytes".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_appeal_finance_cancel_asset_lock_json(
                payload_bytes.as_ptr(),
                payload_bytes.len(),
                label_bytes.as_ptr(),
                label_bytes.len(),
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(
                env,
                buffer,
                "SoraFS appeal-finance CancelAssetLock validation",
            )
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_governance_log_node_json(
    env: &mut jni::JNIEnv<'_>,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    expected_node_cid: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let maximum_input = CONNECT_NORITO_SORAFS_REFERENCE_MAX_INPUT_BYTES_V1 as usize;
        let maximum_label = CONNECT_NORITO_SORAFS_REFERENCE_MAX_LABEL_BYTES_V1 as usize;
        let cid_bytes = CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1 as usize;
        let payload_bytes =
            read_java_sorafs_reference_byte_array(env, &payload, "noritoBytes", maximum_input)?;
        let label_bytes =
            read_java_sorafs_reference_byte_array(env, &label, "label", maximum_label)?;
        let expected_node_cid_bytes = read_java_sorafs_reference_byte_array(
            env,
            &expected_node_cid,
            "expectedNodeCid",
            cid_bytes,
        )?;
        if expected_node_cid_bytes.len() != cid_bytes {
            return Err(format!(
                "expectedNodeCid must contain exactly {cid_bytes} bytes"
            ));
        }
        let aggregate_bytes = payload_bytes
            .len()
            .checked_add(label_bytes.len())
            .and_then(|total| total.checked_add(expected_node_cid_bytes.len()))
            .ok_or_else(|| "governance log-node aggregate input length overflowed".to_owned())?;
        if aggregate_bytes > maximum_input {
            return Err(format!(
                "governance log-node inputs must total at most {maximum_input} bytes"
            ));
        }
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_governance_json(
                payload_bytes.as_ptr(),
                payload_bytes.len(),
                label_bytes.as_ptr(),
                label_bytes.len(),
                expected_node_cid_bytes.as_ptr(),
                expected_node_cid_bytes.len(),
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(
                env,
                buffer,
                "SoraFS governance log-node validation",
            )
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_governance_dag_block_json(
    env: &mut jni::JNIEnv<'_>,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    expected_block_cid: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let maximum_input = CONNECT_NORITO_SORAFS_REFERENCE_MAX_INPUT_BYTES_V1 as usize;
        let maximum_label = CONNECT_NORITO_SORAFS_REFERENCE_MAX_LABEL_BYTES_V1 as usize;
        let cid_bytes = CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1 as usize;
        let payload_bytes =
            read_java_sorafs_reference_byte_array(env, &payload, "noritoBytes", maximum_input)?;
        let label_bytes =
            read_java_sorafs_reference_byte_array(env, &label, "label", maximum_label)?;
        let expected_block_cid_bytes = read_java_sorafs_reference_byte_array(
            env,
            &expected_block_cid,
            "expectedBlockCid",
            cid_bytes,
        )?;
        if !expected_block_cid_bytes.is_empty() && expected_block_cid_bytes.len() != cid_bytes {
            return Err(format!(
                "expectedBlockCid must be empty or exactly {cid_bytes} bytes"
            ));
        }
        let aggregate_bytes = payload_bytes
            .len()
            .checked_add(label_bytes.len())
            .and_then(|total| total.checked_add(expected_block_cid_bytes.len()))
            .ok_or_else(|| "governance DAG block aggregate input length overflowed".to_owned())?;
        if aggregate_bytes > maximum_input {
            return Err(format!(
                "governance DAG block inputs must total at most {maximum_input} bytes"
            ));
        }
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_governance_dag_block_json(
                payload_bytes.as_ptr(),
                payload_bytes.len(),
                label_bytes.as_ptr(),
                label_bytes.len(),
                expected_block_cid_bytes.as_ptr(),
                expected_block_cid_bytes.len(),
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(
                env,
                buffer,
                "SoraFS governance DAG block validation",
            )
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_governance_dag_head_chain_json(
    env: &mut jni::JNIEnv<'_>,
    head: jni::objects::JByteArray<'_>,
    head_label: jni::objects::JByteArray<'_>,
    blocks: jni::objects::JObjectArray<'_>,
    block_labels: jni::objects::JObjectArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let maximum_blocks = CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1 as usize;
        let maximum_input = CONNECT_NORITO_SORAFS_REFERENCE_MAX_INPUT_BYTES_V1 as usize;
        let maximum_label = CONNECT_NORITO_SORAFS_REFERENCE_MAX_LABEL_BYTES_V1 as usize;
        let head_bytes = read_java_sorafs_reference_byte_array(env, &head, "head", maximum_input)?;
        let head_label_bytes =
            read_java_sorafs_reference_byte_array(env, &head_label, "headLabel", maximum_label)?;
        let block_bytes = read_java_sorafs_reference_byte_array_vector(
            env,
            &blocks,
            "blocks",
            None,
            maximum_blocks,
            maximum_input,
        )?;
        let block_label_bytes = read_java_sorafs_reference_byte_array_vector(
            env,
            &block_labels,
            "blockLabels",
            Some(block_bytes.len()),
            maximum_blocks,
            maximum_label,
        )?;
        let mut aggregate_bytes = head_bytes
            .len()
            .checked_add(head_label_bytes.len())
            .ok_or_else(|| {
                "governance DAG head-chain aggregate input length overflowed".to_owned()
            })?;
        let mut descriptors = Vec::with_capacity(block_bytes.len());
        for (block, label) in block_bytes.iter().zip(&block_label_bytes) {
            aggregate_bytes = aggregate_bytes
                .checked_add(block.len())
                .and_then(|total| total.checked_add(label.len()))
                .ok_or_else(|| {
                    "governance DAG head-chain aggregate input length overflowed".to_owned()
                })?;
            if aggregate_bytes > maximum_input {
                return Err(format!(
                    "governance DAG head-chain inputs must total at most {maximum_input} bytes"
                ));
            }
            descriptors.push(sorafs_reference_ffi::SorafsReferenceFfiInput {
                bytes_ptr: block.as_ptr(),
                bytes_len: block.len(),
                label_ptr: label.as_ptr(),
                label_len: label.len(),
            });
        }
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_governance_dag_head_chain_json(
                head_bytes.as_ptr(),
                head_bytes.len(),
                head_label_bytes.as_ptr(),
                head_label_bytes.len(),
                descriptors.as_ptr(),
                descriptors.len(),
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(
                env,
                buffer,
                "SoraFS governance DAG head-chain validation",
            )
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_fixture_bundle_json(
    env: &mut jni::JNIEnv<'_>,
    kinds: jni::objects::JByteArray<'_>,
    payloads: jni::objects::JObjectArray<'_>,
    labels: jni::objects::JObjectArray<'_>,
    now: jni::sys::jlong,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let maximum_payloads = CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_PAYLOADS_V1 as usize;
        let maximum_bytes = CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_TOTAL_BYTES_V1 as usize;
        let maximum_label = CONNECT_NORITO_SORAFS_REFERENCE_MAX_LABEL_BYTES_V1 as usize;
        let kind_bytes =
            read_java_sorafs_reference_byte_array(env, &kinds, "kinds", maximum_payloads)?;
        if kind_bytes.is_empty() {
            return Err(format!("kinds must contain 1..{maximum_payloads} entries"));
        }
        let payload_bytes = read_java_sorafs_reference_byte_array_vector(
            env,
            &payloads,
            "payloads",
            Some(kind_bytes.len()),
            maximum_payloads,
            maximum_bytes,
        )?;
        let label_bytes = read_java_sorafs_reference_byte_array_vector(
            env,
            &labels,
            "labels",
            Some(kind_bytes.len()),
            maximum_payloads,
            maximum_label,
        )?;
        let mut aggregate_bytes = 0usize;
        let mut descriptors = Vec::with_capacity(kind_bytes.len());
        for ((kind, payload), label) in kind_bytes
            .iter()
            .copied()
            .zip(&payload_bytes)
            .zip(&label_bytes)
        {
            aggregate_bytes = aggregate_bytes
                .checked_add(payload.len())
                .and_then(|total| total.checked_add(label.len()))
                .ok_or_else(|| "fixture-bundle aggregate input length overflowed".to_owned())?;
            if aggregate_bytes > maximum_bytes {
                return Err(format!(
                    "fixture-bundle inputs must total at most {maximum_bytes} bytes"
                ));
            }
            descriptors.push(sorafs_reference_ffi::SorafsReferenceFfiBundlePayload {
                kind: u32::from(kind),
                bytes_ptr: payload.as_ptr(),
                bytes_len: payload.len(),
                label_ptr: label.as_ptr(),
                label_len: label.len(),
            });
        }
        let now = java_sorafs_reference_generated_at(now)?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_bundle_json(
                descriptors.as_ptr(),
                descriptors.len(),
                now,
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(env, buffer, "SoraFS fixture-bundle validation")
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_sign_orderbook_payload(
    env: &mut jni::JNIEnv<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let payload_bytes = read_java_byte_array(env, &payload, "noritoBytes")
            .ok_or_else(|| "invalid orderbook payload bytes".to_owned())?;
        let private_key_bytes = Zeroizing::new(
            read_java_byte_array(env, &private_key, "privateKey")
                .ok_or_else(|| "invalid orderbook private key bytes".to_owned())?,
        );
        let kind = u32::try_from(kind).map_err(|_| "kind must be non-negative".to_owned())?;
        let kind = sorafs_reference_orderbook_kind_from_bridge(kind)
            .map_err(|_| "unsupported orderbook payload kind".to_owned())?;
        let signed = sign_orderbook_payload_bytes_ed25519_v1(
            kind,
            &payload_bytes,
            private_key_bytes.as_slice(),
        )
        .map_err(|err| err.to_string())?;
        env.byte_array_from_slice(&signed)
            .map(|array| array.into_raw())
            .map_err(|err| err.to_string())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_derive_orderbook_order_id(
    env: &mut jni::JNIEnv<'_>,
    owner_account: jni::objects::JByteArray<'_>,
    nonce: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let owner_account = java_sorafs_orderbook_non_empty(
            read_java_byte_array(env, &owner_account, "ownerAccount")
                .ok_or_else(|| "invalid ownerAccount bytes".to_owned())?,
            "ownerAccount",
        )?;
        let nonce = java_sorafs_orderbook_u64(nonce, "nonce")?;
        if nonce == 0 {
            return Err("nonce must be positive".to_owned());
        }
        let order_id = derive_orderbook_order_id_v1(&owner_account, nonce);
        env.byte_array_from_slice(&order_id)
            .map(|array| array.into_raw())
            .map_err(|err| err.to_string())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_orderbook_u64(
    value: jni::sys::jlong,
    field: &str,
) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{field} must be non-negative"))
}
pub(super) fn java_sorafs_orderbook_fee_bps(
    value: jni::sys::jint,
    field: &str,
) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| format!("{field} must fit in u16 basis points"))
}
pub(super) fn java_sorafs_orderbook_fixed32(
    bytes: Vec<u8>,
    field: &str,
) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!("{field} must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
pub(super) fn java_sorafs_orderbook_provider_id(
    bytes: Vec<u8>,
) -> Result<Option<[u8; 32]>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let provider_id = java_sorafs_orderbook_fixed32(bytes, "providerId")?;
    if provider_id == [0; 32] {
        return Err("providerId must not be all zero".to_owned());
    }
    Ok(Some(provider_id))
}
pub(super) fn java_sorafs_orderbook_non_empty(
    bytes: Vec<u8>,
    field: &str,
) -> Result<Vec<u8>, String> {
    if bytes.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if bytes.len() > ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 {
        return Err(format!(
            "{field} must be at most {ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1} bytes"
        ));
    }
    Ok(bytes)
}
pub(super) fn java_sorafs_orderbook_xor_quantity(
    bytes: Vec<u8>,
    field: &str,
) -> Result<XorQuantity, String> {
    sorafs_xor_quantity_from_bytes(&bytes)
        .map_err(|_| format!("{field} must be a canonical non-negative XOR quantity"))
}
pub(super) fn java_sorafs_reference_build_signed_orderbook_order_request(
    env: &mut jni::JNIEnv<'_>,
    inputs: JavaSorafsOrderbookOrderRequestArrays<'_>,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let private_key_bytes = Zeroizing::new(
            read_java_byte_array(env, &inputs.private_key, "privateKey")
                .ok_or_else(|| "invalid orderbook private key bytes".to_owned())?,
        );
        let supplied_order_id = java_sorafs_orderbook_fixed32(
            read_java_byte_array(env, &inputs.order_id, "orderId")
                .ok_or_else(|| "invalid orderId bytes".to_owned())?,
            "orderId",
        )?;
        let owner_account = java_sorafs_orderbook_non_empty(
            read_java_byte_array(env, &inputs.owner_account, "ownerAccount")
                .ok_or_else(|| "invalid ownerAccount bytes".to_owned())?,
            "ownerAccount",
        )?;
        let provider_id = java_sorafs_orderbook_provider_id(
            read_java_byte_array(env, &inputs.provider_id, "providerId")
                .ok_or_else(|| "invalid providerId bytes".to_owned())?,
        )?;
        let nonce = java_sorafs_orderbook_u64(inputs.nonce, "nonce")?;
        let expected_order_id = derive_orderbook_order_id_v1(&owner_account, nonce);
        if supplied_order_id != expected_order_id {
            return Err(format!(
                "orderId must equal the canonical owner-and-nonce derivation {}",
                hex::encode(expected_order_id)
            ));
        }
        let fields = OrderbookOrderRequestFieldsV1 {
            side: sorafs_orderbook_side_from_bridge(
                u32::try_from(inputs.side).map_err(|_| "side must be non-negative".to_owned())?,
            )
            .map_err(|_| "unsupported orderbook side".to_owned())?,
            tier: sorafs_orderbook_tier_from_bridge(
                u32::try_from(inputs.tier).map_err(|_| "tier must be non-negative".to_owned())?,
            )
            .map_err(|_| "unsupported orderbook tier".to_owned())?,
            price_per_gib: java_sorafs_orderbook_xor_quantity(
                read_java_byte_array(env, &inputs.price_per_gib, "pricePerGib")
                    .ok_or_else(|| "invalid pricePerGib bytes".to_owned())?,
                "pricePerGib",
            )?,
            quantity_gib: java_sorafs_orderbook_u64(inputs.quantity_gib, "quantityGib")?,
            remaining_gib: java_sorafs_orderbook_u64(inputs.remaining_gib, "remainingGib")?,
            owner_account,
            provider_id,
            expiry_unix: java_sorafs_orderbook_u64(inputs.expiry_unix, "expiryUnix")?,
            nonce,
            maker_fee_bps: java_sorafs_orderbook_fee_bps(inputs.maker_fee_bps, "makerFeeBps")?,
            taker_fee_bps: java_sorafs_orderbook_fee_bps(inputs.taker_fee_bps, "takerFeeBps")?,
        };
        let signed = build_signed_orderbook_order_request_bytes_ed25519_v1(
            fields,
            private_key_bytes.as_slice(),
        )
        .map_err(|err| err.to_string())?;
        env.byte_array_from_slice(&signed)
            .map(|array| array.into_raw())
            .map_err(|err| err.to_string())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) struct JavaSorafsOrderbookOrderRequestArrays<'a> {
    order_id: jni::objects::JByteArray<'a>,
    side: jni::sys::jint,
    tier: jni::sys::jint,
    price_per_gib: jni::objects::JByteArray<'a>,
    quantity_gib: jni::sys::jlong,
    remaining_gib: jni::sys::jlong,
    owner_account: jni::objects::JByteArray<'a>,
    provider_id: jni::objects::JByteArray<'a>,
    expiry_unix: jni::sys::jlong,
    nonce: jni::sys::jlong,
    maker_fee_bps: jni::sys::jint,
    taker_fee_bps: jni::sys::jint,
    private_key: jni::objects::JByteArray<'a>,
}
pub(super) fn java_sorafs_reference_build_signed_orderbook_order_cancel(
    env: &mut jni::JNIEnv<'_>,
    order_id: jni::objects::JByteArray<'_>,
    owner_account: jni::objects::JByteArray<'_>,
    reason: jni::sys::jint,
    nonce: jni::sys::jlong,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let private_key_bytes = Zeroizing::new(
            read_java_byte_array(env, &private_key, "privateKey")
                .ok_or_else(|| "invalid orderbook private key bytes".to_owned())?,
        );
        let fields = OrderbookOrderCancelFieldsV1 {
            order_id: java_sorafs_orderbook_fixed32(
                read_java_byte_array(env, &order_id, "orderId")
                    .ok_or_else(|| "invalid orderId bytes".to_owned())?,
                "orderId",
            )?,
            owner_account: java_sorafs_orderbook_non_empty(
                read_java_byte_array(env, &owner_account, "ownerAccount")
                    .ok_or_else(|| "invalid ownerAccount bytes".to_owned())?,
                "ownerAccount",
            )?,
            reason: sorafs_orderbook_cancel_reason_from_bridge(
                u32::try_from(reason).map_err(|_| "reason must be non-negative".to_owned())?,
            )
            .map_err(|_| "unsupported orderbook cancel reason".to_owned())?,
            nonce: java_sorafs_orderbook_u64(nonce, "nonce")?,
        };
        let signed = build_signed_orderbook_order_cancel_bytes_ed25519_v1(
            fields,
            private_key_bytes.as_slice(),
        )
        .map_err(|err| err.to_string())?;
        env.byte_array_from_slice(&signed)
            .map(|array| array.into_raw())
            .map_err(|err| err.to_string())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_build_signed_orderbook_settlement_receipt(
    env: &mut jni::JNIEnv<'_>,
    inputs: JavaSorafsOrderbookSettlementReceiptArrays<'_>,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let private_key_bytes = Zeroizing::new(
            read_java_byte_array(env, &inputs.private_key, "privateKey")
                .ok_or_else(|| "invalid orderbook private key bytes".to_owned())?,
        );
        let fields = OrderbookSettlementReceiptFieldsV1 {
            receipt_id: java_sorafs_orderbook_fixed32(
                read_java_byte_array(env, &inputs.receipt_id, "receiptId")
                    .ok_or_else(|| "invalid receiptId bytes".to_owned())?,
                "receiptId",
            )?,
            channel_id: java_sorafs_orderbook_fixed32(
                read_java_byte_array(env, &inputs.channel_id, "channelId")
                    .ok_or_else(|| "invalid channelId bytes".to_owned())?,
                "channelId",
            )?,
            trade_id: java_sorafs_orderbook_fixed32(
                read_java_byte_array(env, &inputs.trade_id, "tradeId")
                    .ok_or_else(|| "invalid tradeId bytes".to_owned())?,
                "tradeId",
            )?,
            range_start: java_sorafs_orderbook_u64(inputs.range_start, "rangeStart")?,
            range_end: java_sorafs_orderbook_u64(inputs.range_end, "rangeEnd")?,
            chunk_hash: java_sorafs_orderbook_fixed32(
                read_java_byte_array(env, &inputs.chunk_hash, "chunkHash")
                    .ok_or_else(|| "invalid chunkHash bytes".to_owned())?,
                "chunkHash",
            )?,
            bytes_delivered: java_sorafs_orderbook_u64(inputs.bytes_delivered, "bytesDelivered")?,
            xor_debited: java_sorafs_orderbook_xor_quantity(
                read_java_byte_array(env, &inputs.xor_debited, "xorDebited")
                    .ok_or_else(|| "invalid xorDebited bytes".to_owned())?,
                "xorDebited",
            )?,
            provider_credit: java_sorafs_orderbook_xor_quantity(
                read_java_byte_array(env, &inputs.provider_credit, "providerCredit")
                    .ok_or_else(|| "invalid providerCredit bytes".to_owned())?,
                "providerCredit",
            )?,
            fee_amount: java_sorafs_orderbook_xor_quantity(
                read_java_byte_array(env, &inputs.fee_amount, "feeAmount")
                    .ok_or_else(|| "invalid feeAmount bytes".to_owned())?,
                "feeAmount",
            )?,
            issued_at_unix: java_sorafs_orderbook_u64(inputs.issued_at_unix, "issuedAtUnix")?,
        };
        let signed = build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(
            fields,
            private_key_bytes.as_slice(),
        )
        .map_err(|err| err.to_string())?;
        env.byte_array_from_slice(&signed)
            .map(|array| array.into_raw())
            .map_err(|err| err.to_string())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) struct JavaSorafsOrderbookSettlementReceiptArrays<'a> {
    receipt_id: jni::objects::JByteArray<'a>,
    channel_id: jni::objects::JByteArray<'a>,
    trade_id: jni::objects::JByteArray<'a>,
    range_start: jni::sys::jlong,
    range_end: jni::sys::jlong,
    chunk_hash: jni::objects::JByteArray<'a>,
    bytes_delivered: jni::sys::jlong,
    xor_debited: jni::objects::JByteArray<'a>,
    provider_credit: jni::objects::JByteArray<'a>,
    fee_amount: jni::objects::JByteArray<'a>,
    issued_at_unix: jni::sys::jlong,
    private_key: jni::objects::JByteArray<'a>,
}
pub(super) fn java_sorafs_reference_validate_pdp_payload_json(
    env: &mut jni::JNIEnv<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let payload_bytes = read_java_byte_array(env, &payload, "noritoBytes")
            .ok_or_else(|| "invalid PDP payload bytes".to_owned())?;
        let label_bytes = read_java_byte_array(env, &label, "label")
            .ok_or_else(|| "invalid PDP label bytes".to_owned())?;
        let kind = u32::try_from(kind).map_err(|_| "kind must be non-negative".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_validate_pdp_payload_buffer(
                kind,
                payload_bytes.as_ptr(),
                payload_bytes.len() as c_ulong,
                label_bytes.as_ptr(),
                label_bytes.len() as c_ulong,
                generated_at,
            )
        };
        unsafe { java_sorafs_reference_buffer_to_array(env, buffer, "SoraFS PDP validation") }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_pdp_commitment_challenge_json(
    env: &mut jni::JNIEnv<'_>,
    commitment: jni::objects::JByteArray<'_>,
    commitment_label: jni::objects::JByteArray<'_>,
    challenge: jni::objects::JByteArray<'_>,
    challenge_label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let commitment_bytes = read_java_byte_array(env, &commitment, "commitment")
            .ok_or_else(|| "invalid PDP commitment bytes".to_owned())?;
        let commitment_label_bytes =
            read_java_byte_array(env, &commitment_label, "commitmentLabel")
                .ok_or_else(|| "invalid PDP commitment label bytes".to_owned())?;
        let challenge_bytes = read_java_byte_array(env, &challenge, "challenge")
            .ok_or_else(|| "invalid PDP challenge bytes".to_owned())?;
        let challenge_label_bytes =
            read_java_byte_array(env, &challenge_label, "challengeLabel")
                .ok_or_else(|| "invalid PDP challenge label bytes".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_pdp_commitment_challenge_json(
                commitment_bytes.as_ptr(),
                commitment_bytes.len(),
                commitment_label_bytes.as_ptr(),
                commitment_label_bytes.len(),
                challenge_bytes.as_ptr(),
                challenge_bytes.len(),
                challenge_label_bytes.as_ptr(),
                challenge_label_bytes.len(),
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(
                env,
                buffer,
                "SoraFS PDP commitment/challenge validation",
            )
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_sorafs_reference_validate_pdp_challenge_proof_json(
    env: &mut jni::JNIEnv<'_>,
    challenge: jni::objects::JByteArray<'_>,
    challenge_label: jni::objects::JByteArray<'_>,
    proof: jni::objects::JByteArray<'_>,
    proof_label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let challenge_bytes = read_java_byte_array(env, &challenge, "challenge")
            .ok_or_else(|| "invalid PDP challenge bytes".to_owned())?;
        let challenge_label_bytes =
            read_java_byte_array(env, &challenge_label, "challengeLabel")
                .ok_or_else(|| "invalid PDP challenge label bytes".to_owned())?;
        let proof_bytes = read_java_byte_array(env, &proof, "proof")
            .ok_or_else(|| "invalid PDP proof bytes".to_owned())?;
        let proof_label_bytes = read_java_byte_array(env, &proof_label, "proofLabel")
            .ok_or_else(|| "invalid PDP proof label bytes".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_pdp_challenge_proof_json(
                challenge_bytes.as_ptr(),
                challenge_bytes.len(),
                challenge_label_bytes.as_ptr(),
                challenge_label_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                proof_label_bytes.as_ptr(),
                proof_label_bytes.len(),
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(
                env,
                buffer,
                "SoraFS PDP challenge/proof validation",
            )
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) struct JavaSorafsPdpBundleArrays<'local> {
    commitment: jni::objects::JByteArray<'local>,
    commitment_label: jni::objects::JByteArray<'local>,
    challenge: jni::objects::JByteArray<'local>,
    challenge_label: jni::objects::JByteArray<'local>,
    proof: jni::objects::JByteArray<'local>,
    proof_label: jni::objects::JByteArray<'local>,
}
pub(super) fn java_sorafs_reference_validate_pdp_bundle_json(
    env: &mut jni::JNIEnv<'_>,
    arrays: JavaSorafsPdpBundleArrays<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let commitment_bytes = read_java_byte_array(env, &arrays.commitment, "commitment")
            .ok_or_else(|| "invalid PDP commitment bytes".to_owned())?;
        let commitment_label_bytes =
            read_java_byte_array(env, &arrays.commitment_label, "commitmentLabel")
                .ok_or_else(|| "invalid PDP commitment label bytes".to_owned())?;
        let challenge_bytes = read_java_byte_array(env, &arrays.challenge, "challenge")
            .ok_or_else(|| "invalid PDP challenge bytes".to_owned())?;
        let challenge_label_bytes =
            read_java_byte_array(env, &arrays.challenge_label, "challengeLabel")
                .ok_or_else(|| "invalid PDP challenge label bytes".to_owned())?;
        let proof_bytes = read_java_byte_array(env, &arrays.proof, "proof")
            .ok_or_else(|| "invalid PDP proof bytes".to_owned())?;
        let proof_label_bytes = read_java_byte_array(env, &arrays.proof_label, "proofLabel")
            .ok_or_else(|| "invalid PDP proof label bytes".to_owned())?;
        let generated_at = java_sorafs_reference_generated_at(generated_at)?;
        let buffer = unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_pdp_json(
                commitment_bytes.as_ptr(),
                commitment_bytes.len(),
                commitment_label_bytes.as_ptr(),
                commitment_label_bytes.len(),
                challenge_bytes.as_ptr(),
                challenge_bytes.len(),
                challenge_label_bytes.as_ptr(),
                challenge_label_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                proof_label_bytes.as_ptr(),
                proof_label_bytes.len(),
                generated_at,
            )
        };
        unsafe {
            java_sorafs_reference_buffer_to_array(env, buffer, "SoraFS PDP bundle validation")
        }
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            ptr::null_mut()
        }
    }
}
pub(super) fn java_algorithm_from_code(
    algorithm_code: jni::sys::jint,
) -> Result<Algorithm, String> {
    let checked_code = u8::try_from(algorithm_code)
        .map_err(|_| format!("unsupported signing algorithm code: {algorithm_code}"))?;
    parse_algorithm_code(checked_code)
        .map_err(|_| format!("unsupported signing algorithm code: {algorithm_code}"))
}
pub(super) fn java_public_key_from_private_bytes(
    algorithm_code: jni::sys::jint,
    private_key: &[u8],
) -> Result<Vec<u8>, String> {
    let algorithm = java_algorithm_from_code(algorithm_code)?;
    let private_key = parse_private_key_with_algorithm(private_key, algorithm)
        .map_err(|_| "invalid private key bytes".to_string())?;
    let key_pair = KeyPair::from_private_key(private_key)
        .map_err(|_| "failed to derive public key".to_string())?;
    key_pair
        .public_key()
        .try_to_bytes()
        .map(|(_algorithm, payload)| payload.to_vec())
        .map_err(|_| "failed to extract public key bytes".to_string())
}
pub(super) fn java_keypair_from_seed_bytes(
    algorithm_code: jni::sys::jint,
    seed: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), String> {
    let algorithm = java_algorithm_from_code(algorithm_code)?;
    let key_pair = KeyPair::try_from_seed(seed.to_vec(), algorithm)
        .map_err(|err| format!("failed to derive key pair: {err}"))?;
    let (public_key, private_key) = key_pair.into_parts();
    let public_bytes = public_key
        .try_to_bytes()
        .map(|(_algorithm, payload)| payload.to_vec())
        .map_err(|_| "failed to extract public key bytes".to_string())?;
    Ok((Zeroizing::new(private_key.to_bytes().1), public_bytes))
}
pub(super) fn java_sign_detached_bytes(
    algorithm_code: jni::sys::jint,
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, String> {
    let algorithm = java_algorithm_from_code(algorithm_code)?;
    let private_key = parse_private_key_with_algorithm(private_key, algorithm)
        .map_err(|_| "invalid private key bytes".to_string())?;
    Signature::try_new(&private_key, message)
        .map(|signature| signature.payload().to_vec())
        .map_err(|err| format!("failed to sign message: {err}"))
}
pub(super) fn java_verify_detached_bytes(
    algorithm_code: jni::sys::jint,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let algorithm = java_algorithm_from_code(algorithm_code)?;
    let public_key = PublicKey::from_bytes(algorithm, public_key)
        .map_err(|_| "invalid public key bytes".to_string())?;
    let signature = match connect_signature_from_algorithm_bytes(algorithm, signature) {
        Some(signature) => signature,
        None => return Ok(false),
    };
    match signature.verify(&public_key, message) {
        Ok(()) => Ok(true),
        Err(CryptoError::BadSignature) => Ok(false),
        Err(_) => Err("signature verification failed".to_string()),
    }
}
pub(super) fn java_native_public_key_from_private(
    env: &mut jni::JNIEnv<'_>,
    algorithm_code: jni::sys::jint,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let private_bytes = read_java_byte_array(env, &private_key, "privateKey")
            .ok_or_else(|| "invalid private key bytes".to_string())?;
        let public_bytes = java_public_key_from_private_bytes(algorithm_code, &private_bytes)?;
        let array = env
            .byte_array_from_slice(&public_bytes)
            .map_err(|err| err.to_string())?;
        Ok(array.into_raw())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            std::ptr::null_mut()
        }
    }
}
pub(super) fn java_native_keypair_from_seed(
    env: &mut jni::JNIEnv<'_>,
    algorithm_code: jni::sys::jint,
    seed: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    let result = (|| -> Result<jni::sys::jobjectArray, String> {
        let seed_bytes = read_java_byte_array(env, &seed, "seed")
            .ok_or_else(|| "invalid seed bytes".to_string())?;
        let (private_bytes, public_bytes) =
            java_keypair_from_seed_bytes(algorithm_code, &seed_bytes)?;
        let private_array = env
            .byte_array_from_slice(&private_bytes)
            .map_err(|err| err.to_string())?;
        let public_array = env
            .byte_array_from_slice(&public_bytes)
            .map_err(|err| err.to_string())?;
        let byte_array_class = env.find_class("[B").map_err(|err| err.to_string())?;
        let array = env
            .new_object_array(2, byte_array_class, jni::objects::JObject::null())
            .map_err(|err| err.to_string())?;
        env.set_object_array_element(&array, 0, &private_array)
            .map_err(|err| err.to_string())?;
        env.set_object_array_element(&array, 1, &public_array)
            .map_err(|err| err.to_string())?;
        Ok(array.into_raw())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            std::ptr::null_mut()
        }
    }
}
pub(super) fn java_native_sign_detached(
    env: &mut jni::JNIEnv<'_>,
    algorithm_code: jni::sys::jint,
    private_key: jni::objects::JByteArray<'_>,
    message: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let private_bytes = read_java_byte_array(env, &private_key, "privateKey")
            .ok_or_else(|| "invalid private key bytes".to_string())?;
        let message_bytes = read_java_byte_array(env, &message, "message")
            .ok_or_else(|| "invalid message bytes".to_string())?;
        let signature = java_sign_detached_bytes(algorithm_code, &private_bytes, &message_bytes)?;
        let array = env
            .byte_array_from_slice(&signature)
            .map_err(|err| err.to_string())?;
        Ok(array.into_raw())
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            std::ptr::null_mut()
        }
    }
}
pub(super) fn java_native_verify_detached(
    env: &mut jni::JNIEnv<'_>,
    algorithm_code: jni::sys::jint,
    public_key: jni::objects::JByteArray<'_>,
    message: jni::objects::JByteArray<'_>,
    signature: jni::objects::JByteArray<'_>,
) -> jni::sys::jboolean {
    let result = (|| -> Result<jni::sys::jboolean, String> {
        let public_bytes = read_java_byte_array(env, &public_key, "publicKey")
            .ok_or_else(|| "invalid public key bytes".to_string())?;
        let message_bytes = read_java_byte_array(env, &message, "message")
            .ok_or_else(|| "invalid message bytes".to_string())?;
        let signature_bytes = read_java_byte_array(env, &signature, "signature")
            .ok_or_else(|| "invalid signature bytes".to_string())?;
        let valid = java_verify_detached_bytes(
            algorithm_code,
            &public_bytes,
            &message_bytes,
            &signature_bytes,
        )?;
        Ok(if valid { 1 } else { 0 })
    })();
    match result {
        Ok(valid) => valid,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            0
        }
    }
}
pub(super) fn java_text_array(
    env: &mut jni::JNIEnv<'_>,
    array: &jni::objects::JByteArray<'_>,
    context: &str,
) -> Result<String, String> {
    let mut bytes = read_java_byte_array(env, array, context)
        .ok_or_else(|| format!("invalid {context} bytes"))?;
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) if !text.trim().is_empty() && text.trim() == text => text.to_owned(),
        Ok(_) => {
            bytes.fill(0);
            return Err(format!(
                "{context} must be non-empty without surrounding whitespace"
            ));
        }
        Err(_) => {
            bytes.fill(0);
            return Err(format!("{context} must be UTF-8"));
        }
    };
    bytes.fill(0);
    Ok(text)
}
pub(super) fn java_network_id(
    env: &mut jni::JNIEnv<'_>,
    array: &jni::objects::JByteArray<'_>,
) -> Result<NetworkId, String> {
    let bytes = read_java_byte_array(env, array, "networkId")
        .ok_or_else(|| "invalid networkId bytes".to_owned())?;
    network_id_from_raw_bytes(&bytes).map_err(str::to_owned)
}
pub(super) fn java_optional_text_array(
    env: &mut jni::JNIEnv<'_>,
    array: &jni::objects::JByteArray<'_>,
    present: jni::sys::jboolean,
    context: &str,
) -> Result<Option<String>, String> {
    if present == 0 {
        return Ok(None);
    }
    java_text_array(env, array, context).map(Some)
}
pub(super) fn java_fee_payment_intent(
    env: &mut jni::JNIEnv<'_>,
    fee_payment_json: &jni::objects::JByteArray<'_>,
) -> Result<FeePaymentIntent, String> {
    let mut bytes = read_java_byte_array(env, fee_payment_json, "feePaymentJson")
        .ok_or_else(|| "invalid feePaymentJson bytes".to_owned())?;
    let result = java_fee_payment_intent_from_json(&bytes);
    bytes.fill(0);
    result
}
pub(super) fn java_fee_payment_intent_from_json(bytes: &[u8]) -> Result<FeePaymentIntent, String> {
    let intent = norito::json::from_slice::<FeePaymentIntent>(bytes)
        .map_err(|err| format!("feePaymentJson must be canonical Norito JSON: {err}"))?;
    intent
        .validate()
        .map_err(|err| format!("invalid feePayment: {err}"))?;
    Ok(intent)
}
pub(super) fn java_verifying_key_id(
    value: Option<String>,
    context: &str,
) -> Result<Option<VerifyingKeyId>, String> {
    value
        .map(|text| {
            parse_verifying_key_id_value(&text)
                .map_err(|_| format!("{context} must use backend:name syntax"))
        })
        .transpose()
}
pub(super) fn java_private_key(
    algorithm_code: jni::sys::jint,
    private_key: &jni::objects::JByteArray<'_>,
    env: &mut jni::JNIEnv<'_>,
) -> Result<PrivateKey, String> {
    let algorithm = java_algorithm_from_code(algorithm_code)?;
    let mut private_bytes = read_java_byte_array(env, private_key, "privateKey")
        .ok_or_else(|| "invalid private key bytes".to_owned())?;
    let key = parse_private_key_with_algorithm(&private_bytes, algorithm)
        .map_err(|_| "invalid private key bytes".to_owned());
    private_bytes.fill(0);
    key
}
pub(super) fn java_signed_transaction_pair(
    env: &mut jni::JNIEnv<'_>,
    signed_bytes: &[u8],
    hash_bytes: &[u8; 32],
) -> Result<jni::sys::jobjectArray, String> {
    java_byte_array_pair(env, signed_bytes, hash_bytes)
}
pub(super) fn java_byte_array_pair(
    env: &mut jni::JNIEnv<'_>,
    first: &[u8],
    second: &[u8],
) -> Result<jni::sys::jobjectArray, String> {
    let signed_array = env
        .byte_array_from_slice(first)
        .map_err(|err| err.to_string())?;
    let hash_array = env
        .byte_array_from_slice(second)
        .map_err(|err| err.to_string())?;
    let byte_array_class = env.find_class("[B").map_err(|err| err.to_string())?;
    let array = env
        .new_object_array(2, byte_array_class, jni::objects::JObject::null())
        .map_err(|err| err.to_string())?;
    env.set_object_array_element(&array, 0, &signed_array)
        .map_err(|err| err.to_string())?;
    env.set_object_array_element(&array, 1, &hash_array)
        .map_err(|err| err.to_string())?;
    Ok(array.into_raw())
}

fn java_account_read_permission_args(
    env: &mut jni::JNIEnv<'_>,
    network_id: &jni::objects::JByteArray<'_>,
    authority: &jni::objects::JByteArray<'_>,
    reporting_account: &jni::objects::JByteArray<'_>,
    change: jni::sys::jint,
    creation_time_ms: jni::sys::jlong,
) -> Result<(String, String, String, u8, u64), String> {
    let change = u8::try_from(change).map_err(|_| "invalid permission change".to_owned())?;
    if change != 1 && change != 2 {
        return Err("permission change must be grant (1) or revoke (2)".to_owned());
    }
    let creation_time_ms =
        u64::try_from(creation_time_ms).map_err(|_| "negative creationTimeMs".to_owned())?;
    let network_id = java_text_array(env, network_id, "networkId")?;
    let authority = java_text_array(env, authority, "authority")?;
    let reporting_account = java_text_array(env, reporting_account, "reportingAccount")?;
    Ok((
        network_id,
        authority,
        reporting_account,
        change,
        creation_time_ms,
    ))
}

pub(super) fn java_native_account_read_permission_multisig_payload_hash(
    env: &mut jni::JNIEnv<'_>,
    network_id: jni::objects::JByteArray<'_>,
    authority: jni::objects::JByteArray<'_>,
    reporting_account: jni::objects::JByteArray<'_>,
    change: jni::sys::jint,
    creation_time_ms: jni::sys::jlong,
    fee_payment_json: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let result = (|| -> Result<jni::sys::jbyteArray, String> {
        let (network, source, reporter, change, created) = java_account_read_permission_args(
            env,
            &network_id,
            &authority,
            &reporting_account,
            change,
            creation_time_ms,
        )?;
        let mut hash = [0_u8; 32];
        let fee = read_java_byte_array_bounded(env, &fee_payment_json, "feePaymentJson", 4096)
            .ok_or_else(|| "invalid feePaymentJson".to_owned())?;
        let code = unsafe {
            connect_norito_account_read_permission_multisig_payload_hash(
                network.as_ptr().cast(),
                network.len() as c_ulong,
                source.as_ptr().cast(),
                source.len() as c_ulong,
                reporter.as_ptr().cast(),
                reporter.len() as c_ulong,
                change,
                created,
                fee.as_ptr(),
                fee.len() as c_ulong,
                hash.as_mut_ptr(),
                hash.len() as c_ulong,
            )
        };
        if code != 0 {
            return Err(format!(
                "native account permission prehash rejected input ({code})"
            ));
        }
        env.byte_array_from_slice(&hash)
            .map(jni::objects::JByteArray::into_raw)
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(value) => value,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            std::ptr::null_mut()
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Mirrors the Java native method's signed request arguments."
)]
pub(super) fn java_native_finalize_account_read_permission_multisig(
    env: &mut jni::JNIEnv<'_>,
    network_id: jni::objects::JByteArray<'_>,
    authority: jni::objects::JByteArray<'_>,
    reporting_account: jni::objects::JByteArray<'_>,
    change: jni::sys::jint,
    creation_time_ms: jni::sys::jlong,
    fee_payment_json: jni::objects::JByteArray<'_>,
    signature: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    let result = (|| -> Result<jni::sys::jobjectArray, String> {
        let (network, source, reporter, change, created) = java_account_read_permission_args(
            env,
            &network_id,
            &authority,
            &reporting_account,
            change,
            creation_time_ms,
        )?;
        let signature = read_java_byte_array_bounded(env, &signature, "signature", 64)
            .ok_or_else(|| "invalid signature".to_owned())?;
        let fee = read_java_byte_array_bounded(env, &fee_payment_json, "feePaymentJson", 4096)
            .ok_or_else(|| "invalid feePaymentJson".to_owned())?;
        if signature.len() != 64 {
            return Err("signature must be 64 bytes".to_owned());
        }
        let mut signed_ptr = std::ptr::null_mut();
        let mut signed_len: c_ulong = 0;
        let mut hash = [0_u8; 32];
        let code = unsafe {
            connect_norito_account_read_permission_multisig_finalize(
                network.as_ptr().cast(),
                network.len() as c_ulong,
                source.as_ptr().cast(),
                source.len() as c_ulong,
                reporter.as_ptr().cast(),
                reporter.len() as c_ulong,
                change,
                created,
                fee.as_ptr(),
                fee.len() as c_ulong,
                signature.as_ptr(),
                signature.len() as c_ulong,
                &mut signed_ptr,
                &mut signed_len,
                hash.as_mut_ptr(),
                hash.len() as c_ulong,
            )
        };
        if code != 0 || signed_ptr.is_null() || signed_len == 0 || signed_len > 1024 * 1024 {
            connect_norito_free(signed_ptr);
            return Err(format!(
                "native account permission finalize rejected signature ({code})"
            ));
        }
        let signed =
            unsafe { std::slice::from_raw_parts(signed_ptr, signed_len as usize).to_vec() };
        connect_norito_free(signed_ptr);
        java_signed_transaction_pair(env, &signed, &hash)
    })();
    match result {
        Ok(value) => value,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            std::ptr::null_mut()
        }
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn java_native_encode_register_zk_asset_signed_transaction(
    env: &mut jni::JNIEnv<'_>,
    algorithm_code: jni::sys::jint,
    network_id: jni::objects::JByteArray<'_>,
    chain_discriminant: jni::sys::jint,
    authority: jni::objects::JByteArray<'_>,
    creation_time_ms: jni::sys::jlong,
    ttl_ms: jni::sys::jlong,
    ttl_present: jni::sys::jboolean,
    asset: jni::objects::JByteArray<'_>,
    vk_unshield: jni::objects::JByteArray<'_>,
    vk_unshield_present: jni::sys::jboolean,
    private_key: jni::objects::JByteArray<'_>,
    fee_payment_json: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    let result = (|| -> Result<jni::sys::jobjectArray, String> {
        if creation_time_ms < 0 || ttl_ms < 0 {
            return Err("creationTimeMs and ttlMs must be non-negative".to_owned());
        }
        let network_id = java_network_id(env, &network_id)?;
        let chain_discriminant = u16::try_from(chain_discriminant)
            .map_err(|_| "chainDiscriminant must fit in u16".to_owned())?;
        let authority = parse_account_id_for_chain(
            java_text_array(env, &authority, "authority")?,
            chain_discriminant,
        )
        .map_err(|_| "invalid authority".to_owned())?;
        let asset_definition = parse_asset_definition(java_text_array(env, &asset, "asset")?)
            .map_err(|_| "invalid asset".to_owned())?;
        let vk_unshield = java_verifying_key_id(
            java_optional_text_array(
                env,
                &vk_unshield,
                vk_unshield_present,
                "unshieldVerifyingKey",
            )?,
            "unshieldVerifyingKey",
        )?;
        let private_key = java_private_key(algorithm_code, &private_key, env)?;
        let ttl =
            parse_ttl(ttl_ms as u64, ttl_present != 0).map_err(|_| "invalid ttlMs".to_owned())?;
        let register = zk::RegisterZkAsset::new(asset_definition, vk_unshield);
        let fee_payment = java_fee_payment_intent(env, &fee_payment_json)?;
        let (signed_bytes, hash_bytes) =
            encode_asset_transaction_with_nonce_fee_payment_and_metadata(
                network_id,
                authority,
                creation_time_ms as u64,
                ttl,
                None,
                fee_payment,
                Metadata::default(),
                private_key,
                move || Executable::from([InstructionBox::from(register)]),
            )
            .map_err(|err| format!("failed to encode signed transaction ({})", err.code()))?;
        java_signed_transaction_pair(env, &signed_bytes, &hash_bytes)
    })();
    match result {
        Ok(array) => array,
        Err(message) => {
            throw_java_illegal_argument(env, message);
            std::ptr::null_mut()
        }
    }
}
