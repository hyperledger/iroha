//! JNI surfaces for candidate-only admission and exact retained-original continuation.
use super::{
    CONNECT_NORITO_BRIDGE_ABI_VERSION, catch_unwind_to_java, read_java_byte_array_bounded,
    throw_java_illegal_argument, throw_java_illegal_state,
};
use jni::objects::JByteArray;

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFiContextContinuationBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFiContextContinuationBridge_nativeVerifierContractVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    1
}

fn emit(
    env: &mut jni::JNIEnv<'_>,
    maximum: usize,
    body: impl FnOnce() -> Result<Vec<u8>, String> + std::panic::UnwindSafe,
) -> jni::sys::jbyteArray {
    let Some(result) = catch_unwind_to_java(env, "FI continuation", body) else {
        return std::ptr::null_mut();
    };
    let bytes = match result {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= maximum => bytes,
        _ => {
            throw_java_illegal_argument(env, "Native FI continuation/admission refused".into());
            return std::ptr::null_mut();
        }
    };
    match env.byte_array_from_slice(&bytes) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            throw_java_illegal_state(env, "Native FI result allocation failed".into());
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// The JVM supplies valid arrays and environment for the complete synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFiContextContinuationBridge_nativeAdmitFiAssertionOriginalV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    wire: JByteArray<'_>,
    request: JByteArray<'_>,
    checkpoint: JByteArray<'_>,
    trust: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(wire) = read_java_byte_array_bounded(&mut env, &wire, "signedOriginal", 64 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(request) =
        read_java_byte_array_bounded(&mut env, &request, "originalRequest", 64 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(checkpoint) = read_java_byte_array_bounded(
        &mut env,
        &checkpoint,
        "originalCheckpoint",
        68 * 1024 * 1024,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(trust) = read_java_byte_array_bounded(&mut env, &trust, "originalTrust", 32 * 1024)
    else {
        return std::ptr::null_mut();
    };
    emit(&mut env, 2048, || {
        crate::fi_context_continuation::admit_fi_assertion_original_json(
            &wire,
            &request,
            &checkpoint,
            &trust,
        )
    })
}

/// # Safety
/// The JVM supplies valid arrays and environment for the complete synchronous call.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFiContextContinuationBridge_nativeVerifyFiContextContinuationV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    capsule: JByteArray<'_>,
    request: JByteArray<'_>,
    wire: JByteArray<'_>,
    floor: JByteArray<'_>,
    cursor: JByteArray<'_>,
    trust: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(capsule) = read_java_byte_array_bounded(&mut env, &capsule, "capsule", 512 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(request) =
        read_java_byte_array_bounded(&mut env, &request, "originalRequest", 64 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(wire) = read_java_byte_array_bounded(&mut env, &wire, "signedOriginal", 64 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(floor) =
        read_java_byte_array_bounded(&mut env, &floor, "originalCheckpoint", 68 * 1024 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(cursor) = read_java_byte_array_bounded(
        &mut env,
        &cursor,
        "branchCursorCheckpoint",
        68 * 1024 * 1024,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(trust) =
        read_java_byte_array_bounded(&mut env, &trust, "continuationTrust", 36 * 1024)
    else {
        return std::ptr::null_mut();
    };
    emit(&mut env, 512 * 1024, || {
        crate::fi_context_continuation::verify_fi_context_continuation_json(
            &capsule, &request, &wire, &floor, &cursor, &trust,
        )
    })
}
