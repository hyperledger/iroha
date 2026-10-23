//! JNI facade of the single four-buffer native FI context assertion verifier.

use super::{
    CONNECT_NORITO_BRIDGE_ABI_VERSION, catch_unwind_to_java, read_java_byte_array_bounded,
    throw_java_illegal_argument, throw_java_illegal_state,
};
use jni::objects::JByteArray;

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFiContextAssertionBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFiContextAssertionBridge_nativeVerifierContractVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    1
}

/// Verify a remote candidate against the independently retained local originals.
///
/// # Safety
/// The JVM supplies a valid environment, class and byte arrays for this call.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFiContextAssertionBridge_nativeVerifyFiContextAssertionV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    capsule: JByteArray<'_>,
    original: JByteArray<'_>,
    checkpoint: JByteArray<'_>,
    trust: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(capsule) = read_java_byte_array_bounded(&mut env, &capsule, "capsule", 512 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(original) =
        read_java_byte_array_bounded(&mut env, &original, "retainedRequest", 64 * 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(checkpoint) = read_java_byte_array_bounded(
        &mut env,
        &checkpoint,
        "trustedCheckpoint",
        iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(trust) = read_java_byte_array_bounded(&mut env, &trust, "localTrust", 32 * 1024)
    else {
        return std::ptr::null_mut();
    };
    if capsule.is_empty() || original.is_empty() || checkpoint.is_empty() || trust.is_empty() {
        throw_java_illegal_argument(&mut env, "Empty FI context verifier input".to_owned());
        return std::ptr::null_mut();
    }
    let Some(result) = catch_unwind_to_java(&mut env, "FI context assertion", || {
        struct Output(*mut std::os::raw::c_uchar);
        impl Drop for Output {
            fn drop(&mut self) {
                crate::connect_norito_free(self.0);
            }
        }
        let mut output = Output(std::ptr::null_mut());
        let mut length: std::os::raw::c_ulong = 0;
        let code = unsafe {
            crate::fi_context_bridge::connect_norito_verify_fi_context_assertion_v1(
                capsule.as_ptr(),
                capsule.len() as std::os::raw::c_ulong,
                original.as_ptr(),
                original.len() as std::os::raw::c_ulong,
                checkpoint.as_ptr(),
                checkpoint.len() as std::os::raw::c_ulong,
                trust.as_ptr(),
                trust.len() as std::os::raw::c_ulong,
                &mut output.0,
                &mut length,
            )
        };
        let length = usize::try_from(length).map_err(|_| "Invalid FI context result length")?;
        if code != 0 || output.0.is_null() || length == 0 || length > 512 * 1024 {
            return Err("Native FI context assertion rejected candidate or local pins");
        }
        Ok(unsafe { std::slice::from_raw_parts(output.0, length).to_vec() })
    }) else {
        return std::ptr::null_mut();
    };
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error.to_owned());
            return std::ptr::null_mut();
        }
    };
    match env.byte_array_from_slice(&bytes) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            throw_java_illegal_state(
                &mut env,
                "Native FI context result allocation failed".to_owned(),
            );
            std::ptr::null_mut()
        }
    }
}
