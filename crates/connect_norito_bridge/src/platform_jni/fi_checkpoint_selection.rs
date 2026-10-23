//! JNI projection of the exact signed-runtime checkpoint selection verifier.

use super::{
    CONNECT_NORITO_BRIDGE_ABI_VERSION, catch_unwind_to_java, read_java_byte_array_bounded,
    throw_java_illegal_argument, throw_java_illegal_state,
};
use jni::objects::JByteArray;

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFinalityCheckpointBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFinalityCheckpointBridge_nativeVerifierContractVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    1
}

/// Authenticate the exact original bytes and all independently selected checkpoint pins.
///
/// # Safety
/// The JVM supplies a valid environment, class and byte arrays for this call.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFinalityCheckpointBridge_nativeVerifyFiCheckpointSelectionV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    checkpoint: JByteArray<'_>,
    network_id: JByteArray<'_>,
    expected_chain: JByteArray<'_>,
    expected_sha256: JByteArray<'_>,
    expected_height: JByteArray<'_>,
    expected_context_id: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(checkpoint) = read_java_byte_array_bounded(
        &mut env, &checkpoint, "checkpointBytes",
        iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
    ) else { return std::ptr::null_mut(); };
    let Some(network) = read_java_byte_array_bounded(&mut env, &network_id, "networkId", 74)
    else { return std::ptr::null_mut(); };
    let Some(chain) = read_java_byte_array_bounded(&mut env, &expected_chain, "expectedChain", 1024)
    else { return std::ptr::null_mut(); };
    let Some(digest) = read_java_byte_array_bounded(&mut env, &expected_sha256, "expectedSha256", 32)
    else { return std::ptr::null_mut(); };
    let Some(height) = read_java_byte_array_bounded(&mut env, &expected_height, "expectedHeight", 20)
    else { return std::ptr::null_mut(); };
    let Some(context) = read_java_byte_array_bounded(&mut env, &expected_context_id, "expectedContextId", 32)
    else { return std::ptr::null_mut(); };
    if checkpoint.is_empty() || network.is_empty() || chain.is_empty() || height.is_empty()
        || digest.len() != 32 || context.len() != 32
    {
        throw_java_illegal_argument(&mut env, "Invalid checkpoint selection input size".to_owned());
        return std::ptr::null_mut();
    }
    let Some(result) = catch_unwind_to_java(&mut env, "FI checkpoint selection", || {
        struct Output(*mut std::os::raw::c_uchar);
        impl Drop for Output {
            fn drop(&mut self) { crate::connect_norito_free(self.0); }
        }
        let mut output = Output(std::ptr::null_mut());
        let mut length: std::os::raw::c_ulong = 0;
        let code = unsafe {
            crate::fi_checkpoint_selection::connect_norito_verify_fi_checkpoint_selection_v1(
                checkpoint.as_ptr(), checkpoint.len() as std::os::raw::c_ulong,
                network.as_ptr(), network.len() as std::os::raw::c_ulong,
                chain.as_ptr(), chain.len() as std::os::raw::c_ulong,
                digest.as_ptr(), digest.len() as std::os::raw::c_ulong,
                height.as_ptr(), height.len() as std::os::raw::c_ulong,
                context.as_ptr(), context.len() as std::os::raw::c_ulong,
                &mut output.0, &mut length,
            )
        };
        let length = usize::try_from(length).map_err(|_| "Invalid checkpoint metadata length")?;
        if code != 0 || output.0.is_null() || length == 0 || length > 1024 {
            return Err("Native checkpoint selection rejected the bytes or selected pins");
        }
        // The C verifier owns this allocation until Output drops after the bounded copy.
        Ok(unsafe { std::slice::from_raw_parts(output.0, length).to_vec() })
    }) else { return std::ptr::null_mut(); };
    let metadata = match result {
        Ok(value) => value,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error.to_owned());
            return std::ptr::null_mut();
        }
    };
    match env.byte_array_from_slice(&metadata) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            throw_java_illegal_state(&mut env, "Native checkpoint metadata allocation failed".to_owned());
            std::ptr::null_mut()
        }
    }
}
