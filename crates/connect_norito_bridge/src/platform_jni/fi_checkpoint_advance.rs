//! JNI ownership and bounds for the existing native checkpoint page verifier.
use super::{
    CONNECT_NORITO_BRIDGE_ABI_VERSION, catch_unwind_to_java, read_java_byte_array_bounded,
    throw_java_illegal_argument, throw_java_illegal_state,
};
use jni::objects::{JByteArray, JObjectArray};

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFinalityCheckpointAdvanceBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFinalityCheckpointAdvanceBridge_nativeVerifierContractVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    1
}

/// # Safety
/// The JVM supplies a valid environment, class and arrays for this call.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_NativeFinalityCheckpointAdvanceBridge_nativeAdvanceFiCheckpointV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    checkpoint: JByteArray<'_>,
    frames: JObjectArray<'_>,
    network: JByteArray<'_>,
    chain: JByteArray<'_>,
    sha: JByteArray<'_>,
    height: JByteArray<'_>,
    context: JByteArray<'_>,
) -> jni::sys::jobjectArray {
    let Some(checkpoint) = read_java_byte_array_bounded(
        &mut env,
        &checkpoint,
        "checkpoint",
        iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(network) = read_java_byte_array_bounded(&mut env, &network, "networkId", 74) else {
        return std::ptr::null_mut();
    };
    let Some(chain) = read_java_byte_array_bounded(&mut env, &chain, "chain", 1024) else {
        return std::ptr::null_mut();
    };
    let Some(sha) = read_java_byte_array_bounded(&mut env, &sha, "sha256", 32) else {
        return std::ptr::null_mut();
    };
    let Some(height) = read_java_byte_array_bounded(&mut env, &height, "height", 20) else {
        return std::ptr::null_mut();
    };
    let Some(context) = read_java_byte_array_bounded(&mut env, &context, "contextId", 32) else {
        return std::ptr::null_mut();
    };
    let count = match env.get_array_length(&frames) {
        Ok(count) if (2..=4096).contains(&count) => count,
        _ => {
            throw_java_illegal_argument(
                &mut env,
                "Checkpoint advance requires 2..4096 frames".into(),
            );
            return std::ptr::null_mut();
        }
    };
    let mut proofs = Vec::with_capacity(count as usize);
    let mut remaining = 16 * 1024 * 1024;
    for index in 0..count {
        let frame = match env.get_object_array_element(&frames, index) {
            Ok(frame) if !frame.is_null() => JByteArray::from(frame),
            _ => {
                throw_java_illegal_argument(&mut env, "Invalid checkpoint proof array".into());
                return std::ptr::null_mut();
            }
        };
        let Some(wire) = read_java_byte_array_bounded(&mut env, &frame, "proofFrame", remaining)
        else {
            return std::ptr::null_mut();
        };
        // A 4096-frame page must not retain 4096 JVM local references.
        if env.delete_local_ref(frame).is_err() {
            throw_java_illegal_state(
                &mut env,
                "Unable to release checkpoint proof reference".into(),
            );
            return std::ptr::null_mut();
        }
        if wire.is_empty() {
            throw_java_illegal_argument(&mut env, "Empty checkpoint proof".into());
            return std::ptr::null_mut();
        }
        remaining -= wire.len();
        proofs.push(wire);
    }
    let Some(result) = catch_unwind_to_java(&mut env, "FI checkpoint advance", || {
        struct Output(*mut std::os::raw::c_uchar);
        impl Drop for Output {
            fn drop(&mut self) {
                crate::connect_norito_free(self.0);
            }
        }
        let pointers: Vec<_> = proofs.iter().map(|proof| proof.as_ptr()).collect();
        let lengths: Vec<_> = proofs
            .iter()
            .map(|proof| proof.len() as std::os::raw::c_ulong)
            .collect();
        let mut promoted = Output(std::ptr::null_mut());
        let mut promoted_len = 0;
        let mut metadata = Output(std::ptr::null_mut());
        let mut metadata_len = 0;
        let code = unsafe {
            crate::fi_checkpoint_advance::connect_norito_advance_fi_checkpoint_v1(
                checkpoint.as_ptr(),
                checkpoint.len() as std::os::raw::c_ulong,
                pointers.as_ptr(),
                lengths.as_ptr(),
                proofs.len() as std::os::raw::c_ulong,
                network.as_ptr(),
                network.len() as std::os::raw::c_ulong,
                chain.as_ptr(),
                chain.len() as std::os::raw::c_ulong,
                sha.as_ptr(),
                sha.len() as std::os::raw::c_ulong,
                height.as_ptr(),
                height.len() as std::os::raw::c_ulong,
                context.as_ptr(),
                context.len() as std::os::raw::c_ulong,
                &mut promoted.0,
                &mut promoted_len,
                &mut metadata.0,
                &mut metadata_len,
            )
        };
        let promoted_len =
            usize::try_from(promoted_len).map_err(|_| "Invalid promoted checkpoint length")?;
        let metadata_len = usize::try_from(metadata_len)
            .map_err(|_| "Invalid promoted checkpoint metadata length")?;
        if code != 0
            || promoted.0.is_null()
            || metadata.0.is_null()
            || promoted_len == 0
            || promoted_len > iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES
            || metadata_len == 0
            || metadata_len > 4096
        {
            return Err("Native checkpoint page rejected");
        }
        Ok(unsafe {
            [
                std::slice::from_raw_parts(promoted.0, promoted_len).to_vec(),
                std::slice::from_raw_parts(metadata.0, metadata_len).to_vec(),
            ]
        })
    }) else {
        return std::ptr::null_mut();
    };
    let fields = match result {
        Ok(fields) => fields,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error.into());
            return std::ptr::null_mut();
        }
    };
    let result = (|| {
        let class = env.find_class("[B")?;
        let array = env.new_object_array(2, class, jni::objects::JObject::null())?;
        for (index, bytes) in fields.iter().enumerate() {
            let value = env.byte_array_from_slice(bytes)?;
            env.set_object_array_element(&array, index as i32, &value)?;
        }
        Ok::<_, jni::errors::Error>(array.into_raw())
    })();
    match result {
        Ok(array) => array,
        Err(error) => {
            throw_java_illegal_state(
                &mut env,
                format!("Checkpoint advance result allocation failed: {error}"),
            );
            std::ptr::null_mut()
        }
    }
}
