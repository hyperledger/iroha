//! Canonical native scaffold inspection for Kotlin wallet reviews.
use super::{
    catch_unwind_to_java, read_java_byte_array_bounded, throw_java_illegal_argument,
    throw_java_illegal_state,
};

/// Return the closed typed native review of one canonical transaction scaffold.
///
/// # Safety
/// The JVM supplies a valid environment, class and byte array for this call.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeInspectDetachedTransactionScaffold(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    input: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(bytes) = read_java_byte_array_bounded(
        &mut env,
        &input,
        "transactionScaffold",
        crate::DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(result) = catch_unwind_to_java(&mut env, "detached transaction inspection", || {
        crate::inspect_detached_transaction_scaffold(&bytes)
    }) else {
        return std::ptr::null_mut();
    };
    let (_, json) = match result {
        Ok(value) => value,
        Err(_) => {
            throw_java_illegal_argument(
                &mut env,
                "Invalid or unsupported transaction scaffold".to_owned(),
            );
            return std::ptr::null_mut();
        }
    };
    match env.byte_array_from_slice(&json) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            throw_java_illegal_state(
                &mut env,
                "Native inspection output allocation failed".to_owned(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Replace the scaffold signature using the existing native verifier and return wire plus metadata.
///
/// # Safety
/// The JVM supplies a valid environment, class and byte arrays for this call.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeFinalizeDetachedTransactionScaffold(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    scaffold: jni::objects::JByteArray<'_>,
    public_key: jni::objects::JByteArray<'_>,
    signature: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    let Some(scaffold) = read_java_byte_array_bounded(
        &mut env,
        &scaffold,
        "transactionScaffold",
        crate::DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(public_key) = read_java_byte_array_bounded(&mut env, &public_key, "publicKey", 32)
    else {
        return std::ptr::null_mut();
    };
    let Some(signature) = read_java_byte_array_bounded(&mut env, &signature, "signature", 64)
    else {
        return std::ptr::null_mut();
    };
    if scaffold.is_empty() || public_key.len() != 32 || signature.len() != 64 {
        throw_java_illegal_argument(&mut env, "Invalid detached finalization input size".to_owned());
        return std::ptr::null_mut();
    }
    let Some(result) = catch_unwind_to_java(&mut env, "detached transaction finalization", || {
        // Both C allocations are released on success, rejection and Rust unwinding.
        struct Outputs {
            signed: *mut std::os::raw::c_uchar,
            metadata: *mut std::os::raw::c_uchar,
        }
        impl Drop for Outputs {
            fn drop(&mut self) {
                crate::connect_norito_free(self.signed);
                crate::connect_norito_free(self.metadata);
            }
        }
        let mut outputs = Outputs { signed: std::ptr::null_mut(), metadata: std::ptr::null_mut() };
        let mut signed_len: std::os::raw::c_ulong = 0;
        let mut metadata_len: std::os::raw::c_ulong = 0;
        let code = unsafe {
            crate::connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
                scaffold.as_ptr(), scaffold.len() as std::os::raw::c_ulong,
                public_key.as_ptr(), public_key.len() as std::os::raw::c_ulong,
                signature.as_ptr(), signature.len() as std::os::raw::c_ulong,
                &mut outputs.signed, &mut signed_len, &mut outputs.metadata, &mut metadata_len,
            )
        };
        let signed_len = usize::try_from(signed_len).map_err(|_| "Invalid signed wire length")?;
        let metadata_len = usize::try_from(metadata_len).map_err(|_| "Invalid finalization metadata length")?;
        if code != 0 || outputs.signed.is_null() || outputs.metadata.is_null()
            || signed_len == 0 || signed_len > crate::DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES
            || metadata_len == 0 || metadata_len > 4096
        {
            return Err("Native detached finalization rejected the original scaffold or signature");
        }
        // The C finalizer owns these valid allocations until Outputs drops after copying.
        let signed = unsafe { std::slice::from_raw_parts(outputs.signed, signed_len).to_vec() };
        let metadata = unsafe { std::slice::from_raw_parts(outputs.metadata, metadata_len).to_vec() };
        Ok((signed, metadata))
    }) else {
        return std::ptr::null_mut();
    };
    let (signed, metadata) = match result {
        Ok(value) => value,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error.to_owned());
            return std::ptr::null_mut();
        }
    };
    let result = (|| -> jni::errors::Result<jni::sys::jobjectArray> {
        let array = env.new_object_array(2, "[B", jni::objects::JObject::null())?;
        let signed = env.byte_array_from_slice(&signed)?;
        let metadata = env.byte_array_from_slice(&metadata)?;
        env.set_object_array_element(&array, 0, signed)?;
        env.set_object_array_element(&array, 1, metadata)?;
        Ok(array.into_raw())
    })();
    match result {
        Ok(value) => value,
        Err(_) => {
            throw_java_illegal_state(&mut env, "Native finalization output allocation failed".to_owned());
            std::ptr::null_mut()
        }
    }
}
