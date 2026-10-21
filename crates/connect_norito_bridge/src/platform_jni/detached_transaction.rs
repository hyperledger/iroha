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
