//! JNI front-end of the same exclusive Rust KAGEMUSHA owner used by Apple.

use crate::kagemusha_wallet_ffi as wallet;
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JObjectArray, JValue},
    sys::{jboolean, jint, jlong, jobject},
};

pub(super) fn read(
    env: &mut JNIEnv<'_>,
    bytes: &JByteArray<'_>,
    bound: usize,
) -> wallet::Result<Vec<u8>> {
    let length = env
        .get_array_length(bytes)
        .map_err(|_| wallet::Failure::code(wallet::INVALID))?;
    if length < 0 || length as usize > bound {
        return Err(wallet::Failure::code(wallet::INVALID));
    }
    env.convert_byte_array(bytes)
        .map_err(|_| wallet::Failure::code(wallet::INVALID))
}
pub(super) fn response(env: &mut JNIEnv<'_>, result: wallet::Result<wallet::Response>) -> jobject {
    response_class(
        env,
        result,
        "org/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletCallV1",
    )
}
/// Canonical locator DATA rebinding only; no installed runtime, proof or account admission.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_relocateRegistrationSource(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    source: JByteArray<'_>,
    root: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        for (array, maximum) in [(&source, 8192), (&root, 4096)] {
            let length = env
                .get_array_length(array)
                .map_err(|_| wallet::Failure::code(wallet::INVALID))?;
            if length <= 0 || length > maximum {
                return Err(wallet::Failure::code(wallet::INVALID));
            }
        }
        let source = read(&mut env, &source, 8192)?;
        let root = read(&mut env, &root, 4096)?;
        wallet::relocate_registration_source(&source, &root)
    });
    response(&mut env, result)
}
pub(super) fn response_class(
    env: &mut JNIEnv<'_>,
    result: wallet::Result<wallet::Response>,
    class: &str,
) -> jobject {
    let (status, reason, code, sequence, detail, bytes) = match result {
        Ok(value) => (value.kind, -1, 0, value.sequence, value.detail, value.bytes),
        Err(error) => (
            error.status,
            error.reason,
            error.platform_code,
            0,
            0,
            vec![],
        ),
    };
    let result = (|| -> jni::errors::Result<JObject<'_>> {
        let bytes = env.byte_array_from_slice(&bytes)?;
        env.new_object(
            class,
            "(IIIJJI[B)V",
            &[
                JValue::Int(status),
                JValue::Int(reason),
                JValue::Int(code),
                JValue::Long(sequence as jlong),
                JValue::Long((sequence >> 64) as jlong),
                JValue::Int(detail as jint),
                JValue::Object(&bytes),
            ],
        )
    })();
    match result {
        Ok(object) => object.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
/// Native wallet contract; it does not claim authenticated artifacts have been loaded.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_revision(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    1
}
/// Begin account admission from exact originals under a native-provisioned runtime.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_openBegin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    runtime: jlong,
    credential: JByteArray<'_>,
    certificates: JByteArray<'_>,
    account: JByteArray<'_>,
    asset: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        let a = read(&mut env, &credential, wallet::open::BOUNDS[0])?;
        let b = read(&mut env, &certificates, wallet::open::BOUNDS[1])?;
        let c = read(&mut env, &account, wallet::open::BOUNDS[2])?;
        let d = read(&mut env, &asset, wallet::open::BOUNDS[3])?;
        wallet::open::begin(runtime as u64, [&a, &b, &c, &d])
    });
    response(&mut env, result)
}
/// Consume one account challenge; failed signatures retain unadmitted native custody.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_openFinish(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    runtime: jlong,
    signature: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        // Failed/oversized input still consumes this pending challenge as an invalid signature.
        let signature = read(&mut env, &signature, 64).unwrap_or_default();
        wallet::open::finish(runtime as u64, &signature)
    });
    response(&mut env, result)
}
/// Abandon an account challenge without accepting any authority or deleting custody.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_openCancel(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    runtime: jlong,
) -> jint {
    wallet::run(|| wallet::open::cancel(runtime as u64))
        .err()
        .map_or(0, |error| error.status)
}
/// Close with cooperative proof cancellation; retained payments remain in source custody.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_close(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jint {
    wallet::run(|| wallet::close(handle as u64))
        .err()
        .map_or(0, |error| error.status)
}
/// Update scheduler without waiting for the wallet operation mutex.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_activity(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    foreground: jint,
    charging: jint,
) -> jint {
    wallet::run(|| {
        if !(0..=1).contains(&foreground) || !(0..=1).contains(&charging) {
            return Err(wallet::Failure::code(wallet::INVALID));
        }
        wallet::activity(handle as u64, foreground != 0, charging != 0)
    })
    .err()
    .map_or(0, |error| error.status)
}
/// Custody call: retry1, resume2, fold3, CreditStatus4, request-status5; selector0 is invalid.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_call(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    operation: jint,
    first: JByteArray<'_>,
    second: JByteArray<'_>,
) -> jobject {
    let observation = (operation == 3)
        .then(|| wallet::FoldBridgeTurnV1::begin(handle as u64))
        .flatten();
    let result = wallet::run(|| {
        let first = read(&mut env, &first, 32)?;
        let second = read(&mut env, &second, 32)?;
        if operation != 4 && !second.is_empty() {
            return Err(wallet::Failure::code(wallet::INVALID));
        }
        match operation {
            5 => wallet::request_status(handle as u64, &first),
            1 => wallet::retry(handle as u64, &first),
            2 if first.is_empty() => wallet::resume(handle as u64),
            3 if first.is_empty() => wallet::fold(handle as u64),
            4 => wallet::credit(handle as u64, &first, &second),
            _ => Err(wallet::Failure::code(wallet::INVALID)),
        }
    });
    if let Some(observation) = observation {
        observation.finish(result.is_ok());
    }
    response(&mut env, result)
}

/// Source-bound setup; all input array lengths are checked before any original is copied.
/// The canonical call reply preserves distinct setup and monetary status projections.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_setup(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JByteArray<'_>,
    selector: jint,
    amount_low: jlong,
    amount_high: jlong,
    token: jlong,
    first: JByteArray<'_>,
    second: JByteArray<'_>,
    third: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        let selector =
            u32::try_from(selector).map_err(|_| wallet::Failure::code(wallet::INVALID))?;
        let token = u64::try_from(token).map_err(|_| wallet::Failure::code(wallet::INVALID))?;
        let bounds = wallet::setup::bounds(selector)?;
        for (index, (array, bound)) in [&request_id, &first, &second, &third]
            .into_iter()
            .zip([32, bounds[0], bounds[1], bounds[2]])
            .enumerate()
        {
            let length = env
                .get_array_length(array)
                .map_err(|_| wallet::Failure::code(wallet::INVALID))?;
            if length < 0 || length as usize > bound || (index == 0 && length != 32) {
                return Err(wallet::Failure::code(wallet::INVALID));
            }
        }
        let request_id = read(&mut env, &request_id, 32)?;
        let first = read(&mut env, &first, bounds[0])?;
        let second = read(&mut env, &second, bounds[1])?;
        let third = read(&mut env, &third, bounds[2])?;
        let request = wallet::setup::request(
            &request_id,
            selector,
            u128::from(amount_low as u64) | (u128::from(amount_high as u64) << 64),
            token,
            [&first, &second, &third],
        )?;
        wallet::setup(handle as u64, request)
    });
    wallet::terminal::deliver(handle as u64, selector as u32, result, |result| {
        let value = response(&mut env, result);
        (value, !value.is_null())
    })
}

/// Typed lifecycle request; bounds are checked before copying any original object.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_execute(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JByteArray<'_>,
    selector: jint,
    amount_low: jlong,
    amount_high: jlong,
    first: JByteArray<'_>,
    second: JByteArray<'_>,
    third: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        let selector =
            u32::try_from(selector).map_err(|_| wallet::Failure::code(wallet::INVALID))?;
        let bounds = wallet::requests::bounds(selector)?;
        let request_id = read(&mut env, &request_id, 32)?;
        let first = read(&mut env, &first, bounds[0])?;
        let second = read(&mut env, &second, bounds[1])?;
        let third = read(&mut env, &third, bounds[2])?;
        let request = wallet::requests::request(
            &request_id,
            selector,
            u128::from(amount_low as u64) | (u128::from(amount_high as u64) << 64),
            [&first, &second, &third],
        )?;
        wallet::execute(handle as u64, request)
    });
    response(&mut env, result)
}

/// Fixed typed source-selected ownership/fold projection; no caller selectors or codecs.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_snapshot(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let value = match wallet::run(|| wallet::snapshot(handle as u64)) {
        Ok(value) => wallet::WalletSnapshot::from(value),
        Err(error) => wallet::WalletSnapshot::from(error),
    };
    // Scalars are low/high bit patterns, not signed arithmetic or a binary financial codec.
    let scalars: Vec<jlong> = [
        value.sequence,
        value.balance,
        value.core_burned_total,
        value.known_burned_total,
        value.owned_balance,
        value.folded_balance,
        value.fold_backlog,
        value.folded_sequence,
        value.folded_burned_total,
    ]
    .into_iter()
    .flat_map(|v| [v.low as jlong, v.high as jlong])
    .collect();
    let result = (|| -> jni::errors::Result<JObject<'_>> {
        let scheme = env.byte_array_from_slice(&value.scheme)?;
        let wallet_id = env.byte_array_from_slice(&value.wallet)?;
        let head = env.byte_array_from_slice(&value.head)?;
        let credential = env.byte_array_from_slice(&value.credential)?;
        let folded_head = env.byte_array_from_slice(&value.folded_head)?;
        let folded_credential = env.byte_array_from_slice(&value.folded_credential)?;
        let numbers = env.new_long_array(18)?;
        env.set_long_array_region(&numbers, 0, &scalars)?;
        env.new_object(
            "org/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletSnapshotReplyV1",
            "(IIIII[B[B[B[B[B[B[J)V",
            &[
                JValue::Int(value.status),
                JValue::Int(value.reason),
                JValue::Int(value.platform_code),
                JValue::Int(value.lifecycle as jint),
                JValue::Int(value.flags as jint),
                JValue::Object(&scheme),
                JValue::Object(&wallet_id),
                JValue::Object(&head),
                JValue::Object(&credential),
                JValue::Object(&folded_head),
                JValue::Object(&folded_credential),
                JValue::Object(&numbers),
            ],
        )
    })();
    result.map_or(std::ptr::null_mut(), |object| object.into_raw())
}

/// Original enrollment actions; JNI copies bounded raw evidence, never a decoded verdict.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_enrollment(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    runtime: jlong,
    selector: jint,
    first: JByteArray<'_>,
    second: JByteArray<'_>,
    third: JByteArray<'_>,
    certificates: JObjectArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        let selector =
            u32::try_from(selector).map_err(|_| wallet::Failure::code(wallet::INVALID))?;
        let bounds = wallet::enrollment::bounds(selector)?;
        let count = env
            .get_array_length(&certificates)
            .map_err(|_| wallet::Failure::code(wallet::INVALID))?;
        if !(0..=8).contains(&count) || (selector != 3 && count != 0) {
            return Err(wallet::Failure::code(wallet::INVALID));
        }
        for (array, bound) in [&first, &second, &third].into_iter().zip(bounds) {
            let length = env
                .get_array_length(array)
                .map_err(|_| wallet::Failure::code(wallet::INVALID))?;
            if length < 0 || length as usize > bound {
                return Err(wallet::Failure::code(wallet::INVALID));
            }
        }
        let first = read(&mut env, &first, bounds[0])?;
        let second = read(&mut env, &second, bounds[1])?;
        let third = read(&mut env, &third, bounds[2])?;
        let mut chain = Vec::with_capacity(count as usize);
        for index in 0..count {
            let item = env
                .get_object_array_element(&certificates, index)
                .map_err(|_| wallet::Failure::code(wallet::INVALID))?;
            chain.push(read(&mut env, &JByteArray::from(item), 16_384)?);
        }
        let refs: Vec<_> = chain.iter().map(Vec::as_slice).collect();
        let action = wallet::enrollment::request(selector, [&first, &second, &third], &refs)?;
        wallet::enrollment::call(runtime as u64, action)
    });
    response(&mut env, result)
}
/// Closed E1 refusal table (design §2.4), the same pure lookup as the C export: the holder
/// class 1 Phone, 2 App, 3 Attempt or 4 Account, or `INVALID` for zero, unknown and
/// platform-inapplicable codes. No handle, state or admission verdict.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_enrollmentRefusal(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    code: jint,
    android: jboolean,
) -> jint {
    match u16::try_from(code) {
        Ok(code) => wallet::connect_norito_kagemusha_wallet_enrollment_refusal_v1(code, android),
        Err(_) => wallet::INVALID,
    }
}
