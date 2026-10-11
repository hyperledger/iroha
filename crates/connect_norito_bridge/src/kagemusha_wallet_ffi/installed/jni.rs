//! Android receives the same move-only installation attempt before registry refusal.

use super::*;
use ::jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject},
    sys::jlong,
};

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_beginInstallation(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    platform: JObject<'_>,
    app_manifest: JByteArray<'_>,
    envelope: JByteArray<'_>,
    wallet_runtime: JByteArray<'_>,
    verifier_pack: JByteArray<'_>,
    producer_inventory: JByteArray<'_>,
    signed_genesis: JByteArray<'_>,
    originals_root: JByteArray<'_>,
    registration_source: JByteArray<'_>,
) -> jlong {
    let result = run(|| {
        let arrays = [
            &app_manifest,
            &envelope,
            &wallet_runtime,
            &verifier_pack,
            &producer_inventory,
            &signed_genesis,
            &originals_root,
            &registration_source,
        ];
        // Check every original extent before copying any Java array or invoking platform.
        for (index, (array, bound)) in arrays.into_iter().zip(RUNTIME_BOUNDS).enumerate() {
            let length = env
                .get_array_length(array)
                .map_err(|_| Failure::code(INVALID))?;
            if length < 0
                || length as usize > bound
                || (length == 0 && matches!(index, 0 | 1 | 2 | 5))
            {
                return Err(Failure::code(INVALID));
            }
        }
        let originals: Vec<Vec<u8>> = arrays
            .into_iter()
            .map(|array| {
                env.convert_byte_array(array)
                    .map_err(|_| Failure::code(INVALID))
            })
            .collect::<Result<_>>()?;
        let prepared = PreparedInstallation::load(RuntimeOriginals {
            app_manifest: &originals[0],
            envelope: &originals[1],
            wallet_runtime: &originals[2],
            verifier_pack: &originals[3],
            producer_inventory: &originals[4],
            signed_genesis: &originals[5],
            originals_root: &originals[6],
            registration_source: &originals[7],
        })?;
        let platform = AndroidPlatform::new(&mut env, &platform)?;
        let root = platform
            .custody_root()
            .map_err(|error| Failure::unavailable(UNAVAILABLE, error))?;
        let owner = prepared.runtime(platform, root, true)?;
        Ok(Box::new(WalletInstallationAttempt::new(owner)))
    });
    match result {
        Ok(attempt) => Box::into_raw(attempt) as usize as jlong,
        Err(error) => error.status as jlong,
    }
}

/// Consumes the exact unique Native pointer only on positive actual registry ID.
/// A negative status retains that same opaque pointer; JNI allocates no response object.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_registerInstallation(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    attempt: jlong,
) -> jlong {
    let mut original = attempt as usize as *mut WalletInstallationAttempt;
    let mut runtime = 0;
    // SAFETY: private managed Native binding serializes and retains the unique original pointer.
    let status = unsafe {
        connect_norito_kagemusha_wallet_installation_register_v1(&mut original, &mut runtime)
    };
    if status == 0 {
        runtime as jlong
    } else {
        status as jlong
    }
}
/// Zero acknowledges consuming close of the same attempt; all other statuses retain it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_closeInstallation(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    attempt: jlong,
) -> ::jni::sys::jint {
    let mut original = attempt as usize as *mut WalletInstallationAttempt;
    // SAFETY: same private managed pointer contract; close retry keeps the original on refusal.
    unsafe { connect_norito_kagemusha_wallet_installation_close_v1(&mut original) }
}
