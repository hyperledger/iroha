//! Bounded DATA copies through the existing Native observation owner.
use super::kagemusha_wallet_advance::{read, response_class};
use crate::kagemusha_wallet_ffi as wallet;
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass},
    sys::{jint, jlong, jobject},
};

fn response(env: &mut JNIEnv<'_>, result: wallet::Result<wallet::Response>) -> jobject {
    response_class(
        env,
        result,
        "org/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletObservationReplyV1",
    )
}

/// Copy immutable admission, released output or prepared Load DATA from the same live owner.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletObservationNativeV1_observe(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    selector: jint,
    identity: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        let selector =
            u32::try_from(selector).map_err(|_| wallet::Failure::code(wallet::INVALID))?;
        let identity = read(&mut env, &identity, 32)?;
        wallet::observation::observe(handle as u64, selector, &identity)
    });
    response(&mut env, result)
}
