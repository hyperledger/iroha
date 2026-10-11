//! JNI financial-review DATA uses the same single Native owner as the C boundary.
use super::kagemusha_wallet_advance::{read, response, response_class};
use crate::kagemusha_wallet_ffi::{self as wallet, review};
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass},
    sys::{jint, jlong, jobject},
};
/// Only Send1/Unload8; retained token and bounded original-bearing DATA arrive as result18.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_review(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    selector: jint,
    amount_low: jlong,
    amount_high: jlong,
    first: JByteArray<'_>,
    second: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        let selector =
            u32::try_from(selector).map_err(|_| wallet::Failure::code(wallet::INVALID))?;
        let bounds = review::bounds(selector)?;
        let first = read(&mut env, &first, bounds[0])?;
        let second = read(&mut env, &second, bounds[1])?;
        let amount = u128::from(amount_low as u64) | (u128::from(amount_high as u64) << 64);
        review::review(
            handle as u64,
            review::request(selector, amount, &first, &second)?,
        )
    });
    let token = result.as_ref().ok().map(|value| value.sequence as u64);
    let object = response_class(
        &mut env,
        result,
        "org/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletReviewReplyV1",
    );
    if object.is_null()
        && let Some(token) = token
    {
        let _ = wallet::run(|| review::discard_review(handle as u64, token));
    }
    object
}
/// Actual retained review supplies all financial inputs. The local retry ID grants no authority.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_executeReviewed(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    token: jlong,
    request_id: JByteArray<'_>,
) -> jobject {
    let result = wallet::run(|| {
        let request = match read(&mut env, &request_id, 32) {
            Ok(value) if value.len() == 32 => value,
            _ => {
                let _ = review::discard_review(handle as u64, token as u64);
                return Err(wallet::Failure::code(wallet::INVALID));
            }
        };
        review::execute_reviewed(handle as u64, token as u64, &request)
    });
    response(&mut env, result)
}
/// Cancellation drops only the in-memory actual review; never durable monetary data.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_discardReview(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    token: jlong,
) -> jint {
    wallet::run(|| review::discard_review(handle as u64, token as u64))
        .err()
        .map_or(0, |error| error.status)
}
