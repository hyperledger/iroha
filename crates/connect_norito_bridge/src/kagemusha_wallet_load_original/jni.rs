//! JNI calls the same bounded DATA decoder; no owner or proof callback exists here.

use super::*;
use ::jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JLongArray},
    sys::jint,
};

/// Decode exact unsigned Load transport originals. All foreign extents are checked before
/// any array copy. Zero means canonical DATA binding only, never financial proof acceptance.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletLoadOriginalNativeV1_validate(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    scheme: JByteArray<'_>,
    wallet_id: JByteArray<'_>,
    request: JByteArray<'_>,
    payer: JByteArray<'_>,
    receipt: JByteArray<'_>,
    finality: JByteArray<'_>,
    out_height: JLongArray<'_>,
) -> jint {
    wallet::run(|| {
        if env
            .get_array_length(&out_height)
            .map_err(|_| Failure::code(INVALID))?
            != 1
        {
            return Err(Failure::code(INVALID));
        }
        env.set_long_array_region(&out_height, 0, &[0])
            .map_err(|_| Failure::code(INVALID))?;
        let inputs = [&scheme, &wallet_id, &request, &payer, &receipt, &finality];
        let bounds = [
            32,
            32,
            32,
            PAYER_MAX_BYTES,
            KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        ];
        for (index, (input, bound)) in inputs.iter().zip(bounds).enumerate() {
            let length = env
                .get_array_length(*input)
                .map_err(|_| Failure::code(INVALID))?;
            if length <= 0 || length as usize > bound || (index < 3 && length != 32) {
                return Err(Failure::code(INVALID));
            }
        }
        let mut originals = Vec::with_capacity(inputs.len());
        for input in inputs {
            originals.push(
                env.convert_byte_array(input)
                    .map_err(|_| Failure::code(INVALID))?,
            );
        }
        let height = validate(
            &originals[0],
            &originals[1],
            &originals[2],
            &originals[3],
            &originals[4],
            &originals[5],
        )?;
        env.set_long_array_region(&out_height, 0, &[height as i64])
            .map_err(|_| Failure::code(INVALID))
    })
    .err()
    .map_or(0, |error| error.status)
}
