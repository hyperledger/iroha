//! JNI admission of complete canonical account controllers through the Rust model owner.

use super::{catch_unwind_to_java, read_java_byte_array_bounded, throw_java_illegal_state};
use iroha_data_model::account::address::{AccountAddress, AccountAddressError};
use jni::objects::{JThrowable, JValue};

/// Maximum raw account-address input accepted by the SDK JNI resource boundary.
const MAX_CANONICAL_ADDRESS_BYTES_V1: usize = 64 * 1024 * 1024;

#[derive(Debug)]
enum AddressAdmissionError {
    InputBound,
    NonCanonical,
    Model(AccountAddressError),
}
impl AddressAdmissionError {
    fn code(&self) -> &'static str {
        match self {
            Self::InputBound => "ERR_INVALID_LENGTH",
            Self::NonCanonical => "ERR_INVALID_PUBLIC_KEY",
            Self::Model(original) => original.code_str(),
        }
    }
    fn capability(&self) -> Option<iroha_crypto::UnsupportedImplementation> {
        match self {
            Self::Model(AccountAddressError::UnsupportedImplementation(original)) => {
                Some(*original)
            }
            _ => None,
        }
    }
    fn message(&self) -> String {
        match self {
            Self::InputBound => "canonical account address exceeds the JNI input bound".to_owned(),
            Self::NonCanonical => {
                "account address is not its exact canonical representation".to_owned()
            }
            Self::Model(original) => original.to_string(),
        }
    }
}

fn validate_canonical_address(bytes: &[u8]) -> Result<(), AddressAdmissionError> {
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_ADDRESS_BYTES_V1 {
        return Err(AddressAdmissionError::InputBound);
    }
    let address =
        AccountAddress::from_canonical_bytes(bytes).map_err(AddressAdmissionError::Model)?;
    let encoded = address
        .canonical_hex()
        .map_err(AddressAdmissionError::Model)?;
    let expected_len = 2 + bytes.len() * 2;
    let hex = b"0123456789abcdef";
    if encoded.len() != expected_len
        || !encoded.starts_with("0x")
        || !encoded.as_bytes()[2..]
            .chunks_exact(2)
            .zip(bytes)
            .all(|(pair, byte)| {
                pair[0] == hex[usize::from(byte >> 4)] && pair[1] == hex[usize::from(byte & 0x0f)]
            })
    {
        return Err(AddressAdmissionError::NonCanonical);
    }
    Ok(())
}

fn throw_address_error(env: &mut jni::JNIEnv<'_>, original: AddressAdmissionError) {
    let code = original.code();
    let capability = original.capability();
    let message = original.message();
    let algorithm = capability.map_or("", |cause| cause.algorithm.as_static_str());
    let operation = capability.map_or_else(String::new, |cause| cause.operation.to_string());
    let result = (|| -> jni::errors::Result<()> {
        let code = env.new_string(code)?;
        let message = env.new_string(message)?;
        let algorithm = env.new_string(algorithm)?;
        let operation = env.new_string(operation)?;
        let throwable = env.new_object(
            "org/hyperledger/iroha/sdk/address/AccountAddressNativeException",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(code.as_ref()),
                JValue::Object(message.as_ref()),
                JValue::Object(algorithm.as_ref()),
                JValue::Object(operation.as_ref()),
            ],
        )?;
        env.throw(JThrowable::from(throwable))
    })();
    if result.is_err() {
        // JNI allocation/class loading can already have raised its original exception.
        // Never erase that pending cause with an address-invalid replacement.
        if matches!(env.exception_check(), Ok(false)) {
            throw_java_illegal_state(
                env,
                "structured address exception could not be constructed".to_owned(),
            );
        }
    }
}

/// Validate every controller key and policy and return the exact admitted canonical bytes.
///
/// # Safety
/// The JVM must provide the native environment and a valid byte-array handle for this call.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeValidateAccountAddressCanonical(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    input: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(bytes) = read_java_byte_array_bounded(
        &mut env,
        &input,
        "canonicalAccountAddress",
        MAX_CANONICAL_ADDRESS_BYTES_V1,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(result) = catch_unwind_to_java(&mut env, "canonical account validation", || {
        validate_canonical_address(&bytes)
    }) else {
        return std::ptr::null_mut();
    };
    if let Err(original) = result {
        throw_address_error(&mut env, original);
        return std::ptr::null_mut();
    }
    match env.byte_array_from_slice(&bytes) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            super::throw_java_illegal_state(
                &mut env,
                format!("canonical account output allocation failed: {error}"),
            );
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_jni_classifies_original_capability_unknown_curve_and_bad_material_separately() {
        use iroha_crypto::{Algorithm, CryptoOperation};
        for &algorithm in Algorithm::ALL {
            let Err(expected) = algorithm.require_implementation(CryptoOperation::ParsePublicKey)
            else {
                continue;
            };
            let curve = iroha_data_model::account::curve::CurveId::from_algorithm(algorithm);
            let mut bytes = vec![2, 0, curve.as_u8(), 48];
            bytes.extend_from_slice(&[1; 48]);
            let error = validate_canonical_address(&bytes).unwrap_err();
            assert_eq!(error.code(), "ERR_UNSUPPORTED_IMPLEMENTATION");
            assert_eq!(error.capability(), Some(expected));
        }
        let unknown = validate_canonical_address(&[2, 0, 255, 1, 1]).unwrap_err();
        assert_eq!(unknown.code(), "ERR_UNKNOWN_CURVE");
        assert!(unknown.capability().is_none());
        let mut bad = vec![2, 0, 1, 32];
        bad.extend_from_slice(&[0; 32]);
        let error = validate_canonical_address(&bad).unwrap_err();
        assert_eq!(error.code(), "ERR_INVALID_PUBLIC_KEY");
        assert!(error.capability().is_none());
        assert_eq!(
            validate_canonical_address(&[]).unwrap_err().code(),
            "ERR_INVALID_LENGTH"
        );
    }

    #[test]
    fn full_controller_fixture_is_accepted_without_byte_normalization() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/account/multisig_wire_v1.json"
        ))
        .unwrap();
        let cases = fixture.get("positive").unwrap().as_array().unwrap();
        assert_eq!(cases.len(), 16);
        for case in cases {
            let encoded = case.get("canonical_address_hex").unwrap().as_str().unwrap();
            let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded)).unwrap();
            validate_canonical_address(&bytes).unwrap();
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(validate_canonical_address(&trailing).is_err());
        }
    }

    #[test]
    fn malformed_points_are_rejected_for_every_controller_algorithm() {
        let mut vectors = vec![
            (1, [vec![1], vec![0; 31]].concat()),
            (1, vec![0xff; 32]),
            (4, [vec![2], vec![0xff; 32]].concat()),
            (3, vec![0xff; 48]),
            (5, vec![0xff; 96]),
            (2, vec![0; 1952]),
            (15, [vec![0, 0, 4], vec![0xff; 64]].concat()),
        ];
        for curve in [10, 11, 12, 13, 14] {
            vectors.push((curve, vec![0xff; if curve < 13 { 64 } else { 128 }]));
        }
        assert_eq!(vectors.len(), 12);
        for (curve, key) in vectors {
            let mut encoded = vec![2, if key.len() <= 255 { 0 } else { 2 }, curve];
            if key.len() <= 255 {
                encoded.push(u8::try_from(key.len()).unwrap());
            } else {
                encoded.extend_from_slice(&u16::try_from(key.len()).unwrap().to_be_bytes());
            }
            encoded.extend_from_slice(&key);
            assert!(
                validate_canonical_address(&encoded).is_err(),
                "curve {curve}"
            );
        }
        assert!(validate_canonical_address(&[]).is_err());
        assert!(validate_canonical_address(&vec![0; MAX_CANONICAL_ADDRESS_BYTES_V1 + 1]).is_err());
    }
}
