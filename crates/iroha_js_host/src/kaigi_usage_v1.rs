//! Native final V1 Kaigi billing proof bound to the stored host commitment.

use iroha_data_model::{kaigi::scalar::KaigiAuthorizationScalarV1, proof::VerifyingKeyBox};
use kaigi_zk::{
    authorization_v1::KaigiAuthorizationWitnessV1,
    usage_v1::{KaigiUsageContextV1, compute_usage_v1},
};
use napi::{
    Env,
    bindgen_prelude::{BigInt, Buffer, Uint8Array, Uint8ArraySlice},
};
use napi_derive::napi;

use super::kaigi_proof_v1::{consume_blinding, encode_verified_envelope, failure, invalid};

/// Canonical proof of one host-authorized final V1 usage segment.
#[napi(object)]
pub struct JsKaigiUsageProofV1 {
    /// Exact stored host C opened by the supplied blinding.
    pub host_commitment: Buffer,
    /// Raw canonical Pasta Fp usage commitment U.
    pub usage_commitment: Buffer,
    /// Exact roster root bound by the usage relation.
    pub pre_roster_root: Buffer,
    /// Canonical final V1 `OpenVerifyEnvelope`, already verified by Core.
    pub proof: Buffer,
}

fn exact_u64(value: &BigInt, name: &str) -> napi::Result<u64> {
    let (negative, value, lossless) = value.get_u64();
    if negative || !lossless {
        return Err(invalid(format!(
            "{name} must be an exact unsigned 64-bit bigint"
        )));
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)] // Typed final context is explicit across N-API.
fn parse_context(
    network: &[u8],
    domain: &str,
    call: &str,
    host: &str,
    root: &[u8],
    segment: f64,
    duration: &BigInt,
    gas: &BigInt,
) -> napi::Result<KaigiUsageContextV1> {
    let host_context = super::kaigi_authorization_v1::parse_context(
        network,
        domain,
        call,
        host,
        host,
        &BigInt::from(0_u64),
        "hostCreate",
        root,
    )?;
    if !segment.is_finite()
        || segment.fract() != 0.0
        || !(0.0..=f64::from(u32::MAX)).contains(&segment)
    {
        return Err(invalid(
            "segmentIndex must be an exact unsigned 32-bit integer",
        ));
    }
    let context = KaigiUsageContextV1 {
        network_id: host_context.network_id,
        call_id: host_context.call_id,
        host_id: host_context.host_id,
        pre_roster_root: host_context.pre_roster_root,
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // Exact u32 range checked above.
        segment_index: segment as u32,
        duration_ms: exact_u64(duration, "durationMs")?,
        billed_gas: exact_u64(gas, "billedGas")?,
    };
    context.validate().map_err(invalid)?;
    Ok(context)
}

fn parse_host_commitment(bytes: &[u8]) -> napi::Result<[u8; 32]> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("hostCommitment must contain exactly 32 canonical Pasta Fp bytes"))?;
    KaigiAuthorizationScalarV1::from_le_bytes(bytes)
        .ok_or_else(|| invalid("hostCommitment must contain canonical Pasta Fp bytes"))?;
    Ok(bytes)
}

fn produce(
    context: KaigiUsageContextV1,
    expected_host: [u8; 32],
    witness: KaigiAuthorizationWitnessV1,
) -> napi::Result<(JsKaigiUsageProofV1, VerifyingKeyBox)> {
    let outputs = compute_usage_v1(&context, &witness).map_err(invalid)?;
    let [host, usage] = outputs.canonical_bytes();
    if host != expected_host {
        return Err(invalid(
            "blinding does not open the stored hostCommitment for this network, call and original host",
        ));
    }
    let key = iroha_core_zk::native_pipa_r::kaigi_verifying_key(
        kaigi_zk::native::NativeRelationV1::Usage,
    )
    .map_err(failure)?;
    let envelope =
        iroha_core_zk::native_pipa_r::prove_kaigi_usage(context, witness).map_err(failure)?;
    let proof = encode_verified_envelope(&envelope, &key)?;
    Ok((
        JsKaigiUsageProofV1 {
            host_commitment: host.to_vec().into(),
            usage_commitment: usage.to_vec().into(),
            pre_roster_root: context.pre_roster_root.to_vec().into(),
            proof: proof.into(),
        },
        key,
    ))
}

/// Consume the original host opening and prove the exact current usage segment.
///
/// Mutable blinding bytes are cleared before context validation. Cached proving
/// material contains only the witness-free circuit, never caller secrets.
#[napi(js_name = "buildKaigiUsageProofV1")]
#[allow(clippy::too_many_arguments)] // Keep each final V1 field typed across N-API.
pub fn build_kaigi_usage_proof_v1(
    env: Env,
    network_id: Uint8Array,
    domain_id: String,
    call_name: String,
    host_id: String,
    pre_roster_root: Uint8Array,
    segment_index: f64,
    duration_ms: BigInt,
    billed_gas: BigInt,
    host_commitment: Uint8Array,
    mut blinding: Uint8ArraySlice<'_>,
) -> napi::Result<JsKaigiUsageProofV1> {
    // Retain the supplied public context if its JS view overlaps blinding.
    let network: Result<[u8; 32], _> = network_id.as_ref().try_into();
    let root: Result<[u8; 32], _> = pre_roster_root.as_ref().try_into();
    let host: Result<[u8; 32], _> = host_commitment.as_ref().try_into();
    let witness = consume_blinding(env, &mut blinding)?;
    let network = network.map_err(|_| invalid("networkId must contain exactly 32 bytes"))?;
    let root = root.map_err(|_| invalid("preRosterRoot must contain exactly 32 bytes"))?;
    let host = host.map_err(|_| invalid("hostCommitment must contain exactly 32 bytes"))?;
    let context = parse_context(
        &network,
        &domain_id,
        &call_name,
        &host_id,
        &root,
        segment_index,
        &duration_ms,
        &billed_gas,
    )?;
    let host = parse_host_commitment(&host)?;
    produce(context, host, witness).map(|(artifacts, _)| artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kaigi_proof_v1::{VK_BACKEND, take_witness};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{account::AccountId, proof::ProofBox, zk::OpenVerifyEnvelope};
    use kaigi_zk::usage_v1::{KAIGI_USAGE_CIRCUIT_ID_V1, KAIGI_USAGE_PUBLIC_INPUTS_SCHEMA_V1};

    fn host() -> String {
        AccountId::new(
            KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
        .to_string()
    }
    fn fixture_context() -> KaigiUsageContextV1 {
        parse_context(
            &[0x13; 32],
            "kaigi.universal",
            "native-usage",
            &host(),
            &[0x35; 32],
            0.0,
            &BigInt::from(123_u64),
            &BigInt::from(12_u64),
        )
        .unwrap()
    }

    #[test]
    fn usage_context_requires_exact_metrics_and_canonical_host_commitment() {
        for segment in [
            -1.0,
            0.5,
            f64::NAN,
            f64::INFINITY,
            f64::from(u32::MAX) + 1.0,
        ] {
            assert!(
                parse_context(
                    &[0x13; 32],
                    "kaigi.universal",
                    "native-usage",
                    &host(),
                    &[0x35; 32],
                    segment,
                    &BigInt::from(1_u64),
                    &BigInt::from(0_u64)
                )
                .is_err()
            );
        }
        let maximum = parse_context(
            &[0x13; 32],
            "kaigi.universal",
            "native-usage",
            &host(),
            &[0x35; 32],
            f64::from(u32::MAX),
            &BigInt::from(u64::MAX),
            &BigInt::from(u64::MAX),
        )
        .unwrap();
        assert_eq!(maximum.segment_index, u32::MAX);
        assert_eq!(maximum.duration_ms, u64::MAX);
        assert_eq!(maximum.billed_gas, u64::MAX);
        assert!(
            parse_context(
                &[0x13; 32],
                "kaigi.universal",
                "native-usage",
                &host(),
                &[0x35; 32],
                0.0,
                &BigInt::from(0_u64),
                &BigInt::from(0_u64)
            )
            .is_err()
        );
        for value in [
            BigInt {
                sign_bit: true,
                words: vec![1],
            },
            BigInt {
                sign_bit: false,
                words: vec![0, 1],
            },
        ] {
            assert!(exact_u64(&value, "durationMs").is_err());
            assert!(exact_u64(&value, "billedGas").is_err());
        }
        for bytes in [vec![0xff; 32], vec![1; 31], vec![1; 33]] {
            assert!(parse_host_commitment(&bytes).is_err());
        }
        assert_eq!(parse_host_commitment(&[0; 32]).unwrap(), [0; 32]);
        let mut secret = [0x11; 32];
        assert!(
            produce(
                fixture_context(),
                [0; 32],
                take_witness(&mut secret).unwrap()
            )
            .is_err()
        );
        assert_eq!(secret, [0; 32]);
    }

    #[test]
    fn native_usage_proof_opens_host_commitment_and_rejects_all_25_row_mutations() {
        let context = fixture_context();
        let mut secret = [0x11; 32];
        let witness = take_witness(&mut secret).unwrap();
        let [expected_host, expected_usage] = compute_usage_v1(&context, &witness)
            .unwrap()
            .canonical_bytes();
        let (artifacts, key) = produce(context, expected_host, witness).unwrap();
        assert!(std::ptr::eq(
            kaigi_zk::native::NativeRelationV1::Usage.prover().unwrap(),
            kaigi_zk::native::NativeRelationV1::Usage.prover().unwrap()
        ));
        assert_eq!(secret, [0; 32]);
        assert_eq!(artifacts.host_commitment.as_ref(), expected_host);
        assert_eq!(artifacts.usage_commitment.as_ref(), expected_usage);
        assert_eq!(artifacts.pre_roster_root.as_ref(), context.pre_roster_root);
        let envelope: OpenVerifyEnvelope =
            norito::decode_canonical(artifacts.proof.as_ref()).unwrap();
        assert_eq!(envelope.circuit_id, KAIGI_USAGE_CIRCUIT_ID_V1);
        assert_eq!(envelope.public_inputs, KAIGI_USAGE_PUBLIC_INPUTS_SCHEMA_V1);
        assert_eq!(envelope.vk_hash, iroha_core_zk::hash_vk(&key));
        assert!(envelope.aux.is_empty());
        for row in 0..25 {
            let mut changed = envelope.clone();
            let mut inner: iroha_data_model::zk::NativePipaRProofV1 =
                norito::decode_canonical(&changed.proof_bytes).unwrap();
            assert_eq!(inner.public_inputs.len(), 25);
            let bytes = &mut inner.public_inputs[row];
            let zero = bytes.iter().all(|byte| *byte == 0);
            bytes.fill(0);
            if zero {
                bytes[0] = 1;
            }
            changed.proof_bytes = norito::encode_canonical(&inner).unwrap();
            let proof = ProofBox::new(
                VK_BACKEND.to_owned(),
                norito::encode_canonical(&changed).unwrap(),
            );
            assert!(
                !iroha_core_zk::verify_backend(VK_BACKEND, &proof, Some(&key)),
                "modified row {row}"
            );
        }
    }
}
