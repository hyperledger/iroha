//! Captured STARK frame identities and canonical payload boundary regressions.
//!
//! The fixture records actual original compiler identities, not historical frame bytes.
//! Populated values below exercise the current unchanged codec and proof constructors.

use super::*;
use norito::{NoritoSchema, core::NoritoDeserialize, core::NoritoSerialize, json::Value};

fn observed_identity<T: NoritoSchema>(identifier: &str) {
    let rows: Vec<Value> = norito::json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/core/stark_frame_identity_observations.v1.json"
    )))
    .expect("immutable original compiler observations");
    assert_eq!(rows.len(), 6);
    let mut directions = std::collections::BTreeSet::new();
    for row in rows
        .iter()
        .filter(|row| row.get("identifier").and_then(Value::as_str) == Some(identifier))
    {
        let field = |key| row.get(key).and_then(Value::as_str).expect("captured text");
        assert!(directions.insert(field("direction")));
        assert_eq!(T::nominal_name(), field("nominal"));
        assert_eq!(
            std::any::type_name::<T>(),
            crate::frame_test_support::relocated_rust_path(field("nominal")).as_str()
        );
        assert_eq!(T::frame_name(), field("root_hint"));
        let hash = norito::schema::identity::frame_hash::<T>();
        let observed: Vec<u8> = field("schema_hash")
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(hash.as_slice(), observed);
    }
    assert_eq!(
        directions,
        ["deserialize", "serialize"].into_iter().collect()
    );
}

fn canonical_roundtrip<T>(value: &T)
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    let expected = norito::encode_canonical(value).expect("canonical frame");
    let view = norito::core::from_bytes_view(&expected).expect("valid frame and checksum");
    assert_eq!(view.schema(), norito::schema::identity::frame_hash::<T>());
    let ambient = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _ambient = norito::core::DecodeFlagsGuard::enter(ambient);
    assert_eq!(norito::encode_canonical(value).unwrap(), expected);
    let decoded: T = norito::decode_canonical(&expected).expect("canonical typed roundtrip");
    assert_eq!(norito::encode_canonical(&decoded).unwrap(), expected);
    assert_eq!(norito::core::get_decode_flags(), ambient);

    let mut trailing = expected.clone();
    trailing.push(0);
    assert!(norito::decode_canonical::<T>(&trailing).is_err());
    let mut wrong_root = expected.clone();
    wrong_root[6] ^= 1;
    assert!(norito::decode_canonical::<T>(&wrong_root).is_err());
    let mut corrupt_payload = expected.clone();
    *corrupt_payload.last_mut().unwrap() ^= 1;
    assert!(norito::decode_canonical::<T>(&corrupt_payload).is_err());
    assert!(norito::decode_canonical::<T>(&expected[..expected.len() - 1]).is_err());
    assert_eq!(norito::core::get_decode_flags(), ambient);
}

fn shapes<T>(value: &T)
where
    T: Clone + NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    canonical_roundtrip(value);
    canonical_roundtrip(&Option::<T>::None);
    canonical_roundtrip(&Some(value.clone()));
    canonical_roundtrip(&Vec::<T>::new());
    canonical_roundtrip(&vec![value.clone(), value.clone()]);
}

fn params() -> StarkFriParamsV1 {
    StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:air".to_owned(),
    }
}

#[test]
fn captured_stark_params_frame_identity() {
    observed_identity::<StarkFriParamsV1>("StarkFriParamsV1");
    shapes(&params());
}

#[test]
fn captured_stark_verifying_key_frame_identity() {
    observed_identity::<StarkFriVerifyingKeyV1>("StarkFriVerifyingKeyV1");
    let value = StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: "stark/fri/poseidon-x7-goldilocks-6x64-v1:bounded-vk-test".to_owned(),
        n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    validate_stark_fri_canonical_verifying_key_payload(&value, &value.circuit_id, "test")
        .expect("existing ledger-grade verifier key fixture");
    let encoded = norito::encode_canonical(&value).unwrap();
    let decoded = decode_stark_fri_verifying_key_v1(&encoded).expect("actual bounded key decoder");
    assert_eq!(norito::encode_canonical(&decoded).unwrap(), encoded);
    shapes(&value);
}

#[test]
fn captured_stark_envelope_frame_identity() {
    observed_identity::<StarkVerifyEnvelopeV1>("StarkVerifyEnvelopeV1");
    let bytes = prove_stark_fri_air_envelope_bytes(
        params(),
        "IROHA-TEST-STARK-AIR".to_owned(),
        "stark/fri/poseidon-x7-goldilocks-6x64-v1:air-test".to_owned(),
        GoldilocksDigest384V1::new([0x42; 6]).unwrap(),
    )
    .expect("existing populated AIR proof fixture");
    assert!(
        verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
    let value: StarkVerifyEnvelopeV1 = norito::decode_from_bytes(&bytes).unwrap();
    assert!(value.proof.air.is_some());
    assert!(!value.proof.queries.is_empty());
    assert!(!value.proof.commits.roots.is_empty());
    shapes(&value);
}
