//! Canonical quantity-frame limits, scale binding and commitment separation.

use super::*;
use iroha_primitives::{bigint::BigInt, numeric::Numeric};

fn maximum() -> Quantity {
    let mut bytes = [0xff; 64];
    bytes[63] = 0x7f;
    Quantity::from_canonical_numeric(
        Numeric::try_new(BigInt::from_twos_bytes(&bytes).unwrap(), 0).unwrap(),
    )
    .unwrap()
}

#[test]
fn canonical_frames_roundtrip_all_scales_and_ignore_ambient_layout() {
    for quantity in [Quantity::zero(), Quantity::from(u128::MAX), maximum()] {
        for scale in 0..=28 {
            let units = FastpqQuantityUnits::from_quantity(&quantity, scale).unwrap();
            let encoded = encode_quantity_units_v1(&units).unwrap();
            assert!(encoded.len() <= QUANTITY_VALUE_MAX_BYTES_V1);
            assert_eq!(decode_quantity_units_v1(&encoded).unwrap(), units);
            let raw: QuantityValueV1 = norito::decode_canonical_with_limits(
                &encoded,
                norito::canonical_decode_limits(QUANTITY_VALUE_MAX_BYTES_V1),
            )
            .unwrap();
            assert_eq!(raw.scale, scale);
            assert_eq!(raw.limbs, *units.limbs());
            let _ambient = norito::core::DecodeFlagsGuard::enter(0);
            assert_eq!(encode_quantity_units_v1(&units).unwrap(), encoded);
            assert_eq!(decode_quantity_units_v1(&encoded).unwrap(), units);
        }
    }
}

#[test]
fn canonical_decoder_rejects_wrong_schema_domain_and_framing() {
    #[derive(NoritoSerialize, norito::NoritoSchema)]
    #[norito_schema(
        name = "fastpq_prover::gadgets::public_transfer_statement::quantity::tests::canonical_decoder_rejects_wrong_schema_domain_and_framing::OtherValue",
        frame = "fastpq_prover::public_transfer::OtherQuantityValueV1"
    )]
    struct OtherValue {
        scale: u32,
        limbs: [u32; FASTPQ_QUANTITY_UNIT_LIMBS],
    }

    let units = FastpqQuantityUnits::from_quantity(&Quantity::one(), 0).unwrap();
    let encoded = encode_quantity_units_v1(&units).unwrap();
    for length in [0, 1, 8, encoded.len() - 1] {
        assert!(decode_quantity_units_v1(&encoded[..length]).is_err());
    }
    let mut suffixed = encoded.clone();
    suffixed.push(0);
    assert!(decode_quantity_units_v1(&suffixed).is_err());
    assert!(decode_quantity_units_v1(&1_u64.to_le_bytes()).is_err());
    assert!(decode_quantity_units_v1(&vec![0; QUANTITY_VALUE_MAX_BYTES_V1 + 1]).is_err());
    for (scale, limbs) in [
        (29, [0; FASTPQ_QUANTITY_UNIT_LIMBS]),
        (u32::MAX, [0; FASTPQ_QUANTITY_UNIT_LIMBS]),
        (0, [u32::MAX; FASTPQ_QUANTITY_UNIT_LIMBS]),
        (28, [u32::MAX; FASTPQ_QUANTITY_UNIT_LIMBS]),
    ] {
        let invalid = norito::encode_canonical(&QuantityValueV1 { scale, limbs }).unwrap();
        assert!(decode_quantity_units_v1(&invalid).is_err());
    }
    let other = norito::encode_canonical(&OtherValue {
        scale: 0,
        limbs: *units.limbs(),
    })
    .unwrap();
    assert!(decode_quantity_units_v1(&other).is_err());
}

#[test]
fn canonical_encoder_preserves_an_enclosing_allocation_refusal() {
    let units = FastpqQuantityUnits::from_quantity(&maximum(), 28).unwrap();
    let expected = encode_quantity_units_v1(&units).unwrap();
    let exhausted = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32);
    let rejected =
        norito::core::with_decode_limits_scope(exhausted, || encode_quantity_units_v1(&units));
    assert!(matches!(
        rejected,
        Err(crate::Error::Encode(norito::Error::TotalAllocationExceeded {
            attempted,
            limit: 0,
        })) if attempted > 0
    ));
    assert_eq!(encode_quantity_units_v1(&units).unwrap(), expected);
    assert_eq!(decode_quantity_units_v1(&expected).unwrap(), units);
}

#[test]
fn canonical_decoder_respects_an_enclosing_resource_budget() {
    let units = FastpqQuantityUnits::from_quantity(&maximum(), 28).unwrap();
    let encoded = encode_quantity_units_v1(&units).unwrap();
    let limited = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let decoded = norito::with_decode_limits_scope(limited, || decode_quantity_units_v1(&encoded));
    assert!(decoded.is_err());
    assert_eq!(decode_quantity_units_v1(&encoded).unwrap(), units);
}

#[test]
fn value_commitment_binds_scale_and_high_limbs_in_a_distinct_domain() {
    let key: [u8; 32] = Hash::new(b"full quantity key").into();
    let quantity = maximum();
    let first = FastpqQuantityUnits::from_quantity(&quantity, 28).unwrap();
    let another_scale = FastpqQuantityUnits::from_quantity(&quantity, 27).unwrap();
    let mut altered_bytes = [0xff; 64];
    altered_bytes[63] = 0x3f;
    let altered = Quantity::from_canonical_numeric(
        Numeric::try_new(BigInt::from_twos_bytes(&altered_bytes).unwrap(), 0).unwrap(),
    )
    .unwrap();
    let high_limb_change = FastpqQuantityUnits::from_quantity(&altered, 28).unwrap();
    assert_ne!(first.limbs()[18], high_limb_change.limbs()[18]);
    assert_ne!(
        FastpqQuantityUnits::leaf(&key, first).unwrap(),
        FastpqQuantityUnits::leaf(&key, another_scale).unwrap()
    );
    assert_ne!(
        FastpqQuantityUnits::leaf(&key, first).unwrap(),
        FastpqQuantityUnits::leaf(&key, high_limb_change).unwrap()
    );
    let small = FastpqQuantityUnits::from_quantity(&Quantity::one(), 0).unwrap();
    assert_ne!(
        FastpqQuantityUnits::leaf(&key, small).unwrap(),
        <u64 as TransferValue>::leaf(&key, 1).unwrap()
    );
    let zero = FastpqQuantityUnits::from_quantity(&Quantity::zero(), 0).unwrap();
    let scaled_zero = FastpqQuantityUnits::from_quantity(&Quantity::zero(), 28).unwrap();
    assert_eq!(zero.limbs(), scaled_zero.limbs());
    assert_ne!(zero.row_key(), scaled_zero.row_key());
    assert_ne!(
        FastpqQuantityUnits::leaf(&key, zero).unwrap(),
        FastpqQuantityUnits::leaf(&key, scaled_zero).unwrap()
    );
    let frame = encode_quantity_units_v1(&first).unwrap();
    let value_hash = Hash::new([b"fastpq:quantity:v1:smt:value|".as_slice(), &frame].concat());
    let expected =
        Hash::new([b"fastpq:v1:smt:leaf|".as_slice(), &key, value_hash.as_ref()].concat());
    let expected: [u8; 32] = expected.into();
    assert_eq!(FastpqQuantityUnits::leaf(&key, first).unwrap(), expected);
}
