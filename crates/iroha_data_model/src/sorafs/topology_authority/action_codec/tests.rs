//! Exact canonical expiry wire, schema, resource and memory-layout regressions.

use super::*;
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};

/// Original single expiry branch used only to compare the canonical frame.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::topology_authority::TopologyActionV1")]
#[repr(align(8))]
enum InlineExpiry {
    /// The original unboxed tag and field.
    #[codec(index = 5)]
    Expire(TopologyExpireV1),
}

fn expiry() -> TopologyExpireV1 {
    TopologyExpireV1 {
        operation_id: [11; 32],
        reservation: SignerOperationReservationV1 {
            reservation_id: [23; 32],
            fence: 17,
            expires_at_unix_ms: 180_000,
        },
    }
}

#[test]
fn boxed_expiry_preserves_original_canonical_frame() {
    let original = InlineExpiry::Expire(expiry());
    let action = TopologyActionV1::Expire(Box::new(expiry()));
    let expected = norito::encode_canonical(&original).unwrap();
    let actual = norito::encode_canonical(&action).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        norito::decode_canonical::<TopologyActionV1>(&expected).unwrap(),
        action
    );
    assert_eq!(
        norito::decode_canonical::<InlineExpiry>(&actual).unwrap(),
        original
    );
}

#[test]
fn boxed_action_retains_original_alignment_and_small_memory_layout() {
    assert_eq!(core::mem::align_of::<TopologyActionV1>(), 8);
    assert!(core::mem::size_of::<TopologyActionV1>() <= core::mem::size_of::<Vec<u8>>() + 8);
}

#[test]
fn expiry_bare_decoder_rejects_truncation_suffix_and_unknown_tag() {
    let action = TopologyActionV1::Expire(Box::new(expiry()));
    let bytes = action.encode();
    for length in 0..bytes.len() {
        assert!(
            <TopologyActionV1 as ncore::DecodeFromSlice>::decode_from_slice(&bytes[..length])
                .is_err()
        );
    }
    let mut suffix = bytes.clone();
    suffix.push(0);
    assert!(<TopologyActionV1 as ncore::DecodeFromSlice>::decode_from_slice(&suffix).is_err());
    let mut unknown = bytes;
    unknown[..4].copy_from_slice(&7_u32.to_le_bytes());
    assert!(<TopologyActionV1 as ncore::DecodeFromSlice>::decode_from_slice(&unknown).is_err());
}

#[test]
fn expiry_box_allocation_is_charged_before_construction() {
    let bytes = TopologyActionV1::Expire(Box::new(expiry())).encode();
    let limits = |allocation| ncore::DecodeLimits::new(1024, 1024, 1024, allocation, 32);
    let (decoded, usage) = ncore::with_decode_limits_measured(limits(8192), || {
        <TopologyActionV1 as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
    });
    decoded.unwrap();
    let charged = usage.total_allocated_bytes();
    assert!(charged >= ncore::owned_box_allocation_bytes::<TopologyExpireV1>());
    let exact = ncore::with_decode_limits_scope(limits(charged), || {
        <TopologyActionV1 as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
    });
    exact.unwrap();
    let short = ncore::with_decode_limits_scope(limits(charged - 1), || {
        <TopologyActionV1 as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
    });
    assert!(matches!(
        short,
        Err(ncore::Error::TotalAllocationExceeded { .. })
    ));
}

// The original enum has the ARM layout defect. Retain it only for the host
// schema comparison; the all-target inline single-branch test above preserves
// the expiry wire without reintroducing the large variant to ARM compilations.
#[cfg(target_pointer_width = "64")]
mod original_schema {
    use super::*;

    /// The original complete action schema, with the same published type identifier.
    #[derive(
        Debug,
        PartialEq,
        Eq,
        iroha_schema::IntoSchema,
        NoritoSerialize,
        NoritoDeserialize,
        NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::sorafs::topology_authority::TopologyActionV1")]
    pub enum TopologyActionV1 {
        /// Configure original canonical custody policy.
        #[codec(index = 0)]
        Configure(Vec<u8>),
        /// Enroll original custody predecessor.
        #[codec(index = 1)]
        Enroll(Vec<u8>),
        /// Revoke original generations.
        #[codec(index = 2)]
        Revoke(TopologyRevocationV1),
        /// Reserve original operation.
        #[codec(index = 3)]
        Reserve(Box<TopologyReserveV1>),
        /// Complete original reservation.
        #[codec(index = 4)]
        Complete(Box<TopologyCompleteV1>),
        /// Expire original reservation without a boxed schema field.
        #[codec(index = 5)]
        Expire(TopologyExpireV1),
        /// Check original claims.
        #[codec(index = 6)]
        Check(Box<TopologyCheckV1>),
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn boxed_expiry_preserves_complete_original_wire_schema_identity() {
    use iroha_schema::IntoSchema;
    let actual = TopologyActionV1::schema();
    let original = original_schema::TopologyActionV1::schema();
    let original_action = original_schema::TopologyActionV1::Expire(expiry());
    let native_action = TopologyActionV1::Expire(Box::new(expiry()));
    let original_bytes = norito::encode_canonical(&original_action).unwrap();
    let native_bytes = norito::encode_canonical(&native_action).unwrap();
    assert_eq!(native_bytes, original_bytes);
    assert_eq!(
        norito::decode_canonical::<original_schema::TopologyActionV1>(&native_bytes).unwrap(),
        original_action
    );
    assert_eq!(
        actual.get::<TopologyActionV1>(),
        original.get::<original_schema::TopologyActionV1>()
    );
    assert!(!actual.contains_key::<Box<TopologyExpireV1>>());
    assert_eq!(crate::wire_schema::wire_root_defects(&actual), Vec::new());
    assert_eq!(
        crate::wire_schema::wire_schema_hash_of(&[&actual], &[], [0; 32]),
        crate::wire_schema::wire_schema_hash_of(&[&original], &[], [0; 32])
    );
}
