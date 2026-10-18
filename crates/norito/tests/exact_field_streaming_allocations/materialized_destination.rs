//! Original wire, consuming-hook and local-refusal parity for actual-value destinations.
//!
//! These lower-seam controls do not assert complete physical graph custody. The
//! reference types exercise the pre-existing owning generator, not another wire.
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use norito::core::{
    CanonicalField, DecodeField, DecodeFlagsGuard, DecodeFromSlice, DecodeIntoError,
    DecodeValueDestination, DecodeValueFields, DecodeVariantField, EnumFieldDestination,
    FieldDestination, OwnedFields, SerializePayload, header_flags,
};
use norito::{DeserializePayload, NoritoSchema, NoritoSerialize};
use std::cell::Cell;

thread_local! {static HOOK_CALLS:Cell<usize>=const{Cell::new(0)};}
fn normalize(value: u8) -> Result<u8, norito::Error> {
    HOOK_CALLS.set(HOOK_CALLS.get() + 1);
    match value {
        0 => Err(norito::Error::Message("original zero value".into())),
        254 => Err(norito::Error::TotalAllocationExceeded {
            attempted: 4097,
            limit: 4096,
        }),
        255 => Ok(9),
        _ => Ok(value),
    }
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "materialized.Checked")]
#[norito(decode_fields, decode_from_slice, validate = "Self::validate")]
struct Checked {
    value: u8,
    fixed: [u8; 4],
}
impl Checked {
    fn validate(mut self) -> Result<Self, norito::Error> {
        self.value = normalize(self.value)?;
        Ok(self)
    }
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "materialized.Checked")]
#[norito(decode_from_slice, validate = "Self::validate")]
struct OriginalChecked {
    value: u8,
    fixed: [u8; 4],
}
impl OriginalChecked {
    fn validate(mut self) -> Result<Self, norito::Error> {
        self.value = normalize(self.value)?;
        Ok(self)
    }
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "materialized.Choice")]
#[norito(decode_fields, decode_from_slice, validate = "Self::validate")]
enum Choice {
    #[codec(index = 7)]
    Unit,
    #[codec(index = 19)]
    Tuple(u8, [u8; 4]),
    Named {
        bytes: Vec<u8>,
        value: u8,
    },
}
impl Choice {
    fn validate(self) -> Result<Self, norito::Error> {
        Ok(match self {
            Self::Unit => {
                normalize(1)?;
                Self::Unit
            }
            Self::Tuple(value, fixed) => Self::Tuple(normalize(value)?, fixed),
            Self::Named { bytes, value } => Self::Named {
                bytes,
                value: normalize(value)?,
            },
        })
    }
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "materialized.Choice")]
#[norito(decode_from_slice, validate = "Self::validate")]
enum OriginalChoice {
    #[codec(index = 7)]
    Unit,
    #[codec(index = 19)]
    Tuple(u8, [u8; 4]),
    Named {
        bytes: Vec<u8>,
        value: u8,
    },
}
impl OriginalChoice {
    fn validate(self) -> Result<Self, norito::Error> {
        Ok(match self {
            Self::Unit => {
                normalize(1)?;
                Self::Unit
            }
            Self::Tuple(value, fixed) => Self::Tuple(normalize(value)?, fixed),
            Self::Named { bytes, value } => Self::Named {
                bytes,
                value: normalize(value)?,
            },
        })
    }
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "materialized.Tuple")]
#[norito(decode_fields, decode_from_slice, validate = "Self::validate")]
struct CheckedTuple(u8);
impl CheckedTuple {
    fn validate(self) -> Result<Self, norito::Error> {
        Ok(Self(normalize(self.0)?))
    }
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "materialized.Tuple")]
#[norito(decode_from_slice, validate = "Self::validate")]
struct OriginalTuple(u8);
impl OriginalTuple {
    fn validate(self) -> Result<Self, norito::Error> {
        Ok(Self(normalize(self.0)?))
    }
}

#[derive(Default)]
struct Destination {
    variant: Option<u32>,
    fields: Vec<(u32, usize)>,
    refusal: Option<AllocationRefusal>,
}
impl FieldDestination for Destination {
    type Error = AllocationRefusal;
}
impl<T> DecodeValueDestination<T> for Destination {
    fn restore_value(&mut self, value: T) {
        drop(value);
    }
}
impl EnumFieldDestination for Destination {
    fn begin_variant(&mut self, variant: u32) -> Result<(), Self::Error> {
        if let Some(original) = self.refusal.take() {
            return Err(original);
        }
        self.variant = Some(variant);
        Ok(())
    }
}
impl<const V: u32, const I: usize, T> DecodeVariantField<V, I, T> for Destination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Self::Error>> {
        self.fields.push((V, I));
        Ok(field.decode_owned()?)
    }

    fn restore_variant_field(&mut self, value: T) {
        drop(value);
    }
}
impl<const I: usize, T> DecodeField<I, T> for Destination {
    type Value = T;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Self::Error>> {
        if let Some(original) = self.refusal.take() {
            return Err(DecodeIntoError::Destination(original));
        }
        self.fields.push((0, I));
        Ok(field.decode_owned()?)
    }
}
fn bare(value: &dyn SerializePayload, flags: u8) -> Vec<u8> {
    super::bare_bytes(value, flags)
}
fn codec<E: std::fmt::Debug>(result: DecodeIntoError<E>) -> norito::Error {
    match result {
        DecodeIntoError::Codec(error) => error,
        other => panic!("unexpected destination cause {other:?}"),
    }
}
fn values() -> [Choice; 3] {
    [
        Choice::Unit,
        Choice::Tuple(9, [1, 2, 3, 4]),
        Choice::Named {
            bytes: vec![5, 6, 7],
            value: 9,
        },
    ]
}

#[test]
fn materialized_enum_preserves_original_all_variants_tags_arrays_and_exact_hook_result() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for (value, expected_tag, expected_fields) in [
            (Choice::Unit, 7, vec![]),
            (Choice::Tuple(255, [1, 2, 3, 4]), 19, vec![(19, 0), (19, 1)]),
            (
                Choice::Named {
                    bytes: vec![5, 6, 7],
                    value: 255,
                },
                2,
                vec![(2, 0), (2, 1)],
            ),
        ] {
            let bytes = bare(&value, flags);
            assert_eq!(
                u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                expected_tag
            );
            if expected_tag == 19 {
                // Independent literal geometry of the existing enum serializer.
                // A generic element-framed array cannot satisfy either vector.
                let mut expected = 19u32.to_le_bytes().to_vec();
                if flags == 0 {
                    expected.extend_from_slice(&1u64.to_le_bytes());
                    expected.push(255);
                    expected.extend_from_slice(&4u64.to_le_bytes());
                } else {
                    expected.extend_from_slice(&[1, 255, 4]);
                }
                expected.extend_from_slice(&[1, 2, 3, 4]);
                assert_eq!(bytes, expected);
                assert_eq!(bytes.len(), if flags == 0 { 25 } else { 11 });
            }
            HOOK_CALLS.set(0);
            let (prior, prior_used) =
                norito::core::decode_field_canonical::<OriginalChoice>(&bytes).unwrap();
            assert_eq!(HOOK_CALLS.get(), 1);
            HOOK_CALLS.set(0);
            let mut destination = Destination::default();
            let (prepared, used) = Choice::decode_value_fields(&bytes, &mut destination).unwrap();
            assert_eq!(HOOK_CALLS.get(), 1);
            assert_eq!((used, prior_used), (bytes.len(), bytes.len()));
            assert_eq!(destination.variant, Some(expected_tag));
            assert_eq!(destination.fields, expected_fields);
            assert_eq!(bare(&prepared, flags), bare(&prior, flags));
            HOOK_CALLS.set(0);
            let (owned, used) = Choice::decode_value_fields(&bytes, &mut OwnedFields).unwrap();
            assert_eq!(HOOK_CALLS.get(), 1);
            assert_eq!(owned, prepared);
            assert_eq!(used, bytes.len());
            let ordinary = Choice::decode_from_slice(&bytes).unwrap().0;
            assert_eq!(ordinary, prepared);
        }
    }
}

#[test]
fn validated_record_and_tuple_return_original_normalized_value_without_hook_duplication() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = bare(
            &Checked {
                value: 255,
                fixed: [1, 2, 3, 4],
            },
            flags,
        );
        HOOK_CALLS.set(0);
        let (prior, prior_used) =
            norito::core::decode_field_canonical::<OriginalChecked>(&bytes).unwrap();
        assert_eq!(HOOK_CALLS.get(), 1);
        HOOK_CALLS.set(0);
        let mut destination = Destination::default();
        let (value, used) = Checked::decode_value_fields(&bytes, &mut destination).unwrap();
        assert_eq!(HOOK_CALLS.get(), 1);
        assert_eq!(value.value, 9);
        assert_eq!((used, prior_used), (bytes.len(), bytes.len()));
        assert_eq!(bare(&value, flags), bare(&prior, flags));
        assert_eq!(destination.fields, [(0, 0), (0, 1)]);
        let bytes = bare(&CheckedTuple(255), flags);
        let (prior, used_prior) = OriginalTuple::decode_from_slice(&bytes).unwrap();
        HOOK_CALLS.set(0);
        let (value, used) = CheckedTuple::decode_from_slice(&bytes).unwrap();
        assert_eq!(HOOK_CALLS.get(), 1);
        assert_eq!(value.0, 9);
        assert_eq!(used, used_prior);
        assert_eq!(bare(&value, flags), bare(&prior, flags));
    }
}

#[test]
fn enum_truncation_unknown_tags_and_trailing_bytes_keep_original_cause_before_hook() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for value in values() {
            let bytes = bare(&value, flags);
            let mut mutations: Vec<_> = (0..bytes.len()).map(|end| bytes[..end].to_vec()).collect();
            let mut unknown = bytes.clone();
            unknown[..4].copy_from_slice(&u32::MAX.to_le_bytes());
            mutations.push(unknown);
            let mut trailing = bytes.clone();
            trailing.push(0xa5);
            mutations.push(trailing);
            for changed in mutations {
                HOOK_CALLS.set(0);
                let prior =
                    norito::core::decode_field_canonical::<OriginalChoice>(&changed).unwrap_err();
                assert_eq!(HOOK_CALLS.get(), 0);
                HOOK_CALLS.set(0);
                let mut destination = Destination::default();
                let actual =
                    codec(Choice::decode_value_fields(&changed, &mut destination).unwrap_err());
                assert_eq!(HOOK_CALLS.get(), 0);
                assert_eq!(actual.to_string(), prior.to_string());
                if changed.len() >= 4 && changed[..4] == u32::MAX.to_le_bytes() {
                    assert_eq!(destination.variant, None);
                    assert!(destination.fields.is_empty());
                }
            }
        }
        let bytes = bare(
            &Checked {
                value: 9,
                fixed: [1, 2, 3, 4],
            },
            flags,
        );
        for end in 0..bytes.len() {
            HOOK_CALLS.set(0);
            let prior =
                norito::core::decode_field_canonical::<OriginalChecked>(&bytes[..end]).unwrap_err();
            assert_eq!(HOOK_CALLS.get(), 0);
            let actual = codec(
                Checked::decode_value_fields(&bytes[..end], &mut Destination::default())
                    .unwrap_err(),
            );
            assert_eq!(HOOK_CALLS.get(), 0);
            assert_eq!(actual.to_string(), prior.to_string());
        }
    }
}

#[test]
fn original_hook_semantic_and_typed_resource_causes_survive_materialization() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for value in [0, 254] {
            let bytes = bare(&Choice::Tuple(value, [1, 2, 3, 4]), flags);
            HOOK_CALLS.set(0);
            let prior = norito::core::decode_field_canonical::<OriginalChoice>(&bytes).unwrap_err();
            assert_eq!(HOOK_CALLS.get(), 1);
            HOOK_CALLS.set(0);
            let actual = codec(
                Choice::decode_value_fields(&bytes, &mut Destination::default()).unwrap_err(),
            );
            assert_eq!(HOOK_CALLS.get(), 1);
            assert_eq!(actual.to_string(), prior.to_string());
            match (value, actual) {
                (0, norito::Error::Message(message)) => assert_eq!(message, "original zero value"),
                (254, norito::Error::TotalAllocationExceeded { attempted, limit }) => {
                    assert_eq!((attempted, limit), (4097, 4096))
                }
                (_, other) => panic!("lost original hook cause {other:?}"),
            }
        }
    }
}

#[test]
fn local_original_pool_refusal_remains_destination_owned_before_hook_and_same_source_retry() {
    let pool = AllocationBudget::new(1);
    let held = pool.try_reserve_bytes(1).unwrap();
    let original = pool.try_reserve_bytes(1).unwrap_err();
    let bytes = bare(&Choice::Tuple(9, [1, 2, 3, 4]), 0);
    let input = bytes.as_ptr();
    let _flags = DecodeFlagsGuard::enter(0);
    let mut destination = Destination {
        refusal: Some(original.clone()),
        ..Destination::default()
    };
    HOOK_CALLS.set(0);
    assert!(
        matches!(Choice::decode_value_fields(&bytes,&mut destination),Err(DecodeIntoError::Destination(error)) if error==original)
    );
    assert_eq!(HOOK_CALLS.get(), 0);
    assert_eq!(destination.variant, None);
    assert!(destination.fields.is_empty());
    drop(held);
    let granted = pool.try_reserve_bytes(1).unwrap();
    let (value, used) = Choice::decode_value_fields(&bytes, &mut destination).unwrap();
    assert_eq!(input, bytes.as_ptr());
    assert_eq!(used, bytes.len());
    assert_eq!(HOOK_CALLS.get(), 1);
    assert_eq!(bare(&value, 0), bytes);
    drop(granted);
    let original = pool.try_reserve_bytes(2).unwrap_err();
    destination.refusal = Some(original.clone());
    let bytes = bare(
        &Checked {
            value: 9,
            fixed: [1, 2, 3, 4],
        },
        0,
    );
    HOOK_CALLS.set(0);
    assert!(
        matches!(Checked::decode_value_fields(&bytes,&mut destination),Err(DecodeIntoError::Destination(error)) if error==original)
    );
    assert_eq!(HOOK_CALLS.get(), 0);
}

#[test]
fn materialized_enum_keeps_prefix_contract_and_full_frame_nominal_check() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for value in values() {
            let bytes = bare(&value, flags);
            let mut following = bytes.clone();
            following.extend_from_slice(&[0xa5, 0x5a]);
            let (actual, used) = Choice::decode_from_slice(&following).unwrap();
            let (prior, prior_used) = OriginalChoice::decode_from_slice(&following).unwrap();
            assert_eq!((used, prior_used), (bytes.len(), bytes.len()));
            assert_eq!(&following[used..], &[0xa5, 0x5a]);
            assert_eq!(bare(&actual, flags), bare(&prior, flags));
            assert!(matches!(
                norito::core::decode_field_canonical::<Choice>(&following),
                Err(norito::Error::LengthMismatch)
            ));
        }
    }
    let value = Choice::Named {
        bytes: vec![5, 6, 7],
        value: 9,
    };
    let frame = norito::encode_canonical(&value).unwrap();
    assert_eq!(norito::decode_canonical::<Choice>(&frame).unwrap(), value);
    let original = norito::decode_canonical::<OriginalChoice>(&frame).unwrap();
    assert_eq!(norito::encode_canonical(&original).unwrap(), frame);
    assert_eq!(norito::verify_exact_frame(&value, &frame).unwrap(), ());
    let changed = Choice::Named {
        bytes: vec![5, 6, 7],
        value: 255,
    };
    let frame = norito::encode_canonical(&changed).unwrap();
    assert!(norito::decode_canonical::<Choice>(&frame).is_err());
    assert!(norito::decode_canonical::<OriginalChoice>(&frame).is_err());
}
