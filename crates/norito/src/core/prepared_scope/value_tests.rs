//! Canonical value roots share ordinary framing and retain original refusal custody.
use super::*;

#[derive(
    Debug, PartialEq, crate::NoritoSerialize, crate::NoritoDeserialize, crate::NoritoSchema,
)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "prepared.value.root")]
enum Value {
    #[codec(index = 7)]
    Unit,
    #[codec(index = 19)]
    Pair(u64, [u8; 4]),
}
#[derive(
    Debug, PartialEq, crate::NoritoSerialize, crate::NoritoDeserialize, crate::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(name = "prepared.value.root")]
enum OriginalValue {
    #[codec(index = 7)]
    Unit,
    #[codec(index = 19)]
    Pair(u64, [u8; 4]),
}
#[derive(Debug, thiserror::Error)]
enum Refusal {
    #[error("selected variant is outside this destination")]
    Variant,
    #[error(transparent)]
    Capacity(iroha_allocation::AllocationRefusal),
}
#[derive(Default)]
struct Destination {
    variant: Option<u32>,
    fields: usize,
    restores: usize,
    resets: usize,
    restored: Option<Value>,
    deny_pair: bool,
    change_scalar: bool,
    charge_work: bool,
    refusal: Option<iroha_allocation::AllocationRefusal>,
}
impl FieldDestination for Destination {
    type Error = Refusal;
}
impl EnumFieldDestination for Destination {
    fn begin_variant(&mut self, variant: u32) -> Result<(), Self::Error> {
        if let Some(original) = self.refusal.take() {
            return Err(Refusal::Capacity(original));
        }
        if self.deny_pair && variant == 19 {
            return Err(Refusal::Variant);
        }
        self.variant = Some(variant);
        Ok(())
    }
}
impl DecodeVariantField<19, 0, u64> for Destination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, u64>,
    ) -> Result<u64, DecodeIntoError<Self::Error>> {
        self.fields += 1;
        let value = field.with_payload(|bytes| {
            if self.charge_work {
                reserve_decode_allocation(1)?;
            }
            let (value, used) = <u64 as DecodeFromSlice>::decode_from_slice(bytes)?;
            validate_decode_consumption(bytes, used)?;
            Ok(value)
        })?;
        Ok(value + u64::from(self.change_scalar))
    }
    fn restore_variant_field(&mut self, _value: u64) {}
}
impl DecodeVariantField<19, 1, [u8; 4]> for Destination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, [u8; 4]>,
    ) -> Result<[u8; 4], DecodeIntoError<Self::Error>> {
        self.fields += 1;
        field.with_payload(|bytes| {
            if self.charge_work {
                reserve_decode_allocation(1)?;
            }
            bytes.try_into().map_err(|_| Error::LengthMismatch.into())
        })
    }
    fn restore_variant_field(&mut self, _value: [u8; 4]) {}
}
impl DecodeValueDestination<Value> for Destination {
    fn restore_value(&mut self, value: Value) {
        self.restores += 1;
        self.restored = Some(value);
    }
}
impl PreparedValueDestination<Value> for Destination {
    fn reset(&mut self) {
        self.resets += 1;
        self.variant = None;
        // Returned storage is deliberately retained across resets and retry.
    }
}
fn limits() -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128)
}
fn prepared() -> (AllocationBudget, PreparedDecodeWorkspace) {
    let pool = AllocationBudget::new(1024 * 1024);
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    (pool, workspace)
}
fn reframe(bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut header = Header::read(&mut std::io::Cursor::new(bytes)).unwrap();
    header.length = u64::try_from(payload.len()).unwrap();
    header.checksum = crc64(payload);
    let mut frame = Vec::new();
    header.write(&mut frame).unwrap();
    frame.resize(Header::SIZE + payload_alignment_padding_for::<Value>(), 0);
    frame.extend_from_slice(payload);
    frame
}
#[test]
fn canonical_value_root_matches_original_enum_bytes_and_never_constructs_refused_children() {
    let (_pool, mut workspace) = prepared();
    let mut destination = Destination::default();
    for (value, original) in [
        (Value::Unit, OriginalValue::Unit),
        (
            Value::Pair(9, [1, 2, 3, 4]),
            OriginalValue::Pair(9, [1, 2, 3, 4]),
        ),
    ] {
        let bytes = crate::encode_canonical(&value).unwrap();
        assert_eq!(bytes, crate::encode_canonical(&original).unwrap());
        assert_eq!(
            crate::decode_canonical::<OriginalValue>(&bytes).unwrap(),
            original
        );
        assert_eq!(
            workspace
                .decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
                .unwrap(),
            value
        );
    }
    let bytes = crate::encode_canonical(&Value::Pair(9, [1, 2, 3, 4])).unwrap();
    let fields = destination.fields;
    destination.deny_pair = true;
    assert!(matches!(
        workspace.decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination),
        Err(PreparedDecodeError::Destination(Refusal::Variant))
    ));
    assert_eq!(destination.fields, fields);
    destination.deny_pair = false;
    let pool = AllocationBudget::new(1);
    let held = pool.try_reserve_bytes(1).unwrap();
    let refusal = pool.try_reserve_bytes(1).unwrap_err();
    let original = refusal.clone();
    destination.refusal = Some(refusal);
    let error = workspace
        .decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
        .unwrap_err();
    let PreparedDecodeError::Destination(Refusal::Capacity(retained)) = error else {
        panic!("original destination cause lost");
    };
    assert_eq!(retained, original);
    drop(held);
    let _retry_reservation = pool.try_reserve_bytes(1).unwrap();
    assert_eq!(destination.fields, fields);
    assert_eq!(
        workspace
            .decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
            .unwrap(),
        Value::Pair(9, [1, 2, 3, 4])
    );
}
#[test]
fn canonical_value_root_restores_actual_value_on_final_comparison_and_framing_failure() {
    let (_pool, mut workspace) = prepared();
    let value = Value::Pair(9, [1, 2, 3, 4]);
    let bytes = crate::encode_canonical(&value).unwrap();
    let mut destination = Destination {
        change_scalar: true,
        ..Default::default()
    };
    let error = workspace
        .decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
        .unwrap_err();
    let PreparedDecodeError::Codec(error) = error else {
        panic!("expected canonical mismatch");
    };
    assert!(matches!(error.into_error(), Error::NonCanonicalEncoding));
    assert_eq!(destination.restored, Some(Value::Pair(10, [1, 2, 3, 4])));
    assert_eq!(destination.restores, 1);
    assert_eq!(destination.variant, None);
    destination.change_scalar = false;
    assert_eq!(
        workspace
            .decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
            .unwrap(),
        value
    );
    // The retry did not discard the earlier restored destination storage.
    assert_eq!(destination.restored, Some(Value::Pair(10, [1, 2, 3, 4])));
    let payload = crate::checked_uncompressed_payload::<Value>(
        &bytes,
        &crate::checked_canonical_header(&bytes).unwrap(),
    )
    .unwrap();
    let mut trailing = payload.to_vec();
    trailing.push(0);
    let trailing = reframe(&bytes, &trailing);
    assert!(crate::decode_canonical::<OriginalValue>(&trailing).is_err());
    let before = destination.restores;
    assert!(
        workspace
            .decode_canonical_value_into::<Value, _>(&trailing, limits(), &mut destination)
            .is_err()
    );
    assert_eq!(destination.restores, before + 1);
    assert_eq!(destination.restored, Some(value));
    assert_eq!(
        workspace
            .decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
            .unwrap(),
        Value::Pair(9, [1, 2, 3, 4])
    );
}
#[test]
fn canonical_value_root_retains_inherited_work_and_original_attempt_owner() {
    let (_pool, mut workspace) = prepared();
    let bytes = crate::encode_canonical(&Value::Pair(9, [1, 2, 3, 4])).unwrap();
    let context = DecodeBudgetContext::new(DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        2,
        128,
    ));
    let mut destination = Destination {
        charge_work: true,
        ..Default::default()
    };
    context
        .with(|| {
            workspace.decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
        })
        .unwrap();
    let error = context
        .with(|| {
            workspace.decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
        })
        .unwrap_err();
    let PreparedDecodeError::Codec(error) = error else {
        panic!("original enclosing quota lost")
    };
    assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let original = error.into_local_refusal().unwrap();
    assert!(matches!(
        original.resource_error(),
        DecodeResourceError::TotalAllocationExceeded {
            attempted: 3,
            limit: 2
        }
    ));
    drop(context);
    assert_eq!(
        workspace
            .decode_canonical_value_into::<Value, _>(&bytes, limits(), &mut destination)
            .unwrap(),
        Value::Pair(9, [1, 2, 3, 4])
    );
    drop(original);
}

#[test]
fn canonical_value_root_rejects_corrupt_identity_and_unknown_tag_before_destination() {
    let (_pool, mut workspace) = prepared();
    let bytes = crate::encode_canonical(&Value::Pair(9, [1, 2, 3, 4])).unwrap();
    let header = crate::checked_canonical_header(&bytes).unwrap();
    let payload = crate::checked_uncompressed_payload::<Value>(&bytes, &header).unwrap();
    let mut unknown = payload.to_vec();
    unknown[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let unknown = reframe(&bytes, &unknown);
    let mut checksum = bytes.clone();
    *checksum.last_mut().unwrap() ^= 1;
    let mut schema = bytes.clone();
    schema[6] ^= 1;
    for frame in [checksum, schema, unknown] {
        let ordinary = crate::decode_canonical::<OriginalValue>(&frame).unwrap_err();
        let mut destination = Destination::default();
        let PreparedDecodeError::Codec(actual) = workspace
            .decode_canonical_value_into::<Value, _>(&frame, limits(), &mut destination)
            .unwrap_err()
        else {
            panic!("invalid wire became local destination refusal")
        };
        assert_eq!(actual.into_error().to_string(), ordinary.to_string());
        assert_eq!(destination.fields, 0);
        assert_eq!(destination.variant, None);
        assert_eq!(destination.restores, 0);
    }
}
