//! The prepared canonical value root reuses controls without allocating.
use iroha_allocation::AllocationBudget;
use norito::core::{
    CanonicalField, DecodeFromSlice, DecodeIntoError, DecodeLimits, DecodeValueDestination,
    DecodeVariantField, EnumFieldDestination, FieldDestination, PreparedDecodeError,
    PreparedDecodeWorkspace, PreparedValueDestination,
};
#[derive(
    Debug, PartialEq, norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema,
)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "prepared.value.allocation")]
enum Value {
    Scalar(u8),
}
#[derive(Default)]
struct Destination {
    change: bool,
    restored: Option<Value>,
}
impl FieldDestination for Destination {
    type Error = std::convert::Infallible;
}
impl EnumFieldDestination for Destination {
    fn begin_variant(&mut self, _: u32) -> Result<(), Self::Error> {
        Ok(())
    }
}
impl DecodeVariantField<0, 0, u8> for Destination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, u8>,
    ) -> Result<u8, DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (value, used) = u8::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(value + u8::from(self.change))
        })
    }
    fn restore_variant_field(&mut self, _: u8) {}
}
impl DecodeValueDestination<Value> for Destination {
    fn restore_value(&mut self, value: Value) {
        self.restored = Some(value);
    }
}
impl PreparedValueDestination<Value> for Destination {
    fn reset(&mut self) {}
}
#[test]
fn canonical_value_root_success_restore_and_retry_make_no_allocator_calls() {
    let bytes = norito::encode_canonical(&Value::Scalar(9)).unwrap();
    let layouts = PreparedDecodeWorkspace::allocation_layouts();
    let pool = AllocationBudget::new(layouts.iter().map(std::alloc::Layout::size).sum());
    let mut reservation = pool.try_reserve_layouts(layouts).unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    let mut destination = Destination::default();
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128);
    pool.set_limit_bytes(0);
    let allocations = super::allocations_during(|| {
        for _ in 0..8 {
            assert_eq!(
                workspace
                    .decode_canonical_value_into::<Value, _>(&bytes, limits, &mut destination)
                    .unwrap(),
                Value::Scalar(9)
            );
            destination.change = true;
            let error = workspace
                .decode_canonical_value_into::<Value, _>(&bytes, limits, &mut destination)
                .unwrap_err();
            let PreparedDecodeError::Codec(error) = error else {
                panic!("canonical comparison cause lost")
            };
            assert!(matches!(
                error.into_error(),
                norito::Error::NonCanonicalEncoding
            ));
            assert_eq!(destination.restored, Some(Value::Scalar(10)));
            destination.change = false;
        }
    });
    assert_eq!(allocations, 0);
}
