//! Enum destinations materialize actual fields using exact variant/field coordinates.
use norito::core::{
    CanonicalField, DecodeIntoError, DecodeValueDestination, DecodeValueFields, DecodeVariantField,
    EnumFieldDestination, FieldDestination,
};
use std::convert::Infallible;
#[derive(norito::NoritoSerialize, norito::DeserializePayload, norito::NoritoSchema)]
#[norito_schema(name = "ui.PreparedEnumValue")]
#[norito(decode_fields, decode_from_slice)]
enum Choice {
    #[codec(index = 7)]
    Unit,
    #[codec(index = 19)]
    Tuple([u8; 4]),
    Named {
        value: u8,
    },
}
struct Destination;
impl FieldDestination for Destination {
    type Error = Infallible;
}
impl<T> DecodeValueDestination<T> for Destination {
    fn restore_value(&mut self, value: T) {
        drop(value);
    }
}
impl EnumFieldDestination for Destination {
    fn begin_variant(&mut self, _variant: u32) -> Result<(), Self::Error> {
        Ok(())
    }
}
impl<const V: u32, const I: usize, T> DecodeVariantField<V, I, T> for Destination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Self::Error>> {
        Ok(field.decode_owned()?)
    }

    fn restore_variant_field(&mut self, value: T) {
        drop(value);
    }
}
fn main() {
    fn materializes<T: DecodeValueFields<Destination>>() {}
    materializes::<Choice>();
    for value in [
        Choice::Unit,
        Choice::Tuple([1, 2, 3, 4]),
        Choice::Named { value: 9 },
    ] {
        let bytes = norito::encode_canonical(&value).unwrap();
        norito::decode_canonical::<Choice>(&bytes).unwrap();
    }
}
