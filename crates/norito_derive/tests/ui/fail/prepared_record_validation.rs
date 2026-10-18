//! A span-only destination cannot implement whole-value validation materialization.
use norito::core::{
    CanonicalField, DecodeField, DecodeIntoError, DecodeValueFields, FieldDestination,
};
use std::convert::Infallible;
#[derive(norito::DeserializePayload)]
#[norito(decode_fields, validate = "Self::validate")]
struct Checked {
    value: u8,
}
impl Checked {
    fn validate(self) -> Result<Self, norito::Error> {
        Ok(self)
    }
}
struct Destination;
impl FieldDestination for Destination {
    type Error = Infallible;
}
impl DecodeField<0, u8> for Destination {
    type Value = ();
    fn decode_field(
        &mut self,
        _field: CanonicalField<'_, u8>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        Ok(())
    }
}
fn main() {
    fn requires_actual_value<T: DecodeValueFields<Destination>>() {}
    requires_actual_value::<Checked>();
}
