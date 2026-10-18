//! Actual-value destinations preserve the original consuming record hook.
use norito::core::{
    CanonicalField, DecodeField, DecodeIntoError, DecodeValueFields, FieldDestination,
};
use std::convert::Infallible;
#[derive(norito::NoritoSerialize, norito::DeserializePayload, norito::NoritoSchema)]
#[norito_schema(name = "ui.PreparedValidatedValue")]
#[norito(decode_fields, validate = "Self::normalize", decode_from_slice)]
struct Checked {
    value: u8,
}
impl Checked {
    fn normalize(mut self) -> Result<Self, norito::Error> {
        self.value = self.value.min(9);
        Ok(self)
    }
}
struct Destination;
impl FieldDestination for Destination {
    type Error = Infallible;
}
impl DecodeField<0, u8> for Destination {
    type Value = u8;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u8>,
    ) -> Result<u8, DecodeIntoError<Self::Error>> {
        Ok(field.decode_owned()?)
    }
}
fn main() {
    fn materializes<T: DecodeValueFields<Destination>>() {}
    materializes::<Checked>();
    let bytes = norito::encode_canonical(&Checked { value: 7 }).unwrap();
    assert_eq!(
        norito::decode_canonical::<Checked>(&bytes).unwrap().value,
        7
    );
}
