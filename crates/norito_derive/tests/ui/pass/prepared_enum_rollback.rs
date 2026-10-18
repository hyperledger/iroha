//! Required rollback receives the original actual Box at its typed field coordinate.
use norito::core::{
    CanonicalField, DecodeIntoError, DecodeValueDestination, DecodeValueFields, DecodeVariantField,
    EnumFieldDestination, FieldDestination,
};
use std::convert::Infallible;
#[derive(Debug, norito::NoritoSerialize, norito::DeserializePayload, norito::NoritoSchema)]
#[norito_schema(name = "ui.EnumRollback")]
#[norito(decode_fields, decode_from_slice)]
enum Choice {
    #[codec(index = 19)]
    Pair(Box<[u8; 4]>, u8),
}
struct Destination {
    returned: Option<Box<[u8; 4]>>,
    whole: Option<Choice>,
}
impl FieldDestination for Destination {
    type Error = Infallible;
}
impl DecodeValueDestination<Choice> for Destination {
    fn restore_value(&mut self, value: Choice) {
        assert!(self.whole.is_none());
        self.whole = Some(value);
    }
}
impl EnumFieldDestination for Destination {
    fn begin_variant(&mut self, variant: u32) -> Result<(), Self::Error> {
        assert_eq!(variant, 19);
        Ok(())
    }
}
impl DecodeVariantField<19, 0, Box<[u8; 4]>> for Destination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, Box<[u8; 4]>>,
    ) -> Result<Box<[u8; 4]>, DecodeIntoError<Self::Error>> {
        Ok(field.decode_owned()?)
    }
    fn restore_variant_field(&mut self, value: Box<[u8; 4]>) {
        assert!(self.returned.is_none());
        self.returned = Some(value);
    }
}
impl DecodeVariantField<19, 1, u8> for Destination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, u8>,
    ) -> Result<u8, DecodeIntoError<Self::Error>> {
        Ok(field.decode_owned()?)
    }
    fn restore_variant_field(&mut self, value: u8) {
        let _ = value;
    }
}
fn main() {
    let value = Choice::Pair(Box::new([1, 2, 3, 4]), 9);
    let original = norito::codec::Encode::encode(&value);
    let mut bytes = original.clone();
    bytes.pop().unwrap();
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut destination = Destination {
        returned: None,
        whole: None,
    };
    assert!(Choice::decode_value_fields(&bytes, &mut destination).is_err());
    assert_eq!(destination.returned.as_deref(), Some(&[1, 2, 3, 4]));
    let mut trailing = original;
    trailing.push(0xa5);
    let mut destination = Destination {
        returned: None,
        whole: None,
    };
    assert!(Choice::decode_value_fields(&trailing, &mut destination).is_err());
    assert!(destination.returned.is_none());
    let Choice::Pair(first, tail) = destination.whole.as_ref().unwrap();
    assert_eq!(first.as_ref(), &[1, 2, 3, 4]);
    assert_eq!(*tail, 9);
}
