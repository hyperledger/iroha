//! Borrowed canonical sequence projection for bounded contract declaration tables.

use norito::{NoritoSchema, SerializePayload, core::Encoder};

struct DeclarationTable<'a, T>(&'a [T]);

impl<T: SerializePayload> SerializePayload for DeclarationTable<'_, T> {
    fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<T, _>(encoder, self.0.iter())
    }
}

impl<T: NoritoSchema> NoritoSchema for DeclarationTable<'_, T> {
    fn nominal_name() -> String {
        Vec::<T>::nominal_name()
    }
}

/// Count the original non-byte declaration sequence without cloning its elements.
pub(super) fn canonical_len<T: SerializePayload + NoritoSchema>(
    declarations: &[T],
) -> Result<usize, norito::Error> {
    norito::canonical_frame_len(&DeclarationTable(declarations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smart_contract::manifest::{
        ContractEnumTypeDescriptorV1, ContractEnumVariantDescriptorV1,
    };

    #[test]
    fn borrowed_declaration_count_matches_native_vector_under_ambient_layouts() {
        let declarations = vec![ContractEnumTypeDescriptorV1 {
            identity: "local::Status".into(),
            variants: vec![ContractEnumVariantDescriptorV1 {
                name: "Open".into(),
                code: 7,
            }],
        }];
        let expected = norito::encode_canonical(&declarations).unwrap().len();
        for flags in [0, norito::core::default_encode_flags()] {
            let _guard = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(canonical_len(&declarations).unwrap(), expected);
        }
    }
}
