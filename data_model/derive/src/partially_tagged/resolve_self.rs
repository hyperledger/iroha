use syn2::visit_mut::VisitMut;

struct Visitor<'a> {
    self_ty: &'a syn2::Type,
}

impl VisitMut for Visitor<'_> {
    fn visit_type_mut(&mut self, ty: &mut syn2::Type) {
        match ty {
            syn2::Type::Path(path_ty)
                if path_ty.qself.is_none() && path_ty.path.is_ident("Self") =>
            {
                *ty = self.self_ty.clone();
            }
            _ => syn2::visit_mut::visit_type_mut(self, ty),
        }
    }
}

/// Transforms the [`resolving_ty`] by replacing `Self` with [`self_ty`].
///
/// This is required to be able to use `Self` in `PartiallyTaggedSerialize` and `PartiallyTaggedDeserialize`,
///     as they define an additional intermediate type during serialization/deserialization. Using `Self` there would refer to an incorrect type.
pub fn resolve_self(self_ty: &syn2::Type, mut resolving_ty: syn2::Type) -> syn2::Type {
    Visitor { self_ty }.visit_type_mut(&mut resolving_ty);
    resolving_ty
}

#[cfg(test)]
mod tests {
    use quote::ToTokens;
    use syn2::{parse_quote, Type};

    #[test]
    fn test_resolve_self() {
        let test_types = [
            parse_quote!(i32),
            parse_quote!(Self),
            parse_quote!(Vec<Self>),
            parse_quote!((Self, Self)),
            parse_quote!(<Self as Trait>::Type),
        ];
        let expected_types = [
            parse_quote!(i32),
            parse_quote!(()),
            parse_quote!(Vec<()>),
            parse_quote!(((), ())),
            parse_quote!(<() as Trait>::Type),
        ];
        let _: &Type = &test_types[0];
        let _: &Type = &expected_types[0];

        for (test_type, expected_type) in test_types.iter().zip(expected_types.iter()) {
            let resolved = super::resolve_self(&parse_quote!(()), test_type.clone());
            assert_eq!(
                resolved,
                *expected_type,
                "Failed to resolve `Self` in `{}`",
                test_type.to_token_stream()
            );
        }
    }
}
