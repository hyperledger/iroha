use syn::{
    parse::{Parse, ParseStream},
    Attribute, Field, GenericArgument, Ident, PathArguments, Type,
};

use super::config;

/// Remove attributes with ident [`attr_ident`] from attributes
pub(crate) fn remove_attr(attrs: &mut Vec<Attribute>, attr_ident: &str) {
    attrs.retain(|attr| !attr.path.is_ident(attr_ident));
}

/// Return [`Vec`] of fields idents
pub(crate) fn extract_field_idents(fields: &[Field]) -> Vec<&Ident> {
    fields
        .iter()
        .map(|field| {
            #[allow(clippy::expect_used)]
            field
                .ident
                .as_ref()
                .expect("Should always be set for named structures")
        })
        .collect::<Vec<_>>()
}

/// Return [`Vec`] of fields types
pub(crate) fn extract_field_types(fields: &[Field]) -> Vec<&Type> {
    fields.iter().map(|field| &field.ty).collect::<Vec<_>>()
}

pub(crate) fn get_type_argument<'sl, 'tl>(
    s: &'sl str,
    ty: &'tl Type,
) -> Option<&'tl GenericArgument> {
    let path = if let Type::Path(r#type) = ty {
        r#type
    } else {
        return None;
    };
    let segments = &path.path.segments;
    if segments.len() != 1 || segments[0].ident != s {
        return None;
    }

    if let PathArguments::AngleBracketed(bracketed_arguments) = &segments[0].arguments {
        if bracketed_arguments.args.len() == 1 {
            return Some(&bracketed_arguments.args[0]);
        }
    }
    None
}

pub(crate) fn get_inner_type<'tl, 'sl>(outer_ty_ident: &'sl str, ty: &'tl Type) -> &'tl Type {
    #[allow(clippy::shadow_unrelated)]
    get_type_argument(outer_ty_ident, ty)
        .and_then(|ty| {
            if let GenericArgument::Type(r#type) = ty {
                Some(r#type)
            } else {
                None
            }
        })
        .unwrap_or(ty)
}

pub(crate) fn is_arc_rwlock(ty: &Type) -> bool {
    let dearced_ty = get_inner_type("Arc", ty);
    get_type_argument("RwLock", dearced_ty).is_some()
}

// TODO: make it const generic type once it will be stabilized
pub(crate) fn parse_const_ident(input: ParseStream, ident: &'static str) -> syn::Result<Ident> {
    let parse_ident: Ident = input.parse()?;
    if parse_ident == ident {
        Ok(parse_ident)
    } else {
        Err(syn::Error::new_spanned(parse_ident, "Unknown ident"))
    }
}

// TODO: complete doc
/// Receives all the attrs on fields, returns a vec ...
pub(crate) fn field_has_inner_attr(field_attrs: &[&[Attribute]]) -> Vec<bool> {
    field_attrs
        .iter()
        .map(|attrs| {
            attrs
                .iter()
                .any(|attr| attr.parse_args::<config::Inner>().is_ok())
        })
        .collect::<Vec<_>>()
}

/// Check if the provided type is of the form [`Option<..>`]
pub(crate) fn is_option_type(ty: &Type) -> bool {
    get_type_argument("Option", ty).is_some()
}
