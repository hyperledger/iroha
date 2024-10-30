//! Algorithm for generating trait bounds in `IntoSchema` derive
//!
//! Based on <https://github.com/paritytech/parity-scale-codec/blob/2c61d4ab70dfa157556430546441cd2deb5031f2/derive/src/trait_bounds.rs>

use std::iter;

use proc_macro2::Ident;
use syn::{
    parse_quote,
    visit::{self, Visit},
    Generics, Type, TypePath,
};

use crate::{IntoSchemaData, IntoSchemaField};

/// Visits the ast and checks if one of the given idents is found.
struct ContainIdents<'a> {
    result: bool,
    idents: &'a [Ident],
}

impl<'ast> Visit<'ast> for ContainIdents<'_> {
    fn visit_ident(&mut self, i: &'ast Ident) {
        if self.idents.iter().any(|id| id == i) {
            self.result = true;
        }
    }
}

/// Checks if the given type contains one of the given idents.
fn type_contain_idents(ty: &Type, idents: &[Ident]) -> bool {
    let mut visitor = ContainIdents {
        result: false,
        idents,
    };
    visitor.visit_type(ty);
    visitor.result
}

/// Visits the ast and checks if the a type path starts with the given ident.
struct TypePathStartsWithIdent<'a> {
    result: bool,
    ident: &'a Ident,
}

impl<'ast> Visit<'ast> for TypePathStartsWithIdent<'_> {
    fn visit_type_path(&mut self, i: &'ast TypePath) {
        if let Some(segment) = i.path.segments.first() {
            if &segment.ident == self.ident {
                self.result = true;
                return;
            }
        }

        visit::visit_type_path(self, i);
    }
}

/// Checks if the given type path or any containing type path starts with the given ident.
fn type_path_or_sub_starts_with_ident(ty: &TypePath, ident: &Ident) -> bool {
    let mut visitor = TypePathStartsWithIdent {
        result: false,
        ident,
    };
    visitor.visit_type_path(ty);
    visitor.result
}

/// Checks if the given type or any containing type path starts with the given ident.
fn type_or_sub_type_path_starts_with_ident(ty: &Type, ident: &Ident) -> bool {
    let mut visitor = TypePathStartsWithIdent {
        result: false,
        ident,
    };
    visitor.visit_type(ty);
    visitor.result
}

/// Visits the ast and collects all type paths that do not start or contain the given ident.
///
/// Returns `T`, `N`, `A` for `Vec<(Recursive<T, N>, A)>` with `Recursive` as ident.
struct FindTypePathsNotStartOrContainIdent<'a> {
    result: Vec<TypePath>,
    ident: &'a Ident,
}

impl<'ast> Visit<'ast> for FindTypePathsNotStartOrContainIdent<'_> {
    fn visit_type_path(&mut self, i: &'ast TypePath) {
        if type_path_or_sub_starts_with_ident(i, self.ident) {
            visit::visit_type_path(self, i);
        } else {
            self.result.push(i.clone());
        }
    }
}

/// Collects all type paths that do not start or contain the given ident in the given type.
///
/// Returns `T`, `N`, `A` for `Vec<(Recursive<T, N>, A)>` with `Recursive` as ident.
fn find_type_paths_not_start_or_contain_ident(ty: &Type, ident: &Ident) -> Vec<TypePath> {
    let mut visitor = FindTypePathsNotStartOrContainIdent {
        result: Vec::new(),
        ident,
    };
    visitor.visit_type(ty);
    visitor.result
}

#[allow(clippy::too_many_arguments)]
/// Add required trait bounds to all generic types.
///
/// This adds types of all the fields of the struct or enum that use a generic parameter to the where clause, with the following exceptions:
///
/// - If the field is marked as `#[codec(skip)]`, a different bound or no bound at all is added (based on the value of `codec_skip_bound` parameter).
/// - If the field mentions the input type itself, no bound is added. Heuristics are used, so this might not work in all cases.
/// - If the field is marked as `#[codec(compact)]`, the type `Compact<T>` is used instead of `T`.
pub fn add(
    input_ident: &Ident,
    generics: &mut Generics,
    data: &IntoSchemaData,
    // custom_trait_bound: Option<CustomTraitBound<N>>,
    codec_bound: &syn::Path,
    codec_skip_bound: Option<&syn::Path>,
    dumb_trait_bounds: bool,
    crate_path: &syn::Path,
) {
    let skip_type_params = Vec::<Ident>::new();
    // NOTE: not implementing custom trait bounds for now
    // can be implemented later if needed
    // = match custom_trait_bound {
    //     Some(CustomTraitBound::SpecifiedBounds { bounds, .. }) => {
    //         generics.make_where_clause().predicates.extend(bounds);
    //         return;
    //     }
    //     Some(CustomTraitBound::SkipTypeParams { type_names, .. }) => {
    //         type_names.into_iter().collect::<Vec<_>>()
    //     }
    //     None => Vec::new(),
    // };

    let ty_params = generics
        .type_params()
        .filter(|tp| skip_type_params.iter().all(|skip| skip != &tp.ident))
        .map(|tp| tp.ident.clone())
        .collect::<Vec<_>>();
    if ty_params.is_empty() {
        return;
    }

    let codec_types =
        get_types_to_add_trait_bound(input_ident, data, &ty_params, dumb_trait_bounds);

    let compact_types = collect_types(data, |t| t.codec_attrs.compact)
        .into_iter()
        // Only add a bound if the type uses a generic
        .filter(|ty| type_contain_idents(ty, &ty_params))
        .collect::<Vec<_>>();

    let skip_types = if codec_skip_bound.is_some() {
        let needs_default_bound = |f: &IntoSchemaField| f.codec_attrs.skip;
        collect_types(data, needs_default_bound)
            .into_iter()
            // Only add a bound if the type uses a generic
            .filter(|ty| type_contain_idents(ty, &ty_params))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    if !codec_types.is_empty() || !compact_types.is_empty() || !skip_types.is_empty() {
        let where_clause = generics.make_where_clause();

        for ty in codec_types {
            where_clause
                .predicates
                .push(parse_quote!(#ty : #codec_bound))
        }

        for ty in compact_types {
            where_clause
                .predicates
                .push(parse_quote!(#crate_path::Compact<#ty> : #codec_bound))
        }

        for ty in skip_types {
            where_clause
                .predicates
                .push(parse_quote!(#ty : #codec_skip_bound))
        }
    }
}

/// Returns all types that must be added to the where clause with the respective trait bound.
fn get_types_to_add_trait_bound(
    input_ident: &Ident,
    data: &IntoSchemaData,
    ty_params: &[Ident],
    dumb_trait_bound: bool,
) -> Vec<Type> {
    if dumb_trait_bound {
        ty_params.iter().map(|t| parse_quote!( #t )).collect()
    } else {
        let needs_codec_bound = |f: &IntoSchemaField| {
            !f.codec_attrs.compact
                // utils::get_encoded_as_type(f).is_none()
                && !f.codec_attrs.skip
        };
        collect_types(data, needs_codec_bound)
            .into_iter()
            // Only add a bound if the type uses a generic
            .filter(|ty| type_contain_idents(ty, ty_params))
            // If a struct contains itself as field type, we can not add this type into the where
            // clause. This is required to work a round the following compiler bug: https://github.com/rust-lang/rust/issues/47032
            .flat_map(|ty| {
                find_type_paths_not_start_or_contain_ident(&ty, input_ident)
                    .into_iter()
                    .map(Type::Path)
                    // Remove again types that do not contain any of our generic parameters
                    .filter(|ty| type_contain_idents(ty, ty_params))
                    // Add back the original type, as we don't want to loose it.
                    .chain(iter::once(ty))
            })
            // Remove all remaining types that start/contain the input ident to not have them in the
            // where clause.
            .filter(|ty| !type_or_sub_type_path_starts_with_ident(ty, input_ident))
            .collect()
    }
}

fn collect_types(data: &IntoSchemaData, type_filter: fn(&IntoSchemaField) -> bool) -> Vec<Type> {
    let types = match *data {
        IntoSchemaData::Struct(ref data) => data
            .fields
            .iter()
            .filter(|f| type_filter(f))
            .map(|f| f.ty.clone())
            .collect(),

        IntoSchemaData::Enum(ref variants) => variants
            .iter()
            .filter(|variant| !variant.codec_attrs.skip)
            .flat_map(|variant| {
                variant
                    .fields
                    .iter()
                    .filter(|f| type_filter(f))
                    .map(|f| f.ty.clone())
                    .collect::<Vec<_>>()
            })
            .collect(),
    };

    types
}
