use core::str::FromStr as _;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, Data, DataEnum, DeriveInput, Generics, Ident, Type};

use crate::{find_attr, is_extern, is_opaque, is_repr_attr};

pub fn derive_ffi_type(input: DeriveInput) -> TokenStream {
    let name = &input.ident;

    if is_extern(&input.attrs) {
        return derive_ffi_type_for_extern_item(name, input.generics);
    }
    if is_opaque(&input) {
        return derive_ffi_type_for_opaque_item(name, input.generics);
    }
    if is_transparent(&input) {
        return derive_ffi_type_for_transparent_item(&input);
    }

    match input.data {
        Data::Enum(item) => {
            let repr = find_attr(&input.attrs, "repr");

            if item.variants.is_empty() {
                abort!(name, "uninhabited enum's cannot be instantiated");
            }

            if is_fieldless_enum(&item) {
                derive_ffi_type_for_fieldless_enum(&input.ident, &item, &repr)
            } else {
                derive_ffi_type_for_data_carrying_enum(
                    &input.ident,
                    &input.attrs,
                    input.generics,
                    &item,
                )
            }
        }
        Data::Struct(item) => {
            if !is_non_owning_item(&input.attrs, item.fields.iter().map(|field| &field.ty)) {
                abort!(name, "if applicable, attach `#[ffi_type(non_owning)`")
            }

            derive_ffi_type_for_repr_c_struct(name, input.generics, &item)
        }
        Data::Union(item) => {
            if !is_non_owning_item(
                &input.attrs,
                item.fields.named.iter().map(|field| &field.ty),
            ) {
                abort!(name, "if applicable, attach `#[ffi_type(non_owning)`")
            }

            derive_ffi_type_for_union(name, input.generics, &item)
        }
    }
}

// TODO: The type is also non-owning if it implements `Copy`
fn is_non_owning_item<'itm>(
    attrs: &[syn::Attribute],
    fields: impl IntoIterator<Item = &'itm syn::Type>,
) -> bool {
    let non_owning: syn::Attribute = parse_quote! {#[ffi_type(non_owning)]};

    if attrs.iter().any(|attr| *attr == non_owning) {
        return true;
    }
    if fields.into_iter().all(|field_ty| !is_owning_type(field_ty)) {
        return true;
    }

    false
}

fn is_owning_type(type_: &syn::Type) -> bool {
    use syn::visit::Visit;
    struct PtrVistor(bool);

    impl Visit<'_> for PtrVistor {
        fn visit_type_path(&mut self, node: &syn::TypePath) {
            if let Some(last_seg) = node.path.segments.iter().last() {
                if &last_seg.ident == "Box" || &last_seg.ident == "NonNull" {
                    self.0 = true;
                }
            }
        }
        fn visit_type_ptr(&mut self, _: &syn::TypePtr) {
            self.0 = true;
        }
    }

    let mut ptr_visitor = PtrVistor(false);
    ptr_visitor.visit_type(type_);
    ptr_visitor.0
}

fn derive_ffi_type_for_extern_item(name: &Ident, mut generics: Generics) -> TokenStream {
    let ref_name = Ident::new(&format!("{}Ref", name), proc_macro2::Span::call_site());

    let lifetime = quote!('__iroha_ffi_itm);
    let (impl_generics, ty_generics, where_clause) =
        split_for_impl_with_type_params(&mut generics, &[]);

    quote! {
        impl<#lifetime, #impl_generics> iroha_ffi::ir::Transmute for &#lifetime #name #ty_generics #where_clause {
            type Target = *mut iroha_ffi::Extern;

            unsafe fn is_valid(source: Self::ReprC) -> bool {
                source.as_mut().is_some()
            }
        }

        impl<#impl_generics> iroha_ffi::ir::Ir for #name #ty_generics #where_clause {
            // NOTE: It's ok to get null pointer, dereferencing opaque pointer is UB anyhow
            type Type = iroha_ffi::ir::Robust<Self>;
        }
        impl<#impl_generics> iroha_ffi::ir::Ir for #ref_name #ty_generics #where_clause {
            type Type = iroha_ffi::ir::Transparent<Self>;
        }
    }
}

fn derive_ffi_type_for_opaque_item(name: &Ident, mut generics: Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) =
        split_for_impl_with_type_params(&mut generics, &[]);

    quote! {
        impl<#impl_generics> iroha_ffi::option::Niche for #name #ty_generics #where_clause {
            const NICHE_VALUE: Self::ReprC = core::ptr::null_mut();
        }

        unsafe impl<#impl_generics> iroha_ffi::ir::Transmute for #name #ty_generics #where_clause {
            type Target = Self;

            unsafe fn is_valid(source: &Self::Target) -> bool {
                true
            }
        }

        impl<#impl_generics> iroha_ffi::ir::Ir for #name #ty_generics #where_clause {
            type Type = iroha_ffi::ir::Opaque<Self>;
        }
    }
}

fn derive_ffi_type_for_transparent_item(input: &syn::DeriveInput) -> TokenStream {
    let name = &input.ident;

    // TODO: We don't check to find which field is not a ZST.
    // It is just assumed that it is the first field
    let inner = match &input.data {
        Data::Enum(item) => item
            .variants
            .iter()
            .next()
            .and_then(|variant| variant.fields.iter().next().map(|field| &field.ty))
            .expect_or_abort(
                "transparent `enum` must have at least one variant with at least one field",
            ),
        Data::Struct(item) => item
            .fields
            .iter()
            .next()
            .map(|field| &field.ty)
            .expect_or_abort("transparent struct must have at least one field"),
        Data::Union(item) => item
            .fields
            .named
            .iter()
            .next()
            .map(|field| &field.ty)
            .expect_or_abort("transparent union must have at least one field"),
    };

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    quote! {
        unsafe impl #impl_generics iroha_ffi::ir::Transmute for #name #ty_generics #where_clause {
            type Target = #inner;

            // FIXME: We should force the transparent type to have `from_inner` and derive implementation
            // only if requested specifically by the user (via macro attribute). The reason for this is
            // that even though two types are equal on the byte level, they may have different semantics
            // that cannot be proven when deriving `from_inner` (e.g. `NonZeroU8` is a wrapper for `u8`)
            // Deriving implementation of this method cannot be guaranteed to always return true
            unsafe fn is_valid(inner: &Self::Target) -> bool {
                true
            }
        }

        impl #impl_generics iroha_ffi::ir::Ir for #name #ty_generics #where_clause {
            type Type = iroha_ffi::ir::Transparent<Self>;
        }
    }
}

fn derive_ffi_type_for_repr_c_struct(
    name: &Ident,
    mut generics: Generics,
    struct_: &syn::DataStruct,
) -> TokenStream {
    let mut repr_c_where_clause = generics.make_where_clause().clone();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    struct_
        .fields
        .iter()
        .map(|field| &field.ty)
        .map(|ty| parse_quote! {#ty: iroha_ffi::ReprC})
        .for_each(|predicate| repr_c_where_clause.predicates.push(predicate));

    quote! {
        unsafe impl #impl_generics iroha_ffi::ReprC for #name #ty_generics #repr_c_where_clause {}

        unsafe impl #impl_generics iroha_ffi::ir::Transmute for #name #ty_generics #where_clause {
            type Target = Self;

            unsafe fn is_valid(source: &Self) -> bool {
                true
            }
        }
        impl #impl_generics iroha_ffi::ir::Ir for #name #ty_generics #where_clause {
            type Type = iroha_ffi::ir::Robust<Self>;
        }
    }
}

fn derive_ffi_type_for_fieldless_enum(
    enum_name: &Ident,
    enum_: &DataEnum,
    repr: &[syn::NestedMeta],
) -> TokenStream {
    if enum_.variants.len() == 1 {
        abort!(enum_name, "one-variant enums have representation of ()");
    }

    let ffi_type = enum_size(enum_name, repr);
    let (discriminants, discriminant_decls) = gen_discriminants(enum_name, enum_, &ffi_type);

    quote! {
        impl iroha_ffi::option::Niche for #enum_name {
            const NICHE_VALUE: Self::ReprC = Self::ReprC::MAX;
        }

        unsafe impl iroha_ffi::ir::Transmute for #enum_name {
            type Target = #ffi_type;

            unsafe fn is_valid(inner: &#ffi_type) -> bool {
                #(#discriminant_decls)*

                match *inner {
                    #( | #discriminants )* => true,
                    _ => false,
                }
            }
        }
        impl iroha_ffi::ir::Ir for #enum_name {
            type Type = iroha_ffi::ir::Transparent<Self>;
        }
    }
}

#[allow(clippy::too_many_lines)]
fn derive_ffi_type_for_data_carrying_enum(
    enum_name: &Ident,
    attrs: &[syn::Attribute],
    mut generics: Generics,
    enum_: &DataEnum,
) -> TokenStream {
    let (repr_c_enum_name, repr_c_enum) =
        gen_data_carrying_repr_c_enum(enum_name, &mut generics, enum_);
    let mut non_local_where_clause = generics.make_where_clause().clone();

    let lifetime = quote! {'__iroha_ffi_itm};
    let (impl_generics, ty_generics, where_clause) =
        split_for_impl_with_type_params(&mut generics, &[]);

    let variant_rust_stores = enum_
        .variants
        .iter()
        .map(|variant| {
            variant_mapper(
                variant,
                || quote! { () },
                |field| {
                    let ty = &field.ty;
                    quote! { <#ty as iroha_ffi::FfiConvert<#lifetime, <#ty as iroha_ffi::FfiType>::ReprC>>::RustStore }
                },
            )
        })
        .collect::<Vec<_>>();

    let variant_ffi_stores = enum_
        .variants
        .iter()
        .map(|variant| {
            variant_mapper(
                variant,
                || quote! { () },
                |field| {
                    let ty = &field.ty;
                    quote! { <#ty as iroha_ffi::FfiConvert<#lifetime, <#ty as iroha_ffi::FfiType>::ReprC>>::FfiStore }
                },
            )
        })
        .collect::<Vec<_>>();

    #[allow(clippy::expect_used)]
    let variants_into_ffi = enum_.variants.iter().enumerate().map(|(i, variant)| {
        let idx = TokenStream::from_str(&format!("{i}")).expect("Valid");
        let payload_name = gen_repr_c_enum_payload_name(enum_name);
        let variant_name = &variant.ident;

        variant_mapper(
            variant,
            || {
                quote! { Self::#variant_name => #repr_c_enum_name {
                    tag: #idx, payload: #payload_name {#variant_name: ()}
                }}
            },
            |_| {
                quote! {
                    Self::#variant_name(payload) => {
                        let payload = #payload_name {
                            #variant_name: core::mem::ManuallyDrop::new(
                                iroha_ffi::FfiConvert::into_ffi(payload, &mut store.#idx)
                            )
                        };

                        #repr_c_enum_name { tag: #idx, payload }
                    }
                }
            },
        )
    });

    #[allow(clippy::expect_used)]
    let variants_try_from_ffi = enum_.variants.iter().enumerate().map(|(i, variant)| {
        let idx = TokenStream::from_str(&format!("{i}")).expect("Valid");
        let variant_name = &variant.ident;

        variant_mapper(
            variant,
            || quote! { #idx => Ok(Self::#variant_name) },
            |_| {
                quote! {
                    #idx => {
                        let payload = core::mem::ManuallyDrop::into_inner(
                            source.payload.#variant_name
                        );

                        iroha_ffi::FfiConvert::try_from_ffi(payload, &mut store.#idx).map(Self::#variant_name)
                    }
                }
            },
        )
    });

    // TODO: Tuples don't support impl of `Default` for arity > 12 currently.
    // Once this limitation is lifted `Option<tuple>` will not be necessary
    let (rust_store, ffi_store, rust_store_conversion, ffi_store_conversion) =
        if enum_.variants.len() > 12 {
            (
                quote! { Option<(#( #variant_rust_stores, )*)> },
                quote! { Option<(#( #variant_ffi_stores, )*)> },
                quote! { let store = store.insert((#( #variant_rust_stores::default(), )*)); },
                quote! { let store = store.insert((#( #variant_ffi_stores::default(), )*)); },
            )
        } else {
            (
                quote! { (#( #variant_rust_stores, )*) },
                quote! { (#( #variant_ffi_stores, )*) },
                quote! {},
                quote! {},
            )
        };

    let non_locality = if is_non_local(attrs) {
        enum_
            .variants
            .iter()
            .filter_map(|variant| match &variant.fields {
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                    Some(&unnamed[0].ty)
                }
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) => {
                    abort!(unnamed, "Only 1-sized variants are supported")
                }
                syn::Fields::Named(syn::FieldsNamed { named, .. }) => {
                    abort!(named, "Named variants are not supported")
                }
                syn::Fields::Unit => None,
            })
            .map(|ty| parse_quote! {<#ty as iroha_ffi::ir::Ir>::Type: iroha_ffi::repr_c::NonLocal})
            .for_each(|predicate| non_local_where_clause.predicates.push(predicate));

        quote! {unsafe impl<#impl_generics> iroha_ffi::repr_c::NonLocal for #enum_name #ty_generics #non_local_where_clause {}}
    } else {
        quote! {}
    };

    quote! {
        #repr_c_enum

        // TODO: Enum can be transmutable if all variants are transmutable and the enum is `repr(C)`
        impl<#impl_generics> iroha_ffi::repr_c::NonTransmute for #enum_name #ty_generics #where_clause where Self: Clone {}

        // NOTE: Data-carrying enum cannot implement `ReprC` unless it is robust `repr(C)`
        impl<#impl_generics> iroha_ffi::ir::Ir for #enum_name #ty_generics #where_clause {
            type Type = Self;
        }
        impl<#impl_generics> iroha_ffi::ir::Ir for &#enum_name #ty_generics #where_clause {
            type Type = Self;
        }

        impl<#impl_generics> iroha_ffi::repr_c::CType for #enum_name #ty_generics #where_clause {
            type ReprC = #repr_c_enum_name #ty_generics;
        }
        impl<#lifetime, #impl_generics> iroha_ffi::repr_c::CTypeConvert<#lifetime, #repr_c_enum_name #ty_generics> for #enum_name #ty_generics #where_clause {
            type RustStore = #rust_store;
            type FfiStore = #ffi_store;

            fn into_repr_c(self, store: &mut Self::RustStore) -> #repr_c_enum_name #ty_generics {
                #ffi_store_conversion

                match self {
                    #(#variants_into_ffi,)*
                }
            }

            unsafe fn try_from_repr_c(source: #repr_c_enum_name #ty_generics, store: &mut Self::FfiStore) -> iroha_ffi::Result<Self> {
                #rust_store_conversion

                match source.tag {
                    #(#variants_try_from_ffi,)*
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation)
                }
            }
        }

        impl<#impl_generics> iroha_ffi::repr_c::COutPtr for #enum_name #ty_generics #where_clause {
            type OutPtr = *mut Self::ReprC;
        }

        #non_locality
    }
}

fn derive_ffi_type_for_union(
    name: &Ident,
    mut generics: Generics,
    union_: &syn::DataUnion,
) -> TokenStream {
    let mut repr_c_where_clause = generics.make_where_clause().clone();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    union_
        .fields
        .named
        .iter()
        .map(|field| &field.ty)
        .map(|ty| parse_quote! {#ty: iroha_ffi::ReprC})
        .for_each(|predicate| repr_c_where_clause.predicates.push(predicate));

    quote! {
        unsafe impl #impl_generics iroha_ffi::ReprC for #name #ty_generics #repr_c_where_clause {}

        unsafe impl #impl_generics iroha_ffi::ir::Transmute for #name #ty_generics #where_clause {
            type Target = Self;

            unsafe fn is_valid(source: &Self) -> bool {
                true
            }
        }
        impl #impl_generics iroha_ffi::ir::Ir for #name #ty_generics #where_clause {
            type Type = iroha_ffi::ir::Robust<Self>;
        }
    }
}

fn gen_data_carrying_repr_c_enum(
    enum_name: &Ident,
    generics: &mut Generics,
    enum_: &DataEnum,
) -> (Ident, TokenStream) {
    let (payload_name, payload) = gen_data_carrying_enum_payload(enum_name, generics, enum_);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let doc = format!(" [`ReprC`] equivalent of [`{}`]", enum_name);
    let enum_tag_type = gen_enum_tag_type(enum_name, enum_);
    let repr_c_enum_name = gen_repr_c_enum_name(enum_name);

    let repr_c_enum = quote! {
        #payload

        #[repr(C)]
        #[doc = #doc]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct #repr_c_enum_name #impl_generics #where_clause {
            tag: #enum_tag_type, payload: #payload_name #ty_generics,
        }

        impl #impl_generics Copy for #repr_c_enum_name #ty_generics where #payload_name #ty_generics: Copy {}
        unsafe impl #impl_generics iroha_ffi::ReprC for #repr_c_enum_name #ty_generics #where_clause {}
    };

    (repr_c_enum_name, repr_c_enum)
}

fn gen_data_carrying_enum_payload(
    enum_name: &Ident,
    generics: &mut Generics,
    enum_: &DataEnum,
) -> (Ident, TokenStream) {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let field_names = enum_.variants.iter().map(|variant| &variant.ident);
    let payload_name = gen_repr_c_enum_payload_name(enum_name);
    let doc = format!(" [`ReprC`] equivalent of [`{}`]", enum_name);

    let field_tys = enum_
        .variants
        .iter()
        .map(|variant| {
            variant_mapper(
                variant,
                || quote! {()},
                |field| {
                    let field_ty = &field.ty;
                    quote! {core::mem::ManuallyDrop<<#field_ty as iroha_ffi::FfiType>::ReprC>}
                },
            )
        })
        .collect::<Vec<_>>();

    let payload = quote! {
        #[repr(C)]
        #[doc = #doc]
        #[derive(Clone)]
        #[allow(non_snake_case, non_camel_case_types)]
        pub union #payload_name #impl_generics #where_clause {
            #(#field_names: #field_tys),*
        }

        impl #impl_generics Copy for #payload_name #ty_generics where #( #field_tys: Copy ),* {}
        unsafe impl #impl_generics iroha_ffi::ReprC for #payload_name #ty_generics #where_clause {}
    };

    (payload_name, payload)
}

fn gen_discriminants(
    enum_name: &Ident,
    enum_: &DataEnum,
    tag_type: &Type,
) -> (Vec<Ident>, Vec<TokenStream>) {
    let variant_names: Vec<_> = enum_.variants.iter().map(|v| &v.ident).collect();
    let discriminant_values = variant_discriminants(enum_);

    variant_names.iter().zip(discriminant_values.iter()).fold(
        <(Vec<_>, Vec<_>)>::default(),
        |mut acc, (variant_name, discriminant_value)| {
            let discriminant_name = Ident::new(
                &format!("{}__{}", enum_name, variant_name).to_uppercase(),
                proc_macro2::Span::call_site(),
            );

            acc.1.push(quote! {
                const #discriminant_name: #tag_type = #discriminant_value;
            });
            acc.0.push(discriminant_name);

            acc
        },
    )
}

fn variant_discriminants(enum_: &DataEnum) -> Vec<syn::Expr> {
    let mut curr_discriminant: syn::Expr = parse_quote! {0};

    enum_.variants.iter().fold(Vec::new(), |mut acc, variant| {
        let discriminant = variant.discriminant.as_ref().map_or_else(
            || curr_discriminant.clone(),
            |discriminant| discriminant.1.clone(),
        );

        acc.push(discriminant.clone());
        curr_discriminant = parse_quote! {
            1 + #discriminant
        };

        acc
    })
}

fn variant_mapper<F0: FnOnce() -> TokenStream, F1: FnOnce(&syn::Field) -> TokenStream>(
    variant: &syn::Variant,
    unit_mapper: F0,
    field_mapper: F1,
) -> TokenStream {
    match &variant.fields {
        syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
            field_mapper(&unnamed[0])
        }
        syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) => {
            abort!(unnamed, "Only 1-sized variants are supported")
        }
        syn::Fields::Named(syn::FieldsNamed { named, .. }) => {
            abort!(named, "Named variants are not supported")
        }
        syn::Fields::Unit => unit_mapper(),
    }
}

fn gen_repr_c_enum_name(enum_name: &Ident) -> Ident {
    Ident::new(
        &format!("__iroha_ffi__ReprC{}", enum_name),
        proc_macro2::Span::call_site(),
    )
}

fn gen_repr_c_enum_payload_name(enum_name: &Ident) -> Ident {
    Ident::new(
        &format!("__iroha_ffi__{}Payload", enum_name),
        proc_macro2::Span::call_site(),
    )
}

fn is_transparent(input: &DeriveInput) -> bool {
    let repr = &find_attr(&input.attrs, "repr");
    is_repr_attr(repr, "transparent")
}

// TODO: `local` is a temporary workaround for https://github.com/rust-lang/rust/issues/48214
// because some derived types cannot derive `NonLocal` othwerise
fn is_non_local(attrs: &[syn::Attribute]) -> bool {
    let local_attr = parse_quote! {#[ffi_type(local)]};
    attrs.iter().all(|a| *a != local_attr)
}

fn is_fieldless_enum(item: &DataEnum) -> bool {
    item.variants
        .iter()
        .all(|variant| matches!(variant.fields, syn::Fields::Unit))
}

fn enum_size(enum_name: &Ident, repr: &[syn::NestedMeta]) -> Type {
    if is_repr_attr(repr, "u8") {
        parse_quote! {u8}
    } else if is_repr_attr(repr, "i8") {
        parse_quote! {i8}
    } else if is_repr_attr(repr, "u16") {
        parse_quote! {u16}
    } else if is_repr_attr(repr, "i16") {
        parse_quote! {i16}
    } else if is_repr_attr(repr, "u32") {
        parse_quote! {u32}
    } else if is_repr_attr(repr, "i32") {
        parse_quote! {i32}
    } else {
        abort!(enum_name, "Enum representation not supported")
    }
}

fn gen_enum_tag_type(enum_name: &Ident, enum_: &DataEnum) -> TokenStream {
    const U8_MAX: usize = u8::MAX as usize;
    const U16_MAX: usize = u16::MAX as usize;
    const U32_MAX: usize = u32::MAX as usize;

    // NOTE: Arms are matched in the order of declaration
    #[allow(clippy::match_overlapping_arm)]
    match enum_.variants.len() {
        0..=U8_MAX => quote! {u8},
        0..=U16_MAX => quote! {u16},
        0..=U32_MAX => quote! {u32},
        _ => abort!(enum_name, "Too many variants"),
    }
}

fn split_for_impl_with_type_params<'generics>(
    generics: &'generics mut Generics,
    type_params: &'generics [syn::TypeParam],
) -> (
    syn::punctuated::Punctuated<syn::GenericParam, syn::Token![,]>,
    syn::TypeGenerics<'generics>,
    Option<&'generics syn::WhereClause>,
) {
    let (_, ty_generics, where_clause) = generics.split_for_impl();

    let mut impl_generics = generics.params.clone();
    impl_generics.extend(type_params.iter().cloned().map(syn::GenericParam::Type));

    (impl_generics, ty_generics, where_clause)
}
