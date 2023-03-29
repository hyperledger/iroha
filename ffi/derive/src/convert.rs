use core::str::FromStr as _;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, visit::Visit, Data, DataEnum, DeriveInput, Generics, Ident, Type};

use crate::{find_attr, is_opaque, is_repr_attr, without_repr};

pub fn derive_ffi_type(mut input: DeriveInput) -> TokenStream {
    let name = &input.ident;

    if let Data::Enum(enum_) = &input.data {
        if enum_.variants.is_empty() {
            abort!(enum_.variants, "Uninhabited enums are not allowed in FFI");
        }
    }

    if is_opaque(&input) {
        return derive_ffi_type_for_opaque_item(name, &input.generics);
    }
    if is_transparent(&input) {
        return derive_ffi_type_for_transparent_item(&mut input);
    }

    match &input.data {
        Data::Enum(item) => {
            let repr = find_attr(&input.attrs, "repr");

            if is_fieldless_enum(item) {
                if item.variants.len() == 1 {
                    // NOTE: one-variant fieldless enums have representation of ()
                    return derive_ffi_type_for_opaque_item(name, &input.generics);
                }
                if without_repr(&repr) {
                    abort!(name, "Fieldless enum missing #[repr(int)]");
                }
                if let Some(variant) = item.variants.iter().find(|v| v.discriminant.is_some()) {
                    abort!(
                        variant,
                        "Fieldless enums with explicit discriminants are prohibited",
                    )
                }

                derive_ffi_type_for_fieldless_enum(&input.ident, item, &repr)
            } else {
                verify_is_non_owning(&input.data);
                let local = !is_non_local(&input.attrs);

                derive_ffi_type_for_data_carrying_enum(&input.ident, input.generics, item, local)
            }
        }
        Data::Struct(item) => {
            let ffi_type_impl = derive_ffi_type_for_repr_c(&input);

            let repr_c_impl = {
                let predicates = &mut input.generics.make_where_clause().predicates;
                let add_bound = |ty| predicates.push(parse_quote! {#ty: iroha_ffi::ReprC});

                match &item.fields {
                    syn::Fields::Named(fields) => fields
                        .named
                        .iter()
                        .map(|field| &field.ty)
                        .for_each(add_bound),
                    syn::Fields::Unnamed(fields) => fields
                        .unnamed
                        .iter()
                        .map(|field| &field.ty)
                        .for_each(add_bound),
                    syn::Fields::Unit => unreachable!("Unit struct cannot implement `ReprC`"),
                }

                derive_unsafe_repr_c(&input.ident, &input.generics)
            };

            quote! {
                #repr_c_impl
                #ffi_type_impl
            }
        }
        Data::Union(item) => {
            let ffi_type_impl = derive_ffi_type_for_repr_c(&input);

            let repr_c_impl = {
                let predicates = &mut input.generics.make_where_clause().predicates;
                let add_bound = |ty| predicates.push(parse_quote! {#ty: iroha_ffi::ReprC});

                item.fields
                    .named
                    .iter()
                    .map(|field| &field.ty)
                    .for_each(add_bound);

                derive_unsafe_repr_c(&input.ident, &input.generics)
            };

            quote! {
                #repr_c_impl
                #ffi_type_impl
            }
        }
    }
}

/// Before deriving this trait make sure that all invariants are upheld
fn derive_unsafe_repr_c(name: &Ident, generics: &Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        // SAFETY: Type is robust with #[repr(C)] attribute attached
        unsafe impl #impl_generics iroha_ffi::ReprC for #name #ty_generics #where_clause {}


    }
}

fn derive_ffi_type_for_opaque_item(name: &Ident, generics: &Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics iroha_ffi::ir::Ir for #name #ty_generics #where_clause {
            type Type = iroha_ffi::ir::Opaque;
        }

        // SAFETY: Opaque types are never dereferenced and therefore &mut T is considered to be transmutable
        unsafe impl #impl_generics iroha_ffi::ir::InfallibleTransmute for #name #ty_generics #where_clause {}

        impl #impl_generics iroha_ffi::option::Niche<'_> for #name #ty_generics #where_clause {
            const NICHE_VALUE: *mut Self = core::ptr::null_mut();
        }
    }
}

fn derive_ffi_type_for_transparent_item(input: &mut syn::DeriveInput) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let name = &input.ident;

    // TODO: We don't check to find which field is not a ZST.
    // It is just assumed that it is the first field
    let inner = match &input.data {
        Data::Enum(item) => {
            let first_variant = item
                .variants
                .iter()
                .next()
                .expect_or_abort("transparent enum must have at least one variant");

            if let Some(first_variant) = first_variant.fields.iter().next() {
                &first_variant.ty
            } else {
                // NOTE: one-variant fieldless enums have representation of ()
                return derive_ffi_type_for_opaque_item(name, &input.generics);
            }
        }
        Data::Struct(item) => {
            if let Some(first_field) = item.fields.iter().next() {
                &first_field.ty
            } else {
                // NOTE: Fieldless structs have representation of ()
                return derive_ffi_type_for_opaque_item(name, &input.generics);
            }
        }
        Data::Union(_) => unreachable!("https://github.com/rust-lang/rust/issues/60405"),
    };

    if is_robust(&input.attrs) {
        return quote! {
            iroha_ffi::ffi_type! {
                // SAFETY: User must make sure the type is robust
                unsafe impl #impl_generics Transparent for #name #ty_generics #where_clause {
                    type Target = #inner;
                }
            }
        };
    }

    quote! {}
}

fn derive_ffi_type_for_fieldless_enum(
    enum_name: &Ident,
    enum_: &DataEnum,
    repr: &[syn::NestedMeta],
) -> TokenStream {
    let ffi_type = enum_size(enum_name, repr);
    let (discriminants, discriminant_decls) = gen_discriminants(enum_name, enum_, &ffi_type);

    quote! {
        iroha_ffi::ffi_type! {
            unsafe impl Transparent for #enum_name {
                type Target = #ffi_type;

                validation_fn=unsafe {|target: &#ffi_type| {
                    #(#discriminant_decls)*

                    match *target {
                        #( | #discriminants )* => true,
                        _ => false,
                    }
                }},
                niche_value=<Self as iroha_ffi::FfiType>::ReprC::MAX
            }
        }

        impl iroha_ffi::WrapperTypeOf<#enum_name> for #ffi_type {
            type Type = #enum_name;
        }
    }
}

#[allow(clippy::too_many_lines)]
fn derive_ffi_type_for_data_carrying_enum(
    enum_name: &Ident,
    mut generics: Generics,
    enum_: &DataEnum,
    local: bool,
) -> TokenStream {
    let (repr_c_enum_name, repr_c_enum) =
        gen_data_carrying_repr_c_enum(enum_name, &mut generics, enum_);

    generics.make_where_clause();
    let lifetime = quote! {'__iroha_ffi_itm};
    let (impl_generics, ty_generics, where_clause) = split_for_impl(&generics);

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

    let non_locality = if local {
        quote! {}
    } else {
        let mut non_local_where_clause = where_clause.expect_or_abort("Defined").clone();

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
            .map(|ty| parse_quote! {#ty: iroha_ffi::repr_c::NonLocal<<#ty as iroha_ffi::ir::Ir>::Type>})
            .for_each(|predicate| non_local_where_clause.predicates.push(predicate));

        quote! {
            unsafe impl<#impl_generics> iroha_ffi::repr_c::NonLocal<Self> for #enum_name #ty_generics #non_local_where_clause {}

            impl<#impl_generics> iroha_ffi::repr_c::CWrapperType<Self> for #enum_name #ty_generics #non_local_where_clause {
                type InputType = Self;
                type ReturnType = Self;
            }
            impl<#impl_generics> iroha_ffi::repr_c::COutPtr<Self> for #enum_name #ty_generics #non_local_where_clause {
                type OutPtr = Self::ReprC;
            }
            impl<#impl_generics> iroha_ffi::repr_c::COutPtrWrite<Self> for #enum_name #ty_generics #non_local_where_clause {
                unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
                    iroha_ffi::repr_c::write_non_local::<_, Self>(self, out_ptr);
                }
            }
            impl<#impl_generics> iroha_ffi::repr_c::COutPtrRead<Self> for #enum_name #ty_generics #non_local_where_clause {
                unsafe fn try_read_out(out_ptr: Self::OutPtr) -> iroha_ffi::Result<Self> {
                    iroha_ffi::repr_c::read_non_local::<Self, Self>(out_ptr)
                }
            }
        }
    };

    quote! {
        #repr_c_enum

        // NOTE: Data-carrying enum cannot implement `ReprC` unless it is robust `repr(C)`
        impl<#impl_generics> iroha_ffi::ir::Ir for #enum_name #ty_generics #where_clause {
            type Type = Self;
        }

        impl<#impl_generics> iroha_ffi::repr_c::CType<Self> for #enum_name #ty_generics #where_clause {
            type ReprC = #repr_c_enum_name #ty_generics;
        }
        impl<#lifetime, #impl_generics> iroha_ffi::repr_c::CTypeConvert<#lifetime, Self, #repr_c_enum_name #ty_generics> for #enum_name #ty_generics #where_clause {
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

        // TODO: Enum can be transmutable if all variants are transmutable and the enum is `repr(C)`
        impl<#impl_generics> iroha_ffi::repr_c::Cloned for #enum_name #ty_generics #where_clause where Self: Clone {}

        #non_locality
    }
}

fn derive_ffi_type_for_repr_c(input: &DeriveInput) -> TokenStream {
    verify_is_non_owning(&input.data);
    assert_is_repr_c(&input.attrs);

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let name = &input.ident;

    quote! {
        iroha_ffi::ffi_type! {
            impl #impl_generics Robust for #name #ty_generics #where_clause {}
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
    let doc = format!(" [`ReprC`] equivalent of [`{enum_name}`]");
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
    let doc = format!(" [`ReprC`] equivalent of [`{enum_name}`]");

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
                &format!("{enum_name}__{variant_name}").to_uppercase(),
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

fn variant_discriminants(enum_: &DataEnum) -> Vec<proc_macro2::Literal> {
    enum_
        .variants
        .iter()
        .enumerate()
        .map(|(i, _)| proc_macro2::Literal::usize_unsuffixed(i))
        .collect()
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
        &format!("__iroha_ffi__ReprC{enum_name}"),
        proc_macro2::Span::call_site(),
    )
}

fn gen_repr_c_enum_payload_name(enum_name: &Ident) -> Ident {
    Ident::new(
        &format!("__iroha_ffi__{enum_name}Payload"),
        proc_macro2::Span::call_site(),
    )
}

fn is_transparent(input: &DeriveInput) -> bool {
    let repr = &find_attr(&input.attrs, "repr");
    is_repr_attr(repr, "transparent")
}

fn is_robust(attrs: &[syn::Attribute]) -> bool {
    let robust_attr = parse_quote! {#[ffi_type(unsafe {robust})]};
    attrs.iter().any(|a| *a == robust_attr)
}

// NOTE: Except for the raw pointers there should be no other type
// that is at the same time Robust and also transfers ownership
fn verify_is_non_owning(data: &syn::Data) {
    const RAW_POINTER_FOUND_MSG: &str = "Raw pointer found. If the pointer doesn't own the data, attach `#[ffi_type(unsafe {non_owning})` to the field. Otherwise, mark the entire type as opaque with `#[ffi_type(opaque)]`";

    struct PtrVistor;
    impl Visit<'_> for PtrVistor {
        fn visit_field(&mut self, node: &syn::Field) {
            let non_owning = parse_quote!(#[ffi_type(unsafe {non_owning})]);

            if !node.attrs.iter().any(|attr| *attr == non_owning) {
                syn::visit::visit_field(self, node);
            }
        }
        fn visit_type_ptr(&mut self, node: &syn::TypePtr) {
            abort!(node, RAW_POINTER_FOUND_MSG);
        }
    }

    let mut ptr_visitor = PtrVistor;
    ptr_visitor.visit_data(data);
}

fn is_non_local(attrs: &[syn::Attribute]) -> bool {
    let local = parse_quote! {#[ffi_type(local)]};
    !attrs.iter().any(|attr| *attr == local)
}

fn is_fieldless_enum(item: &DataEnum) -> bool {
    item.variants
        .iter()
        .all(|variant| matches!(variant.fields, syn::Fields::Unit))
}

fn assert_is_repr_c(attrs: &[syn::Attribute]) {
    let repr = find_attr(attrs, "repr");
    assert!(is_repr_attr(&repr, "C"));
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

fn split_for_impl(
    generics: &Generics,
) -> (
    syn::punctuated::Punctuated<syn::GenericParam, syn::Token![,]>,
    syn::TypeGenerics<'_>,
    Option<&syn::WhereClause>,
) {
    let impl_generics = generics.params.clone();
    let (_, ty_generics, where_clause) = generics.split_for_impl();
    (impl_generics, ty_generics, where_clause)
}
