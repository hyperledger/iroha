use core::str::FromStr as _;
use std::fmt::{Display, Formatter};

use darling::{
    ast::Style, util::SpannedValue, FromAttributes, FromDeriveInput, FromField, FromVariant,
};
use manyhow::{emit, error_message};
use proc_macro2::{Delimiter, Span, TokenStream};
use quote::quote;
use syn2::{
    parse::ParseStream, spanned::Spanned as _, visit::Visit as _, Attribute, Field, Ident, Meta,
};

use crate::{
    attr_parse::{
        derive::DeriveAttrs,
        doc::DocAttrs,
        getset::{GetSetFieldAttrs, GetSetStructAttrs},
        repr::{Repr, ReprKind, ReprPrimitive},
    },
    emitter::Emitter,
};

#[derive(Debug)]
enum FfiTypeToken {
    Opaque,
    UnsafeRobust,
    UnsafeNonOwning,
    Local,
}

impl Display for FfiTypeToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            FfiTypeToken::Opaque => "#[ffi_type(opaque)]",
            FfiTypeToken::UnsafeRobust => "#[ffi_type(unsafe {robust})]",
            FfiTypeToken::UnsafeNonOwning => "#[ffi_type(unsafe {non_owning})]",
            FfiTypeToken::Local => "#[ffi_type(local)]",
        };
        write!(f, "{}", text)
    }
}

#[derive(Debug)]
struct SpannedFfiTypeToken {
    span: Span,
    token: FfiTypeToken,
}

impl syn2::parse::Parse for SpannedFfiTypeToken {
    fn parse(input: ParseStream) -> syn2::Result<Self> {
        let (span, token) = input.step(|cursor| {
            let Some((token, after_token)) = cursor.ident() else {
                return Err(cursor.error("expected ffi type kind"))
            };

            let mut span = token.span();
            let token = token.to_string();
            match token.as_str() {
                "opaque" => Ok(((span, FfiTypeToken::Opaque), after_token)),
                "local" => Ok(((span, FfiTypeToken::Local), after_token)),
                "unsafe" => {
                    let Some((inside_of_group, group_span, after_group)) = after_token.group(Delimiter::Brace) else {
                        return Err(cursor.error("expected `{ ... }` after `unsafe`"))
                    };
                    span = span.join(group_span.span()).expect("Spans must be in the same file");

                    let Some((token, after_token)) = inside_of_group.ident() else {
                        return Err(cursor.error("expected ffi type kind"))
                    };
                    if !after_token.eof() {
                        return Err(cursor.error("`unsafe { ... }` should only contain one identifier inside"))
                    }

                    let token = token.to_string();
                    match token.as_str() {
                        "robust" => Ok(((span, FfiTypeToken::UnsafeRobust), after_group)),
                        "non_owning" => Ok(((span, FfiTypeToken::UnsafeNonOwning), after_group)),
                        other => Err(syn2::Error::new(token.span(), format!("unknown unsafe ffi type kind: {}", other))),
                    }
                }
                other => Err(syn2::Error::new(span, format!("unknown unsafe ffi type kind: {}", other))),
            }
        })?;

        Ok(Self { span, token })
    }
}

/// This represents an `#[ffi_type(...)]` attribute on a type
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum FfiTypeKindAttribute {
    Opaque,
    UnsafeRobust,
    Local,
}

impl syn2::parse::Parse for FfiTypeKindAttribute {
    fn parse(input: ParseStream) -> syn2::Result<Self> {
        input.call(SpannedFfiTypeToken::parse).and_then(|token| {
            Ok(match token.token {
                FfiTypeToken::Opaque => FfiTypeKindAttribute::Opaque,
                FfiTypeToken::UnsafeRobust => FfiTypeKindAttribute::UnsafeRobust,
                FfiTypeToken::Local => FfiTypeKindAttribute::Local,
                other => {
                    return Err(syn2::Error::new(
                        token.span,
                        format!("`{}` cannot be used on a type", other),
                    ))
                }
            })
        })
    }
}

/// This represents an `#[ffi_type(...)]` attribute on a field
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum FfiTypeKindFieldAttribute {
    UnsafeNonOwning,
}

impl syn2::parse::Parse for FfiTypeKindFieldAttribute {
    fn parse(input: ParseStream) -> syn2::Result<Self> {
        input.call(SpannedFfiTypeToken::parse).and_then(|token| {
            Ok(match token.token {
                FfiTypeToken::UnsafeNonOwning => FfiTypeKindFieldAttribute::UnsafeNonOwning,
                other => {
                    return Err(syn2::Error::new(
                        token.span,
                        format!("`{}` cannot be used on a field", other),
                    ))
                }
            })
        })
    }
}

fn parse_ffi_type_attr<T: syn2::parse::Parse>(attrs: &[Attribute]) -> darling::Result<Option<T>> {
    let mut accumulator = darling::error::Accumulator::default();

    // first, ensure there is only one "ffi_type" attribute (we don't support multiple)
    let ffi_type_attrs = attrs
        .iter()
        .filter(|a| a.path().is_ident("ffi_type"))
        .collect::<Vec<_>>();
    let attr = match *ffi_type_attrs.as_slice() {
        [] => {
            return accumulator.finish_with(None);
        }
        [attr] => attr,
        [attr, ref tail @ ..] => {
            // allow parsing to proceed further to collect more errors
            accumulator.push(
                darling::Error::custom("Only one #[ffi_type] attribute is allowed!").with_span(
                    &tail
                        .iter()
                        .map(syn2::spanned::Spanned::span)
                        .reduce(|a, b| a.join(b).unwrap())
                        .unwrap(),
                ),
            );
            attr
        }
    };

    let mut kind = None;

    match &attr.meta {
        Meta::Path(_) | Meta::NameValue(_) => accumulator.push(darling::Error::custom(
            "Expected #[ffi_type(...)] attribute to be a list",
        )),
        Meta::List(list) => {
            kind = accumulator.handle(syn2::parse2(list.tokens.clone()).map_err(Into::into));
        }
    }

    accumulator.finish_with(kind)
}

pub struct FfiTypeAttr {
    pub kind: Option<FfiTypeKindAttribute>,
}

impl FromAttributes for FfiTypeAttr {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        parse_ffi_type_attr(attrs).map(|kind| Self { kind })
    }
}

pub struct FfiTypeFieldAttr {
    kind: Option<FfiTypeKindFieldAttribute>,
}

impl FromAttributes for FfiTypeFieldAttr {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        parse_ffi_type_attr(attrs).map(|kind| Self { kind })
    }
}

pub type FfiTypeData = darling::ast::Data<SpannedValue<FfiTypeVariant>, FfiTypeField>;
pub type FfiTypeFields = darling::ast::Fields<FfiTypeField>;

pub struct FfiTypeInput {
    pub vis: syn2::Visibility,
    pub ident: syn2::Ident,
    pub generics: syn2::Generics,
    pub data: FfiTypeData,
    pub doc_attrs: DocAttrs,
    pub derive_attr: DeriveAttrs,
    pub repr_attr: Repr,
    pub ffi_type_attr: FfiTypeAttr,
    pub getset_attr: GetSetStructAttrs,
    pub span: Span,
    /// The original DeriveInput this structure was parsed from
    pub ast: syn2::DeriveInput,
}

impl FfiTypeInput {
    pub fn is_opaque(&self) -> bool {
        self.ffi_type_attr.kind == Some(FfiTypeKindAttribute::Opaque)
            || !self.data.is_enum() && self.repr_attr.kind.as_deref().is_none()
    }
}

impl darling::FromDeriveInput for FfiTypeInput {
    fn from_derive_input(input: &syn2::DeriveInput) -> darling::Result<Self> {
        let vis = input.vis.clone();
        let ident = input.ident.clone();
        let generics = input.generics.clone();
        let data = darling::ast::Data::try_from(&input.data)?;
        let doc_attrs = DocAttrs::from_attributes(&input.attrs)?;
        let derive_attr = DeriveAttrs::from_attributes(&input.attrs)?;
        let repr_attr = Repr::from_attributes(&input.attrs)?;
        let ffi_type_attr = FfiTypeAttr::from_attributes(&input.attrs)?;
        let getset_attr = GetSetStructAttrs::from_attributes(&input.attrs)?;
        let span = input.span();

        Ok(FfiTypeInput {
            vis,
            ident,
            generics,
            data,
            doc_attrs,
            derive_attr,
            repr_attr,
            ffi_type_attr,
            getset_attr,
            span,
            ast: input.clone(),
        })
    }
}

#[derive(FromVariant)]
pub struct FfiTypeVariant {
    pub ident: syn2::Ident,
    pub discriminant: Option<syn2::Expr>,
    pub fields: darling::ast::Fields<FfiTypeField>,
}

pub struct FfiTypeField {
    pub ident: Option<syn2::Ident>,
    pub ty: syn2::Type,
    pub doc_attrs: DocAttrs,
    pub ffi_type_attr: FfiTypeFieldAttr,
    pub getset_attr: GetSetFieldAttrs,
}

impl FromField for FfiTypeField {
    fn from_field(field: &Field) -> darling::Result<Self> {
        let ident = field.ident.clone();
        let ty = field.ty.clone();
        let doc_attrs = DocAttrs::from_attributes(&field.attrs)?;
        let ffi_type_attr = FfiTypeFieldAttr::from_attributes(&field.attrs)?;
        let getset_attr = GetSetFieldAttrs::from_attributes(&field.attrs)?;
        Ok(Self {
            ident,
            ty,
            doc_attrs,
            ffi_type_attr,
            getset_attr,
        })
    }
}

pub fn derive_ffi_type(emitter: &mut Emitter, input: &syn2::DeriveInput) -> TokenStream {
    let Some(mut input) = emitter.handle(FfiTypeInput::from_derive_input(input)) else {
        return quote!();
    };

    let name = &input.ident;

    if let darling::ast::Data::Enum(variants) = &input.data {
        if variants.is_empty() {
            emit!(
                emitter,
                input.span,
                "Uninhabited enums are not allowed in FFI"
            );
        }
    }

    // the logic of `is_opaque` is somewhat convoluted and I am not sure if it is even correct
    // there is also `is_opaque_struct`...
    if input.is_opaque() {
        return derive_ffi_type_for_opaque_item(name, &input.generics);
    }
    if input.repr_attr.kind.as_deref() == Some(&ReprKind::Transparent) {
        return derive_ffi_type_for_transparent_item(emitter, &input);
    }

    match &input.data {
        darling::ast::Data::Enum(variants) => {
            if variants.iter().all(|v| v.fields.is_empty()) {
                if variants.len() == 1 {
                    // NOTE: one-variant fieldless enums have representation of ()
                    return derive_ffi_type_for_opaque_item(name, &input.generics);
                }
                if let Some(variant) = variants.iter().find(|v| v.discriminant.is_some()) {
                    emit!(
                        emitter,
                        &variant.span(),
                        "Fieldless enums with explicit discriminants are prohibited",
                    )
                }

                derive_ffi_type_for_fieldless_enum(
                    emitter,
                    &input.ident,
                    variants,
                    &input.repr_attr,
                )
            } else {
                verify_is_non_owning(emitter, &input.data);
                let local = input.ffi_type_attr.kind == Some(FfiTypeKindAttribute::Local);

                derive_ffi_type_for_data_carrying_enum(
                    emitter,
                    &input.ident,
                    input.generics,
                    variants,
                    local,
                )
            }
        }
        darling::ast::Data::Struct(item) => {
            let ffi_type_impl = derive_ffi_type_for_repr_c(emitter, &input);

            let repr_c_impl = {
                let predicates = &mut input.generics.make_where_clause().predicates;
                let add_bound = |ty| predicates.push(syn2::parse_quote! {#ty: iroha_ffi::ReprC});

                if item.style == Style::Unit {
                    emit!(
                        emitter,
                        &input.span,
                        "Unit structs cannot implement `ReprC`"
                    );
                }

                item.fields
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
fn derive_unsafe_repr_c(name: &Ident, generics: &syn2::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        // SAFETY: Type is robust with #[repr(C)] attribute attached
        unsafe impl #impl_generics iroha_ffi::ReprC for #name #ty_generics #where_clause {}
    }
}

fn derive_ffi_type_for_opaque_item(name: &Ident, generics: &syn2::Generics) -> TokenStream {
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

fn derive_ffi_type_for_transparent_item(
    emitter: &mut Emitter,
    input: &FfiTypeInput,
) -> TokenStream {
    assert_eq!(
        input.repr_attr.kind.as_deref().copied(),
        Some(ReprKind::Transparent)
    );

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let name = &input.ident;

    // #[repr(transparent)] can only be used on a struct or
    //      single-variant enum that has a single non-zero-sized field (there may be additional zero-sized fields).
    // The effect is that the layout and ABI of the whole struct/enum is guaranteed to be the same as that one field.

    // TODO: We don't check to find which field is not a ZST.
    // It is just assumed that it is the first field
    let inner = match &input.data {
        darling::ast::Data::Enum(variants) => {
            let first_variant = emitter.handle(variants.iter().next().ok_or_else(|| {
                error_message!("transparent enum must have exactly one variant, but it has none")
            }));

            if let Some(first_variant) = first_variant.and_then(|v| v.fields.fields.first()) {
                &first_variant.ty
            } else {
                // NOTE: one-variant fieldless enums have representation of ()
                return derive_ffi_type_for_opaque_item(name, &input.generics);
            }
        }
        darling::ast::Data::Struct(item) => {
            if let Some(first_field) = item.fields.first() {
                &first_field.ty
            } else {
                // NOTE: Fieldless structs have representation of ()
                return derive_ffi_type_for_opaque_item(name, &input.generics);
            }
        }
    };

    if input.ffi_type_attr.kind == Some(FfiTypeKindAttribute::UnsafeRobust) {
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
    emitter: &mut Emitter,
    enum_name: &Ident,
    variants: &[SpannedValue<FfiTypeVariant>],
    repr: &Repr,
) -> TokenStream {
    let enum_repr_type = get_enum_repr_type(emitter, enum_name, repr, variants.is_empty());
    // FIXME: I think this doesn't actually require variant names, just using a range would suffice
    // (note that we don't support custom discriminants)
    let (discriminants, discriminant_decls) =
        gen_discriminants(enum_name, variants, &enum_repr_type);

    let match_ = if discriminants.is_empty() {
        quote! {false}
    } else {
        quote! {
            match *target {
                #( | #discriminants )* => true,
                _ => false,
            }
        }
    };

    quote! {
        iroha_ffi::ffi_type! {
            unsafe impl Transparent for #enum_name {
                type Target = #enum_repr_type;

                validation_fn=unsafe {|target: &#enum_repr_type| {
                    #(#discriminant_decls)*

                    #match_
                }},
                niche_value=<Self as iroha_ffi::FfiType>::ReprC::MAX
            }
        }

        impl iroha_ffi::WrapperTypeOf<#enum_name> for #enum_repr_type {
            type Type = #enum_name;
        }
    }
}

#[allow(clippy::too_many_lines)]
fn derive_ffi_type_for_data_carrying_enum(
    emitter: &mut Emitter,
    enum_name: &Ident,
    mut generics: syn2::Generics,
    variants: &[SpannedValue<FfiTypeVariant>],
    local: bool,
) -> TokenStream {
    let (repr_c_enum_name, repr_c_enum) =
        gen_data_carrying_repr_c_enum(emitter, enum_name, &mut generics, variants);

    generics.make_where_clause();
    let lifetime = quote! {'__iroha_ffi_itm};
    let (impl_generics, ty_generics, where_clause) = split_for_impl(&generics);

    let variant_rust_stores = variants
        .iter()
        .map(|variant| {
            variant_mapper(
                emitter,
                variant,
                || quote! { () },
                |field| {
                    let ty = &field.ty;
                    quote! { <#ty as iroha_ffi::FfiConvert<#lifetime, <#ty as iroha_ffi::FfiType>::ReprC>>::RustStore }
                },
            )
        })
        .collect::<Vec<_>>();

    let variant_ffi_stores = variants
        .iter()
        .map(|variant| {
            variant_mapper(
                emitter,
                variant,
                || quote! { () },
                |field| {
                    let ty = &field.ty;
                    quote! { <#ty as iroha_ffi::FfiConvert<#lifetime, <#ty as iroha_ffi::FfiType>::ReprC>>::FfiStore }
                },
            )
        })
        .collect::<Vec<_>>();

    let variants_into_ffi = variants
        .iter()
        .enumerate()
        .map(|(i, variant)| {
            let idx = TokenStream::from_str(&format!("{i}")).expect("Valid");
            let payload_name = gen_repr_c_enum_payload_name(enum_name);
            let variant_name = &variant.ident;

            variant_mapper(
                emitter,
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
        })
        .collect::<Vec<_>>();

    let variants_try_from_ffi = variants.iter().enumerate().map(|(i, variant)| {
        let idx = TokenStream::from_str(&format!("{i}")).expect("Valid");
        let variant_name = &variant.ident;

        variant_mapper(
            emitter,
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
    }).collect::<Vec<_>>();

    // TODO: Tuples don't support impl of `Default` for arity > 12 currently.
    // Once this limitation is lifted `Option<tuple>` will not be necessary
    let (rust_store, ffi_store, rust_store_conversion, ffi_store_conversion) =
        if variants.len() > 12 {
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
        let mut non_local_where_clause = where_clause.unwrap().clone();

        for variant in variants {
            let Some(ty) = variant_mapper(
                emitter, variant,
                || None,
                |field| Some(field.ty.clone())
            ) else {
                continue
            };

            non_local_where_clause.predicates.push(
                syn2::parse_quote! {#ty: iroha_ffi::repr_c::NonLocal<<#ty as iroha_ffi::ir::Ir>::Type>},
            );
        }

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

fn derive_ffi_type_for_repr_c(emitter: &mut Emitter, input: &FfiTypeInput) -> TokenStream {
    verify_is_non_owning(emitter, &input.data);
    if input.repr_attr.kind.as_deref().copied() != Some(ReprKind::C) {
        let span = input
            .repr_attr
            .kind
            .map_or_else(Span::call_site, |kind| kind.span());
        // TODO: this error message may be unclear. Consider adding a note about the `#[ffi_type]` attribute
        emit!(emitter, span, "To make an FFI type robust you must mark it with `#[repr(C)]`. Alternatively, try using `#[ffi_type(opaque)]` to make it opaque");
    }

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let name = &input.ident;

    quote! {
        iroha_ffi::ffi_type! {
            impl #impl_generics Robust for #name #ty_generics #where_clause {}
        }
    }
}

fn gen_data_carrying_repr_c_enum(
    emitter: &mut Emitter,
    enum_name: &Ident,
    generics: &mut syn2::Generics,
    variants: &[SpannedValue<FfiTypeVariant>],
) -> (Ident, TokenStream) {
    let (payload_name, payload) =
        gen_data_carrying_enum_payload(emitter, enum_name, generics, variants);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let doc = format!(" [`ReprC`] equivalent of [`{enum_name}`]");
    let enum_tag_type = gen_enum_tag_type(variants);
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
    emitter: &mut Emitter,
    enum_name: &Ident,
    generics: &mut syn2::Generics,
    variants: &[SpannedValue<FfiTypeVariant>],
) -> (Ident, TokenStream) {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let field_names = variants.iter().map(|variant| &variant.ident);
    let payload_name = gen_repr_c_enum_payload_name(enum_name);
    let doc = format!(" [`ReprC`] equivalent of [`{enum_name}`]");

    let field_tys = variants
        .iter()
        .map(|variant| {
            variant_mapper(
                emitter,
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
    variants: &[SpannedValue<FfiTypeVariant>],
    tag_type: &syn2::Type,
) -> (Vec<Ident>, Vec<TokenStream>) {
    let variant_names: Vec<_> = variants.iter().map(|v| &v.ident).collect();
    let discriminant_values = variant_discriminants(variants);

    variant_names.iter().zip(discriminant_values.iter()).fold(
        <(Vec<_>, Vec<_>)>::default(),
        |mut acc, (variant_name, discriminant_value)| {
            let discriminant_name = Ident::new(
                &format!("{enum_name}__{variant_name}").to_uppercase(),
                Span::call_site(),
            );

            acc.1.push(quote! {
                const #discriminant_name: #tag_type = #discriminant_value;
            });
            acc.0.push(discriminant_name);

            acc
        },
    )
}

fn variant_discriminants(variants: &[SpannedValue<FfiTypeVariant>]) -> Vec<proc_macro2::Literal> {
    variants
        .iter()
        .enumerate()
        .map(|(i, _)| proc_macro2::Literal::usize_unsuffixed(i))
        .collect()
}

fn variant_mapper<T: Sized, F0: FnOnce() -> T, F1: FnOnce(&FfiTypeField) -> T>(
    emitter: &mut Emitter,
    variant: &SpannedValue<FfiTypeVariant>,
    unit_mapper: F0,
    field_mapper: F1,
) -> T {
    match &variant.fields.style {
        Style::Tuple if variant.fields.fields.len() == 1 => field_mapper(&variant.fields.fields[0]),
        Style::Tuple => {
            emit!(
                emitter,
                variant.span(),
                "Only unit or single unnamed field variants supported"
            );
            unit_mapper()
        }
        Style::Struct => {
            emit!(
                emitter,
                variant.span(),
                "Only unit or single unnamed field variants supported"
            );
            unit_mapper()
        }
        Style::Unit => unit_mapper(),
    }
}

fn gen_repr_c_enum_name(enum_name: &Ident) -> Ident {
    Ident::new(&format!("__iroha_ffi__ReprC{enum_name}"), Span::call_site())
}

fn gen_repr_c_enum_payload_name(enum_name: &Ident) -> Ident {
    Ident::new(
        &format!("__iroha_ffi__{enum_name}Payload"),
        Span::call_site(),
    )
}

// NOTE: Except for the raw pointers there should be no other type
// that is at the same time Robust and also transfers ownership
/// Verifies for each pointer type found inside the `FfiTypeData` that it is marked as non-owning
fn verify_is_non_owning(emitter: &mut Emitter, data: &FfiTypeData) {
    struct PtrVisitor<'a> {
        emitter: &'a mut Emitter,
    }
    impl syn2::visit::Visit<'_> for PtrVisitor<'_> {
        fn visit_type_ptr(&mut self, node: &syn2::TypePtr) {
            emit!(self.emitter, node, "Raw pointer found. If the pointer doesn't own the data, attach `#[ffi_type(unsafe {{non_owning}})` to the field. Otherwise, mark the entire type as opaque with `#[ffi_type(opaque)]`");
        }
    }

    fn visit_field(ptr_visitor: &mut PtrVisitor, field: &FfiTypeField) {
        if field.ffi_type_attr.kind == Some(FfiTypeKindFieldAttribute::UnsafeNonOwning) {
            return;
        }
        ptr_visitor.visit_type(&field.ty);
    }

    let mut ptr_visitor = PtrVisitor { emitter };
    match data {
        FfiTypeData::Enum(variants) => {
            for variant in variants {
                for field in variant.fields.iter() {
                    visit_field(&mut ptr_visitor, field);
                }
            }
        }
        FfiTypeData::Struct(fields) => {
            for field in fields.iter() {
                visit_field(&mut ptr_visitor, field);
            }
        }
    }
}

fn get_enum_repr_type(
    emitter: &mut Emitter,
    enum_name: &Ident,
    repr: &Repr,
    is_empty: bool,
) -> syn2::Type {
    let Some(kind) = repr.kind else {
        // empty enums are not allowed to have a `#[repr]` attribute
        // it's an error to use an `#[derive(FfiType)]` on them
        // but we still want to generate a reasonable error message, so we check for it here
        if !is_empty {
            emit!(emitter, enum_name, "Enum representation is not specified. Try adding `#[repr(u32)]` or similar");
        }
        return syn2::parse_quote! {u32}
    };

    let ReprKind::Primitive(primitive) = &*kind else {
        emit!(emitter, &kind.span(), "Enum should have a primitive representation (like `#[repr(u32)]`)");
        return syn2::parse_quote! {u32}
    };

    match primitive {
        ReprPrimitive::U8 => syn2::parse_quote! {u8},
        ReprPrimitive::U16 => syn2::parse_quote! {u16},
        ReprPrimitive::U32 => syn2::parse_quote! {u32},
        ReprPrimitive::U64 => syn2::parse_quote! {u64},
        ReprPrimitive::I8 => syn2::parse_quote! {i8},
        ReprPrimitive::I16 => syn2::parse_quote! {i16},
        ReprPrimitive::I32 => syn2::parse_quote! {i32},

        _ => {
            emit!(
                emitter,
                &kind.span(),
                "Enum representation is not supported"
            );
            syn2::parse_quote! {u32}
        }
    }
}

fn gen_enum_tag_type(variants: &[SpannedValue<FfiTypeVariant>]) -> TokenStream {
    const U8_MAX: usize = u8::MAX as usize;
    const U16_MAX: usize = u16::MAX as usize;
    const U32_MAX: usize = u32::MAX as usize;

    // NOTE: Arms are matched in the order of declaration
    #[allow(clippy::match_overlapping_arm)]
    match variants.len() {
        0..=U8_MAX => quote! {u8},
        0..=U16_MAX => quote! {u16},
        0..=U32_MAX => quote! {u32},
        _ => {
            // I don't think ANYONE will ever see this error lol
            unreachable!("Come get your easter egg!");
        }
    }
}

fn split_for_impl(
    generics: &syn2::Generics,
) -> (
    syn2::punctuated::Punctuated<syn2::GenericParam, syn2::Token![,]>,
    syn2::TypeGenerics<'_>,
    Option<&syn2::WhereClause>,
) {
    let impl_generics = generics.params.clone();
    let (_, ty_generics, where_clause) = generics.split_for_impl();
    (impl_generics, ty_generics, where_clause)
}
