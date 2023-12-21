//! Crate with derive `IntoSchema` macro

// darling-generated code triggers this lint
#![allow(clippy::option_if_let_else)]

use darling::{ast::Style, FromAttributes, FromDeriveInput, FromField, FromMeta, FromVariant};
use manyhow::{bail, emit, error_message, manyhow, Emitter, Result};
use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens};
use syn2::parse_quote;

/// Derive [`iroha_schema::TypeId`]
///
/// Check out [`iroha_schema`] documentation
#[manyhow]
#[proc_macro_derive(TypeId, attributes(type_id))]
pub fn type_id_derive(input: TokenStream) -> Result<TokenStream> {
    let mut input = syn2::parse2(input)?;
    Ok(impl_type_id(&mut input))
}

fn impl_type_id(input: &mut syn2::DeriveInput) -> TokenStream {
    let name = &input.ident;

    input.generics.type_params_mut().for_each(|ty_param| {
        ty_param
            .bounds
            .push(syn2::parse_quote! {iroha_schema::TypeId});
    });

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let type_id_body = trait_body(name, &input.generics, true);

    quote! {
        impl #impl_generics iroha_schema::TypeId for #name #ty_generics #where_clause {
            fn id() -> String {
                #type_id_body
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Transparent {
    NotTransparent,
    Transparent(Option<syn2::Type>),
}

impl FromMeta for Transparent {
    fn from_none() -> Option<Self> {
        Some(Self::NotTransparent)
    }

    fn from_word() -> darling::Result<Self> {
        Ok(Self::Transparent(None))
    }

    fn from_string(value: &str) -> darling::Result<Self> {
        let ty = syn2::parse_str(value)?;
        Ok(Self::Transparent(Some(ty)))
    }
}

#[derive(Debug, Clone, FromAttributes)]
#[darling(attributes(schema))]
struct SchemaAttributes {
    transparent: Transparent,
    bounds: Option<String>,
}

// NOTE: this will fail on unknown attributes.. This is not ideal
#[derive(Debug, Clone, FromAttributes)]
#[darling(attributes(codec))]
struct CodecAttributes {
    #[darling(default)]
    skip: bool,
    #[darling(default)]
    compact: bool,
    index: Option<u8>,
}

type IntoSchemaData = darling::ast::Data<IntoSchemaVariant, IntoSchemaField>;

#[derive(Debug, Clone)]
struct IntoSchemaInput {
    ident: syn2::Ident,
    generics: syn2::Generics,
    data: IntoSchemaData,
    schema_attrs: SchemaAttributes,
}

impl FromDeriveInput for IntoSchemaInput {
    fn from_derive_input(input: &syn2::DeriveInput) -> darling::Result<Self> {
        let ident = input.ident.clone();
        let generics = input.generics.clone();
        let data = darling::ast::Data::try_from(&input.data)?;
        let schema_attrs = SchemaAttributes::from_attributes(&input.attrs)?;

        Ok(Self {
            ident,
            generics,
            data,
            schema_attrs,
        })
    }
}

#[derive(Debug, Clone)]
struct IntoSchemaVariant {
    ident: syn2::Ident,
    discriminant: Option<syn2::Expr>,
    fields: IntoSchemaFields,
    codec_attrs: CodecAttributes,
}

impl FromVariant for IntoSchemaVariant {
    fn from_variant(variant: &syn2::Variant) -> darling::Result<Self> {
        let ident = variant.ident.clone();
        let discriminant = variant.discriminant.as_ref().map(|(_, expr)| expr.clone());
        let fields = IntoSchemaFields::try_from(&variant.fields)?;
        let codec_attrs = CodecAttributes::from_attributes(&variant.attrs)?;

        Ok(Self {
            ident,
            discriminant,
            fields,
            codec_attrs,
        })
    }
}

type IntoSchemaFields = darling::ast::Fields<IntoSchemaField>;

#[derive(Debug, Clone)]
struct IntoSchemaField {
    ident: Option<syn2::Ident>,
    ty: syn2::Type,
    codec_attrs: CodecAttributes,
}

impl FromField for IntoSchemaField {
    fn from_field(field: &syn2::Field) -> darling::Result<Self> {
        let ident = field.ident.clone();
        let ty = field.ty.clone();
        let codec_attrs = CodecAttributes::from_attributes(&field.attrs)?;

        Ok(Self {
            ident,
            ty,
            codec_attrs,
        })
    }
}

#[derive(Debug, Clone)]
struct CodegenField {
    ident: Option<syn2::Ident>,
    ty: syn2::Type,
}

/// Derive [`iroha_schema::IntoSchema`] and [`iroha_schema::TypeId`]
///
/// Check out [`iroha_schema`] documentation
///
/// # Panics
///
/// - If found invalid `transparent` attribute
/// - If it's impossible to infer the type for transparent attribute
#[manyhow]
#[proc_macro_derive(IntoSchema, attributes(schema, codec))]
pub fn schema_derive(input: TokenStream) -> Result<TokenStream> {
    let original_input = input.clone();

    let input: syn2::DeriveInput = syn2::parse2(input)?;
    let mut input = IntoSchemaInput::from_derive_input(&input)?;

    input.generics.type_params_mut().for_each(|ty_param| {
        ty_param
            .bounds
            .push(parse_quote! {iroha_schema::IntoSchema});
    });

    let mut emitter = Emitter::new();

    let impl_type_id = impl_type_id(&mut syn2::parse2(original_input).unwrap());

    let impl_schema = match &input.schema_attrs.transparent {
        Transparent::NotTransparent => impl_into_schema(&input, input.schema_attrs.bounds.as_ref()),
        Transparent::Transparent(transparent_type) => {
            let transparent_type = transparent_type
                .clone()
                .unwrap_or_else(|| infer_transparent_type(&input.data, &mut emitter));
            impl_transparent_into_schema(
                &input,
                &transparent_type,
                input.schema_attrs.bounds.as_ref(),
            )
        }
    };
    let impl_schema = match impl_schema {
        Ok(impl_schema) => impl_schema,
        Err(err) => {
            emitter.emit(err);
            quote!()
        }
    };

    emitter.into_result()?;

    Ok(quote! {
        #impl_type_id
        #impl_schema
    })
}

fn impl_transparent_into_schema(
    input: &IntoSchemaInput,
    transparent_type: &syn2::Type,
    bounds: Option<&String>,
) -> Result<TokenStream> {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let name = &input.ident;
    let where_clause: Option<syn2::WhereClause> = match bounds {
        Some(bounds) => Some(syn2::parse_str(&format!("where {bounds}"))?),
        None => where_clause.cloned(),
    };

    Ok(quote! {
        impl #impl_generics iroha_schema::IntoSchema for #name #ty_generics #where_clause {
            fn update_schema_map(map: &mut iroha_schema::MetaMap) {
                if !map.contains_key::<Self>() {
                    if !map.contains_key::<#transparent_type>() {
                        <#transparent_type as iroha_schema::IntoSchema>::update_schema_map(map);
                    }

                    if let Some(schema) = map.get::<#transparent_type>() {
                        map.insert::<Self>(schema.clone());
                    }
                }
            }

            fn type_name() -> String {
               <#transparent_type as iroha_schema::IntoSchema>::type_name()
            }
        }
    })
}

fn impl_into_schema(input: &IntoSchemaInput, bounds: Option<&String>) -> Result<TokenStream> {
    let name = &input.ident;
    let type_name_body = trait_body(name, &input.generics, false);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let metadata = metadata(&input.data)?;
    let where_clause: Option<syn2::WhereClause> = match bounds {
        Some(bounds) => Some(syn2::parse_str(&format!("where {bounds}"))?),
        None => where_clause.cloned(),
    };

    Ok(quote! {
        impl #impl_generics iroha_schema::IntoSchema for #name #ty_generics #where_clause {
            fn type_name() -> String {
                #type_name_body
            }

            fn update_schema_map(map: &mut iroha_schema::MetaMap) {
               #metadata
            }
        }
    })
}

fn infer_transparent_type(input: &IntoSchemaData, emitter: &mut Emitter) -> syn2::Type {
    const TRY_MESSAGE: &str =
        "try to specify it explicitly using #[schema(transparent = \"Type\")]";

    match input {
        IntoSchemaData::Enum(variants) => {
            if variants.len() != 1 {
                emit!(
                    emitter,
                    "Enums with only one variant support transparent type inference, {}",
                    TRY_MESSAGE
                );
                return parse_quote!(());
            }

            let variant = variants.iter().next().unwrap();
            if variant.fields.style != Style::Tuple {
                emit!(
                    emitter,
                    "Only unnamed fields are supported for transparent type inference, {}",
                    TRY_MESSAGE,
                );
                return parse_quote!(());
            }

            if variant.fields.len() != 1 {
                emit!(
                    emitter,
                    "Enums with only one unnamed field support transparent type inference, {}",
                    TRY_MESSAGE,
                );
                return parse_quote!(());
            }
            let field = variant.fields.iter().next().unwrap();

            field.ty.clone()
        }
        IntoSchemaData::Struct(IntoSchemaFields {
            style: Style::Struct,
            fields,
            ..
        }) => {
            if fields.len() != 1 {
                emit!(
                    emitter,
                    "Structs with only one named field support transparent type inference, {}",
                    TRY_MESSAGE
                );
                return parse_quote!(());
            }

            let field = fields.iter().next().expect("Checked via `len`");
            field.ty.clone()
        }
        IntoSchemaData::Struct(IntoSchemaFields {
            style: Style::Tuple,
            fields,
            ..
        }) => {
            if fields.len() != 1 {
                emit!(
                    emitter,
                    "Structs with only one unnamed field support transparent type inference, {}",
                    TRY_MESSAGE
                );
                return parse_quote!(());
            }
            let field = fields.iter().next().expect("Checked via `len`");

            field.ty.clone()
        }
        IntoSchemaData::Struct(IntoSchemaFields {
            style: Style::Unit, ..
        }) => {
            emit!(
                emitter,
                "Transparent attribute type inference is not supported for unit structs, {}",
                TRY_MESSAGE
            );
            parse_quote!(())
        }
    }
}

/// Body of [`IntoSchema::type_name`] method
fn trait_body(
    name: &syn2::Ident,
    generics: &syn2::Generics,
    is_type_id_trait: bool,
) -> TokenStream {
    let generics = &generics
        .params
        .iter()
        .filter_map(|param| match param {
            syn2::GenericParam::Type(ty) => Some(&ty.ident),
            _ => None,
        })
        .collect::<Vec<_>>();
    let name = syn2::LitStr::new(&name.to_string(), Span::call_site());

    if generics.is_empty() {
        return quote! { format!("{}", #name) };
    }

    let mut format_str = "{}<".to_owned();
    format_str.push_str(
        &generics
            .iter()
            .map(|_| "{}".to_owned())
            .collect::<Vec<_>>()
            .join(", "),
    );
    format_str.push('>');
    let format_str = syn2::LitStr::new(&format_str, Span::mixed_site());

    let generics = if is_type_id_trait {
        quote!(#(<#generics as iroha_schema::TypeId>::id()),*)
    } else {
        quote!(#(<#generics as iroha_schema::IntoSchema>::type_name()),*)
    };

    quote! {
        format!(
            #format_str,
            #name,
            #generics
        )
    }
}

/// Returns schema method body
fn metadata(data: &IntoSchemaData) -> Result<TokenStream> {
    let (types, expr) = match &data {
        IntoSchemaData::Enum(variants) => metadata_for_enums(variants)?,
        IntoSchemaData::Struct(IntoSchemaFields {
            style: Style::Struct,
            fields,
            ..
        }) => metadata_for_structs(fields),
        IntoSchemaData::Struct(IntoSchemaFields {
            style: Style::Tuple,
            fields,
            ..
        }) => metadata_for_tuplestructs(fields),
        IntoSchemaData::Struct(IntoSchemaFields {
            style: Style::Unit, ..
        }) => {
            let expr: syn2::Expr = parse_quote! {
                iroha_schema::Metadata::Tuple(
                    iroha_schema::UnnamedFieldsMeta {
                        types: Vec::new()
                    }
                )
            };
            (vec![], expr)
        }
    };

    Ok(quote! {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(#expr); #(

            <#types as iroha_schema::IntoSchema>::update_schema_map(map); )*
        }
    })
}

/// Returns types for which schema should be called and metadata for tuplestruct
fn metadata_for_tuplestructs(fields: &[IntoSchemaField]) -> (Vec<syn2::Type>, syn2::Expr) {
    let fields = fields.iter().filter_map(convert_field_to_codegen);
    let fields_ty = fields.clone().map(|field| field.ty).collect();
    let types = fields
        .map(|field| field.ty)
        .map(|ty| quote! { core::any::TypeId::of::<#ty>()});
    let expr = parse_quote! {
        iroha_schema::Metadata::Tuple(
            iroha_schema::UnnamedFieldsMeta {
                types: {
                    let mut types = Vec::new();
                    #( types.push(#types); )*
                    types
                }
            }
        )
    };
    (fields_ty, expr)
}

/// Returns types for which schema should be called and metadata for struct
fn metadata_for_structs(fields: &[IntoSchemaField]) -> (Vec<syn2::Type>, syn2::Expr) {
    let fields = fields.iter().filter_map(convert_field_to_codegen);
    let declarations = fields.clone().map(|field| field_to_declaration(&field));
    let fields_ty = fields.map(|field| field.ty).collect();
    let expr = parse_quote! {
        iroha_schema::Metadata::Struct(
            iroha_schema::NamedFieldsMeta {
                declarations: {
                    let mut declarations = Vec::new();
                    #( declarations.push(#declarations); )*
                    declarations
                }
            }
        )
    };
    (fields_ty, expr)
}

/// Takes variant fields and gets its type
fn variant_field(fields: &IntoSchemaFields) -> Result<Option<syn2::Type>> {
    let field = match fields.style {
        Style::Unit => return Ok(None),
        Style::Tuple if fields.len() == 1 => fields.iter().next().unwrap(),
        Style::Tuple => {
            bail!("Use at most 1 field in unnamed enum variants. Check out styleguide");
        }
        Style::Struct => {
            bail!("Please don't use named fields on enums. It is against iroha styleguide")
        }
    };
    Ok(convert_field_to_codegen(field).map(|this_field| this_field.ty))
}

/// Returns types for which schema should be called and metadata for struct
fn metadata_for_enums(variants: &[IntoSchemaVariant]) -> Result<(Vec<syn2::Type>, syn2::Expr)> {
    let variant_exprs: Vec<_> = variants
        .iter()
        .enumerate()
        .filter(|(_, variant)| !variant.codec_attrs.skip)
        .map(|(discriminant, variant)| {
            let discriminant = variant_index(variant, discriminant)?;
            if variant.discriminant.is_some() {
                bail!("Fieldless enums with explicit discriminants are not allowed")
            }

            let name = &variant.ident;
            let ty = variant_field(&variant.fields)?.map_or_else(
                || quote! { None },
                |ty| quote! { Some(core::any::TypeId::of::<#ty>()) },
            );
            Ok(quote! {
                iroha_schema::EnumVariant {
                    tag: String::from(stringify!(#name)),
                    discriminant: #discriminant,
                    ty: #ty,
                }
            })
        })
        .collect::<Result<_>>()?;
    let fields_ty = variants
        .iter()
        .filter(|variant| !variant.codec_attrs.skip)
        .filter_map(|variant| variant_field(&variant.fields).transpose())
        .collect::<Result<_>>()?;
    let expr = parse_quote! {
        iroha_schema::Metadata::Enum(iroha_schema::EnumMeta {
            variants: {
                let mut variants = Vec::new();
                #( variants.push(#variant_exprs); )*
                variants
            }
        })
    };

    Ok((fields_ty, expr))
}

/// Generates declaration for field
fn field_to_declaration(field: &CodegenField) -> TokenStream {
    let ident = field.ident.as_ref().expect("Field to declaration");
    let ty = &field.ty;

    quote! {
        iroha_schema::Declaration {
            name: String::from(stringify!(#ident)),
            ty: core::any::TypeId::of::<#ty>(),
        }
    }
}

/// Look for a `#[codec(index = $int)]` attribute on a variant. If no attribute
/// is found, fall back to the discriminant or just the variant index.
fn variant_index(v: &IntoSchemaVariant, i: usize) -> Result<TokenStream> {
    Ok(match (v.codec_attrs.index, v.discriminant.as_ref()) {
        // first, try to use index from the `codec` attribute
        (Some(index), _) => index.to_token_stream(),
        // then try to use explicit discriminant
        (_, Some(discriminant)) => discriminant.to_token_stream(),
        // then fallback to just variant index
        (_, _) => {
            let index = u8::try_from(i).map_err(|_| error_message!("Too many enum variants"))?;
            index.to_token_stream()
        }
    })
}

/// Convert field to the codegen representation, filtering out skipped fields.
fn convert_field_to_codegen(field: &IntoSchemaField) -> Option<CodegenField> {
    if field.codec_attrs.skip {
        return None;
    }
    let ty = if field.codec_attrs.compact {
        let ty = &field.ty;
        parse_quote!(iroha_schema::Compact<#ty>)
    } else {
        field.ty.clone()
    };

    Some(CodegenField {
        ident: field.ident.clone(),
        ty,
    })
}
