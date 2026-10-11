//! Derive macros for the `norito` serialization framework.
//!
//! Binary derives implement payload serialization and reconstruction for structs
//! and enums. `NoritoSerialize` also generates an `Archived` type alias. Typed
//! framing requires a separate [`NoritoSchema`] declaration; field codecs do not
//! require frame identities.
//!
//! ```ignore
//! use norito::core::*;
//!
//! #[derive(norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema)]
//! #[norito_schema(name = "example::Point")]
//! struct Point { x: u32, y: bool }
//!
//! let bytes = to_bytes(&Point { x: 1, y: false }).unwrap();
//! let archived = from_bytes::<Point>(&bytes).unwrap();
//! let decoded = <Point as DeserializePayload>::deserialize(archived);
//! assert_eq!(decoded.x, 1);
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens as _, format_ident, quote};
use syn::{
    Attribute, Data, DataEnum, DeriveInput, Fields, Generics, Index, Result as SynResult, Token,
    Variant, parse_macro_input, parse_quote,
};

mod binary_decode;
mod field_destination;
use binary_decode::{derive_enum_deserialize, derive_struct_deserialize};

mod decode_validation;
mod schema_identity;
mod slice_decode;

#[cfg(test)]
#[path = "../../../scripts/norito_schema_capture/derive_probe.rs"]
mod capture_probe_tests;

/// Declare a canonical schema identity independent of the Rust item location.
#[proc_macro_derive(NoritoSchema, attributes(norito_schema))]
pub fn derive_norito_schema(input: TokenStream) -> TokenStream {
    schema_identity::expand(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

mod json_write_bounded;
use json_write_bounded::{EnumAttr, VariantAttr, parse_helper_path};

include!("attribute_helpers.rs");

fn is_option_type(ty: &syn::Type) -> bool {
    // Macro ty fragments introduce invisible groups; parentheses are equally transparent.
    match ty {
        syn::Type::Group(group) => is_option_type(&group.elem),
        syn::Type::Paren(paren) => is_option_type(&paren.elem),
        _ => type_ident(ty).is_some_and(|ident| ident == "Option"),
    }
}

fn token_stream_mentions_generic(tokens: TokenStream2, generic_names: &[syn::Ident]) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => generic_names.contains(&ident),
        proc_macro2::TokenTree::Group(group) => {
            token_stream_mentions_generic(group.stream(), generic_names)
        }
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

/// Add a trait bound to the generated `where` clause when the field type
/// depends on one of the container's generic parameters.
///
/// Concrete field types are checked directly while compiling the generated
/// implementation, so repeating their trait obligations in a `where` clause
/// is unnecessary. More importantly, such bounds turn a valid concrete
/// recursive type such as `enum Expr { Nested(Box<Expr>) }` into the cyclic
/// obligation `Box<Expr>: Trait -> Expr: Trait -> Box<Expr>: Trait`.
fn add_bound(generics: &mut Generics, ty: &syn::Type, bound: TokenStream2) {
    let generic_names = generics
        .params
        .iter()
        .map(|parameter| match parameter {
            syn::GenericParam::Type(parameter) => parameter.ident.clone(),
            syn::GenericParam::Lifetime(parameter) => parameter.lifetime.ident.clone(),
            syn::GenericParam::Const(parameter) => parameter.ident.clone(),
        })
        .collect::<Vec<_>>();
    if generic_names.is_empty()
        || !token_stream_mentions_generic(ty.to_token_stream(), &generic_names)
    {
        return;
    }
    let where_clause = generics.make_where_clause();
    let pred: syn::WherePredicate = parse_quote!(#ty: #bound);
    where_clause.predicates.push(pred);
}

#[cfg(test)]
mod generic_bound_tests {
    include!("tests/generic_bounds.rs");
}

/// Validate `#[norito(...)]` attributes on fields for common misuse cases.
fn validate_field_attrs(fields: &Fields) -> Result<(), syn::Error> {
    match fields {
        Fields::Named(named) => {
            for f in &named.named {
                let attrs = FieldAttr::parse(&f.attrs)?;
                validate_required_attr(f, &attrs, true)?;
                if attrs.skip && attrs.default {
                    return Err(syn::Error::new_spanned(
                        f,
                        "conflicting attributes: #[norito(skip)] and #[norito(default)]",
                    ));
                }
                if attrs.flatten {
                    if attrs.rename.is_some() {
                        return Err(syn::Error::new_spanned(
                            f,
                            "#[norito(flatten)] cannot be combined with #[norito(rename = ...)]",
                        ));
                    }
                    if attrs.with.is_some() {
                        return Err(syn::Error::new_spanned(
                            f,
                            "#[norito(flatten)] cannot be combined with #[norito(with = ...)]",
                        ));
                    }
                    if attrs.skip_serializing_if.is_some() {
                        return Err(syn::Error::new_spanned(
                            f,
                            "#[norito(flatten)] cannot be combined with #[norito(skip_serializing_if = ...)]",
                        ));
                    }
                }
            }
        }
        Fields::Unnamed(unnamed) => {
            for f in &unnamed.unnamed {
                let attrs = FieldAttr::parse(&f.attrs)?;
                validate_required_attr(f, &attrs, false)?;
                if attrs.rename.is_some() {
                    return Err(syn::Error::new_spanned(
                        f,
                        "#[norito(rename = ...)] is only allowed on named fields",
                    ));
                }
                if attrs.skip && attrs.default {
                    return Err(syn::Error::new_spanned(
                        f,
                        "conflicting attributes: #[norito(skip)] and #[norito(default)]",
                    ));
                }
                if attrs.flatten {
                    return Err(syn::Error::new_spanned(
                        f,
                        "#[norito(flatten)] is only supported on named struct fields",
                    ));
                }
            }
        }
        Fields::Unit => {}
    }
    Ok(())
}

fn validate_required_attr(
    field: &syn::Field,
    attrs: &FieldAttr,
    is_named: bool,
) -> Result<(), syn::Error> {
    if !attrs.required {
        return Ok(());
    }
    let error = if !is_named {
        Some("#[norito(required)] is only supported on named fields")
    } else if !is_option_type(&field.ty) {
        Some("#[norito(required)] can only be used on Option fields")
    } else if attrs.default {
        Some("#[norito(required)] cannot be combined with #[norito(default)]")
    } else if attrs.skip {
        Some("#[norito(required)] cannot be combined with #[norito(skip)]")
    } else if attrs.flatten {
        Some("#[norito(required)] cannot be combined with #[norito(flatten)]")
    } else if attrs.skip_serializing_if.is_some() {
        Some("#[norito(required)] cannot be combined with #[norito(skip_serializing_if = ...)]")
    } else {
        None
    };
    if let Some(message) = error {
        return Err(syn::Error::new_spanned(field, message));
    }
    Ok(())
}

/// Validate field attributes for structs and for every enum-variant shape.
fn validate_data_field_attrs(data: &Data) -> syn::Result<()> {
    match data {
        Data::Struct(data) => validate_field_attrs(&data.fields),
        Data::Enum(data) => {
            for variant in &data.variants {
                validate_field_attrs(&variant.fields)?;
            }
            Ok(())
        }
        Data::Union(data) => Err(syn::Error::new_spanned(
            data.union_token,
            "Norito derives do not support unions",
        )),
    }
}

/// Extract a custom wire index from `#[codec(index = ...)]`.
fn codec_variant_index(variant: &Variant) -> SynResult<Option<u32>> {
    let mut result = None;
    for attr in &variant.attrs {
        if attr.path().is_ident("codec") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("index") {
                    if result.is_some() {
                        return Err(meta.error("duplicate `codec(index = ...)` attribute"));
                    }
                    let lit: syn::LitInt = meta.value()?.parse()?;
                    result = Some(lit.base10_parse::<u32>()?);
                } else {
                    consume_unknown_meta(meta)?;
                }
                Ok(())
            })?;
        }
    }
    Ok(result)
}

fn explicit_variant_discriminant(variant: &Variant) -> SynResult<Option<u32>> {
    let Some((_, expression)) = &variant.discriminant else {
        return Ok(None);
    };
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(literal),
        ..
    }) = expression
    else {
        return Err(syn::Error::new_spanned(
            expression,
            "Norito enum discriminants must be integer literals in 0..=u32::MAX",
        ));
    };
    literal.base10_parse::<u32>().map(Some).map_err(|_| {
        syn::Error::new_spanned(
            expression,
            "Norito enum discriminants must be integer literals in 0..=u32::MAX",
        )
    })
}

/// Resolve the canonical `u32` wire index for every enum variant.
///
/// Rust discriminants participate in the usual implicit increment sequence.
/// `#[codec(index = ...)]` may make an implicit Rust variant's wire index
/// explicit, but it must agree when the Rust discriminant is also explicit.
fn enum_variant_indices(data: &DataEnum) -> SynResult<Vec<u32>> {
    let mut next_rust_discriminant = Some(0_u32);
    let mut assigned = std::collections::BTreeMap::<u32, &syn::Ident>::new();
    let mut indices = Vec::with_capacity(data.variants.len());

    for variant in &data.variants {
        let explicit = explicit_variant_discriminant(variant)?;
        let rust_discriminant = match explicit {
            Some(discriminant) => discriminant,
            None => next_rust_discriminant.ok_or_else(|| {
                syn::Error::new_spanned(
                    &variant.ident,
                    "implicit Norito enum discriminant exceeds u32::MAX",
                )
            })?,
        };
        next_rust_discriminant = rust_discriminant.checked_add(1);

        let codec_index = codec_variant_index(variant)?;
        if let (Some(explicit), Some(codec_index)) = (explicit, codec_index)
            && explicit != codec_index
        {
            return Err(syn::Error::new_spanned(
                variant,
                format!(
                    "`#[codec(index = {codec_index})]` must match explicit Rust discriminant {explicit}"
                ),
            ));
        }
        let index = codec_index.unwrap_or(rust_discriminant);
        if let Some(first) = assigned.insert(index, &variant.ident) {
            return Err(syn::Error::new_spanned(
                variant,
                format!("duplicate Norito enum index {index}; first assigned to variant `{first}`"),
            ));
        }
        indices.push(index);
    }

    Ok(indices)
}

#[cfg(test)]
mod enum_variant_index_tests {
    use super::*;

    fn indices(input: DeriveInput) -> SynResult<Vec<u32>> {
        let Data::Enum(data) = input.data else {
            panic!("test input must be an enum");
        };
        enum_variant_indices(&data)
    }

    #[test]
    fn byte_array_length_classifier_rejects_other_arrays() {
        let bytes: syn::Type = syn::parse_quote!([u8; 32]);
        let words: syn::Type = syn::parse_quote!([u16; 32]);
        assert!(u8_array_len(&bytes).is_some());
        assert!(u8_array_len(&words).is_none());
    }
    #[test]
    fn explicit_discriminants_drive_implicit_successors() {
        let input = syn::parse_quote! {
            enum Phase {
                Prepare = 4,
                Commit,
                NewView = 9,
                Recovery,
            }
        };
        assert_eq!(indices(input).expect("valid indices"), [4, 5, 9, 10]);
    }

    #[test]
    fn codec_index_can_override_an_implicit_rust_discriminant() {
        let input = syn::parse_quote! {
            enum Message {
                #[codec(index = 42)]
                First,
                Second,
            }
        };
        assert_eq!(indices(input).expect("valid indices"), [42, 1]);
    }

    #[test]
    fn duplicate_effective_index_is_rejected() {
        let input = syn::parse_quote! {
            enum Message {
                #[codec(index = 1)]
                First,
                Second,
            }
        };
        let error = indices(input).expect_err("duplicate index must fail");
        assert_eq!(
            error.to_string(),
            "duplicate Norito enum index 1; first assigned to variant `First`"
        );
    }

    #[test]
    fn codec_index_must_match_explicit_discriminant() {
        let input = syn::parse_quote! {
            enum Phase {
                #[codec(index = 2)]
                Prepare = 1,
            }
        };
        let error = indices(input).expect_err("mismatched explicit indices must fail");
        assert_eq!(
            error.to_string(),
            "`#[codec(index = 2)]` must match explicit Rust discriminant 1"
        );
    }

    #[test]
    fn non_literal_discriminant_is_rejected() {
        let input = syn::parse_quote! {
            enum Phase {
                Prepare = 1 << 2,
            }
        };
        let error = indices(input).expect_err("non-literal discriminant must fail");
        assert_eq!(
            error.to_string(),
            "Norito enum discriminants must be integer literals in 0..=u32::MAX"
        );
    }
}

/// Parsed helper attributes for a field.
#[derive(Default, Clone)]
struct FieldAttr {
    /// Optional renamed identifier used during (de)serialization.
    #[allow(dead_code)]
    rename: Option<String>,
    /// Whether the field should be skipped entirely.
    skip: bool,
    /// Require this `Option` field's key to be present during JSON deserialization.
    required: bool,
    /// Use [`Default::default`] when the field is missing from JSON input.
    default: bool,
    /// Optional function path to compute a missing JSON field's default value.
    default_fn: Option<syn::Path>,
    /// Optional predicate to skip serialization when it returns true.
    skip_serializing_if: Option<syn::Path>,
    /// Optional ordinary and checked custom JSON helpers for the field.
    with: Option<syn::Path>,
    bounded_with: Option<syn::Path>,
    combined_json_helper: bool,
    /// Whether the field should be flattened into the surrounding struct payload.
    flatten: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RenameRule {
    Lowercase,
    Uppercase,
    SnakeCase,
    ScreamingSnakeCase,
    KebabCase,
    ScreamingKebabCase,
    CamelCase,
    PascalCase,
}

impl RenameRule {
    fn from_str(lit: &syn::LitStr) -> syn::Result<Self> {
        match lit.value().as_str() {
            "lowercase" => Ok(Self::Lowercase),
            "UPPERCASE" => Ok(Self::Uppercase),
            "snake_case" => Ok(Self::SnakeCase),
            "SCREAMING_SNAKE_CASE" => Ok(Self::ScreamingSnakeCase),
            "kebab-case" => Ok(Self::KebabCase),
            "SCREAMING-KEBAB-CASE" => Ok(Self::ScreamingKebabCase),
            "camelCase" => Ok(Self::CamelCase),
            "PascalCase" => Ok(Self::PascalCase),
            other => Err(syn::Error::new_spanned(
                lit,
                format!("unsupported rename_all value `{other}`"),
            )),
        }
    }

    fn apply(&self, ident: &str) -> String {
        match self {
            Self::Lowercase => ident.to_ascii_lowercase(),
            Self::Uppercase => ident.to_ascii_uppercase(),
            Self::SnakeCase => join_words(words(ident), '_', |w| w),
            Self::ScreamingSnakeCase => join_words(words(ident), '_', ascii_uppercase),
            Self::KebabCase => join_words(words(ident), '-', |w| w),
            Self::ScreamingKebabCase => join_words(words(ident), '-', ascii_uppercase),
            Self::CamelCase => camel_case(words(ident)),
            Self::PascalCase => pascal_case(words(ident)),
        }
    }
}

fn camel_case(words: Vec<String>) -> String {
    let mut iter = words.into_iter();
    let mut result = iter.next().unwrap_or_default();
    for word in iter {
        if let Some((first, rest)) = word.split_first_char() {
            result.push_str(&first.to_uppercase().collect::<String>());
            result.push_str(rest);
        } else {
            result.push_str(&word);
        }
    }
    result
}

fn pascal_case(words: Vec<String>) -> String {
    let mut out = String::new();
    for word in words {
        if let Some((first, rest)) = word.split_first_char() {
            out.push_str(&first.to_uppercase().collect::<String>());
            out.push_str(rest);
        } else {
            out.push_str(&word);
        }
    }
    out
}

fn join_words<F>(words: Vec<String>, separator: char, map: F) -> String
where
    F: FnMut(String) -> String,
{
    let mut iter = words.into_iter().map(map);
    let mut result = iter.next().unwrap_or_default();
    for word in iter {
        result.push(separator);
        result.push_str(&word);
    }
    result
}

fn ascii_uppercase(mut s: String) -> String {
    s.make_ascii_uppercase();
    s
}

trait SplitFirstChar {
    fn split_first_char(&self) -> Option<(char, &str)>;
}

impl SplitFirstChar for String {
    fn split_first_char(&self) -> Option<(char, &str)> {
        let mut chars = self.chars();
        let first = chars.next()?;
        Some((first, chars.as_str()))
    }
}

fn words(ident: &str) -> Vec<String> {
    use core::mem;

    let mut chars = ident.chars().peekable();
    let mut current = String::new();
    let mut result = Vec::new();
    let mut prev_is_lower = false;
    let mut prev_is_upper = false;
    let mut prev_is_digit = false;

    while let Some(ch) = chars.next() {
        if ch == '_' || ch == '-' {
            if !current.is_empty() {
                result.push(mem::take(&mut current));
            }
            prev_is_lower = false;
            prev_is_upper = false;
            prev_is_digit = false;
            continue;
        }

        let is_upper = ch.is_uppercase();
        let is_lower = ch.is_lowercase();
        let is_digit = ch.is_ascii_digit();
        let starts_new_word = is_upper
            && !current.is_empty()
            && (prev_is_lower
                || prev_is_digit
                || (prev_is_upper && chars.peek().is_some_and(|next| next.is_lowercase())));
        if starts_new_word {
            result.push(mem::take(&mut current));
        }

        if is_upper {
            current.extend(ch.to_lowercase());
        } else {
            current.push(ch);
        }

        prev_is_lower = is_lower;
        prev_is_upper = is_upper;
        prev_is_digit = is_digit;
    }

    if !current.is_empty() {
        result.push(current);
    }

    if result.is_empty() {
        result.push(String::new());
    }

    result
}

#[derive(Default)]
struct ContainerAttr {
    rename_all: Option<RenameRule>,
    validate: Option<syn::Path>,
    deny_unknown_fields: bool,
    decode_from_slice: bool,
    decode_fields: bool,
    reuse_archived: bool,
    no_fast_from_json: bool,
    tag: Option<String>,
    content: Option<String>,
}

impl ContainerAttr {
    fn parse(attrs: &[Attribute]) -> syn::Result<Self> {
        let mut out = ContainerAttr::default();
        for attr in attrs {
            if !attr.path().is_ident("norito") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename_all") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    let rule = RenameRule::from_str(&lit)?;
                    if out.rename_all.replace(rule).is_some() {
                        return Err(meta.error("duplicate rename_all attribute"));
                    }
                } else if meta.path.is_ident("schema_name") {
                    return Err(meta.error(
                        "schema_name is unsupported; declare identity once with NoritoSchema and #[norito_schema(name = \"...\")] (with frame = \"...\" for an explicit projection)",
                    ));
                } else if meta.path.is_ident("validate") {
                    if out.validate.replace(parse_helper_path(&meta)?).is_some() {
                        return Err(meta.error("duplicate `validate` attribute"));
                    }
                } else if meta.path.is_ident("deny_unknown_fields") {
                    if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                        return Err(meta.error("deny_unknown_fields does not take a value"));
                    }
                    if out.deny_unknown_fields {
                        return Err(meta.error("duplicate deny_unknown_fields attribute"));
                    }
                    out.deny_unknown_fields = true;
                } else if meta.path.is_ident("decode_fields") {
                    if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                        return Err(meta.error("decode_fields does not take a value"));
                    }
                    if out.decode_fields {
                        return Err(meta.error("duplicate decode_fields attribute"));
                    }
                    out.decode_fields = true;
                } else if meta.path.is_ident("decode_from_slice") {
                    if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                        return Err(
                            meta.error("this `norito` container flag does not take a value")
                        );
                    }
                    if out.decode_from_slice {
                        return Err(meta.error("duplicate decode_from_slice attribute"));
                    }
                    out.decode_from_slice = true;
                } else if meta.path.is_ident("reuse_archived") {
                    if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                        return Err(
                            meta.error("this `norito` container flag does not take a value")
                        );
                    }
                    if out.reuse_archived {
                        return Err(meta.error("duplicate reuse_archived attribute"));
                    }
                    out.reuse_archived = true;
                } else if meta.path.is_ident("no_fast_from_json") {
                    if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                        return Err(
                            meta.error("this `norito` container flag does not take a value")
                        );
                    }
                    if out.no_fast_from_json {
                        return Err(meta.error("duplicate no_fast_from_json attribute"));
                    }
                    out.no_fast_from_json = true;
                } else if meta.path.is_ident("tag") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    if out.tag.replace(lit.value()).is_some() {
                        return Err(meta.error("duplicate `tag` attribute"));
                    }
                } else if meta.path.is_ident("content") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    if out.content.replace(lit.value()).is_some() {
                        return Err(meta.error("duplicate `content` attribute"));
                    }
                } else {
                    return Err(meta.error("unknown `norito` container attribute"));
                }
                Ok(())
            })?;
        }
        Ok(out)
    }

    fn rename_field(&self, ident: &syn::Ident, attrs: &FieldAttr) -> String {
        if let Some(custom) = &attrs.rename {
            custom.clone()
        } else if let Some(rule) = self.rename_all {
            rule.apply(&ident.to_string())
        } else {
            ident.to_string()
        }
    }

    fn rename_variant(&self, ident: &syn::Ident, attrs: &VariantAttr) -> String {
        if let Some(custom) = &attrs.rename {
            custom.clone()
        } else if let Some(rule) = self.rename_all {
            rule.apply(&ident.to_string())
        } else {
            ident.to_string()
        }
    }
}

#[cfg(test)]
mod container_attr_tests {
    use super::*;

    #[test]
    fn deny_unknown_fields_attribute_is_parsed() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(deny_unknown_fields, rename_all = "snake_case")]
            struct Demo {
                field_name: u32,
            }
        };

        let attrs = ContainerAttr::parse(&input.attrs).expect("valid container attributes");
        assert!(attrs.deny_unknown_fields);
        assert_eq!(
            attrs.rename_field(&syn::parse_quote!(field_name), &FieldAttr::default()),
            "field_name"
        );
    }

    #[test]
    fn deny_unknown_fields_after_attributes_owned_by_other_derives_is_parsed() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(tag = "kind", content = "payload", deny_unknown_fields)]
            enum Demo {
                Unit,
            }
        };

        let attrs = ContainerAttr::parse(&input.attrs).expect("valid mixed attributes");
        assert!(attrs.deny_unknown_fields);
    }

    #[test]
    fn schema_name_is_rejected_with_canonical_identity_guidance() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(schema_name = "stable", deny_unknown_fields)]
            struct Demo {
                value: u32,
            }
        };

        let Err(error) = ContainerAttr::parse(&input.attrs) else {
            panic!("framing attributes must not define a second identity owner");
        };
        assert_eq!(
            error.to_string(),
            "schema_name is unsupported; declare identity once with NoritoSchema and #[norito_schema(name = \"...\")] (with frame = \"...\" for an explicit projection)",
        );
    }

    #[test]
    fn duplicate_deny_unknown_fields_attribute_is_rejected() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(deny_unknown_fields, deny_unknown_fields)]
            struct Demo {
                value: u32,
            }
        };

        let Err(error) = ContainerAttr::parse(&input.attrs) else {
            panic!("duplicate flag must reject");
        };
        assert_eq!(error.to_string(), "duplicate deny_unknown_fields attribute");
    }

    #[test]
    fn deny_unknown_fields_value_is_rejected() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(deny_unknown_fields = true)]
            struct Demo {
                value: u32,
            }
        };

        let Err(error) = ContainerAttr::parse(&input.attrs) else {
            panic!("valued flag must reject");
        };
        assert_eq!(
            error.to_string(),
            "deny_unknown_fields does not take a value"
        );
    }

    #[test]
    fn unknown_container_attribute_is_rejected() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(transparent)]
            struct Demo(u32);
        };

        let Err(error) = ContainerAttr::parse(&input.attrs) else {
            panic!("unknown key must reject");
        };
        assert_eq!(error.to_string(), "unknown `norito` container attribute");
    }

    #[test]
    fn attributes_owned_by_other_norito_derives_are_accepted() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(
                decode_from_slice,
                reuse_archived,
                no_fast_from_json,
                tag = "kind",
                content = "payload"
            )]
            enum Demo {
                Unit,
            }
        };

        ContainerAttr::parse(&input.attrs).expect("known shared container attributes");
    }

    #[test]
    fn duplicate_shared_container_attribute_is_rejected() {
        let input: DeriveInput = syn::parse_quote! {
            #[norito(decode_from_slice, decode_from_slice)]
            struct Demo(u32);
        };

        let Err(error) = ContainerAttr::parse(&input.attrs) else {
            panic!("duplicate shared flag must reject");
        };
        assert_eq!(error.to_string(), "duplicate decode_from_slice attribute");
    }
}

impl FieldAttr {
    /// Parse `#[norito(...)]` attributes from a field definition.
    fn parse(attrs: &[syn::Attribute]) -> syn::Result<Self> {
        let mut out = FieldAttr::default();
        for attr in attrs {
            if attr.path().is_ident("norito") {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("rename") {
                        let lit: syn::LitStr = meta.value()?.parse()?;
                        if out.rename.replace(lit.value()).is_some() {
                            return Err(meta.error("duplicate `rename` attribute"));
                        }
                    } else if meta.path.is_ident("skip") {
                        if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                            return Err(meta.error("`skip` does not take a value"));
                        }
                        if out.skip {
                            return Err(meta.error("duplicate `skip` attribute"));
                        }
                        out.skip = true;
                    } else if meta.path.is_ident("required") {
                        if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                            return Err(meta.error("`required` does not take a value"));
                        }
                        if out.required {
                            return Err(meta.error("duplicate `required` attribute"));
                        }
                        out.required = true;
                    } else if meta.path.is_ident("default") {
                        if out.default {
                            return Err(meta.error("duplicate `default` attribute"));
                        }
                        out.default = true;
                        if meta.input.peek(Token![=]) {
                            out.default_fn = Some(parse_helper_path(&meta)?);
                        }
                    } else if meta.path.is_ident("skip_serializing_if") {
                        let path = parse_helper_path(&meta)?;
                        if out.skip_serializing_if.replace(path).is_some() {
                            return Err(meta.error("duplicate `skip_serializing_if` attribute"));
                        }
                    } else if meta.path.is_ident("with") {
                        out.parse_with(&meta)?;
                    } else if meta.path.is_ident("json") {
                        out.parse_json_helper(&meta)?;
                    } else if meta.path.is_ident("bounded_with") {
                        out.parse_bounded_with(&meta)?;
                    } else if meta.path.is_ident("flatten") {
                        if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                            return Err(meta.error("`flatten` does not take a value"));
                        }
                        if out.flatten {
                            return Err(meta.error("duplicate `flatten` attribute"));
                        }
                        out.flatten = true;
                    } else {
                        return Err(meta.error("unknown `norito` field attribute"));
                    }
                    Ok(())
                })?;
            }
        }
        Ok(out)
    }

    /// Parse attributes after the derive entry point has validated every field.
    fn parse_validated(attrs: &[syn::Attribute]) -> Self {
        Self::parse(attrs).expect("field attributes must be validated before code generation")
    }
}

struct StructField<'a> {
    field: &'a syn::Field,
    attrs: FieldAttr,
    member: syn::Member,
}

fn struct_fields(fields: &Fields) -> Vec<StructField<'_>> {
    match fields {
        Fields::Named(named) => named
            .named
            .iter()
            .map(|field| StructField {
                field,
                attrs: FieldAttr::parse_validated(&field.attrs),
                member: syn::Member::Named(
                    field
                        .ident
                        .clone()
                        .expect("named fields must have identifiers"),
                ),
            })
            .collect(),
        Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .enumerate()
            .map(|(index, field)| StructField {
                field,
                attrs: FieldAttr::parse_validated(&field.attrs),
                member: syn::Member::Unnamed(Index::from(index)),
            })
            .collect(),
        Fields::Unit => Vec::new(),
    }
}

fn active_struct_fields<'fields, 'ast>(
    fields: &'fields [StructField<'ast>],
) -> impl Iterator<Item = &'fields StructField<'ast>> {
    fields.iter().filter(|field| !field.attrs.skip)
}

#[cfg(test)]
#[path = "tests/field_attrs.rs"]
mod field_attr_tests;

#[cfg(test)]
#[path = "tests/variant_attrs.rs"]
mod variant_attr_tests;

#[derive(Clone, Copy)]
enum EncodedLenKind {
    Hint,
    Exact,
}

fn enum_field_len_add(binding: &syn::Ident, ty: &syn::Type, kind: EncodedLenKind) -> TokenStream2 {
    let method = match kind {
        EncodedLenKind::Hint => format_ident!("encoded_len_hint"),
        EncodedLenKind::Exact => format_ident!("encoded_len_exact"),
    };
    let length = if u8_array_len(ty).is_some() {
        quote! { core::mem::size_of_val(#binding) }
    } else {
        quote! { norito::core::SerializePayload::#method(#binding)? }
    };
    quote! {
        let __e = #length;
        __sum = __sum
            .checked_add(norito::core::len_prefix_len(__e))?
            .checked_add(__e)?;
    }
}

/// Stream one enum-variant field into its length-prefixed frame.
///
/// `[u8; N]` fields write their raw bytes; every other field delegates to its
/// own `SerializePayload` implementation.
fn enum_field_serialize(binding: &syn::Ident, ty: &syn::Type) -> TokenStream2 {
    if u8_array_len(ty).is_some() {
        quote! {
            norito::core::write_len(writer, core::mem::size_of_val(#binding) as u64)?;
            writer.write_all(&#binding[..])?;
        }
    } else {
        quote! {
            norito::core::write_len_prefixed(writer, #binding)?;
        }
    }
}

fn derive_struct_len_body(parsed_fields: &[StructField<'_>], kind: EncodedLenKind) -> TokenStream2 {
    let method = match kind {
        EncodedLenKind::Hint => format_ident!("encoded_len_hint"),
        EncodedLenKind::Exact => format_ident!("encoded_len_exact"),
    };
    let len_var = match kind {
        EncodedLenKind::Hint => format_ident!("__h"),
        EncodedLenKind::Exact => format_ident!("__e"),
    };
    let parts = active_struct_fields(parsed_fields)
        .map(|field| {
            let member = &field.member;
            let length = if u8_array_len(&field.field.ty).is_some() && !field.attrs.flatten {
                quote! { core::mem::size_of_val(&self.#member) }
            } else {
                quote! { norito::core::SerializePayload::#method(&self.#member)? }
            };
            let sum = if field.attrs.flatten {
                quote! { __sum = __sum.checked_add(#len_var)?; }
            } else {
                quote! {
                    __sum = __sum
                        .checked_add(norito::core::len_prefix_len(#len_var))?
                        .checked_add(#len_var)?;
                }
            };
            quote! {
                let #len_var = #length;
                #sum
            }
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return quote! { Some(0) };
    }
    quote! {
        let mut __sum: usize = 0;
        #(#parts)*
        Some(__sum)
    }
}

fn generic_arguments(generics: &Generics) -> TokenStream2 {
    let params = generics.params.iter().map(|param| match param {
        syn::GenericParam::Type(ty) => ty.ident.to_token_stream(),
        syn::GenericParam::Lifetime(lifetime) => lifetime.lifetime.to_token_stream(),
        syn::GenericParam::Const(constant) => constant.ident.to_token_stream(),
    });
    if generics.params.is_empty() {
        TokenStream2::new()
    } else {
        quote! { < #( #params ),* > }
    }
}

fn struct_serialize_calls(
    fields: &[StructField<'_>],
    generics: &mut Generics,
) -> Vec<TokenStream2> {
    active_struct_fields(fields)
        .map(|field| {
            let member = &field.member;
            add_bound(
                generics,
                &field.field.ty,
                quote!(norito::core::SerializePayload),
            );
            if field.attrs.flatten {
                quote! {
                    norito::core::SerializePayload::serialize(&self.#member, writer)?;
                }
            } else if u8_array_len(&field.field.ty).is_some() {
                quote! {
                    let __len_bytes = core::mem::size_of_val(&self.#member);
                    norito::core::write_len(writer, __len_bytes as u64)?;
                    writer.write_all(&self.#member)?;
                }
            } else {
                quote! {
                    norito::core::write_len_prefixed(writer, &self.#member)?;
                }
            }
        })
        .collect()
}

/// Generate payload serialization and, when requested, an archived alias.
///
/// Each field is serialized in definition order and the resulting
/// implementation is bounded by that field's own `SerializePayload` trait.
fn derive_struct_serialize(
    ident: &syn::Ident,
    generics: &Generics,
    fields: &Fields,
    container_attrs: &[Attribute],
    generate_archived: bool,
) -> TokenStream2 {
    let parsed_fields = struct_fields(fields);
    let mut r#gen = generics.clone();
    let serialize_calls = struct_serialize_calls(&parsed_fields, &mut r#gen);
    let len_hint_body = derive_struct_len_body(&parsed_fields, EncodedLenKind::Hint);
    let len_exact_body = derive_struct_len_body(&parsed_fields, EncodedLenKind::Exact);

    let archived = format_ident!("Archived{}", ident);
    let alias_generics = generic_arguments(generics);
    let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
    let alias_decl = if !generate_archived || reuse_archived_alias(container_attrs) {
        quote! {}
    } else {
        let archived_doc = format!(
            "Archived Norito representation of `{}` generated by `#[derive(NoritoSerialize)]`.",
            ident
        );
        quote! {
            #[doc = #archived_doc]
            pub type #archived #alias_generics = norito::core::Archived<#ident #ty_generics>;
        }
    };
    quote! {
        #alias_decl
        impl #impl_generics norito::core::SerializePayload for #ident #ty_generics #where_clause {
            fn encoded_len_hint(&self) -> Option<usize> {
                let _norito_depth = norito::core::EncodeValueDepthGuard::enter().ok()?;
                #len_hint_body
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                let _norito_depth = norito::core::EncodeValueDepthGuard::enter().ok()?;
                #len_exact_body
            }
            fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> ::core::result::Result<(), norito::core::Error> {
                let _norito_depth = norito::core::EncodeValueDepthGuard::enter()?;
                use norito::core::WriteBytesExt;
                // Count each field before streaming it into its declared frame.
                #(#serialize_calls)*
                Ok(())
            }
        }
    }
}

/// Generate enum payload serialization and, when requested, an archived alias.
///
/// Each variant is preceded by a `u32` discriminant followed by its fields.
fn derive_enum_serialize(
    ident: &syn::Ident,
    generics: &Generics,
    data: &DataEnum,
    container_attrs: &[Attribute],
    generate_archived: bool,
) -> TokenStream2 {
    let mut r#gen = generics.clone();
    let mut arms = Vec::new();
    let mut hint_arms = Vec::new();
    let mut exact_arms = Vec::new();
    let discriminants = match enum_variant_indices(data) {
        Ok(discriminants) => discriminants,
        Err(error) => return error.to_compile_error(),
    };

    for (variant, disc) in data.variants.iter().zip(discriminants) {
        let v_ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    Self::#v_ident => {
                        norito::core::SerializePayload::serialize(&(#disc as u32), writer)?;
                    }
                });
                hint_arms.push(quote! { Self::#v_ident => Some(4) });
                exact_arms.push(quote! { Self::#v_ident => Some(4) });
            }
            Fields::Unnamed(fields) => {
                let bindings: Vec<_> = (0..fields.unnamed.len())
                    .map(|i| format_ident!("field{}", i))
                    .collect();
                let ignored_bindings = fields
                    .unnamed
                    .iter()
                    .zip(&bindings)
                    .filter_map(|(field, binding)| {
                        FieldAttr::parse_validated(&field.attrs)
                            .skip
                            .then_some(quote! { let _ = #binding; })
                    })
                    .collect::<Vec<_>>();
                let serialize_calls =
                    fields
                        .unnamed
                        .iter()
                        .zip(bindings.iter())
                        .filter_map(|(f, b)| {
                            if FieldAttr::parse_validated(&f.attrs).skip {
                                return None;
                            }
                            add_bound(&mut r#gen, &f.ty, quote!(norito::core::SerializePayload));
                            Some(enum_field_serialize(b, &f.ty))
                        });

                arms.push(quote! {
                    Self::#v_ident(#(#bindings),*) => {
                        norito::core::SerializePayload::serialize(&(#disc as u32), writer)?;
                        #(#ignored_bindings)*
                        #(#serialize_calls)*
                    }
                });
                for (kind, length_arms) in [
                    (EncodedLenKind::Hint, &mut hint_arms),
                    (EncodedLenKind::Exact, &mut exact_arms),
                ] {
                    let adds = fields
                        .unnamed
                        .iter()
                        .zip(&bindings)
                        .filter(|(field, _)| !FieldAttr::parse_validated(&field.attrs).skip)
                        .map(|(field, binding)| enum_field_len_add(binding, &field.ty, kind))
                        .collect::<Vec<_>>();
                    length_arms.push(quote! {
                        Self::#v_ident(#(#bindings),*) => {
                            let mut __sum: usize = 4;
                            #(#ignored_bindings)*
                            #(#adds)*
                            Some(__sum)
                        }
                    });
                }
            }
            Fields::Named(fields) => {
                let names: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| f.ident.as_ref().unwrap())
                    .collect();
                let ignored_names = fields
                    .named
                    .iter()
                    .zip(&names)
                    .filter_map(|(field, name)| {
                        FieldAttr::parse_validated(&field.attrs)
                            .skip
                            .then_some(quote! { let _ = #name; })
                    })
                    .collect::<Vec<_>>();
                let serialize_calls = fields.named.iter().filter_map(|f| {
                    if FieldAttr::parse_validated(&f.attrs).skip {
                        return None;
                    }
                    let name = f.ident.as_ref().unwrap();
                    add_bound(&mut r#gen, &f.ty, quote!(norito::core::SerializePayload));
                    Some(enum_field_serialize(name, &f.ty))
                });
                arms.push(quote! {
                    Self::#v_ident { #(#names),* } => {
                        norito::core::SerializePayload::serialize(&(#disc as u32), writer)?;
                        #(#ignored_names)*
                        #(#serialize_calls)*
                    }
                });
                for (kind, length_arms) in [
                    (EncodedLenKind::Hint, &mut hint_arms),
                    (EncodedLenKind::Exact, &mut exact_arms),
                ] {
                    let adds = fields
                        .named
                        .iter()
                        .zip(&names)
                        .filter(|(field, _)| !FieldAttr::parse_validated(&field.attrs).skip)
                        .map(|(field, name)| enum_field_len_add(name, &field.ty, kind))
                        .collect::<Vec<_>>();
                    length_arms.push(quote! {
                        Self::#v_ident { #(#names),* } => {
                            let mut __sum: usize = 4;
                            #(#ignored_names)*
                            #(#adds)*
                            Some(__sum)
                        }
                    });
                }
            }
        }
    }

    let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
    let params = r#gen
        .params
        .iter()
        .map(|param| match param {
            syn::GenericParam::Type(ty) => {
                let ident = &ty.ident;
                quote! { #ident }
            }
            syn::GenericParam::Lifetime(lt) => {
                let lt = &lt.lifetime;
                quote! { #lt }
            }
            syn::GenericParam::Const(c) => {
                let ident = &c.ident;
                quote! { #ident }
            }
        })
        .collect::<Vec<_>>();
    let alias_generics = if params.is_empty() {
        quote! {}
    } else {
        quote! { < #( #params ),* > }
    };
    let archived = format_ident!("Archived{}", ident);
    let alias_decl = if !generate_archived || reuse_archived_alias(container_attrs) {
        quote! {}
    } else {
        let archived_doc = format!(
            "Archived Norito representation of `{}` generated by `#[derive(NoritoSerialize)]`.",
            ident
        );
        quote! {
            #[doc = #archived_doc]
            pub type #archived #alias_generics = norito::core::Archived<#ident #ty_generics>;
        }
    };
    quote! {
        #alias_decl
        impl #impl_generics norito::core::SerializePayload for #ident #ty_generics #where_clause {
            fn encoded_len_hint(&self) -> Option<usize> {
                let _norito_depth = norito::core::EncodeValueDepthGuard::enter().ok()?;
                match self { #( #hint_arms ),* }
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                let _norito_depth = norito::core::EncodeValueDepthGuard::enter().ok()?;
                match self { #( #exact_arms ),* }
            }
            fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> ::core::result::Result<(), norito::core::Error> {
                let _norito_depth = norito::core::EncodeValueDepthGuard::enter()?;
                use norito::core::WriteBytesExt;
                match self {
                    #(#arms),*
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod deserialize_codegen_tests {
    include!("tests/deserialize_codegen.rs");
}

#[proc_macro_derive(NoritoSerialize, attributes(codec, norito))]
/// Derive payload serialization and an archived alias.
///
/// Typed framing is supplied by the blanket `NoritoSerialize` implementation
/// when this type also has a separate `NoritoSchema` declaration.
/// A payload implementation alone does not grant typed frame ownership.
///
/// ```compile_fail
/// #[derive(norito::NoritoSerialize)]
/// struct Field(u32);
/// let _ = norito::to_bytes(&Field(7));
/// ```
pub fn derive_norito_serialize(input: TokenStream) -> TokenStream {
    expand_serialize(parse_macro_input!(input as DeriveInput), true)
}

/// Derive only object-safe bare payload serialization, without a frame identity.
#[proc_macro_derive(SerializePayload, attributes(codec, norito))]
pub fn derive_serialize_payload(input: TokenStream) -> TokenStream {
    expand_serialize(parse_macro_input!(input as DeriveInput), false)
}

fn expand_serialize(input: DeriveInput, generate_archived: bool) -> TokenStream {
    if let Err(error) = validate_data_field_attrs(&input.data) {
        return error.to_compile_error().into();
    }
    if let Err(error) = ContainerAttr::parse(&input.attrs) {
        return error.to_compile_error().into();
    }
    match &input.data {
        Data::Struct(data) => derive_struct_serialize(
            &input.ident,
            &input.generics,
            &data.fields,
            &input.attrs,
            generate_archived,
        )
        .into(),
        Data::Enum(data) => derive_enum_serialize(
            &input.ident,
            &input.generics,
            data,
            &input.attrs,
            generate_archived,
        )
        .into(),
        _ => syn::Error::new_spanned(
            &input.ident,
            if generate_archived {
                "NoritoSerialize only supports structs and enums"
            } else {
                "SerializePayload only supports structs and enums"
            },
        )
        .to_compile_error()
        .into(),
    }
}

#[proc_macro_derive(NoritoDeserialize, attributes(codec, norito))]
/// Derive payload reconstruction.
///
/// Typed framing is supplied by the blanket `NoritoDeserialize` implementation
/// when this type also has a separate `NoritoSchema` declaration.
///
/// `#[norito(validate = "Self::validate_decoded")]` calls the supplied function
/// once after successful binary reconstruction. The function consumes `Self`
/// and returns `Result<Self, norito::Error>`; errors propagate unchanged. It must
/// preserve the decoded canonical fields rather than normalize external input.
/// The hook also runs for generated slice decoders. It does not run during
/// serialization or JSON decoding.
/// A payload implementation alone does not grant typed frame ownership.
///
/// ```compile_fail
/// #[derive(norito::NoritoSerialize, norito::NoritoDeserialize)]
/// struct Field(u32);
/// let _ = norito::from_bytes::<Field>(&[]);
/// ```
pub fn derive_norito_deserialize(input: TokenStream) -> TokenStream {
    expand_deserialize(
        parse_macro_input!(input as DeriveInput),
        "NoritoDeserialize",
    )
}

/// Derive payload reconstruction without a typed frame identity.
///
/// Validation and exact field-consumption checks are shared with the typed
/// decoder. Frame identities belong exclusively to `NoritoSchema`.
///
/// ```compile_fail
/// #[derive(norito::DeserializePayload)]
/// #[norito(schema_name = "not.a.payload.property")]
/// struct Field(u32);
/// ```
#[proc_macro_derive(DeserializePayload, attributes(codec, norito))]
pub fn derive_deserialize_payload(input: TokenStream) -> TokenStream {
    expand_deserialize(
        parse_macro_input!(input as DeriveInput),
        "DeserializePayload",
    )
}

fn expand_deserialize(input: DeriveInput, derive_name: &str) -> TokenStream {
    if let Err(error) = validate_data_field_attrs(&input.data) {
        return error.to_compile_error().into();
    }
    if let Err(error) = ContainerAttr::parse(&input.attrs) {
        return error.to_compile_error().into();
    }
    match &input.data {
        Data::Struct(data) => {
            derive_struct_deserialize(&input.ident, &input.generics, &data.fields, &input.attrs)
                .into()
        }
        Data::Enum(data) => {
            derive_enum_deserialize(&input.ident, &input.generics, data, &input.attrs).into()
        }
        _ => syn::Error::new_spanned(
            &input.ident,
            format!("{derive_name} only supports structs and enums"),
        )
        .to_compile_error()
        .into(),
    }
}

// ===== FastJson (prototype) =====

struct JsonFlattenParts {
    generics: Generics,
    inits: Vec<TokenStream2>,
    parses: Vec<TokenStream2>,
    flattens: Vec<TokenStream2>,
    finals: Vec<TokenStream2>,
}

fn json_flatten_parts(
    generics: &Generics,
    named: &syn::FieldsNamed,
    container_attrs: &ContainerAttr,
    fast: bool,
) -> syn::Result<JsonFlattenParts> {
    let mut generics = generics.clone();
    let mut inits = Vec::new();
    let mut parses = Vec::new();
    let mut flattens = Vec::new();
    let mut finals = Vec::new();
    let error = if fast {
        quote!(norito::Error)
    } else {
        quote!(norito::json::Error)
    };
    for field in &named.named {
        let attrs = FieldAttr::parse(&field.attrs)?;
        let field_ident = field.ident.as_ref().unwrap();
        let ty = &field.ty;
        if attrs.skip {
            if attrs.default || attrs.default_fn.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "#[norito(skip)] cannot be combined with #[norito(default)]",
                ));
            }
            add_bound(&mut generics, ty, quote!(::core::default::Default));
            finals.push(quote! { #field_ident: ::core::default::Default::default() });
            continue;
        }
        attrs.require_json_deserialize_bound(&mut generics, ty);
        if fast && attrs.flatten {
            attrs.require_json_serialize_bound(&mut generics, ty);
        }
        let variable = format_ident!("__norito_field_{}", field_ident);
        inits.push(quote! {
            let mut #variable: ::core::option::Option<#ty> =
                ::core::option::Option::None;
        });
        if attrs.flatten {
            let parse = attrs
                .deserialize_from_value(ty, quote!(norito::json::Value::Object(__map.clone())));
            flattens.push(quote! {
                let parsed = #parse;
                let __used = norito::json::to_value(&parsed)?;
                if let norito::json::Value::Object(__used_map) = __used {
                    for __key in __used_map.keys() {
                        __map.remove(__key);
                    }
                } else {
                    return Err(#error::Message(
                        "#[norito(flatten)] field must deserialize to an object".into(),
                    ));
                }
                #variable = ::core::option::Option::Some(parsed);
            });
        } else {
            let key = container_attrs.rename_field(field_ident, &attrs);
            let key = syn::LitStr::new(&key, proc_macro2::Span::call_site());
            let parse = attrs.deserialize_from_value(ty, quote!(value));
            parses.push(quote! {
                if let ::core::option::Option::Some(value) = __map.remove(#key) {
                    let parsed = #parse;
                    #variable = ::core::option::Option::Some(parsed);
                }
            });
        }
        let missing_key = container_attrs.rename_field(field_ident, &attrs);
        let missing_key = syn::LitStr::new(&missing_key, proc_macro2::Span::call_site());
        let default = if let Some(path) = &attrs.default_fn {
            Some(quote! { (#path)() })
        } else if attrs.default {
            add_bound(&mut generics, ty, quote!(::core::default::Default));
            Some(quote! { ::core::default::Default::default() })
        } else {
            None
        };
        let value = if is_option_type(ty) && !attrs.required {
            default.map_or_else(
                || quote! { #variable.unwrap_or(::core::option::Option::None) },
                |default| quote! { #variable.unwrap_or_else(|| #default) },
            )
        } else if let Some(default) = default {
            quote! { #variable.unwrap_or_else(|| #default) }
        } else if fast {
            quote! {
                #variable.ok_or_else(|| norito::Error::from(
                    norito::json::Error::missing_field(#missing_key)
                ))?
            }
        } else {
            quote! {
                #variable.ok_or_else(|| norito::json::Error::missing_field(#missing_key))?
            }
        };
        finals.push(quote! { #field_ident: #value });
    }
    Ok(JsonFlattenParts {
        generics,
        inits,
        parses,
        flattens,
        finals,
    })
}

fn derive_fast_json_struct_flatten(
    ident: &syn::Ident,
    generics: &Generics,
    named: &syn::FieldsNamed,
    container_attrs: &ContainerAttr,
) -> syn::Result<TokenStream2> {
    let JsonFlattenParts {
        generics: r#gen,
        inits: init_stmts,
        parses: parse_stmts,
        flattens: flatten_stmts,
        finals,
    } = json_flatten_parts(generics, named, container_attrs, true)?;

    let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
    let reject_unknown_fields = if container_attrs.deny_unknown_fields {
        quote! {
            if let ::core::option::Option::Some(__key) = __map.keys().next() {
                return Err(norito::json::Error::unknown_field(__key.clone()).into());
            }
        }
    } else {
        TokenStream2::new()
    };
    Ok(quote! {
        impl<'a> #impl_generics norito::json::FastFromJson<'a> for #ident #ty_generics #where_clause {
            fn parse<'arena>(
                w: &mut norito::json::TapeWalker<'a>,
                _arena: &'arena mut norito::json::Arena,
            ) -> ::core::result::Result<Self, norito::Error> {
                w.ensure_document_depth()?;
                let mut parser = norito::json::Parser::new_at(w.input(), w.raw_pos());
                let value = norito::json::Value::json_deserialize(&mut parser)?;
                w.sync_to_raw(parser.position());
                let mut __map = match value {
                    norito::json::Value::Object(map) => map,
                    _ => {
                        return Err(norito::Error::Message("expected JSON object".into()));
                    }
                };
                #(#init_stmts)*
                #(#parse_stmts)*
                #(#flatten_stmts)*
                #reject_unknown_fields
                Ok(Self { #(#finals),* })
            }
        }
    })
}

fn type_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    match ty {
        // Macro-forwarded type fragments and parentheses preserve the inner type.
        syn::Type::Group(group) => type_ident(&group.elem),
        syn::Type::Paren(paren) => type_ident(&paren.elem),
        syn::Type::Path(path) => path.path.segments.last().map(|segment| &segment.ident),
        _ => None,
    }
}

fn single_type_argument(path: &syn::TypePath) -> Option<&syn::Type> {
    let arguments = &path.path.segments.last()?.arguments;
    let syn::PathArguments::AngleBracketed(arguments) = arguments else {
        return None;
    };
    if arguments.args.len() != 1 {
        return None;
    }
    match arguments.args.first()? {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    }
}

fn fast_json_assign_field(
    name: &syn::Ident,
    key: &syn::LitStr,
    bitmask: u128,
    value: TokenStream2,
) -> TokenStream2 {
    quote! {
        let v = #value;
        if (__seen & #bitmask) != 0 {
            return Err(norito::Error::Message(
                concat!("duplicate field `", #key, "`").into(),
            ));
        }
        __seen |= #bitmask;
        #name = Some(v);
    }
}

fn fast_json_parser_field(
    ty: &syn::Type,
    name: &syn::Ident,
    key: &syn::LitStr,
    bitmask: u128,
) -> TokenStream2 {
    let value = quote! {{
        let s_in = w.input();
        let mut p = norito::json::Parser::new_at(s_in, w.raw_pos());
        let parsed: #ty =
            <#ty as norito::json::JsonDeserialize>::json_deserialize(&mut p)?;
        w.sync_to_raw(p.position());
        parsed
    }};
    fast_json_assign_field(name, key, bitmask, value)
}

fn fast_json_vec_field(
    inner: &syn::Type,
    name: &syn::Ident,
    key: &syn::LitStr,
    bitmask: u128,
) -> TokenStream2 {
    let value = match type_ident(inner).map(ToString::to_string).as_deref() {
        Some("u64") => quote! { w.parse_u64_inline()? },
        Some("u32") => quote! {{
            let value = w.parse_u64_inline()?;
            u32::try_from(value)
                .map_err(|_| norito::Error::Message("u32 overflow".into()))?
        }},
        Some("u128") => quote! { w.parse_u128_inline()? },
        Some("i64") => quote! { w.parse_i64_inline()? },
        Some("f64") => quote! { w.parse_f64_inline()? },
        Some("bool") => quote! { w.parse_bool_inline()? },
        Some("String") => quote! { w.parse_string_ref_inline(arena)?.to_string() },
        _ => quote! { <#inner as norito::json::FastFromJson>::parse(w, arena)? },
    };
    quote! {
        w.skip_ws();
        if let Some((off, b'[')) = w.peek_struct() {
            let _ = w.next_struct();
            w.sync_to_raw(off + 1);
        } else {
            return Err(norito::Error::Message("expected array".into()));
        }
        let mut tmp: ::std::vec::Vec<#inner> = ::std::vec::Vec::new();
        loop {
            w.skip_ws();
            let __raw = w.raw_pos();
            let __bytes = w.input().as_bytes();
            if __raw < __bytes.len() && __bytes[__raw] == b']' {
                if let Some((off, ch)) = w.peek_struct() {
                    if ch == b']' && off == __raw {
                        let _ = w.next_struct();
                        w.sync_to_raw(off + 1);
                    } else {
                        w.sync_to_raw(__raw + 1);
                    }
                } else {
                    w.sync_to_raw(__raw + 1);
                }
                break;
            }
            let v = #value;
            tmp.push(v);
            let _ = w.consume_comma_if_present()?;
        }
        if (__seen & #bitmask) != 0 {
            return Err(norito::Error::Message(
                concat!("duplicate field `", #key, "`").into(),
            ));
        }
        __seen |= #bitmask;
        #name = Some(tmp);
    }
}

fn fast_json_option_field(
    inner: &syn::Type,
    name: &syn::Ident,
    key: &syn::LitStr,
    bitmask: u128,
) -> Option<TokenStream2> {
    let value = match type_ident(inner).map(ToString::to_string).as_deref()? {
        "u64" => quote! { w.parse_u64_inline()? },
        "u32" => quote! {{
            let value = w.parse_u64_inline()?;
            u32::try_from(value)
                .map_err(|_| norito::Error::Message("u32 overflow".into()))?
        }},
        "u128" => quote! { w.parse_u128_inline()? },
        "i64" => quote! { w.parse_i64_inline()? },
        "f64" => quote! { w.parse_f64_inline()? },
        "bool" => quote! { w.parse_bool_inline()? },
        "String" => quote! { w.parse_string_ref_inline(arena)?.to_string() },
        _ => return None,
    };
    let option = quote! {{
        w.skip_ws();
        let bytes = w.input().as_bytes();
        if w.raw_pos() + 4 <= bytes.len()
            && &bytes[w.raw_pos()..w.raw_pos() + 4] == b"null"
        {
            w.sync_to_raw(w.raw_pos() + 4);
            None
        } else {
            Some(#value)
        }
    }};
    Some(fast_json_assign_field(name, key, bitmask, option))
}

fn fast_json_field_parser(
    ty: &syn::Type,
    name: &syn::Ident,
    key: &syn::LitStr,
    bitmask: u128,
) -> TokenStream2 {
    match ty {
        syn::Type::Path(path) => match type_ident(ty).map(ToString::to_string).as_deref() {
            Some("String") => fast_json_assign_field(
                name,
                key,
                bitmask,
                quote! { w.parse_string_ref_inline(arena)?.to_string() },
            ),
            Some("bool") => {
                fast_json_assign_field(name, key, bitmask, quote! { w.parse_bool_inline()? })
            }
            Some("u64") => {
                fast_json_assign_field(name, key, bitmask, quote! { w.parse_u64_inline()? })
            }
            Some("u32") => fast_json_assign_field(
                name,
                key,
                bitmask,
                quote! {{
                    let value = w.parse_u64_inline()?;
                    u32::try_from(value)
                        .map_err(|_| norito::Error::Message("u32 overflow".into()))?
                }},
            ),
            Some("Vec") => single_type_argument(path).map_or_else(
                || fast_json_parser_field(ty, name, key, bitmask),
                |inner| fast_json_vec_field(inner, name, key, bitmask),
            ),
            Some("StrRef") => fast_json_assign_field(
                name,
                key,
                bitmask,
                quote! { w.parse_string_ref_inline(arena)? },
            ),
            Some("Option") => single_type_argument(path)
                .and_then(|inner| fast_json_option_field(inner, name, key, bitmask))
                .unwrap_or_else(|| fast_json_parser_field(ty, name, key, bitmask)),
            _ => fast_json_parser_field(ty, name, key, bitmask),
        },
        syn::Type::Reference(reference) if matches!(&*reference.elem, syn::Type::Path(path) if path.path.is_ident("str")) => {
            fast_json_assign_field(
                name,
                key,
                bitmask,
                quote! {{
                    let sref = w.parse_string_ref_inline(arena)?;
                    match sref {
                        norito::json::StrRef::Borrowed(value) => value,
                        norito::json::StrRef::Owned(value) => value,
                    }
                }},
            )
        }
        _ => fast_json_parser_field(ty, name, key, bitmask),
    }
}

#[proc_macro_derive(FastJson, attributes(norito))]
pub fn derive_fast_json(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident,
        data,
        attrs,
        generics,
        ..
    } = parse_macro_input!(input);
    if let Err(error) = validate_data_field_attrs(&data) {
        return error.to_compile_error().into();
    }
    let container_attrs = match ContainerAttr::parse(&attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.to_compile_error().into(),
    };
    let body = match data {
        Data::Struct(ds) => {
            match ds.fields {
                Fields::Named(named) => {
                    if named
                        .named
                        .iter()
                        .any(|f| FieldAttr::parse_validated(&f.attrs).flatten)
                    {
                        match derive_fast_json_struct_flatten(
                            &ident,
                            &generics,
                            &named,
                            &container_attrs,
                        ) {
                            Ok(tokens) => tokens,
                            Err(err) => return err.to_compile_error().into(),
                        }
                    } else {
                        // Hashed-key dispatch using TapeWalker::read_key_hash with
                        // last_key() collision guard. This avoids building a temporary
                        // String for the key and speeds up large object decoding.

                        let mut inits = Vec::new();
                        let mut cases = Vec::new();
                        let mut finals = Vec::new();
                        let reject_unknown_field = if container_attrs.deny_unknown_fields {
                            quote! {
                                return Err(norito::json::Error::unknown_field(w.last_key()).into());
                            }
                        } else {
                            quote! {
                                w.skip_value()?;
                            }
                        };

                        for (idx, f) in named.named.iter().enumerate() {
                            let name = f.ident.as_ref().unwrap();
                            let attrs = FieldAttr::parse_validated(&f.attrs);
                            let key = container_attrs.rename_field(name, &attrs);
                            let key_lit = syn::LitStr::new(&key, proc_macro2::Span::call_site());
                            // Precompute 64-bit key hash at compile-time to match TapeWalker
                            let key_hash_expr: syn::Expr =
                                syn::parse_quote! { norito::json::key_hash_const(#key_lit) };

                            inits.push(quote! { let mut #name = None; });

                            let bitmask: u128 = 1u128 << idx;
                            let parse_body = fast_json_field_parser(&f.ty, name, &key_lit, bitmask);

                            let default_expr = if let Some(path) = &attrs.default_fn {
                                quote! { #path() }
                            } else {
                                quote! { ::core::default::Default::default() }
                            };

                            cases.push(quote! {
                                x if x == #key_hash_expr => {
                                    if w.last_key() == #key_lit {
                                        #parse_body
                                    } else {
                                        // A hash collision remains an unknown key after the
                                        // exact key comparison.
                                        #reject_unknown_field
                                    }
                                }
                            });
                            // Required vs optional: for Option<T> fields, absence should map to None
                            let is_option = is_option_type(&f.ty);
                            if attrs.default {
                                finals
                                    .push(quote! { #name: #name.unwrap_or_else(|| #default_expr) });
                            } else if is_option && !attrs.required {
                                finals.push(quote! { #name: #name.unwrap_or(None) });
                            } else {
                                finals.push(quote! {
                                    #name: #name.ok_or_else(|| norito::Error::from(
                                        norito::json::Error::missing_field(#key_lit)
                                    ))?
                                });
                            }
                        }

                        quote! {
                            impl<'a> norito::json::FastFromJson<'a> for #ident {
                                fn parse<'arena>(w: &mut norito::json::TapeWalker<'a>, arena: &'arena mut norito::json::Arena) -> ::core::result::Result<Self, norito::Error> {
                                    w.ensure_document_depth()?;
                                    w.expect_object_start()?;
                                    #(#inits)*
                                    let mut __seen: u128 = 0;
                                    while !w.peek_object_end()? {
                                        // Read hashed key via TapeWalker, then dispatch.
                                        let __kh = w.read_key_hash()?;
                                        w.expect_colon_resync()?;
                                        match __kh {
                                            #(#cases),*,
                                            _ => {
                                                #reject_unknown_field
                                            }
                                        }
                                        let _ = w.consume_comma_if_present()?;
                                    }
                                    w.expect_object_end()?;
                                    Ok(Self { #(#finals),* })
                                }
                            }
                        }
                    }
                }
                _ => quote! { compile_error!("FastJson only supports named structs"); },
            }
        }
        Data::Enum(de) => {
            let enum_attr = match EnumAttr::parse(&attrs) {
                Ok(attr) => attr,
                Err(err) => return err.to_compile_error().into(),
            };
            let tag = match enum_attr.tag {
                Some(t) => t,
                None => {
                    return syn::Error::new_spanned(
                        &ident,
                        "FastJson enum support currently requires #[norito(tag = ...)]",
                    )
                    .to_compile_error()
                    .into();
                }
            };
            let content = match enum_attr.content {
                Some(c) => c,
                None => {
                    return syn::Error::new_spanned(
                        &ident,
                        "FastJson enum support currently requires #[norito(content = ...)]",
                    )
                    .to_compile_error()
                    .into();
                }
            };

            let tag_lit = syn::LitStr::new(&tag, proc_macro2::Span::call_site());
            let content_lit = syn::LitStr::new(&content, proc_macro2::Span::call_site());
            let tag_hash_expr: syn::Expr =
                syn::parse_quote! { norito::json::key_hash_const(#tag_lit) };
            let content_hash_expr: syn::Expr =
                syn::parse_quote! { norito::json::key_hash_const(#content_lit) };
            let reject_unknown_variant_field = if container_attrs.deny_unknown_fields {
                quote! {
                    return Err(norito::json::Error::unknown_field(key).into());
                }
            } else {
                quote! {
                    __parser.skip_value()?;
                }
            };
            let reject_unknown_envelope_field = if container_attrs.deny_unknown_fields {
                quote! {
                    return Err(norito::json::Error::unknown_field(w.last_key()).into());
                }
            } else {
                quote! {
                    w.skip_value()?;
                }
            };

            let mut tag_match_arms = Vec::new();
            let mut parse_arms = Vec::new();

            for (idx, variant) in de.variants.iter().enumerate() {
                if let Err(err) = VariantAttr::parse(&variant.attrs) {
                    return err.to_compile_error().into();
                }
                let idx_lit = syn::LitInt::new(&idx.to_string(), proc_macro2::Span::call_site());
                let v_ident = &variant.ident;
                let v_attr = VariantAttr::parse(&variant.attrs).expect("validated above");
                let variant_name = container_attrs.rename_variant(v_ident, &v_attr);
                let variant_lit = syn::LitStr::new(&variant_name, proc_macro2::Span::call_site());

                tag_match_arms.push(quote! { #variant_lit => #idx_lit as u8, });

                match &variant.fields {
                    Fields::Unit => {
                        parse_arms.push(quote! {
                            #idx_lit => {
                                let mut __parser = norito::json::Parser::new(__norito_content_slice);
                                __parser.parse_null()?;
                                __parser.skip_ws();
                                if !__parser.eof() {
                                    Err(norito::Error::Message(format!(
                                        "unexpected content for unit variant `{}`",
                                        #variant_lit
                                    ).into()))
                                } else {
                                    Ok(Self::#v_ident)
                                }
                            }
                        });
                    }
                    Fields::Unnamed(fields) => {
                        for field in fields.unnamed.iter() {
                            let attrs = FieldAttr::parse_validated(&field.attrs);
                            if attrs.skip {
                                return syn::Error::new_spanned(
                                    field,
                                    "#[norito(skip)] is not supported on enum tuple variants",
                                )
                                .to_compile_error()
                                .into();
                            }
                            if attrs.flatten {
                                return syn::Error::new_spanned(
                                    field,
                                    "#[norito(flatten)] is not supported on enum tuple variants",
                                )
                                .to_compile_error()
                                .into();
                            }
                        }

                        if fields.unnamed.len() == 1 {
                            let field = &fields.unnamed[0];
                            let attrs = FieldAttr::parse_validated(&field.attrs);
                            let ty = &field.ty;
                            let deserialize_call =
                                attrs.deserializer_call(ty, quote!(&mut __parser));
                            parse_arms.push(quote! {
                                #idx_lit => {
                                    let mut __parser = norito::json::Parser::new(__norito_content_slice);
                                    let value = #deserialize_call;
                                    __parser.skip_ws();
                                    if !__parser.eof() {
                                        Err(norito::Error::Message(format!(
                                            "unexpected trailing data for variant `{}`",
                                            #variant_lit
                                        ).into()))
                                    } else {
                                        Ok(Self::#v_ident(value))
                                    }
                                }
                            });
                        } else {
                            let mut inits = Vec::new();
                            let mut match_tokens = Vec::new();
                            let mut finals = Vec::new();
                            for (tuple_idx, field) in fields.unnamed.iter().enumerate() {
                                let attrs = FieldAttr::parse_validated(&field.attrs);
                                let ty = &field.ty;
                                let binding = format_ident!("__norito_variant_{tuple_idx}");
                                inits.push(quote! {
                                    let mut #binding: ::core::option::Option<#ty> = ::core::option::Option::None;
                                });
                                let missing_text = format!(
                                    "missing tuple index {tuple_idx} for variant `{variant_name}`"
                                );
                                let missing_msg =
                                    syn::LitStr::new(&missing_text, proc_macro2::Span::call_site());
                                let deserialize_call =
                                    attrs.deserializer_call(ty, quote!(&mut __parser));
                                let tuple_idx_lit = syn::LitInt::new(
                                    &tuple_idx.to_string(),
                                    proc_macro2::Span::call_site(),
                                );
                                match_tokens.push(quote! {
                                    #tuple_idx_lit => {
                                        let value = #deserialize_call;
                                        #binding = ::core::option::Option::Some(value);
                                    }
                                });
                                finals.push(quote! {
                                    #binding.ok_or_else(|| norito::Error::Message(#missing_msg.into()))?
                                });
                            }
                            let constructor = quote! { Self::#v_ident( #( #finals ),* ) };
                            parse_arms.push(quote! {
                                #idx_lit => {
                                    let mut __parser = norito::json::Parser::new(__norito_content_slice);
                                    __parser.skip_ws();
                                    __parser.expect(b'[')?;
                                    __parser.skip_ws();
                                    #(#inits)*
                                    let mut __idx = 0usize;
                                    if !__parser.try_consume_char(b']')? {
                                        let mut __first = true;
                                        loop {
                                            if !__first {
                                                __parser.expect(b',')?;
                                            }
                                            __first = false;
                                            match __idx {
                                                #( #match_tokens ),*,
                                                _ => {
                                                    __parser.skip_value()?;
                                                    return Err(norito::Error::Message(format!(
                                                        "too many elements for variant `{}`",
                                                        #variant_lit
                                                    ).into()));
                                                }
                                            }
                                            __idx += 1;
                                            __parser.skip_ws();
                                            if __parser.try_consume_char(b']')? {
                                                break;
                                            }
                                        }
                                    }
                                    __parser.skip_ws();
                                    if !__parser.eof() {
                                        return Err(norito::Error::Message(format!(
                                            "unexpected trailing data for variant `{}`",
                                            #variant_lit
                                        ).into()));
                                    }
                                    Ok(#constructor)
                                }
                            });
                        }
                    }
                    Fields::Named(fields) => {
                        for field in fields.named.iter() {
                            let attrs = FieldAttr::parse_validated(&field.attrs);
                            if attrs.skip {
                                return syn::Error::new_spanned(
                                    field,
                                    "#[norito(skip)] is not supported on enum struct variants",
                                )
                                .to_compile_error()
                                .into();
                            }
                            if attrs.flatten {
                                return syn::Error::new_spanned(
                                    field,
                                    "#[norito(flatten)] is not supported on enum struct variants",
                                )
                                .to_compile_error()
                                .into();
                            }
                        }

                        let mut inits = Vec::new();
                        let mut match_tokens = Vec::new();
                        let mut finals = Vec::new();
                        for field in fields.named.iter() {
                            let attrs = FieldAttr::parse_validated(&field.attrs);
                            let field_ident = field.ident.as_ref().unwrap();
                            let key = container_attrs.rename_field(field_ident, &attrs);
                            let key_lit = syn::LitStr::new(&key, proc_macro2::Span::call_site());
                            let var_ident = format_ident!("__norito_variant_field_{}", field_ident);
                            let ty = &field.ty;
                            inits.push(quote! { let mut #var_ident: ::core::option::Option<#ty> = ::core::option::Option::None; });
                            let duplicate_text =
                                format!("duplicate field `{key}` in variant `{variant_name}`");
                            let duplicate_msg =
                                syn::LitStr::new(&duplicate_text, proc_macro2::Span::call_site());
                            let deserialize_call =
                                attrs.deserializer_call(ty, quote!(&mut __parser));
                            match_tokens.push(quote! {
                                #key_lit => {
                                    if #var_ident.is_some() {
                                        return Err(norito::Error::Message(#duplicate_msg.into()));
                                    }
                                    let value = #deserialize_call;
                                    #var_ident = ::core::option::Option::Some(value);
                                }
                            });
                            finals.push(quote! {
                                #field_ident: #var_ident.ok_or_else(|| norito::Error::from(
                                    norito::json::Error::missing_field(#key_lit)
                                ))?
                            });
                        }
                        parse_arms.push(quote! {
                            #idx_lit => {
                                let mut __parser = norito::json::Parser::new(__norito_content_slice);
                                __parser.skip_ws();
                                if !__parser.try_consume_char(b'{')? {
                                    return Err(norito::Error::Message(format!(
                                        "expected object for variant `{}`",
                                        #variant_lit
                                    ).into()));
                                }
                                #(#inits)*
                                __parser.skip_ws();
                                if !__parser.try_consume_char(b'}')? {
                                    loop {
                                        __parser.skip_ws();
                                        let key = __parser.parse_string()?;
                                        __parser.expect(b':')?;
                                        match key.as_str() {
                                            #( #match_tokens ),*,
                                            _ => {
                                                #reject_unknown_variant_field
                                            }
                                        }
                                        __parser.skip_ws();
                                        if __parser.try_consume_char(b'}')? {
                                            break;
                                        }
                                        __parser.expect(b',')?;
                                    }
                                }
                                __parser.skip_ws();
                                if !__parser.eof() {
                                    return Err(norito::Error::Message(format!(
                                        "unexpected trailing data for variant `{}`",
                                        #variant_lit
                                    ).into()));
                                }
                                Ok(Self::#v_ident { #( #finals ),* })
                            }
                        });
                    }
                }
            }

            let unknown_tag_msg = syn::LitStr::new(
                &format!("unknown variant `{{}}` for {ident}"),
                proc_macro2::Span::call_site(),
            );
            let missing_tag_msg =
                syn::LitStr::new("missing tag field", proc_macro2::Span::call_site());
            let missing_content_msg =
                syn::LitStr::new("missing content field", proc_macro2::Span::call_site());

            let parse_match = quote! {
                match __idx_local {
                    #(#parse_arms),*,
                    _ => Err(norito::Error::Message("invalid enum variant index".into())),
                }
            };

            quote! {
                impl<'a> norito::json::FastFromJson<'a> for #ident {
                    fn parse<'arena>(
                        w: &mut norito::json::TapeWalker<'a>,
                        arena: &'arena mut norito::json::Arena,
                    ) -> ::core::result::Result<Self, norito::Error> {
                        w.ensure_document_depth()?;
                        let __input = w.input();
                        w.expect_object_start()?;
                        let mut __variant_idx: ::core::option::Option<u8> = ::core::option::Option::None;
                        let mut __content_slice: ::core::option::Option<&str> = ::core::option::Option::None;
                        let mut __result: ::core::option::Option<Self> = ::core::option::Option::None;

                        while !w.peek_object_end()? {
                            let __kh = w.read_key_hash()?;
                            w.expect_colon_resync()?;
                            if __kh == #tag_hash_expr && w.last_key() == #tag_lit {
                                if __variant_idx.is_some() {
                                    return Err(norito::json::Error::duplicate_field(#tag_lit).into());
                                }
                                let __tag_ref = w.parse_string_ref_inline(arena)?;
                                let __tag_str: &str = match __tag_ref {
                                    norito::json::StrRef::Borrowed(s) => s,
                                    norito::json::StrRef::Owned(s) => s,
                                };
                                let __idx = match __tag_str {
                                    #(#tag_match_arms)*
                                    other => {
                                        return Err(norito::Error::Message(format!(#unknown_tag_msg, other).into()));
                                    }
                                };
                                __variant_idx = Some(__idx);
                                if let Some(__slice) = __content_slice.take() {
                                    let __norito_content_slice = __slice;
                                    let __value = {
                                        let __idx_local = __idx;
                                        #parse_match
                                    }?;
                                    __result = Some(__value);
                                }
                            } else if __kh == #content_hash_expr && w.last_key() == #content_lit {
                                if __content_slice.is_some() || __result.is_some() {
                                    return Err(norito::json::Error::duplicate_field(#content_lit).into());
                                }
                                let __start = w.raw_pos();
                                let mut __parser = norito::json::Parser::new_at(__input, __start);
                                __parser.skip_value()?;
                                let __end = __parser.position();
                                w.sync_to_raw(__end);
                                let __slice = &__input[__start..__end];
                                if let Some(__idx) = __variant_idx {
                                    let __norito_content_slice = __slice;
                                    let __value = {
                                        let __idx_local = __idx;
                                        #parse_match
                                    }?;
                                    __result = Some(__value);
                                } else {
                                    __content_slice = Some(__slice);
                                }
                            } else {
                                #reject_unknown_envelope_field
                            }
                            let _ = w.consume_comma_if_present()?;
                        }
                        w.expect_object_end()?;

                        if let Some(value) = __result {
                            return Ok(value);
                        }

                        let __idx = __variant_idx.ok_or_else(|| norito::Error::Message(#missing_tag_msg.into()))?;
                        let __slice = __content_slice.ok_or_else(|| norito::Error::Message(#missing_content_msg.into()))?;
                        let __norito_content_slice = __slice;
                        let __idx_local = __idx;
                        #parse_match
                    }
                }
            }
        }
        _ => quote! { compile_error!("FastJson only supports structs and enums"); },
    };
    body.into()
}

#[proc_macro_derive(FastJsonWrite, attributes(norito))]
pub fn derive_fast_json_write(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident,
        data,
        generics,
        attrs,
        ..
    } = parse_macro_input!(input as DeriveInput);
    if let Err(error) = validate_data_field_attrs(&data) {
        return error.to_compile_error().into();
    }
    let container_attrs = match ContainerAttr::parse(&attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.to_compile_error().into(),
    };
    match data {
        Data::Struct(ds) => match ds.fields {
            Fields::Named(named) => {
                let mut r#gen = generics.clone();
                let mut writers = Vec::new();
                let mut fixed_keys = Vec::new();
                let mut has_dynamic_fields = false;
                for f in named.named.iter() {
                    let attrs = FieldAttr::parse_validated(&f.attrs);
                    if attrs.skip {
                        continue;
                    }
                    attrs.require_json_serialize_bound(&mut r#gen, &f.ty);
                    let fname = f.ident.as_ref().unwrap();
                    let key = container_attrs.rename_field(fname, &attrs);
                    let key_lit = syn::LitStr::new(&key, proc_macro2::Span::call_site());
                    has_dynamic_fields |= attrs.flatten || attrs.skip_serializing_if.is_some();
                    fixed_keys.push(key_lit.clone());
                    let serialize_call =
                        attrs.bounded_serializer_call(quote!(&self.#fname), quote!(out));
                    let bounded_flatten = if let Some(path) = &attrs.bounded_with {
                        quote! { #path(&self.#fname, out, &mut __norito_first) }
                    } else {
                        quote! {
                            ::core::result::Result::Err(
                                norito::json::BoundedJsonError::Unsupported,
                            )
                        }
                    };
                    let flatten_tokens = quote! {{
                        if let ::core::option::Option::Some(out) =
                            norito::json::JsonWriteSink::unbounded_output(out)
                        {
                            let __value = norito::json::to_value(&self.#fname)
                                .expect("flatten field must serialize to JSON value");
                            if let norito::json::Value::Object(__map) = __value {
                                for (__key, __val) in __map.into_iter() {
                                    if !__norito_first {
                                        out.push(',');
                                    } else {
                                        __norito_first = false;
                                    }
                                    out.push('"');
                                    out.push_str(&__key);
                                    out.push_str("\":");
                                    norito::json::JsonSerialize::json_serialize(&__val, out);
                                }
                                ::core::result::Result::Ok(())
                            } else {
                                panic!("#[norito(flatten)] field must serialize to an object");
                            }
                        } else {
                            #bounded_flatten
                        }
                    }};
                    let render = if attrs.flatten {
                        quote! { #flatten_tokens?; }
                    } else if let Some(predicate) = &attrs.skip_serializing_if {
                        quote! {
                            if !(#predicate)(&self.#fname) {
                                if !__norito_first {
                                    out.push(',')?;
                                } else {
                                    __norito_first = false;
                                }
                                out.push('"')?;
                                out.push_str(#key_lit)?;
                                out.push_str("\":")?;
                                #serialize_call?;
                            }
                        }
                    } else {
                        quote! {
                            if !__norito_first {
                                out.push(',')?;
                            } else {
                                __norito_first = false;
                            }
                            out.push('"')?;
                            out.push_str(#key_lit)?;
                            out.push_str("\":")?;
                            #serialize_call?;
                        }
                    };
                    writers.push(render);
                }
                let field_order = if has_dynamic_fields {
                    quote! { ::core::option::Option::None }
                } else {
                    quote! { ::core::option::Option::Some(&[#(#fixed_keys),*]) }
                };
                let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
                quote! {
                        #[automatically_derived]
                        impl #impl_generics norito::json::FastJsonWrite for #ident #ty_generics #where_clause {
                            fn json_object_field_order() -> ::core::option::Option<&'static [&'static str]> {
                                #field_order
                            }

                            fn write_json(&self, out: &mut ::std::string::String) {
                                norito::json::write_json_unbounded(self, out);
                            }

                            fn write_json_to(
                                &self,
                                out: &mut dyn norito::json::JsonWriteSink,
                            ) -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.begin_container()?;
                                let __norito_container_result_1 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.push('{')?;
                                let mut __norito_first = true;
                                #(#writers)*
                                out.push('}')?;
                                ::core::result::Result::Ok(())
                                })();
                                out.end_container();
                                __norito_container_result_1?;
                                ::core::result::Result::Ok(())
                            }
                        }
                    }
                    .into()
            }
            Fields::Unnamed(unnamed) => {
                let mut r#gen = generics.clone();
                let mut writers = Vec::new();
                for (idx, f) in unnamed.unnamed.iter().enumerate() {
                    let attrs = FieldAttr::parse_validated(&f.attrs);
                    if attrs.skip {
                        continue;
                    }
                    attrs.require_json_serialize_bound(&mut r#gen, &f.ty);
                    let index = Index::from(idx);
                    let serialize_call =
                        attrs.bounded_serializer_call(quote!(&self.#index), quote!(out));
                    if let Some(predicate) = &attrs.skip_serializing_if {
                        writers.push(quote! {
                            if !(#predicate)(&self.#index) {
                                if !__norito_first {
                                    out.push(',')?;
                                } else {
                                    __norito_first = false;
                                }
                                #serialize_call?;
                            }
                        });
                    } else {
                        writers.push(quote! {
                            if !__norito_first {
                                out.push(',')?;
                            } else {
                                __norito_first = false;
                            }
                            #serialize_call?;
                        });
                    }
                }
                let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
                quote! {
                        #[automatically_derived]
                        impl #impl_generics norito::json::FastJsonWrite for #ident #ty_generics #where_clause {
                            fn write_json(&self, out: &mut ::std::string::String) {
                                norito::json::write_json_unbounded(self, out);
                            }

                            fn write_json_to(
                                &self,
                                out: &mut dyn norito::json::JsonWriteSink,
                            ) -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.begin_container()?;
                                let __norito_container_result_2 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.push('[')?;
                                let mut __norito_first = true;
                                #(#writers)*
                                out.push(']')?;
                                ::core::result::Result::Ok(())
                                })();
                                out.end_container();
                                __norito_container_result_2?;
                                ::core::result::Result::Ok(())
                            }
                        }
                    }
                    .into()
            }
            Fields::Unit => {
                let r#gen = generics.clone();
                let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
                quote! {
                        #[automatically_derived]
                        impl #impl_generics norito::json::FastJsonWrite for #ident #ty_generics #where_clause {
                            fn write_json(&self, out: &mut ::std::string::String) {
                                norito::json::write_json_unbounded(self, out);
                            }

                            fn write_json_to(
                                &self,
                                out: &mut dyn norito::json::JsonWriteSink,
                            ) -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.push_str("null")
                            }
                        }
                    }
                    .into()
            }
        },
        Data::Enum(de) => {
            let enum_attr = match EnumAttr::parse(&attrs) {
                Ok(attr) => attr,
                Err(err) => return err.to_compile_error().into(),
            };
            let tag = match enum_attr.tag {
                Some(t) => t,
                None => {
                    return syn::Error::new_spanned(
                        &ident,
                        "enum JsonSerialize requires #[norito(tag = ...)]",
                    )
                    .to_compile_error()
                    .into();
                }
            };
            let content = match enum_attr.content {
                Some(c) => c,
                None => {
                    return syn::Error::new_spanned(
                        &ident,
                        "enum JsonSerialize requires #[norito(content = ...)]",
                    )
                    .to_compile_error()
                    .into();
                }
            };
            let tag_lit = syn::LitStr::new(&tag, proc_macro2::Span::call_site());
            let content_lit = syn::LitStr::new(&content, proc_macro2::Span::call_site());
            let mut r#gen = generics.clone();
            let mut arms = Vec::new();
            for variant in de.variants.iter() {
                let v_ident = &variant.ident;
                let v_attr = match VariantAttr::parse(&variant.attrs) {
                    Ok(attr) => attr,
                    Err(err) => return err.to_compile_error().into(),
                };
                let variant_name = container_attrs.rename_variant(v_ident, &v_attr);
                let variant_lit = syn::LitStr::new(&variant_name, proc_macro2::Span::call_site());
                match &variant.fields {
                    Fields::Unit => {
                        arms.push(quote! {
                            Self::#v_ident => {
                                out.begin_container()?;
                                let __norito_container_result_3 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.push('{')?;
                                out.push('"')?;
                                out.push_str(#tag_lit)?;
                                out.push_str("\":")?;
                                norito::json::write_json_string_to(#variant_lit, out)?;
                                out.push(',')?;
                                out.push('"')?;
                                out.push_str(#content_lit)?;
                                out.push_str("\":null")?;
                                out.push('}')?;
                                ::core::result::Result::Ok(())
                                })();
                                out.end_container();
                                __norito_container_result_3?;
                                ::core::result::Result::Ok(())
                            }
                        });
                    }
                    Fields::Unnamed(fields) => {
                        if fields.unnamed.is_empty() {
                            arms.push(quote! {
                                Self::#v_ident() => {
                                    out.begin_container()?;
                                    let __norito_container_result_4 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                    out.push('{')?;
                                    out.push('"')?;
                                    out.push_str(#tag_lit)?;
                                    out.push_str("\":")?;
                                    norito::json::write_json_string_to(#variant_lit, out)?;
                                    out.push(',')?;
                                    out.push('"')?;
                                    out.push_str(#content_lit)?;
                                    out.push_str("\":null")?;
                                    out.push('}')?;
                                    ::core::result::Result::Ok(())
                                    })();
                                    out.end_container();
                                    __norito_container_result_4?;
                                    ::core::result::Result::Ok(())
                                }
                            });
                            continue;
                        }
                        if fields.unnamed.len() == 1 {
                            let attrs = FieldAttr::parse_validated(&fields.unnamed[0].attrs);
                            if attrs.skip {
                                return syn::Error::new_spanned(
                                    &fields.unnamed[0],
                                    "#[norito(skip)] is not supported on enum tuple variants",
                                )
                                .to_compile_error()
                                .into();
                            }
                            let ty = &fields.unnamed[0].ty;
                            attrs.require_json_serialize_bound(&mut r#gen, ty);
                            let binding = format_ident!("__norito_field");
                            let serialize_call =
                                attrs.bounded_serializer_call(quote!(#binding), quote!(out));
                            arms.push(quote! {
                                Self::#v_ident(#binding) => {
                                    out.begin_container()?;
                                    let __norito_container_result_5 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                    out.push('{')?;
                                    out.push('"')?;
                                    out.push_str(#tag_lit)?;
                                    out.push_str("\":")?;
                                    norito::json::write_json_string_to(#variant_lit, out)?;
                                    out.push(',')?;
                                    out.push('"')?;
                                    out.push_str(#content_lit)?;
                                    out.push_str("\":")?;
                                    #serialize_call?;
                                    out.push('}')?;
                                    ::core::result::Result::Ok(())
                                    })();
                                    out.end_container();
                                    __norito_container_result_5?;
                                    ::core::result::Result::Ok(())
                                }
                            });
                        } else {
                            let mut bindings = Vec::new();
                            let mut serializers = Vec::new();
                            for (idx, field) in fields.unnamed.iter().enumerate() {
                                let attrs = FieldAttr::parse_validated(&field.attrs);
                                if attrs.skip {
                                    return syn::Error::new_spanned(
                                        field,
                                        "#[norito(skip)] is not supported on enum tuple variants",
                                    )
                                    .to_compile_error()
                                    .into();
                                }
                                attrs.require_json_serialize_bound(&mut r#gen, &field.ty);
                                let binding = format_ident!("__norito_v{idx}");
                                let serialize_call =
                                    attrs.bounded_serializer_call(quote!(#binding), quote!(out));
                                serializers.push(quote! {
                                    if !__norito_first {
                                        out.push(',')?;
                                    } else {
                                        __norito_first = false;
                                    }
                                    #serialize_call?;
                                });
                                bindings.push(binding);
                            }
                            let ref_bindings: Vec<_> = bindings.iter().collect();
                            arms.push(quote! {
                                Self::#v_ident( #( #ref_bindings ),* ) => {
                                    out.begin_container()?;
                                    let __norito_container_result_6 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                    out.push('{')?;
                                    out.push('"')?;
                                    out.push_str(#tag_lit)?;
                                    out.push_str("\":")?;
                                    norito::json::write_json_string_to(#variant_lit, out)?;
                                    out.push(',')?;
                                    out.push('"')?;
                                    out.push_str(#content_lit)?;
                                    out.push_str("\":")?;
                                    out.begin_container()?;
                                    let __norito_container_result_7 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                    out.push('[')?;
                                    let mut __norito_first = true;
                                    #(#serializers)*
                                    out.push(']')?;
                                    ::core::result::Result::Ok(())
                                    })();
                                    out.end_container();
                                    __norito_container_result_7?;
                                    out.push('}')?;
                                    ::core::result::Result::Ok(())
                                    })();
                                    out.end_container();
                                    __norito_container_result_6?;
                                    ::core::result::Result::Ok(())
                                }
                            });
                        }
                    }
                    Fields::Named(fields) => {
                        let mut field_writers = Vec::new();
                        let mut ref_idents = Vec::new();
                        for field in fields.named.iter() {
                            let attrs = FieldAttr::parse_validated(&field.attrs);
                            if attrs.skip {
                                return syn::Error::new_spanned(
                                    field,
                                    "#[norito(skip)] is not supported on enum struct variants",
                                )
                                .to_compile_error()
                                .into();
                            }
                            attrs.require_json_serialize_bound(&mut r#gen, &field.ty);
                            let fname = field.ident.as_ref().unwrap();
                            ref_idents.push(fname.clone());
                            let key = attrs.rename.clone().unwrap_or_else(|| fname.to_string());
                            let key_lit = syn::LitStr::new(&key, proc_macro2::Span::call_site());
                            let serialize_call =
                                attrs.bounded_serializer_call(quote!(#fname), quote!(out));
                            field_writers.push(quote! {
                                if !__norito_first_inner {
                                    out.push(',')?;
                                } else {
                                    __norito_first_inner = false;
                                }
                                out.push('"')?;
                                out.push_str(#key_lit)?;
                                out.push_str("\":")?;
                                #serialize_call?;
                            });
                        }
                        arms.push(quote! {
                            Self::#v_ident { #( #ref_idents ),* } => {
                                out.begin_container()?;
                                let __norito_container_result_8 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.push('{')?;
                                out.push('"')?;
                                out.push_str(#tag_lit)?;
                                out.push_str("\":")?;
                                norito::json::write_json_string_to(#variant_lit, out)?;
                                out.push(',')?;
                                out.push('"')?;
                                out.push_str(#content_lit)?;
                                out.push_str("\":")?;
                                out.begin_container()?;
                                let __norito_container_result_9 = (|| -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                                out.push('{')?;
                                let mut __norito_first_inner = true;
                                #(#field_writers)*
                                out.push('}')?;
                                ::core::result::Result::Ok(())
                                })();
                                out.end_container();
                                __norito_container_result_9?;
                                out.push('}')?;
                                ::core::result::Result::Ok(())
                                })();
                                out.end_container();
                                __norito_container_result_8?;
                                ::core::result::Result::Ok(())
                            }
                        });
                    }
                }
            }
            let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
            quote! {
                #[automatically_derived]
                impl #impl_generics norito::json::FastJsonWrite for #ident #ty_generics #where_clause {
                    fn write_json(&self, out: &mut ::std::string::String) {
                        norito::json::write_json_unbounded(self, out);
                    }

                    fn write_json_to(
                        &self,
                        out: &mut dyn norito::json::JsonWriteSink,
                    ) -> ::core::result::Result<(), norito::json::BoundedJsonError> {
                        match self {
                            #( #arms ),*
                        }
                    }
                }
            }
            .into()
        }
        _ => syn::Error::new_spanned(ident, "FastJsonWrite only supports structs and enums")
            .to_compile_error()
            .into(),
    }
}

#[proc_macro_derive(JsonSerialize, attributes(norito))]
pub fn derive_json_serialize(input: TokenStream) -> TokenStream {
    derive_fast_json_write(input)
}

fn derive_struct_json_deserialize(
    ident: &syn::Ident,
    generics: &Generics,
    data: &syn::DataStruct,
    container_attrs: &ContainerAttr,
) -> syn::Result<TokenStream2> {
    validate_field_attrs(&data.fields)?;
    if container_attrs.deny_unknown_fields && !matches!(&data.fields, Fields::Named(_)) {
        return Err(syn::Error::new_spanned(
            ident,
            "#[norito(deny_unknown_fields)] requires a struct with named fields",
        ));
    }
    let mut r#gen = generics.clone();
    match &data.fields {
        Fields::Named(named) => {
            if named
                .named
                .iter()
                .any(|f| FieldAttr::parse_validated(&f.attrs).flatten)
            {
                return derive_struct_json_deserialize_flatten(
                    ident,
                    generics,
                    named,
                    container_attrs,
                );
            }
            let unknown_field_arm = if container_attrs.deny_unknown_fields {
                quote! {
                    _ => {
                        return Err(norito::json::Error::unknown_field(key.as_str()));
                    }
                }
            } else {
                quote! {
                    _ => {
                        parser.skip_value_lexical()?;
                    }
                }
            };
            let mut inits = Vec::new();
            let mut arms = Vec::new();
            let mut finals = Vec::new();
            for f in named.named.iter() {
                let attrs = FieldAttr::parse_validated(&f.attrs);
                let field_ident = f.ident.as_ref().unwrap();
                let key = container_attrs.rename_field(field_ident, &attrs);
                let key_lit = syn::LitStr::new(&key, proc_macro2::Span::call_site());
                let var_ident = format_ident!("__norito_field_{}", field_ident);
                if attrs.skip {
                    if attrs.default || attrs.default_fn.is_some() {
                        return Err(syn::Error::new_spanned(
                            f,
                            "#[norito(skip)] cannot be combined with #[norito(default)]",
                        ));
                    }
                    // Skipped fields are filled from Default
                    add_bound(&mut r#gen, &f.ty, quote!(::core::default::Default));
                    finals.push(quote! { #field_ident: ::core::default::Default::default() });
                    continue;
                }
                attrs.require_json_deserialize_bound(&mut r#gen, &f.ty);
                let ty = &f.ty;
                inits.push(quote! { let mut #var_ident: ::core::option::Option<#ty> = ::core::option::Option::None; });
                let deserialize_call = attrs.deserializer_call(ty, quote!(parser));
                arms.push(quote! {
                    #key_lit => {
                        if #var_ident.is_some() {
                            return Err(norito::json::Error::duplicate_field(#key_lit));
                        }
                        let value = #deserialize_call;
                        #var_ident = ::core::option::Option::Some(value);
                    }
                });
                let default_expr = if let Some(path) = &attrs.default_fn {
                    Some(quote! { (#path)() })
                } else if attrs.default {
                    add_bound(&mut r#gen, &f.ty, quote!(::core::default::Default));
                    Some(quote! { ::core::default::Default::default() })
                } else {
                    None
                };
                if is_option_type(&f.ty) && !attrs.required {
                    if let Some(expr) = default_expr {
                        finals.push(quote! { #field_ident: #var_ident.unwrap_or_else(|| #expr) });
                    } else {
                        finals.push(quote! { #field_ident: #var_ident.unwrap_or(::core::option::Option::None) });
                    }
                } else if let Some(expr) = default_expr {
                    finals.push(quote! { #field_ident: #var_ident.unwrap_or_else(|| #expr) });
                } else {
                    finals.push(quote! {
                        #field_ident: #var_ident.ok_or_else(|| norito::json::Error::missing_field(#key_lit))?
                    });
                }
            }
            let field_loop = if arms.is_empty() && container_attrs.deny_unknown_fields {
                quote! {
                    if !parser.try_consume_char(b'}')? {
                        parser.skip_ws();
                        let key = parser.parse_key()?;
                        return Err(norito::json::Error::unknown_field(key.as_str()));
                    }
                }
            } else {
                quote! {
                    if !parser.try_consume_char(b'}')? {
                        loop {
                            parser.skip_ws();
                            let key = parser.parse_key()?;
                            match key.as_str() {
                                #( #arms, )*
                                #unknown_field_arm
                            }
                            parser.skip_ws();
                            if parser.try_consume_char(b',')? {
                                continue;
                            }
                            parser.expect(b'}')?;
                            break;
                        }
                    }
                }
            };
            let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
            let result = quote! {
                #[automatically_derived]
                impl #impl_generics norito::json::JsonDeserialize for #ident #ty_generics #where_clause {
                    #[allow(clippy::useless_let_if_seq)]
                    fn json_deserialize(parser: &mut norito::json::Parser<'_>) -> ::core::result::Result<Self, norito::json::Error> {
                        parser.skip_ws();
                        parser.preflight_object_entries()?;
                        parser.expect(b'{')?;
                        parser.skip_ws();
                        #(#inits)*
                        #field_loop
                        Ok(Self { #( #finals ),* })
                    }
                }
            };
            Ok(result)
        }
        Fields::Unnamed(unnamed) => {
            let mut inits = Vec::new();
            let mut match_arms = Vec::new();
            let mut finals = Vec::new();
            let mut gen_local = r#gen.clone();
            for (idx, f) in unnamed.unnamed.iter().enumerate() {
                let attrs = FieldAttr::parse_validated(&f.attrs);
                let var_ident = format_ident!("__norito_tuple_{idx}");
                if attrs.skip {
                    add_bound(&mut gen_local, &f.ty, quote!(::core::default::Default));
                    finals.push(quote! { ::core::default::Default::default() });
                    match_arms.push(quote! {
                        #idx => {
                            parser.skip_value_lexical()?;
                        }
                    });
                    continue;
                }
                attrs.require_json_deserialize_bound(&mut gen_local, &f.ty);
                let ty = &f.ty;
                inits.push(quote! { let mut #var_ident: ::core::option::Option<#ty> = ::core::option::Option::None; });
                let deserialize_call = attrs.deserializer_call(ty, quote!(parser));
                match_arms.push(quote! {
                    #idx => {
                        let value = #deserialize_call;
                        #var_ident = ::core::option::Option::Some(value);
                    }
                });
                let missing_msg = syn::LitStr::new(
                    &format!("missing tuple index {idx}"),
                    proc_macro2::Span::call_site(),
                );
                let default_expr = if let Some(path) = &attrs.default_fn {
                    Some(quote! { (#path)() })
                } else if attrs.default {
                    add_bound(&mut gen_local, &f.ty, quote!(::core::default::Default));
                    Some(quote! { ::core::default::Default::default() })
                } else {
                    None
                };
                if is_option_type(&f.ty) {
                    if let Some(expr) = default_expr {
                        finals.push(quote! { #var_ident.unwrap_or_else(|| #expr) });
                    } else {
                        finals.push(quote! { #var_ident.unwrap_or(::core::option::Option::None) });
                    }
                } else if let Some(expr) = default_expr {
                    finals.push(quote! { #var_ident.unwrap_or_else(|| #expr) });
                } else {
                    finals.push(quote! {
                        #var_ident.ok_or_else(|| norito::json::Error::Message(#missing_msg.into()))?
                    });
                }
            }
            let (impl_generics, ty_generics, where_clause) = gen_local.split_for_impl();
            let len = unnamed.unnamed.len();
            let result = quote! {
                #[automatically_derived]
                impl #impl_generics norito::json::JsonDeserialize for #ident #ty_generics #where_clause {
                    #[allow(clippy::useless_let_if_seq)]
                    fn json_deserialize(parser: &mut norito::json::Parser<'_>) -> ::core::result::Result<Self, norito::json::Error> {
                        parser.skip_ws();
                        parser.expect(b'[')?;
                        parser.skip_ws();
                        #(#inits)*
                        let mut __norito_index: usize = 0;
                        if !parser.try_consume_char(b']')? {
                            let mut __first = true;
                            loop {
                                if !__first {
                                    parser.expect(b',')?;
                                }
                                __first = false;
                                match __norito_index {
                                    #( #match_arms ),*,
                                    _ => {
                                        parser.skip_value_lexical()?;
                                        return Err(norito::json::Error::Message(format!("too many elements for tuple struct `{}`", stringify!(#ident)).into()));
                                    }
                                }
                                __norito_index += 1;
                                parser.skip_ws();
                                if parser.try_consume_char(b']')? {
                                    break;
                                }
                            }
                        }
                        if __norito_index < #len {
                            // Missing trailing elements will be handled by final unwrap/default logic
                        }
                        Ok(Self( #( #finals ),* ))
                    }
                }
            };
            Ok(result)
        }
        Fields::Unit => {
            let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
            Ok(quote! {
                #[automatically_derived]
                impl #impl_generics norito::json::JsonDeserialize for #ident #ty_generics #where_clause {
                    #[allow(clippy::useless_let_if_seq)]
                    fn json_deserialize(parser: &mut norito::json::Parser<'_>) -> ::core::result::Result<Self, norito::json::Error> {
                        parser.parse_null()?;
                        Ok(Self)
                    }
                }
            })
        }
    }
}

fn derive_struct_json_deserialize_flatten(
    ident: &syn::Ident,
    generics: &Generics,
    named: &syn::FieldsNamed,
    container_attrs: &ContainerAttr,
) -> syn::Result<TokenStream2> {
    let JsonFlattenParts {
        generics: r#gen,
        inits: init_stmts,
        parses: parse_stmts,
        flattens: flatten_stmts,
        finals,
    } = json_flatten_parts(generics, named, container_attrs, false)?;

    let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
    let reject_unknown_fields = if container_attrs.deny_unknown_fields {
        quote! {
            if let ::core::option::Option::Some(__key) = __map.keys().next() {
                return Err(norito::json::Error::unknown_field(__key.clone()));
            }
        }
    } else {
        TokenStream2::new()
    };
    let result = quote! {
        #[automatically_derived]
        impl #impl_generics norito::json::JsonDeserialize for #ident #ty_generics #where_clause {
            #[allow(clippy::useless_let_if_seq)]
            fn json_deserialize(parser: &mut norito::json::Parser<'_>) -> ::core::result::Result<Self, norito::json::Error> {
                let value = norito::json::Value::json_deserialize(parser)?;
                let mut __map = match value {
                    norito::json::Value::Object(map) => map,
                    _ => {
                        return Err(norito::json::Error::Message(
                            "expected JSON object".into(),
                        ));
                    }
                };
                #(#init_stmts)*
                #(#parse_stmts)*
                #(#flatten_stmts)*
                #reject_unknown_fields
                Ok(Self { #(#finals),* })
            }
        }
    };
    Ok(result)
}

fn derive_enum_json_deserialize(
    ident: &syn::Ident,
    generics: &Generics,
    data: &syn::DataEnum,
    attrs: &[Attribute],
    container_attrs: &ContainerAttr,
) -> syn::Result<TokenStream2> {
    let enum_attr = EnumAttr::parse(attrs)?;
    let tag = enum_attr.tag.ok_or_else(|| {
        syn::Error::new_spanned(ident, "enum JsonDeserialize requires #[norito(tag = ...)]")
    })?;
    let content = enum_attr.content.ok_or_else(|| {
        syn::Error::new_spanned(
            ident,
            "enum JsonDeserialize requires #[norito(content = ...)]",
        )
    })?;
    let tag_lit = syn::LitStr::new(&tag, proc_macro2::Span::call_site());
    let content_lit = syn::LitStr::new(&content, proc_macro2::Span::call_site());
    let unknown_variant_field = if container_attrs.deny_unknown_fields {
        quote! {
            _ => {
                return Err(norito::json::Error::unknown_field(key.as_str()));
            }
        }
    } else {
        quote! {
            _ => {
                __parser.skip_value_lexical()?;
            }
        }
    };

    let mut r#gen = generics.clone();
    let mut arms = Vec::new();

    for variant in data.variants.iter() {
        let v_ident = &variant.ident;
        let v_attr = VariantAttr::parse(&variant.attrs)?;
        let variant_name = container_attrs.rename_variant(v_ident, &v_attr);
        let variant_lit = syn::LitStr::new(&variant_name, proc_macro2::Span::call_site());
        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    #variant_lit => {
                        let mut __parser = norito::json::Parser::new(__norito_content_str);
                        __parser.parse_null()?;
                        __parser.skip_ws();
                        if !__parser.eof() {
                            return Err(norito::json::Error::Message(
                                format!("unexpected content for unit variant `{}`", #variant_lit).into(),
                            ));
                        }
                        Ok(Self::#v_ident)
                    }
                });
            }
            Fields::Unnamed(fields) => {
                let count = fields.unnamed.len();
                if count == 1 {
                    let field = &fields.unnamed[0];
                    let attrs = FieldAttr::parse(&field.attrs)?;
                    if attrs.skip {
                        return Err(syn::Error::new_spanned(
                            field,
                            "#[norito(skip)] is not supported on enum tuple variants",
                        ));
                    }
                    attrs.require_json_deserialize_bound(&mut r#gen, &field.ty);
                    let ty = &field.ty;
                    let deserialize_call = attrs.deserializer_call(ty, quote!(&mut __parser));
                    arms.push(quote! {
                        #variant_lit => {
                            let mut __parser = norito::json::Parser::new(__norito_content_str);
                            let value = #deserialize_call;
                            __parser.skip_ws();
                            if !__parser.eof() {
                                return Err(norito::json::Error::Message(format!(
                                    "unexpected trailing data for variant `{}`", #variant_lit
                                ).into()));
                            }
                            Ok(Self::#v_ident(value))
                        }
                    });
                } else {
                    let mut gen_local = r#gen.clone();
                    let mut inits = Vec::new();
                    let mut match_tokens = Vec::new();
                    let mut finals = Vec::new();
                    for (idx, field) in fields.unnamed.iter().enumerate() {
                        let attrs = FieldAttr::parse(&field.attrs)?;
                        if attrs.skip {
                            return Err(syn::Error::new_spanned(
                                field,
                                "#[norito(skip)] is not supported on enum tuple variants",
                            ));
                        }
                        let ty = &field.ty;
                        attrs.require_json_deserialize_bound(&mut gen_local, ty);
                        let binding = format_ident!("__norito_variant_{idx}");
                        inits.push(quote! {
                            let mut #binding: ::core::option::Option<#ty> = ::core::option::Option::None;
                        });
                        let missing_text =
                            format!("missing tuple index {idx} for variant `{variant_name}`");
                        let missing_msg =
                            syn::LitStr::new(&missing_text, proc_macro2::Span::call_site());
                        let deserialize_call = attrs.deserializer_call(ty, quote!(&mut __parser));
                        match_tokens.push(quote! {
                            #idx => {
                                let value = #deserialize_call;
                                #binding = ::core::option::Option::Some(value);
                            }
                        });
                        finals.push(quote! {
                            #binding.ok_or_else(|| norito::json::Error::Message(#missing_msg.into()))?
                        });
                    }
                    let constructor = quote! { Self::#v_ident( #( #finals ),* ) };
                    arms.push(quote! {
                        #variant_lit => {
                            let mut __parser = norito::json::Parser::new(__norito_content_str);
                            __parser.skip_ws();
                            __parser.expect(b'[')?;
                            __parser.skip_ws();
                            #(#inits)*
                            let mut __idx = 0usize;
                            if !__parser.try_consume_char(b']')? {
                                let mut __first = true;
                                loop {
                                    if !__first {
                                        __parser.expect(b',')?;
                                    }
                                    __first = false;
                                    match __idx {
                                        #( #match_tokens ),*,
                                        _ => {
                                            __parser.skip_value_lexical()?;
                                            return Err(norito::json::Error::Message(format!(
                                                "too many elements for variant `{}`", #variant_lit
                                            ).into()));
                                        }
                                    }
                                    __idx += 1;
                                    __parser.skip_ws();
                                    if __parser.try_consume_char(b']')? {
                                        break;
                                    }
                                }
                            }
                            __parser.skip_ws();
                            if !__parser.eof() {
                                return Err(norito::json::Error::Message(format!(
                                    "unexpected trailing data for variant `{}`", #variant_lit
                                ).into()));
                            }
                            Ok(#constructor)
                        }
                    });
                    r#gen = gen_local;
                }
            }
            Fields::Named(fields) => {
                let mut inits = Vec::new();
                let mut match_tokens = Vec::new();
                let mut finals = Vec::new();
                let mut gen_local = r#gen.clone();
                for field in fields.named.iter() {
                    let attrs = FieldAttr::parse(&field.attrs)?;
                    if attrs.skip {
                        return Err(syn::Error::new_spanned(
                            field,
                            "#[norito(skip)] is not supported on enum struct variants",
                        ));
                    }
                    let field_ident = field.ident.as_ref().unwrap();
                    let key = container_attrs.rename_field(field_ident, &attrs);
                    let key_lit = syn::LitStr::new(&key, proc_macro2::Span::call_site());
                    attrs.require_json_deserialize_bound(&mut gen_local, &field.ty);
                    let var_ident = format_ident!("__norito_variant_field_{}", field_ident);
                    let ty = &field.ty;
                    inits.push(quote! { let mut #var_ident: ::core::option::Option<#ty> = ::core::option::Option::None; });
                    let duplicate_text =
                        format!("duplicate field `{key}` in variant `{variant_name}`");
                    let duplicate_msg =
                        syn::LitStr::new(&duplicate_text, proc_macro2::Span::call_site());
                    let deserialize_call = attrs.deserializer_call(ty, quote!(&mut __parser));
                    match_tokens.push(quote! {
                        #key_lit => {
                            if #var_ident.is_some() {
                                return Err(norito::json::Error::Message(#duplicate_msg.into()));
                            }
                            let value = #deserialize_call;
                            #var_ident = ::core::option::Option::Some(value);
                        }
                    });
                    finals.push(quote! {
                        #field_ident: #var_ident.ok_or_else(|| norito::json::Error::missing_field(#key_lit))?
                    });
                }
                arms.push(quote! {
                    #variant_lit => {
                        let mut __parser = norito::json::Parser::new(__norito_content_str);
                        __parser.skip_ws();
                        __parser.preflight_object_entries()?;
                        if !__parser.try_consume_char(b'{')? {
                            return Err(norito::json::Error::Message(format!(
                                "expected object for variant `{}`", #variant_lit
                            ).into()));
                        }
                        #(#inits)*
                        __parser.skip_ws();
                        if !__parser.try_consume_char(b'}')? {
                            loop {
                                __parser.skip_ws();
                                let key = __parser.parse_key()?;
                                match key.as_str() {
                                    #( #match_tokens ),*,
                                    #unknown_variant_field
                                }
                                __parser.skip_ws();
                                if __parser.try_consume_char(b',')? {
                                    continue;
                                }
                                __parser.expect(b'}')?;
                                break;
                            }
                        }
                        __parser.skip_ws();
                        if !__parser.eof() {
                            return Err(norito::json::Error::Message(format!(
                                "unexpected trailing data for variant `{}`", #variant_lit
                            ).into()));
                        }
                        Ok(Self::#v_ident { #( #finals ),* })
                    }
                });
                r#gen = gen_local;
            }
        }
    }

    let (impl_generics, ty_generics, where_clause) = r#gen.split_for_impl();
    let unknown_envelope_field = if container_attrs.deny_unknown_fields {
        quote! {
            return Err(norito::json::Error::unknown_field(key.as_str()));
        }
    } else {
        quote! {
            parser.skip_value_lexical()?;
        }
    };
    let result = quote! {
        #[automatically_derived]
        impl #impl_generics norito::json::JsonDeserialize for #ident #ty_generics #where_clause {
            #[allow(clippy::useless_let_if_seq)]
            fn json_deserialize(parser: &mut norito::json::Parser<'_>) -> ::core::result::Result<Self, norito::json::Error> {
                parser.skip_ws();
                parser.preflight_object_entries()?;
                parser.expect(b'{')?;
                parser.skip_ws();
                let mut __norito_tag: ::core::option::Option<String> = ::core::option::Option::None;
                let mut __norito_raw: ::core::option::Option<&str> = ::core::option::Option::None;
                if !parser.try_consume_char(b'}')? {
                    loop {
                        parser.skip_ws();
                        let key = parser.parse_key()?;
                        if key.as_str() == #tag_lit {
                            if __norito_tag.is_some() {
                                return Err(norito::json::Error::duplicate_field(#tag_lit));
                            }
                            let value = parser.parse_string()?;
                            __norito_tag = ::core::option::Option::Some(value);
                        } else if key.as_str() == #content_lit {
                            if __norito_raw.is_some() {
                                return Err(norito::json::Error::duplicate_field(#content_lit));
                            }
                            __norito_raw = ::core::option::Option::Some(parser.raw_value_slice()?);
                        } else {
                            #unknown_envelope_field
                        }
                        parser.skip_ws();
                        if parser.try_consume_char(b',')? {
                            continue;
                        }
                        parser.expect(b'}')?;
                        break;
                    }
                }
                let tag = __norito_tag.ok_or_else(|| norito::json::Error::Message(
                    format!("missing `{}` field", #tag_lit).into(),
                ))?;
                let __norito_content_str = __norito_raw.ok_or_else(||
                    norito::json::Error::missing_field(#content_lit)
                )?;
                match tag.as_str() {
                    #( #arms ),*,
                    _ => Err(norito::json::Error::Message(
                        "unknown JSON enum variant".into(),
                    )),
                }
            }
        }
    };
    Ok(result)
}
/// Select an implementation lifetime without shadowing user parameters or nested binders.
fn json_implementation_lifetime(generics: &Generics, base: &str) -> syn::Lifetime {
    let params = &generics.params;
    let where_clause = &generics.where_clause;
    let tokens = quote!(#params #where_clause);
    let mut ident = format_ident!("{base}");
    while token_stream_mentions_generic(tokens.clone(), ::core::slice::from_ref(&ident)) {
        ident = format_ident!("_{ident}");
    }
    syn::Lifetime::new(&format!("'{ident}"), proc_macro2::Span::call_site())
}

fn derive_fast_from_json_fallback(input: &DeriveInput) -> TokenStream2 {
    let ident = &input.ident;
    let input_lifetime = json_implementation_lifetime(&input.generics, "__norito_json");
    let arena_lifetime = json_implementation_lifetime(&input.generics, "__norito_arena");
    let mut implementation = input.generics.clone();
    implementation.params.insert(
        0,
        syn::GenericParam::Lifetime(syn::LifetimeParam::new(input_lifetime.clone())),
    );
    // Reuse the actual derived obligation, including skipped/default and custom-helper fields.
    implementation
        .make_where_clause()
        .predicates
        .push(parse_quote!(Self: norito::json::JsonDeserialize));
    let (impl_generics, _, where_clause) = implementation.split_for_impl();
    let (_, ty_generics, _) = input.generics.split_for_impl();
    quote! {
        impl #impl_generics norito::json::FastFromJson<#input_lifetime> for #ident #ty_generics #where_clause {
            fn parse<#arena_lifetime>(
                w: &mut norito::json::TapeWalker<#input_lifetime>,
                _arena: &#arena_lifetime mut norito::json::Arena,
            ) -> ::core::result::Result<Self, norito::Error> {
                w.ensure_document_depth()?;
                let input = w.input();
                let mut parser = norito::json::Parser::new_at(input, w.raw_pos());
                let value = <Self as norito::json::JsonDeserialize>::json_deserialize(&mut parser)
                    .map_err(norito::Error::from)?;
                w.sync_to_raw(parser.position());
                Ok(value)
            }
        }
    }
}

fn has_no_fast_from_json_attr(attrs: &[syn::Attribute]) -> bool {
    ContainerAttr::parse(attrs)
        .expect("container attributes must be validated before code generation")
        .no_fast_from_json
}

#[proc_macro_derive(JsonDeserialize, attributes(norito))]
/// Derive Norito JSON deserialization.
///
/// Named structs and tagged enums may opt into closed object schemas with
/// `#[norito(deny_unknown_fields)]`. The option rejects unknown object keys;
/// nested types remain responsible for selecting the same policy when their
/// schemas are also closed.
pub fn derive_json_deserialize(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as DeriveInput);
    if let Err(error) = validate_data_field_attrs(&parsed.data) {
        return error.to_compile_error().into();
    }
    let container_attrs = match ContainerAttr::parse(&parsed.attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.to_compile_error().into(),
    };
    let fast_impl = if has_no_fast_from_json_attr(&parsed.attrs) {
        None
    } else {
        Some(derive_fast_from_json_fallback(&parsed))
    };
    let deserialize_impl = match &parsed.data {
        Data::Struct(data) => {
            match derive_struct_json_deserialize(
                &parsed.ident,
                &parsed.generics,
                data,
                &container_attrs,
            ) {
                Ok(ts) => ts,
                Err(e) => return e.to_compile_error().into(),
            }
        }
        Data::Enum(data) => {
            match derive_enum_json_deserialize(
                &parsed.ident,
                &parsed.generics,
                data,
                &parsed.attrs,
                &container_attrs,
            ) {
                Ok(ts) => ts,
                Err(e) => return e.to_compile_error().into(),
            }
        }
        _ => {
            return syn::Error::new_spanned(
                &parsed.ident,
                "JsonDeserialize only supports structs and enums",
            )
            .to_compile_error()
            .into();
        }
    };
    let mut tokens = TokenStream2::new();
    if let Some(fallback) = fast_impl {
        tokens.extend(fallback);
    }
    tokens.extend(deserialize_impl);
    tokens.into()
}

#[proc_macro_derive(Encode, attributes(codec, norito))]
/// Derive `norito::codec::Encode` for structs.
pub fn derive_encode(input: TokenStream) -> TokenStream {
    derive_norito_serialize(input)
}

#[proc_macro_derive(Decode, attributes(codec, norito))]
/// Derive `norito::codec::Decode` for structs.
pub fn derive_decode(input: TokenStream) -> TokenStream {
    derive_norito_deserialize(input)
}
