//! TODO

#![allow(unused)]

use darling::{FromAttributes, FromDeriveInput};
use iroha_macro_utils::Emitter;
use manyhow::{manyhow, Result};
use proc_macro2::TokenStream;

use crate::ast::Input;

/// Derive `iroha_config_base::reader::ReadConfig` trait.
///
/// Example:
///
/// ```
/// use iroha_config_base_derive::ReadConfig;
///
/// #[derive(ReadConfig)]
/// struct Config {
///   #[config(default, env = "FOO")]
///   foo: bool,
///   #[config(nested)]
///   nested: Nested
/// }
///
/// #[derive(ReadConfig)]
/// struct Nested {
///   #[config(default = "42")]
///   foo: u64
/// }
/// ```
///
/// Supported field shapes:
///
/// - `T` - required parameter
/// - `WithOrigin<T>` - required parameter with origin data
/// - `Option<T>` - optional parameter
/// - `Option<WithOrigin<T>>` - optional parameter with origin data
///
/// Supported field attributes:
///
/// - `env = "<env var name>"` - read parameter from env (bound: `T: FromEnvStr`)
/// - `env_only` - skip reading from file. Removes `T: Deserialize` bound.
/// - `default` - fallback to default value (bound: `T: Default`)
/// - `default = "<expr>"` - fallback to a default value specified as an expression
/// - `default_lazy = "<expr>"` - computes the default value expression lazily
/// - `nested` - delegates further reading (bound: `T: ReadConfig`).
///   It uses the field name as a namespace.
///
/// A bound of `T: Deserialize` is required unless `env_only` is set.
#[manyhow]
#[proc_macro_derive(ReadConfig, attributes(config))]
pub fn derive_read_config(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };
    let Some(parsed) = emitter.handle(Input::from_derive_input(&input)) else {
        return emitter.finish_token_stream();
    };
    let Some(ir) = parsed.lower(&mut emitter) else {
        return emitter.finish_token_stream();
    };

    emitter.finish_token_stream_with(ir.generate())
}

/// Parsing proc-macro input
mod ast {
    use iroha_macro_utils::Emitter;
    use manyhow::emit;
    use proc_macro2::{Span, TokenStream, TokenTree};
    use syn::parse::ParseStream;

    use crate::codegen;

    // TODO: `attributes(config)` rejects all unknown fields
    //       it would be better to emit an error "we don't support struct attrs" instead
    #[derive(darling::FromDeriveInput, Debug)]
    #[darling(supports(struct_named), attributes(config))]
    pub struct Input {
        ident: syn::Ident,
        generics: syn::Generics,
        data: darling::ast::Data<(), Field>,
    }

    impl Input {
        pub fn lower(self, emitter: &mut Emitter) -> Option<codegen::Ir> {
            let mut halt_codegen = false;

            for i in self.generics.params {
                emit!(emitter, i, "generics are not supported");
                // proceeding to codegen with these errors will produce a mess
                halt_codegen = true;
            }

            let entries = self
                .data
                .take_struct()
                .expect("darling should reject enums")
                .fields
                .into_iter()
                .map(|field| field.into_codegen(emitter))
                .collect();

            if halt_codegen {
                None
            } else {
                Some(codegen::Ir {
                    ident: self.ident,
                    entries,
                })
            }
        }
    }

    #[derive(Debug)]
    struct Field {
        ident: syn::Ident,
        ty: syn::Type,
        attrs: Attrs,
    }

    impl darling::FromField for Field {
        fn from_field(field: &syn::Field) -> darling::Result<Self> {
            let ident = field
                .ident
                .as_ref()
                .expect("darling should only allow named structs")
                .clone();
            let ty = field.ty.clone();

            let attrs: Attrs =
                iroha_macro_utils::parse_single_list_attr_opt("config", &field.attrs)?
                    .unwrap_or_default();

            Ok(Self { ident, ty, attrs })
        }
    }

    impl Field {
        fn into_codegen(self, emitter: &mut Emitter) -> codegen::Entry {
            let Field { ident, ty, attrs } = self;

            let kind = match attrs {
                Attrs::Nested => codegen::EntryKind::Nested,
                Attrs::Parameter { default, env } => {
                    let shape = ParameterTypeShape::analyze(&ty);
                    let evaluation = match (shape.option, default) {
                        (false, AttrDefault::None) => codegen::Evaluation::Required,
                        (false, AttrDefault::Expr(expr)) => codegen::Evaluation::OrElse(expr),
                        (false, AttrDefault::Word) => codegen::Evaluation::OrDefault,
                        (true, AttrDefault::None) => codegen::Evaluation::Optional,
                        (true, _) => {
                            emit!(emitter, ident, "parameter of type `Option<..>` conflicts with `config(default)` attribute");
                            codegen::Evaluation::Optional
                        }
                    };
                    let with_origin = shape.with_origin;
                    let parse = match env {
                        AttrEnv::None => codegen::ParseParameter::FileOnly,
                        AttrEnv::Env { var, only: false } => {
                            codegen::ParseParameter::FileAndEnv { var }
                        }
                        AttrEnv::Env { var, only: true } => {
                            codegen::ParseParameter::EnvOnly { var }
                        }
                    };

                    codegen::EntryKind::Parameter {
                        parse,
                        evaluation,
                        with_origin,
                    }
                }
            };

            codegen::Entry { ident, kind }
        }
    }

    #[derive(Debug)]
    enum Attrs {
        Nested,
        Parameter { default: AttrDefault, env: AttrEnv },
    }

    impl Default for Attrs {
        fn default() -> Self {
            Self::Parameter {
                default: <_>::default(),
                env: <_>::default(),
            }
        }
    }

    #[derive(Debug, Default)]
    enum AttrDefault {
        /// `default` was not set
        #[default]
        None,
        /// `config(default)`
        Word,
        /// `config(default = "<expr>")`
        Expr(syn::Expr),
    }

    #[derive(Debug, Default)]
    enum AttrEnv {
        #[default]
        None,
        Env {
            var: syn::LitStr,
            only: bool,
        },
    }

    impl syn::parse::Parse for Attrs {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            input.step(|cursor| {
                let mut attr_default = None;
                let mut attr_env = None;
                let mut attr_env_only = None;
                let mut attr_nested = false;

                let mut rest = *cursor;

                enum LocalError {
                    IncompatibleWithNested(Span),
                    NestedOnlyAlone(Span),
                    Duplicate(Span),
                    BadEnvFormat(Span),
                    EnvOnlyWithoutEnv(Span),
                    BadDefaultFormat(Span),
                    BadDefaultExpr(Span, syn::Error),
                    UnexpectedIdent(Span),
                    UnexpectedToken(Span)
                }

                impl From<LocalError> for syn::Error {
                    fn from(value: LocalError) -> Self {
                        match value {
                            LocalError::IncompatibleWithNested(span) => Self::new(span, "attribute is not compatible with `nested` attribute set previously"),
                            LocalError::NestedOnlyAlone(span) => Self::new(span, "`nested` attribute cannot be set with any other attributes"),
                            LocalError::Duplicate(span) => Self::new(span, "duplicate attribute"),
                            LocalError::BadDefaultFormat(span) => Self::new(span, "supported `default` formats: `default`, `default = \"<expr>\"`"),
                            LocalError::BadDefaultExpr(span, error) => Self::new(span, format!("couldn't parse expression: {error}")),
                            LocalError::BadEnvFormat(span) => Self::new(span, "`env` should be set as `env = \"VARIABLE_NAME\""),
                            LocalError::EnvOnlyWithoutEnv(span) => Self::new(span, "`env_only` cannot be set without `env`"),
                            LocalError::UnexpectedToken(span) => Self::new(span, "unexpected token; expected a word or a comma"),
                            LocalError::UnexpectedIdent(span) => Self::new(span, "unexpected attribute; expected `default`, `env`, `env_only`, or `nested`")
                        }
                    }
                }

                while let Some((tt, next)) = rest.token_tree() {
                    match &tt {
                        TokenTree::Ident(ident) => {
                            let token = ident.to_string();
                            match token.as_str() {
                                "default" => {
                                    if attr_nested {
                                        Err(LocalError::IncompatibleWithNested(ident.span()))?
                                    }
                                    if attr_default.is_some() {
                                        Err(LocalError::Duplicate(ident.span()))?
                                    }

                                    rest = next;
                                    let next = match next.punct() {
                                        Some((punct, next)) if punct.as_char() == '=' => next,
                                        None => {
                                            attr_default = Some(AttrDefault::Word);
                                            continue;
                                        }
                                        Some((punct, next)) if punct.as_char() == ',' => {
                                            attr_default = Some(AttrDefault::Word);
                                            rest = next;
                                            continue;
                                        }
                                        Some(_) => Err(LocalError::BadDefaultFormat(ident.span()))?,
                                    };

                                    // parsing default as expr

                                    let Some((lit, next)) = next.literal() else {
                                        Err(LocalError::BadDefaultFormat(ident.span()))?
                                    };

                                    // FIXME: how to extract an expression from the literal properly?
                                    let lit = syn::LitStr::new(lit.to_string().trim_matches('"'), lit.span());
                                    let expr: syn::Expr = lit
                                        .parse()
                                        .map_err(|err| LocalError::BadDefaultExpr(lit.span(), err))?;

                                    attr_default = Some(AttrDefault::Expr(expr));
                                    rest = next;
                                }
                                "nested" => {
                                    // err if default/env/nested was set
                                    if attr_default.is_some() || attr_env.is_some() {
                                        Err(LocalError::NestedOnlyAlone(ident.span()))?
                                    }
                                    if attr_nested {
                                        Err(LocalError::Duplicate(ident.span()))?
                                    }
                                    attr_nested = true;
                                    rest = next;
                                }
                                "env" => {
                                    // err if nested was set
                                    if attr_nested {
                                        Err(LocalError::IncompatibleWithNested(ident.span()))?
                                    }
                                    if attr_env.is_some() {
                                        Err(LocalError::Duplicate(ident.span()))?
                                    }

                                    let next = match next.punct() {
                                        Some((punct, next)) if punct.as_char() == '=' => next,
                                        _ => Err(LocalError::BadEnvFormat(ident.span()))?,
                                    };

                                    let Some((lit, next)) = next.literal() else {
                                        Err(LocalError::BadEnvFormat(ident.span()))?
                                    };

                                    let lit = syn::LitStr::new(&lit.to_string().trim_matches('"'), lit.span());
                                    attr_env = Some(lit);
                                    rest = next;
                                }
                                "env_only" => {
                                    if attr_nested {
                                        Err(LocalError::IncompatibleWithNested(ident.span()))?
                                    }
                                    if attr_env_only.is_some() {
                                        Err(LocalError::Duplicate(ident.span()))?
                                    }

                                    attr_env_only = Some((ident.span()));
                                    rest = next;
                                }
                                other => {
                                    Err(LocalError::UnexpectedIdent(ident.span()))?
                                }
                            }
                        }
                        TokenTree::Punct(punct) if punct.as_char() == ',' => {
                            rest = next;
                        }
                        other => {
                            Err(LocalError::UnexpectedToken(other.span()))?
                        }
                    }
                }

                let combined = if attr_nested {
                    Self::Nested
                } else {
                    Self::Parameter {
                        default: attr_default.unwrap_or_default(),
                        env: match (attr_env, attr_env_only) {
                            (Some(lit), Some(_span)) => AttrEnv::Env {
                                var: lit,
                                only: true,
                            },
                            (Some(lit), None) => AttrEnv::Env {
                                var: lit,
                                only: false,
                            },
                            (None, None) => AttrEnv::None,
                            (None, Some(span)) => Err(LocalError::EnvOnlyWithoutEnv(span))?,
                        },
                    }
                };

                Ok((combined, rest))
            })
        }
    }

    #[derive(Debug, PartialEq)]
    struct ParameterTypeShape {
        option: bool,
        with_origin: bool,
    }

    impl ParameterTypeShape {
        fn analyze(ty: &syn::Type) -> Self {
            #[derive(Debug)]
            enum Token {
                Option,
                WithOrigin,
                Unknown,
            }

            fn parse_tokens(ty: &syn::Type, depth: u8) -> Vec<Token> {
                if depth == 0 {
                    return vec![];
                }

                let mut found = None;

                if let syn::Type::Path(type_path) = ty {
                    if let Some(last_segment) = type_path.path.segments.last() {
                        match &last_segment.arguments {
                            syn::PathArguments::AngleBracketed(args) if args.args.len() == 1 => {
                                if let syn::GenericArgument::Type(ty) =
                                    args.args.first().expect("should be exactly 1")
                                {
                                    found = Some((Some(ty), &last_segment.ident));
                                }
                            }
                            syn::PathArguments::None => found = Some((None, &last_segment.ident)),
                            _ => {}
                        }
                    }
                }

                if let Some((next, ident)) = found {
                    let token = match ident.to_string().as_ref() {
                        "Option" => Token::Option,
                        "WithOrigin" => Token::WithOrigin,
                        _ => Token::Unknown,
                    };

                    let mut chain = vec![token];

                    if let Some(next) = next {
                        chain.extend(parse_tokens(next, depth - 1));
                    }
                    chain
                } else {
                    vec![]
                }
            }

            let chain = parse_tokens(ty, 3);

            let (option, with_origin) = match (chain.get(0), chain.get(1)) {
                (Some(Token::Option), Some(Token::WithOrigin)) => (true, true),
                (Some(Token::Option), Some(_)) => (true, false),
                (Some(Token::WithOrigin), _) => (false, true),
                _ => (false, false),
            };

            Self {
                option,
                with_origin,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use syn::parse_quote;

        use super::*;

        #[test]
        fn parse_default() {
            let attrs: Attrs = syn::parse_quote!(default);

            assert!(matches!(
                attrs,
                Attrs::Parameter {
                    default: AttrDefault::Word,
                    env: AttrEnv::None
                }
            ));
        }

        #[test]
        fn parse_default_with_expr() {
            let attrs: Attrs = syn::parse_quote!(default = "42 + 411");

            assert!(matches!(
                attrs,
                Attrs::Parameter {
                    default: AttrDefault::Expr(_),
                    env: AttrEnv::None
                }
            ));
        }

        #[test]
        fn parse_default_env_env_only() {
            let attrs: Attrs = syn::parse_quote!(default, env = "$!@#", env_only);

            let Attrs::Parameter {
                default: AttrDefault::Word,
                env: AttrEnv::Env { var, only: true },
            } = attrs
            else {
                panic!("expectation failed")
            };
            assert_eq!(var.value(), "$!@#");
        }

        #[test]
        #[should_panic(
            expected = "attribute is not compatible with `nested` attribute set previously"
        )]
        fn conflict_env() {
            let _: Attrs = syn::parse_quote!(nested, default);
        }

        #[test]
        #[should_panic(expected = "duplicate attribute")]
        fn duplicates() {
            let _: Attrs = syn::parse_quote!(default, default);
        }

        #[test]
        fn determine_shapes() {
            macro_rules! case {
                ($input:ty, $option:literal, $with_origin:literal) => {
                    let ty: syn::Type = syn::parse_quote!($input);
                    let shape = ParameterTypeShape::analyze(&ty);
                    assert_eq!(
                        shape,
                        ParameterTypeShape {
                            option: $option,
                            with_origin: $with_origin
                        }
                    );
                };
            }

            case!(Something, false, false);
            case!(Option<Something>, true, false);
            case!(Option<WithOrigin<Something>>, true, true);
            case!(WithOrigin<Something>, false, true);
            case!(WithOrigin<Option<Something>>, false, true);
            case!(Option<Option<WithOrigin<Something>>>, true, false);
            case!(
                std::option::Option<whatever::WithOrigin<Something>>,
                true,
                true
            );
        }
    }
}

/// Generating code based on [`model`]
mod codegen {
    use proc_macro2::TokenStream;
    use quote::quote;

    pub struct Ir {
        /// The type we are implementing `ReadConfig` for
        pub ident: syn::Ident,
        pub entries: Vec<Entry>,
    }

    impl Ir {
        pub fn generate(self) -> TokenStream {
            let (read_fields, unwrap_fields): (Vec<_>, Vec<_>) = self
                .entries
                .into_iter()
                .map(Entry::generate)
                .map(|EntryParts { read, unwrap }| (read, unwrap))
                .unzip();

            let ident = self.ident;

            quote! {
                impl ::iroha_config_base::reader::ReadConfig for #ident {
                    fn read(
                        __reader: ::iroha_config_base::reader::ConfigReader
                    ) -> (
                        ::iroha_config_base::reader::OkAfterFinish<Self>,
                        ::iroha_config_base::reader::ConfigReader
                    )
                    where
                        Self: Sized,
                    {
                        #(#read_fields)*

                        (
                            ::iroha_config_base::reader::OkAfterFinish::value_fn(|| Self {
                                #(#unwrap_fields),*
                            }),
                            __reader
                        )
                    }
                }
            }
        }
    }

    pub struct Entry {
        pub ident: syn::Ident,
        pub kind: EntryKind,
    }

    impl Entry {
        fn generate(self) -> EntryParts {
            let Self { kind, ident } = self;

            let read = match kind {
                EntryKind::Nested => {
                    quote! { let (#ident, __reader) = __reader.read_nested(stringify!(#ident)); }
                }
                EntryKind::Parameter {
                    parse,
                    evaluation,
                    with_origin,
                } => {
                    let mut read = quote! {
                        let (#ident, __reader) = __reader
                    };
                    read.extend(match parse {
                        ParseParameter::FileOnly => {
                            quote! { .parameter([stringify!(#ident)]) }
                        }
                        ParseParameter::FileAndEnv { var } => {
                            quote! {
                                .parameter([stringify!(#ident)])
                                .env(#var)
                            }
                        }
                        ParseParameter::EnvOnly { var } => {
                            quote! { .parameter_env([stringify!(#ident)], #var) }
                        }
                    });
                    read.extend(match evaluation {
                        Evaluation::Required => quote! { .value_required() },
                        Evaluation::OrElse(expr) => quote! { .value_or_else(|| #expr) },
                        Evaluation::OrDefault => quote! { .value_or_default() },
                        Evaluation::Optional => quote! { .value_optional() },
                    });
                    read.extend(if with_origin {
                        quote! { .finish_with_origin(); }
                    } else {
                        quote! { .finish(); }
                    });
                    read
                }
            };

            EntryParts {
                read,
                unwrap: quote! { #ident: #ident.unwrap() },
            }
        }
    }

    struct EntryParts {
        read: TokenStream,
        unwrap: TokenStream,
    }

    pub enum EntryKind {
        Parameter {
            parse: ParseParameter,
            evaluation: Evaluation,
            with_origin: bool,
        },
        Nested,
    }

    pub enum ParseParameter {
        FileOnly,
        FileAndEnv { var: syn::LitStr },
        EnvOnly { var: syn::LitStr },
    }

    pub enum Evaluation {
        Required,
        OrElse(syn::Expr),
        OrDefault,
        Optional,
    }

    #[cfg(test)]
    mod tests {
        use expect_test::expect;
        use syn::parse_quote;

        use super::*;

        #[test]
        fn entry_with_env_reading() {
            let entry = Entry {
                ident: parse_quote!(test),
                kind: EntryKind::Parameter {
                    parse: ParseParameter::FileAndEnv {
                        var: parse_quote!("TEST_ENV"),
                    },
                    evaluation: Evaluation::Required,
                    with_origin: false,
                },
            };

            let actual = entry.generate().read.to_string();

            expect![[r#"let (test , __reader) = __reader . parameter ([stringify ! (test)]) . env ("TEST_ENV") . value_required () . finish () ;"#]].assert_eq(&actual);
        }
    }
}
