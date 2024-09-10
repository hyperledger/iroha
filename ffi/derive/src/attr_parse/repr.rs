//! This module provides parsing of standard rust `#[repr(...)]` attributes.

// TODO: it's probably a common functionality, move it to `iroha_derive_primitives` when it will use syn 2.0

use darling::{error::Accumulator, util::SpannedValue, FromAttributes};
use proc_macro2::{Delimiter, Span};
use strum::{Display, EnumString};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    spanned::Spanned as _,
    Attribute, Meta, Token,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ReprPrimitive {
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ReprKind {
    C,
    Transparent,
    Primitive(ReprPrimitive),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ReprAlignment {
    Packed,
    Aligned(u32),
}

#[derive(Debug)]
enum ReprToken {
    Kind(ReprKind),
    Alignment(ReprAlignment),
}

#[derive(Debug)]
struct SpannedReprToken {
    span: Span,
    token: ReprToken,
}

impl Parse for SpannedReprToken {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let (span, token) = input.step(|cursor| {
            let Some((ident, after_token)) = cursor.ident() else {
                return Err(cursor.error("Expected repr kind"));
            };

            let mut span = ident.span();

            let str = ident.to_string();
            if let Ok(primitive) = str.parse() {
                return Ok(((span,ReprToken::Kind(ReprKind::Primitive(primitive))), after_token));
            }

            match str.as_str() {
                "C" => Ok(((span,ReprToken::Kind(ReprKind::C)), after_token)),
                "transparent" => Ok(((span,ReprToken::Kind(ReprKind::Transparent)), after_token)),
                "packed" => Ok(((span,ReprToken::Alignment(ReprAlignment::Packed)), after_token)),
                "aligned" => {
                    let Some((inside_of_group, group_span, after_group)) = after_token.group(Delimiter::Parenthesis) else {
                        return Err(cursor.error("Expected a number inside of a `repr(aligned(<number>)), found `repr(aligned)`"));
                    };

                    span = span.join(group_span.span()).unwrap_or(span);
                    let alignment = syn::parse2::<syn::LitInt>(inside_of_group.token_stream())?;
                    let alignment = alignment.base10_parse::<u32>()?;

                    Ok((
                        (span, ReprToken::Alignment(ReprAlignment::Aligned(alignment))),
                        after_group,
                    ))
                }
                _ => Err(cursor.error("Unrecognized repr kind")),
            }
        })?;

        Ok(SpannedReprToken { span, token })
    }
}

#[derive(Debug)]
struct ReprTokens(Vec<SpannedReprToken>);

impl Parse for ReprTokens {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self(
            Punctuated::<_, Token![,]>::parse_terminated(input)?
                .into_iter()
                .collect(),
        ))
    }
}

#[derive(Debug, Default)]
pub struct Repr {
    /// Repr kind
    ///
    /// The value of None means no repr was specified.
    /// It corresponds what is called `repr(Rust)` in the Rust reference.
    /// It's not a real syntax though
    pub kind: Option<SpannedValue<ReprKind>>,
    /// Repr alignment
    pub alignment: Option<SpannedValue<ReprAlignment>>,
}

impl FromAttributes for Repr {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        let mut result = Repr::default();
        let mut accumulator = Accumulator::default();

        for attr in attrs {
            if attr.path().is_ident("repr") {
                match &attr.meta {
                    Meta::Path(_) | Meta::NameValue(_) => accumulator.push(
                        darling::Error::custom(
                            "Unsupported repr shape, expected parenthesized list",
                        )
                        .with_span(&attr),
                    ),
                    Meta::List(list) => {
                        let Some(tokens) = accumulator.handle(
                            syn::parse2::<ReprTokens>(list.tokens.clone()).map_err(Into::into),
                        ) else {
                            continue;
                        };

                        for SpannedReprToken { token, span } in tokens.0 {
                            match token {
                                ReprToken::Kind(kind) => {
                                    if result.kind.is_some() {
                                        accumulator.push(
                                            darling::error::Error::custom("Duplicate repr kind")
                                                .with_span(&span),
                                        );
                                    }
                                    result.kind = Some(SpannedValue::new(kind, span));
                                }
                                ReprToken::Alignment(alignment) => {
                                    if result.alignment.is_some() {
                                        accumulator.push(
                                            darling::error::Error::custom(
                                                "Duplicate repr alignment",
                                            )
                                            .with_span(&span),
                                        );
                                    }
                                    result.alignment = Some(SpannedValue::new(alignment, span));
                                }
                            }
                        }
                    }
                }
            }
        }

        accumulator.finish_with(result)
    }
}

#[cfg(test)]
mod test {
    use darling::FromAttributes as _;
    use proc_macro2::TokenStream;
    use quote::quote;

    use super::{Repr, ReprAlignment, ReprKind, ReprPrimitive};

    fn parse_repr(attrs: TokenStream) -> darling::Result<Repr> {
        let attrs = crate::parse_attributes(attrs);
        Repr::from_attributes(&attrs)
    }

    macro_rules! assert_repr_ok {
        ($( #[$meta:meta] )*,
            Repr {
                kind: $kind:expr,
                alignment: $alignment:expr,
            }
        ) => {
            {
                let repr = parse_repr(quote!(
                    $( #[$meta] )*
                )).unwrap();
                assert_eq!(repr.kind.map(|v| *v.as_ref()), $kind, "The parsed repr kind does not match the expected one");
                assert_eq!(repr.alignment.map(|v| *v.as_ref()), $alignment, "The parsed repr alignment does not match the expected one");
            }
        };
    }

    #[test]
    fn repr_empty() {
        assert_repr_ok!(
            #[aboba], // unrelated attr
            Repr {
                kind: None,
                alignment: None,
            }
        );
    }

    #[test]
    fn repr_c() {
        assert_repr_ok!(
            #[repr(C)],
            Repr {
                kind: Some(ReprKind::C),
                alignment: None,
            }
        );
    }

    #[test]
    fn aligned() {
        assert_repr_ok!(
            #[repr(aligned(4))],
            Repr {
                kind: None,
                alignment: Some(ReprAlignment::Aligned(4)),
            }
        );
    }

    #[test]
    fn primitive() {
        assert_repr_ok!(
            #[repr(u8)],
            Repr {
                kind: Some(ReprKind::Primitive(ReprPrimitive::U8)),
                alignment: None,
            }
        );
    }

    #[test]
    fn kind_and_alignment() {
        assert_repr_ok!(
            #[repr(C, aligned(4))],
            Repr {
                kind: Some(ReprKind::C),
                alignment: Some(ReprAlignment::Aligned(4)),
            }
        );
    }

    macro_rules! assert_repr_err {
        ($( #[$meta:meta] )*, $error:expr) => {
            assert_eq!(
                parse_repr(quote!(
                    $( #[$meta] )*
                ))
                .unwrap_err()
                .to_string(),
                $error,
                "The error message does not match the expected one"
            )
        };
    }

    // we don't care __that__ much about good errors here
    // rustc should already handle the #[repr] attributes and produce reasonable errors
    #[test]
    fn err_duplicate_kind() {
        assert_repr_err!(
            #[repr(C)] #[repr(C)],
            "Duplicate repr kind"
        );
        assert_repr_err!(
            #[repr(C)] #[repr(u32)],
            "Duplicate repr kind"
        );
    }

    #[test]
    fn err_duplicate_alignment() {
        assert_repr_err!(
            #[repr(aligned(4))] #[repr(aligned(4))],
            "Duplicate repr alignment"
        );
        assert_repr_err!(
            #[repr(aligned(4))] #[repr(aligned(8))],
            "Duplicate repr alignment"
        );
    }

    #[test]
    fn err_incomplete_alignment() {
        assert_repr_err!(
            #[repr(aligned)],
            "Expected a number inside of a `repr(aligned(<number>)), found `repr(aligned)`"
        );
        assert_repr_err!(
            #[repr(aligned())],
            "unexpected end of input, expected integer literal"
        );
        assert_repr_err!(
            #[repr(aligned(4,))],
            "unexpected token"
        );
        assert_repr_err!(
            #[repr(aligned(4, 8))],
            "unexpected token"
        );
    }

    #[test]
    fn err_unknown_kind() {
        assert_repr_err!(
            #[repr(unknown)],
            "Unrecognized repr kind"
        );
    }
}
