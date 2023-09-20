// TODO: add docs
#![allow(missing_docs)]

use std::{convert::TryFrom, iter::Peekable, str::FromStr};

use litrs::Literal;
use proc_macro2::{
    token_stream::IntoIter,
    TokenStream, TokenTree,
    TokenTree::{Ident, Punct},
};
use quote::quote;

#[derive(PartialEq)]
enum ExprType {
    Nil,
    Int,
    Bool,
}

// within the compiler, these generate tokens for
// Value
struct ParsedExpr {
    t: ExprType,
    tokens: TokenStream,
}

struct Operator(i32, ExprType, &'static str);

fn parse_literal(it: &mut Peekable<IntoIter>) -> ParsedExpr {
    let token = it
        .next()
        .expect("failed to parse literal, hit end of string");

    match token {
        Punct(ref x) => {
            if x.as_char() == '(' {
                let v = parse_expr(it);

                it.next()
                    .expect("expected closing paren, hit end of string");
                return v;
            }
        }

        // boolean literals
        Ident(ref x) => match x.to_string().as_str() {
            "true" => {
                return ParsedExpr {
                    t: ExprType::Bool,
                    tokens: quote! { true },
                }
            }
            "false" => {
                return ParsedExpr {
                    t: ExprType::Bool,
                    tokens: quote! { false },
                }
            }

            // unary not
            "not" => {
                let v = parse_literal(it).tokens;
                return ParsedExpr {
                    t: ExprType::Bool,
                    tokens: quote! { Not::new(#v) },
                };
            }
            _ => panic!("error: unknown identifier"),
        },

        // kinda ugly but we fallthrough basically
        _ => {}
    }

    // integer literals
    if let Ok(Literal::Integer(i)) = Literal::try_from(token) {
        let v = i.value::<u64>().expect("i don't think this integer fits?");
        return ParsedExpr {
            t: ExprType::Int,
            tokens: quote! { #v },
        };
    }

    ParsedExpr {
        t: ExprType::Nil,
        tokens: TokenStream::new(),
    }
}

fn precedence(it: &mut Peekable<IntoIter>) -> Option<Operator> {
    match it.peek() {
        Some(Punct(x)) => match x.as_char() {
            // arithmatic
            '+' => Some(Operator(4, ExprType::Int, "Add")),
            '-' => Some(Operator(4, ExprType::Int, "Subtract")),
            '*' => Some(Operator(3, ExprType::Int, "Multiply")),

            // compares
            '=' => Some(Operator(2, ExprType::Int, "Equal")),
            '>' => Some(Operator(2, ExprType::Int, "Greater")),
            '<' => Some(Operator(2, ExprType::Int, "Less")),
            _ => None,
        },
        Some(Ident(ref x)) => match x.to_string().as_str() {
            "and" => Some(Operator(1, ExprType::Bool, "And")),
            "or" => Some(Operator(1, ExprType::Bool, "Or")),
            _ => None,
        },
        _ => None,
    }
}

/// precedence walking
fn parse_binop(it: &mut Peekable<IntoIter>, min_prec: i32) -> ParsedExpr {
    let mut lhs = parse_literal(it);
    while let Some(prec) = precedence(it) {
        it.next();
        if prec.0 < min_prec {
            break;
        }

        let op = proc_macro2::TokenStream::from_str(prec.2).unwrap();
        let rhs = parse_literal(it);

        assert!(
            lhs.t == prec.1 && rhs.t == prec.1,
            "cannot perform binary operator on these!"
        );

        let lhs_tokens = lhs.tokens;
        let rhs_tokens = rhs.tokens;
        lhs = ParsedExpr {
            t: prec.1,
            tokens: quote! { #op::new(#lhs_tokens, #rhs_tokens) },
        };
    }

    lhs
}

fn is_ident(a: &TokenTree, b: &'static str) -> bool {
    if let Ident(ref x) = a {
        return x.to_string().as_str() == b;
    }

    false
}

fn parse_expr(it: &mut Peekable<IntoIter>) -> ParsedExpr {
    if is_ident(it.peek().expect("hit end of string"), "if") {
        it.next();

        let cond_tokens = parse_binop(it, 0).tokens;
        assert!(
            is_ident(&it.next().expect("hit end of string"), "then"),
            "expected 'then'"
        );

        let true_case = parse_binop(it, 0);
        assert!(
            is_ident(&it.next().expect("hit end of string"), "else"),
            "expected 'else'"
        );

        let false_case = parse_binop(it, 0);
        assert!(
            true_case.t == false_case.t,
            "both types in a conditional must match"
        );

        let true_tokens = true_case.tokens;
        let false_tokens = false_case.tokens;
        return ParsedExpr {
            t: ExprType::Int,
            tokens: quote! { If::new(#cond_tokens, #true_tokens, #false_tokens) },
        };
    }

    // normal expression
    parse_binop(it, 0)
}

/// Convert arithmetic expression into bare expression in the iroha data model.
///
/// Basic arithmetic and boolean expressions are supported, namely: `> < = + - * and or if not`
///
/// # Examples
///
/// ```
/// extern crate iroha_dsl;
/// extern crate iroha_data_model;
/// use iroha_dsl::expr;
/// use iroha_data_model::{prelude::*, ParseError};
///
/// fn main() {
///     assert_eq!(expr!(54654*5 + 1), Add::new(Multiply::new(54654_u64, 5_u64), 1_u64));
///     println!("{}", expr!(not true and false));
///     println!("{}", expr!(if 4 = 4 then 64 else 32));
/// }
/// ```
#[proc_macro]
pub fn expr(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = proc_macro2::TokenStream::from(input);
    let mut it = input.into_iter().peekable();

    proc_macro::TokenStream::from(parse_expr(&mut it).tokens)
}
