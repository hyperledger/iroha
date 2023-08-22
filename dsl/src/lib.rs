use std::{convert::TryFrom, iter::Peekable, str::FromStr};

use enum_dispatch::enum_dispatch;
use litrs::Literal;
use proc_macro2::{
    token_stream::IntoIter,
    TokenStream, TokenTree,
    TokenTree::{Ident, Punct},
};
use quote::quote;

#[derive(PartialEq, Copy, Clone)]
enum ExprType {
    Nil,
    Int,
    Bool,

    /// RegisterBox
    Register,

    /// alice@bucket
    Account,
    /// bucket
    Domain,
    /// beans#bucket
    AssetDefinition,
    /// beans##alice@bucket
    Asset,
}

// within the compiler, these generate tokens for
// Value
struct ParsedExpr {
    t: ExprType,
    tokens: TokenStream,
}

#[enum_dispatch]
trait BinaryOperator {
    fn accept(&self, op: &String) -> bool;
    fn level(&self) -> i32;
    fn type_check(&self, lhs: ExprType, rhs: ExprType) -> ExprType;
    fn compile(&self, t: ExprType, lhs: TokenStream, rhs: TokenStream) -> TokenStream;
}

#[enum_dispatch(BinaryOperator)]
#[derive(Clone)]
enum BinaryOperatorEnum {
    TrivialBinaryOperator,
}

#[derive(Clone)]
struct TrivialBinaryOperator {
    operator: &'static str,
    precedence: i32,
    t: ExprType,
    name: &'static str,
}

impl TrivialBinaryOperator {
    const fn new(
        operator: &'static str,
        prec: i32,
        t: ExprType,
        name: &'static str,
    ) -> BinaryOperatorEnum {
        BinaryOperatorEnum::TrivialBinaryOperator(TrivialBinaryOperator {
            operator,
            precedence: prec,
            t,
            name,
        })
    }
}

impl BinaryOperator for TrivialBinaryOperator {
    fn accept(&self, op: &String) -> bool {
        self.operator == op
    }

    fn level(&self) -> i32 {
        self.precedence
    }

    fn type_check(&self, lhs: ExprType, rhs: ExprType) -> ExprType {
        assert!(
            lhs == self.t && rhs == self.t,
            "cannot perform binary operator on these!"
        );

        self.t
    }

    fn compile(&self, _t: ExprType, lhs: TokenStream, rhs: TokenStream) -> TokenStream {
        let op = proc_macro2::TokenStream::from_str(self.name).unwrap();
        quote! { #op::new(#lhs, #rhs) }
    }
}

const OPERATORS: &'static [BinaryOperatorEnum] = &[
    // arithmatic
    TrivialBinaryOperator::new("+", 1, ExprType::Int, "Add"),
    TrivialBinaryOperator::new("-", 1, ExprType::Int, "Subtract"),
    TrivialBinaryOperator::new("*", 2, ExprType::Int, "Multiply"),
    // compares
    TrivialBinaryOperator::new("=", 3, ExprType::Int, "Equal"),
    TrivialBinaryOperator::new(">", 3, ExprType::Int, "Greater"),
    TrivialBinaryOperator::new("<", 3, ExprType::Int, "Less"),
    // logical
    TrivialBinaryOperator::new("&", 4, ExprType::Bool, "And"),
    TrivialBinaryOperator::new("|", 4, ExprType::Bool, "Or"),
    TrivialBinaryOperator::new("and", 4, ExprType::Bool, "And"),
    TrivialBinaryOperator::new("or", 4, ExprType::Bool, "Or"),
];

fn infer_type_from_name(name: &str) -> ExprType {
    let len = name.len();
    let arr = name.as_bytes();

    for (i, ch) in arr.iter().enumerate() {
        match ch {
            b'@' => return ExprType::Account,
            b'#' => {
                if i + 1 < len && arr[i + 1] == b'#' {
                    return ExprType::Asset;
                } else {
                    return ExprType::AssetDefinition;
                }
            }
            _ => {}
        }
    }

    ExprType::Domain
}

fn parse_literal(it: &mut Peekable<IntoIter>) -> ParsedExpr {
    let token = it
        .next()
        .expect("failed to parse literal, hit end of string");

    match token {
        Punct(ref x) => match x.as_char() {
            '(' => {
                let v = parse_expr(it);

                it.next()
                    .expect("expected closing paren, hit end of string");
                return v;
            }
            '!' => {
                let v = parse_literal(it).tokens;
                return ParsedExpr {
                    t: ExprType::Bool,
                    tokens: quote! { Not::new(#v) },
                };
            }
            _ => {}
        },

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
    match Literal::try_from(token) {
        Ok(Literal::Integer(i)) => {
            let v = i.value::<u64>().expect("i don't think this integer fits?");
            return ParsedExpr {
                t: ExprType::Int,
                tokens: quote! { #v },
            };
        }

        Ok(Literal::String(lit)) => {
            let v = lit.value();
            let t = infer_type_from_name(v);

            let tokens = match t {
                ExprType::Domain => quote! { Domain::new(#v.parse().unwrap()) },
                ExprType::Asset => quote! { Asset::new(#v.parse().unwrap()) },
                ExprType::Account => quote! { Account::new(#v.parse().unwrap(), []) },
                ExprType::AssetDefinition => quote! { AssetDefinition::new(#v.parse().unwrap()) },
                _ => todo!(),
            };

            return ParsedExpr { t, tokens };
        }

        _ => {
            return ParsedExpr {
                t: ExprType::Nil,
                tokens: TokenStream::new(),
            }
        }
    }
}

fn get_binop(it: &mut Peekable<IntoIter>) -> Option<BinaryOperatorEnum> {
    let op_name = it.peek()?.to_string();

    // find a matching operator
    for op in OPERATORS {
        if op.accept(&op_name) {
            return Some(op.clone());
        }
    }

    None
}

/// precedence walking
fn parse_binop(it: &mut Peekable<IntoIter>, min_prec: i32) -> ParsedExpr {
    let mut lhs = parse_literal(it);
    while let Some(op) = get_binop(it) {
        let prec = op.level();
        if op.level() < min_prec {
            break;
        }

        it.next();

        let rhs = parse_binop(it, prec + 1);
        let t = op.type_check(lhs.t, rhs.t);

        lhs = ParsedExpr {
            t,
            tokens: op.compile(t, lhs.tokens, rhs.tokens),
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
    match it.peek() {
        Some(Ident(ref x)) => match x.to_string().as_str() {
            "if" => {
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
            "register" => {
                it.next();

                let e = parse_binop(it, 0).tokens;
                return ParsedExpr {
                    t: ExprType::Register,
                    tokens: quote! { RegisterBox::new(#e) },
                };
            }
            _ => {}
        },
        _ => {}
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
