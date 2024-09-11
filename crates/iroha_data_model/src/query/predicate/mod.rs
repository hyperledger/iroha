//! Contain definitions of predicates for different types and a DSL to build them.
//!
//! # Implementation details of the predicate DSL
//!
//! There are three main components to the predicate DSL:
//! - Prototypes
//! - Projectors
//! - Atomic predicates and combinators
//!
//! Prototype is a structure that mimics an object the predicate is being built on.
//! You can call methods on it to build predicate directly (like [`prototypes::account::AccountIdPrototype::eq`]) or access one of its fields, which are all prototypes of the elements of the object (like `account_id.domain_id`).
//!
//! Projectors are needed for inner elements of prototypes to remember the object they are part of, so that `account_id.domain_id` would still build `AccountIdPredicateBox`es, while still being an `DomainIdPrototype`.
//!
//! This is achieved by passing an implementation of [`projectors::ObjectProjector`] trait to the prototype. An object projector accepts a predicate of a more specific type and returns a predicate of a more general type wrapped in a projection.
//!
//! For example, `AccountIdDomainIdProjector` accepts a predicate on `DomainId` makes a predicate on `AccountId` by wrapping it with `AccountIdDomainIdProjection`. Notice the difference between projector and projection: projector is just an utility type, while projection is a predicate.
//!
//! ## Predicate combinators and normalization
//!
//! There are also two representations of the predicates:
//! - Normalized representation, which is designed for serialization and evaluation
//! - AST representation, which is designed for type-checking and easy & efficient composition
//!
//! Normalized representation consists of [`CompoundPredicate<T>`], with `T` being an atomic predicate box for that type (like [`predicate_atoms::account::AccountIdPredicateBox`]).
//! The [`CompoundPredicate`] layer implements logical operators on top of the atomic predicate, while the projections are handled with the atomic predicate itself, with variants like [`predicate_atoms::account::AccountIdPredicateBox::DomainId`].
//!
//! Normalized representation aims to reduce the number of types not to bloat the schema and reduce redundancy.
//!
//! Predicates in the normalized representation can be evaluated using the [`EvaluatePredicate`] trait.
//!
//! Ast predicates are more numerous: they include atomic predicates (like [`predicate_atoms::account::AccountIdPredicateBox`]), logical combinators (three types in [`predicate_combinators`]), and projections (like [`projectors::AccountIdDomainIdProjection`]).
//!
//! Ast predicates implement [`AstPredicate<T>`] the trait with `T` being the atomic predicate box they normalize into.
//! The [`AstPredicate<T>`] defines the logic for converting the AST into the normalized representation.

pub mod predicate_ast_extensions;
pub mod predicate_atoms;
pub mod predicate_combinators;
pub mod projectors;
pub mod prototypes;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};

use super::*;

/// Trait defining how to apply a predicate to a value `T`.
pub trait EvaluatePredicate<T: ?Sized> {
    /// The result of applying the predicate to a value.
    fn applies(&self, input: &T) -> bool;
}

/// A predicate combinator adding support for logical operations on some atomic (basis) predicate type.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum CompoundPredicate<Atom> {
    /// An atomic predicate as-is.
    Atom(Atom),
    /// A negation of a compound predicate.
    Not(Box<Self>),
    /// A conjunction of multiple predicates.
    And(Vec<Self>),
    /// A disjunction of multiple predicates.
    Or(Vec<Self>),
}

impl<Atom> CompoundPredicate<Atom> {
    /// A compound predicate that always evaluates to `true`.
    pub const PASS: Self = Self::And(Vec::new());
    /// A compound predicate that always evaluates to `false`.
    pub const FAIL: Self = Self::Or(Vec::new());

    /// Negate the predicate.
    #[allow(clippy::should_implement_trait)]
    // not implementing std::ops::Not, because
    // - don't need it used as an overloaded operator (most of this happens with AST predicates)
    // - making this symmetric with `and` and `or` would require renaming them to `bitand` and `bitor` which is a downgrade IMO
    #[must_use]
    pub fn not(self) -> Self {
        match self {
            // if the top-level predicate is a negation, we can just remove it
            CompoundPredicate::Not(expr) => *expr,
            this => CompoundPredicate::Not(Box::new(this)),
        }
    }

    /// Combine two predicates with an "and" operation.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            // if any of the predicates is an and - flatten it
            (CompoundPredicate::And(mut and_list), other) => {
                and_list.push(other);
                CompoundPredicate::And(and_list)
            }
            (this, CompoundPredicate::And(mut and_list)) => {
                // push to front to preserve user-specified order (our predicates are short-circuiting)
                and_list.insert(0, this);
                CompoundPredicate::And(and_list)
            }
            (this, other) => CompoundPredicate::And(vec![this, other]),
        }
    }

    /// Combine two predicates with an "or" operation.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            // if any of the predicates is an or - flatten it
            (CompoundPredicate::Or(mut or_list), other) => {
                or_list.push(other);
                CompoundPredicate::Or(or_list)
            }
            (this, CompoundPredicate::Or(mut or_list)) => {
                // push to front to preserve user-specified order (our predicates are short-circuiting)
                or_list.insert(0, this);
                CompoundPredicate::Or(or_list)
            }
            (this, other) => CompoundPredicate::Or(vec![this, other]),
        }
    }
}

/// A marker trait allowing to associate a predicate box type corresponding to the type.
pub trait HasPredicateBox {
    /// The type of the atomic predicate corresponding to the type.
    type PredicateBoxType: EvaluatePredicate<Self>;
}

/// A marker trait allowing to get a type of prototype for the type.
///
/// Not that it is implemented on predicate, not on concrete types. That is because some predicates, like [`predicate_atoms::StringPredicateBox`] are applicable to multiple types.
pub trait HasPrototype {
    /// Get a prototype for the predicate, with the given projector.
    type Prototype<Projector: Default>: Default;
}

impl<T, Atom> EvaluatePredicate<T> for CompoundPredicate<Atom>
where
    Atom: EvaluatePredicate<T>,
{
    fn applies(&self, input: &T) -> bool {
        match self {
            CompoundPredicate::Atom(atom) => atom.applies(input),
            CompoundPredicate::Not(expr) => !expr.applies(input),
            CompoundPredicate::And(exprs) => exprs.iter().all(|expr| expr.applies(input)),
            CompoundPredicate::Or(exprs) => exprs.iter().any(|expr| expr.applies(input)),
        }
    }
}

/// Trait that marks a predicate in AST representation. The `PredType` generic parameters defines the type of the atomic predicate this predicate normalizes into.
///
/// The main task is to facilitate normalization:
/// the extraction of all logical combinators ("not", "and" and "or") to the outer scope,
/// leaving only projections as "atomic" predicates
pub trait AstPredicate<PredType> {
    /// Normalize the predicate, applying `proj` to every atomic predicate emitted.
    fn normalize_with_proj<OutputType, Proj>(self, proj: Proj) -> CompoundPredicate<OutputType>
    where
        Proj: Fn(PredType) -> OutputType + Copy;
}

pub mod prelude {
    //! Re-export important types and traits for glob import `(::*)`
    pub use super::{predicate_atoms::prelude::*, CompoundPredicate, EvaluatePredicate};
}

#[cfg(test)]
mod test {
    use iroha_crypto::PublicKey;

    use crate::{
        account::AccountId,
        asset::AssetId,
        domain::DomainId,
        prelude::{AssetDefinitionIdPredicateBox, AssetIdPredicateBox, StringPredicateBox},
        query::predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_atoms::{
                account::{AccountIdPredicateBox, AccountPredicateBox},
                domain::DomainIdPredicateBox,
                PublicKeyPredicateBox,
            },
            projectors::BaseProjector,
            prototypes::account::AccountPrototype,
            CompoundPredicate,
        },
    };

    /// Smoke test that creates a simple predicate using a prototype
    #[test]
    fn test_prototype_api() {
        let alice_account_id: AccountId =
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland"
                .parse()
                .unwrap();

        // construct a prototype (done by the machinery)
        let account = AccountPrototype::<BaseProjector<AccountPredicateBox>>::default();
        // take a look at the type name (it should be `AccountIdPrototype<AccountIdProjector<BaseProjector<AccountPredicateBox>>>`)
        #[allow(unused)]
        let account_id_prototype = account.id;
        // make a predicate from it (done by the user)
        let predicate = account.id.eq(alice_account_id.clone());
        // normalize it (done by the machinery)
        let predicate_norm = predicate.normalize();

        // check that the predicate is correct
        assert_eq!(
            predicate_norm,
            CompoundPredicate::Atom(AccountPredicateBox::Id(AccountIdPredicateBox::Equals(
                alice_account_id
            )))
        );
    }

    /// Same as [`test_prototype_api`], but uses the `AccountPredicateBox::build()` method
    #[test]
    fn test_builder_api() {
        let alice_account_id: AccountId =
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland"
                .parse()
                .unwrap();

        let predicate_norm =
            AccountPredicateBox::build(|account| account.id.eq(alice_account_id.clone()));

        // check that the predicate is correct
        assert_eq!(
            predicate_norm,
            CompoundPredicate::Atom(AccountPredicateBox::Id(AccountIdPredicateBox::Equals(
                alice_account_id
            )))
        );
    }

    /// Create a denormalized predicate (logical combinator inside a projection), check that it normalizes correctly
    #[test]
    fn test_prototype_normalization() {
        let alice_signatory: PublicKey =
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .unwrap();
        let alice_domain_id: DomainId = "wonderland".parse().unwrap();

        let account_predicate_denorm = AccountPredicateBox::build_fragment(|account| {
            let account_id_predicate = AccountIdPredicateBox::build_fragment(|account_id| {
                account_id
                    .signatory
                    .eq(alice_signatory.clone())
                    .and(account_id.domain_id.eq(alice_domain_id.clone()))
            });

            // note that we use a non-normalized predicate, built with `build_fragment`
            account.id.satisfies(account_id_predicate)
        });
        let account_predicate = account_predicate_denorm.normalize();

        // check that the predicate is correct
        assert_eq!(
            account_predicate,
            CompoundPredicate::And(vec![
                CompoundPredicate::Atom(AccountPredicateBox::Id(AccountIdPredicateBox::Signatory(
                    PublicKeyPredicateBox::Equals(alice_signatory)
                ))),
                CompoundPredicate::Atom(AccountPredicateBox::Id(AccountIdPredicateBox::DomainId(
                    DomainIdPredicateBox::Equals(alice_domain_id)
                )))
            ])
        );
    }

    /// Tests operator overloading shorthand combinators for various cases
    #[test]
    fn test_operator_overloading() {
        let asset_id1: AssetId = "xor##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
        let asset_id2: AssetId = "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();

        let asset_predicate = AssetIdPredicateBox::build(|id| {
            // DSL uses `|` and `&` operators, even though the actual logic is short-circuiting internally.
            // this is because `||` and `&&` are not overloadable in Rust

            // check that operator overloading works on atomic predicates
            let or_predicate1 = id.eq(asset_id1.clone()) | id.eq(asset_id2.clone());

            // check that operator overloading works on projection predicates
            let or_predicate2 = id.definition_id.name.starts_with("xor")
                | id.account.domain_id.eq("wonderland".parse().unwrap());

            // check that operator overloading works on predicate combinators
            or_predicate1 & or_predicate2
        });

        assert_eq!(
            asset_predicate,
            CompoundPredicate::And(vec![
                CompoundPredicate::Or(vec![
                    CompoundPredicate::Atom(AssetIdPredicateBox::Equals(asset_id1)),
                    CompoundPredicate::Atom(AssetIdPredicateBox::Equals(asset_id2)),
                ]),
                CompoundPredicate::Or(vec![
                    CompoundPredicate::Atom(AssetIdPredicateBox::DefinitionId(
                        AssetDefinitionIdPredicateBox::Name(StringPredicateBox::StartsWith(
                            "xor".to_string()
                        ))
                    )),
                    CompoundPredicate::Atom(AssetIdPredicateBox::AccountId(
                        AccountIdPredicateBox::DomainId(DomainIdPredicateBox::Equals(
                            "wonderland".parse().unwrap()
                        ))
                    )),
                ]),
            ])
        );
    }

    #[test]
    fn test_flattening() {
        // check `and` flattening
        let right_assoc = StringPredicateBox::build(|s| {
            s.starts_with("a") & (s.ends_with("b") & s.ends_with("c"))
        });
        let left_assoc = StringPredicateBox::build(|s| {
            (s.starts_with("a") & s.ends_with("b")) & s.ends_with("c")
        });

        // the user ordering should be preserved, to mimic the short-circuiting behavior of `&&`
        assert_eq!(right_assoc, left_assoc);

        // the predicates should get flattened
        assert_eq!(
            right_assoc,
            CompoundPredicate::And(vec![
                CompoundPredicate::Atom(StringPredicateBox::StartsWith("a".to_string())),
                CompoundPredicate::Atom(StringPredicateBox::EndsWith("b".to_string())),
                CompoundPredicate::Atom(StringPredicateBox::EndsWith("c".to_string())),
            ])
        );

        // check the same for `or`
        let right_assoc = StringPredicateBox::build(|s| {
            s.starts_with("a") | (s.ends_with("b") | s.ends_with("c"))
        });
        let left_assoc = StringPredicateBox::build(|s| {
            (s.starts_with("a") | s.ends_with("b")) | s.ends_with("c")
        });

        // the user ordering should be preserved, to mimic the short-circuiting behavior of `||`
        assert_eq!(right_assoc, left_assoc);

        // the predicates should get flattened
        assert_eq!(
            right_assoc,
            CompoundPredicate::Or(vec![
                CompoundPredicate::Atom(StringPredicateBox::StartsWith("a".to_string())),
                CompoundPredicate::Atom(StringPredicateBox::EndsWith("b".to_string())),
                CompoundPredicate::Atom(StringPredicateBox::EndsWith("c".to_string())),
            ])
        );

        // check `not` flattening
        let not_flat = StringPredicateBox::build(|s| !!s.starts_with("a"));

        assert_eq!(
            not_flat,
            CompoundPredicate::Atom(StringPredicateBox::StartsWith("a".to_string()))
        );
    }
}
