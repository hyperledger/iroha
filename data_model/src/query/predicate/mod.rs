#![warn(missing_docs)] // TODO
#![allow(missing_copy_implementations)]
//! Predicate-related logic. Should contain predicate-related `impl`s.

pub mod predicate_ast_extensions;
pub mod predicate_atoms;
pub mod predicate_combinators;
pub mod projectors;
pub mod prototypes;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};

use super::*;

/// Trait for generic predicates.
pub trait PredicateTrait<T: ?Sized> {
    /// The result of applying the predicate to a value.
    fn applies(&self, input: &T) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum CompoundPredicate<Atom> {
    Atom(Atom),
    Not(Box<Self>),
    And(Vec<Self>),
    Or(Vec<Self>),
}

impl<Atom> CompoundPredicate<Atom> {
    /// A compound predicate that always evaluates to `true`.
    pub const PASS: Self = Self::And(Vec::new());
    /// A compound predicate that always evaluates to `false`.
    pub const FAIL: Self = Self::Or(Vec::new());

    pub fn and(self, other: Self) -> Self {
        match self {
            CompoundPredicate::And(mut and_list) => {
                and_list.push(other);
                CompoundPredicate::And(and_list)
            }
            this => CompoundPredicate::And(vec![this, other]),
        }
    }
}

/// A marker trait allowing to associate a predicate box type corresponding to the type
pub trait HasPredicateBox {
    type PredicateBoxType: PredicateTrait<Self>; // + AstPredicate<Self::PredicateBoxType>
}

/// A marker trait allowing to associate an object prototype used to build a certain predicate type
pub trait HasPrototype {
    type Prototype<Projector: Default>: Default;
}

impl<T, Atom> PredicateTrait<T> for CompoundPredicate<Atom>
where
    Atom: PredicateTrait<T>,
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

/// Trait that marks an ast-form predicate
///
/// The main task is to facilitate normalization:
/// the extraction of all logical combinators ("not", "and" and "or") to the outer scope,
/// leaving only projections as "atomic" predicates
pub trait AstPredicate<PredType> {
    fn normalize_with_proj<OutputType, Proj>(self, proj: Proj) -> CompoundPredicate<OutputType>
    where
        Proj: Fn(PredType) -> OutputType + Copy;
}

pub mod prelude {
    //! Re-export important types and traits for glob import `(::*)`
    pub use super::{predicate_atoms::prelude::*, CompoundPredicate, PredicateTrait};
}

#[cfg(test)]
mod test {
    use iroha_crypto::PublicKey;

    use crate::{
        account::AccountId,
        domain::DomainId,
        query::predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_atoms::{
                account::{AccountIdPredicateBox, AccountPredicateBox},
                asset::AssetPredicateBox,
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
                // can't use `&&` because it's not overloadable =(
                account_id.signatory.eq(alice_signatory.clone())
                    & account_id.domain_id.eq(alice_domain_id.clone())

                // alternative syntax w/o operator overloading
                // account_id
                //     .signatory
                //     .eq(alice_signatory.clone())
                //     .and(account_id.domain_id.eq(alice_domain_id.clone()))
            });

            // TODO: do we want to allow `CompoundPredicate` to be passed here? Converting from the normalized representation it uses is kind of inefficient...
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
        AssetPredicateBox::build(|asset| {
            let id = asset.id;

            id.definition_id.name.starts_with("xor")
                | id.account.domain_id.eq("wonderland".parse().unwrap())
        });

        // TODO
    }
}
