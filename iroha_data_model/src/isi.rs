//! This library contains basic Iroha Special Instructions.

#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    future_incompatible,
    nonstandard_style,
    unsafe_code,
    unused_import_braces,
    unused_results,
    variant_size_differences
)]

use super::prelude::*;
use std::fmt::Debug;

/// Generic instruction for an addition of an object to the identifiable destination.
#[derive(Debug)]
pub struct Add<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be added.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a removal of an object from the identifiable destination.
#[derive(Debug)]
pub struct Remove<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be removed.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a registration of an object to the identifiable destination.
#[derive(Debug)]
pub struct Register<D, O>
where
    D: Identifiable,
{
    /// Object which should be registered.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a mint of an object to the identifiable destination.
#[derive(Debug)]
pub struct Mint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be minted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a demint of an object to the identifiable destination.
#[derive(Debug)]
pub struct Demint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be deminted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
#[derive(Debug)]
pub struct Transfer<S: Identifiable, O, D: Identifiable>
where
    O: Value,
{
    /// Source object `Id`.
    pub source_id: S::Id,
    /// Object which should be transfered.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Mathematical instruction to compare two values and check that left is greater than right.
#[derive(Debug)]
pub struct Greater<L: Value, R: Value> {
    left: L,
    right: R,
}

/// Composite instruction for a pair of instructions.
#[derive(Debug)]
pub struct Pair {
    /// Left instruction
    pub left_instruction: Box<dyn Instruction>,
    /// Right instruction
    pub right_instruction: Box<dyn Instruction>,
}

/// Composite instruction for a conditional execution of other instructions.
#[derive(Debug)]
pub struct If {
    /// Condition to be checked.
    condition: Box<dyn Instruction>,
    /// Instruction to be executed if condition pass.
    then: Box<dyn Instruction>,
    /// Optional instruction to be executed if condition fail.
    otherwise: Option<Box<dyn Instruction>>,
}

/// Utilitary instruction to fail execution and submit an error `message`.
#[derive(Debug)]
pub struct Fail {
    /// Message to submit.
    message: String,
}

/// Composite instruction to inverse result of the another instruction.
#[derive(Debug)]
pub struct Not {
    instruction: Box<dyn Instruction>,
}

/// Marker trait for Iroha Special Instructions.
//TODO: develop derive macro for this trait
pub trait Instruction: Debug {}

impl<D, O> Instruction for Add<D, O>
where
    D: Identifiable,
    O: Value,
{
}
impl<D, O> Instruction for Remove<D, O>
where
    D: Identifiable,
    O: Value,
{
}
impl Instruction for Register<Domain, Account> {}
impl Instruction for Register<Domain, AssetDefinition> {}
impl<O> Instruction for Mint<Asset, O> where O: Value {}
impl<O> Instruction for Demint<Asset, O> where O: Value {}
impl<O> Instruction for Transfer<Asset, O, Asset> where O: Value {}
impl<LV, RV> Instruction for Greater<LV, RV>
where
    LV: Value,
    RV: Value,
{
}
impl Instruction for Pair {}
impl Instruction for If {}
impl Instruction for Fail {}
impl Instruction for Not {}

impl<D, O> Add<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Add` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Add {
            object,
            destination_id,
        }
    }
}

impl<D, O> Remove<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Remove` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Remove {
            object,
            destination_id,
        }
    }
}

impl<D, O> Register<D, O>
where
    D: Identifiable,
{
    /// Default `Register` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Register {
            object,
            destination_id,
        }
    }
}

impl<D, O> Mint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Mint` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Mint {
            object,
            destination_id,
        }
    }
}

impl<D, O> Demint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Demint` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Demint {
            object,
            destination_id,
        }
    }
}

impl<S, O, D> Transfer<S, O, D>
where
    S: Identifiable,
    D: Identifiable,
    O: Value,
{
    /// Default `Transfer` constructor.
    pub fn new(source_id: S::Id, object: O, destination_id: D::Id) -> Self {
        Transfer {
            source_id,
            object,
            destination_id,
        }
    }
}

impl<LV, RV> Greater<LV, RV>
where
    LV: Value,
    RV: Value,
{
    /// Default `Greater` constructor.
    pub fn new(left: LV, right: RV) -> Self {
        Greater { left, right }
    }
}

impl Pair {
    /// Default `Pair` constructor.
    pub fn new(
        left_instruction: Box<dyn Instruction>,
        right_instruction: Box<dyn Instruction>,
    ) -> Self {
        Pair {
            left_instruction,
            right_instruction,
        }
    }
}

impl If {
    /// Default `If` constructor.
    pub fn new(condition: Box<dyn Instruction>, then: Box<dyn Instruction>) -> Self {
        If {
            condition,
            then,
            otherwise: None,
        }
    }
    /// `If` constructor with `otherwise` instruction.
    pub fn with_otherwise(
        condition: Box<dyn Instruction>,
        then: Box<dyn Instruction>,
        otherwise: Box<dyn Instruction>,
    ) -> Self {
        If {
            condition,
            then,
            otherwise: Some(otherwise),
        }
    }
}
impl Fail {
    /// Default `Fail` constructor.
    pub fn new(message: &str) -> Self {
        Fail {
            message: message.to_string(),
        }
    }
}
impl Not {
    /// Default `Not` constructor.
    pub fn new(instruction: Box<dyn Instruction>) -> Self {
        Not { instruction }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Add, Demint, Fail, Greater, If, Mint, Not, Pair, Register, Remove, Transfer};
}
