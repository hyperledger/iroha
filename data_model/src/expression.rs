//! Expressions to use inside of ISIs.

#![allow(
    // Because of `codec(skip)`
    clippy::default_trait_access,
    // Because of length on instructions and expressions (can't be 0)
    clippy::len_without_is_empty,
    // Because of length on instructions and expressions (XXX: Should it be trait?)
    clippy::unused_self
)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_map, format, string::String, vec, vec::Vec};
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::Display;
use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{query::QueryBox, Value, ValueBox};

/// Bound name for a value.
pub type ValueName = String;

/// Context, composed of (name, value) pairs.
pub type Context<const HASH_LENGTH: usize> = btree_map::BTreeMap<ValueName, Value<HASH_LENGTH>>;

/// Boxed expression.
pub type ExpressionBox<const HASH_LENGTH: usize> = Box<Expression<HASH_LENGTH>>;

/// Struct for type checking and converting expression results.
#[derive(Debug, Display, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(transparent)]
#[display(fmt = "Expressions aren't `fmt::Display` yet :(")] // TODO: implement
pub struct EvaluatesTo<V: TryFrom<Value<HASH_LENGTH>>, const HASH_LENGTH: usize> {
    /// Expression.
    #[serde(flatten)]
    pub expression: ExpressionBox<HASH_LENGTH>,
    #[codec(skip)]
    _value_type: PhantomData<V>,
}

impl<
        V: TryFrom<Value<HASH_LENGTH>>,
        E: Into<ExpressionBox<HASH_LENGTH>>,
        const HASH_LENGTH: usize,
    > From<E> for EvaluatesTo<V, HASH_LENGTH>
{
    fn from(expression: E) -> Self {
        Self {
            expression: expression.into(),
            _value_type: PhantomData::default(),
        }
    }
}

impl<V: TryFrom<Value<HASH_LENGTH>>, const HASH_LENGTH: usize> EvaluatesTo<V, HASH_LENGTH> {
    /// Number of underneath expressions.
    #[inline]
    pub fn len(&self) -> usize {
        self.expression.len()
    }
}

impl<V: IntoSchema + TryFrom<Value<HASH_LENGTH>>, const HASH_LENGTH: usize> IntoSchema
    for EvaluatesTo<V, HASH_LENGTH>
{
    fn type_name() -> String {
        format!("{}::EvaluatesTo<{}>", module_path!(), V::type_name())
    }
    fn schema(map: &mut MetaMap) {
        ExpressionBox::schema(map);

        map.entry(Self::type_name()).or_insert_with(|| {
            const EXPRESSION: &str = "expression";

            Metadata::Struct(NamedFieldsMeta {
                declarations: vec![Declaration {
                    name: String::from(EXPRESSION),
                    ty: ExpressionBox::type_name(),
                }],
            })
        });
    }
}

/// Represents all possible expressions.
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Expression<const HASH_LENGTH: usize> {
    /// Add expression.
    Add(Add<{ HASH_LENGTH }>),
    /// Subtract expression.
    Subtract(Subtract<{ HASH_LENGTH }>),
    /// Multiply expression.
    Multiply(Multiply<{ HASH_LENGTH }>),
    /// Divide expression.
    Divide(Divide<{ HASH_LENGTH }>),
    /// Module expression.
    Mod(Mod<{ HASH_LENGTH }>),
    /// Raise to power expression.
    RaiseTo(RaiseTo<{ HASH_LENGTH }>),
    /// Greater expression.
    Greater(Greater<{ HASH_LENGTH }>),
    /// Less expression.
    Less(Less<{ HASH_LENGTH }>),
    /// Equal expression.
    Equal(Equal<{ HASH_LENGTH }>),
    /// Not expression.
    Not(Not<{ HASH_LENGTH }>),
    /// And expression.
    And(And<{ HASH_LENGTH }>),
    /// Or expression.
    Or(Or<{ HASH_LENGTH }>),
    /// If expression.
    If(If<{ HASH_LENGTH }>),
    /// Raw value.
    Raw(ValueBox<{ HASH_LENGTH }>),
    /// Query to Iroha state.
    Query(QueryBox<{ HASH_LENGTH }>),
    /// Contains expression for vectors.
    Contains(Contains<{ HASH_LENGTH }>),
    /// Contains all expression for vectors.
    ContainsAll(ContainsAll<{ HASH_LENGTH }>),
    /// Contains any expression for vectors.
    ContainsAny(ContainsAny<{ HASH_LENGTH }>),
    /// Where expression to supply temporary values to local context.
    Where(Where<{ HASH_LENGTH }>),
    /// Get a temporary value by name
    ContextValue(ContextValue),
}

impl<const HASH_LENGTH: usize> Expression<HASH_LENGTH> {
    /// Number of underneath expressions.
    #[inline]
    pub fn len(&self) -> usize {
        use Expression::*;

        match self {
            Add(add) => add.len(),
            Subtract(subtract) => subtract.len(),
            Greater(greater) => greater.len(),
            Less(less) => less.len(),
            Equal(equal) => equal.len(),
            Not(not) => not.len(),
            And(and) => and.len(),
            Or(or) => or.len(),
            If(if_expression) => if_expression.len(),
            Raw(raw) => raw.len(),
            Query(query) => query.len(),
            Contains(contains) => contains.len(),
            ContainsAll(contains_all) => contains_all.len(),
            ContainsAny(contains_any) => contains_any.len(),
            Where(where_expression) => where_expression.len(),
            ContextValue(context_value) => context_value.len(),
            Multiply(multiply) => multiply.len(),
            Divide(divide) => divide.len(),
            Mod(modulus) => modulus.len(),
            RaiseTo(raise_to) => raise_to.len(),
        }
    }
}

impl<T: Into<Value<HASH_LENGTH>>, const HASH_LENGTH: usize> From<T> for ExpressionBox<HASH_LENGTH> {
    fn from(value: T) -> Self {
        Expression::Raw(Box::new(value.into())).into()
    }
}

/// Get a temporary value by name.
/// The values are brought into [`Context`] by [`Where`] expression.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct ContextValue {
    /// Name bound to the value.
    pub value_name: String,
}

impl ContextValue {
    /// Number of underneath expressions.
    pub const fn len(&self) -> usize {
        1
    }

    /// Constructs `ContextValue`.
    pub fn new(value_name: &str) -> Self {
        Self {
            value_name: String::from(value_name),
        }
    }
}

impl<const HASH_LENGTH: usize> From<ContextValue> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: ContextValue) -> Self {
        Expression::ContextValue(expression).into()
    }
}

/// Evaluates to the multiplication of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Multiply<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Multiply<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Multiply` expression.
    pub fn new(
        left: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
        right: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Multiply<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Multiply<HASH_LENGTH>) -> Self {
        Expression::Multiply(expression).into()
    }
}

/// Evaluates to the division of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Divide<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Divide<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Multiply` expression.
    pub fn new(
        left: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
        right: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Divide<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Divide<HASH_LENGTH>) -> Self {
        Expression::Divide(expression).into()
    }
}

/// Evaluates to the modulus of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Mod<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Mod<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Mod` expression.
    pub fn new(
        left: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
        right: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Mod<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Mod<HASH_LENGTH>) -> Self {
        Expression::Mod(expression).into()
    }
}

/// Evaluates to the right expression in power of left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct RaiseTo<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> RaiseTo<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `RaiseTo` expression.
    pub fn new(
        left: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
        right: impl Into<EvaluatesTo<u32, HASH_LENGTH>>,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<RaiseTo<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: RaiseTo<HASH_LENGTH>) -> Self {
        Expression::RaiseTo(expression).into()
    }
}

/// Evaluates to the sum of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Add<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Add<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Add` expression.
    pub fn new<L: Into<EvaluatesTo<u32, HASH_LENGTH>>, R: Into<EvaluatesTo<u32, HASH_LENGTH>>>(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Add<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Add<HASH_LENGTH>) -> Self {
        Expression::Add(expression).into()
    }
}

/// Evaluates to the difference of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Subtract<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Subtract<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Subtract` expression.
    pub fn new<L: Into<EvaluatesTo<u32, HASH_LENGTH>>, R: Into<EvaluatesTo<u32, HASH_LENGTH>>>(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Subtract<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Subtract<HASH_LENGTH>) -> Self {
        Expression::Subtract(expression).into()
    }
}

/// Returns whether the `left` expression is greater than the `right`.
/// Works only for `Value::U32`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Greater<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Greater<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Greater` expression.
    pub fn new<L: Into<EvaluatesTo<u32, HASH_LENGTH>>, R: Into<EvaluatesTo<u32, HASH_LENGTH>>>(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Greater<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Greater<HASH_LENGTH>) -> Self {
        Expression::Greater(expression).into()
    }
}

/// Returns whether the `left` expression is less than the `right`.
/// Works only for `Value::U32`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Less<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<u32, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<u32, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Less<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Less` expression.
    pub fn new<L: Into<EvaluatesTo<u32, HASH_LENGTH>>, R: Into<EvaluatesTo<u32, HASH_LENGTH>>>(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Less<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Less<HASH_LENGTH>) -> Self {
        Expression::Less(expression).into()
    }
}

/// Negates the result of the `expression`.
/// Works only for `Value::Bool`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Not<const HASH_LENGTH: usize> {
    /// Expression that should evaluate to `Value::Bool`.
    pub expression: EvaluatesTo<bool, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Not<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.expression.len() + 1
    }

    /// Constructs `Not` expression.
    pub fn new<E: Into<EvaluatesTo<bool, HASH_LENGTH>>>(expression: E) -> Self {
        Self {
            expression: expression.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Not<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Not<HASH_LENGTH>) -> Self {
        Expression::Not(expression).into()
    }
}

/// Applies the logical `and` to two `Value::Bool` operands.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct And<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<bool, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<bool, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> And<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `And` expression.
    pub fn new<L: Into<EvaluatesTo<bool, HASH_LENGTH>>, R: Into<EvaluatesTo<bool, HASH_LENGTH>>>(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<And<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: And<HASH_LENGTH>) -> Self {
        Expression::And(expression).into()
    }
}

/// Applies the logical `or` to two `Value::Bool` operands.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Or<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<bool, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<bool, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Or<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Or` expression.
    pub fn new<L: Into<EvaluatesTo<bool, HASH_LENGTH>>, R: Into<EvaluatesTo<bool, HASH_LENGTH>>>(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Or<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Or<HASH_LENGTH>) -> Self {
        Expression::Or(expression).into()
    }
}

/// Builder for [`If`] expression.
#[derive(Debug)]
#[must_use = ".build() not used"]
pub struct IfBuilder<const HASH_LENGTH: usize> {
    /// Condition expression, which should evaluate to `Value::Bool`.
    /// If it is `true` then the evaluated `then_expression` will be returned, else - evaluated `else_expression`.
    pub condition: EvaluatesTo<bool, HASH_LENGTH>,
    /// Expression evaluated and returned if the condition is `true`.
    pub then_expression: Option<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
    /// Expression evaluated and returned if the condition is `false`.
    pub else_expression: Option<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
}

impl<const HASH_LENGTH: usize> IfBuilder<HASH_LENGTH> {
    ///Sets the `condition`.
    pub fn condition<C: Into<EvaluatesTo<bool, HASH_LENGTH>>>(condition: C) -> Self {
        IfBuilder {
            condition: condition.into(),
            then_expression: None,
            else_expression: None,
        }
    }

    /// Sets `then_expression`.
    pub fn then_expression<E: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>>(
        self,
        expression: E,
    ) -> Self {
        IfBuilder {
            then_expression: Some(expression.into()),
            ..self
        }
    }

    /// Sets `else_expression`.
    pub fn else_expression<E: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>>(
        self,
        expression: E,
    ) -> Self {
        IfBuilder {
            else_expression: Some(expression.into()),
            ..self
        }
    }

    /// Returns [`If`] expression, if all the fields are filled.
    ///
    /// # Errors
    ///
    /// Fails if some of fields are not filled.
    pub fn build(self) -> Result<If<HASH_LENGTH>, &'static str> {
        if let (Some(then_expression), Some(else_expression)) =
            (self.then_expression, self.else_expression)
        {
            return Ok(If::new(self.condition, then_expression, else_expression));
        }

        Err("Not all fields filled")
    }
}

/// If expression. Returns either a result of `then_expression`, or a result of `else_expression`
/// based on the `condition`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct If<const HASH_LENGTH: usize> {
    /// Condition expression, which should evaluate to `Value::Bool`.
    pub condition: EvaluatesTo<bool, HASH_LENGTH>,
    /// Expression evaluated and returned if the condition is `true`.
    pub then_expression: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Expression evaluated and returned if the condition is `false`.
    pub else_expression: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> If<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.condition.len() + self.then_expression.len() + self.else_expression.len() + 1
    }

    /// Constructs `If` expression.
    pub fn new<
        C: Into<EvaluatesTo<bool, HASH_LENGTH>>,
        T: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
        E: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
    >(
        condition: C,
        then_expression: T,
        else_expression: E,
    ) -> Self {
        Self {
            condition: condition.into(),
            then_expression: then_expression.into(),
            else_expression: else_expression.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<If<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(if_expression: If<HASH_LENGTH>) -> Self {
        Expression::If(if_expression).into()
    }
}

/// `Contains` expression.
/// Returns `true` if `collection` contains an `element`, `false` otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Contains<const HASH_LENGTH: usize> {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>,
    /// Element expression.
    pub element: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Contains<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.collection.len() + self.element.len() + 1
    }

    /// Constructs `Contains` expression.
    pub fn new<
        C: Into<EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>>,
        E: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
    >(
        collection: C,
        element: E,
    ) -> Self {
        Self {
            collection: collection.into(),
            element: element.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Contains<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: Contains<HASH_LENGTH>) -> Self {
        Expression::Contains(expression).into()
    }
}

/// `Contains` expression.
/// Returns `true` if `collection` contains all `elements`, `false` otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct ContainsAll<const HASH_LENGTH: usize> {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>,
    /// Expression, which should evaluate to `Value::Vec`.
    pub elements: EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> ContainsAll<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.collection.len() + self.elements.len() + 1
    }

    /// Constructs `Contains` expression.
    pub fn new<
        C: Into<EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>>,
        E: Into<EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>>,
    >(
        collection: C,
        elements: E,
    ) -> Self {
        Self {
            collection: collection.into(),
            elements: elements.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<ContainsAll<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: ContainsAll<HASH_LENGTH>) -> Self {
        Expression::ContainsAll(expression).into()
    }
}

/// `Contains` expression.
/// Returns `true` if `collection` contains any element out of the `elements`, `false` otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct ContainsAny<const HASH_LENGTH: usize> {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>,
    /// Expression, which should evaluate to `Value::Vec`.
    pub elements: EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> ContainsAny<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.collection.len() + self.elements.len() + 1
    }

    /// Constructs `Contains` expression.
    pub fn new<
        C: Into<EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>>,
        E: Into<EvaluatesTo<Vec<Value<HASH_LENGTH>>, HASH_LENGTH>>,
    >(
        collection: C,
        elements: E,
    ) -> Self {
        Self {
            collection: collection.into(),
            elements: elements.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<ContainsAny<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(expression: ContainsAny<HASH_LENGTH>) -> Self {
        Expression::ContainsAny(expression).into()
    }
}

/// Returns `true` if `left` operand is equal to the `right` operand.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Equal<const HASH_LENGTH: usize> {
    /// Left operand.
    pub left: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Right operand.
    pub right: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Equal<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Or` expression.
    pub fn new<
        L: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
        R: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
    >(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> From<Equal<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(equal: Equal<HASH_LENGTH>) -> Self {
        Expression::Equal(equal).into()
    }
}

/// [`Where`] builder.
#[derive(Debug)]
pub struct WhereBuilder<const HASH_LENGTH: usize> {
    /// Expression to be evaluated.
    expression: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Context values for the context binded to their `String` names.
    values: btree_map::BTreeMap<ValueName, EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
}

impl<const HASH_LENGTH: usize> WhereBuilder<HASH_LENGTH> {
    /// Sets the `expression` to be evaluated.
    #[must_use]
    pub fn evaluate<E: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>>(expression: E) -> Self {
        Self {
            expression: expression.into(),
            values: btree_map::BTreeMap::new(),
        }
    }

    /// Binds `expression` result to a `value_name`, by which it will be reachable from the main expression.
    #[must_use]
    pub fn with_value<E: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>>(
        mut self,
        value_name: ValueName,
        expression: E,
    ) -> Self {
        let _result = self.values.insert(value_name, expression.into());
        self
    }

    /// Returns a [`Where`] expression.
    #[inline]
    #[must_use]
    pub fn build(self) -> Where<HASH_LENGTH> {
        Where::new(self.expression, self.values)
    }
}

/// Adds a local context of `values` for the `expression`.
/// It is similar to *Haskell's where syntax* although, evaluated eagerly.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Where<const HASH_LENGTH: usize> {
    /// Expression to be evaluated.
    pub expression: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Context values for the context binded to their `String` names.
    pub values: btree_map::BTreeMap<ValueName, EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
}

impl<const HASH_LENGTH: usize> Where<HASH_LENGTH> {
    /// Number of underneath expressions.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.expression.len() + self.values.values().map(EvaluatesTo::len).sum::<usize>() + 1
    }

    /// Constructs `Or` expression.
    #[must_use]
    pub fn new<E: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>>(
        expression: E,
        values: btree_map::BTreeMap<ValueName, EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
    ) -> Self {
        Self {
            expression: expression.into(),
            values,
        }
    }
}

impl<const HASH_LENGTH: usize> From<Where<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(where_expression: Where<HASH_LENGTH>) -> Self {
        Expression::Where(where_expression).into()
    }
}

impl<const HASH_LENGTH: usize> QueryBox<HASH_LENGTH> {
    /// Number of underneath expressions.
    pub const fn len(&self) -> usize {
        1
    }
}

impl<const HASH_LENGTH: usize> From<QueryBox<HASH_LENGTH>> for ExpressionBox<HASH_LENGTH> {
    fn from(query: QueryBox<HASH_LENGTH>) -> Self {
        Expression::Query(query).into()
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Add, And, Contains, ContainsAll, ContainsAny, Context, ContextValue, Divide, Equal,
        EvaluatesTo, Expression, ExpressionBox, Greater, If as IfExpression, IfBuilder, Less, Mod,
        Multiply, Not, Or, RaiseTo, Subtract, ValueName, Where, WhereBuilder,
    };
}
