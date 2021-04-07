//! Expressions to use inside of ISIs.

#![allow(
    clippy::default_trait_access,
    clippy::len_without_is_empty,
    clippy::unused_self
)]

use std::{collections::BTreeMap, convert::TryFrom, marker::PhantomData};

use iroha_derive::FromVariant;
use iroha_error::{error, Result};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{query::QueryBox, Value, ValueBox};

/// Binded name for a value.
pub type ValueName = String;

/// Context, composed of (name, value) pairs.
pub type Context = BTreeMap<ValueName, Value>;

/// Boxed expression.
pub type ExpressionBox = Box<Expression>;

/// Struct for type checking and converting expression results.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvaluatesTo<V: TryFrom<Value>> {
    /// Expression.
    #[serde(flatten)]
    pub expression: ExpressionBox,
    #[serde(skip)]
    #[codec(skip)]
    _value_type: PhantomData<V>,
}

impl<V: TryFrom<Value>, E: Into<ExpressionBox>> From<E> for EvaluatesTo<V> {
    fn from(expression: E) -> EvaluatesTo<V> {
        EvaluatesTo {
            expression: expression.into(),
            _value_type: PhantomData::default(),
        }
    }
}

impl<V: TryFrom<Value>> EvaluatesTo<V> {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.expression.len()
    }
}

/// Represents all possible expressions.
#[derive(
    Debug,
    Clone,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    FromVariant,
    PartialOrd,
    Ord,
)]
pub enum Expression {
    /// Add expression.
    Add(Add),
    /// Subtract expression.
    Subtract(Subtract),
    /// Multiply expression.
    Multiply(Multiply),
    /// Divide expression.
    Divide(Divide),
    /// Module expression.
    Mod(Mod),
    /// Raise to power expression.
    RaiseTo(RaiseTo),
    /// Greater expression.
    Greater(Greater),
    /// Less expression.
    Less(Less),
    /// Equal expression.
    Equal(Equal),
    /// Not expression.
    Not(Not),
    /// And expression.
    And(And),
    /// Or expression.
    Or(Or),
    /// If expression.
    If(If),
    /// Raw value.
    Raw(ValueBox),
    /// Query to Iroha state.
    Query(QueryBox),
    /// Contains expression for vectors.
    Contains(Contains),
    /// Contains all expression for vectors.
    ContainsAll(ContainsAll),
    /// Contains any expression for vectors.
    ContainsAny(ContainsAny),
    /// Where expression to supply temporary values to local context.
    Where(Where),
    /// Get a temporary value by name
    ContextValue(ContextValue),
}

impl Expression {
    /// Number of underneath expressions.
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

impl<T: Into<Value>> From<T> for ExpressionBox {
    fn from(value: T) -> Self {
        Expression::Raw(Box::new(value.into())).into()
    }
}

/// Get a temporary value by name.
/// The values are brought into [`Context`] by [`Where`] expression.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContextValue {
    /// Name binded to the value.
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
            value_name: value_name.to_string(),
        }
    }
}

impl From<ContextValue> for ExpressionBox {
    fn from(expression: ContextValue) -> Self {
        Expression::ContextValue(expression).into()
    }
}

/// Evaluates to the multiplication of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Multiply {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Multiply {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Multiply` expression.
    pub fn new(left: impl Into<EvaluatesTo<u32>>, right: impl Into<EvaluatesTo<u32>>) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Multiply> for ExpressionBox {
    fn from(expression: Multiply) -> Self {
        Expression::Multiply(expression).into()
    }
}

/// Evaluates to the division of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Divide {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Divide {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Multiply` expression.
    pub fn new(left: impl Into<EvaluatesTo<u32>>, right: impl Into<EvaluatesTo<u32>>) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Divide> for ExpressionBox {
    fn from(expression: Divide) -> Self {
        Expression::Divide(expression).into()
    }
}

/// Evaluates to the modulus of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mod {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Mod {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Mod` expression.
    pub fn new(left: impl Into<EvaluatesTo<u32>>, right: impl Into<EvaluatesTo<u32>>) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Mod> for ExpressionBox {
    fn from(expression: Mod) -> Self {
        Expression::Mod(expression).into()
    }
}

/// Evaluates to the right expression in power of left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RaiseTo {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl RaiseTo {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `RaiseTo` expression.
    pub fn new(left: impl Into<EvaluatesTo<u32>>, right: impl Into<EvaluatesTo<u32>>) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<RaiseTo> for ExpressionBox {
    fn from(expression: RaiseTo) -> Self {
        Expression::RaiseTo(expression).into()
    }
}

/// Evaluates to the sum of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Add {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Add {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Add` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Add> for ExpressionBox {
    fn from(expression: Add) -> Self {
        Expression::Add(expression).into()
    }
}

/// Evaluates to the difference of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subtract {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Subtract {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Subtract` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Subtract> for ExpressionBox {
    fn from(expression: Subtract) -> Self {
        Expression::Subtract(expression).into()
    }
}

/// Returns whether the `left` expression is greater than the `right`.
/// Works only for `Value::U32`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Greater {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Greater {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Greater` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Greater> for ExpressionBox {
    fn from(expression: Greater) -> Self {
        Expression::Greater(expression).into()
    }
}

/// Returns whether the `left` expression is less than the `right`.
/// Works only for `Value::U32`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Less {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Less {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Less` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Less> for ExpressionBox {
    fn from(expression: Less) -> Self {
        Expression::Less(expression).into()
    }
}

/// Negates the result of the `expression`.
/// Works only for `Value::Bool`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Not {
    /// Expression that should evaluate to `Value::Bool`.
    pub expression: EvaluatesTo<bool>,
}

impl Not {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.expression.len() + 1
    }

    /// Constructs `Not` expression.
    pub fn new<E: Into<EvaluatesTo<bool>>>(expression: E) -> Self {
        Self {
            expression: expression.into(),
        }
    }
}

impl From<Not> for ExpressionBox {
    fn from(expression: Not) -> Self {
        Expression::Not(expression).into()
    }
}

/// Applies the logical `and` to two `Value::Bool` operands.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct And {
    /// Left operand.
    pub left: EvaluatesTo<bool>,
    /// Right operand.
    pub right: EvaluatesTo<bool>,
}

impl And {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `And` expression.
    pub fn new<L: Into<EvaluatesTo<bool>>, R: Into<EvaluatesTo<bool>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<And> for ExpressionBox {
    fn from(expression: And) -> Self {
        Expression::And(expression).into()
    }
}

/// Applies the logical `or` to two `Value::Bool` operands.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Or {
    /// Left operand.
    pub left: EvaluatesTo<bool>,
    /// Right operand.
    pub right: EvaluatesTo<bool>,
}

impl Or {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Or` expression.
    pub fn new<L: Into<EvaluatesTo<bool>>, R: Into<EvaluatesTo<bool>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Or> for ExpressionBox {
    fn from(expression: Or) -> Self {
        Expression::Or(expression).into()
    }
}

/// Builder for [`If`] expression.
#[derive(Debug)]
pub struct IfBuilder {
    /// Condition expression, which should evaluate to `Value::Bool`.
    /// If it is `true` then the evaluated `then_expression` will be returned, else - evaluated `else_expression`.
    pub condition: EvaluatesTo<bool>,
    /// Expression evaluated and returned if the condition is `true`.
    pub then_expression: Option<EvaluatesTo<Value>>,
    /// Expression evaluated and returned if the condition is `false`.
    pub else_expression: Option<EvaluatesTo<Value>>,
}

impl IfBuilder {
    ///Sets the `condition`.
    pub fn condition<C: Into<EvaluatesTo<bool>>>(condition: C) -> Self {
        IfBuilder {
            condition: condition.into(),
            then_expression: None,
            else_expression: None,
        }
    }

    /// Sets `then_expression`.
    pub fn then_expression<E: Into<EvaluatesTo<Value>>>(self, expression: E) -> Self {
        IfBuilder {
            then_expression: Some(expression.into()),
            ..self
        }
    }

    /// Sets `else_expression`.
    pub fn else_expression<E: Into<EvaluatesTo<Value>>>(self, expression: E) -> Self {
        IfBuilder {
            else_expression: Some(expression.into()),
            ..self
        }
    }

    /// Returns [`If`] expression, if all the fields are filled.
    ///
    /// # Errors
    /// Fails if some of fields are not filled.
    pub fn build(self) -> Result<If> {
        if let (Some(then_expression), Some(else_expression)) =
            (self.then_expression, self.else_expression)
        {
            Ok(If::new(self.condition, then_expression, else_expression))
        } else {
            Err(error!("Not all fields are filled."))
        }
    }
}

/// If expression. Returns either a result of `then_expression`, or a result of `else_expression`
/// based on the `condition`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct If {
    /// Condition expression, which should evaluate to `Value::Bool`.
    pub condition: EvaluatesTo<bool>,
    /// Expression evaluated and returned if the condition is `true`.
    pub then_expression: EvaluatesTo<Value>,
    /// Expression evaluated and returned if the condition is `false`.
    pub else_expression: EvaluatesTo<Value>,
}

impl If {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.condition.len() + self.then_expression.len() + self.else_expression.len() + 1
    }

    /// Constructs `If` expression.
    pub fn new<
        C: Into<EvaluatesTo<bool>>,
        T: Into<EvaluatesTo<Value>>,
        E: Into<EvaluatesTo<Value>>,
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

impl From<If> for ExpressionBox {
    fn from(if_expression: If) -> Self {
        Expression::If(if_expression).into()
    }
}

/// `Contains` expression.
/// Returns `true` if `collection` contains an `element`, `false` otherwise.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Contains {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value>>,
    /// Element expression.
    pub element: EvaluatesTo<Value>,
}

impl Contains {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.collection.len() + self.element.len() + 1
    }

    /// Constructs `Contains` expression.
    pub fn new<C: Into<EvaluatesTo<Vec<Value>>>, E: Into<EvaluatesTo<Value>>>(
        collection: C,
        element: E,
    ) -> Self {
        Self {
            collection: collection.into(),
            element: element.into(),
        }
    }
}

impl From<Contains> for ExpressionBox {
    fn from(expression: Contains) -> Self {
        Expression::Contains(expression).into()
    }
}

/// `Contains` expression.
/// Returns `true` if `collection` contains all `elements`, `false` otherwise.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContainsAll {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value>>,
    /// Expression, which should evaluate to `Value::Vec`.
    pub elements: EvaluatesTo<Vec<Value>>,
}

impl ContainsAll {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.collection.len() + self.elements.len() + 1
    }

    /// Constructs `Contains` expression.
    pub fn new<C: Into<EvaluatesTo<Vec<Value>>>, E: Into<EvaluatesTo<Vec<Value>>>>(
        collection: C,
        elements: E,
    ) -> Self {
        Self {
            collection: collection.into(),
            elements: elements.into(),
        }
    }
}

impl From<ContainsAll> for ExpressionBox {
    fn from(expression: ContainsAll) -> Self {
        Expression::ContainsAll(expression).into()
    }
}

/// `Contains` expression.
/// Returns `true` if `collection` contains any element out of the `elements`, `false` otherwise.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContainsAny {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value>>,
    /// Expression, which should evaluate to `Value::Vec`.
    pub elements: EvaluatesTo<Vec<Value>>,
}

impl ContainsAny {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.collection.len() + self.elements.len() + 1
    }

    /// Constructs `Contains` expression.
    pub fn new<C: Into<EvaluatesTo<Vec<Value>>>, E: Into<EvaluatesTo<Vec<Value>>>>(
        collection: C,
        elements: E,
    ) -> Self {
        Self {
            collection: collection.into(),
            elements: elements.into(),
        }
    }
}

impl From<ContainsAny> for ExpressionBox {
    fn from(expression: ContainsAny) -> Self {
        Expression::ContainsAny(expression).into()
    }
}

/// Returns `true` if `left` operand is equal to the `right` operand.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Equal {
    /// Left operand.
    pub left: EvaluatesTo<Value>,
    /// Right operand.
    pub right: EvaluatesTo<Value>,
}

impl Equal {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.left.len() + self.right.len() + 1
    }

    /// Constructs `Or` expression.
    pub fn new<L: Into<EvaluatesTo<Value>>, R: Into<EvaluatesTo<Value>>>(
        left: L,
        right: R,
    ) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl From<Equal> for ExpressionBox {
    fn from(equal: Equal) -> Self {
        Expression::Equal(equal).into()
    }
}

/// [`Where`] builder.
#[derive(Debug)]
pub struct WhereBuilder {
    /// Expression to be evaluated.
    expression: EvaluatesTo<Value>,
    /// Context values for the context binded to their `String` names.
    values: BTreeMap<ValueName, EvaluatesTo<Value>>,
}

impl WhereBuilder {
    /// Sets the `expression` to be evaluated.
    pub fn evaluate<E: Into<EvaluatesTo<Value>>>(expression: E) -> WhereBuilder {
        WhereBuilder {
            expression: expression.into(),
            values: BTreeMap::new(),
        }
    }

    /// Binds `expression` result to a `value_name`, by which it will be reachable from the main expression.
    pub fn with_value<E: Into<EvaluatesTo<Value>>>(
        mut self,
        value_name: ValueName,
        expression: E,
    ) -> WhereBuilder {
        let _result = self.values.insert(value_name, expression.into());
        self
    }

    /// Returns a [`Where`] expression.
    pub fn build(self) -> Where {
        Where::new(self.expression, self.values)
    }
}

/// Adds a local context of `values` for the `expression`.
/// It is similar to *Haskell's where syntax* although, evaluated eagerly.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Where {
    /// Expression to be evaluated.
    pub expression: EvaluatesTo<Value>,
    /// Context values for the context binded to their `String` names.
    pub values: BTreeMap<ValueName, EvaluatesTo<Value>>,
}

impl Where {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        self.expression.len() + self.values.values().map(EvaluatesTo::len).sum::<usize>() + 1
    }

    /// Constructs `Or` expression.
    pub fn new<E: Into<EvaluatesTo<Value>>>(
        expression: E,
        values: BTreeMap<ValueName, EvaluatesTo<Value>>,
    ) -> Self {
        Self {
            expression: expression.into(),
            values,
        }
    }
}

impl From<Where> for ExpressionBox {
    fn from(where_expression: Where) -> Self {
        Expression::Where(where_expression).into()
    }
}

impl QueryBox {
    /// Number of underneath expressions.
    pub const fn len(&self) -> usize {
        1
    }
}

impl From<QueryBox> for ExpressionBox {
    fn from(query: QueryBox) -> Self {
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
